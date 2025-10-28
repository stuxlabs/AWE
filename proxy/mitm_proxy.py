#!/usr/bin/env python3
"""
MITM Proxy module for intercepting HTTP/HTTPS traffic
Used for detecting stored and DOM-based XSS vulnerabilities
"""

import asyncio
import json
import logging
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable, Set
from urllib.parse import urlparse, parse_qs

try:
    from mitmproxy import http, ctx
    from mitmproxy.options import Options
    from mitmproxy.master import Master
    from mitmproxy.server import ProxyServer
    MITM_AVAILABLE = True
except ImportError:
    MITM_AVAILABLE = False
    logging.warning("mitmproxy not available. MITM functionality will be disabled.")

from core.models import MITMInterceptionResult, XSSType
from core.utils import is_xss_payload, extract_forms_from_html, get_timestamp


class XSSInterceptor:
    """Main interceptor class for capturing XSS-related traffic"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.logger = logging.getLogger(self.__class__.__name__)
        self.intercepted_requests: List[MITMInterceptionResult] = []
        self.injected_payloads: Dict[str, str] = {}  # session_id -> payload
        self.payload_tracking: Dict[str, Dict] = {}  # payload -> tracking info
        self.storage_callbacks: List[Callable] = []
        self.running = False
        
        # Track forms and injection points
        self.discovered_forms: Dict[str, List[Dict]] = {}  # url -> forms
        self.injection_points: Set[str] = set()
        
        # Patterns for detecting XSS in responses
        self.xss_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'on\w+\s*=',
            r'<img[^>]*onerror',
            r'<svg[^>]*onload',
            r'document\.write',
            r'innerHTML\s*='
        ]
    
    def add_storage_callback(self, callback: Callable):
        """Add callback for when intercepted data should be stored"""
        self.storage_callbacks.append(callback)
    
    def request(self, flow: 'http.HTTPFlow'):
        """Handle intercepted requests"""
        try:
            request = flow.request
            url = request.pretty_url
            method = request.method
            
            # Extract request data
            headers = dict(request.headers)
            body = request.content.decode('utf-8', errors='ignore') if request.content else None
            
            # Check if this is a form submission with potential XSS payload
            injected_payload = None
            injection_point = None
            
            if method == "POST" and body:
                injected_payload, injection_point = self._check_for_payload_injection(body)
            elif method == "GET" and request.query:
                query_params = parse_qs(request.query)
                for param, values in query_params.items():
                    for value in values:
                        if is_xss_payload(value):
                            injected_payload = value
                            injection_point = f"query_param:{param}"
                            break
            
            # Create interception result
            result = MITMInterceptionResult(
                request_url=url,
                request_method=method,
                request_headers=headers,
                request_body=body,
                injected_payload=injected_payload,
                injection_point=injection_point,
                session_id=self._get_session_id(headers)
            )
            
            # Store in request context for response processing
            flow.request.xss_context = result
            
            self.logger.debug(f"Intercepted {method} request to {url}")
            if injected_payload:
                self.logger.info(f"XSS payload injection detected: {injected_payload[:50]}...")
                
        except Exception as e:
            self.logger.error(f"Error processing request: {e}")
    
    def response(self, flow: 'http.HTTPFlow'):
        """Handle intercepted responses"""
        try:
            request = flow.request
            response = flow.response
            
            # Get the request context
            result = getattr(request, 'xss_context', None)
            if not result:
                return
            
            # Update result with response data
            result.response_status = response.status_code
            result.response_headers = dict(response.headers)
            result.response_body = response.content.decode('utf-8', errors='ignore') if response.content else None
            
            # Check for payload reflection or storage
            if result.injected_payload and result.response_body:
                result.payload_reflected = result.injected_payload in result.response_body
                
                # Check if this might be stored XSS (payload not immediately reflected)
                if not result.payload_reflected:
                    self._track_potential_stored_payload(result)
                
                # Extract forms for future injection attempts
                if 'text/html' in result.response_headers.get('content-type', ''):
                    forms = extract_forms_from_html(result.response_body, result.request_url)
                    if forms:
                        self.discovered_forms[result.request_url] = forms
            
            # Add to intercepted requests
            self.intercepted_requests.append(result)
            
            # Notify callbacks
            for callback in self.storage_callbacks:
                try:
                    callback(result)
                except Exception as e:
                    self.logger.error(f"Storage callback error: {e}")
            
            self.logger.debug(f"Processed response from {result.request_url} (status: {result.response_status})")
            
        except Exception as e:
            self.logger.error(f"Error processing response: {e}")
    
    def _check_for_payload_injection(self, body: str) -> tuple[Optional[str], Optional[str]]:
        """Check if request body contains XSS payload injection"""
        if not body:
            return None, None
        
        # Parse form data
        if 'application/x-www-form-urlencoded' in body or '=' in body:
            try:
                params = parse_qs(body)
                for param, values in params.items():
                    for value in values:
                        if is_xss_payload(value):
                            return value, f"form_field:{param}"
            except Exception:
                pass
        
        # Check raw body for XSS patterns
        if is_xss_payload(body):
            return body, "request_body"
        
        return None, None
    
    def _get_session_id(self, headers: Dict[str, str]) -> Optional[str]:
        """Extract session ID from request headers"""
        # Look for common session cookies
        cookie_header = headers.get('cookie', '')
        if cookie_header:
            for cookie in cookie_header.split(';'):
                cookie = cookie.strip()
                if '=' in cookie:
                    name, value = cookie.split('=', 1)
                    name = name.strip().lower()
                    if name in ['sessionid', 'session_id', 'jsessionid', 'phpsessid']:
                        return value
        
        return None
    
    def _track_potential_stored_payload(self, result: MITMInterceptionResult):
        """Track payload that might be stored for later execution"""
        if result.injected_payload:
            self.payload_tracking[result.injected_payload] = {
                'injection_url': result.request_url,
                'injection_time': result.timestamp,
                'session_id': result.session_id,
                'injection_point': result.injection_point
            }
    
    def get_intercepted_requests(self) -> List[MITMInterceptionResult]:
        """Get all intercepted requests"""
        return self.intercepted_requests.copy()
    
    def get_discovered_forms(self) -> Dict[str, List[Dict]]:
        """Get all discovered forms"""
        return self.discovered_forms.copy()
    
    def clear_data(self):
        """Clear all intercepted data"""
        self.intercepted_requests.clear()
        self.discovered_forms.clear()
        self.payload_tracking.clear()
    
    def check_stored_payloads(self, response_body: str, url: str) -> List[str]:
        """Check if any tracked payloads appear in this response"""
        found_payloads = []
        
        for payload, tracking_info in self.payload_tracking.items():
            if payload in response_body and url != tracking_info['injection_url']:
                found_payloads.append(payload)
                self.logger.info(f"Stored XSS detected: payload '{payload[:50]}...' found on {url}")
        
        return found_payloads


class MITMProxyServer:
    """MITM proxy server wrapper"""
    
    def __init__(self, config: Optional[Dict] = None):
        if not MITM_AVAILABLE:
            raise ImportError("mitmproxy is required for MITM functionality")
        
        self.config = config or {}
        self.logger = logging.getLogger(self.__class__.__name__)
        self.interceptor = XSSInterceptor(config)
        self.master = None
        self.server_thread = None
        self.running = False
        
        # Proxy configuration
        self.proxy_port = self.config.get('proxy_port', 8080)
        self.bind_address = self.config.get('bind_address', '127.0.0.1')
        
    async def start(self):
        """Start the MITM proxy server"""
        try:
            # Configure mitmproxy options
            options = Options(
                listen_port=self.proxy_port,
                listen_host=self.bind_address,
                ssl_insecure=self.config.get('ssl_insecure', True),
                upstream_cert=self.config.get('upstream_cert', False),
            )
            
            # Create master with interceptor
            self.master = Master(options)
            self.master.addons.add(self.interceptor)
            
            # Start server in thread
            self.server_thread = threading.Thread(target=self._run_server, daemon=True)
            self.server_thread.start()
            
            # Wait for server to start
            await asyncio.sleep(1)
            self.running = True
            
            self.logger.info(f"MITM proxy started on {self.bind_address}:{self.proxy_port}")
            
        except Exception as e:
            self.logger.error(f"Failed to start MITM proxy: {e}")
            raise
    
    def _run_server(self):
        """Run the proxy server (called in thread)"""
        try:
            asyncio.set_event_loop(asyncio.new_event_loop())
            asyncio.get_event_loop().run_until_complete(self.master.run())
        except Exception as e:
            self.logger.error(f"Proxy server error: {e}")
    
    async def stop(self):
        """Stop the MITM proxy server"""
        if self.master and self.running:
            try:
                self.master.shutdown()
                if self.server_thread:
                    self.server_thread.join(timeout=5)
                self.running = False
                self.logger.info("MITM proxy stopped")
            except Exception as e:
                self.logger.error(f"Error stopping proxy: {e}")
    
    def get_interceptor(self) -> XSSInterceptor:
        """Get the XSS interceptor instance"""
        return self.interceptor
    
    def is_running(self) -> bool:
        """Check if proxy is running"""
        return self.running
    
    def get_proxy_url(self) -> str:
        """Get the proxy URL for configuration"""
        return f"http://{self.bind_address}:{self.proxy_port}"


class MITMManager:
    """High-level manager for MITM proxy operations"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.logger = logging.getLogger(self.__class__.__name__)
        self.proxy_server = None
        self.output_directory = Path(self.config.get('output_directory', 'mitm_logs'))
        self.output_directory.mkdir(exist_ok=True)
    
    async def start_proxy(self) -> MITMProxyServer:
        """Start MITM proxy and return server instance"""
        if not MITM_AVAILABLE:
            self.logger.error("MITM proxy not available - mitmproxy not installed")
            return None
        
        try:
            self.proxy_server = MITMProxyServer(self.config)
            await self.proxy_server.start()
            
            # Set up storage callback
            interceptor = self.proxy_server.get_interceptor()
            interceptor.add_storage_callback(self._save_interception_result)
            
            return self.proxy_server
            
        except Exception as e:
            self.logger.error(f"Failed to start MITM proxy manager: {e}")
            raise
    
    async def stop_proxy(self):
        """Stop MITM proxy"""
        if self.proxy_server:
            await self.proxy_server.stop()
            self.proxy_server = None
    
    def _save_interception_result(self, result: MITMInterceptionResult):
        """Save interception result to file"""
        try:
            timestamp = get_timestamp()
            filename = f"mitm_interception_{timestamp}.json"
            filepath = self.output_directory / filename
            
            # Convert to dict for JSON serialization
            data = {
                'request_url': result.request_url,
                'request_method': result.request_method,
                'request_headers': result.request_headers,
                'request_body': result.request_body,
                'response_status': result.response_status,
                'response_headers': result.response_headers,
                'response_body': result.response_body[:1000] if result.response_body else None,  # Truncate
                'injected_payload': result.injected_payload,
                'injection_point': result.injection_point,
                'payload_reflected': result.payload_reflected,
                'payload_stored': result.payload_stored,
                'timestamp': result.timestamp,
                'session_id': result.session_id
            }
            
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            
        except Exception as e:
            self.logger.error(f"Error saving interception result: {e}")
    
    def get_all_intercepted_data(self) -> List[MITMInterceptionResult]:
        """Get all intercepted data"""
        if self.proxy_server:
            return self.proxy_server.get_interceptor().get_intercepted_requests()
        return []
    
    def get_discovered_forms(self) -> Dict[str, List[Dict]]:
        """Get all discovered forms"""
        if self.proxy_server:
            return self.proxy_server.get_interceptor().get_discovered_forms()
        return {}
    
    def analyze_for_stored_xss(self, response_body: str, url: str) -> List[str]:
        """Analyze response for stored XSS payloads"""
        if self.proxy_server:
            return self.proxy_server.get_interceptor().check_stored_payloads(response_body, url)
        return []