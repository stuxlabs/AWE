#!/usr/bin/env python3
"""
Request/Response interceptor for analyzing web traffic patterns
"""

import json
import logging
import re
from datetime import datetime
from typing import Dict, List, Any, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs, unquote

from core.models import MITMInterceptionResult, XSSType
from core.utils import is_xss_payload, extract_forms_from_html


class TrafficInterceptor:
    """Intercepts and analyzes web traffic for XSS vulnerabilities"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.intercepted_data: List[MITMInterceptionResult] = []
        self.payload_tracking: Dict[str, Dict] = {}
        self.session_tracking: Dict[str, List[str]] = {}
        
        # Patterns for identifying interesting content
        self.form_patterns = [
            r'<form[^>]*>.*?</form>',
            r'<input[^>]*>',
            r'<textarea[^>]*>.*?</textarea>',
            r'<select[^>]*>.*?</select>'
        ]
        
        self.js_sink_patterns = [
            r'document\.write\s*\(',
            r'innerHTML\s*=',
            r'outerHTML\s*=',
            r'document\.createElement',
            r'insertAdjacentHTML',
            r'eval\s*\(',
            r'setTimeout\s*\(',
            r'setInterval\s*\('
        ]
        
        self.js_source_patterns = [
            r'location\.hash',
            r'location\.search',
            r'location\.href',
            r'document\.URL',
            r'document\.documentURI',
            r'document\.referrer',
            r'window\.name'
        ]
    
    def intercept_request(self, url: str, method: str, headers: Dict[str, str], 
                         body: Optional[str] = None) -> MITMInterceptionResult:
        """Intercept and analyze a request"""
        
        # Create base result
        result = MITMInterceptionResult(
            request_url=url,
            request_method=method,
            request_headers=headers,
            request_body=body,
            timestamp=datetime.now().isoformat()
        )
        
        # Extract session information
        result.session_id = self._extract_session_id(headers)
        
        # Check for payload injection
        injected_payload, injection_point = self._analyze_request_for_payloads(url, method, body)
        if injected_payload:
            result.injected_payload = injected_payload
            result.injection_point = injection_point
            
            # Track payload for stored XSS detection
            self._track_payload(injected_payload, url, result.session_id)
        
        return result
    
    def intercept_response(self, result: MITMInterceptionResult, status: int, 
                          headers: Dict[str, str], body: Optional[str] = None) -> MITMInterceptionResult:
        """Intercept and analyze a response"""
        
        # Update result with response data
        result.response_status = status
        result.response_headers = headers
        result.response_body = body
        
        if body:
            # Check for payload reflection
            if result.injected_payload:
                result.payload_reflected = self._check_payload_reflection(result.injected_payload, body)
            
            # Check for stored payloads from other requests
            stored_payloads = self._check_for_stored_payloads(body, result.request_url)
            if stored_payloads:
                result.payload_stored = True
                self.logger.info(f"Stored XSS detected: {len(stored_payloads)} payloads found in response")
            
            # Analyze for DOM manipulation patterns
            result.dom_modifications = self._analyze_dom_patterns(body)
            
            # Extract forms for future injection
            if 'text/html' in headers.get('content-type', '').lower():
                self._extract_and_cache_forms(body, result.request_url)
        
        # Store the complete result
        self.intercepted_data.append(result)
        
        return result
    
    def _extract_session_id(self, headers: Dict[str, str]) -> Optional[str]:
        """Extract session ID from headers"""
        cookie_header = headers.get('cookie', headers.get('Cookie', ''))
        
        if not cookie_header:
            return None
        
        # Common session cookie names
        session_names = ['sessionid', 'session_id', 'jsessionid', 'phpsessid', 'asp.net_sessionid']
        
        for cookie in cookie_header.split(';'):
            cookie = cookie.strip()
            if '=' in cookie:
                name, value = cookie.split('=', 1)
                name = name.strip().lower()
                if any(session_name in name for session_name in session_names):
                    return value.strip()
        
        return None
    
    def _analyze_request_for_payloads(self, url: str, method: str, 
                                     body: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
        """Analyze request for XSS payload injection"""
        
        # Check URL parameters
        parsed_url = urlparse(url)
        if parsed_url.query:
            query_params = parse_qs(parsed_url.query)
            for param_name, values in query_params.items():
                for value in values:
                    decoded_value = unquote(value)
                    if is_xss_payload(decoded_value):
                        return decoded_value, f"url_param:{param_name}"
        
        # Check POST body
        if method.upper() == 'POST' and body:
            # Try to parse as form data
            if 'application/x-www-form-urlencoded' in str(body) or '=' in body:
                try:
                    form_params = parse_qs(body)
                    for param_name, values in form_params.items():
                        for value in values:
                            decoded_value = unquote(value)
                            if is_xss_payload(decoded_value):
                                return decoded_value, f"form_param:{param_name}"
                except Exception:
                    pass
            
            # Check JSON body
            if self._looks_like_json(body):
                try:
                    json_data = json.loads(body)
                    payload, location = self._scan_json_for_payloads(json_data)
                    if payload:
                        return payload, f"json_field:{location}"
                except Exception:
                    pass
            
            # Check raw body
            if is_xss_payload(body):
                return body, "request_body"
        
        return None, None
    
    def _looks_like_json(self, body: str) -> bool:
        """Check if body looks like JSON"""
        stripped = body.strip()
        return (stripped.startswith('{') and stripped.endswith('}')) or \
               (stripped.startswith('[') and stripped.endswith(']'))
    
    def _scan_json_for_payloads(self, data: Any, path: str = "") -> Tuple[Optional[str], Optional[str]]:
        """Recursively scan JSON data for XSS payloads"""
        
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                result = self._scan_json_for_payloads(value, current_path)
                if result[0]:
                    return result
        
        elif isinstance(data, list):
            for i, item in enumerate(data):
                current_path = f"{path}[{i}]" if path else f"[{i}]"
                result = self._scan_json_for_payloads(item, current_path)
                if result[0]:
                    return result
        
        elif isinstance(data, str):
            if is_xss_payload(data):
                return data, path
        
        return None, None
    
    def _check_payload_reflection(self, payload: str, response_body: str) -> bool:
        """Check if payload is reflected in response"""
        # Direct reflection
        if payload in response_body:
            return True
        
        # URL-encoded reflection
        import urllib.parse
        encoded_payload = urllib.parse.quote(payload)
        if encoded_payload in response_body:
            return True
        
        # HTML-encoded reflection
        html_encoded = payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
        if html_encoded in response_body:
            return True
        
        return False
    
    def _track_payload(self, payload: str, url: str, session_id: Optional[str]):
        """Track payload for stored XSS detection"""
        self.payload_tracking[payload] = {
            'injection_url': url,
            'injection_time': datetime.now().isoformat(),
            'session_id': session_id
        }
        
        # Track by session
        if session_id:
            if session_id not in self.session_tracking:
                self.session_tracking[session_id] = []
            self.session_tracking[session_id].append(payload)
    
    def _check_for_stored_payloads(self, response_body: str, current_url: str) -> List[str]:
        """Check if any tracked payloads appear in this response (stored XSS)"""
        found_payloads = []
        
        for payload, tracking_info in self.payload_tracking.items():
            if payload in response_body:
                # Don't count immediate reflection as stored XSS
                if current_url != tracking_info['injection_url']:
                    found_payloads.append(payload)
                    self.logger.info(f"Stored XSS detected: payload injected at {tracking_info['injection_url']} found at {current_url}")
        
        return found_payloads
    
    def _analyze_dom_patterns(self, response_body: str) -> List[Dict[str, Any]]:
        """Analyze response for DOM manipulation patterns"""
        modifications = []
        
        # Check for JavaScript sinks
        for pattern in self.js_sink_patterns:
            matches = re.finditer(pattern, response_body, re.IGNORECASE)
            for match in matches:
                modifications.append({
                    'type': 'js_sink',
                    'pattern': pattern,
                    'match': match.group(),
                    'position': match.start()
                })
        
        # Check for JavaScript sources
        for pattern in self.js_source_patterns:
            matches = re.finditer(pattern, response_body, re.IGNORECASE)
            for match in matches:
                modifications.append({
                    'type': 'js_source',
                    'pattern': pattern,
                    'match': match.group(),
                    'position': match.start()
                })
        
        return modifications
    
    def _extract_and_cache_forms(self, html_content: str, base_url: str):
        """Extract forms from HTML and cache for future injection"""
        try:
            forms = extract_forms_from_html(html_content, base_url)
            if forms:
                self.logger.debug(f"Found {len(forms)} forms on {base_url}")
                # Could store these for later use by injection agents
        except Exception as e:
            self.logger.error(f"Error extracting forms: {e}")
    
    def get_intercepted_data(self) -> List[MITMInterceptionResult]:
        """Get all intercepted data"""
        return self.intercepted_data.copy()
    
    def get_payloads_for_session(self, session_id: str) -> List[str]:
        """Get all payloads injected in a session"""
        return self.session_tracking.get(session_id, [])
    
    def clear_tracking_data(self):
        """Clear all tracking data"""
        self.intercepted_data.clear()
        self.payload_tracking.clear()
        self.session_tracking.clear()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about intercepted traffic"""
        total_requests = len(self.intercepted_data)
        requests_with_payloads = sum(1 for r in self.intercepted_data if r.injected_payload)
        reflected_payloads = sum(1 for r in self.intercepted_data if r.payload_reflected)
        stored_payloads = sum(1 for r in self.intercepted_data if r.payload_stored)
        
        return {
            'total_requests': total_requests,
            'requests_with_payloads': requests_with_payloads,
            'reflected_payloads': reflected_payloads,
            'stored_payloads': stored_payloads,
            'unique_payloads_tracked': len(self.payload_tracking),
            'active_sessions': len(self.session_tracking)
        }