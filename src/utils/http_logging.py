#!/usr/bin/env python3
"""
HTTP Request/Response Logging Integration

This module provides enhanced HTTP logging capabilities that integrate with the
existing ProxyAgent and HTTP clients to provide comprehensive forensic audit trails.
"""

import asyncio
import json
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Union
from pathlib import Path

import httpx
from utils.forensic_logger import ForensicLoggerManager


class EnhancedHttpxClient:
    """
    Enhanced HTTP client wrapper that logs all requests/responses
    """
    
    def __init__(self, forensic_logger: ForensicLoggerManager, client: httpx.Client = None):
        """
        Initialize enhanced HTTP client
        
        Args:
            forensic_logger: ForensicLoggerManager instance
            client: Optional existing httpx.Client instance
        """
        self.forensic_logger = forensic_logger
        self.client = client or httpx.Client(timeout=30.0)
        self.request_counter = 0
    
    def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """
        Make HTTP request with comprehensive logging
        
        Args:
            method: HTTP method
            url: Request URL
            **kwargs: Additional request parameters
            
        Returns:
            Response object
        """
        self.request_counter += 1
        request_id = f"req_{self.request_counter}_{int(time.time() * 1000)}"
        
        # Prepare request data for logging
        request_data = {
            'id': request_id,
            'method': method.upper(),
            'url': url,
            'headers': dict(kwargs.get('headers', {})),
            'body': self._extract_body(kwargs),
            'timestamp': datetime.now().isoformat()
        }
        
        # Log request initiation
        self.forensic_logger.log_event('http.request.started', {
            'request_id': request_id,
            'method': method.upper(),
            'url': url,
            'headers_count': len(request_data['headers']),
            'has_body': bool(request_data['body'])
        })
        
        start_time = time.time()
        
        try:
            # Make the actual request
            response = self.client.request(method, url, **kwargs)
            
            # Prepare response data for logging
            response_data = {
                'id': request_id,
                'status': response.status_code,
                'headers': dict(response.headers),
                'body': response.text,
                'timestamp': datetime.now().isoformat(),
                'duration_ms': int((time.time() - start_time) * 1000)
            }
            
            # Log the complete request/response
            self.forensic_logger.log_http_request_response(
                request=request_data,
                response=response_data
            )
            
            # Log successful completion
            self.forensic_logger.log_event('http.request.completed', {
                'request_id': request_id,
                'status_code': response.status_code,
                'duration_ms': response_data['duration_ms'],
                'response_size_bytes': len(response.content)
            })
            
            return response
            
        except Exception as e:
            # Log request error
            error_data = {
                'id': request_id,
                'status': 0,
                'headers': {},
                'body': f"Request failed: {str(e)}",
                'timestamp': datetime.now().isoformat(),
                'duration_ms': int((time.time() - start_time) * 1000),
                'error': str(e)
            }
            
            self.forensic_logger.log_http_request_response(
                request=request_data,
                response=error_data
            )
            
            self.forensic_logger.log_event('http.request.error', {
                'request_id': request_id,
                'error': str(e),
                'error_type': type(e).__name__,
                'duration_ms': error_data['duration_ms']
            })
            
            raise
    
    def _extract_body(self, kwargs: Dict[str, Any]) -> str:
        """Extract request body from kwargs"""
        if 'content' in kwargs:
            content = kwargs['content']
            if isinstance(content, bytes):
                return content.decode('utf-8', errors='replace')
            return str(content)
        elif 'data' in kwargs:
            data = kwargs['data']
            if isinstance(data, dict):
                return json.dumps(data)
            elif isinstance(data, bytes):
                return data.decode('utf-8', errors='replace')
            return str(data)
        elif 'json' in kwargs:
            return json.dumps(kwargs['json'])
        
        return ""
    
    def get(self, url: str, **kwargs) -> httpx.Response:
        """Make GET request"""
        return self.request('GET', url, **kwargs)
    
    def post(self, url: str, **kwargs) -> httpx.Response:
        """Make POST request"""
        return self.request('POST', url, **kwargs)
    
    def put(self, url: str, **kwargs) -> httpx.Response:
        """Make PUT request"""
        return self.request('PUT', url, **kwargs)
    
    def delete(self, url: str, **kwargs) -> httpx.Response:
        """Make DELETE request"""
        return self.request('DELETE', url, **kwargs)
    
    def close(self):
        """Close the underlying HTTP client"""
        if hasattr(self.client, 'close'):
            self.client.close()
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()


class EnhancedProxyAgent:
    """
    Enhanced proxy agent wrapper that provides comprehensive HAR logging
    """
    
    def __init__(self, original_proxy_agent, forensic_logger: ForensicLoggerManager):
        """
        Initialize enhanced proxy agent
        
        Args:
            original_proxy_agent: Original ProxyAgent instance
            forensic_logger: ForensicLoggerManager instance
        """
        self.original = original_proxy_agent
        self.forensic_logger = forensic_logger
        
        # Store original methods
        self._original_start = original_proxy_agent.start
        self._original_stop = original_proxy_agent.stop
        self._original_get_captures = original_proxy_agent.get_captures
        self._original_replay_request = original_proxy_agent.replay_request
    
    def start(self) -> None:
        """Enhanced proxy start with logging"""
        self.forensic_logger.log_event('proxy.starting', {
            'bind_host': self.original.bind_host,
            'bind_port': self.original.bind_port,
            'whitelist': self.original.whitelist
        })
        
        try:
            # Call original start
            self._original_start()
            
            self.forensic_logger.log_event('proxy.started', {
                'proxy_url': self.original.get_proxy_url(),
                'capture_file': str(self.original.capture_file) if self.original.capture_file else None
            })
            
        except Exception as e:
            self.forensic_logger.log_event('proxy.start_failed', {
                'error': str(e),
                'error_type': type(e).__name__
            })
            raise
    
    def stop(self) -> None:
        """Enhanced proxy stop with final capture logging"""
        try:
            # Capture final HAR data before stopping
            if self.original.running:
                self.forensic_logger.log_event('proxy.stopping', {
                    'capture_file': str(self.original.capture_file) if self.original.capture_file else None
                })
                
                # Save final HAR file to our structure
                self._save_har_to_forensic_logs()
            
            # Call original stop
            self._original_stop()
            
            self.forensic_logger.log_event('proxy.stopped', {})
            
        except Exception as e:
            self.forensic_logger.log_event('proxy.stop_error', {
                'error': str(e),
                'error_type': type(e).__name__
            })
            # Don't re-raise, we want cleanup to continue
    
    def get_captures(self) -> List:
        """Enhanced get captures with logging"""
        try:
            captures = self._original_get_captures()
            
            self.forensic_logger.log_event('proxy.captures_retrieved', {
                'capture_count': len(captures),
                'capture_file': str(self.original.capture_file) if self.original.capture_file else None
            })
            
            # Log individual captures for forensic analysis
            for capture in captures:
                self._log_proxy_capture(capture)
            
            return captures
            
        except Exception as e:
            self.forensic_logger.log_event('proxy.captures_error', {
                'error': str(e),
                'error_type': type(e).__name__
            })
            raise
    
    def replay_request(self, entry_id: str, modified_request: Dict[str, Any] = None) -> Dict[str, Any]:
        """Enhanced replay with logging"""
        self.forensic_logger.log_event('proxy.replay_started', {
            'entry_id': entry_id,
            'has_modifications': modified_request is not None,
            'modifications': list(modified_request.keys()) if modified_request else []
        })
        
        try:
            # Call original replay
            result = self._original_replay_request(entry_id, modified_request)
            
            # Log the replay result
            self.forensic_logger.log_http_request_response(
                request=self._extract_request_from_replay(entry_id, modified_request),
                response=result
            )
            
            self.forensic_logger.log_event('proxy.replay_completed', {
                'entry_id': entry_id,
                'status': result.get('status', 0),
                'has_error': 'error' in result
            })
            
            return result
            
        except Exception as e:
            self.forensic_logger.log_event('proxy.replay_error', {
                'entry_id': entry_id,
                'error': str(e),
                'error_type': type(e).__name__
            })
            raise
    
    def _save_har_to_forensic_logs(self):
        """Save HAR file to forensic log structure"""
        if not self.original.capture_file or not self.original.capture_file.exists():
            return
        
        try:
            # Copy HAR file to our proxy directory
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            forensic_har_path = self.forensic_logger.current_run_dir / 'proxy' / f'capture_{timestamp}.har'
            
            # Copy the file
            with open(self.original.capture_file, 'r') as src:
                with open(forensic_har_path, 'w') as dst:
                    dst.write(src.read())
            
            self.forensic_logger.log_event('proxy.har_saved', {
                'original_path': str(self.original.capture_file),
                'forensic_path': str(forensic_har_path),
                'file_size_bytes': forensic_har_path.stat().st_size
            })
            
        except Exception as e:
            self.forensic_logger.log_event('proxy.har_save_error', {
                'error': str(e),
                'original_path': str(self.original.capture_file)
            })
    
    def _log_proxy_capture(self, capture):
        """Log individual proxy capture entry"""
        try:
            # Extract key information for logging
            request_data = {
                'id': capture.id,
                'method': capture.request.get('method', 'UNKNOWN'),
                'url': capture.request.get('url', ''),
                'headers': capture.request.get('headers', {}),
                'body': capture.request.get('body', ''),
                'timestamp': capture.timestamp
            }
            
            response_data = {
                'id': capture.id,
                'status': capture.response.get('status', 0),
                'headers': capture.response.get('headers', {}),
                'body': capture.response.get('body', ''),
                'timestamp': capture.timestamp
            }
            
            # Log the capture
            self.forensic_logger.log_http_request_response(
                request=request_data,
                response=response_data
            )
            
        except Exception as e:
            self.forensic_logger.log_event('proxy.capture_logging_error', {
                'capture_id': getattr(capture, 'id', 'unknown'),
                'error': str(e)
            })
    
    def _extract_request_from_replay(self, entry_id: str, modifications: Dict[str, Any] = None) -> Dict[str, Any]:
        """Extract request data for replay logging"""
        # Find the original capture entry
        for capture in self.original.captures:
            if capture.id == entry_id:
                request = capture.request.copy()
                
                # Apply modifications if provided
                if modifications:
                    request.update(modifications)
                
                return request
        
        # Fallback if entry not found
        return {
            'id': entry_id,
            'method': 'REPLAY',
            'url': 'unknown',
            'headers': modifications or {},
            'body': '',
            'timestamp': datetime.now().isoformat(),
            'is_replay': True,
            'original_entry_id': entry_id
        }
    
    # Delegate all other attributes to original
    def __getattr__(self, name):
        return getattr(self.original, name)


def enhance_http_client(client: httpx.Client, forensic_logger: ForensicLoggerManager) -> EnhancedHttpxClient:
    """
    Enhance an existing HTTP client with forensic logging
    
    Args:
        client: Existing httpx.Client instance
        forensic_logger: ForensicLoggerManager instance
        
    Returns:
        Enhanced HTTP client with logging capabilities
    """
    return EnhancedHttpxClient(forensic_logger, client)


def enhance_proxy_agent(proxy_agent, forensic_logger: ForensicLoggerManager) -> EnhancedProxyAgent:
    """
    Enhance an existing proxy agent with forensic logging
    
    Args:
        proxy_agent: Existing ProxyAgent instance
        forensic_logger: ForensicLoggerManager instance
        
    Returns:
        Enhanced proxy agent with comprehensive logging
    """
    return EnhancedProxyAgent(proxy_agent, forensic_logger)


class HttpRequestInterceptor:
    """
    Interceptor for monkey-patching existing HTTP libraries to add logging
    """
    
    def __init__(self, forensic_logger: ForensicLoggerManager):
        """
        Initialize HTTP request interceptor
        
        Args:
            forensic_logger: ForensicLoggerManager instance
        """
        self.forensic_logger = forensic_logger
        self.original_methods = {}
    
    def install(self):
        """Install HTTP interception on common libraries"""
        self._intercept_httpx()
        
    def uninstall(self):
        """Remove HTTP interception and restore original methods"""
        self._restore_httpx()
    
    def _intercept_httpx(self):
        """Intercept httpx requests"""
        try:
            import httpx
            
            # Store original method
            self.original_methods['httpx.Client.request'] = httpx.Client.request
            
            # Create wrapper
            def logged_request(self_client, method, url, **kwargs):
                # Create enhanced client temporarily
                enhanced = EnhancedHttpxClient(self.forensic_logger, self_client)
                return enhanced.request(method, url, **kwargs)
            
            # Monkey patch
            httpx.Client.request = logged_request
            
        except ImportError:
            pass  # httpx not available
    
    def _restore_httpx(self):
        """Restore original httpx methods"""
        if 'httpx.Client.request' in self.original_methods:
            import httpx
            httpx.Client.request = self.original_methods['httpx.Client.request']
    
    def __enter__(self):
        """Context manager entry"""
        self.install()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.uninstall()