"""
Context-Aware XSS Tester
Uses reflection analysis + filter detection + LLM payload generation

This is the novel architecture for USENIX paper
"""

import logging
import asyncio
import uuid
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from playwright.async_api import async_playwright, Page, Browser

from ..analyzers.reflection_analyzer import ReflectionAnalyzer, ReflectionPoint, ReflectionContext
from ..analyzers.filter_detector import FilterDetector, FilterProfile
from ..analyzers.llm_payload_engine import LLMPayloadEngine, GeneratedPayload


logger = logging.getLogger(__name__)


@dataclass
class XSSVulnerability:
    """Confirmed XSS vulnerability"""
    url: str
    parameter: str
    payload: str
    context: str
    technique: str
    confidence: float
    screenshot_path: Optional[str] = None
    reasoning: str = ""
    flag: Optional[str] = None  # Captured flag if present in response


class ContextAwareXSSTester:
    """
    Novel XSS detection using:
    1. Reflection analysis - understand WHERE input lands
    2. Filter detection - understand WHAT is blocked
    3. LLM payload generation - understand HOW to bypass
    """

    def __init__(self, llm_client, cost_tracker=None):
        self.llm_client = llm_client
        self.cost_tracker = cost_tracker
        self.logger = logging.getLogger(__name__)

        # Initialize analyzers
        self.reflection_analyzer = ReflectionAnalyzer()
        self.filter_detector = FilterDetector()
        self.payload_engine = LLMPayloadEngine(llm_client, cost_tracker)

    async def test_reflected_xss(self,
                                url: str,
                                parameters: Dict[str, str],
                                method: str = "GET") -> List[XSSVulnerability]:
        """
        Test for reflected XSS using context-aware approach

        Flow:
        1. Send canary in each parameter
        2. Analyze where it's reflected
        3. Detect filters
        4. Generate context-aware payloads
        5. Test payloads
        6. Verify with real browser
        """
        self.logger.info(f"Starting context-aware XSS testing on {url}")
        print(f"        Starting context-aware XSS testing...")
        self.method = method  # Store method for use in other methods
        vulnerabilities = []

        for param_name, param_value in parameters.items():
            self.logger.info(f"\n{'='*70}")
            self.logger.info(f"Testing parameter: {param_name}")
            self.logger.info(f"{'='*70}")
            print(f"        Testing parameter: {param_name}")

            # Phase 1: Multi-Canary Injection (parallel testing to bypass filters)
            self.logger.info(f"Phase 1: Testing multiple canaries in parallel")
            print(f"        Phase 1: Testing multiple canaries to bypass filters...")

            try:
                # Test multiple canaries in parallel - finds one that bypasses filters
                canary, baseline_response, effective_method = await self._test_canaries_parallel(
                    url, param_name, method
                )

                if not canary:
                    self.logger.info(f"✗ Parameter '{param_name}' - no canary reflected (all blocked by filter)")
                    print(f"        ✗ Parameter '{param_name}' not reflected - all canaries blocked")
                    continue

                # Update method if it changed
                if effective_method != method:
                    method = effective_method
                    self.method = method

                print(f"        ✓ Canary '{canary}' reflected using {method}")

                # Phase 2: Reflection Analysis with the working canary
                self.logger.info("Phase 2: Analyzing reflections")
                reflections = self.reflection_analyzer.find_reflections(
                    baseline_response,
                    canary,
                    check_encoded=True
                )

                if not reflections:
                    self.logger.info(f"✗ Parameter '{param_name}' - canary detected but reflection analysis failed")
                    print(f"        ✗ Parameter '{param_name}' reflection analysis failed - skipping")
                    continue

                self.logger.info(f"✓ Found {len(reflections)} reflection points (using {method})")
                print(f"        ✓ Found {len(reflections)} reflection point(s)")

                # Phase 3: Filter Detection
                self.logger.info("Phase 3: Detecting filters")
                print(f"        Phase 2: Detecting filters...")
                filter_profile = await self.filter_detector.detect_filters(
                    lambda params: self._submit_request(url, {param_name: params.get(param_name, "")}, method),
                    param_name,
                    baseline_response
                )

                # Print filter report
                filter_report = self.filter_detector.generate_report(filter_profile)
                self.logger.info(f"\n{filter_report}")

                print(f"        Phase 2: Filter detection complete")

                # Phase 4: Test each reflection point
                for idx, reflection in enumerate(reflections):
                    self.logger.info(f"\n--- Reflection Point {idx+1}/{len(reflections)} ---")
                    self.logger.info(f"Context: {reflection.context.value}")
                    self.logger.info(f"Location: ...{reflection.context_before[-30:]}[HERE]{reflection.context_after[:30]}...")
                    print(f"        Reflection {idx+1}: Context = {reflection.context.value}")

                    # Phase 4: Generate context-aware payloads
                    self.logger.info("Phase 4: Generating LLM-based context-aware payloads")
                    print(f"        Phase 3: Generating LLM payloads...")
                    payloads = await self.payload_engine.generate_context_aware_payloads(
                        reflection,
                        filter_profile,
                        num_payloads=10
                    )

                    if not payloads:
                        self.logger.warning("LLM failed to generate payloads")
                        print(f"        ✗ LLM failed to generate payloads")
                        continue

                    self.logger.info(f"Generated {len(payloads)} payloads")
                    print(f"        ✓ Generated {len(payloads)} context-aware payloads")

                    # Phase 5: Test payloads
                    self.logger.info("Phase 5: Testing generated payloads")
                    print(f"        Phase 4: Testing {len(payloads)} payloads with browser...")

                    # Track if we found XSS and flag
                    first_successful_vuln = None
                    flag_found = False
                    payloads_after_xss = 0
                    MAX_PAYLOADS_AFTER_XSS = 5  # Try up to 5 more payloads after finding XSS without flag

                    for i, generated in enumerate(payloads, 1):
                        # If we already found XSS but no flag, limit additional attempts
                        if first_successful_vuln and not flag_found:
                            payloads_after_xss += 1
                            if payloads_after_xss > MAX_PAYLOADS_AFTER_XSS:
                                self.logger.info(f"  Stopping after {MAX_PAYLOADS_AFTER_XSS} more attempts (no flag found)")
                                print(f"        Tried {MAX_PAYLOADS_AFTER_XSS} more payloads, no flag - stopping")
                                break

                        self.logger.info(f"\nPayload {i}/{len(payloads)}:")
                        self.logger.info(f"  Payload: {generated.payload}")
                        self.logger.info(f"  Technique: {generated.technique}")
                        self.logger.info(f"  Confidence: {generated.confidence:.2f}")
                        self.logger.info(f"  Reasoning: {generated.reasoning}")
                        print(f"        Testing payload {i}/{len(payloads)}: {generated.payload[:50]}...")

                        # Test with real browser
                        success = await self._verify_xss_with_browser(
                            url,
                            {param_name: generated.payload}
                        )

                        if success:
                            self.logger.info(f"  🎉 SUCCESS! XSS Confirmed!")
                            print(f"        🎉 SUCCESS! XSS confirmed with payload {i}")

                            # Try to extract flag from response
                            print(f"        Attempting flag extraction...")
                            flag = await self._extract_flag(url, {param_name: generated.payload})
                            if flag:
                                self.logger.info(f"  🚩 FLAG CAPTURED: {flag}")
                                print(f"        🚩 FLAG: {flag}")
                                flag_found = True

                            vuln = XSSVulnerability(
                                url=url,
                                parameter=param_name,
                                payload=generated.payload,
                                context=reflection.context.value,
                                technique=generated.technique,
                                confidence=generated.confidence,
                                reasoning=generated.reasoning,
                                flag=flag
                            )

                            # Track first successful vuln, but keep best one (with flag)
                            if not first_successful_vuln:
                                first_successful_vuln = vuln
                                print(f"        (First XSS found, will try more payloads to capture flag)")

                            # If we found a flag, this is the best result - stop
                            if flag_found:
                                vulnerabilities.append(vuln)
                                print(f"        🎯 Flag captured! Stopping payload testing.")
                                break
                            else:
                                self.logger.info(f"  No flag - continuing to try more payloads...")
                                print(f"        (No flag yet, trying more payloads...)")
                        else:
                            self.logger.info(f"  ✗ Payload did not execute")
                            # Don't print every failed payload to reduce noise

                    # If we found XSS but no flag, add the first successful vuln
                    if first_successful_vuln and not flag_found:
                        vulnerabilities.append(first_successful_vuln)
                        print(f"        XSS confirmed but no flag captured (server may use different browser)")

            except Exception as e:
                self.logger.error(f"Error testing parameter '{param_name}': {e}")
                print(f"        ⚠️  Error testing parameter '{param_name}': {e}")
                import traceback
                self.logger.error(traceback.format_exc())
                continue

        self.logger.info(f"\n{'='*70}")
        self.logger.info(f"Testing complete: Found {len(vulnerabilities)} XSS vulnerabilities")
        self.logger.info(f"{'='*70}")
        print(f"        Testing complete: Found {len(vulnerabilities)} vulnerability(ies)")

        return vulnerabilities

    def _generate_canary(self) -> str:
        """Generate a unique canary marker (lowercase for compatibility)"""
        return f"xsstest{uuid.uuid4().hex[:8]}"

    def _generate_canary_set(self) -> List[Dict[str, str]]:
        """
        Generate multiple canaries designed to bypass different filters.
        Each canary avoids certain character classes that filters might block.
        """
        uid = uuid.uuid4().hex[:6]
        return [
            {"canary": f"xsstest{uid}", "name": "lowercase", "avoids": "uppercase"},
            {"canary": f"XSSTEST{uid.upper()}", "name": "uppercase", "avoids": "lowercase"},
            {"canary": f"zqtest{uid}", "name": "no_common_xss_chars", "avoids": "x,s,X,S"},
            {"canary": f"99887766{uid[:4]}", "name": "numeric_start", "avoids": "letters at start"},
            {"canary": f"test_{uid}", "name": "underscore", "avoids": "special chars"},
            {"canary": f"canary{uid}", "name": "simple_alpha", "avoids": "x,s,t keywords"},
            {"canary": f"qwerty{uid}", "name": "no_script_chars", "avoids": "s,c,r,i,p,t"},
            {"canary": f"aaabbb{uid}", "name": "repeated", "avoids": "diverse chars"},
        ]

    async def _test_canaries_parallel(self, url: str, param_name: str, method: str) -> tuple:
        """
        Test multiple canaries in parallel to find one that reflects.
        Returns (reflected_canary, response_text, method_used) or (None, None, None)
        """
        import asyncio

        canary_set = self._generate_canary_set()
        self.logger.info(f"Testing {len(canary_set)} canaries in parallel to bypass filters...")

        async def test_single_canary(canary_info, test_method):
            """Test a single canary with a specific method"""
            try:
                response = await self._submit_request(url, {param_name: canary_info["canary"]}, test_method)
                # Check if canary is reflected (exact match or encoded)
                if canary_info["canary"] in response.text:
                    return (canary_info, response.text, test_method, "exact")
                # Check URL encoded
                import urllib.parse
                if urllib.parse.quote(canary_info["canary"]) in response.text:
                    return (canary_info, response.text, test_method, "url_encoded")
                # Check HTML encoded
                import html
                if html.escape(canary_info["canary"]) in response.text:
                    return (canary_info, response.text, test_method, "html_encoded")
            except Exception as e:
                self.logger.debug(f"Canary {canary_info['name']} failed: {e}")
            return None

        # Test all canaries with primary method first
        tasks = [test_single_canary(c, method) for c in canary_set]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Check for successful reflection
        for result in results:
            if result and not isinstance(result, Exception):
                canary_info, response_text, method_used, encoding = result
                self.logger.info(f"✓ Canary '{canary_info['name']}' ({canary_info['canary']}) reflected ({encoding})!")
                return (canary_info["canary"], response_text, method_used)

        # Try alternate method if primary failed
        alt_method = "GET" if method.upper() == "POST" else "POST"
        self.logger.info(f"No canaries reflected with {method}, trying {alt_method}...")

        tasks = [test_single_canary(c, alt_method) for c in canary_set]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if result and not isinstance(result, Exception):
                canary_info, response_text, method_used, encoding = result
                self.logger.info(f"✓ Canary '{canary_info['name']}' ({canary_info['canary']}) reflected with {alt_method} ({encoding})!")
                return (canary_info["canary"], response_text, method_used)

        return (None, None, None)

    async def _submit_request(self, url: str, params: Dict[str, str], method: str = "GET"):
        """Submit HTTP request with parameters (supports GET and POST)"""
        try:
            from urllib.parse import urlencode

            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context()
                page = await context.new_page()

                if method.upper() == "POST":
                    # For POST, navigate to page first then submit form data
                    # Or use page.request for direct POST
                    response = await page.request.post(url, form=params)
                    text = await response.text()
                    status = response.status
                else:
                    # GET request with URL params
                    full_url = f"{url}?{urlencode(params)}" if params else url
                    response = await page.goto(full_url, wait_until="networkidle", timeout=10000)
                    text = await page.content()
                    status = response.status

                await browser.close()

                return type('Response', (), {'text': text, 'status': status})()

        except Exception as e:
            self.logger.error(f"Request failed: {e}")
            raise

    async def _verify_xss_with_browser(self, url: str, params: Dict[str, str], method: str = None) -> bool:
        """
        Verify XSS execution with real browser (Playwright)

        Returns True if JavaScript executed
        """
        # Use stored method if not specified
        if method is None:
            method = getattr(self, 'method', 'GET')

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context()
                page = await context.new_page()

                # Track if alert/prompt/confirm was triggered
                js_executed = False

                async def dialog_handler(dialog):
                    nonlocal js_executed
                    js_executed = True
                    await dialog.dismiss()

                page.on("dialog", lambda d: asyncio.create_task(dialog_handler(d)))

                from urllib.parse import urlencode

                if method.upper() == "POST":
                    # For POST, use page.request.post and then set content
                    try:
                        response = await page.request.post(url, form=params)
                        html_content = await response.text()
                        # Create a new page and set the content directly
                        await page.set_content(html_content)
                        await asyncio.sleep(2)  # Wait for any scripts to execute
                    except Exception as post_err:
                        self.logger.error(f"POST request failed: {post_err}")
                        # Fallback: try to find and fill the form
                        await page.goto(url, wait_until="networkidle", timeout=10000)
                        for param_name, param_value in params.items():
                            try:
                                await page.fill(f'input[name="{param_name}"]', param_value)
                            except:
                                pass
                        try:
                            await page.click('input[type="submit"], button[type="submit"], button:not([type])')
                            await asyncio.sleep(2)
                        except:
                            pass
                else:
                    # GET request
                    full_url = f"{url}?{urlencode(params)}"
                    try:
                        await page.goto(full_url, wait_until="networkidle", timeout=10000)
                    except Exception:
                        pass

                await asyncio.sleep(2)  # Let JS execute

                await browser.close()
                return js_executed

        except Exception as e:
            self.logger.error(f"Browser verification error: {e}")
            return False

    async def _extract_flag(self, url: str, params: Dict[str, str], method: str = None) -> Optional[str]:
        """
        Extract flag from response after successful XSS

        Looks for common flag patterns in the response body
        """
        # Use stored method if not specified
        if method is None:
            method = getattr(self, 'method', 'GET')

        import re
        try:
            self.logger.info(f"Extracting flag from {url} with method {method}")
            response = await self._submit_request(url, params, method)
            text = response.text

            # Debug: Log a snippet of the response to see what we got
            self.logger.info(f"Response length: {len(text)} chars")

            # Look for flag-related content in response
            if 'flag' in text.lower() or 'congratulations' in text.lower():
                self.logger.info(f"Found flag-related content in response!")
                # Find and log the relevant portion
                for keyword in ['flag', 'Flag', 'FLAG', 'Congratulations']:
                    idx = text.find(keyword)
                    if idx != -1:
                        snippet = text[max(0, idx-20):min(len(text), idx+100)]
                        self.logger.info(f"Context around '{keyword}': ...{snippet}...")
                        print(f"        Found '{keyword}' in response: ...{snippet[:80]}...")

            # Common flag patterns
            patterns = [
                r'FLAG\{[^}]+\}',           # FLAG{...}
                r'flag\{[^}]+\}',           # flag{...}
                r'CTF\{[^}]+\}',            # CTF{...}
                r'Here is the flag:\s*([^\s<]+)',  # "Here is the flag: XXX"
                r'flag:\s*([^\s<]+)',       # "flag: XXX"
                r'secret:\s*([^\s<]+)',     # "secret: XXX"
                r'xben[_-]?\d+[_-]?\d*[_-]?flag',  # XBEN flag format
            ]

            for pattern in patterns:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    # Return the full match or group 1 if available
                    result = match.group(0) if match.lastindex is None else match.group(1)
                    self.logger.info(f"Found flag with pattern '{pattern}': {result}")
                    return result

            self.logger.info("No flag pattern matched in response")
            return None

        except Exception as e:
            self.logger.error(f"Flag extraction error: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
            return None

    async def test_stored_xss(self,
                             url: str,
                             form_data: Dict[str, str],
                             verification_urls: List[str]) -> List[XSSVulnerability]:
        """
        Test for stored XSS

        Similar flow but also checks verification URLs after submission
        """
        self.logger.info(f"Testing stored XSS on {url}")
        # Similar implementation to reflected, but with form submission
        # and checking multiple pages for execution
        pass

    def generate_report(self, vulnerabilities: List[XSSVulnerability]) -> str:
        """Generate detailed vulnerability report"""
        report = ["=" * 70]
        report.append("CONTEXT-AWARE XSS DETECTION REPORT")
        report.append("=" * 70)

        report.append(f"\n✓ Total Vulnerabilities Found: {len(vulnerabilities)}\n")

        for idx, vuln in enumerate(vulnerabilities, 1):
            report.append(f"\n--- Vulnerability {idx} ---")
            report.append(f"URL: {vuln.url}")
            report.append(f"Parameter: {vuln.parameter}")
            report.append(f"Context: {vuln.context}")
            report.append(f"Technique: {vuln.technique}")
            report.append(f"Confidence: {vuln.confidence:.2f}")
            report.append(f"\nPayload:")
            report.append(f"  {vuln.payload}")
            report.append(f"\nReasoning:")
            report.append(f"  {vuln.reasoning}")
            if vuln.flag:
                report.append(f"\n🚩 FLAG CAPTURED:")
                report.append(f"  {vuln.flag}")
            report.append("")

        report.append("=" * 70)

        return "\n".join(report)
