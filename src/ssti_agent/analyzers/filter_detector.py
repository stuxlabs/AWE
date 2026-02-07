"""
SSTI Filter Detector - Detects WHAT is blocked (filters, WAFs, blacklists)
"""
from dataclasses import dataclass
from typing import List, Callable, Awaitable, Dict
import asyncio


@dataclass
class SSTIFilterProfile:
    """Profile of detected SSTI filters"""
    blocked_keywords: List[str]
    blocked_functions: List[str]
    blocked_attributes: List[str]
    blocked_imports: List[str]
    blocked_characters: List[str]
    waf_signature: str
    bypass_hints: List[str]
    strictness_level: str  # 'none', 'low', 'medium', 'high'


class SSTIFilterDetector:
    """Detects filters and WAFs blocking SSTI attempts"""

    def __init__(self):
        # Probe payloads to test for filters
        self.keyword_probes = [
            "eval", "exec", "system", "popen", "subprocess",
            "import", "os", "file", "open", "read"
        ]

        self.function_probes = [
            "__class__", "__bases__", "__subclasses__", "__globals__",
            "__init__", "__import__", "compile", "getattr", "setattr"
        ]

        self.attribute_probes = [
            "config", "request", "session", "app", "g", "self", "env"
        ]

        self.character_probes = [
            "'", '"', "[", "]", "(", ")", ".", "_", "{", "}"
        ]

    async def detect_filters(
        self,
        submit_func: Callable[[str], Awaitable[str]],
        baseline_response: str,
        parameter: str
    ) -> SSTIFilterProfile:
        """
        Detect what filters/WAFs are blocking SSTI attempts

        Args:
            submit_func: Async function to submit payloads
            baseline_response: Normal response for comparison
            parameter: Parameter being tested

        Returns:
            SSTIFilterProfile with detected filters
        """

        blocked_keywords = []
        blocked_functions = []
        blocked_attributes = []
        blocked_imports = []
        blocked_characters = []
        waf_signature = "none"
        bypass_hints = []

        print("    🔍 Testing for SSTI filters...")

        # Test keywords
        for keyword in self.keyword_probes:
            test_payload = f"{{{{'{keyword}'}}}}"  # Safe test that shouldn't execute
            try:
                response = await submit_func(test_payload)
                if self._is_blocked(response, baseline_response):
                    blocked_keywords.append(keyword)
                    print(f"      ❌ Keyword blocked: {keyword}")
            except Exception as e:
                # Exception might indicate WAF block
                blocked_keywords.append(keyword)

        # Test functions/attributes
        for func in self.function_probes:
            test_payload = f"{{{{x.{func}}}}}"
            try:
                response = await submit_func(test_payload)
                if self._is_blocked(response, baseline_response):
                    blocked_functions.append(func)
                    print(f"      ❌ Function blocked: {func}")
            except:
                blocked_functions.append(func)

        # Test attributes
        for attr in self.attribute_probes:
            test_payload = f"{{{{{attr}}}}}"
            try:
                response = await submit_func(test_payload)
                if self._is_blocked(response, baseline_response):
                    blocked_attributes.append(attr)
                    print(f"      ❌ Attribute blocked: {attr}")
            except:
                blocked_attributes.append(attr)

        # Test characters
        for char in self.character_probes:
            test_payload = f"test{char}test"
            try:
                response = await submit_func(test_payload)
                if self._is_blocked(response, baseline_response):
                    blocked_characters.append(char)
                    print(f"      ❌ Character blocked: {char}")
            except:
                blocked_characters.append(char)

        # Detect WAF signature
        waf_signature = self._detect_waf(blocked_keywords, blocked_functions)

        # Generate bypass hints
        bypass_hints = self._generate_bypass_hints(
            blocked_keywords, blocked_functions, blocked_attributes, blocked_characters
        )

        # Determine strictness
        total_blocked = len(blocked_keywords) + len(blocked_functions) + len(blocked_attributes)
        if total_blocked == 0:
            strictness = "none"
        elif total_blocked < 3:
            strictness = "low"
        elif total_blocked < 7:
            strictness = "medium"
        else:
            strictness = "high"

        profile = SSTIFilterProfile(
            blocked_keywords=blocked_keywords,
            blocked_functions=blocked_functions,
            blocked_attributes=blocked_attributes,
            blocked_imports=blocked_imports,
            blocked_characters=blocked_characters,
            waf_signature=waf_signature,
            bypass_hints=bypass_hints,
            strictness_level=strictness
        )

        self._print_filter_report(profile)

        return profile

    def _is_blocked(self, response: str, baseline: str) -> bool:
        """Check if response indicates blocking"""

        # WAF/filter indicators
        block_indicators = [
            "blocked", "denied", "forbidden", "not allowed",
            "security", "firewall", "waf", "filtered",
            "403", "406", "418", "invalid", "malicious"
        ]

        response_lower = response.lower()

        # Check for block indicators
        for indicator in block_indicators:
            if indicator in response_lower and indicator not in baseline.lower():
                return True

        # Check if response is significantly different (might indicate block)
        if len(response) < len(baseline) * 0.5:
            return True

        return False

    def _detect_waf(self, blocked_keywords: List[str], blocked_functions: List[str]) -> str:
        """Detect WAF based on blocking patterns"""

        if len(blocked_keywords) > 5 and len(blocked_functions) > 5:
            return "strict_waf"
        elif "eval" in blocked_keywords and "exec" in blocked_keywords:
            return "python_filter"
        elif "__class__" in blocked_functions and "__globals__" in blocked_functions:
            return "advanced_filter"
        elif len(blocked_keywords) > 0 or len(blocked_functions) > 0:
            return "basic_filter"

        return "none"

    def _generate_bypass_hints(
        self,
        blocked_keywords: List[str],
        blocked_functions: List[str],
        blocked_attributes: List[str],
        blocked_characters: List[str]
    ) -> List[str]:
        """Generate hints for bypassing detected filters"""

        hints = []

        if "eval" in blocked_keywords or "exec" in blocked_keywords:
            hints.append("Try: Using __import__ or getattr to access functions indirectly")

        if "__class__" in blocked_functions:
            hints.append("Try: Alternative attribute access like __mro__ or __base__")

        if "[" in blocked_characters or "]" in blocked_characters:
            hints.append("Try: Using __getitem__ or |attr filter instead of brackets")

        if "." in blocked_characters:
            hints.append("Try: Using |attr or [] notation instead of dots")

        if "_" in blocked_characters:
            hints.append("Try: Using hex encoding or request.args to pass underscores")

        if "import" in blocked_keywords:
            hints.append("Try: Using __import__ or __builtins__")

        if blocked_attributes:
            hints.append(f"Try: Accessing via indirect methods to avoid {', '.join(blocked_attributes)}")

        if not hints:
            hints.append("No significant filters detected - standard payloads should work")

        return hints

    def _print_filter_report(self, profile: SSTIFilterProfile):
        """Print filter detection report"""

        print("\n" + "="*70)
        print("SSTI FILTER DETECTION REPORT")
        print("="*70)

        print(f"\n📊 Filter Strictness: {profile.strictness_level.upper()}")
        print(f"🛡️  WAF Signature: {profile.waf_signature}")

        if profile.blocked_keywords:
            print(f"\n🚫 Blocked Keywords ({len(profile.blocked_keywords)}):")
            print(f"   {', '.join(profile.blocked_keywords)}")

        if profile.blocked_functions:
            print(f"\n🚫 Blocked Functions ({len(profile.blocked_functions)}):")
            print(f"   {', '.join(profile.blocked_functions)}")

        if profile.blocked_attributes:
            print(f"\n🚫 Blocked Attributes ({len(profile.blocked_attributes)}):")
            print(f"   {', '.join(profile.blocked_attributes)}")

        if profile.blocked_characters:
            print(f"\n🚫 Blocked Characters ({len(profile.blocked_characters)}):")
            print(f"   {', '.join(profile.blocked_characters)}")

        if profile.bypass_hints:
            print(f"\n💡 Bypass Hints:")
            for hint in profile.bypass_hints:
                print(f"   • {hint}")

        print("="*70 + "\n")
