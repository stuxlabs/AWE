"""
Concrete Analysis Stages

Implements the 4 core analysis stages:
1. Transformation Analysis - What happened to the payload?
2. Context Detection - Where did it land?
3. Protection Fingerprinting - What's blocking us?
4. Bypass Strategy - How to bypass?
"""

from typing import List, Dict, Any
from .base import AnalysisStage, AnalysisResult, TestAttempt
import difflib
import html
from urllib.parse import quote, unquote


class TransformationAnalysisStage(AnalysisStage):
    """
    Stage A: Analyzes how the payload was transformed in the response.

    Detects:
    - Character-level changes
    - Encoding applied (HTML, URL, JavaScript)
    - Characters stripped or replaced
    - Patterns in filtering
    """

    def get_stage_name(self) -> str:
        return "Transformation Analysis"

    async def analyze(
        self,
        attempt: TestAttempt,
        previous_results: List[AnalysisResult]
    ) -> AnalysisResult:
        """Analyze payload transformation"""

        self.logger.info(f"Analyzing transformation for payload: {attempt.payload[:50]}...")

        # Quick checks before LLM
        quick_analysis = self._quick_transformation_check(
            attempt.payload,
            attempt.response_html
        )

        prompt = self._build_prompt(
            payload=attempt.payload,
            response=attempt.response_html[:2000],
            quick_analysis=quick_analysis
        )

        try:
            response = await self._call_llm(prompt, temperature=0.5)
            data = self._parse_json_response(response)

            insights = []
            if data.get('transformation_detected'):
                insights.append(f"Transformation: {data.get('transformation_type')}")
            if data.get('encoding'):
                insights.append(f"Encoding: {', '.join(data.get('encoding'))}")
            if data.get('stripped_chars'):
                insights.append(f"Stripped: {', '.join(data.get('stripped_chars'))}")
            if data.get('filter_patterns'):
                insights.append(f"Patterns: {', '.join(data.get('filter_patterns')[:2])}")

            return AnalysisResult(
                stage_name=self.get_stage_name(),
                insights=insights or ["No transformation detected"],
                data=data,
                continue_analysis=data.get('continue_analysis', True),
                reasoning=data.get('reasoning', ''),
                confidence=data.get('confidence', 70)
            )

        except Exception as e:
            self.logger.error(f"Transformation analysis failed: {e}")
            return AnalysisResult(
                stage_name=self.get_stage_name(),
                insights=["Analysis failed"],
                data={'error': str(e)},
                continue_analysis=False,
                reasoning=f"Stage failed: {e}",
                error=str(e)
            )

    def _build_prompt(self, payload: str, response: str, quick_analysis: Dict) -> str:
        """Build prompt for transformation analysis"""
        return f"""
Analyze how this XSS payload was transformed in the response.

PAYLOAD SENT: {payload}

RESPONSE (first 2000 chars):
{response}

QUICK ANALYSIS:
- Payload found in response: {quick_analysis['found']}
- HTML encoding detected: {quick_analysis['html_encoded']}
- URL encoding detected: {quick_analysis['url_encoded']}
- Characters stripped: {quick_analysis['stripped_chars']}

TASK: Provide detailed transformation analysis.

Respond ONLY with JSON:
{{
  "transformation_detected": true/false,
  "transformation_type": "html_encoded|url_encoded|stripped|replaced|none",
  "encoding": ["list", "of", "encodings"],
  "stripped_chars": ["<", ">", "script"],
  "replaced_patterns": {{"from": "to"}},
  "filter_patterns": ["regex_pattern1", "pattern2"],
  "confidence": 0-100,
  "continue_analysis": true/false,
  "reasoning": "why continue or stop"
}}
"""

    def _quick_transformation_check(self, payload: str, response: str) -> Dict[str, Any]:
        """Quick transformation checks before LLM analysis"""
        result = {
            'found': payload in response,
            'html_encoded': False,
            'url_encoded': False,
            'stripped_chars': []
        }

        # Check HTML encoding
        html_encoded = html.escape(payload)
        if html_encoded != payload and html_encoded in response:
            result['html_encoded'] = True

        # Check URL encoding
        url_encoded = quote(payload)
        if url_encoded != payload and url_encoded in response:
            result['url_encoded'] = True

        # Check stripped characters
        dangerous_chars = ['<', '>', '"', "'", 'script', 'alert', 'onerror', 'onload']
        for char in dangerous_chars:
            if char.lower() in payload.lower() and char.lower() not in response.lower():
                result['stripped_chars'].append(char)

        return result


class ContextDetectionStage(AnalysisStage):
    """
    Stage B: Detects where the payload landed in the response.

    Detects:
    - HTML context (tag, attribute, text node)
    - JavaScript context (string, variable, code)
    - Execution context (can it execute?)
    - Surrounding code/markup
    """

    def get_stage_name(self) -> str:
        return "Context Detection"

    async def analyze(
        self,
        attempt: TestAttempt,
        previous_results: List[AnalysisResult]
    ) -> AnalysisResult:
        """Detect injection context"""

        self.logger.info("Detecting injection context...")

        # Get previous transformation data
        transformation_data = {}
        if previous_results:
            transformation_data = previous_results[0].data

        # Extract context window
        context_window = self._extract_context(attempt.payload, attempt.response_html)

        prompt = self._build_prompt(
            payload=attempt.payload,
            response=attempt.response_html[:2000],
            transformation_data=transformation_data,
            context_window=context_window
        )

        try:
            response = await self._call_llm(prompt, temperature=0.5)
            data = self._parse_json_response(response)

            insights = []
            if data.get('html_context'):
                insights.append(f"HTML: {data.get('html_context')}")
            if data.get('js_context'):
                insights.append(f"JS: {data.get('js_context')}")
            if data.get('can_execute'):
                insights.append("✓ Execution possible")
            else:
                insights.append("✗ Execution blocked")

            return AnalysisResult(
                stage_name=self.get_stage_name(),
                insights=insights,
                data=data,
                continue_analysis=data.get('continue_analysis', True),
                reasoning=data.get('reasoning', ''),
                confidence=data.get('confidence', 70)
            )

        except Exception as e:
            self.logger.error(f"Context detection failed: {e}")
            return AnalysisResult(
                stage_name=self.get_stage_name(),
                insights=["Context detection failed"],
                data={'error': str(e)},
                continue_analysis=False,
                reasoning=f"Stage failed: {e}",
                error=str(e)
            )

    def _build_prompt(
        self,
        payload: str,
        response: str,
        transformation_data: Dict,
        context_window: str
    ) -> str:
        """Build prompt for context detection"""
        return f"""
Analyze where this XSS payload landed in the response.

PAYLOAD: {payload}

TRANSFORMATION INFO: {transformation_data}

CONTEXT WINDOW (payload surroundings):
{context_window}

FULL RESPONSE (first 2000 chars):
{response}

TASK: Determine injection context and execution possibility.

Respond ONLY with JSON:
{{
  "html_context": "inside_tag|attribute|text_node|comment|none",
  "html_element": "div|script|input|etc",
  "attribute_name": "value|href|onclick|etc or null",
  "js_context": "string|variable|code|none",
  "js_quote_type": "single|double|backtick|none",
  "can_execute": true/false,
  "blocking_reason": "why execution blocked or null",
  "confidence": 0-100,
  "continue_analysis": true/false,
  "reasoning": "why continue or stop"
}}
"""

    def _extract_context(self, payload: str, response: str, window_size: int = 200) -> str:
        """Extract surrounding context where payload appears"""
        try:
            # Try to find payload or transformed version
            idx = response.find(payload)
            if idx == -1:
                # Try HTML encoded
                html_encoded = html.escape(payload)
                idx = response.find(html_encoded)

            if idx == -1:
                return "Payload not found in response"

            start = max(0, idx - window_size)
            end = min(len(response), idx + len(payload) + window_size)
            context = response[start:end]

            # Mark the payload location
            payload_in_context = payload if payload in context else html.escape(payload)
            context = context.replace(payload_in_context, f"<<<{payload_in_context}>>>")

            return context

        except Exception as e:
            return f"Error extracting context: {e}"


class ProtectionFingerprintingStage(AnalysisStage):
    """
    Stage C: Identifies protection mechanisms in place.

    Detects:
    - WAF signatures (ModSecurity, Cloudflare, etc.)
    - Filter rules (keyword blocking, pattern matching)
    - Sanitization functions
    - CSP policies
    """

    def get_stage_name(self) -> str:
        return "Protection Fingerprinting"

    async def analyze(
        self,
        attempt: TestAttempt,
        previous_results: List[AnalysisResult]
    ) -> AnalysisResult:
        """Fingerprint protection mechanisms"""

        self.logger.info("Fingerprinting protections...")

        # Extract data from previous stages
        transformation_data = previous_results[0].data if len(previous_results) > 0 else {}
        context_data = previous_results[1].data if len(previous_results) > 1 else {}

        # Check response headers for clues
        waf_headers = self._check_waf_headers(attempt.response_headers)

        prompt = self._build_prompt(
            payload=attempt.payload,
            transformation_data=transformation_data,
            context_data=context_data,
            headers=attempt.response_headers,
            waf_hints=waf_headers
        )

        try:
            response = await self._call_llm(prompt, temperature=0.5)
            data = self._parse_json_response(response)

            insights = []
            if data.get('waf_detected'):
                insights.append(f"WAF: {data.get('waf_signature')}")
            if data.get('filter_rules'):
                insights.append(f"Filters: {len(data.get('filter_rules'))} detected")
            if data.get('sanitization_function'):
                insights.append(f"Sanitizer: {data.get('sanitization_function')}")

            return AnalysisResult(
                stage_name=self.get_stage_name(),
                insights=insights or ["No specific protections detected"],
                data=data,
                continue_analysis=data.get('continue_analysis', True),
                reasoning=data.get('reasoning', ''),
                confidence=data.get('confidence', 60)
            )

        except Exception as e:
            self.logger.error(f"Protection fingerprinting failed: {e}")
            return AnalysisResult(
                stage_name=self.get_stage_name(),
                insights=["Fingerprinting failed"],
                data={'error': str(e)},
                continue_analysis=True,  # Continue anyway
                reasoning=f"Stage failed but continuing: {e}",
                error=str(e)
            )

    def _build_prompt(
        self,
        payload: str,
        transformation_data: Dict,
        context_data: Dict,
        headers: Dict,
        waf_hints: List[str]
    ) -> str:
        """Build prompt for protection fingerprinting"""
        return f"""
Identify protection mechanisms based on how the payload was handled.

PAYLOAD: {payload}

TRANSFORMATION DATA: {transformation_data}

CONTEXT DATA: {context_data}

RESPONSE HEADERS: {headers}

WAF HINTS: {waf_hints}

TASK: Fingerprint protection mechanisms.

Respond ONLY with JSON:
{{
  "waf_detected": true/false,
  "waf_signature": "ModSecurity|Cloudflare|Akamai|Imperva|Generic|Unknown",
  "waf_confidence": 0-100,
  "filter_rules": [
    {{"pattern": "regex or keyword", "type": "keyword|regex|character"}},
  ],
  "sanitization_function": "DOMPurify|encodeURI|custom|none",
  "csp_detected": true/false,
  "csp_policy": "policy string or null",
  "protection_level": "high|medium|low",
  "confidence": 0-100,
  "continue_analysis": true/false,
  "reasoning": "why continue or stop"
}}
"""

    def _check_waf_headers(self, headers: Dict[str, str]) -> List[str]:
        """Check headers for WAF signatures"""
        hints = []
        waf_headers = {
            'X-Sucuri-ID': 'Sucuri',
            'Server': 'cloudflare',
            'X-CDN': 'Cloudflare',
            'X-Akamai-Request-ID': 'Akamai',
            'X-Varnish': 'Varnish',
        }

        for header, waf_name in waf_headers.items():
            if header.lower() in [h.lower() for h in headers.keys()]:
                hints.append(waf_name)

        # Check server header
        server = headers.get('Server', '').lower()
        if 'cloudflare' in server:
            hints.append('Cloudflare')
        elif 'akamai' in server:
            hints.append('Akamai')

        return list(set(hints))


class BypassStrategyStage(AnalysisStage):
    """
    Stage D: Proposes specific bypass strategies.

    Based on all previous analysis, suggests:
    - Specific bypass techniques
    - Reasoning for why it should work
    - What protections it avoids
    - Confidence score
    """

    def get_stage_name(self) -> str:
        return "Bypass Strategy"

    async def analyze(
        self,
        attempt: TestAttempt,
        previous_results: List[AnalysisResult]
    ) -> AnalysisResult:
        """Propose bypass strategy"""

        self.logger.info("Generating bypass strategy...")

        # Compile all previous insights
        all_insights = []
        for result in previous_results:
            all_insights.extend(result.insights)

        prompt = self._build_prompt(
            payload=attempt.payload,
            all_results=previous_results,
            all_insights=all_insights
        )

        try:
            response = await self._call_llm(prompt, temperature=0.7)  # Higher temp for creativity
            data = self._parse_json_response(response)

            insights = []
            if data.get('bypass_technique'):
                insights.append(f"Technique: {data.get('bypass_technique')}")
            if data.get('confidence'):
                insights.append(f"Confidence: {data.get('confidence')}%")
            if data.get('payload_template'):
                insights.append(f"Template: {data.get('payload_template')[:50]}...")

            return AnalysisResult(
                stage_name=self.get_stage_name(),
                insights=insights,
                data=data,
                continue_analysis=False,  # This is the last stage
                reasoning=data.get('reasoning', ''),
                confidence=data.get('confidence', 50)
            )

        except Exception as e:
            self.logger.error(f"Bypass strategy failed: {e}")
            return AnalysisResult(
                stage_name=self.get_stage_name(),
                insights=["Strategy generation failed"],
                data={'error': str(e)},
                continue_analysis=False,
                reasoning=f"Stage failed: {e}",
                error=str(e)
            )

    def _build_prompt(
        self,
        payload: str,
        all_results: List[AnalysisResult],
        all_insights: List[str]
    ) -> str:
        """Build prompt for bypass strategy"""

        # Format previous results
        results_summary = ""
        for i, result in enumerate(all_results):
            results_summary += f"\n{result.stage_name}:\n"
            results_summary += f"  Insights: {', '.join(result.insights)}\n"
            results_summary += f"  Data: {result.data}\n"

        return f"""
Based on complete analysis, propose a bypass strategy.

FAILED PAYLOAD: {payload}

COMPLETE ANALYSIS:
{results_summary}

KEY INSIGHTS:
{chr(10).join(f"- {insight}" for insight in all_insights)}

TASK: Propose specific bypass that addresses identified protections.

Respond ONLY with JSON:
{{
  "bypass_technique": "descriptive name",
  "bypass_category": "encoding|obfuscation|alternative_function|context_breaking|protocol|mxss",
  "reasoning": "detailed explanation why this bypasses the protections",
  "avoids": ["protection1", "protection2"],
  "payload_template": "example payload structure",
  "specific_recommendations": ["rec1", "rec2"],
  "confidence": 0-100,
  "alternative_approaches": ["approach1", "approach2"],
  "continue_analysis": false,
  "reasoning": "Analysis complete"
}}
"""
