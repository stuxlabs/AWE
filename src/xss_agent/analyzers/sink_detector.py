#!/usr/bin/env python3
"""
JavaScript Sink Detector and Analyzer

This module provides advanced detection and analysis of JavaScript sinks
that could be vulnerable to DOM-based XSS attacks.
"""

import json
import logging
import re
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, asdict


@dataclass
class SinkPattern:
    """Represents a dangerous sink pattern"""
    name: str
    pattern: str
    severity: str  # critical, high, medium, low
    description: str
    exploitation_notes: str
    bypass_techniques: List[str]


@dataclass
class DetectedSink:
    """Represents a detected sink in JavaScript code"""
    sink_name: str
    sink_type: str
    location: str  # file:line or context
    code_snippet: str
    severity: str
    confidence: float
    taint_analysis: Optional[Dict] = None


class SinkDetectorAnalyzer:
    """
    Advanced analyzer for detecting dangerous JavaScript sinks
    """

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)

        # Try to load AI client
        try:
            import sys
            from pathlib import Path
            sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
            from ..llm_client import get_llm_client
            self.ai_client = get_llm_client()
            self.has_ai = True
        except Exception as e:
            self.logger.warning(f"AI client not available: {e}")
            self.has_ai = False
            self.ai_client = None

        # Define sink patterns
        self.sink_patterns = self._initialize_sink_patterns()

    def _initialize_sink_patterns(self) -> List[SinkPattern]:
        """Initialize known dangerous sink patterns"""
        return [
            # Code execution sinks
            SinkPattern(
                name="eval",
                pattern=r'\beval\s*\(',
                severity="critical",
                description="Direct JavaScript code execution",
                exploitation_notes="Any user input reaching eval() can execute arbitrary JavaScript",
                bypass_techniques=[
                    "String concatenation to break static analysis",
                    "Indirect eval via Function constructor",
                    "setTimeout/setInterval with string argument"
                ]
            ),
            SinkPattern(
                name="Function constructor",
                pattern=r'\bnew\s+Function\s*\(',
                severity="critical",
                description="Dynamic function creation",
                exploitation_notes="Similar to eval, creates function from string",
                bypass_techniques=[
                    "Use Function('return ' + code)()",
                    "Stored XSS via function body injection"
                ]
            ),
            SinkPattern(
                name="setTimeout string",
                pattern=r'setTimeout\s*\(\s*["\']',
                severity="high",
                description="String argument to setTimeout",
                exploitation_notes="setTimeout with string evaluates as code",
                bypass_techniques=[
                    "Break out of string context",
                    "Use parentheses to inject additional code"
                ]
            ),
            SinkPattern(
                name="setInterval string",
                pattern=r'setInterval\s*\(\s*["\']',
                severity="high",
                description="String argument to setInterval",
                exploitation_notes="setInterval with string evaluates as code",
                bypass_techniques=[
                    "Similar to setTimeout bypasses",
                    "Repeated execution for persistence"
                ]
            ),

            # DOM manipulation sinks
            SinkPattern(
                name="innerHTML",
                pattern=r'\.innerHTML\s*=',
                severity="high",
                description="HTML injection via innerHTML",
                exploitation_notes="Unsanitized user input can inject HTML and execute scripts",
                bypass_techniques=[
                    "Use <img onerror=> for inline execution",
                    "SVG with <script> tags",
                    "Use <iframe src=javascript:> for inline code"
                ]
            ),
            SinkPattern(
                name="outerHTML",
                pattern=r'\.outerHTML\s*=',
                severity="high",
                description="HTML injection via outerHTML",
                exploitation_notes="Similar to innerHTML but replaces entire element",
                bypass_techniques=[
                    "Same as innerHTML bypasses",
                    "Replace critical elements for phishing"
                ]
            ),
            SinkPattern(
                name="document.write",
                pattern=r'document\.write\s*\(',
                severity="high",
                description="Direct document write",
                exploitation_notes="Can inject arbitrary HTML into document",
                bypass_techniques=[
                    "<script> tags work directly",
                    "Can inject entire pages"
                ]
            ),
            SinkPattern(
                name="insertAdjacentHTML",
                pattern=r'\.insertAdjacentHTML\s*\(',
                severity="high",
                description="Insert HTML at specified position",
                exploitation_notes="Injects HTML relative to element",
                bypass_techniques=[
                    "beforebegin/afterend to break out of context",
                    "Use event handlers in injected HTML"
                ]
            ),

            # jQuery sinks
            SinkPattern(
                name="jQuery.html",
                pattern=r'\$\([^)]*\)\.html\s*\(',
                severity="high",
                description="jQuery HTML injection",
                exploitation_notes="jQuery's html() method is equivalent to innerHTML",
                bypass_techniques=[
                    "Standard innerHTML bypasses",
                    "jQuery doesn't sanitize by default"
                ]
            ),
            SinkPattern(
                name="jQuery.append",
                pattern=r'\$\([^)]*\)\.append\s*\(',
                severity="medium",
                description="jQuery append HTML",
                exploitation_notes="Appends content which can include scripts",
                bypass_techniques=[
                    "Inject script tags",
                    "Use event handlers"
                ]
            ),

            # Location sinks
            SinkPattern(
                name="location.href assignment",
                pattern=r'location\.href\s*=',
                severity="high",
                description="Navigation via location.href",
                exploitation_notes="javascript: protocol can execute code",
                bypass_techniques=[
                    "javascript:alert(1)",
                    "data:text/html injection",
                    "Use for open redirect + XSS combo"
                ]
            ),
            SinkPattern(
                name="window.location assignment",
                pattern=r'window\.location\s*=',
                severity="high",
                description="Navigation via window.location",
                exploitation_notes="Same as location.href",
                bypass_techniques=[
                    "javascript: protocol",
                    "data: URLs"
                ]
            ),

            # React sinks
            SinkPattern(
                name="dangerouslySetInnerHTML",
                pattern=r'dangerouslySetInnerHTML\s*=',
                severity="critical",
                description="React's dangerous HTML injection",
                exploitation_notes="React's explicit unsafe HTML rendering",
                bypass_techniques=[
                    "Inject standard XSS payloads",
                    "React won't sanitize"
                ]
            ),

            # Vue sinks
            SinkPattern(
                name="v-html directive",
                pattern=r'v-html\s*=',
                severity="critical",
                description="Vue's HTML directive",
                exploitation_notes="Vue's raw HTML rendering",
                bypass_techniques=[
                    "Standard XSS payloads",
                    "Vue bypasses auto-escaping here"
                ]
            ),

            # Angular sinks
            SinkPattern(
                name="bypassSecurityTrust",
                pattern=r'bypassSecurityTrust',
                severity="critical",
                description="Angular security bypass",
                exploitation_notes="Explicitly bypasses Angular's security",
                bypass_techniques=[
                    "If user input reaches this, direct XSS",
                    "Check what's passed to bypassSecurityTrustHtml/Script"
                ]
            ),

            # Storage sinks
            SinkPattern(
                name="localStorage.setItem",
                pattern=r'localStorage\.setItem\s*\(',
                severity="low",
                description="Local storage write",
                exploitation_notes="Can persist XSS payload for later execution",
                bypass_techniques=[
                    "Inject payload to be read later",
                    "Combine with localStorage.getItem sink"
                ]
            ),
        ]

    def analyze_javascript_code(self, javascript_code: str, context: str = "unknown") -> List[DetectedSink]:
        """
        Analyze JavaScript code to detect dangerous sinks

        Args:
            javascript_code: JavaScript source code to analyze
            context: Context information (filename, URL, etc.)

        Returns:
            List of detected sinks
        """
        detected = []

        # Simple pattern matching
        for sink_pattern in self.sink_patterns:
            matches = re.finditer(sink_pattern.pattern, javascript_code, re.IGNORECASE)

            for match in matches:
                # Extract code snippet around the match
                start = max(0, match.start() - 50)
                end = min(len(javascript_code), match.end() + 50)
                snippet = javascript_code[start:end]

                # Calculate line number
                line_num = javascript_code[:match.start()].count('\n') + 1

                detected.append(DetectedSink(
                    sink_name=sink_pattern.name,
                    sink_type=sink_pattern.name,
                    location=f"{context}:{line_num}",
                    code_snippet=snippet,
                    severity=sink_pattern.severity,
                    confidence=0.8  # Pattern matching confidence
                ))

        # If AI available, enhance analysis
        if self.has_ai and self.ai_client and detected:
            detected = self._ai_enhance_sink_analysis(javascript_code, detected)

        return detected

    def _ai_enhance_sink_analysis(self, code: str, detected_sinks: List[DetectedSink]) -> List[DetectedSink]:
        """
        Use AI to enhance sink analysis with taint analysis
        """
        # Prepare context for AI
        sinks_summary = "\n".join([
            f"- {s.sink_name} at {s.location}: {s.code_snippet[:100]}"
            for s in detected_sinks[:10]  # Limit to first 10
        ])

        prompt = f"""
You are a security analyst performing taint analysis on JavaScript code.

DETECTED SINKS:
{sinks_summary}

JAVASCRIPT CODE SAMPLE:
{code[:2000]}

TASK: For each detected sink, determine:
1. Is user input (location.*, document.*, postMessage, etc.) flowing to this sink?
2. What is the data flow path from source to sink?
3. How confident are you that this is exploitable (0.0-1.0)?
4. What specific bypass techniques would work here?

RESPONSE FORMAT (JSON):
[
  {{
    "sink_name": "innerHTML",
    "location": "app.js:42",
    "taint_detected": true,
    "confidence": 0.9,
    "data_flow": ["location.hash", "decodeURIComponent", "element.innerHTML"],
    "exploitable": true,
    "bypass_suggestions": ["Use <img src=x onerror=alert(1)>", "Try <svg onload=alert(1)>"]
  }}
]

Analyze and respond with JSON only.
"""

        try:
            response = self.ai_client.simple_chat(
                model="claude-4-sonnet",
                message=prompt,
                temperature=0.3  # Lower temperature for analysis
            )

            # Parse response
            cleaned = self._clean_json_response(response)
            ai_analysis = json.loads(cleaned)

            # Enhance detected sinks with AI analysis
            for sink in detected_sinks:
                # Find matching analysis
                for analysis in ai_analysis:
                    if sink.sink_name in analysis.get('sink_name', ''):
                        sink.confidence = analysis.get('confidence', sink.confidence)
                        sink.taint_analysis = {
                            'taint_detected': analysis.get('taint_detected', False),
                            'data_flow': analysis.get('data_flow', []),
                            'exploitable': analysis.get('exploitable', False),
                            'bypass_suggestions': analysis.get('bypass_suggestions', [])
                        }
                        break

        except Exception as e:
            self.logger.error(f"AI enhancement failed: {e}")

        return detected_sinks

    def generate_exploitation_strategy(self, detected_sinks: List[DetectedSink]) -> Dict[str, Any]:
        """
        Generate exploitation strategy based on detected sinks

        Args:
            detected_sinks: List of detected sinks

        Returns:
            Dictionary with exploitation strategy
        """
        if not detected_sinks:
            return {
                'strategy': 'none',
                'reason': 'No dangerous sinks detected'
            }

        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        detected_sinks.sort(key=lambda s: severity_order.get(s.severity, 4))

        # Use AI to generate strategy if available
        if self.has_ai and self.ai_client:
            return self._ai_generate_strategy(detected_sinks)

        # Fallback template strategy
        primary_sink = detected_sinks[0]

        return {
            'strategy': 'template',
            'primary_target': primary_sink.sink_name,
            'severity': primary_sink.severity,
            'attack_vectors': [
                f"Target {primary_sink.sink_name} at {primary_sink.location}",
                "Test with standard XSS payloads",
                "Try framework-specific bypasses if applicable"
            ]
        }

    def _ai_generate_strategy(self, detected_sinks: List[DetectedSink]) -> Dict[str, Any]:
        """
        Use AI to generate sophisticated exploitation strategy
        """
        sinks_data = [
            {
                'sink': s.sink_name,
                'location': s.location,
                'severity': s.severity,
                'snippet': s.code_snippet[:100],
                'taint_analysis': s.taint_analysis
            }
            for s in detected_sinks[:5]
        ]

        prompt = f"""
You are an expert penetration tester creating an exploitation strategy.

DETECTED SINKS:
{json.dumps(sinks_data, indent=2)}

TASK: Create a prioritized exploitation strategy:
1. Which sink to target first and why
2. Specific payloads to try for each sink
3. Bypasses for common protections (CSP, WAF, sanitizers)
4. Fallback strategies if primary target fails

RESPONSE FORMAT (JSON):
{{
  "primary_target": {{
    "sink": "innerHTML",
    "location": "app.js:42",
    "reasoning": "Most direct path to XSS execution"
  }},
  "attack_sequence": [
    {{
      "step": 1,
      "action": "Test basic XSS payload in location.hash",
      "payload": "<img src=x onerror=alert(1)>",
      "expected_sink": "innerHTML"
    }},
    {{
      "step": 2,
      "action": "If blocked, try SVG-based payload",
      "payload": "<svg onload=alert(1)>",
      "expected_sink": "innerHTML"
    }}
  ],
  "bypasses": [
    "If CSP detected, try event handlers instead of script tags",
    "If sanitizer detected, try mutation-based payloads"
  ]
}}

Generate the strategy in JSON format.
"""

        try:
            response = self.ai_client.simple_chat(
                model="claude-4-sonnet",
                message=prompt,
                temperature=0.7
            )

            cleaned = self._clean_json_response(response)
            strategy = json.loads(cleaned)

            return strategy

        except Exception as e:
            self.logger.error(f"AI strategy generation failed: {e}")
            return {
                'strategy': 'fallback',
                'error': str(e)
            }

    def _clean_json_response(self, response: str) -> str:
        """Clean AI response to extract JSON - improved parsing"""
        if not response:
            return "{}"

        cleaned = response.strip()

        # Remove markdown code blocks
        if "```json" in cleaned:
            start = cleaned.find("```json") + 7
            end = cleaned.find("```", start)
            if end != -1:
                cleaned = cleaned[start:end].strip()
        elif "```" in cleaned:
            start = cleaned.find("```") + 3
            end = cleaned.find("```", start)
            if end != -1:
                cleaned = cleaned[start:end].strip()

        # Try to extract JSON by finding matching braces/brackets
        # First try array
        if '[' in cleaned:
            start = cleaned.find('[')
            # Count brackets to find the matching closing bracket
            bracket_count = 0
            in_string = False
            escape_next = False

            for i in range(start, len(cleaned)):
                char = cleaned[i]

                if escape_next:
                    escape_next = False
                    continue

                if char == '\\':
                    escape_next = True
                    continue

                if char == '"' and not escape_next:
                    in_string = not in_string
                    continue

                if not in_string:
                    if char == '[':
                        bracket_count += 1
                    elif char == ']':
                        bracket_count -= 1
                        if bracket_count == 0:
                            return cleaned[start:i+1]

        # Try object
        if '{' in cleaned:
            start = cleaned.find('{')
            # Count braces to find the matching closing brace
            brace_count = 0
            in_string = False
            escape_next = False

            for i in range(start, len(cleaned)):
                char = cleaned[i]

                if escape_next:
                    escape_next = False
                    continue

                if char == '\\':
                    escape_next = True
                    continue

                if char == '"' and not escape_next:
                    in_string = not in_string
                    continue

                if not in_string:
                    if char == '{':
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            return cleaned[start:i+1]

        return cleaned.strip()

    def get_sink_info(self, sink_name: str) -> Optional[SinkPattern]:
        """
        Get detailed information about a specific sink

        Args:
            sink_name: Name of the sink

        Returns:
            SinkPattern object with details
        """
        for pattern in self.sink_patterns:
            if pattern.name.lower() == sink_name.lower():
                return pattern
        return None

    def export_analysis(self, detected_sinks: List[DetectedSink], output_file: str):
        """
        Export sink analysis to JSON file

        Args:
            detected_sinks: List of detected sinks
            output_file: Output file path
        """
        analysis_data = {
            'timestamp': str(datetime.now()),
            'total_sinks': len(detected_sinks),
            'severity_breakdown': self._calculate_severity_breakdown(detected_sinks),
            'sinks': [asdict(s) for s in detected_sinks]
        }

        with open(output_file, 'w') as f:
            json.dump(analysis_data, f, indent=2, default=str)

        self.logger.info(f"Sink analysis exported to {output_file}")

    def _calculate_severity_breakdown(self, sinks: List[DetectedSink]) -> Dict[str, int]:
        """Calculate breakdown by severity"""
        breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

        for sink in sinks:
            severity = sink.severity.lower()
            if severity in breakdown:
                breakdown[severity] += 1

        return breakdown


# Example usage
if __name__ == "__main__":
    from datetime import datetime

    analyzer = SinkDetectorAnalyzer()

    # Example JavaScript code
    test_code = """
    function updatePage() {
        var hash = location.hash.substring(1);
        var element = document.getElementById('content');
        element.innerHTML = hash;  // Dangerous!
    }

    function jsonpCallback() {
        var callback = new URLSearchParams(location.search).get('callback');
        eval(callback + '()');  // Very dangerous!
    }
    """

    # Analyze
    detected = analyzer.analyze_javascript_code(test_code, "test.js")

    print(f"Detected {len(detected)} dangerous sinks:")
    for sink in detected:
        print(f"\n[{sink.severity.upper()}] {sink.sink_name}")
        print(f"  Location: {sink.location}")
        print(f"  Snippet: {sink.code_snippet}")
        print(f"  Confidence: {sink.confidence}")

    # Generate strategy
    strategy = analyzer.generate_exploitation_strategy(detected)
    print(f"\nExploitation Strategy:")
    print(json.dumps(strategy, indent=2))
