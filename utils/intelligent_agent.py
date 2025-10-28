"""
Intelligent Agent Base Class

Integrates reasoning transparency and memory into the agent pipeline.
Agents inherit from this to automatically get smart behavior.
"""

import time
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse

from utils.memory_manager import MemoryManager
from utils.reasoning_tracker import ReasoningTracker


class IntelligentAgent:
    """
    Base class for intelligent agents with memory and reasoning

    Features:
    - Automatic memory integration
    - Reasoning transparency at key points
    - Smart payload selection
    - Learning from results
    - Filter-aware testing
    """

    def __init__(
        self,
        memory_manager: Optional[MemoryManager] = None,
        reasoning_tracker: Optional[ReasoningTracker] = None,
        reasoning_session_id: Optional[str] = None
    ):
        """Initialize intelligent agent"""
        self.memory = memory_manager
        self.reasoning = reasoning_tracker
        self.reasoning_session = reasoning_session_id
        self.start_time = time.time()

        # Track current scan
        self.current_target = None
        self.payloads_tested = []
        self.successful_payloads = []
        self.detected_filters = set()

    def _log_observation(self, content: str, context: Optional[Dict] = None):
        """Log an observation with reasoning system"""
        if self.reasoning and self.reasoning_session:
            self.reasoning.log_observation(
                self.reasoning_session,
                content,
                context
            )

    def _log_hypothesis(self, content: str, confidence: float = 0.5, reasoning: str = None):
        """Log a hypothesis with reasoning system"""
        if self.reasoning and self.reasoning_session:
            self.reasoning.log_hypothesis(
                self.reasoning_session,
                content,
                confidence,
                reasoning
            )

    def _log_action(self, content: str, payload: str = None, strategy: str = None):
        """Log an action with reasoning system"""
        if self.reasoning and self.reasoning_session:
            self.reasoning.log_action(
                self.reasoning_session,
                content,
                payload,
                strategy
            )

    def _log_result(
        self,
        content: str,
        success: bool,
        transformation: str = None,
        detected_filter: str = None
    ):
        """Log a result with reasoning system"""
        if self.reasoning and self.reasoning_session:
            self.reasoning.log_result(
                self.reasoning_session,
                content,
                success,
                transformation,
                detected_filter
            )

    def _log_analysis(
        self,
        content: str,
        detected_filters: List[str] = None,
        next_strategy: str = None
    ):
        """Log an analysis with reasoning system"""
        if self.reasoning and self.reasoning_session:
            self.reasoning.log_analysis(
                self.reasoning_session,
                content,
                detected_filters,
                next_strategy
            )

    def should_test_payload(
        self,
        payload: str,
        payload_type: str = "xss"
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if payload should be tested based on memory

        Returns:
            (should_test, reason)
        """
        if not self.memory:
            return True, None

        # Check memory
        previous = self.memory.was_payload_tested(payload)

        if previous:
            # Already succeeded - skip
            if previous.get('success'):
                reason = f"Already succeeded (source: {previous['source']})"
                self._log_observation(
                    f"Skipping payload: {payload[:50]}...",
                    context={"reason": reason, "source": "memory"}
                )
                return False, reason

            # Already failed - check if we should retry
            if previous.get('detected_filter'):
                # If we know the filter, maybe try bypass
                filter_type = previous['detected_filter']
                bypasses = self.memory.get_bypass_recommendations(filter_type, limit=1)

                if bypasses:
                    reason = f"Known to fail but bypass available: {bypasses[0]['bypass_technique']}"
                    self._log_observation(
                        f"Payload failed before but bypass available",
                        context={"filter": filter_type, "bypass": bypasses[0]['bypass_technique']}
                    )
                    return True, reason
                else:
                    reason = f"Previously failed (filter: {filter_type})"
                    self._log_observation(
                        f"Skipping known failure: {payload[:50]}...",
                        context={"reason": reason, "filter": filter_type}
                    )
                    return False, reason

        return True, None

    def get_smart_payload_order(
        self,
        payloads: List[str],
        payload_type: str = "xss"
    ) -> List[str]:
        """
        Reorder payloads based on memory insights

        Prioritizes:
        1. Payloads similar to previous successes
        2. Bypasses for detected filters
        3. Recommended strategies
        4. Untested payloads
        5. Previously failed payloads (lowest priority)
        """
        if not self.memory:
            return payloads

        self._log_observation(
            "Using memory to optimize payload order",
            context={"total_payloads": len(payloads)}
        )

        scored_payloads = []

        for payload in payloads:
            score = 50  # Base score

            # Check memory
            previous = self.memory.was_payload_tested(payload)

            if previous:
                if previous.get('success'):
                    score = 100  # Highest priority - known success
                elif previous.get('detected_filter'):
                    score = 10  # Lowest priority - known failure
                else:
                    score = 20  # Low priority - failed but no filter detected
            else:
                score = 50  # Medium priority - untested

            # Boost score for bypass-related payloads
            for filter_type in self.detected_filters:
                bypasses = self.memory.get_bypass_recommendations(filter_type, limit=3)
                for bypass in bypasses:
                    if bypass['bypass_technique'] in payload.lower():
                        score += 30
                        break

            scored_payloads.append((score, payload))

        # Sort by score (highest first)
        scored_payloads.sort(key=lambda x: x[0], reverse=True)

        ordered = [p for _, p in scored_payloads]

        self._log_analysis(
            f"Reordered {len(payloads)} payloads based on memory",
            detected_filters=list(self.detected_filters)
        )

        return ordered

    def remember_test_result(
        self,
        payload: str,
        payload_type: str,
        strategy: str,
        success: bool,
        transformation: str = None,
        detected_filter: str = None,
        confidence: float = 0.8
    ):
        """Remember a payload test result"""
        # Track locally
        self.payloads_tested.append(payload)

        if success:
            self.successful_payloads.append(payload)

        if detected_filter:
            self.detected_filters.add(detected_filter)

        # Store in memory
        if self.memory:
            self.memory.remember_attempt(
                payload=payload,
                payload_type=payload_type,
                strategy=strategy,
                success=success,
                transformation=transformation,
                detected_filter=detected_filter,
                confidence=confidence
            )

            # Learn from result
            if success:
                elapsed = time.time() - self.start_time
                self.memory.learn_from_success(strategy, payload, elapsed)

                self._log_analysis(
                    f"Learned from successful {strategy} strategy",
                    next_strategy="continue_exploitation"
                )
            else:
                self.memory.learn_from_failure(strategy)

                if detected_filter:
                    self._log_analysis(
                        f"Detected filter: {detected_filter}",
                        detected_filters=[detected_filter],
                        next_strategy="try_bypass"
                    )

    def get_memory_insights(self) -> Dict[str, Any]:
        """Get insights from memory"""
        if not self.memory:
            return {}

        return self.memory.get_memory_insights()

    def get_recommended_strategies(self, limit: int = 3) -> List[str]:
        """Get recommended strategies from memory"""
        if not self.memory:
            return []

        strategies = self.memory.get_strategy_recommendations(limit)

        if strategies:
            self._log_observation(
                f"Memory recommends {len(strategies)} strategies",
                context={"strategies": strategies}
            )

        return strategies

    def get_bypass_recommendations(self, filter_type: str, limit: int = 3) -> List[Dict]:
        """Get bypass recommendations for a detected filter"""
        if not self.memory:
            return []

        bypasses = self.memory.get_bypass_recommendations(filter_type, limit)

        if bypasses:
            self._log_observation(
                f"Memory recalls {len(bypasses)} bypasses for {filter_type}",
                context={
                    "filter": filter_type,
                    "bypasses": [b['bypass_technique'] for b in bypasses]
                }
            )

            self._log_hypothesis(
                f"Bypasses may work based on {bypasses[0]['success_count']} previous successes",
                confidence=bypasses[0]['effectiveness_score']
            )

        return bypasses

    def detect_filter(
        self,
        payload: str,
        response: str,
        transformed: str = None
    ) -> Optional[str]:
        """
        Detect what filter blocked the payload

        Returns filter type or None
        """
        filter_type = None

        # Script tag blocked
        if '<script>' in payload.lower() and '&lt;script&gt;' in (transformed or response):
            filter_type = "script_tag_blocked"

        # Event handler blocked
        elif 'onerror' in payload.lower() and 'onerror' not in (transformed or response):
            filter_type = "event_handler_blocked"

        # HTML tags stripped
        elif '<' in payload and '<' not in (transformed or response):
            filter_type = "html_tags_stripped"

        # JavaScript protocol blocked
        elif 'javascript:' in payload.lower() and 'javascript:' not in (transformed or response):
            filter_type = "javascript_protocol_blocked"

        # Generic HTML encoding
        elif any(entity in (transformed or response) for entity in ['&lt;', '&gt;', '&quot;']):
            filter_type = "html_entity_encoding"

        if filter_type:
            self.detected_filters.add(filter_type)
            self._log_result(
                f"Filter detected: {filter_type}",
                success=False,
                transformation=transformed or response[:100],
                detected_filter=filter_type
            )

        return filter_type

    def announce_scan_start(self, target: str):
        """Announce scan start with memory insights"""
        self.current_target = target

        self._log_observation(
            f"Starting scan of {target}",
            context={"target": target, "timestamp": time.time()}
        )

        if self.memory:
            # Get insights
            insights = self.get_memory_insights()

            # Show what memory knows
            if insights.get('detected_filters'):
                filters = insights['detected_filters']
                self._log_observation(
                    f"Memory recalls {len(filters)} filters on this target",
                    context={"filters": filters}
                )

                # Get bypasses
                for filter_type in filters[:3]:  # Top 3
                    bypasses = self.get_bypass_recommendations(filter_type, limit=1)
                    if bypasses:
                        self._log_hypothesis(
                            f"For {filter_type}: try {bypasses[0]['bypass_technique']}",
                            confidence=bypasses[0]['effectiveness_score'],
                            reasoning=f"Worked {bypasses[0]['success_count']} times before"
                        )

            # Show recommended strategies
            strategies = self.get_recommended_strategies(limit=3)
            if strategies:
                self._log_hypothesis(
                    f"Recommended strategies: {', '.join(strategies)}",
                    confidence=0.7,
                    reasoning="Based on historical effectiveness"
                )

    def announce_scan_complete(self):
        """Announce scan completion with summary"""
        elapsed = time.time() - self.start_time

        success_rate = (
            len(self.successful_payloads) / len(self.payloads_tested)
            if self.payloads_tested else 0
        )

        self._log_analysis(
            f"Scan complete: {len(self.successful_payloads)}/{len(self.payloads_tested)} successful",
            detected_filters=list(self.detected_filters)
        )

        if self.memory:
            summary = self.memory.get_session_summary()

            self._log_observation(
                "Memory session summary",
                context={
                    "tested": summary['tested_payloads'],
                    "success_rate": f"{summary['success_rate']:.1%}",
                    "filters": len(summary['detected_filters']),
                    "elapsed": f"{elapsed:.2f}s"
                }
            )
