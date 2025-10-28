"""
Agent Memory Manager

Provides high-level memory interface for agents with:
- Short-term (session) memory
- Long-term (persistent) memory
- Automatic learning from attempts
- Smart recall and recommendations
"""

import time
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse
from datetime import datetime
from .memory_storage import MemoryStorage


class MemoryManager:
    """
    High-level memory manager for agents
    Combines short-term session memory with long-term persistent storage
    """

    def __init__(
        self,
        session_id: str,
        target_url: str,
        db_path: str = "memory/agent_memory.db",
        enabled: bool = True
    ):
        """
        Initialize memory manager

        Args:
            session_id: Current session ID
            target_url: Target URL being tested
            db_path: Path to SQLite database
            enabled: Enable/disable memory system
        """
        self.session_id = session_id
        self.target_url = target_url
        self.target_domain = urlparse(target_url).netloc
        self.enabled = enabled

        # Initialize storage
        self.storage = MemoryStorage(db_path) if enabled else None

        # Short-term session memory (in-memory)
        self.session_memory = {
            'tested_payloads': {},  # payload -> result
            'detected_filters': set(),
            'attempted_strategies': [],
            'start_time': time.time(),
            'success_count': 0,
            'failure_count': 0
        }

    def remember_attempt(
        self,
        payload: str,
        payload_type: str,
        strategy: str,
        success: bool,
        transformation: Optional[str] = None,
        detected_filter: Optional[str] = None,
        confidence: float = 0.5
    ) -> None:
        """
        Remember a payload attempt in both short-term and long-term memory

        Args:
            payload: The payload that was tested
            payload_type: Type of payload (xss, sqli, etc)
            strategy: Strategy used
            success: Whether it succeeded
            transformation: How the payload was transformed
            detected_filter: Filter that was detected
            confidence: Confidence score
        """
        if not self.enabled:
            return

        # Short-term memory
        self.session_memory['tested_payloads'][payload] = {
            'success': success,
            'transformation': transformation,
            'detected_filter': detected_filter,
            'strategy': strategy,
            'timestamp': datetime.now().isoformat()
        }

        if success:
            self.session_memory['success_count'] += 1
        else:
            self.session_memory['failure_count'] += 1

        if detected_filter:
            self.session_memory['detected_filters'].add(detected_filter)

        # Long-term memory
        if self.storage:
            self.storage.record_payload_attempt(
                session_id=self.session_id,
                target_url=self.target_url,
                payload=payload,
                payload_type=payload_type,
                strategy=strategy,
                success=success,
                transformation=transformation,
                detected_filter=detected_filter,
                confidence=confidence
            )

            # Record detected filter
            if detected_filter:
                self.storage.record_detected_filter(
                    target_domain=self.target_domain,
                    filter_type=detected_filter,
                    filter_signature=transformation or payload
                )

            # Record successful bypass
            if success and detected_filter:
                self.storage.record_successful_bypass(
                    target_domain=self.target_domain,
                    filter_type=detected_filter,
                    bypass_technique=strategy,
                    payload_example=payload,
                    metadata={
                        'confidence': confidence,
                        'transformation': transformation
                    }
                )

    def was_payload_tested(self, payload: str) -> Optional[Dict[str, Any]]:
        """
        Check if payload was already tested in this session or previously

        Returns:
            Dict with previous result if found, None otherwise
        """
        if not self.enabled:
            return None

        # Check short-term memory first (current session)
        if payload in self.session_memory['tested_payloads']:
            return {
                'source': 'session',
                **self.session_memory['tested_payloads'][payload]
            }

        # Check long-term memory (previous sessions)
        if self.storage:
            result = self.storage.check_payload_tested(
                self.target_domain, payload
            )
            if result:
                return {
                    'source': 'history',
                    **result
                }

        return None

    def get_detected_filters(self) -> List[str]:
        """Get all detected filters (session + historical)"""
        if not self.enabled:
            return []

        filters = set(self.session_memory['detected_filters'])

        # Add historical filters
        if self.storage:
            historical = self.storage.get_detected_filters(self.target_domain)
            for filter_data in historical:
                filters.add(filter_data['filter_type'])

        return list(filters)

    def get_bypass_recommendations(
        self,
        filter_type: str,
        limit: int = 3
    ) -> List[Dict[str, Any]]:
        """
        Get recommended bypass techniques for a specific filter

        Args:
            filter_type: The filter type to bypass
            limit: Maximum number of recommendations

        Returns:
            List of recommended bypass techniques with effectiveness scores
        """
        if not self.enabled or not self.storage:
            return []

        bypasses = self.storage.get_effective_bypasses(
            filter_type=filter_type,
            min_effectiveness=0.3,
            limit=limit
        )

        return bypasses

    def get_similar_attempts(
        self,
        payload_type: Optional[str] = None,
        limit: int = 5
    ) -> List[Dict[str, Any]]:
        """Get similar previous attempts on this target"""
        if not self.enabled or not self.storage:
            return []

        return self.storage.get_similar_payloads(
            target_domain=self.target_domain,
            payload_type=payload_type,
            limit=limit
        )

    def learn_from_success(
        self,
        strategy: str,
        payload: str,
        time_elapsed: Optional[float] = None
    ) -> None:
        """
        Learn from a successful exploitation

        Args:
            strategy: Strategy that succeeded
            payload: Successful payload
            time_elapsed: Time to success in seconds
        """
        if not self.enabled or not self.storage:
            return

        # Update strategy effectiveness
        self.storage.update_strategy_effectiveness(
            strategy_name=strategy,
            target_type='generic',  # Could be made more specific
            success=True,
            time_to_success=time_elapsed
        )

    def learn_from_failure(self, strategy: str) -> None:
        """
        Learn from a failed attempt

        Args:
            strategy: Strategy that failed
        """
        if not self.enabled or not self.storage:
            return

        self.storage.update_strategy_effectiveness(
            strategy_name=strategy,
            target_type='generic',
            success=False
        )

    def get_strategy_recommendations(self, limit: int = 3) -> List[str]:
        """
        Get recommended strategies based on historical effectiveness

        Returns:
            List of strategy names ordered by effectiveness
        """
        if not self.enabled or not self.storage:
            return []

        strategies = self.storage.get_best_strategies(
            target_type='generic',
            limit=limit
        )

        return [s['strategy_name'] for s in strategies]

    def should_skip_payload(
        self,
        payload: str,
        skip_if_failed: bool = True
    ) -> Tuple[bool, Optional[str]]:
        """
        Determine if a payload should be skipped based on memory

        Args:
            payload: Payload to check
            skip_if_failed: Skip if previously failed

        Returns:
            (should_skip, reason)
        """
        if not self.enabled:
            return False, None

        previous = self.was_payload_tested(payload)

        if not previous:
            return False, None

        # Always skip if it already succeeded
        if previous.get('success'):
            return True, f"Already succeeded ({previous.get('source')})"

        # Skip if failed and skip_if_failed is True
        if skip_if_failed and not previous.get('success'):
            return True, f"Previously failed ({previous.get('source')})"

        return False, None

    def get_target_intelligence(self) -> Dict[str, Any]:
        """Get intelligence about the current target"""
        if not self.enabled or not self.storage:
            return {}

        intel = self.storage.get_target_intelligence(self.target_domain)
        if not intel:
            return {}

        return intel

    def update_target_intelligence(
        self,
        technology_stack: Optional[str] = None,
        waf_detected: Optional[str] = None,
        vulnerability_found: bool = False,
        notes: Optional[str] = None
    ) -> None:
        """Update intelligence about the current target"""
        if not self.enabled or not self.storage:
            return

        # Get current count
        current = self.get_target_intelligence()
        vuln_count = current.get('vulnerability_count', 0)

        if vulnerability_found:
            vuln_count += 1

        self.storage.update_target_intelligence(
            target_domain=self.target_domain,
            technology_stack=technology_stack,
            waf_detected=waf_detected,
            vulnerability_count=vuln_count,
            notes=notes
        )

    def get_session_summary(self) -> Dict[str, Any]:
        """Get summary of current session memory"""
        elapsed = time.time() - self.session_memory['start_time']

        return {
            'session_id': self.session_id,
            'target_domain': self.target_domain,
            'tested_payloads': len(self.session_memory['tested_payloads']),
            'success_count': self.session_memory['success_count'],
            'failure_count': self.session_memory['failure_count'],
            'detected_filters': list(self.session_memory['detected_filters']),
            'success_rate': (
                self.session_memory['success_count'] /
                (self.session_memory['success_count'] + self.session_memory['failure_count'])
                if (self.session_memory['success_count'] + self.session_memory['failure_count']) > 0
                else 0
            ),
            'elapsed_time': elapsed
        }

    def get_memory_insights(self) -> Dict[str, Any]:
        """
        Get actionable insights from memory

        Returns:
            Dictionary with insights and recommendations
        """
        if not self.enabled:
            return {'enabled': False}

        insights = {
            'enabled': True,
            'session_summary': self.get_session_summary(),
            'detected_filters': self.get_detected_filters(),
            'recommended_strategies': self.get_strategy_recommendations(limit=3),
            'target_intelligence': self.get_target_intelligence()
        }

        # Add bypass recommendations for each detected filter
        insights['bypass_recommendations'] = {}
        for filter_type in insights['detected_filters']:
            bypasses = self.get_bypass_recommendations(filter_type, limit=2)
            if bypasses:
                insights['bypass_recommendations'][filter_type] = bypasses

        return insights

    def export_session_memory(self) -> Dict[str, Any]:
        """Export current session memory for analysis"""
        return {
            'session_id': self.session_id,
            'target_url': self.target_url,
            'target_domain': self.target_domain,
            'start_time': datetime.fromtimestamp(
                self.session_memory['start_time']
            ).isoformat(),
            'tested_payloads': self.session_memory['tested_payloads'],
            'detected_filters': list(self.session_memory['detected_filters']),
            'statistics': self.get_session_summary()
        }

    def cleanup_old_memories(self, days: int = 90) -> int:
        """
        Clean up old memories from database

        Args:
            days: Remove memories older than this many days

        Returns:
            Number of records deleted
        """
        if not self.enabled or not self.storage:
            return 0

        return self.storage.cleanup_old_memories(days)

    def get_statistics(self) -> Dict[str, int]:
        """Get memory database statistics"""
        if not self.enabled or not self.storage:
            return {}

        return self.storage.get_statistics()

    def finalize_session(self) -> None:
        """Finalize session and clean up"""
        if not self.enabled:
            return

        # Update final target intelligence
        filters = self.get_detected_filters()
        if filters:
            self.update_target_intelligence(
                notes=f"Filters detected: {', '.join(filters)}"
            )

    def close(self):
        """Close memory manager and storage"""
        if self.storage:
            self.storage.close()


class MemoryAwareAgent:
    """
    Mixin class to add memory awareness to agents
    Provides methods for agents to interact with memory system
    """

    def __init__(self, *args, memory_manager: Optional[MemoryManager] = None, **kwargs):
        """Initialize with optional memory manager"""
        super().__init__(*args, **kwargs)
        self.memory = memory_manager

    def check_memory_before_testing(self, payload: str) -> Tuple[bool, Optional[str]]:
        """Check memory before testing a payload"""
        if not self.memory:
            return False, None

        return self.memory.should_skip_payload(payload, skip_if_failed=True)

    def remember_test_result(
        self,
        payload: str,
        payload_type: str,
        strategy: str,
        success: bool,
        **kwargs
    ) -> None:
        """Remember a test result"""
        if not self.memory:
            return

        self.memory.remember_attempt(
            payload=payload,
            payload_type=payload_type,
            strategy=strategy,
            success=success,
            **kwargs
        )

    def get_memory_recommendations(self) -> Dict[str, Any]:
        """Get recommendations from memory"""
        if not self.memory:
            return {}

        return self.memory.get_memory_insights()

    def recall_similar_attacks(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Recall similar attacks from memory"""
        if not self.memory:
            return []

        return self.memory.get_similar_attempts(limit=limit)
