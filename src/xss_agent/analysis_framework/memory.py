"""
Global Memory Manager

Manages testing history with intelligent compression and context management.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime
import logging
import json

from .config import AnalysisConfig
from .summarizer import AnalysisSummarizer


@dataclass
class MemoryEntry:
    """
    A single entry in global memory.

    Stores compact summary instead of full analysis data.
    """
    attempt_number: int
    payload: str
    summary: str
    confidence: int
    success: bool
    timestamp: datetime = field(default_factory=datetime.now)
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        result = asdict(self)
        result['timestamp'] = self.timestamp.isoformat()
        return result


class GlobalMemoryManager:
    """
    Manages global testing history with compression.

    Features:
    - Stores summaries (not full data) for efficiency
    - Automatic compression when history grows too large
    - Pattern recognition across attempts
    - Smart retrieval for payload generation
    """

    def __init__(
        self,
        llm_client,
        config: Optional[AnalysisConfig] = None
    ):
        """
        Initialize memory manager.

        Args:
            llm_client: LLM client for summarization
            config: Configuration object
        """
        self.llm = llm_client
        self.config = config or AnalysisConfig.default()
        self.logger = logging.getLogger(self.__class__.__name__)

        self.history: List[MemoryEntry] = []
        self.compressed_history: List[str] = []  # Meta-summaries
        self.summarizer = AnalysisSummarizer(llm_client, config)

        self._success_patterns: List[str] = []
        self._failure_patterns: List[str] = []

    def add_entry(
        self,
        attempt_number: int,
        payload: str,
        summary: str,
        confidence: int,
        success: bool,
        meta: Optional[Dict] = None
    ) -> None:
        """
        Add a new entry to memory.

        Args:
            attempt_number: Sequential attempt number
            payload: The payload tested
            summary: Compact summary from analysis
            confidence: Confidence score (0-100)
            success: Whether payload succeeded
            meta: Optional metadata
        """
        entry = MemoryEntry(
            attempt_number=attempt_number,
            payload=payload,
            summary=summary,
            confidence=confidence,
            success=success,
            meta=meta or {}
        )

        self.history.append(entry)
        self.logger.debug(f"Added memory entry #{attempt_number}")

        # Track patterns
        if success:
            self._success_patterns.append(payload)
        else:
            self._failure_patterns.append(summary)

        # Check if compression needed
        if len(self.history) >= self.config.compression_threshold:
            self._compress_old_entries()

    async def _compress_old_entries(self) -> None:
        """
        Compress old entries to save memory.

        Takes old entries, creates meta-summary, and removes originals.
        """
        if len(self.history) < self.config.compression_threshold:
            return

        compress_count = self.config.compression_threshold // 2
        self.logger.info(f"Compressing {compress_count} old memory entries")

        # Get old entries
        old_entries = self.history[:compress_count]
        summaries = [e.summary for e in old_entries]

        try:
            # Create meta-summary
            meta_summary = await self.summarizer.meta_summarize(summaries)
            self.compressed_history.append(meta_summary)

            # Remove old entries
            self.history = self.history[compress_count:]

            self.logger.info(f"Compressed {compress_count} entries into meta-summary")

        except Exception as e:
            self.logger.error(f"Compression failed: {e}, keeping entries")

    def get_recent_context(self, count: int = 10) -> List[str]:
        """
        Get recent attempt summaries for context.

        Args:
            count: Number of recent entries to retrieve

        Returns:
            List of recent summaries
        """
        recent = self.history[-count:]
        return [e.summary for e in recent]

    def get_all_context(self) -> Dict[str, Any]:
        """
        Get complete context including compressed history.

        Returns:
            Dict with recent entries and meta-summaries
        """
        return {
            'compressed_history': self.compressed_history,
            'recent_attempts': [e.to_dict() for e in self.history],
            'total_attempts': len(self.history) + len(self.compressed_history) * (self.config.compression_threshold // 2),
            'success_count': len(self._success_patterns),
        }

    def get_successful_payloads(self) -> List[str]:
        """Get all successful payloads"""
        return self._success_patterns.copy()

    def get_recent_failures(self, count: int = 5) -> List[str]:
        """Get recent failure summaries"""
        failures = [e.summary for e in self.history if not e.success]
        return failures[-count:]

    def has_tried_payload(self, payload: str) -> bool:
        """Check if payload was already tried"""
        return any(e.payload == payload for e in self.history)

    def get_average_confidence(self, last_n: int = 5) -> int:
        """Get average confidence from recent attempts"""
        if not self.history:
            return 50

        recent = self.history[-last_n:]
        confidences = [e.confidence for e in recent if e.confidence > 0]

        if not confidences:
            return 50

        return sum(confidences) // len(confidences)

    async def analyze_patterns(self) -> Dict[str, Any]:
        """
        Use LLM to analyze patterns across all attempts.

        Returns:
            Dict with pattern analysis
        """
        if len(self.history) < 5:
            return {'status': 'insufficient_data'}

        self.logger.info("Analyzing patterns across all attempts")

        # Get all summaries
        all_summaries = [e.summary for e in self.history]

        prompt = f"""
Analyze patterns across these {len(all_summaries)} XSS testing attempts:

{chr(10).join(f"{i+1}. {s[:200]}" for i, s in enumerate(all_summaries[-20:]))}

Identify:
1. Recurring protections/failures
2. What consistently doesn't work
3. Patterns we haven't tried yet
4. Recommended strategy shift

Respond ONLY with JSON:
{{
  "recurring_protections": ["protection1", "protection2"],
  "consistent_failures": ["pattern1", "pattern2"],
  "untried_approaches": ["approach1", "approach2"],
  "recommended_shift": "specific recommendation",
  "confidence": 0-100
}}
"""

        try:
            # simple_chat is synchronous, not async
            response = self.llm.simple_chat(
                model="claude-4-sonnet",
                message=prompt,
                temperature=0.5
            )

            # Parse JSON
            import re
            if '{' in response:
                json_start = response.find('{')
                json_end = response.rfind('}') + 1
                json_str = response[json_start:json_end]
                return json.loads(json_str)

            return {'status': 'parse_error', 'raw': response[:500]}

        except Exception as e:
            self.logger.error(f"Pattern analysis failed: {e}")
            return {'status': 'error', 'error': str(e)}

    def save_to_file(self, filepath: str) -> None:
        """Save memory to JSON file"""
        data = {
            'history': [e.to_dict() for e in self.history],
            'compressed_history': self.compressed_history,
            'success_patterns': self._success_patterns,
            'config': self.config.to_dict(),
            'saved_at': datetime.now().isoformat()
        }

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)

        self.logger.info(f"Memory saved to {filepath}")

    def load_from_file(self, filepath: str) -> None:
        """Load memory from JSON file"""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)

            self.compressed_history = data.get('compressed_history', [])
            self._success_patterns = data.get('success_patterns', [])

            # Reconstruct history entries
            self.history = []
            for entry_dict in data.get('history', []):
                entry_dict['timestamp'] = datetime.fromisoformat(entry_dict['timestamp'])
                self.history.append(MemoryEntry(**entry_dict))

            self.logger.info(f"Memory loaded from {filepath}: {len(self.history)} entries")

        except Exception as e:
            self.logger.error(f"Failed to load memory: {e}")

    def clear(self) -> None:
        """Clear all memory"""
        self.history.clear()
        self.compressed_history.clear()
        self._success_patterns.clear()
        self._failure_patterns.clear()
        self.logger.info("Memory cleared")

    def get_stats(self) -> Dict[str, Any]:
        """Get memory statistics"""
        return {
            'total_entries': len(self.history),
            'compressed_batches': len(self.compressed_history),
            'successes': len(self._success_patterns),
            'avg_confidence': self.get_average_confidence(),
            'memory_size_bytes': len(json.dumps([e.to_dict() for e in self.history])),
        }
