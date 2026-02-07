"""
Token and Cost Tracker for LLM API Calls

Tracks:
- Input/output tokens per call
- Total tokens across session
- API call count
- Time per call and total time
- Cost calculation

Pricing (configurable):
- Input: $0.003 per 1,000 tokens (default)
- Output: $0.015 per 1,000 tokens (default)
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
import threading


@dataclass
class APICall:
    """Single API call record"""
    timestamp: str
    tool_name: str
    model: str
    input_tokens: int
    output_tokens: int
    duration_ms: float
    success: bool
    error: Optional[str] = None

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'tool': self.tool_name,
            'model': self.model,
            'input_tokens': self.input_tokens,
            'output_tokens': self.output_tokens,
            'total_tokens': self.total_tokens,
            'duration_ms': self.duration_ms,
            'success': self.success,
            'error': self.error
        }


class TokenTracker:
    """
    Singleton token tracker for monitoring LLM API usage across the application.

    Usage:
        tracker = TokenTracker.get_instance()

        # Record a call
        tracker.record_call(
            tool_name="sqli_agent",
            model="claude-3-haiku",
            input_tokens=1500,
            output_tokens=500,
            duration_ms=2340.5
        )

        # Get summary
        print(tracker.get_summary())

        # Get cost
        print(f"Total cost: ${tracker.get_total_cost():.4f}")
    """

    _instance = None
    _lock = threading.Lock()

    # Default pricing (per 1,000 tokens)
    DEFAULT_INPUT_PRICE = 0.003   # $0.003 per 1K input tokens
    DEFAULT_OUTPUT_PRICE = 0.015  # $0.015 per 1K output tokens

    def __init__(self):
        self.calls: List[APICall] = []
        self.session_start = datetime.now()
        self.input_price_per_1k = self.DEFAULT_INPUT_PRICE
        self.output_price_per_1k = self.DEFAULT_OUTPUT_PRICE
        self._lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> 'TokenTracker':
        """Get singleton instance"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls):
        """Reset the tracker (useful for testing)"""
        with cls._lock:
            cls._instance = None

    def set_pricing(self, input_price_per_1k: float, output_price_per_1k: float):
        """Set custom pricing"""
        self.input_price_per_1k = input_price_per_1k
        self.output_price_per_1k = output_price_per_1k

    def record_call(self,
                    tool_name: str,
                    model: str,
                    input_tokens: int,
                    output_tokens: int,
                    duration_ms: float,
                    success: bool = True,
                    error: Optional[str] = None):
        """Record an API call"""
        call = APICall(
            timestamp=datetime.now().isoformat(),
            tool_name=tool_name,
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            duration_ms=duration_ms,
            success=success,
            error=error
        )
        with self._lock:
            self.calls.append(call)

    @property
    def total_input_tokens(self) -> int:
        """Total input tokens across all calls"""
        return sum(c.input_tokens for c in self.calls)

    @property
    def total_output_tokens(self) -> int:
        """Total output tokens across all calls"""
        return sum(c.output_tokens for c in self.calls)

    @property
    def total_tokens(self) -> int:
        """Total tokens (input + output)"""
        return self.total_input_tokens + self.total_output_tokens

    @property
    def total_duration_ms(self) -> float:
        """Total time spent on API calls"""
        return sum(c.duration_ms for c in self.calls)

    @property
    def total_duration_s(self) -> float:
        """Total time in seconds"""
        return self.total_duration_ms / 1000

    @property
    def call_count(self) -> int:
        """Number of API calls"""
        return len(self.calls)

    @property
    def successful_calls(self) -> int:
        """Number of successful calls"""
        return sum(1 for c in self.calls if c.success)

    @property
    def failed_calls(self) -> int:
        """Number of failed calls"""
        return sum(1 for c in self.calls if not c.success)

    def get_input_cost(self) -> float:
        """Calculate input token cost"""
        return (self.total_input_tokens / 1000) * self.input_price_per_1k

    def get_output_cost(self) -> float:
        """Calculate output token cost"""
        return (self.total_output_tokens / 1000) * self.output_price_per_1k

    def get_total_cost(self) -> float:
        """Calculate total cost"""
        return self.get_input_cost() + self.get_output_cost()

    def get_cost_by_tool(self) -> Dict[str, Dict[str, Any]]:
        """Get cost breakdown by tool"""
        tool_stats: Dict[str, Dict[str, Any]] = {}

        for call in self.calls:
            if call.tool_name not in tool_stats:
                tool_stats[call.tool_name] = {
                    'calls': 0,
                    'input_tokens': 0,
                    'output_tokens': 0,
                    'duration_ms': 0,
                    'cost': 0.0
                }

            stats = tool_stats[call.tool_name]
            stats['calls'] += 1
            stats['input_tokens'] += call.input_tokens
            stats['output_tokens'] += call.output_tokens
            stats['duration_ms'] += call.duration_ms

            # Calculate cost for this call
            input_cost = (call.input_tokens / 1000) * self.input_price_per_1k
            output_cost = (call.output_tokens / 1000) * self.output_price_per_1k
            stats['cost'] += input_cost + output_cost

        return tool_stats

    def get_summary(self) -> str:
        """Get human-readable summary"""
        lines = []
        lines.append("=" * 60)
        lines.append("LLM API USAGE SUMMARY")
        lines.append("=" * 60)

        # Session info
        session_duration = (datetime.now() - self.session_start).total_seconds()
        lines.append(f"Session Duration: {session_duration:.1f}s")
        lines.append("")

        # Call statistics
        lines.append("API Calls:")
        lines.append(f"  Total:      {self.call_count}")
        lines.append(f"  Successful: {self.successful_calls}")
        lines.append(f"  Failed:     {self.failed_calls}")
        lines.append("")

        # Token statistics
        lines.append("Token Usage:")
        lines.append(f"  Input:  {self.total_input_tokens:,} tokens")
        lines.append(f"  Output: {self.total_output_tokens:,} tokens")
        lines.append(f"  Total:  {self.total_tokens:,} tokens")
        lines.append("")

        # Time statistics
        lines.append("Time (API calls only):")
        lines.append(f"  Total: {self.total_duration_s:.2f}s")
        if self.call_count > 0:
            avg_ms = self.total_duration_ms / self.call_count
            lines.append(f"  Avg per call: {avg_ms:.0f}ms")
        lines.append("")

        # Cost breakdown
        lines.append("Cost Breakdown:")
        lines.append(f"  Input:  ${self.get_input_cost():.4f} ({self.total_input_tokens:,} tokens @ ${self.input_price_per_1k}/1K)")
        lines.append(f"  Output: ${self.get_output_cost():.4f} ({self.total_output_tokens:,} tokens @ ${self.output_price_per_1k}/1K)")
        lines.append(f"  ─────────────────")
        lines.append(f"  TOTAL:  ${self.get_total_cost():.4f}")
        lines.append("")

        # Per-tool breakdown
        tool_stats = self.get_cost_by_tool()
        if tool_stats:
            lines.append("Cost by Tool:")
            for tool, stats in sorted(tool_stats.items(), key=lambda x: x[1]['cost'], reverse=True):
                lines.append(f"  {tool}:")
                lines.append(f"    Calls: {stats['calls']}, Tokens: {stats['input_tokens'] + stats['output_tokens']:,}, Cost: ${stats['cost']:.4f}")

        lines.append("=" * 60)

        return "\n".join(lines)

    def get_compact_summary(self) -> str:
        """Get compact one-line summary"""
        return (f"API: {self.call_count} calls | "
                f"Tokens: {self.total_tokens:,} (in:{self.total_input_tokens:,}/out:{self.total_output_tokens:,}) | "
                f"Time: {self.total_duration_s:.1f}s | "
                f"Cost: ${self.get_total_cost():.4f}")

    def to_dict(self) -> Dict[str, Any]:
        """Export all data as dict"""
        return {
            'session_start': self.session_start.isoformat(),
            'pricing': {
                'input_per_1k': self.input_price_per_1k,
                'output_per_1k': self.output_price_per_1k
            },
            'summary': {
                'total_calls': self.call_count,
                'successful_calls': self.successful_calls,
                'failed_calls': self.failed_calls,
                'total_input_tokens': self.total_input_tokens,
                'total_output_tokens': self.total_output_tokens,
                'total_tokens': self.total_tokens,
                'total_duration_ms': self.total_duration_ms,
                'input_cost': self.get_input_cost(),
                'output_cost': self.get_output_cost(),
                'total_cost': self.get_total_cost()
            },
            'by_tool': self.get_cost_by_tool(),
            'calls': [c.to_dict() for c in self.calls]
        }


class TrackedTimer:
    """Context manager for timing operations"""

    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.duration_ms = 0

    def __enter__(self):
        self.start_time = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end_time = time.perf_counter()
        self.duration_ms = (self.end_time - self.start_time) * 1000
        return False


def track_llm_call(tool_name: str = "unknown"):
    """
    Decorator to track LLM API calls.

    The decorated function should return a dict with:
    - 'usage': {'input_tokens': X, 'output_tokens': Y} or
    - 'usage': {'prompt_tokens': X, 'completion_tokens': Y}

    Usage:
        @track_llm_call("sqli_agent")
        def call_llm(prompt):
            response = client.chat(...)
            return response
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            tracker = TokenTracker.get_instance()
            timer = TrackedTimer()

            with timer:
                try:
                    result = func(*args, **kwargs)

                    # Extract token usage from result
                    usage = result.get('usage', {}) if isinstance(result, dict) else {}
                    input_tokens = usage.get('input_tokens', usage.get('prompt_tokens', 0))
                    output_tokens = usage.get('output_tokens', usage.get('completion_tokens', 0))
                    model = result.get('model', 'unknown') if isinstance(result, dict) else 'unknown'

                    tracker.record_call(
                        tool_name=tool_name,
                        model=model,
                        input_tokens=input_tokens,
                        output_tokens=output_tokens,
                        duration_ms=timer.duration_ms,
                        success=True
                    )

                    return result

                except Exception as e:
                    tracker.record_call(
                        tool_name=tool_name,
                        model='unknown',
                        input_tokens=0,
                        output_tokens=0,
                        duration_ms=timer.duration_ms,
                        success=False,
                        error=str(e)
                    )
                    raise

        return wrapper
    return decorator


# Global convenience functions
def get_tracker() -> TokenTracker:
    """Get the global token tracker instance"""
    return TokenTracker.get_instance()


def record_call(tool_name: str, model: str, input_tokens: int, output_tokens: int,
                duration_ms: float, success: bool = True, error: str = None):
    """Record an API call to the global tracker"""
    get_tracker().record_call(tool_name, model, input_tokens, output_tokens,
                              duration_ms, success, error)


def get_summary() -> str:
    """Get summary from global tracker"""
    return get_tracker().get_summary()


def get_total_cost() -> float:
    """Get total cost from global tracker"""
    return get_tracker().get_total_cost()
