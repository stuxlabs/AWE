"""
Transparent Agent Wrapper for Reasoning Transparency

Intercepts agent method calls and logs reasoning steps automatically.
Uses Python's __getattr__ magic method for transparent interception.
Integrates with memory system for smart decision-making.
"""

from typing import Any, Callable, Optional
from functools import wraps
import inspect
from .reasoning_tracker import ReasoningTracker


class TransparentAgent:
    """
    Wrapper class that intercepts agent method calls and logs reasoning steps

    This wrapper transparently adds reasoning transparency to any agent without
    requiring modifications to the agent's code. Optionally integrates with
    memory system for enhanced decision-making.
    """

    def __init__(
        self,
        agent: Any,
        reasoning_tracker: ReasoningTracker,
        session_id: str,
        log_methods: Optional[list] = None,
        memory_manager: Optional[Any] = None
    ):
        """
        Initialize transparent agent wrapper

        Args:
            agent: The agent instance to wrap
            reasoning_tracker: ReasoningTracker instance for logging
            session_id: Session ID for this agent's reasoning context
            log_methods: List of method names to log (None = log all public methods)
            memory_manager: Optional MemoryManager instance for agent memory
        """
        self._agent = agent
        self._reasoning_tracker = reasoning_tracker
        self._session_id = session_id
        self._log_methods = log_methods
        self._method_call_count = {}
        self._memory_manager = memory_manager

        # Inject memory into agent if it has a memory attribute
        if memory_manager and hasattr(agent, 'memory'):
            agent.memory = memory_manager

    def __getattr__(self, name: str) -> Any:
        """
        Intercept attribute access to wrap method calls with reasoning hooks

        This magic method is called when an attribute is accessed that doesn't
        exist on the wrapper itself, allowing transparent delegation to the
        wrapped agent while adding logging.
        """
        # Get the attribute from the wrapped agent
        attr = getattr(self._agent, name)

        # If it's not a callable or is a private method, return as-is
        if not callable(attr) or name.startswith('_'):
            return attr

        # If we have a whitelist and this method isn't in it, return unwrapped
        if self._log_methods is not None and name not in self._log_methods:
            return attr

        # Wrap the method with reasoning hooks
        @wraps(attr)
        def wrapper(*args, **kwargs):
            # Log method call as observation
            method_signature = self._get_method_signature(name, args, kwargs)
            self._log_method_entry(name, method_signature)

            try:
                # Execute the actual method
                result = attr(*args, **kwargs)

                # Log result
                self._log_method_exit(name, result, success=True)

                return result

            except Exception as e:
                # Log failure
                self._log_method_exit(name, str(e), success=False)
                raise

        return wrapper

    def _get_method_signature(self, method_name: str, args: tuple, kwargs: dict) -> str:
        """Generate a readable method signature for logging"""
        arg_strs = []

        # Add positional arguments
        for arg in args:
            arg_str = self._format_arg(arg)
            arg_strs.append(arg_str)

        # Add keyword arguments
        for key, value in kwargs.items():
            value_str = self._format_arg(value)
            arg_strs.append(f"{key}={value_str}")

        return f"{method_name}({', '.join(arg_strs)})"

    def _format_arg(self, arg: Any) -> str:
        """Format an argument for display (truncate if too long)"""
        if isinstance(arg, str):
            if len(arg) > 50:
                return f"'{arg[:47]}...'"
            return f"'{arg}'"
        elif isinstance(arg, (list, dict, tuple)):
            arg_str = str(arg)
            if len(arg_str) > 50:
                return f"{arg_str[:47]}..."
            return arg_str
        else:
            return str(arg)

    def _log_method_entry(self, method_name: str, signature: str) -> None:
        """Log when a method is called"""
        # Track method call count
        self._method_call_count[method_name] = self._method_call_count.get(method_name, 0) + 1
        call_number = self._method_call_count[method_name]

        # Log as observation
        self._reasoning_tracker.log_observation(
            self._session_id,
            f"Calling {signature}",
            context={
                "method": method_name,
                "call_number": call_number
            }
        )

    def _log_method_exit(self, method_name: str, result: Any, success: bool) -> None:
        """Log when a method completes"""
        if success:
            result_str = self._format_result(result)
            self._reasoning_tracker.log_result(
                self._session_id,
                f"Method {method_name} completed successfully",
                success=True,
                transformation=result_str
            )
        else:
            self._reasoning_tracker.log_result(
                self._session_id,
                f"Method {method_name} failed: {result}",
                success=False
            )

    def _format_result(self, result: Any) -> str:
        """Format a method result for display"""
        if result is None:
            return "None"
        elif isinstance(result, bool):
            return str(result)
        elif isinstance(result, (int, float)):
            return str(result)
        elif isinstance(result, str):
            if len(result) > 100:
                return f"{result[:97]}..."
            return result
        elif isinstance(result, (list, tuple)):
            if len(result) == 0:
                return "[]"
            return f"[{len(result)} items]"
        elif isinstance(result, dict):
            if len(result) == 0:
                return "{}"
            keys = list(result.keys())[:3]
            return f"{{keys: {keys}...}}"
        else:
            result_str = str(result)
            if len(result_str) > 100:
                return f"{result_str[:97]}..."
            return result_str

    def get_wrapped_agent(self) -> Any:
        """Get the underlying wrapped agent"""
        return self._agent

    def log_custom_observation(self, content: str, context: Optional[dict] = None) -> None:
        """Allow manual logging of observations"""
        self._reasoning_tracker.log_observation(self._session_id, content, context)

    def log_custom_hypothesis(self, content: str, confidence: float = 0.5, reasoning: str = None) -> None:
        """Allow manual logging of hypotheses"""
        self._reasoning_tracker.log_hypothesis(self._session_id, content, confidence, reasoning)

    def log_custom_action(self, content: str, payload: str = None, strategy: str = None) -> None:
        """Allow manual logging of actions"""
        self._reasoning_tracker.log_action(self._session_id, content, payload, strategy)

    def log_custom_result(self, content: str, success: bool, transformation: str = None, detected_filter: str = None) -> None:
        """Allow manual logging of results"""
        self._reasoning_tracker.log_result(self._session_id, content, success, transformation, detected_filter)

    def log_custom_analysis(
        self,
        content: str,
        detected_filters: list = None,
        next_strategy: str = None,
        confidence_adjustment: float = None
    ) -> None:
        """Allow manual logging of analysis"""
        self._reasoning_tracker.log_analysis(
            self._session_id, content, detected_filters, next_strategy, confidence_adjustment
        )


    def get_memory_manager(self) -> Optional[Any]:
        """Get the memory manager if available"""
        return self._memory_manager

    def check_memory(self, payload: str) -> Optional[dict]:
        """Check memory for previous attempts with this payload"""
        if not self._memory_manager:
            return None
        return self._memory_manager.was_payload_tested(payload)

    def get_memory_insights(self) -> dict:
        """Get insights from memory"""
        if not self._memory_manager:
            return {}
        return self._memory_manager.get_memory_insights()


def wrap_agent(
    agent: Any,
    reasoning_tracker: ReasoningTracker,
    agent_type: str,
    target: str,
    log_methods: Optional[list] = None,
    memory_manager: Optional[Any] = None
) -> TransparentAgent:
    """
    Convenience function to wrap an agent with reasoning transparency and memory

    Args:
        agent: The agent instance to wrap
        reasoning_tracker: ReasoningTracker instance
        agent_type: Type of agent (for logging)
        target: Target URL or identifier
        log_methods: Optional list of method names to log
        memory_manager: Optional MemoryManager instance

    Returns:
        TransparentAgent wrapper with reasoning and memory
    """
    session_id = reasoning_tracker.create_context(agent_type, target)
    return TransparentAgent(agent, reasoning_tracker, session_id, log_methods, memory_manager)
