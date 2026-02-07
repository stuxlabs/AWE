"""
Reasoning Transparency System for AutoHack

Implements Chain-of-Thought style logging that captures and displays
agent decision-making processes in real-time.
"""

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, asdict, field


@dataclass
class ReasoningStep:
    """Represents a single step in the reasoning chain"""
    step: int
    type: str  # observation, hypothesis, action, result, analysis
    content: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    context: Optional[Dict[str, Any]] = None
    confidence: Optional[float] = None
    reasoning: Optional[str] = None
    payload: Optional[str] = None
    strategy: Optional[str] = None
    success: Optional[bool] = None
    transformation: Optional[str] = None
    detected_filter: Optional[str] = None
    detected_filters: Optional[List[str]] = None
    next_strategy: Optional[str] = None
    confidence_adjustment: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, excluding None values"""
        data = asdict(self)
        return {k: v for k, v in data.items() if v is not None}


class ReasoningContext:
    """
    Tracks current decision state across agent operations
    Maintains the five-step decision cycle: observation → hypothesis → action → result → analysis
    """

    def __init__(self, session_id: str, agent_type: str, target: str):
        self.session_id = session_id
        self.agent_type = agent_type
        self.target = target
        self.reasoning_chain: List[ReasoningStep] = []
        self.current_step = 0
        self.metadata: Dict[str, Any] = {}

    def add_step(self, step: ReasoningStep) -> None:
        """Add a reasoning step to the chain"""
        self.reasoning_chain.append(step)

    def to_dict(self) -> Dict[str, Any]:
        """Convert context to dictionary for JSON serialization"""
        return {
            "session_id": self.session_id,
            "timestamp": datetime.utcnow().isoformat(),
            "agent_type": self.agent_type,
            "target": self.target,
            "reasoning_chain": [step.to_dict() for step in self.reasoning_chain],
            "metadata": self.metadata
        }


class ConsoleFormatter:
    """
    Formats reasoning steps for colored console output
    Provides structured, emoji-enhanced output for real-time visibility
    """

    COLORS = {
        'observation': '\033[96m',  # Cyan
        'hypothesis': '\033[95m',   # Magenta
        'action': '\033[93m',       # Yellow
        'result': '\033[92m',       # Green
        'result_fail': '\033[91m',  # Red
        'analysis': '\033[94m',     # Blue
        'reset': '\033[0m',         # Reset
        'bold': '\033[1m',          # Bold
        'dim': '\033[2m'            # Dim
    }

    EMOJIS = {
        'observation': '🔍',
        'hypothesis': '💭',
        'action': '⚡',
        'result': '✅',
        'result_fail': '❌',
        'analysis': '🧠'
    }

    def __init__(self, use_color: bool = True):
        self.use_color = use_color

    def format_step(self, step: ReasoningStep, agent_type: str) -> str:
        """Format a single reasoning step for console output"""
        if not self.use_color:
            return self._format_plain(step, agent_type)
        return self._format_colored(step, agent_type)

    def _format_colored(self, step: ReasoningStep, agent_type: str) -> str:
        """Format with colors and emojis"""
        lines = []

        # Header
        color = self.COLORS.get(step.type, self.COLORS['reset'])
        if step.type == 'result' and step.success is False:
            color = self.COLORS['result_fail']
            emoji = self.EMOJIS['result_fail']
        else:
            emoji = self.EMOJIS.get(step.type, '•')

        lines.append(f"{self.COLORS['bold']}[REASONING] {agent_type} - Step {step.step}{self.COLORS['reset']}")

        # Main content
        step_type_upper = step.type.upper()
        lines.append(f"├─ {emoji} {color}{step_type_upper}{self.COLORS['reset']}: {step.content}")

        # Additional details based on step type
        if step.type == 'observation' and step.context:
            if 'sources' in step.context:
                lines.append(f"│  └─ {self.COLORS['dim']}Sources: {step.context['sources']} | Sinks: {step.context.get('sinks', 'N/A')}{self.COLORS['reset']}")

        elif step.type == 'hypothesis':
            if step.confidence is not None:
                lines.append(f"│  └─ {self.COLORS['dim']}Confidence: {int(step.confidence * 100)}%{self.COLORS['reset']}")
            if step.reasoning:
                lines.append(f"│  └─ {self.COLORS['dim']}Reason: {step.reasoning}{self.COLORS['reset']}")

        elif step.type == 'action':
            if step.payload:
                lines.append(f"│  └─ {self.COLORS['dim']}Payload: {step.payload}{self.COLORS['reset']}")
            if step.strategy:
                lines.append(f"│  └─ {self.COLORS['dim']}Strategy: {step.strategy}{self.COLORS['reset']}")

        elif step.type == 'result':
            if step.transformation:
                lines.append(f"│  └─ {self.COLORS['dim']}Transform: {step.transformation}{self.COLORS['reset']}")
            if step.detected_filter:
                lines.append(f"│  └─ {self.COLORS['dim']}Filter: {step.detected_filter}{self.COLORS['reset']}")

        elif step.type == 'analysis':
            if step.detected_filters:
                lines.append(f"│  └─ {self.COLORS['dim']}Detected filters: {', '.join(step.detected_filters)}{self.COLORS['reset']}")
            if step.next_strategy:
                lines.append(f"└─ {self.COLORS['dim']}Next: {step.next_strategy}{self.COLORS['reset']}")

        return '\n'.join(lines)

    def _format_plain(self, step: ReasoningStep, agent_type: str) -> str:
        """Format without colors (for file output or non-TTY)"""
        lines = []
        lines.append(f"[REASONING] {agent_type} - Step {step.step}")
        lines.append(f"  {step.type.upper()}: {step.content}")

        if step.confidence is not None:
            lines.append(f"    Confidence: {int(step.confidence * 100)}%")
        if step.payload:
            lines.append(f"    Payload: {step.payload}")
        if step.strategy:
            lines.append(f"    Strategy: {step.strategy}")

        return '\n'.join(lines)


class JSONWriter:
    """
    Writes reasoning chains to structured JSON files
    Provides permanent logs for analysis and documentation
    """

    def __init__(self, output_dir: str = "logs/reasoning"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def write(self, context: ReasoningContext) -> Path:
        """Write reasoning context to JSON file"""
        filename = f"{context.session_id}_{context.agent_type}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = self.output_dir / filename

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(context.to_dict(), f, indent=2, ensure_ascii=False)

        return filepath


class ReasoningTracker:
    """
    Central reasoning chain collector and manager
    Coordinates logging, output formatting, and session management
    """

    def __init__(
        self,
        mode: str = "verbose",
        console_output: bool = True,
        json_output: bool = True,
        output_dir: str = "logs/reasoning",
        color_output: bool = True
    ):
        self.mode = mode
        self.console_output = console_output
        self.json_output = json_output
        self.color_output = color_output

        self.console_formatter = ConsoleFormatter(use_color=color_output)
        self.json_writer = JSONWriter(output_dir=output_dir) if json_output else None

        self.active_contexts: Dict[str, ReasoningContext] = {}

    def create_context(self, agent_type: str, target: str) -> str:
        """Create a new reasoning context and return its session ID"""
        session_id = str(uuid.uuid4())
        context = ReasoningContext(session_id, agent_type, target)
        self.active_contexts[session_id] = context
        return session_id

    def log_observation(
        self,
        session_id: str,
        content: str,
        context: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log an observation step"""
        self._log_step(session_id, "observation", content, context=context)

    def log_hypothesis(
        self,
        session_id: str,
        content: str,
        confidence: float = 0.5,
        reasoning: Optional[str] = None
    ) -> None:
        """Log a hypothesis step"""
        self._log_step(
            session_id, "hypothesis", content,
            confidence=confidence, reasoning=reasoning
        )

    def log_action(
        self,
        session_id: str,
        content: str,
        payload: Optional[str] = None,
        strategy: Optional[str] = None
    ) -> None:
        """Log an action step"""
        self._log_step(
            session_id, "action", content,
            payload=payload, strategy=strategy
        )

    def log_result(
        self,
        session_id: str,
        content: str,
        success: bool,
        transformation: Optional[str] = None,
        detected_filter: Optional[str] = None
    ) -> None:
        """Log a result step"""
        self._log_step(
            session_id, "result", content,
            success=success, transformation=transformation,
            detected_filter=detected_filter
        )

    def log_analysis(
        self,
        session_id: str,
        content: str,
        detected_filters: Optional[List[str]] = None,
        next_strategy: Optional[str] = None,
        confidence_adjustment: Optional[float] = None
    ) -> None:
        """Log an analysis step"""
        self._log_step(
            session_id, "analysis", content,
            detected_filters=detected_filters,
            next_strategy=next_strategy,
            confidence_adjustment=confidence_adjustment
        )

    def _log_step(self, session_id: str, step_type: str, content: str, **kwargs) -> None:
        """Internal method to log a reasoning step"""
        if session_id not in self.active_contexts:
            # Context already finalized - silently ignore
            # This can happen during cleanup or when logging after finalization
            return

        context = self.active_contexts[session_id]
        context.current_step += 1

        step = ReasoningStep(
            step=context.current_step,
            type=step_type,
            content=content,
            **kwargs
        )

        context.add_step(step)

        # Output to console if enabled
        if self.console_output and self.mode == "verbose":
            formatted = self.console_formatter.format_step(step, context.agent_type)
            print(formatted)
            print()  # Empty line for readability

    def finalize_context(self, session_id: str) -> Optional[Path]:
        """
        Finalize a reasoning context and write to JSON if enabled
        Returns path to JSON file if written, None otherwise
        """
        if session_id not in self.active_contexts:
            return None

        context = self.active_contexts[session_id]

        # Write to JSON if enabled
        json_path = None
        if self.json_output and self.json_writer:
            json_path = self.json_writer.write(context)

        # Remove from active contexts
        del self.active_contexts[session_id]

        return json_path

    def get_context(self, session_id: str) -> Optional[ReasoningContext]:
        """Get an active reasoning context"""
        return self.active_contexts.get(session_id)
