"""
Base Classes for Analysis Framework

Provides abstract base classes and core data structures for the analysis system.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional, List
from datetime import datetime
import logging


@dataclass
class AnalysisResult:
    """
    Result from a single analysis stage.

    Attributes:
        stage_name: Name of the analysis stage
        insights: Key insights discovered in this stage
        data: Detailed analysis data
        continue_analysis: Whether to proceed to next stage
        reasoning: Explanation for continue/stop decision
        confidence: Confidence score (0-100)
        timestamp: When this analysis completed
        error: Error message if stage failed
    """
    stage_name: str
    insights: List[str]
    data: Dict[str, Any]
    continue_analysis: bool
    reasoning: str
    confidence: int = 0
    timestamp: datetime = field(default_factory=datetime.now)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        result = asdict(self)
        result['timestamp'] = self.timestamp.isoformat()
        return result

    def is_success(self) -> bool:
        """Check if stage completed successfully"""
        return self.error is None

    def get_summary(self) -> str:
        """Get brief summary of this stage"""
        insights_str = '; '.join(self.insights[:3])
        return f"[{self.stage_name}] {insights_str}"


@dataclass
class TestAttempt:
    """
    Represents a single payload test attempt.

    Attributes:
        attempt_number: Sequential attempt number
        payload: The XSS payload tested
        target_url: URL where payload was tested
        response_html: Response HTML (truncated)
        response_headers: HTTP response headers
        success: Whether payload succeeded
        execution_evidence: Evidence of successful execution
        timestamp: When attempt was made
    """
    attempt_number: int
    payload: str
    target_url: str
    response_html: str
    response_headers: Dict[str, str]
    success: bool
    execution_evidence: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        result = asdict(self)
        result['timestamp'] = self.timestamp.isoformat()
        return result


class AnalysisStage(ABC):
    """
    Abstract base class for analysis stages.

    Each stage performs focused analysis on a specific aspect of the response.
    Stages run serially, building on insights from previous stages.
    """

    def __init__(self, llm_client, config: Optional[Dict] = None):
        """
        Initialize analysis stage.

        Args:
            llm_client: LLM client for analysis
            config: Optional configuration dict
        """
        self.llm = llm_client
        self.config = config or {}
        self.logger = logging.getLogger(f"{self.__class__.__name__}")

    @abstractmethod
    async def analyze(
        self,
        attempt: TestAttempt,
        previous_results: List[AnalysisResult]
    ) -> AnalysisResult:
        """
        Perform analysis for this stage.

        Args:
            attempt: The test attempt to analyze
            previous_results: Results from previous stages (for context)

        Returns:
            AnalysisResult with insights and decision to continue
        """
        pass

    @abstractmethod
    def get_stage_name(self) -> str:
        """Get human-readable stage name"""
        pass

    def _build_prompt(self, **kwargs) -> str:
        """
        Build LLM prompt for this stage.
        Subclasses should override to customize prompts.

        Args:
            **kwargs: Context data for prompt

        Returns:
            Formatted prompt string
        """
        raise NotImplementedError("Subclasses must implement _build_prompt")

    async def _call_llm(self, prompt: str, temperature: float = 0.7) -> str:
        """
        Call LLM with error handling.

        Args:
            prompt: Prompt to send to LLM
            temperature: Sampling temperature

        Returns:
            LLM response text
        """
        try:
            # simple_chat is synchronous, not async
            response = self.llm.simple_chat(
                model="claude-4-sonnet",
                message=prompt,
                temperature=temperature
            )
            return response.strip()
        except Exception as e:
            self.logger.error(f"LLM call failed in {self.get_stage_name()}: {e}")
            raise

    def _parse_json_response(self, response: str) -> Dict[str, Any]:
        """
        Parse JSON from LLM response with error handling.

        Args:
            response: Raw LLM response

        Returns:
            Parsed JSON dict
        """
        import json
        import re

        # Try to extract JSON
        if '```json' in response:
            match = re.search(r'```json\s*(.*?)\s*```', response, re.DOTALL)
            if match:
                response = match.group(1)
        elif '```' in response:
            match = re.search(r'```\s*(.*?)\s*```', response, re.DOTALL)
            if match:
                response = match.group(1)

        # Find JSON object
        if '{' in response:
            start = response.find('{')
            # Find matching closing brace
            brace_count = 0
            in_string = False
            escape_next = False

            for i in range(start, len(response)):
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
                            json_str = response[start:i+1]
                            return json.loads(json_str)

        raise ValueError(f"Could not extract JSON from response: {response[:200]}")


class AnalysisException(Exception):
    """Base exception for analysis framework"""
    pass


class StageFailedException(AnalysisException):
    """Raised when an analysis stage fails"""
    pass


class LLMException(AnalysisException):
    """Raised when LLM interaction fails"""
    pass
