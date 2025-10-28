"""
Payload and vulnerability testing data models
"""
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from .nuclei import NucleiResult


@dataclass
class PayloadAttempt:
    """Represents a single payload attempt with full context"""
    attempt: int
    payload: str
    reasoning: str
    result: str  # success/failure
    playwright_response: Optional[Dict[str, Any]] = None
    next_action: str = ""
    timestamp: str = ""


@dataclass
class VulnerabilityContext:
    """Full context for a vulnerability including history"""
    nuclei_result: NucleiResult
    attempt_history: List[PayloadAttempt]
    current_attempt: int = 1
    max_attempts: int = 5
    successful_payload: Optional[str] = None