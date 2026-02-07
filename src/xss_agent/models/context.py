"""
Context analysis data models
"""
from dataclasses import dataclass
from typing import Optional


@dataclass
class ContextInfo:
    """Information about XSS injection context"""
    location: str  # query, post, json, header, path, fragment, multipart, xml, websocket, dom, unknown
    param: Optional[str] = None  # parameter name where payload was injected
    evidence: str = ""  # snippet showing where the reflection occurred


@dataclass
class FailureReport:
    """Report analyzing why an XSS payload attempt failed"""
    reason: str  # "escaped", "blocked", "syntax_error", "neutralized", "missing", "unknown"
    details: str  # human-readable explanation
    confidence: float  # 0.0–1.0