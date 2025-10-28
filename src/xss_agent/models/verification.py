"""
Verification and result data models
"""
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from .forms import StoredXSSAttempt


@dataclass
class ProxyCaptureEntry:
    """Represents a single HTTP request/response captured by proxy"""
    id: str
    timestamp: str
    request: Dict[str, Any]   # method, url, headers, body
    response: Dict[str, Any]  # status, headers, body
    raw_har_entry: Dict[str, Any]  # original HAR entry or mitm entry


@dataclass
class VerificationResult:
    """Results from Playwright verification"""
    url: str
    payload: str
    executed: bool
    reflection_found: bool
    execution_method: Optional[str] = None
    screenshot_path: Optional[str] = None
    error: Optional[str] = None
    timestamp: Optional[str] = None
    console_logs: List[Dict] = None
    alerts_caught: List[str] = None
    page_content: Optional[str] = None
    page_content_file: Optional[str] = None
    response_status: Optional[int] = None
    response_headers: Optional[Dict] = None
    proxy_captures: Optional[List[ProxyCaptureEntry]] = None
    stored_xss_attempt: Optional[StoredXSSAttempt] = None