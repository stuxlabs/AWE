"""
Form-related data models for stored XSS testing
"""
from dataclasses import dataclass
from typing import List, Optional, Dict, Any


@dataclass
class FormField:
    """Represents a form input field"""
    name: str
    field_type: str  # text, textarea, email, password, hidden, etc.
    required: bool = False
    max_length: Optional[int] = None
    placeholder: Optional[str] = None
    default_value: Optional[str] = None


@dataclass
class FormCandidate:
    """Represents a form that could be vulnerable to stored XSS"""
    form_id: str
    action_url: str
    method: str  # GET or POST
    fields: List[FormField]
    submit_buttons: List[str]
    csrf_token: Optional[str] = None
    form_element_html: Optional[str] = None


@dataclass
class StoredXSSAttempt:
    """Represents a stored XSS injection attempt"""
    form_candidate: FormCandidate
    payload: str
    injection_field: str
    submission_result: Optional[Dict] = None
    verification_result: Optional['VerificationResult'] = None
    successful: bool = False
    timestamp: str = ""