"""
XSS Agent Data Models

This module contains all the data classes and models used throughout the XSS agent.
"""

from .nuclei import NucleiResult
from .context import ContextInfo, FailureReport
from .forms import FormField, FormCandidate, StoredXSSAttempt
from .payloads import PayloadAttempt, VulnerabilityContext
from .verification import ProxyCaptureEntry, VerificationResult

__all__ = [
    'NucleiResult',
    'ContextInfo',
    'FailureReport',
    'FormField',
    'FormCandidate',
    'StoredXSSAttempt',
    'PayloadAttempt',
    'VulnerabilityContext',
    'ProxyCaptureEntry',
    'VerificationResult'
]