"""
SQLi Agent Package

AI-powered SQL injection detection and exploitation framework.
"""
from .models import (
    SQLiType,
    DatabaseType,
    SQLContext,
    SQLiTestAttempt,
    SQLiVerificationResult,
    DatabaseFingerprint,
    SQLContextInfo,
    SQLProtectionInfo,
    SQLBypassStrategy,
    InjectionPoint,
    SQLiAnalysisResult,
    SQLiSessionResult
)

__version__ = '1.0.0'
__all__ = [
    'SQLiType',
    'DatabaseType',
    'SQLContext',
    'SQLiTestAttempt',
    'SQLiVerificationResult',
    'DatabaseFingerprint',
    'SQLContextInfo',
    'SQLProtectionInfo',
    'SQLBypassStrategy',
    'InjectionPoint',
    'SQLiAnalysisResult',
    'SQLiSessionResult'
]
