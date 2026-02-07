"""
XSS Agent Testing Components

This module contains all the specialized agents for different types of XSS testing:
- ReconAgent: Nuclei-based vulnerability discovery
- FormDiscoveryAgent: Intelligent form detection for stored XSS
- StoredXSSAgent: Form-based stored XSS testing
- DynamicVerifierAgent: Playwright-based payload verification
"""

from .recon import ReconAgent
from .form_discovery import FormDiscoveryAgent
from .stored_xss import StoredXSSAgent
from .verifier import DynamicVerifierAgent

__all__ = [
    'ReconAgent',
    'FormDiscoveryAgent',
    'StoredXSSAgent',
    'DynamicVerifierAgent'
]