"""
XSS Analysis Framework
======================

A modular, LLM-powered framework for deep XSS vulnerability analysis.

This framework implements multi-stage serial analysis with context compression,
enabling intelligent, adaptive XSS detection that learns from each attempt.

Architecture:
- Deep Analysis Sessions: Multi-stage serial analysis
- Global Memory: Context-aware history management
- Strategic Generation: Intelligent payload creation
- Analysis Compression: Efficient knowledge preservation

Author: Security Research Team
License: MIT
"""

from .base import AnalysisStage, AnalysisResult, TestAttempt
from .session import DeepAnalysisSession
from .stages import (
    TransformationAnalysisStage,
    ContextDetectionStage,
    ProtectionFingerprintingStage,
    BypassStrategyStage
)
from .summarizer import AnalysisSummarizer
from .memory import GlobalMemoryManager
from .generator import StrategicPayloadGenerator
from .hybrid_generator import (
    HybridPayloadGenerator,
    TechniqueCoverageTracker,
    MutationEngine
)
from .config import AnalysisConfig

__version__ = '1.1.0'
__all__ = [
    'AnalysisStage',
    'AnalysisResult',
    'TestAttempt',
    'DeepAnalysisSession',
    'TransformationAnalysisStage',
    'ContextDetectionStage',
    'ProtectionFingerprintingStage',
    'BypassStrategyStage',
    'AnalysisSummarizer',
    'GlobalMemoryManager',
    'StrategicPayloadGenerator',
    'HybridPayloadGenerator',
    'TechniqueCoverageTracker',
    'MutationEngine',
    'AnalysisConfig',
]
