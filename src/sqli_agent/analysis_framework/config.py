"""
SQLi Analysis Framework Configuration

Configuration presets for SQL injection testing.
"""
from dataclasses import dataclass
from typing import Optional


@dataclass
class SQLiAnalysisConfig:
    """Configuration for SQL injection analysis framework"""

    # Testing parameters
    max_attempts_per_target: int = 30
    max_payloads_per_technique: int = 10

    # Detection timeouts
    time_based_threshold: float = 4.5  # seconds
    request_timeout: int = 15000  # milliseconds

    # LLM parameters
    use_llm_generation: bool = True
    llm_model: str = "claude-4-sonnet"
    generation_temperature: float = 0.8

    # Confidence thresholds
    min_confidence_threshold: int = 70
    error_based_confidence: int = 95
    time_based_confidence: int = 90
    boolean_based_confidence: int = 70

    # Database fingerprinting
    enable_fingerprinting: bool = True
    fingerprint_attempts: int = 3

    # Context analysis
    enable_context_analysis: bool = True
    context_detection_attempts: int = 3

    # Payload generation phases
    database_phase_ratio: float = 0.6  # 60% of attempts
    llm_phase_ratio: float = 0.2  # 20% of attempts
    mutation_phase_ratio: float = 0.2  # 20% of attempts

    # Memory and caching
    enable_memory: bool = True
    max_memory_entries: int = 100

    # Output
    save_screenshots: bool = True
    save_html_captures: bool = True
    verbose_logging: bool = False

    @classmethod
    def default(cls) -> 'SQLiAnalysisConfig':
        """Default balanced configuration"""
        return cls()

    @classmethod
    def fast(cls) -> 'SQLiAnalysisConfig':
        """Fast testing configuration (fewer attempts)"""
        return cls(
            max_attempts_per_target=15,
            max_payloads_per_technique=5,
            use_llm_generation=False,
            enable_fingerprinting=False,
            enable_context_analysis=False
        )

    @classmethod
    def aggressive(cls) -> 'SQLiAnalysisConfig':
        """Aggressive testing configuration (more attempts, deeper analysis)"""
        return cls(
            max_attempts_per_target=50,
            max_payloads_per_technique=15,
            use_llm_generation=True,
            enable_fingerprinting=True,
            enable_context_analysis=True,
            fingerprint_attempts=5,
            context_detection_attempts=5,
            verbose_logging=True
        )

    @classmethod
    def conservative(cls) -> 'SQLiAnalysisConfig':
        """Conservative testing (fewer attempts, higher confidence threshold)"""
        return cls(
            max_attempts_per_target=20,
            max_payloads_per_technique=8,
            min_confidence_threshold=80,
            verbose_logging=False
        )
