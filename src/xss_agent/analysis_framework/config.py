"""
Configuration for Analysis Framework

Centralized configuration management for all framework components.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class AnalysisConfig:
    """
    Configuration for the analysis framework.

    Controls behavior of analysis sessions, memory management,
    and payload generation.
    """

    # === Analysis Session Config ===
    max_analysis_stages: int = 4
    """Maximum number of analysis stages per attempt"""

    enable_adaptive_stages: bool = True
    """Allow LLM to decide when to stop analysis"""

    stage_timeout_seconds: int = 30
    """Timeout for each analysis stage"""

    min_confidence_threshold: int = 50
    """Minimum confidence to try a payload (0-100)"""

    # === Memory Management Config ===
    max_history_entries: int = 100
    """Maximum number of attempts to keep in history"""

    compression_threshold: int = 50
    """Compress history when exceeding this many entries"""

    summary_max_tokens: int = 250
    """Maximum tokens for each summary"""

    # === Payload Generation Config ===
    max_attempts_per_target: int = 30
    """Maximum payload attempts before giving up"""

    generation_temperature: float = 0.7
    """LLM temperature for payload generation"""

    analysis_temperature: float = 0.5
    """LLM temperature for analysis (lower = more focused)"""

    use_fallback_database: bool = True
    """Fall back to static payload database if LLM fails"""

    # === Stage-Specific Config ===
    transformation_stage_config: Dict = field(default_factory=lambda: {
        'max_diff_length': 500,
        'detect_encoding': True,
        'detect_filtering': True,
    })

    context_stage_config: Dict = field(default_factory=lambda: {
        'parse_html': True,
        'parse_javascript': True,
        'max_context_length': 300,
    })

    protection_stage_config: Dict = field(default_factory=lambda: {
        'fingerprint_waf': True,
        'detect_filter_rules': True,
        'identify_sanitization': True,
    })

    bypass_stage_config: Dict = field(default_factory=lambda: {
        'propose_alternatives': 3,
        'require_reasoning': True,
        'min_confidence': 60,
    })

    # === Logging Config ===
    log_level: str = "INFO"
    """Logging level (DEBUG, INFO, WARNING, ERROR)"""

    log_file: Optional[str] = "logs/analysis_framework.log"
    """Log file path (None to disable file logging)"""

    verbose_analysis: bool = False
    """Enable verbose analysis logging"""

    # === Performance Config ===
    enable_caching: bool = True
    """Cache analysis results for identical responses"""

    parallel_stages: bool = False
    """Run independent stages in parallel (experimental)"""

    response_truncate_length: int = 5000
    """Truncate responses longer than this for analysis"""

    @classmethod
    def default(cls) -> 'AnalysisConfig':
        """Get default configuration"""
        return cls()

    @classmethod
    def aggressive(cls) -> 'AnalysisConfig':
        """Get aggressive configuration (more attempts, deeper analysis)"""
        return cls(
            max_analysis_stages=6,
            max_attempts_per_target=50,
            min_confidence_threshold=40,
            generation_temperature=0.9,
        )

    @classmethod
    def fast(cls) -> 'AnalysisConfig':
        """Get fast configuration (fewer stages, quick attempts)"""
        return cls(
            max_analysis_stages=2,
            max_attempts_per_target=15,
            enable_adaptive_stages=False,
            stage_timeout_seconds=15,
        )

    @classmethod
    def conservative(cls) -> 'AnalysisConfig':
        """Get conservative configuration (thorough but slow)"""
        return cls(
            max_analysis_stages=5,
            max_attempts_per_target=20,
            min_confidence_threshold=70,
            analysis_temperature=0.3,
            verbose_analysis=True,
        )

    def to_dict(self) -> Dict:
        """Convert config to dictionary"""
        from dataclasses import asdict
        return asdict(self)

    def validate(self) -> None:
        """Validate configuration values"""
        if self.max_analysis_stages < 1:
            raise ValueError("max_analysis_stages must be >= 1")
        if not 0 <= self.min_confidence_threshold <= 100:
            raise ValueError("min_confidence_threshold must be 0-100")
        if self.max_attempts_per_target < 1:
            raise ValueError("max_attempts_per_target must be >= 1")
        if not 0 <= self.generation_temperature <= 2:
            raise ValueError("generation_temperature must be 0-2")
        if self.summary_max_tokens < 50:
            raise ValueError("summary_max_tokens must be >= 50")
