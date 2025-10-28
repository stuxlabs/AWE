"""
Core modules for enhanced XSS detection pipeline
"""

from .models import (
    XSSType, DetectionMethod, NucleiResult, PayloadAttempt, 
    VerificationResult, MITMInterceptionResult, StoredXSSContext,
    DOMXSSContext, VulnerabilityContext, XSSFinding, 
    ScanConfiguration, ScanResults
)
from .utils import (
    setup_logging, create_output_directories, inject_payload_into_url,
    extract_forms_from_html, is_xss_payload, generate_xss_payloads,
    clean_json_response, save_json_results, load_json_results,
    validate_url, Timer
)
from .config import (
    XSSDetectionConfig, NucleiConfig, MITMConfig, PlaywrightConfig,
    LLMConfig, CrawlerConfig, DetectionConfig, OutputConfig,
    SecurityConfig, load_env_file
)

__all__ = [
    # Models
    'XSSType', 'DetectionMethod', 'NucleiResult', 'PayloadAttempt',
    'VerificationResult', 'MITMInterceptionResult', 'StoredXSSContext',
    'DOMXSSContext', 'VulnerabilityContext', 'XSSFinding',
    'ScanConfiguration', 'ScanResults',
    
    # Utils
    'setup_logging', 'create_output_directories', 'inject_payload_into_url',
    'extract_forms_from_html', 'is_xss_payload', 'generate_xss_payloads',
    'clean_json_response', 'save_json_results', 'load_json_results',
    'validate_url', 'Timer',
    
    # Config
    'XSSDetectionConfig', 'NucleiConfig', 'MITMConfig', 'PlaywrightConfig',
    'LLMConfig', 'CrawlerConfig', 'DetectionConfig', 'OutputConfig',
    'SecurityConfig', 'load_env_file'
]