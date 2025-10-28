#!/usr/bin/env python3
"""
Configuration management for enhanced XSS detection pipeline
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field


@dataclass
class NucleiConfig:
    """Configuration for Nuclei scanner"""
    enabled: bool = True
    templates: List[str] = field(default_factory=lambda: ["xss"])
    timeout: int = 120
    rate_limit: int = 100
    threads: int = 25
    custom_templates_path: Optional[str] = None
    severity_filter: List[str] = field(default_factory=lambda: ["low", "medium", "high", "critical"])
    

@dataclass
class MITMConfig:
    """Configuration for MITM proxy"""
    enabled: bool = True
    proxy_port: int = 8080
    bind_address: str = "127.0.0.1"
    ssl_insecure: bool = True
    upstream_cert: bool = False
    confdir: Optional[str] = None
    intercept_patterns: List[str] = field(default_factory=lambda: [".*"])
    exclude_patterns: List[str] = field(default_factory=list)


@dataclass
class PlaywrightConfig:
    """Configuration for Playwright browser automation"""
    headless: bool = True
    browser_type: str = "chromium"  # chromium, firefox, webkit
    timeout: int = 30000
    wait_until: str = "networkidle"
    screenshot_full_page: bool = True
    disable_javascript: bool = False
    user_agent: Optional[str] = None
    viewport: Dict[str, int] = field(default_factory=lambda: {"width": 1920, "height": 1080})


@dataclass
class LLMConfig:
    """Configuration for LLM payload generation"""
    model: str = "llama3.3-70b"
    temperature: float = 0.7
    max_tokens: int = 1000
    timeout: int = 30
    retry_count: int = 3
    retry_delay: float = 1.0


@dataclass 
class CrawlerConfig:
    """Configuration for web crawling"""
    max_depth: int = 2
    max_pages: int = 50
    delay_between_requests: float = 1.0
    follow_redirects: bool = True
    respect_robots_txt: bool = False
    user_agent: str = "XSS-Detection-Agent/1.0"
    custom_headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class DetectionConfig:
    """Configuration for XSS detection parameters"""
    max_payload_attempts: int = 5
    payload_timeout: int = 10
    enable_reflected_xss: bool = True
    enable_stored_xss: bool = True
    enable_dom_xss: bool = True
    stored_xss_delay: int = 3  # seconds to wait before checking stored payloads
    dom_analysis_timeout: int = 15
    custom_payloads: List[str] = field(default_factory=list)


@dataclass
class OutputConfig:
    """Configuration for output and logging"""
    output_directory: str = "./results"
    log_level: str = "INFO"
    save_screenshots: bool = True
    save_html_content: bool = True
    save_mitm_logs: bool = True
    compress_results: bool = False
    json_indent: int = 2


@dataclass
class SecurityConfig:
    """Security configuration and limits"""
    max_scan_duration: int = 3600  # maximum scan duration in seconds
    max_file_size: int = 100 * 1024 * 1024  # 100MB
    allowed_schemes: List[str] = field(default_factory=lambda: ["http", "https"])
    blocked_domains: List[str] = field(default_factory=list)
    rate_limit_requests_per_second: int = 10


@dataclass
class XSSDetectionConfig:
    """Main configuration class combining all sub-configurations"""
    nuclei: NucleiConfig = field(default_factory=NucleiConfig)
    mitm: MITMConfig = field(default_factory=MITMConfig)
    playwright: PlaywrightConfig = field(default_factory=PlaywrightConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    crawler: CrawlerConfig = field(default_factory=CrawlerConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    
    # Authentication settings
    authentication: Optional[Dict[str, str]] = None
    cookies: Optional[Dict[str, str]] = None
    
    @classmethod
    def load_from_env(cls) -> 'XSSDetectionConfig':
        """Load configuration from environment variables"""
        config = cls()
        
        # Nuclei configuration
        if os.getenv('NUCLEI_ENABLED'):
            config.nuclei.enabled = os.getenv('NUCLEI_ENABLED').lower() == 'true'
        if os.getenv('NUCLEI_TIMEOUT'):
            config.nuclei.timeout = int(os.getenv('NUCLEI_TIMEOUT'))
        
        # MITM configuration
        if os.getenv('MITM_ENABLED'):
            config.mitm.enabled = os.getenv('MITM_ENABLED').lower() == 'true'
        if os.getenv('MITM_PORT'):
            config.mitm.proxy_port = int(os.getenv('MITM_PORT'))
        
        # Playwright configuration
        if os.getenv('PLAYWRIGHT_HEADLESS'):
            config.playwright.headless = os.getenv('PLAYWRIGHT_HEADLESS').lower() == 'true'
        if os.getenv('PLAYWRIGHT_BROWSER'):
            config.playwright.browser_type = os.getenv('PLAYWRIGHT_BROWSER')
        
        # LLM configuration
        if os.getenv('LLM_MODEL'):
            config.llm.model = os.getenv('LLM_MODEL')
        if os.getenv('LLM_TEMPERATURE'):
            config.llm.temperature = float(os.getenv('LLM_TEMPERATURE'))
        
        # Detection configuration
        if os.getenv('MAX_PAYLOAD_ATTEMPTS'):
            config.detection.max_payload_attempts = int(os.getenv('MAX_PAYLOAD_ATTEMPTS'))
        
        # Output configuration
        if os.getenv('OUTPUT_DIRECTORY'):
            config.output.output_directory = os.getenv('OUTPUT_DIRECTORY')
        if os.getenv('LOG_LEVEL'):
            config.output.log_level = os.getenv('LOG_LEVEL')
        
        return config
    
    @classmethod
    def load_from_file(cls, config_file: str) -> 'XSSDetectionConfig':
        """Load configuration from JSON/YAML file"""
        import json
        
        config_path = Path(config_file)
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_file}")
        
        with open(config_path, 'r') as f:
            if config_path.suffix.lower() in ['.json']:
                data = json.load(f)
            elif config_path.suffix.lower() in ['.yml', '.yaml']:
                try:
                    import yaml
                    data = yaml.safe_load(f)
                except ImportError:
                    raise ImportError("PyYAML is required for YAML configuration files")
            else:
                raise ValueError(f"Unsupported configuration file format: {config_path.suffix}")
        
        # Create config object from data
        config = cls()
        
        # Update configuration sections
        if 'nuclei' in data:
            for key, value in data['nuclei'].items():
                if hasattr(config.nuclei, key):
                    setattr(config.nuclei, key, value)
        
        if 'mitm' in data:
            for key, value in data['mitm'].items():
                if hasattr(config.mitm, key):
                    setattr(config.mitm, key, value)
        
        if 'playwright' in data:
            for key, value in data['playwright'].items():
                if hasattr(config.playwright, key):
                    setattr(config.playwright, key, value)
        
        if 'llm' in data:
            for key, value in data['llm'].items():
                if hasattr(config.llm, key):
                    setattr(config.llm, key, value)
        
        if 'crawler' in data:
            for key, value in data['crawler'].items():
                if hasattr(config.crawler, key):
                    setattr(config.crawler, key, value)
        
        if 'detection' in data:
            for key, value in data['detection'].items():
                if hasattr(config.detection, key):
                    setattr(config.detection, key, value)
        
        if 'output' in data:
            for key, value in data['output'].items():
                if hasattr(config.output, key):
                    setattr(config.output, key, value)
        
        if 'security' in data:
            for key, value in data['security'].items():
                if hasattr(config.security, key):
                    setattr(config.security, key, value)
        
        # Top-level authentication
        if 'authentication' in data:
            config.authentication = data['authentication']
        if 'cookies' in data:
            config.cookies = data['cookies']
        
        return config
    
    def save_to_file(self, config_file: str) -> None:
        """Save configuration to JSON file"""
        import json
        from dataclasses import asdict
        
        config_path = Path(config_file)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(config_path, 'w') as f:
            json.dump(asdict(self), f, indent=self.output.json_indent, default=str)
    
    def validate(self) -> List[str]:
        """Validate configuration and return list of issues"""
        issues = []
        
        # Validate ports
        if not (1 <= self.mitm.proxy_port <= 65535):
            issues.append(f"Invalid MITM proxy port: {self.mitm.proxy_port}")
        
        # Validate timeouts
        if self.nuclei.timeout <= 0:
            issues.append("Nuclei timeout must be positive")
        
        if self.playwright.timeout <= 0:
            issues.append("Playwright timeout must be positive")
        
        # Validate directories
        try:
            Path(self.output.output_directory).mkdir(parents=True, exist_ok=True)
        except Exception as e:
            issues.append(f"Cannot create output directory: {e}")
        
        # Validate browser type
        valid_browsers = ["chromium", "firefox", "webkit"]
        if self.playwright.browser_type not in valid_browsers:
            issues.append(f"Invalid browser type: {self.playwright.browser_type}")
        
        # Validate log level
        valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.output.log_level.upper() not in valid_log_levels:
            issues.append(f"Invalid log level: {self.output.log_level}")
        
        # Validate LLM settings
        if not (0.0 <= self.llm.temperature <= 1.0):
            issues.append(f"LLM temperature must be between 0.0 and 1.0: {self.llm.temperature}")
        
        return issues
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the current configuration"""
        return {
            'nuclei_enabled': self.nuclei.enabled,
            'mitm_enabled': self.mitm.enabled,
            'mitm_port': self.mitm.proxy_port,
            'browser_type': self.playwright.browser_type,
            'headless': self.playwright.headless,
            'llm_model': self.llm.model,
            'max_attempts': self.detection.max_payload_attempts,
            'xss_types_enabled': {
                'reflected': self.detection.enable_reflected_xss,
                'stored': self.detection.enable_stored_xss,
                'dom': self.detection.enable_dom_xss
            },
            'output_directory': self.output.output_directory,
            'log_level': self.output.log_level
        }


def load_env_file(env_file: str = ".env") -> None:
    """Load environment variables from .env file"""
    env_path = Path(env_file)
    if env_path.exists():
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    # Handle export format
                    if line.startswith('export '):
                        line = line[7:]  # Remove 'export '
                    key, value = line.split('=', 1)
                    # Remove quotes if present
                    value = value.strip('"').strip("'")
                    os.environ[key] = value