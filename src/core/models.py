#!/usr/bin/env python3
"""
Core data models for enhanced XSS detection pipeline
Supports reflected, stored, and DOM-based XSS detection
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Union
from pathlib import Path


class XSSType(Enum):
    """Types of XSS vulnerabilities"""
    REFLECTED = "reflected"
    STORED = "stored"
    DOM_BASED = "dom_based"


class DetectionMethod(Enum):
    """Methods used to detect XSS"""
    NUCLEI = "nuclei"
    MITM_PROXY = "mitm_proxy"
    DOM_ANALYSIS = "dom_analysis"
    TRAFFIC_ANALYSIS = "traffic_analysis"


@dataclass
class NucleiResult:
    """Represents a single Nuclei finding"""
    template_id: str
    template_name: str
    severity: str
    description: str
    matched_url: str
    injection_point: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None


@dataclass 
class PayloadAttempt:
    """Represents a single payload attempt with full context"""
    attempt: int
    payload: str
    reasoning: str
    result: str  # success/failure/error
    xss_type: XSSType = XSSType.REFLECTED
    detection_method: DetectionMethod = DetectionMethod.NUCLEI
    playwright_response: Optional['VerificationResult'] = None
    mitm_response: Optional['MITMInterceptionResult'] = None
    next_action: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class VerificationResult:
    """Results from Playwright verification"""
    url: str
    payload: str
    executed: bool
    reflection_found: bool
    xss_type: XSSType = XSSType.REFLECTED
    execution_method: Optional[str] = None
    screenshot_path: Optional[str] = None
    error: Optional[str] = None
    timestamp: Optional[str] = None
    console_logs: List[Dict] = field(default_factory=list)
    alerts_caught: List[str] = field(default_factory=list)
    page_content: Optional[str] = None
    page_content_file: Optional[str] = None
    response_status: Optional[int] = None
    response_headers: Optional[Dict] = None
    dom_mutations: Optional[List[Dict]] = None


@dataclass
class MITMInterceptionResult:
    """Results from MITM proxy interception and analysis"""
    request_url: str
    request_method: str
    request_headers: Dict[str, str]
    request_body: Optional[str] = None
    response_status: int = 0
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: Optional[str] = None
    injected_payload: Optional[str] = None
    injection_point: Optional[str] = None
    payload_reflected: bool = False
    payload_stored: bool = False
    dom_modifications: List[Dict] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    session_id: Optional[str] = None


@dataclass
class StoredXSSContext:
    """Context for stored XSS testing"""
    injection_url: str
    payload: str
    injection_point: str  # form field, parameter, etc.
    verification_urls: List[str]  # URLs to check for payload execution
    session_data: Optional[Dict] = None
    cookies: Optional[Dict] = None
    delay_before_check: int = 2  # seconds to wait before checking


@dataclass
class DOMXSSContext:
    """Context for DOM-based XSS testing"""
    target_url: str
    payload: str
    dom_sinks: List[str]  # innerHTML, document.write, etc.
    sources: List[str]  # location.hash, document.referrer, etc.
    javascript_execution: bool = False
    dom_mutations_detected: List[Dict] = field(default_factory=list)


@dataclass
class VulnerabilityContext:
    """Enhanced context supporting multiple XSS types"""
    nuclei_result: Optional[NucleiResult] = None
    xss_type: XSSType = XSSType.REFLECTED
    detection_method: DetectionMethod = DetectionMethod.NUCLEI
    attempt_history: List[PayloadAttempt] = field(default_factory=list)
    current_attempt: int = 0
    max_attempts: int = 5
    successful_payload: Optional[str] = None
    
    # Additional contexts for different XSS types
    stored_context: Optional[StoredXSSContext] = None
    dom_context: Optional[DOMXSSContext] = None
    mitm_data: List[MITMInterceptionResult] = field(default_factory=list)


@dataclass
class XSSFinding:
    """Unified representation of an XSS finding regardless of type"""
    xss_type: XSSType
    detection_method: DetectionMethod
    url: str
    payload: str
    severity: str
    description: str
    successful: bool
    vulnerability_context: VulnerabilityContext
    verification_result: Optional[VerificationResult] = None
    mitm_result: Optional[MITMInterceptionResult] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class ScanConfiguration:
    """Configuration for XSS scanning"""
    target_url: str
    enable_nuclei: bool = True
    enable_mitm: bool = True
    enable_stored_xss: bool = True
    enable_dom_xss: bool = True
    mitm_port: int = 8080
    max_payload_attempts: int = 5
    crawl_depth: int = 2
    delay_between_requests: float = 1.0
    custom_headers: Dict[str, str] = field(default_factory=dict)
    authentication: Optional[Dict[str, str]] = None
    excluded_urls: List[str] = field(default_factory=list)


@dataclass
class ScanResults:
    """Complete scan results with all XSS types"""
    scan_config: ScanConfiguration
    scan_start_time: str
    scan_end_time: Optional[str] = None
    total_duration: Optional[float] = None
    
    # Results by type
    reflected_xss: List[XSSFinding] = field(default_factory=list)
    stored_xss: List[XSSFinding] = field(default_factory=list)
    dom_xss: List[XSSFinding] = field(default_factory=list)
    
    # Summary statistics
    total_vulnerabilities: int = 0
    successful_exploits: int = 0
    total_attempts: int = 0
    
    # Files and artifacts
    screenshot_paths: List[str] = field(default_factory=list)
    log_files: List[str] = field(default_factory=list)
    html_captures: List[str] = field(default_factory=list)
    mitm_logs: List[str] = field(default_factory=list)
    
    def add_finding(self, finding: XSSFinding):
        """Add a finding to the appropriate category"""
        if finding.xss_type == XSSType.REFLECTED:
            self.reflected_xss.append(finding)
        elif finding.xss_type == XSSType.STORED:
            self.stored_xss.append(finding)
        elif finding.xss_type == XSSType.DOM_BASED:
            self.dom_xss.append(finding)
        
        self.total_vulnerabilities += 1
        if finding.successful:
            self.successful_exploits += 1
        self.total_attempts += len(finding.vulnerability_context.attempt_history)
    
    def get_success_rate(self) -> float:
        """Calculate overall success rate"""
        if self.total_vulnerabilities == 0:
            return 0.0
        return (self.successful_exploits / self.total_vulnerabilities) * 100
    
    def get_summary(self) -> Dict[str, Any]:
        """Get scan summary statistics"""
        return {
            'scan_duration': self.total_duration,
            'total_vulnerabilities': self.total_vulnerabilities,
            'successful_exploits': self.successful_exploits,
            'success_rate': f"{self.get_success_rate():.1f}%",
            'total_attempts': self.total_attempts,
            'vulnerabilities_by_type': {
                'reflected': len(self.reflected_xss),
                'stored': len(self.stored_xss),
                'dom_based': len(self.dom_xss)
            },
            'successful_by_type': {
                'reflected': sum(1 for f in self.reflected_xss if f.successful),
                'stored': sum(1 for f in self.stored_xss if f.successful),
                'dom_based': sum(1 for f in self.dom_xss if f.successful)
            }
        }