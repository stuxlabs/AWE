#!/usr/bin/env python3
"""
Enhanced XSS Detection Orchestrator
Coordinates multiple detection methods for comprehensive XSS coverage
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

from core.models import (
    ScanConfiguration, ScanResults, XSSFinding, VulnerabilityContext,
    XSSType, DetectionMethod, NucleiResult
)
from core.utils import Timer, get_timestamp, save_json_results
from core.config import XSSDetectionConfig

# Import agents
from agents.recon_agent import ReconAgent
from agents.payload_agent import DynamicPayloadAgent  
from agents.verifier_agent import DynamicVerifierAgent
from agents.stored_xss_agent import StoredXSSAgent
from agents.dom_xss_agent import DOMXSSAgent

# Import MITM agent with error handling
try:
    from agents.mitm_agent import MITMAgent, MITM_AVAILABLE
except ImportError:
    MITM_AVAILABLE = False
    MITMAgent = None


class EnhancedXSSOrchestrator:
    """Enhanced orchestrator for multi-type XSS detection"""
    
    def __init__(self, config: Optional[XSSDetectionConfig] = None):
        self.config = config or XSSDetectionConfig()
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Initialize agents based on configuration
        self.recon_agent = ReconAgent(self.config.nuclei.__dict__) if self.config.nuclei.enabled else None
        self.payload_agent = DynamicPayloadAgent(self.config.llm.__dict__)
        self.verifier_agent = DynamicVerifierAgent(self.config.playwright.__dict__)
        self.stored_xss_agent = StoredXSSAgent(self._get_stored_config()) if self.config.detection.enable_stored_xss else None
        self.dom_xss_agent = DOMXSSAgent(self._get_dom_config()) if self.config.detection.enable_dom_xss else None
        
        # Initialize MITM agent if available and enabled
        self.mitm_agent = None
        if self.config.mitm.enabled and MITM_AVAILABLE and MITMAgent:
            try:
                self.mitm_agent = MITMAgent(self.config.mitm.__dict__)
            except Exception as e:
                self.logger.warning(f"Could not initialize MITM agent: {e}")
        
        # Track scan progress
        self.current_scan: Optional[ScanResults] = None
        
    def _get_stored_config(self) -> Dict[str, Any]:
        """Get configuration for stored XSS agent"""
        return {
            'max_crawl_depth': self.config.crawler.max_depth,
            'delay_between_requests': self.config.crawler.delay_between_requests,
            'verification_delay': self.config.detection.stored_xss_delay,
            'headless': self.config.playwright.headless
        }
    
    def _get_dom_config(self) -> Dict[str, Any]:
        """Get configuration for DOM XSS agent"""
        return {
            'dom_analysis_timeout': self.config.detection.dom_analysis_timeout,
            'payload_timeout': self.config.detection.payload_timeout,
            'headless': self.config.playwright.headless
        }
    
    async def comprehensive_scan(self, target_url: str) -> ScanResults:
        """Perform comprehensive XSS scan using all available methods"""
        
        self.logger.info(f"Starting comprehensive XSS scan for {target_url}")
        
        # Create scan configuration
        scan_config = ScanConfiguration(
            target_url=target_url,
            enable_nuclei=self.config.nuclei.enabled,
            enable_mitm=self.config.mitm.enabled,
            enable_stored_xss=self.config.detection.enable_stored_xss,
            enable_dom_xss=self.config.detection.enable_dom_xss,
            mitm_port=self.config.mitm.proxy_port,
            max_payload_attempts=self.config.detection.max_payload_attempts,
            crawl_depth=self.config.crawler.max_depth
        )
        
        # Initialize scan results
        self.current_scan = ScanResults(
            scan_config=scan_config,
            scan_start_time=get_timestamp()
        )
        
        with Timer("Comprehensive XSS Scan") as timer:
            
            # Phase 1: Traditional Nuclei-based scanning (Reflected XSS)
            if self.config.nuclei.enabled and self.recon_agent:
                await self._phase_nuclei_scanning(target_url)
            
            # Phase 2: MITM Proxy scanning (if no vulns found or enabled)
            should_run_mitm = (
                self.config.mitm.enabled and 
                self.mitm_agent and 
                (not self.current_scan.reflected_xss or self.config.mitm.enabled)
            )
            
            if should_run_mitm:
                await self._phase_mitm_scanning(target_url)
            
            # Phase 3: Stored XSS detection
            if self.config.detection.enable_stored_xss and self.stored_xss_agent:
                await self._phase_stored_xss_detection(target_url)
            
            # Phase 4: DOM-based XSS detection
            if self.config.detection.enable_dom_xss and self.dom_xss_agent:
                await self._phase_dom_xss_detection(target_url)
        
        # Finalize scan results
        self.current_scan.scan_end_time = get_timestamp()
        self.current_scan.total_duration = timer.elapsed
        
        # Save comprehensive results
        await self._save_comprehensive_results(target_url)
        
        self.logger.info(f"Comprehensive scan completed in {timer.elapsed:.2f} seconds")
        self.logger.info(f"Total vulnerabilities found: {self.current_scan.total_vulnerabilities}")
        self.logger.info(f"Success rate: {self.current_scan.get_success_rate():.1f}%")
        
        return self.current_scan
    
    async def _phase_nuclei_scanning(self, target_url: str):
        """Phase 1: Nuclei-based reflected XSS scanning"""
        
        self.logger.info("Phase 1: Nuclei-based scanning for reflected XSS")
        
        try:
            # Run Nuclei reconnaissance
            nuclei_results = await self.recon_agent.run(target_url)
            
            if not nuclei_results:
                self.logger.info("No XSS vulnerabilities found by Nuclei")
                return
            
            # Process each Nuclei finding with dynamic testing
            for finding in nuclei_results:
                self.logger.info(f"Processing Nuclei finding: {finding.template_name}")
                
                # Create vulnerability context
                vulnerability_context = VulnerabilityContext(
                    nuclei_result=finding,
                    xss_type=XSSType.REFLECTED,
                    detection_method=DetectionMethod.NUCLEI,
                    max_attempts=self.config.detection.max_payload_attempts
                )
                
                # Dynamic testing loop with LLM improvement
                success = await self._dynamic_testing_loop(vulnerability_context)
                
                # Create XSS finding
                xss_finding = XSSFinding(
                    xss_type=XSSType.REFLECTED,
                    detection_method=DetectionMethod.NUCLEI,
                    url=finding.matched_url,
                    payload=vulnerability_context.successful_payload or "N/A",
                    severity=finding.severity,
                    description=finding.description,
                    successful=success,
                    vulnerability_context=vulnerability_context
                )
                
                self.current_scan.add_finding(xss_finding)
            
        except Exception as e:
            self.logger.error(f"Error in Nuclei scanning phase: {e}")
    
    async def _phase_mitm_scanning(self, target_url: str):
        """Phase 2: MITM proxy scanning"""
        
        self.logger.info("Phase 2: MITM proxy scanning")
        
        try:
            # Start MITM proxy
            proxy_started = await self.mitm_agent.start_proxy()
            
            if not proxy_started:
                self.logger.warning("Could not start MITM proxy, skipping MITM phase")
                return
            
            # Run MITM interception
            mitm_findings = await self.mitm_agent.run(
                target_url, 
                duration=self.config.crawler.delay_between_requests * 60  # Convert to reasonable duration
            )
            
            # Convert MITM findings to XSS findings
            for mitm_finding in mitm_findings:
                xss_type = XSSType(mitm_finding['xss_type'])
                
                xss_finding = XSSFinding(
                    xss_type=xss_type,
                    detection_method=DetectionMethod.MITM_PROXY,
                    url=mitm_finding.get('url', mitm_finding.get('execution_url', target_url)),
                    payload=mitm_finding.get('payload', 'N/A'),
                    severity=mitm_finding.get('severity', 'medium'),
                    description=f"MITM-detected {xss_type.value} XSS",
                    successful=True,  # MITM findings are already verified
                    vulnerability_context=VulnerabilityContext(
                        xss_type=xss_type,
                        detection_method=DetectionMethod.MITM_PROXY
                    )
                )
                
                self.current_scan.add_finding(xss_finding)
            
        except Exception as e:
            self.logger.error(f"Error in MITM scanning phase: {e}")
    
    async def _phase_stored_xss_detection(self, target_url: str):
        """Phase 3: Stored XSS detection"""
        
        self.logger.info("Phase 3: Stored XSS detection")
        
        try:
            # Get MITM data if available
            mitm_data = []
            if self.mitm_agent:
                mitm_data = self.mitm_agent.get_intercepted_data()
            
            # Run stored XSS detection
            stored_findings = await self.stored_xss_agent.run(target_url, mitm_data)
            
            # Convert to XSS findings
            for stored_finding in stored_findings:
                xss_finding = XSSFinding(
                    xss_type=XSSType.STORED,
                    detection_method=DetectionMethod.TRAFFIC_ANALYSIS,
                    url=stored_finding.get('execution_urls', [target_url])[0] if stored_finding.get('execution_urls') else target_url,
                    payload=stored_finding.get('payload', 'N/A'),
                    severity=stored_finding.get('severity', 'high'),
                    description=f"Stored XSS affecting {stored_finding.get('total_affected_pages', 1)} pages",
                    successful=True,
                    vulnerability_context=VulnerabilityContext(
                        xss_type=XSSType.STORED,
                        detection_method=DetectionMethod.TRAFFIC_ANALYSIS
                    )
                )
                
                self.current_scan.add_finding(xss_finding)
            
        except Exception as e:
            self.logger.error(f"Error in stored XSS detection phase: {e}")
    
    async def _phase_dom_xss_detection(self, target_url: str):
        """Phase 4: DOM-based XSS detection"""
        
        self.logger.info("Phase 4: DOM-based XSS detection")
        
        try:
            # Run DOM XSS detection
            dom_findings = await self.dom_xss_agent.run(target_url)
            
            # Convert to XSS findings
            for dom_finding in dom_findings:
                xss_finding = XSSFinding(
                    xss_type=XSSType.DOM_BASED,
                    detection_method=DetectionMethod.DOM_ANALYSIS,
                    url=dom_finding.get('url', target_url),
                    payload=dom_finding.get('payload', 'N/A'),
                    severity=dom_finding.get('severity', 'medium'),
                    description=f"DOM-based XSS via {dom_finding.get('source', 'unknown source')}",
                    successful=dom_finding.get('executed', False),
                    vulnerability_context=VulnerabilityContext(
                        xss_type=XSSType.DOM_BASED,
                        detection_method=DetectionMethod.DOM_ANALYSIS
                    )
                )
                
                self.current_scan.add_finding(xss_finding)
            
        except Exception as e:
            self.logger.error(f"Error in DOM XSS detection phase: {e}")
    
    async def _dynamic_testing_loop(self, vulnerability_context: VulnerabilityContext) -> bool:
        """Dynamic testing loop with LLM-driven improvement"""
        
        while vulnerability_context.current_attempt < vulnerability_context.max_attempts:
            try:
                # Generate payload
                if vulnerability_context.current_attempt == 0:
                    attempt = await self.payload_agent.generate_initial_payload(vulnerability_context)
                else:
                    last_result = vulnerability_context.attempt_history[-1].playwright_response
                    attempt = await self.payload_agent.improve_payload(vulnerability_context, last_result)
                
                vulnerability_context.current_attempt = attempt.attempt
                
                # Test payload with Playwright
                verification_result = await self.verifier_agent.run(
                    vulnerability_context.nuclei_result.matched_url,
                    attempt.payload,
                    vulnerability_context.xss_type,
                    vulnerability_context.detection_method
                )
                
                # Update attempt with result
                attempt.result = "success" if verification_result.executed else "failure"
                attempt.playwright_response = verification_result
                
                # Add to history
                vulnerability_context.attempt_history.append(attempt)
                
                if verification_result.executed:
                    vulnerability_context.successful_payload = attempt.payload
                    self.logger.info(f"SUCCESS: Found working payload in {attempt.attempt} attempts")
                    return True
                else:
                    self.logger.debug(f"Attempt {attempt.attempt} failed, continuing...")
                
            except Exception as e:
                self.logger.error(f"Error in attempt {vulnerability_context.current_attempt + 1}: {e}")
                vulnerability_context.current_attempt += 1
        
        return False
    
    async def _save_comprehensive_results(self, target_url: str):
        """Save comprehensive scan results"""
        
        try:
            timestamp = get_timestamp()
            
            # Main results file
            results_file = f"results/comprehensive_xss_scan_{timestamp}.json"
            save_json_results(self.current_scan, results_file)
            
            # Summary report
            summary_file = f"results/xss_scan_summary_{timestamp}.json"
            summary = {
                'target_url': target_url,
                'scan_summary': self.current_scan.get_summary(),
                'configuration': {
                    'nuclei_enabled': self.config.nuclei.enabled,
                    'mitm_enabled': self.config.mitm.enabled,
                    'stored_xss_enabled': self.config.detection.enable_stored_xss,
                    'dom_xss_enabled': self.config.detection.enable_dom_xss
                },
                'agent_statistics': await self._collect_agent_statistics()
            }
            save_json_results(summary, summary_file)
            
            self.logger.info(f"Comprehensive results saved to {results_file}")
            self.logger.info(f"Summary report saved to {summary_file}")
            
        except Exception as e:
            self.logger.error(f"Error saving comprehensive results: {e}")
    
    async def _collect_agent_statistics(self) -> Dict[str, Any]:
        """Collect statistics from all agents"""
        
        stats = {}
        
        try:
            if self.recon_agent:
                stats['recon_agent'] = self.recon_agent.get_statistics()
            
            if self.payload_agent:
                stats['payload_agent'] = self.payload_agent.get_statistics()
            
            if self.verifier_agent:
                stats['verifier_agent'] = self.verifier_agent.get_statistics()
            
            if self.stored_xss_agent:
                stats['stored_xss_agent'] = self.stored_xss_agent.get_statistics()
            
            if self.dom_xss_agent:
                stats['dom_xss_agent'] = self.dom_xss_agent.get_statistics()
            
            if self.mitm_agent:
                stats['mitm_agent'] = self.mitm_agent.get_statistics()
                
        except Exception as e:
            self.logger.error(f"Error collecting agent statistics: {e}")
        
        return stats
    
    async def quick_scan(self, target_url: str, scan_type: str = "reflected") -> ScanResults:
        """Perform quick scan for specific XSS type"""
        
        self.logger.info(f"Starting quick {scan_type} XSS scan for {target_url}")
        
        scan_config = ScanConfiguration(
            target_url=target_url,
            enable_nuclei=(scan_type == "reflected"),
            enable_mitm=False,
            enable_stored_xss=(scan_type == "stored"),
            enable_dom_xss=(scan_type == "dom")
        )
        
        self.current_scan = ScanResults(
            scan_config=scan_config,
            scan_start_time=get_timestamp()
        )
        
        with Timer(f"Quick {scan_type} XSS Scan") as timer:
            if scan_type == "reflected" and self.recon_agent:
                await self._phase_nuclei_scanning(target_url)
            elif scan_type == "stored" and self.stored_xss_agent:
                await self._phase_stored_xss_detection(target_url)
            elif scan_type == "dom" and self.dom_xss_agent:
                await self._phase_dom_xss_detection(target_url)
            else:
                self.logger.error(f"Unsupported scan type or agent not available: {scan_type}")
        
        self.current_scan.scan_end_time = get_timestamp()
        self.current_scan.total_duration = timer.elapsed
        
        return self.current_scan
    
    async def cleanup(self):
        """Cleanup resources"""
        
        try:
            if self.mitm_agent:
                await self.mitm_agent.stop_proxy()
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")
    
    def get_scan_status(self) -> Dict[str, Any]:
        """Get current scan status"""
        
        if not self.current_scan:
            return {'status': 'no_active_scan'}
        
        return {
            'status': 'scanning' if not self.current_scan.scan_end_time else 'completed',
            'target_url': self.current_scan.scan_config.target_url,
            'start_time': self.current_scan.scan_start_time,
            'end_time': self.current_scan.scan_end_time,
            'duration': self.current_scan.total_duration,
            'vulnerabilities_found': self.current_scan.total_vulnerabilities,
            'success_rate': self.current_scan.get_success_rate()
        }