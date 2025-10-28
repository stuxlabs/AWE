#!/usr/bin/env python3
"""
MITM Agent - Coordinates MITM proxy for XSS detection
Manages proxy server and traffic analysis
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

from agno.agent import Agent
from core.models import MITMInterceptionResult, XSSType, DetectionMethod
from core.utils import get_timestamp
from proxy.mitm_proxy import MITMManager, MITM_AVAILABLE
from proxy.analyzer import TrafficAnalyzer


class MITMAgent(Agent):
    """Agent for coordinating MITM proxy operations"""
    
    def __init__(self, config: Optional[dict] = None):
        super().__init__()
        self.config = config or {}
        self.logger = logging.getLogger(self.__class__.__name__)
        
        if not MITM_AVAILABLE:
            self.logger.error("MITM functionality not available - mitmproxy not installed")
            raise ImportError("mitmproxy is required for MITM agent")
        
        # MITM configuration
        self.mitm_config = {
            'proxy_port': self.config.get('mitm_port', 8080),
            'bind_address': self.config.get('mitm_bind_address', '127.0.0.1'),
            'ssl_insecure': self.config.get('mitm_ssl_insecure', True),
            'output_directory': self.config.get('mitm_output_dir', 'mitm_logs')
        }
        
        # Initialize MITM manager and analyzer
        self.mitm_manager = MITMManager(self.mitm_config)
        self.traffic_analyzer = TrafficAnalyzer()
        self.proxy_server = None
        self.is_running = False
        
    async def start_proxy(self) -> bool:
        """Start MITM proxy server"""
        
        try:
            self.logger.info(f"Starting MITM proxy on port {self.mitm_config['proxy_port']}")
            self.proxy_server = await self.mitm_manager.start_proxy()
            
            if self.proxy_server and self.proxy_server.is_running():
                self.is_running = True
                self.logger.info(f"MITM proxy started successfully")
                self.logger.info(f"Configure your browser to use proxy: {self.proxy_server.get_proxy_url()}")
                return True
            else:
                self.logger.error("Failed to start MITM proxy")
                return False
                
        except Exception as e:
            self.logger.error(f"Error starting MITM proxy: {e}")
            return False
    
    async def stop_proxy(self):
        """Stop MITM proxy server"""
        
        if self.proxy_server and self.is_running:
            try:
                await self.mitm_manager.stop_proxy()
                self.is_running = False
                self.logger.info("MITM proxy stopped")
            except Exception as e:
                self.logger.error(f"Error stopping MITM proxy: {e}")
    
    async def run(self, target_url: str, duration: int = 300) -> List[Dict[str, Any]]:
        """Run MITM interception for specified duration and analyze traffic"""
        
        self.logger.info(f"Starting MITM analysis for {target_url} (duration: {duration}s)")
        
        findings = []
        
        if not self.is_running:
            if not await self.start_proxy():
                return findings
        
        try:
            # Wait for traffic interception
            self.logger.info(f"Intercepting traffic for {duration} seconds...")
            self.logger.info(f"Please configure your browser to use proxy: {self.proxy_server.get_proxy_url()}")
            self.logger.info("Navigate to the target application and perform actions that might trigger XSS")
            
            # Monitor for the specified duration
            await asyncio.sleep(duration)
            
            # Get intercepted data
            intercepted_data = self.mitm_manager.get_all_intercepted_data()
            self.logger.info(f"Intercepted {len(intercepted_data)} requests")
            
            if intercepted_data:
                # Analyze traffic for XSS vulnerabilities
                analysis_results = self.traffic_analyzer.analyze_traffic_session(intercepted_data)
                
                # Convert analysis to findings
                findings = self._convert_analysis_to_findings(analysis_results, target_url)
                
                # Save detailed results
                await self._save_mitm_results(analysis_results, intercepted_data, target_url)
            
        except Exception as e:
            self.logger.error(f"Error during MITM analysis: {e}")
        
        finally:
            # Keep proxy running for potential additional use
            pass
        
        self.logger.info(f"MITM analysis complete. Found {len(findings)} potential vulnerabilities")
        return findings
    
    def _convert_analysis_to_findings(self, analysis_results: Dict[str, Any], 
                                     target_url: str) -> List[Dict[str, Any]]:
        """Convert traffic analysis results to XSS findings"""
        
        findings = []
        
        # Process reflected XSS findings
        for reflected_xss in analysis_results.get('reflected_xss', []):
            finding = {
                'xss_type': XSSType.REFLECTED.value,
                'detection_method': DetectionMethod.MITM_PROXY.value,
                'url': reflected_xss['url'],
                'payload': reflected_xss['payload'],
                'injection_point': reflected_xss['injection_point'],
                'severity': reflected_xss['severity'],
                'context': reflected_xss['context'],
                'timestamp': reflected_xss['timestamp'],
                'method': reflected_xss['method'],
                'session_id': reflected_xss.get('session_id'),
                'source': 'mitm_traffic_analysis'
            }
            findings.append(finding)
        
        # Process stored XSS findings
        for stored_xss in analysis_results.get('stored_xss', []):
            finding = {
                'xss_type': XSSType.STORED.value,
                'detection_method': DetectionMethod.MITM_PROXY.value,
                'injection_url': stored_xss['injection_url'],
                'execution_url': stored_xss['execution_url'],
                'payload': stored_xss['payload'],
                'injection_point': stored_xss['injection_point'],
                'severity': stored_xss['severity'],
                'context': stored_xss['context'],
                'injection_time': stored_xss['injection_time'],
                'execution_time': stored_xss['execution_time'],
                'delay_seconds': stored_xss.get('delay_seconds'),
                'session_id': stored_xss.get('session_id'),
                'source': 'mitm_traffic_analysis'
            }
            findings.append(finding)
        
        # Process DOM XSS findings
        for dom_xss in analysis_results.get('dom_xss', []):
            finding = {
                'xss_type': XSSType.DOM_BASED.value,
                'detection_method': DetectionMethod.MITM_PROXY.value,
                'url': dom_xss['url'],
                'dom_sinks': dom_xss['dom_sinks'],
                'dom_sources': dom_xss['dom_sources'],
                'dangerous_combinations': dom_xss['dangerous_combinations'],
                'severity': dom_xss['severity'],
                'timestamp': dom_xss['timestamp'],
                'source': 'mitm_traffic_analysis'
            }
            findings.append(finding)
        
        return findings
    
    async def _save_mitm_results(self, analysis_results: Dict[str, Any], 
                                intercepted_data: List[MITMInterceptionResult],
                                target_url: str):
        """Save MITM analysis results"""
        
        try:
            import json
            from pathlib import Path
            
            timestamp = get_timestamp()
            results_dir = Path(self.mitm_config['output_directory'])
            results_dir.mkdir(exist_ok=True)
            
            # Save analysis results
            analysis_file = results_dir / f"mitm_analysis_{timestamp}.json"
            with open(analysis_file, 'w') as f:
                json.dump(analysis_results, f, indent=2, default=str)
            
            # Save raw intercepted data
            raw_data_file = results_dir / f"mitm_raw_data_{timestamp}.json"
            raw_data = []
            for item in intercepted_data:
                raw_data.append({
                    'request_url': item.request_url,
                    'request_method': item.request_method,
                    'request_headers': item.request_headers,
                    'request_body': item.request_body,
                    'response_status': item.response_status,
                    'response_headers': item.response_headers,
                    'response_body': item.response_body[:1000] if item.response_body else None,  # Truncate
                    'injected_payload': item.injected_payload,
                    'injection_point': item.injection_point,
                    'payload_reflected': item.payload_reflected,
                    'payload_stored': item.payload_stored,
                    'timestamp': item.timestamp,
                    'session_id': item.session_id
                })
            
            with open(raw_data_file, 'w') as f:
                json.dump(raw_data, f, indent=2, default=str)
            
            self.logger.info(f"MITM results saved to {analysis_file} and {raw_data_file}")
            
        except Exception as e:
            self.logger.error(f"Error saving MITM results: {e}")
    
    async def inject_test_payloads(self, target_url: str, 
                                  payloads: Optional[List[str]] = None) -> Dict[str, Any]:
        """Inject test payloads and monitor for XSS"""
        
        if not payloads:
            payloads = [
                '<script>alert("MITM-XSS-Test")</script>',
                '<img src=x onerror=alert("MITM-XSS")>',
                '<svg onload=alert("MITM-XSS")>',
                '"><script>alert("MITM-XSS")</script>',
                'javascript:alert("MITM-XSS")'
            ]
        
        injection_results = {
            'payloads_injected': len(payloads),
            'injection_attempts': [],
            'successful_injections': 0
        }
        
        # This would integrate with browser automation to inject payloads
        # through forms while MITM proxy monitors the traffic
        
        self.logger.info(f"Payload injection via MITM not yet implemented")
        self.logger.info("Please manually inject payloads while MITM proxy is running")
        
        return injection_results
    
    def get_proxy_status(self) -> Dict[str, Any]:
        """Get current proxy status"""
        
        return {
            'running': self.is_running,
            'proxy_url': self.proxy_server.get_proxy_url() if self.proxy_server else None,
            'config': self.mitm_config,
            'intercepted_requests': len(self.mitm_manager.get_all_intercepted_data()) if self.mitm_manager else 0
        }
    
    def get_intercepted_data(self) -> List[MITMInterceptionResult]:
        """Get all intercepted data"""
        
        if self.mitm_manager:
            return self.mitm_manager.get_all_intercepted_data()
        return []
    
    def get_discovered_forms(self) -> Dict[str, List[Dict]]:
        """Get forms discovered during traffic analysis"""
        
        if self.mitm_manager:
            return self.mitm_manager.get_discovered_forms()
        return {}
    
    async def analyze_stored_payloads(self, response_body: str, url: str) -> List[str]:
        """Analyze response for stored XSS payloads"""
        
        if self.mitm_manager:
            return self.mitm_manager.analyze_for_stored_xss(response_body, url)
        return []
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get MITM agent statistics"""
        
        stats = {
            'mitm_available': MITM_AVAILABLE,
            'proxy_running': self.is_running,
            'proxy_config': self.mitm_config
        }
        
        if self.mitm_manager:
            intercepted_data = self.mitm_manager.get_all_intercepted_data()
            stats.update({
                'total_requests_intercepted': len(intercepted_data),
                'requests_with_payloads': sum(1 for r in intercepted_data if r.injected_payload),
                'reflected_payloads': sum(1 for r in intercepted_data if r.payload_reflected),
                'stored_payloads': sum(1 for r in intercepted_data if r.payload_stored)
            })
        
        return stats