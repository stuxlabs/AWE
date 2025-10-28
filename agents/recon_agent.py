#!/usr/bin/env python3
"""
Reconnaissance Agent - Nuclei-based XSS scanning
Extracted and enhanced from original dynamic_xss_agent.py
"""

import json
import logging
import os
import subprocess
from typing import List, Optional
from playwright.async_api import async_playwright

from agno.agent import Agent
try:
    from core.models import NucleiResult, XSSType, DetectionMethod
    from core.utils import get_timestamp
except ImportError:
    # Fallback for missing core modules - use classes from dynamic_xss_agent
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from dynamic_xss_agent import NucleiResult
    
    def get_timestamp():
        from datetime import datetime
        return datetime.now().strftime("%Y%m%d_%H%M%S")

from persistence import PersistenceCandidate, PersistenceCandidateExtractor


def run_nuclei_direct(target_url: str, output_file: str, config: Optional[dict] = None) -> bool:
    """Run Nuclei binary directly against target URL"""
    try:
        logger = logging.getLogger(__name__)
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        logger.info(f"Running Nuclei against {target_url}")
        
        # Build command
        cmd = [
            'nuclei',
            '-u', target_url,
            '-tags', 'xss',
            '-jsonl',
            '-o', output_file,
            '-silent'
        ]
        
        # Add additional options from config
        if config:
            if config.get('templates'):
                cmd.extend(['-t'] + config['templates'])
            if config.get('rate_limit'):
                cmd.extend(['-rl', str(config['rate_limit'])])
            if config.get('threads'):
                cmd.extend(['-c', str(config['threads'])])
            if config.get('timeout'):
                cmd.extend(['-timeout', str(config['timeout'])])
        
        # Run nuclei
        timeout = config.get('timeout', 120) if config else 120
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        
        if result.returncode == 0:
            logger.debug("Nuclei completed successfully")
            return os.path.exists(output_file) and os.path.getsize(output_file) > 0
        else:
            logger.error(f"Nuclei failed with return code {result.returncode}")
            if result.stderr:
                logger.error(f"Nuclei stderr: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        logger.error(f"Nuclei scan timeout after {timeout} seconds")
        return False
    except FileNotFoundError:
        logger.error("Nuclei binary not found. Please ensure Nuclei is installed.")
        return False
    except Exception as e:
        logger.error(f"Unexpected error running Nuclei: {e}")
        return False


def parse_nuclei_results(raw_json_file: str) -> List[NucleiResult]:
    """Parse Nuclei JSON output into structured results"""
    logger = logging.getLogger(__name__)
    results = []
    
    try:
        with open(raw_json_file, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line.strip())
                    
                    result = NucleiResult(
                        template_id=data.get('template-id', 'unknown'),
                        template_name=data.get('info', {}).get('name', 'Unknown'),
                        severity=data.get('info', {}).get('severity', 'unknown'),
                        description=data.get('info', {}).get('description', 'No description'),
                        matched_url=data.get('matched-at', data.get('host', '')),
                        injection_point=data.get('extracted-results', [None])[0] if data.get('extracted-results') else None,
                        raw_data=data
                    )
                    results.append(result)
                    
                except json.JSONDecodeError:
                    continue
                    
    except FileNotFoundError:
        logger.error(f"Nuclei results file not found: {raw_json_file}")
    except Exception as e:
        logger.error(f"Error parsing Nuclei results: {e}")
    
    return results


class ReconAgent(Agent):
    """Agent responsible for running Nuclei and parsing results"""
    
    def __init__(self, config: Optional[dict] = None):
        super().__init__()
        self.config = config or {}
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Nuclei configuration
        self.nuclei_config = {
            'timeout': self.config.get('nuclei_timeout', 120),
            'rate_limit': self.config.get('nuclei_rate_limit', 100),
            'threads': self.config.get('nuclei_threads', 25),
            'templates': self.config.get('nuclei_templates', []),
            'severity_filter': self.config.get('nuclei_severity_filter', ['low', 'medium', 'high', 'critical'])
        }
        
        # Initialize persistence candidate extractor
        self.persistence_extractor = PersistenceCandidateExtractor()
        
    async def run(self, target_url: str) -> List[NucleiResult]:
        """Run Nuclei against target and return parsed results"""
        self.logger.info(f"Starting reconnaissance on {target_url}")
        
        # Create output directory
        os.makedirs("./results", exist_ok=True)
        timestamp = get_timestamp()
        output_file = os.path.abspath(f"./results/nuclei_output_{timestamp}.json")
        
        try:
            # Run nuclei scan
            success = run_nuclei_direct(target_url, output_file, self.nuclei_config)
            
            if not success:
                self.logger.error("Failed to run Nuclei")
                return []
            
            # Parse results
            results = parse_nuclei_results(output_file)
            
            # Filter by severity if configured
            if self.nuclei_config.get('severity_filter'):
                filtered_results = []
                for result in results:
                    if result.severity.lower() in [s.lower() for s in self.nuclei_config['severity_filter']]:
                        filtered_results.append(result)
                results = filtered_results
            
            self.logger.info(f"Found {len(results)} XSS vulnerabilities matching severity filter")
            
            # Save summary
            self._save_scan_summary(target_url, results, output_file)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error in reconnaissance: {e}")
            return []
        
        finally:
            if os.path.exists(output_file):
                self.logger.debug(f"Nuclei output saved to: {output_file}")
    
    def _save_scan_summary(self, target_url: str, results: List[NucleiResult], output_file: str):
        """Save scan summary"""
        try:
            summary = {
                'target_url': target_url,
                'scan_timestamp': get_timestamp(),
                'total_findings': len(results),
                'findings_by_severity': {},
                'findings_by_template': {},
                'nuclei_output_file': output_file
            }
            
            # Group by severity
            for result in results:
                severity = result.severity.lower()
                summary['findings_by_severity'][severity] = summary['findings_by_severity'].get(severity, 0) + 1
            
            # Group by template
            for result in results:
                template = result.template_id
                summary['findings_by_template'][template] = summary['findings_by_template'].get(template, 0) + 1
            
            # Save summary
            summary_file = output_file.replace('.json', '_summary.json')
            with open(summary_file, 'w') as f:
                json.dump(summary, f, indent=2, default=str)
            
            self.logger.debug(f"Scan summary saved to: {summary_file}")
            
        except Exception as e:
            self.logger.warning(f"Could not save scan summary: {e}")
    
    async def get_persistence_candidates(self, target_url: str) -> List[PersistenceCandidate]:
        """
        Discover persistence candidates for OAST triggering
        
        Args:
            target_url: Target URL to analyze for persistence points
            
        Returns:
            List of PersistenceCandidate objects with scored persistence potential
        """
        self.logger.info(f"Discovering persistence candidates for {target_url}")
        
        try:
            # Use Playwright to fetch page content and analyze for persistence points
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context()
                page = await context.new_page()
                
                try:
                    # Navigate to target URL
                    response = await page.goto(target_url, wait_until='networkidle', timeout=30000)
                    
                    if not response:
                        self.logger.warning(f"No response received from {target_url}")
                        return []
                    
                    # Get page content
                    html_content = await page.content()
                    response_status = response.status
                    
                    # Extract persistence candidates from HTML
                    candidates = self.persistence_extractor.extract_from_html(
                        url=target_url,
                        html_content=html_content,
                        response_status=response_status
                    )
                    
                    self.logger.info(f"Found {len(candidates)} persistence candidates")
                    
                    # Log details about each candidate
                    for candidate in candidates:
                        self.logger.debug(
                            f"Candidate {candidate.id}: {candidate.method} {candidate.url} "
                            f"(js_score={candidate.js_templating_score:.2f}, "
                            f"path_score={candidate.path_keywords_score:.2f})"
                        )
                    
                    return candidates
                    
                except Exception as e:
                    self.logger.error(f"Error analyzing page {target_url}: {e}")
                    return []
                    
                finally:
                    await browser.close()
                    
        except Exception as e:
            self.logger.error(f"Failed to discover persistence candidates: {e}")
            return []
    
    def get_statistics(self) -> dict:
        """Get statistics about the reconnaissance"""
        return {
            'nuclei_config': self.nuclei_config,
            'supported_severities': self.nuclei_config.get('severity_filter', []),
            'timeout_seconds': self.nuclei_config.get('timeout', 120)
        }