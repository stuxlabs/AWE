#!/usr/bin/env python3
"""
Stored XSS Detection Agent
Specializes in detecting stored/persistent XSS vulnerabilities
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple
from pathlib import Path

from agno.agent import Agent
from playwright.async_api import async_playwright, Page, Browser
from core.models import (
    StoredXSSContext, PayloadAttempt, VerificationResult, 
    VulnerabilityContext, XSSType, DetectionMethod
)
from core.utils import (
    extract_forms_from_html, inject_payload_into_url, 
    generate_xss_payloads, get_timestamp, Timer
)


class StoredXSSAgent(Agent):
    """Agent for detecting stored XSS vulnerabilities"""
    
    def __init__(self, config: Optional[Dict] = None):
        super().__init__()
        self.config = config or {}
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Configuration
        self.max_crawl_depth = self.config.get('max_crawl_depth', 2)
        self.delay_between_requests = self.config.get('delay_between_requests', 2.0)
        self.verification_delay = self.config.get('verification_delay', 3.0)
        self.max_verification_urls = self.config.get('max_verification_urls', 10)
        
        # Tracking
        self.injected_payloads: Dict[str, StoredXSSContext] = {}
        self.discovered_urls: Set[str] = set()
        self.verified_forms: Dict[str, List[Dict]] = {}
        
        # Payloads optimized for stored XSS
        self.stored_xss_payloads = [
            '<script>alert("Stored-XSS-Test")</script>',
            '<img src=x onerror=alert("Stored-XSS")>',
            '<svg onload=alert("Stored-XSS")>',
            '"><script>alert("Stored-XSS")</script>',
            '<iframe src=javascript:alert("Stored-XSS")>',
            '<body onload=alert("Stored-XSS")>',
            '<div onmouseover=alert("Stored-XSS")>test</div>',
            '<input type="text" onfocus=alert("Stored-XSS")>',
            '<textarea onkeyup=alert("Stored-XSS")></textarea>',
            '\'-alert("Stored-XSS")-\'',
            '";alert("Stored-XSS");"',
            'javascript:alert("Stored-XSS")'
        ]
    
    async def run(self, target_url: str, mitm_data: Optional[List] = None) -> List[Dict[str, Any]]:
        """Main stored XSS detection workflow"""
        
        self.logger.info(f"Starting stored XSS detection for {target_url}")
        
        with Timer("Stored XSS Detection") as timer:
            # Phase 1: Discovery and crawling
            discovered_forms = await self._discover_injection_points(target_url)
            
            # Phase 2: Payload injection
            injection_contexts = await self._inject_payloads(discovered_forms)
            
            # Phase 3: Verification across application
            verification_results = await self._verify_stored_payloads(target_url, injection_contexts)
            
            # Phase 4: Analysis and reporting
            findings = await self._analyze_findings(verification_results)
        
        self.logger.info(f"Stored XSS detection completed in {timer.elapsed:.2f} seconds")
        self.logger.info(f"Found {len(findings)} potential stored XSS vulnerabilities")
        
        return findings
    
    async def _discover_injection_points(self, target_url: str) -> Dict[str, List[Dict]]:
        """Discover forms and input points for payload injection"""
        
        self.logger.info("Discovering injection points...")
        discovered_forms = {}
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=self.config.get('headless', True))
            context = await browser.new_context()
            page = await context.new_page()
            
            try:
                # Visit target URL and extract forms
                await page.goto(target_url, wait_until='networkidle', timeout=30000)
                await page.wait_for_timeout(2000)
                
                # Get page content and extract forms
                content = await page.content()
                forms = extract_forms_from_html(content, target_url)
                
                if forms:
                    discovered_forms[target_url] = forms
                    self.logger.info(f"Found {len(forms)} forms on {target_url}")
                
                # Crawl for additional pages with forms
                additional_urls = await self._crawl_for_forms(page, target_url)
                discovered_forms.update(additional_urls)
                
            except Exception as e:
                self.logger.error(f"Error discovering injection points: {e}")
            finally:
                await browser.close()
        
        total_forms = sum(len(forms) for forms in discovered_forms.values())
        self.logger.info(f"Discovery complete. Found {total_forms} forms across {len(discovered_forms)} pages")
        
        return discovered_forms
    
    async def _crawl_for_forms(self, page: Page, base_url: str) -> Dict[str, List[Dict]]:
        """Crawl website to find additional pages with forms"""
        
        crawled_forms = {}
        visited_urls = {base_url}
        
        try:
            # Extract links from current page
            links = await page.evaluate('''
                () => {
                    const links = Array.from(document.querySelectorAll('a[href]'));
                    return links.map(link => link.href).filter(href => 
                        href && 
                        href.startsWith(window.location.origin) && 
                        !href.includes('#') &&
                        !href.includes('mailto:') &&
                        !href.includes('javascript:')
                    );
                }
            ''')
            
            # Visit each link up to crawl depth limit
            for link in links[:self.max_verification_urls]:
                if link in visited_urls:
                    continue
                
                try:
                    self.logger.debug(f"Crawling: {link}")
                    await page.goto(link, wait_until='networkidle', timeout=20000)
                    await page.wait_for_timeout(1000)
                    
                    # Extract forms from this page
                    content = await page.content()
                    forms = extract_forms_from_html(content, link)
                    
                    if forms:
                        crawled_forms[link] = forms
                        self.logger.debug(f"Found {len(forms)} forms on {link}")
                    
                    visited_urls.add(link)
                    
                    # Respect rate limiting
                    await asyncio.sleep(self.delay_between_requests)
                    
                except Exception as e:
                    self.logger.warning(f"Error crawling {link}: {e}")
                    continue
        
        except Exception as e:
            self.logger.error(f"Error during crawling: {e}")
        
        return crawled_forms
    
    async def _inject_payloads(self, discovered_forms: Dict[str, List[Dict]]) -> List[StoredXSSContext]:
        """Inject payloads into discovered forms"""
        
        self.logger.info("Injecting stored XSS payloads...")
        injection_contexts = []
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=self.config.get('headless', True))
            context = await browser.new_context()
            page = await context.new_page()
            
            try:
                for url, forms in discovered_forms.items():
                    for form_idx, form_info in enumerate(forms):
                        # Try each payload on each form
                        for payload_idx, payload in enumerate(self.stored_xss_payloads[:5]):  # Limit payloads
                            try:
                                injection_context = await self._inject_single_payload(
                                    page, url, form_info, payload, payload_idx
                                )
                                if injection_context:
                                    injection_contexts.append(injection_context)
                                
                                # Small delay between injections
                                await asyncio.sleep(0.5)
                                
                            except Exception as e:
                                self.logger.warning(f"Error injecting payload {payload_idx} into form {form_idx}: {e}")
                
            except Exception as e:
                self.logger.error(f"Error during payload injection: {e}")
            finally:
                await browser.close()
        
        self.logger.info(f"Payload injection complete. Created {len(injection_contexts)} injection contexts")
        return injection_contexts
    
    async def _inject_single_payload(self, page: Page, url: str, form_info: Dict, 
                                   payload: str, payload_idx: int) -> Optional[StoredXSSContext]:
        """Inject a single payload into a specific form"""
        
        try:
            # Navigate to form page
            await page.goto(url, wait_until='networkidle', timeout=20000)
            await page.wait_for_timeout(1000)
            
            # Find the form and determine injection strategy
            if form_info.get('inputs'):
                # Fill form inputs with payload
                for input_info in form_info['inputs']:
                    input_name = input_info.get('name')
                    input_type = input_info.get('type', 'text')
                    
                    if input_name and input_type.lower() not in ['submit', 'button', 'hidden']:
                        try:
                            selector = f'input[name="{input_name}"]'
                            await page.fill(selector, payload)
                            self.logger.debug(f"Filled input '{input_name}' with payload")
                        except Exception as e:
                            self.logger.debug(f"Could not fill input '{input_name}': {e}")
                
                # Fill textareas
                for textarea_info in form_info.get('textareas', []):
                    textarea_name = textarea_info.get('name')
                    if textarea_name:
                        try:
                            selector = f'textarea[name="{textarea_name}"]'
                            await page.fill(selector, payload)
                            self.logger.debug(f"Filled textarea '{textarea_name}' with payload")
                        except Exception as e:
                            self.logger.debug(f"Could not fill textarea '{textarea_name}': {e}")
                
                # Submit form
                submit_selector = 'input[type="submit"], button[type="submit"], button:not([type])'
                try:
                    await page.click(submit_selector)
                    await page.wait_for_timeout(2000)  # Wait for submission
                except Exception as e:
                    self.logger.debug(f"Could not submit form: {e}")
                
                # Create injection context
                injection_context = StoredXSSContext(
                    injection_url=url,
                    payload=payload,
                    injection_point=f"form_{payload_idx}",
                    verification_urls=[],  # Will be populated during verification
                    delay_before_check=self.verification_delay
                )
                
                return injection_context
        
        except Exception as e:
            self.logger.error(f"Error injecting payload into form: {e}")
            return None
    
    async def _verify_stored_payloads(self, target_url: str, 
                                    injection_contexts: List[StoredXSSContext]) -> List[VerificationResult]:
        """Verify if injected payloads are stored and executed on other pages"""
        
        self.logger.info("Verifying stored payloads...")
        verification_results = []
        
        # Wait for payloads to be stored
        await asyncio.sleep(self.verification_delay)
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=self.config.get('headless', True))
            context = await browser.new_context()
            page = await context.new_page()
            
            # Set up monitoring
            alerts_caught = []
            console_logs = []
            
            async def handle_dialog(dialog):
                alerts_caught.append(dialog.message)
                await dialog.accept()
                self.logger.info(f"Alert caught: {dialog.message}")
            
            def handle_console(msg):
                console_logs.append({
                    'type': msg.type,
                    'text': msg.text,
                    'url': page.url
                })
            
            page.on("dialog", handle_dialog)
            page.on("console", handle_console)
            
            try:
                # Get list of URLs to check
                verification_urls = await self._get_verification_urls(target_url, page)
                
                for injection_context in injection_contexts:
                    self.logger.debug(f"Verifying payload: {injection_context.payload[:30]}...")
                    
                    # Check each URL for payload execution
                    for check_url in verification_urls:
                        try:
                            # Clear previous alerts/logs
                            alerts_caught.clear()
                            console_logs.clear()
                            
                            # Visit the page
                            await page.goto(check_url, wait_until='networkidle', timeout=20000)
                            await page.wait_for_timeout(3000)  # Wait for potential XSS execution
                            
                            # Check page content
                            content = await page.content()
                            payload_in_content = injection_context.payload in content
                            
                            # Create verification result
                            result = VerificationResult(
                                url=check_url,
                                payload=injection_context.payload,
                                executed=(len(alerts_caught) > 0),
                                reflection_found=payload_in_content,
                                xss_type=XSSType.STORED,
                                execution_method="alert" if alerts_caught else None,
                                console_logs=console_logs.copy(),
                                alerts_caught=alerts_caught.copy(),
                                page_content=content[:1000] if content else None,
                                timestamp=get_timestamp()
                            )
                            
                            # Take screenshot if XSS detected
                            if result.executed or result.reflection_found:
                                screenshot_name = f"stored_xss_{get_timestamp()}.png"
                                screenshot_path = f"screenshots/{screenshot_name}"
                                await page.screenshot(path=screenshot_path, full_page=True)
                                result.screenshot_path = screenshot_path
                                
                                self.logger.info(f"Stored XSS detected on {check_url}!")
                            
                            verification_results.append(result)
                            
                        except Exception as e:
                            self.logger.warning(f"Error verifying {check_url}: {e}")
                            
                        await asyncio.sleep(1)  # Rate limiting
                
            except Exception as e:
                self.logger.error(f"Error during verification: {e}")
            finally:
                await browser.close()
        
        successful_verifications = [r for r in verification_results if r.executed or r.reflection_found]
        self.logger.info(f"Verification complete. {len(successful_verifications)} successful detections")
        
        return verification_results
    
    async def _get_verification_urls(self, target_url: str, page: Page) -> List[str]:
        """Get list of URLs to check for stored payload execution"""
        
        verification_urls = [target_url]  # Always check main page
        
        try:
            # Visit main page and extract additional URLs
            await page.goto(target_url, wait_until='networkidle', timeout=20000)
            
            # Extract navigation links
            links = await page.evaluate('''
                () => {
                    const links = Array.from(document.querySelectorAll('a[href]'));
                    return links.map(link => link.href).filter(href => 
                        href && 
                        href.startsWith(window.location.origin) && 
                        !href.includes('#') &&
                        !href.includes('logout') &&
                        !href.includes('delete') &&
                        href.length < 200
                    );
                }
            ''')
            
            # Add unique links (limited)
            unique_links = list(set(links))[:self.max_verification_urls]
            verification_urls.extend(unique_links)
            
        except Exception as e:
            self.logger.warning(f"Error getting verification URLs: {e}")
        
        return list(set(verification_urls))  # Remove duplicates
    
    async def _analyze_findings(self, verification_results: List[VerificationResult]) -> List[Dict[str, Any]]:
        """Analyze verification results and create findings"""
        
        findings = []
        
        # Group results by payload
        payload_groups = {}
        for result in verification_results:
            if result.payload not in payload_groups:
                payload_groups[result.payload] = []
            payload_groups[result.payload].append(result)
        
        # Create findings for successful stored XSS
        for payload, results in payload_groups.items():
            successful_results = [r for r in results if r.executed or r.reflection_found]
            
            if successful_results:
                # Determine severity
                severity = self._assess_stored_xss_severity(payload, successful_results)
                
                finding = {
                    'xss_type': 'stored',
                    'payload': payload,
                    'severity': severity,
                    'execution_urls': [r.url for r in successful_results if r.executed],
                    'reflection_urls': [r.url for r in successful_results if r.reflection_found],
                    'total_affected_pages': len(successful_results),
                    'detection_method': 'stored_xss_agent',
                    'timestamp': get_timestamp(),
                    'screenshots': [r.screenshot_path for r in successful_results if r.screenshot_path],
                    'verification_results': [
                        {
                            'url': r.url,
                            'executed': r.executed,
                            'reflected': r.reflection_found,
                            'alerts_count': len(r.alerts_caught or []),
                            'console_logs_count': len(r.console_logs or [])
                        } for r in successful_results
                    ]
                }
                
                findings.append(finding)
        
        return findings
    
    def _assess_stored_xss_severity(self, payload: str, results: List[VerificationResult]) -> str:
        """Assess severity of stored XSS finding"""
        
        executed_count = sum(1 for r in results if r.executed)
        affected_pages = len(results)
        
        # High severity if executing on multiple pages
        if executed_count >= 3 or affected_pages >= 5:
            return 'critical'
        elif executed_count >= 1:
            return 'high'
        elif any(r.reflection_found for r in results):
            return 'medium'
        else:
            return 'low'
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about stored XSS detection"""
        return {
            'total_payloads_injected': len(self.injected_payloads),
            'discovered_urls': len(self.discovered_urls),
            'verified_forms': sum(len(forms) for forms in self.verified_forms.values())
        }