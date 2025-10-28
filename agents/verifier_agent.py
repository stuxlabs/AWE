#!/usr/bin/env python3
"""
Dynamic Verification Agent
Enhanced from original dynamic_xss_agent.py with support for multiple XSS types
"""

import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Any

from agno.agent import Agent
from playwright.async_api import async_playwright, Page, ConsoleMessage
from core.models import VerificationResult, XSSType, DetectionMethod
from core.utils import inject_payload_into_url, get_timestamp


class DynamicVerifierAgent(Agent):
    """Agent responsible for testing payloads with Playwright and providing detailed feedback"""
    
    def __init__(self, config: Optional[dict] = None):
        super().__init__()
        self.config = config or {}
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Playwright configuration
        self.playwright_config = {
            'headless': self.config.get('playwright_headless', True),
            'browser_type': self.config.get('playwright_browser', 'chromium'),
            'timeout': self.config.get('playwright_timeout', 30000),
            'wait_until': self.config.get('playwright_wait_until', 'networkidle'),
            'viewport': self.config.get('playwright_viewport', {'width': 1920, 'height': 1080})
        }
        
        # Output directories
        self.screenshot_dir = Path(self.config.get('screenshot_dir', 'screenshots'))
        self.html_captures_dir = Path(self.config.get('html_captures_dir', 'html_captures'))
        self.screenshot_dir.mkdir(exist_ok=True)
        self.html_captures_dir.mkdir(exist_ok=True)
        
        # Verification timeouts by XSS type
        self.verification_timeouts = {
            XSSType.REFLECTED: 3000,  # 3 seconds
            XSSType.STORED: 5000,     # 5 seconds  
            XSSType.DOM_BASED: 7000   # 7 seconds for DOM manipulation
        }
    
    async def run(self, target_url: str, payload: str, 
                 xss_type: XSSType = XSSType.REFLECTED,
                 detection_method: DetectionMethod = DetectionMethod.NUCLEI) -> VerificationResult:
        """Test a single payload using Playwright with detailed feedback"""
        
        # Determine test URL based on XSS type
        if xss_type == XSSType.DOM_BASED:
            # For DOM XSS, try different injection methods
            test_url = await self._prepare_dom_test_url(target_url, payload)
        else:
            # For reflected/stored XSS, inject into URL parameters
            test_url = inject_payload_into_url(target_url, payload)
        
        self.logger.info(f"Testing {xss_type.value} payload: {payload[:50]}...")
        
        # Create output directories
        self.screenshot_dir.mkdir(exist_ok=True)
        self.html_captures_dir.mkdir(exist_ok=True)
        
        async with async_playwright() as p:
            # Launch browser based on configuration
            if self.playwright_config['browser_type'] == 'firefox':
                browser = await p.firefox.launch(headless=self.playwright_config['headless'])
            elif self.playwright_config['browser_type'] == 'webkit':
                browser = await p.webkit.launch(headless=self.playwright_config['headless'])
            else:
                browser = await p.chromium.launch(headless=self.playwright_config['headless'])
            
            context = await browser.new_context(viewport=self.playwright_config['viewport'])
            page = await context.new_page()
            
            # Set up monitoring
            alerts_caught = []
            console_logs = []
            response_status = None
            response_headers = {}
            dom_mutations = []
            
            # Monitor responses
            def handle_response(response):
                nonlocal response_status, response_headers
                if response.url == test_url or response.url == target_url:
                    response_status = response.status
                    response_headers = dict(response.headers)
            
            page.on("response", handle_response)
            
            # Monitor dialogs (alerts, confirms, prompts)
            async def handle_dialog(dialog):
                alert_info = {
                    'message': dialog.message,
                    'type': dialog.type,
                    'timestamp': get_timestamp()
                }
                alerts_caught.append(alert_info)
                self.logger.info(f"XSS Alert caught: {dialog.message}")
                await dialog.accept()
            
            page.on("dialog", handle_dialog)
            
            # Monitor console messages
            def handle_console(msg: ConsoleMessage):
                console_logs.append({
                    'type': msg.type,
                    'text': msg.text,
                    'location': str(msg.location) if msg.location else None,
                    'timestamp': get_timestamp()
                })
            
            page.on("console", handle_console)
            
            # Set up DOM mutation monitoring for DOM XSS
            if xss_type == XSSType.DOM_BASED:
                await self._setup_dom_monitoring(page)
            
            try:
                # Navigate to page with payload
                response = await page.goto(
                    test_url, 
                    wait_until=self.playwright_config['wait_until'], 
                    timeout=self.playwright_config['timeout']
                )
                
                if response:
                    response_status = response.status
                    response_headers = dict(response.headers)
                
                # Wait for XSS execution based on type
                wait_time = self.verification_timeouts.get(xss_type, 3000)
                await page.wait_for_timeout(wait_time)
                
                # For DOM XSS, trigger additional events
                if xss_type == XSSType.DOM_BASED:
                    await self._trigger_dom_events(page)
                
                # Get page content
                page_content = await page.content()
                reflection_found = payload in page_content
                
                # Get DOM mutations if available
                if xss_type == XSSType.DOM_BASED:
                    dom_mutations = await self._get_dom_mutations(page)
                
                # Save HTML content to file
                html_file_path = await self._save_html_content(
                    page_content, test_url, payload, xss_type
                )
                
                # Check if payload executed
                executed, execution_method = self._determine_execution_status(
                    alerts_caught, console_logs, reflection_found, payload, xss_type, dom_mutations
                )
                
                # Take screenshot
                screenshot_path = await self._take_screenshot(
                    page, executed, execution_method or 'failed', xss_type
                )
                
                result = VerificationResult(
                    url=test_url,
                    payload=payload,
                    executed=executed,
                    reflection_found=reflection_found,
                    xss_type=xss_type,
                    execution_method=execution_method,
                    screenshot_path=screenshot_path,
                    timestamp=get_timestamp(),
                    console_logs=console_logs,
                    alerts_caught=[alert['message'] for alert in alerts_caught],
                    page_content=page_content[:1000] + "..." if len(page_content) > 1000 else page_content,
                    page_content_file=html_file_path,
                    response_status=response_status,
                    response_headers=response_headers,
                    dom_mutations=dom_mutations
                )
                
                self.logger.info(f"{xss_type.value} verification complete: {'SUCCESS' if executed else 'FAILED'}")
                if executed:
                    self.logger.info(f"Execution method: {execution_method}")
                
                return result
                
            except Exception as e:
                self.logger.error(f"Verification error: {e}")
                return await self._handle_verification_error(
                    e, test_url, payload, xss_type, page, console_logs, alerts_caught
                )
            
            finally:
                await browser.close()
    
    async def _prepare_dom_test_url(self, target_url: str, payload: str) -> str:
        """Prepare test URL for DOM XSS testing"""
        
        # Try different DOM sources
        dom_test_methods = [
            f"{target_url}#{payload}",  # location.hash
            f"{target_url}?xss={payload}",  # location.search
            target_url  # Will set window.name separately
        ]
        
        # For now, return hash-based injection
        # TODO: Could be enhanced to test multiple methods
        return f"{target_url}#{payload}"
    
    async def _setup_dom_monitoring(self, page: Page):
        """Set up DOM mutation monitoring"""
        
        await page.add_init_script('''
            window.domMutations = [];
            const observer = new MutationObserver((mutations) => {
                mutations.forEach((mutation) => {
                    if (mutation.type === 'childList' || mutation.type === 'attributes') {
                        window.domMutations.push({
                            type: mutation.type,
                            target: mutation.target.tagName || 'UNKNOWN',
                            addedNodes: Array.from(mutation.addedNodes).map(n => n.tagName || n.textContent?.substring(0, 50)),
                            removedNodes: Array.from(mutation.removedNodes).map(n => n.tagName || n.textContent?.substring(0, 50)),
                            timestamp: Date.now()
                        });
                    }
                });
            });
            
            // Start observing
            if (document.body) {
                observer.observe(document.body, {
                    childList: true,
                    subtree: true,
                    attributes: true
                });
            } else {
                document.addEventListener('DOMContentLoaded', () => {
                    observer.observe(document.body, {
                        childList: true,
                        subtree: true,
                        attributes: true
                    });
                });
            }
        ''')
    
    async def _trigger_dom_events(self, page: Page):
        """Trigger events that might cause DOM XSS execution"""
        
        try:
            # Trigger various events that might execute DOM XSS
            await page.evaluate('''
                // Trigger hashchange event
                if (window.location.hash) {
                    window.dispatchEvent(new HashChangeEvent('hashchange'));
                }
                
                // Trigger resize event
                window.dispatchEvent(new Event('resize'));
                
                // Trigger focus events
                document.dispatchEvent(new Event('focus'));
                
                // Click on various elements
                const clickableElements = document.querySelectorAll('a, button, input, [onclick]');
                clickableElements.forEach((el, index) => {
                    if (index < 3) { // Limit to first 3 elements
                        try {
                            el.click();
                        } catch (e) {
                            // Ignore click errors
                        }
                    }
                });
            ''')
            
        except Exception as e:
            self.logger.debug(f"Error triggering DOM events: {e}")
    
    async def _get_dom_mutations(self, page: Page) -> List[Dict[str, Any]]:
        """Get DOM mutations that occurred"""
        
        try:
            mutations = await page.evaluate('window.domMutations || []')
            return mutations[:20]  # Limit to prevent excessive data
        except Exception as e:
            self.logger.debug(f"Error getting DOM mutations: {e}")
            return []
    
    def _determine_execution_status(self, alerts_caught: List[Dict], console_logs: List[Dict],
                                   reflection_found: bool, payload: str, xss_type: XSSType,
                                   dom_mutations: List[Dict]) -> tuple[bool, Optional[str]]:
        """Determine if XSS payload executed and how"""
        
        # Check for alert execution (highest confidence)
        if alerts_caught:
            return True, "alert"
        
        # Check for console-based execution
        xss_indicators = ['XSS', 'xss', 'alert', 'script', payload[:20]]
        for log in console_logs:
            log_text = log.get('text', '').lower()
            if any(indicator.lower() in log_text for indicator in xss_indicators):
                return True, "console"
        
        # For DOM XSS, check for DOM mutations
        if xss_type == XSSType.DOM_BASED and dom_mutations:
            # Look for script-related mutations
            for mutation in dom_mutations:
                added_nodes = mutation.get('addedNodes', [])
                if any('script' in str(node).lower() for node in added_nodes):
                    return True, "dom_mutation"
        
        # Check for reflected payload with dangerous elements
        if reflection_found:
            dangerous_elements = ['<script>', '<svg', '<img', '<iframe', 'javascript:', 'onerror', 'onload']
            if any(element.lower() in payload.lower() for element in dangerous_elements):
                # Additional DOM check for script elements
                return True, "dom_reflection"
        
        return False, None
    
    async def _save_html_content(self, page_content: str, test_url: str, 
                                payload: str, xss_type: XSSType) -> str:
        """Save HTML content to file"""
        
        timestamp = get_timestamp()
        filename = f"{xss_type.value}_content_{timestamp}.html"
        file_path = self.html_captures_dir / filename
        
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(f"<!-- XSS Type: {xss_type.value} -->\n")
                f.write(f"<!-- URL: {test_url} -->\n")
                f.write(f"<!-- Payload: {payload} -->\n")
                f.write(f"<!-- Timestamp: {timestamp} -->\n\n")
                f.write(page_content)
            
            return str(file_path)
            
        except Exception as e:
            self.logger.error(f"Error saving HTML content: {e}")
            return ""
    
    async def _take_screenshot(self, page: Page, executed: bool, 
                              execution_method: str, xss_type: XSSType) -> str:
        """Take screenshot of the page"""
        
        timestamp = get_timestamp()
        status = "success" if executed else "failed"
        filename = f"{xss_type.value}_{status}_{execution_method}_{timestamp}.png"
        screenshot_path = self.screenshot_dir / filename
        
        try:
            await page.screenshot(
                path=str(screenshot_path), 
                full_page=self.config.get('screenshot_full_page', True)
            )
            return str(screenshot_path)
            
        except Exception as e:
            self.logger.error(f"Error taking screenshot: {e}")
            return ""
    
    async def _handle_verification_error(self, error: Exception, test_url: str, 
                                        payload: str, xss_type: XSSType, page: Page,
                                        console_logs: List[Dict], alerts_caught: List[Dict]) -> VerificationResult:
        """Handle verification errors gracefully"""
        
        error_timestamp = get_timestamp()
        
        # Try to take error screenshot
        error_screenshot = None
        try:
            error_screenshot_path = self.screenshot_dir / f"error_{xss_type.value}_{error_timestamp}.png"
            await page.screenshot(path=str(error_screenshot_path), full_page=True)
            error_screenshot = str(error_screenshot_path)
        except:
            pass
        
        # Try to capture error page content
        error_html = None
        try:
            page_content = await page.content()
            error_html_path = self.html_captures_dir / f"error_{xss_type.value}_{error_timestamp}.html"
            with open(error_html_path, 'w', encoding='utf-8') as f:
                f.write(f"<!-- ERROR CAPTURE -->\n")
                f.write(f"<!-- XSS Type: {xss_type.value} -->\n")
                f.write(f"<!-- URL: {test_url} -->\n")
                f.write(f"<!-- Payload: {payload} -->\n")
                f.write(f"<!-- Error: {error} -->\n")
                f.write(f"<!-- Timestamp: {error_timestamp} -->\n\n")
                f.write(page_content)
            error_html = str(error_html_path)
        except:
            error_html = None
        
        return VerificationResult(
            url=test_url,
            payload=payload,
            executed=False,
            reflection_found=False,
            xss_type=xss_type,
            error=str(error),
            timestamp=error_timestamp,
            console_logs=console_logs,
            alerts_caught=[alert.get('message', '') for alert in alerts_caught],
            page_content=f"Failed to capture due to error: {error}",
            page_content_file=error_html,
            screenshot_path=error_screenshot
        )
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about verification"""
        
        return {
            'playwright_config': self.playwright_config,
            'screenshot_dir': str(self.screenshot_dir),
            'html_captures_dir': str(self.html_captures_dir),
            'verification_timeouts': {k.value: v for k, v in self.verification_timeouts.items()},
            'supported_browsers': ['chromium', 'firefox', 'webkit']
        }