#!/usr/bin/env python3
"""
Playwright Verification Logging Integration

This module provides comprehensive logging integration for Playwright-based verification,
capturing screenshots, HTML content, console logs, network activity, and DOM snapshots
for forensic analysis.
"""

import asyncio
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from playwright.async_api import Page, Browser, BrowserContext, ConsoleMessage, Response, Request
from utils.forensic_logger import ForensicLoggerManager


class PlaywrightForensicLogger:
    """
    Enhanced Playwright logger that captures comprehensive verification data
    """
    
    def __init__(self, forensic_logger: ForensicLoggerManager, attempt_id: str = None):
        """
        Initialize Playwright forensic logger
        
        Args:
            forensic_logger: ForensicLoggerManager instance
            attempt_id: Current attempt ID for correlation
        """
        self.forensic_logger = forensic_logger
        self.attempt_id = attempt_id
        self.verification_id = f"verify_{int(time.time() * 1000)}"
        
        # Data collection
        self.console_logs = []
        self.network_requests = []
        self.network_responses = []
        self.dialogs = []
        self.errors = []
        self.dom_snapshots = []
        
        # Tracking
        self.start_time = None
        self.page_loaded = False
        self.screenshots_taken = 0
        self.html_captures = 0
    
    def setup_page_monitoring(self, page: Page):
        """
        Setup comprehensive monitoring on a Playwright page
        
        Args:
            page: Playwright page instance
        """
        self.start_time = time.time()
        
        # Console logging
        page.on("console", self._handle_console_message)
        
        # Dialog handling (alerts, confirms, prompts)
        page.on("dialog", self._handle_dialog)
        
        # Network monitoring
        page.on("request", self._handle_request)
        page.on("response", self._handle_response)
        
        # Error handling
        page.on("pageerror", self._handle_page_error)
        page.on("crash", self._handle_page_crash)
        
        # Load detection
        page.on("load", self._handle_page_load)
        
        self.forensic_logger.log_event('playwright.monitoring_setup', {
            'verification_id': self.verification_id,
            'attempt_id': self.attempt_id,
            'page_url': page.url if hasattr(page, 'url') else 'unknown'
        })
    
    async def capture_comprehensive_state(
        self, 
        page: Page, 
        payload: str, 
        description: str = "verification"
    ) -> Dict[str, Any]:
        """
        Capture comprehensive page state for forensic analysis
        
        Args:
            page: Playwright page instance
            payload: XSS payload being tested
            description: Description of capture context
            
        Returns:
            Dictionary with paths to captured artifacts
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
        base_name = f"{description}_{self.verification_id}_{timestamp}"
        
        artifacts = {
            'verification_id': self.verification_id,
            'attempt_id': self.attempt_id,
            'timestamp': timestamp,
            'payload': payload,
            'page_url': page.url
        }
        
        # 1. Capture screenshot
        try:
            screenshot_path = self.forensic_logger.current_run_dir / 'playwright' / f'screenshot_{base_name}.png'
            await page.screenshot(path=screenshot_path, full_page=True)
            artifacts['screenshot'] = f'playwright/screenshot_{base_name}.png'
            self.screenshots_taken += 1
            
            self.forensic_logger.log_event('playwright.screenshot_captured', {
                'verification_id': self.verification_id,
                'screenshot_path': str(screenshot_path),
                'full_page': True
            })
            
        except Exception as e:
            self.forensic_logger.log_event('playwright.screenshot_error', {
                'verification_id': self.verification_id,
                'error': str(e)
            })
            artifacts['screenshot_error'] = str(e)
        
        # 2. Capture HTML content
        try:
            html_content = await page.content()
            html_path = self.forensic_logger.current_run_dir / 'playwright' / f'html_{base_name}.html'
            
            # Add metadata to HTML
            html_with_metadata = f"""<!DOCTYPE html>
<!-- FORENSIC CAPTURE METADATA -->
<!-- Verification ID: {self.verification_id} -->
<!-- Attempt ID: {self.attempt_id} -->
<!-- Timestamp: {timestamp} -->
<!-- Payload: {payload} -->
<!-- Page URL: {page.url} -->
<!-- Capture Context: {description} -->
<!-- END METADATA -->

{html_content}"""
            
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_with_metadata)
            
            artifacts['html'] = f'playwright/html_{base_name}.html'
            artifacts['html_size_bytes'] = len(html_content)
            self.html_captures += 1
            
        except Exception as e:
            self.forensic_logger.log_event('playwright.html_capture_error', {
                'verification_id': self.verification_id,
                'error': str(e)
            })
            artifacts['html_error'] = str(e)
        
        # 3. Capture DOM snapshot (if possible)
        try:
            # Get a more detailed DOM representation
            dom_info = await page.evaluate("""
                () => {
                    const getElementInfo = (element) => {
                        const rect = element.getBoundingClientRect();
                        return {
                            tagName: element.tagName,
                            id: element.id,
                            className: element.className,
                            innerHTML: element.innerHTML?.substring(0, 1000), // Limit size
                            attributes: Array.from(element.attributes).map(attr => ({
                                name: attr.name,
                                value: attr.value
                            })),
                            rect: {
                                x: rect.x,
                                y: rect.y,
                                width: rect.width,
                                height: rect.height
                            },
                            visible: rect.width > 0 && rect.height > 0
                        };
                    };
                    
                    // Find elements that might contain our payload
                    const allElements = Array.from(document.querySelectorAll('*'));
                    const payloadElements = allElements.filter(el => 
                        el.innerHTML && el.innerHTML.includes('""" + payload.replace('"', '\\"').replace("'", "\\'") + """')
                    );
                    
                    return {
                        title: document.title,
                        url: window.location.href,
                        userAgent: navigator.userAgent,
                        cookieCount: document.cookie.split(';').filter(c => c.trim()).length,
                        scriptCount: document.scripts.length,
                        payloadElements: payloadElements.slice(0, 10).map(getElementInfo), // Limit to 10
                        totalElements: allElements.length,
                        bodyContent: document.body?.innerHTML?.substring(0, 2000) || 'No body'
                    };
                }
            """)
            
            dom_path = self.forensic_logger.current_run_dir / 'playwright' / f'dom_{base_name}.json'
            with open(dom_path, 'w', encoding='utf-8') as f:
                json.dump(dom_info, f, indent=2, default=str)
            
            artifacts['dom_snapshot'] = f'playwright/dom_{base_name}.json'
            artifacts['payload_elements_found'] = len(dom_info.get('payloadElements', []))
            
        except Exception as e:
            self.forensic_logger.log_event('playwright.dom_snapshot_error', {
                'verification_id': self.verification_id,
                'error': str(e)
            })
            artifacts['dom_error'] = str(e)
        
        # 4. Save console logs
        if self.console_logs:
            console_path = self.forensic_logger.current_run_dir / 'playwright' / f'console_{base_name}.json'
            with open(console_path, 'w', encoding='utf-8') as f:
                json.dump(self.console_logs, f, indent=2, default=str)
            
            artifacts['console_logs'] = f'playwright/console_{base_name}.json'
            artifacts['console_log_count'] = len(self.console_logs)
        
        # 5. Save network activity
        if self.network_requests or self.network_responses:
            network_data = {
                'requests': self.network_requests,
                'responses': self.network_responses,
                'request_count': len(self.network_requests),
                'response_count': len(self.network_responses)
            }
            
            network_path = self.forensic_logger.current_run_dir / 'playwright' / f'network_{base_name}.json'
            with open(network_path, 'w', encoding='utf-8') as f:
                json.dump(network_data, f, indent=2, default=str)
            
            artifacts['network_activity'] = f'playwright/network_{base_name}.json'
            artifacts['network_requests_count'] = len(self.network_requests)
        
        # 6. Save dialogs/alerts
        if self.dialogs:
            dialogs_path = self.forensic_logger.current_run_dir / 'playwright' / f'dialogs_{base_name}.json'
            with open(dialogs_path, 'w', encoding='utf-8') as f:
                json.dump(self.dialogs, f, indent=2, default=str)
            
            artifacts['dialogs'] = f'playwright/dialogs_{base_name}.json'
            artifacts['dialog_count'] = len(self.dialogs)
        
        # 7. Performance and timing information
        try:
            performance_info = await page.evaluate("""
                () => {
                    const perfEntries = performance.getEntriesByType('navigation')[0];
                    const timing = performance.timing;
                    
                    return {
                        loadComplete: perfEntries ? perfEntries.loadEventEnd - perfEntries.loadEventStart : 0,
                        domContentLoaded: perfEntries ? perfEntries.domContentLoadedEventEnd - perfEntries.domContentLoadedEventStart : 0,
                        totalLoadTime: timing ? timing.loadEventEnd - timing.navigationStart : 0,
                        domElements: document.querySelectorAll('*').length,
                        memoryUsage: performance.memory ? {
                            usedJSHeapSize: performance.memory.usedJSHeapSize,
                            totalJSHeapSize: performance.memory.totalJSHeapSize,
                            jsHeapSizeLimit: performance.memory.jsHeapSizeLimit
                        } : null
                    };
                }
            """)
            
            artifacts['performance'] = performance_info
            
        except Exception as e:
            artifacts['performance_error'] = str(e)
        
        # Add timing information
        if self.start_time:
            artifacts['capture_duration_ms'] = int((time.time() - self.start_time) * 1000)
        
        # Log comprehensive capture completion
        self.forensic_logger.log_event('playwright.comprehensive_capture_completed', artifacts)
        
        return artifacts
    
    async def analyze_xss_execution(self, page: Page, payload: str) -> Dict[str, Any]:
        """
        Analyze whether XSS payload executed and how
        
        Args:
            page: Playwright page instance
            payload: XSS payload to analyze
            
        Returns:
            Analysis results
        """
        analysis = {
            'verification_id': self.verification_id,
            'payload': payload,
            'executed': False,
            'execution_methods': [],
            'evidence': []
        }
        
        # 1. Check for JavaScript alerts (already handled by dialog monitoring)
        if any(d.get('type') == 'alert' for d in self.dialogs):
            analysis['executed'] = True
            analysis['execution_methods'].append('alert')
            analysis['evidence'].append(f"Alert dialog detected: {[d['message'] for d in self.dialogs if d.get('type') == 'alert']}")
        
        # 2. Check console for XSS-related output
        xss_console_logs = [
            log for log in self.console_logs 
            if any(keyword in log.get('text', '').lower() for keyword in ['xss', 'alert', 'script', payload.lower()[:10]])
        ]
        if xss_console_logs:
            analysis['executed'] = True
            analysis['execution_methods'].append('console_output')
            analysis['evidence'].append(f"XSS-related console output: {len(xss_console_logs)} entries")
        
        # 3. Check for JavaScript errors that might indicate execution
        error_logs = [log for log in self.console_logs if log.get('type') == 'error']
        if error_logs:
            analysis['execution_methods'].append('javascript_error')
            analysis['evidence'].append(f"JavaScript errors detected: {len(error_logs)} errors")
        
        # 4. Advanced DOM analysis for execution
        try:
            dom_analysis = await page.evaluate(f"""
                (payload) => {{
                    const results = {{
                        payloadInDOM: false,
                        scriptsWithPayload: 0,
                        executableElements: 0,
                        suspiciousAttributes: []
                    }};
                    
                    // Check if payload appears in DOM
                    if (document.body.innerHTML.includes(payload)) {{
                        results.payloadInDOM = true;
                    }}
                    
                    // Check for script elements containing payload
                    const scripts = Array.from(document.querySelectorAll('script'));
                    results.scriptsWithPayload = scripts.filter(s => s.innerHTML.includes(payload)).length;
                    
                    // Check for elements with event handlers that might execute payload
                    const allElements = Array.from(document.querySelectorAll('*'));
                    const eventHandlers = ['onclick', 'onload', 'onerror', 'onmouseover'];
                    
                    allElements.forEach(el => {{
                        eventHandlers.forEach(handler => {{
                            const attr = el.getAttribute(handler);
                            if (attr && attr.includes(payload)) {{
                                results.executableElements++;
                                results.suspiciousAttributes.push({{
                                    tagName: el.tagName,
                                    attribute: handler,
                                    value: attr.substring(0, 100)
                                }});
                            }}
                        }});
                    }});
                    
                    return results;
                }}
            """, payload)
            
            if dom_analysis['payloadInDOM']:
                analysis['evidence'].append("Payload found in DOM")
            
            if dom_analysis['scriptsWithPayload'] > 0:
                analysis['executed'] = True
                analysis['execution_methods'].append('script_element')
                analysis['evidence'].append(f"Payload found in {dom_analysis['scriptsWithPayload']} script elements")
            
            if dom_analysis['executableElements'] > 0:
                analysis['executed'] = True
                analysis['execution_methods'].append('event_handler')
                analysis['evidence'].append(f"Payload found in {dom_analysis['executableElements']} event handlers")
            
            analysis['dom_analysis'] = dom_analysis
            
        except Exception as e:
            analysis['dom_analysis_error'] = str(e)
        
        # 5. Check network requests for payload execution side effects
        payload_related_requests = [
            req for req in self.network_requests
            if payload.lower()[:10] in req.get('url', '').lower() or 
               payload.lower()[:10] in str(req.get('postData', '')).lower()
        ]
        
        if payload_related_requests:
            analysis['execution_methods'].append('network_side_effect')
            analysis['evidence'].append(f"Payload-related network requests: {len(payload_related_requests)}")
        
        # Log the analysis
        self.forensic_logger.log_event('playwright.xss_analysis_completed', analysis)
        
        return analysis
    
    def _handle_console_message(self, msg: ConsoleMessage):
        """Handle console message"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'type': msg.type,
            'text': msg.text,
            'location': {
                'url': msg.location.get('url') if msg.location else None,
                'line': msg.location.get('lineNumber') if msg.location else None,
                'column': msg.location.get('columnNumber') if msg.location else None
            } if msg.location else None,
            'args_count': len(msg.args) if msg.args else 0
        }
        
        self.console_logs.append(log_entry)
        
        # Log significant console events
        if msg.type in ['error', 'warning']:
            self.forensic_logger.log_event(f'playwright.console_{msg.type}', {
                'verification_id': self.verification_id,
                'message': msg.text,
                'location': log_entry['location']
            })
    
    async def _handle_dialog(self, dialog):
        """Handle dialog (alert, confirm, prompt)"""
        dialog_info = {
            'timestamp': datetime.now().isoformat(),
            'type': dialog.type,
            'message': dialog.message,
            'default_value': dialog.default_value if hasattr(dialog, 'default_value') else None
        }
        
        self.dialogs.append(dialog_info)
        
        # Auto-accept dialogs and log
        await dialog.accept()
        
        self.forensic_logger.log_event('playwright.dialog_detected', {
            'verification_id': self.verification_id,
            'dialog_type': dialog.type,
            'message': dialog.message
        })
    
    def _handle_request(self, request: Request):
        """Handle network request"""
        request_info = {
            'timestamp': datetime.now().isoformat(),
            'url': request.url,
            'method': request.method,
            'headers': dict(request.headers),
            'postData': request.post_data if hasattr(request, 'post_data') else None,
            'resourceType': request.resource_type if hasattr(request, 'resource_type') else None
        }
        
        self.network_requests.append(request_info)
    
    def _handle_response(self, response: Response):
        """Handle network response"""
        response_info = {
            'timestamp': datetime.now().isoformat(),
            'url': response.url,
            'status': response.status,
            'statusText': response.status_text,
            'headers': dict(response.headers),
            'ok': response.ok
        }
        
        self.network_responses.append(response_info)
    
    def _handle_page_error(self, error):
        """Handle page JavaScript errors"""
        error_info = {
            'timestamp': datetime.now().isoformat(),
            'error': str(error),
            'type': 'page_error'
        }
        
        self.errors.append(error_info)
        
        self.forensic_logger.log_event('playwright.page_error', {
            'verification_id': self.verification_id,
            'error': str(error)
        })
    
    def _handle_page_crash(self):
        """Handle page crash"""
        crash_info = {
            'timestamp': datetime.now().isoformat(),
            'type': 'page_crash'
        }
        
        self.errors.append(crash_info)
        
        self.forensic_logger.log_event('playwright.page_crash', {
            'verification_id': self.verification_id
        })
    
    def _handle_page_load(self):
        """Handle page load completion"""
        self.page_loaded = True
        
        self.forensic_logger.log_event('playwright.page_loaded', {
            'verification_id': self.verification_id,
            'load_time_ms': int((time.time() - self.start_time) * 1000) if self.start_time else 0
        })
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of captured data"""
        return {
            'verification_id': self.verification_id,
            'attempt_id': self.attempt_id,
            'duration_ms': int((time.time() - self.start_time) * 1000) if self.start_time else 0,
            'console_logs_count': len(self.console_logs),
            'network_requests_count': len(self.network_requests),
            'network_responses_count': len(self.network_responses),
            'dialogs_count': len(self.dialogs),
            'errors_count': len(self.errors),
            'screenshots_taken': self.screenshots_taken,
            'html_captures': self.html_captures,
            'page_loaded': self.page_loaded
        }


class EnhancedVerifierAgent:
    """
    Enhanced verifier agent wrapper with comprehensive Playwright logging
    """
    
    def __init__(self, original_verifier, forensic_logger: ForensicLoggerManager):
        """
        Initialize enhanced verifier agent
        
        Args:
            original_verifier: Original DynamicVerifierAgent instance
            forensic_logger: ForensicLoggerManager instance
        """
        self.original = original_verifier
        self.forensic_logger = forensic_logger
    
    async def run(self, target_url: str, payload: str, proxy_agent=None, attempt_id: str = None):
        """Enhanced verification run with comprehensive logging"""
        
        # Create forensic logger for this verification
        playwright_logger = PlaywrightForensicLogger(self.forensic_logger, attempt_id)
        
        # Log verification start
        self.forensic_logger.log_event('verification.playwright.started', {
            'target_url': target_url,
            'payload': payload[:100],  # Truncate for logging
            'attempt_id': attempt_id,
            'verification_id': playwright_logger.verification_id,
            'proxy_enabled': proxy_agent is not None
        })
        
        try:
            # Enhanced verification with comprehensive monitoring
            result = await self._run_enhanced_verification(
                target_url, 
                payload, 
                proxy_agent,
                playwright_logger
            )
            
            # Log successful completion
            summary = playwright_logger.get_summary()
            self.forensic_logger.log_event('verification.playwright.completed', {
                'verification_id': playwright_logger.verification_id,
                'executed': result.executed,
                'reflection_found': result.reflection_found,
                'execution_method': result.execution_method,
                'summary': summary
            })
            
            return result
            
        except Exception as e:
            # Log verification error
            self.forensic_logger.log_event('verification.playwright.error', {
                'verification_id': playwright_logger.verification_id,
                'error': str(e),
                'error_type': type(e).__name__
            })
            raise
    
    async def _run_enhanced_verification(self, target_url: str, payload: str, proxy_agent, playwright_logger: PlaywrightForensicLogger):
        """Run enhanced verification with comprehensive monitoring"""
        
        # Import here to avoid circular imports
        from dynamic_xss_agent import VerificationResult, inject_payload_into_url
        from playwright.async_api import async_playwright
        
        test_url = inject_payload_into_url(target_url, payload)
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            
            # Configure browser context
            context_options = {}
            if proxy_agent and proxy_agent.running:
                proxy_url = proxy_agent.get_proxy_url()
                context_options['proxy'] = {'server': proxy_url}
            
            context = await browser.new_context(**context_options)
            page = await context.new_page()
            
            # Setup comprehensive monitoring
            playwright_logger.setup_page_monitoring(page)
            
            try:
                # Navigate to page with payload
                self.forensic_logger.log_event('verification.navigation.started', {
                    'verification_id': playwright_logger.verification_id,
                    'test_url': test_url
                })
                
                response = await page.goto(test_url, wait_until='networkidle', timeout=30000)
                
                # Initial state capture
                initial_artifacts = await playwright_logger.capture_comprehensive_state(
                    page, payload, "initial_load"
                )
                
                # Wait for any delayed execution
                await page.wait_for_timeout(3000)
                
                # Post-wait state capture
                post_wait_artifacts = await playwright_logger.capture_comprehensive_state(
                    page, payload, "post_wait"
                )
                
                # Analyze XSS execution
                xss_analysis = await playwright_logger.analyze_xss_execution(page, payload)
                
                # Final state capture
                final_artifacts = await playwright_logger.capture_comprehensive_state(
                    page, payload, "final_state"
                )
                
                # Determine execution status
                executed = xss_analysis['executed']
                execution_method = ', '.join(xss_analysis['execution_methods']) if xss_analysis['execution_methods'] else None
                
                # Get page content for reflection check
                page_content = await page.content()
                reflection_found = payload in page_content
                
                # Create comprehensive result
                result = VerificationResult(
                    url=test_url,
                    payload=payload,
                    executed=executed,
                    reflection_found=reflection_found,
                    execution_method=execution_method,
                    screenshot_path=final_artifacts.get('screenshot'),
                    timestamp=datetime.now().strftime("%Y%m%d_%H%M%S"),
                    console_logs=playwright_logger.console_logs,
                    alerts_caught=[d['message'] for d in playwright_logger.dialogs if d.get('type') == 'alert'],
                    page_content=page_content[:1000] + "..." if len(page_content) > 1000 else page_content,
                    page_content_file=final_artifacts.get('html'),
                    response_status=response.status if response else None,
                    response_headers=dict(response.headers) if response else {},
                    proxy_captures=proxy_agent.get_captures() if proxy_agent else []
                )
                
                # Add forensic data to result
                result.forensic_data = {
                    'verification_id': playwright_logger.verification_id,
                    'xss_analysis': xss_analysis,
                    'initial_artifacts': initial_artifacts,
                    'post_wait_artifacts': post_wait_artifacts,
                    'final_artifacts': final_artifacts,
                    'summary': playwright_logger.get_summary()
                }
                
                return result
                
            finally:
                await browser.close()


def enhance_verifier_agent(verifier_agent, forensic_logger: ForensicLoggerManager) -> EnhancedVerifierAgent:
    """
    Enhance an existing verifier agent with comprehensive Playwright logging
    
    Args:
        verifier_agent: Existing DynamicVerifierAgent instance
        forensic_logger: ForensicLoggerManager instance
        
    Returns:
        Enhanced verifier agent with comprehensive logging
    """
    return EnhancedVerifierAgent(verifier_agent, forensic_logger)