#!/usr/bin/env python3
"""
DOM-Based XSS Detection Agent v3.0
Enhanced with Analysis Framework

This version uses the analysis framework for intelligent, adaptive XSS testing.
"""

from .dom_xss import DOMXSSAgent, DOMXSSVulnerability
from ..analysis_framework import (
    AnalysisConfig,
    DeepAnalysisSession,
    GlobalMemoryManager,
    StrategicPayloadGenerator,
    HybridPayloadGenerator,
    AnalysisSummarizer,
    TestAttempt
)
from typing import List, Optional, Dict
import logging


class DOMXSSAgentV3(DOMXSSAgent):
    """
    DOM XSS Agent v3.0 with Analysis Framework

    Inherits from v2.2 but adds framework-based testing.
    """

    def __init__(self, framework_config: str = 'default', use_hybrid: bool = True):
        """
        Initialize agent with framework support.

        Args:
            framework_config: Configuration preset (default|aggressive|fast|conservative)
            use_hybrid: Use hybrid generator (database + LLM + mutation) vs pure LLM
        """
        super().__init__()

        # Initialize framework components
        config_map = {
            'default': AnalysisConfig.default(),
            'aggressive': AnalysisConfig.aggressive(),
            'fast': AnalysisConfig.fast(),
            'conservative': AnalysisConfig.conservative()
        }

        self.framework_config = config_map.get(framework_config, AnalysisConfig.default())
        self.global_memory = GlobalMemoryManager(self.ai_client, self.framework_config)

        # Choose generator type
        self.use_hybrid = use_hybrid
        if use_hybrid:
            self.payload_generator = HybridPayloadGenerator(
                self.ai_client, self.global_memory, self.framework_config
            )
            self.logger.info(f"Initialized DOM XSS Agent v3.0 with HYBRID generator (config: {framework_config})")
        else:
            self.payload_generator = StrategicPayloadGenerator(
                self.ai_client, self.global_memory, self.framework_config
            )
            self.logger.info(f"Initialized DOM XSS Agent v3.0 with LLM-only generator (config: {framework_config})")

        self.summarizer = AnalysisSummarizer(self.ai_client, self.framework_config)

    async def detect_dom_xss(self, target_url: str, proxy_agent=None) -> List[DOMXSSVulnerability]:
        """
        Main entry point using Analysis Framework.

        This replaces the old iterative refinement with the new framework approach.
        """
        self.logger.info(f"Starting Framework-based DOM XSS detection on {target_url}")

        vulnerabilities = []

        # Phase 1: Analyze page (existing logic from parent class)
        analysis = await self._analyze_page_javascript(target_url, proxy_agent)

        # Handle form targets if needed
        if not analysis['sinks'] and analysis['parameters']:
            self.logger.info("No sinks on landing page, checking form targets...")
            form_targets = await self._get_form_targets(target_url, proxy_agent)

            for form_target in form_targets:
                self.logger.info(f"Testing form target: {form_target}")
                form_analysis = await self._analyze_page_javascript(form_target, proxy_agent)
                form_analysis['parameters'].extend(analysis['parameters'])

                if form_analysis['sinks']:
                    analysis = form_analysis
                    target_url = form_target
                    break

        if not analysis['sources'] and not analysis['sinks']:
            self.logger.info("No DOM sources or sinks detected")
            return vulnerabilities

        self.logger.info(f"Detected {len(analysis['sources'])} sources and {len(analysis['sinks'])} sinks")

        # Phase 2: Framework-based intelligent testing
        max_attempts = self.framework_config.max_attempts_per_target

        for attempt_num in range(1, max_attempts + 1):
            self.logger.info(f"\n{'='*60}")
            self.logger.info(f"Framework Attempt {attempt_num}/{max_attempts}")
            self.logger.info(f"{'='*60}")

            # STEP 1: Generate strategic payload
            latest_strategy = None
            if self.global_memory.history:
                latest_strategy = self.global_memory.history[-1].meta.get('strategy')

            payload_data = await self.payload_generator.generate_next_payload(
                target_url=target_url,
                detected_sinks=analysis['sinks'],
                parameters=[p['name'] for p in analysis['parameters']],
                latest_strategy=latest_strategy
            )

            self.logger.info(f"Generated payload: {payload_data['payload']}")
            self.logger.info(f"Technique: {payload_data['bypass_technique']}")
            self.logger.info(f"Confidence: {payload_data['confidence']}%")

            # STEP 2: Test payload using existing test logic
            vector = {
                'source': 'location.search',
                'parameter': payload_data.get('target_parameter', 'q'),
                'payload': payload_data['payload'],
                'sink': payload_data.get('target_sink', 'innerHTML'),
                'test_url_pattern': payload_data.get('test_method', 'query_param'),
                'reasoning': payload_data.get('reasoning', '')
            }

            vuln = await self._test_dom_vector(target_url, vector, proxy_agent)

            if vuln:
                self.logger.info("✓✓✓ SUCCESS! Framework-generated payload worked!")
                vulnerabilities.append(vuln)

                # Save successful session
                self.global_memory.save_to_file(f"success_session_{target_url.replace('://', '_').replace('/', '_')}.json")
                return vulnerabilities

            # STEP 3: Deep analysis session
            self.logger.info("→ Starting deep analysis session...")

            # Build test URL and capture response
            test_url = self._build_test_url(target_url, vector)
            response_html = await self._capture_response(test_url, proxy_agent)

            attempt = TestAttempt(
                attempt_number=attempt_num,
                payload=payload_data['payload'],
                target_url=test_url,
                response_html=response_html[:5000],  # Truncate for efficiency
                response_headers={},
                success=False
            )

            session = DeepAnalysisSession(attempt, self.ai_client, self.framework_config)
            results = await session.run_until_exhausted()

            self.logger.info(f"  Completed {len(results)} analysis stages:")
            for result in results:
                self.logger.info(f"    [{result.stage_name}] {'; '.join(result.insights)}")

            # Check if analysis thinks execution is possible
            execution_possible = self._check_execution_from_analysis(results)
            if execution_possible:
                self.logger.info("⚠️  Analysis suggests execution possible - verifying with browser...")

                # RE-TEST with browser verification to confirm
                # This will check for real alert() dialogs and console output
                verified_vuln = await self._test_dom_vector(target_url, vector, proxy_agent)

                if verified_vuln:
                    self.logger.info("✓✓✓ SUCCESS! Browser verification confirmed - payload actually works!")
                    vulnerabilities.append(verified_vuln)

                    # Save successful session
                    self.global_memory.save_to_file(f"success_session_{target_url.replace('://', '_').replace('/', '_')}.json")
                    return vulnerabilities
                else:
                    self.logger.info("✗ Browser verification failed - LLM analysis was incorrect")
                    self.logger.info("  (Analysis thought it would work, but no alert dialog detected)")

            # STEP 4: Summarize
            summary = await self.summarizer.summarize(
                session_results=results,
                payload=payload_data['payload'],
                attempt_number=attempt_num
            )

            self.logger.debug(f"Summary: {summary[:200]}...")

            # STEP 5: Add to memory
            self.global_memory.add_entry(
                attempt_number=attempt_num,
                payload=payload_data['payload'],
                summary=summary,
                confidence=session.get_confidence(),
                success=False,
                meta={
                    'strategy': session.get_final_strategy(),
                    'technique': payload_data['bypass_technique']
                }
            )

            # Pattern analysis every 10 attempts
            if attempt_num % 10 == 0:
                self.logger.info("\n→ Analyzing patterns across attempts...")
                patterns = await self.global_memory.analyze_patterns()
                if patterns.get('status') != 'error':
                    self.logger.info(f"  Patterns: {patterns}")

        # No success
        self.logger.info(f"\nCompleted {max_attempts} attempts without finding vulnerability")

        # Show coverage stats if using hybrid generator
        if self.use_hybrid and hasattr(self.payload_generator, 'get_coverage_stats'):
            stats = self.payload_generator.get_coverage_stats()
            self.logger.info(f"\n→ Hybrid Generator Coverage Stats:")
            self.logger.info(f"  Techniques tried: {stats['techniques_tried']}/{stats['total_techniques']} ({stats['coverage_percentage']}%)")
            self.logger.info(f"  Payloads tried: {stats['payloads_tried']}/{stats['total_payloads_in_db']}")
            self.logger.info(f"  Final phase: {stats['current_phase']}")

        # Save session for analysis
        self.global_memory.save_to_file(f"failed_session_{target_url.replace('://', '_').replace('/', '_')}.json")

        return vulnerabilities

    async def _capture_response(self, test_url: str, proxy_agent=None) -> str:
        """Helper to capture response HTML for analysis"""
        from playwright.async_api import async_playwright

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
                response_html = await page.content()
                return response_html
            except Exception as e:
                self.logger.error(f"Error capturing response: {e}")
                return ""
            finally:
                await browser.close()

    def _check_execution_from_analysis(self, results: List) -> bool:
        """
        Check if analysis results indicate execution is possible.

        Looks for Context Detection stage saying "✓ Execution possible"
        """
        for result in results:
            if result.stage_name == "Context Detection":
                # Check insights for execution indicators
                for insight in result.insights:
                    if "✓ Execution possible" in insight or "execution possible" in insight.lower():
                        return True

                # Check data for execution_possible flag
                if result.data.get('execution_possible'):
                    return True

        return False

    def _create_vulnerability_from_analysis(
        self,
        target_url: str,
        vector: Dict,
        results: List
    ) -> DOMXSSVulnerability:
        """
        Create vulnerability object from analysis results.
        """
        # Extract context information
        html_context = "unknown"
        js_context = "unknown"
        execution_evidence = []

        for result in results:
            if result.stage_name == "Context Detection":
                html_context = result.data.get('html_context', 'none')
                js_context = result.data.get('js_context', 'none')

                # Build evidence from insights
                execution_evidence = result.insights[:3]  # Top 3 insights

        # Create source/sink objects using correct constructors
        from .dom_xss import DOMSource, DOMSink
        import datetime

        source = DOMSource(
            source_type=vector.get('source', 'location.search'),
            parameter=vector.get('parameter'),
            value=vector['payload'],
            location="Framework-detected"
        )

        sink = DOMSink(
            sink_type=vector.get('sink', 'location.href'),
            sink_location=f"HTML context: {html_context}, JS context: {js_context}",
            tainted_value=vector['payload'],
            source_trace=["Framework analysis confirmed execution"]
        )

        # Create vulnerability with all required fields
        vuln = DOMXSSVulnerability(
            vulnerability_id=f"dom_xss_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}",
            url=target_url,
            source=source,
            sink=sink,
            payload=vector['payload'],
            executed=True,  # Framework confirmed execution
            execution_evidence=execution_evidence,
            timestamp=datetime.datetime.now().isoformat(),
            severity='high',
            recommendation="Implement proper input validation and output encoding for DOM manipulation. "
                         "The payload was detected through framework analysis as having execution capability."
        )

        return vuln
