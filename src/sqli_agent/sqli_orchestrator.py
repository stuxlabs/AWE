"""
SQL Injection Detection Orchestrator

Main orchestrator for SQL injection testing using the analysis framework.
"""
import asyncio
import logging
import json
from pathlib import Path
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs

from .models import (
    SQLiSessionResult,
    SQLiType,
    DatabaseType,
    InjectionPoint,
    SQLiVerificationResult
)
from .agents.verifier import SQLiVerifierAgent
from .agents.verifier_v2 import SQLiVerifierAgentV2
from .agents.aggressive_verifier import AggressiveSQLiVerifier
from .agents.parameter_discovery import ParameterDiscoveryAgent
from .agents.nuclei_sqli import NucleiSQLiScanner
from .analyzers.database_fingerprinter import DatabaseFingerprinter
from .analyzers.context_analyzer import SQLContextAnalyzer
from .analyzers.sast_analyzer import SQLiSASTAnalyzer, SASTProfile
from .analysis_framework.config import SQLiAnalysisConfig

# Try to import hybrid generator and LLM
try:
    from .analysis_framework.sqli_hybrid_generator import SQLiHybridGenerator
    from ..xss_agent.llm_client import get_llm_client
    HYBRID_AVAILABLE = True
except ImportError as e:
    import logging
    logging.getLogger("SQLiOrchestrator").warning(f"Hybrid generator imports failed: {e}")
    HYBRID_AVAILABLE = False
except Exception as e:
    import logging
    logging.getLogger("SQLiOrchestrator").error(f"Unexpected error importing hybrid generator: {e}")
    HYBRID_AVAILABLE = False


class SQLiOrchestrator:
    """
    Orchestrates SQL injection testing workflow

    Workflow:
    1. Discover injectable parameters
    2. Fingerprint database (optional)
    3. Systematic payload testing with database payloads
    4. Verify findings with multiple detection methods
    5. Generate comprehensive report
    """

    def __init__(
        self,
        target_url: str,
        config: Optional[SQLiAnalysisConfig] = None,
        use_hybrid: bool = False,
        memory_manager=None,
        reasoning_tracker=None,
        reasoning_session_id=None
    ):
        self.target_url = target_url
        self.config = config or SQLiAnalysisConfig.default()
        self.logger = logging.getLogger(self.__class__.__name__)

        # Debug hybrid mode
        self.logger.info(f"[INIT] use_hybrid parameter: {use_hybrid}")
        self.logger.info(f"[INIT] HYBRID_AVAILABLE: {HYBRID_AVAILABLE}")
        self.use_hybrid = use_hybrid and HYBRID_AVAILABLE
        self.logger.info(f"[INIT] Final self.use_hybrid: {self.use_hybrid}")

        # Store memory and reasoning for passing to agents
        self.memory_manager = memory_manager
        self.reasoning_tracker = reasoning_tracker
        self.reasoning_session_id = reasoning_session_id

        # Initialize components
        self.verifier = SQLiVerifierAgent()  # Keep old for backward compat
        self.verifier_v2 = SQLiVerifierAgentV2()  # New proper verifier
        self.aggressive_verifier = AggressiveSQLiVerifier()  # FAST SQLMap-style verifier
        self.parameter_discovery = ParameterDiscoveryAgent()
        self.nuclei_scanner = NucleiSQLiScanner()
        self.fingerprinter = DatabaseFingerprinter()
        self.context_analyzer = SQLContextAnalyzer()
        self.sast_analyzer = SQLiSASTAnalyzer()  # SAST analyzer

        # Use aggressive mode by default for speed
        self.use_aggressive = True  # SQLMap-style fast testing

        # Load payload database
        self.payloads_db = self._load_payload_database()

        # Initialize hybrid generator if requested
        self.hybrid_generator = None
        if self.use_hybrid:
            try:
                llm_client = get_llm_client()
                self.hybrid_generator = SQLiHybridGenerator(
                    llm_client=llm_client,
                    memory_manager=memory_manager,
                    reasoning_tracker=reasoning_tracker,
                    reasoning_session_id=reasoning_session_id,
                    sast_profile=None  # Will be set after SAST analysis
                )
                self.logger.info("Hybrid generator with LLM enabled")
                if memory_manager:
                    self.logger.info("   Memory enabled: Learning from past SQLi tests")
                if reasoning_tracker:
                    self.logger.info("   Reasoning transparency enabled")
            except Exception as e:
                self.logger.warning(f"Failed to initialize hybrid generator: {e}")
                import traceback
                self.logger.warning(traceback.format_exc())
                self.use_hybrid = False

        # Session state
        self.injection_points: List[InjectionPoint] = []
        self.successful_payloads: List[Dict] = []
        self.detected_database: DatabaseType = DatabaseType.UNKNOWN
        self.sast_profile: Optional[SASTProfile] = None  # SAST intelligence profile

    def _load_payload_database(self) -> Dict:
        """Load SQL injection payload database"""
        db_path = Path(__file__).parent / 'analysis_framework' / 'payloads_db.json'
        try:
            with open(db_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load payload database: {e}")
            return {'techniques': {}}

    async def run(self) -> SQLiSessionResult:
        """
        Run complete SQL injection testing workflow

        Returns:
            SQLiSessionResult with all findings
        """
        self.logger.info(f"Starting SQL injection testing on {self.target_url}")
        self.logger.info(f"Configuration: {self.config.max_attempts_per_target} max attempts")

        import time
        start_time = time.time()

        # Step 0: Nuclei scan for known SQLi vulnerabilities
        self.logger.info("Step 0: Running Nuclei scan for known SQLi patterns...")
        nuclei_result = await self.nuclei_scanner.scan(self.target_url)

        if nuclei_result['vulnerable']:
            self.logger.info(f"✓ Nuclei detected {len(nuclei_result['findings'])} SQLi vulnerabilities!")
            print(self.nuclei_scanner.get_summary(nuclei_result))

            # If Nuclei found high-confidence vulnerabilities, we might be done
            critical_findings = [f for f in nuclei_result['findings'] if f['severity'] in ['critical', 'high']]
            if critical_findings and not self.config.verbose_logging:
                self.logger.info("High-severity findings detected by Nuclei - marking as vulnerable")
                # Extract parameters from findings
                for finding in critical_findings:
                    # Try to extract parameter from URL
                    url = finding['matched_url']
                    if '?' in url:
                        from urllib.parse import urlparse, parse_qs
                        parsed = urlparse(url)
                        params = parse_qs(parsed.query)
                        for param_name in params.keys():
                            self.injection_points.append(
                                InjectionPoint(
                                    parameter=param_name,
                                    location="query",
                                    original_value=params[param_name][0] if params[param_name] else "",
                                    parameter_type="string",
                                    confidence=95,
                                    notes=f"Found by Nuclei: {finding['template_name']}"
                                )
                            )

                # Create result with Nuclei findings
                return self._create_result(
                    vulnerable=True,
                    total_attempts=len(nuclei_result['findings']),
                    time_elapsed=time.time() - start_time,
                    nuclei_findings=nuclei_result['findings']
                )
        else:
            self.logger.info("Nuclei did not detect SQLi - continuing with manual testing")

        # Step 0.5: SAST Analysis (Intelligence Gathering)
        self.logger.info("Step 0.5: Performing SAST analysis (intelligence gathering)...")
        try:
            self.sast_profile = await self.sast_analyzer.analyze(self.target_url)

            # Use SAST intelligence to prioritize testing
            if self.sast_profile.database_type:
                self.logger.info(f"[SAST] 🎯 Target database: {self.sast_profile.database_type.upper()} "
                               f"(confidence: {self.sast_profile.database_confidence}%)")

            if self.sast_profile.parameter_hints:
                self.logger.info(f"[SAST] 🔍 Found {len(self.sast_profile.parameter_hints)} intelligent parameter hints")

            if self.sast_profile.table_names:
                self.logger.info(f"[SAST] 📊 Discovered tables: {', '.join(list(self.sast_profile.table_names)[:5])}")

            if self.sast_profile.waf_detected:
                self.logger.warning(f"[SAST] ⚠️  WAF detected: {self.sast_profile.waf_detected}")

            # Pass SAST profile to hybrid generator for intelligent payload generation
            if self.use_hybrid and self.hybrid_generator:
                self.hybrid_generator.set_sast_profile(self.sast_profile)
                self.logger.info("[SAST] ✓ Intelligence profile passed to hybrid generator")

        except Exception as e:
            self.logger.warning(f"SAST analysis failed (continuing anyway): {e}")
            self.sast_profile = None

        # Step 1: Discover parameters
        self.logger.info("Step 1: Discovering injectable parameters...")
        self.injection_points = await self.parameter_discovery.discover_parameters(self.target_url)
        self.logger.info(f"Found {len(self.injection_points)} potential injection points")

        if not self.injection_points:
            self.logger.warning("No parameters found to test")
            return self._create_result(vulnerable=False, time_elapsed=time.time() - start_time)

        # Step 1.5: Prioritize parameters using SAST intelligence
        if self.sast_profile and self.sast_profile.parameter_hints:
            self.logger.info("[SAST] Prioritizing parameters based on intelligence...")
            prioritized = []
            normal = []

            for injection_point in self.injection_points:
                param_name = injection_point.parameter

                # Check if SAST found hints for this parameter
                if param_name in self.sast_profile.parameter_hints:
                    hints = self.sast_profile.parameter_hints[param_name]
                    injection_point.confidence = 80  # Higher confidence
                    injection_point.notes = f"SAST hint: {hints.get('table_hint', 'database-related')}"
                    prioritized.append(injection_point)
                    self.logger.info(f"[SAST] 🎯 Priority parameter: {param_name} (has intelligence hints)")
                else:
                    normal.append(injection_point)

            # Test prioritized parameters first
            self.injection_points = prioritized + normal

            if prioritized:
                self.logger.info(f"[SAST] ✓ {len(prioritized)} parameters prioritized, {len(normal)} standard")

        # Step 2: Test each parameter
        vulnerable = False
        total_attempts = 0

        for injection_point in self.injection_points:
            self.logger.info(f"\n{'='*80}")
            self.logger.info(f"Testing parameter: {injection_point.parameter}")
            self.logger.info(f"{'='*80}\n")

            # Test this parameter with proper exploitation testing
            point_result = await self._test_injection_point_proper(injection_point)

            total_attempts += point_result['attempts']

            if point_result['vulnerable']:
                vulnerable = True
                injection_point.confidence = point_result['confidence']
                self.successful_payloads.extend(point_result['successful_payloads'])

                self.logger.info(f"✓ VULNERABLE: {injection_point.parameter}")
                self.logger.info(f"  Type: {point_result['type'].value}")
                self.logger.info(f"  Database: {point_result['database'].value}")
                self.logger.info(f"  Confidence: {point_result['confidence']}%")

                # Update detected database
                if self.detected_database == DatabaseType.UNKNOWN:
                    self.detected_database = point_result['database']

                # Stop after first vulnerability if not in aggressive mode
                if not self.config.verbose_logging:
                    break
            else:
                self.logger.info(f"✗ Not vulnerable: {injection_point.parameter}")

        time_elapsed = time.time() - start_time

        return self._create_result(
            vulnerable=vulnerable,
            total_attempts=total_attempts,
            time_elapsed=time_elapsed
        )


    async def _test_injection_point(
        self,
        injection_point: InjectionPoint
    ) -> Dict:
        """
        Test a single injection point with systematic payload testing

        Returns:
            Dict with test results
        """
        # Use hybrid generator if enabled
        if self.use_hybrid and self.hybrid_generator:
            return await self._test_injection_point_hybrid(injection_point)

        # Default: database-only testing
        attempts = 0
        max_attempts = self.config.max_attempts_per_target
        max_per_technique = self.config.max_payloads_per_technique

        successful_payloads = []
        detected_type = SQLiType.UNKNOWN
        detected_database = DatabaseType.UNKNOWN
        max_confidence = 0

        # Iterate through payload techniques
        for technique_name, technique_data in self.payloads_db['techniques'].items():
            if attempts >= max_attempts:
                break

            self.logger.info(f"Testing technique: {technique_name}")

            payloads = technique_data.get('payloads', [])
            technique_db = technique_data.get('database', 'generic')
            technique_type = technique_data.get('type', 'unknown')

            # Test payloads from this technique
            for payload in payloads[:max_per_technique]:
                if attempts >= max_attempts:
                    break

                attempts += 1
                self.logger.debug(f"Attempt {attempts}/{max_attempts}: {payload[:50]}...")

                # Map technique type to SQLiType
                sqli_type = self._map_technique_type(technique_type)

                # Test payload
                result = await self.verifier.verify(
                    self.target_url,
                    injection_point.parameter,
                    payload,
                    sqli_type,
                    injection_point.location
                )

                # Check if vulnerable
                if result.vulnerable and result.confidence >= self.config.min_confidence_threshold:
                    self.logger.info(f"✓ SUCCESS! Payload worked: {payload[:50]}...")

                    successful_payloads.append({
                        'payload': payload,
                        'type': result.injection_type.value,
                        'confidence': result.confidence,
                        'database': result.database_type.value,
                        'technique': technique_name,
                        'error_messages': result.error_messages
                    })

                    # Update detection info
                    if result.confidence > max_confidence:
                        max_confidence = result.confidence
                        detected_type = result.injection_type
                        detected_database = result.database_type

                    # If high confidence, we can stop
                    if result.confidence >= 95:
                        self.logger.info(f"High confidence detection ({result.confidence}%), stopping tests")
                        break

                # Small delay to avoid rate limiting
                await asyncio.sleep(0.5)

            # If we found a vulnerability, we can stop testing more techniques
            if successful_payloads and not self.config.verbose_logging:
                break

        vulnerable = len(successful_payloads) > 0

        return {
            'vulnerable': vulnerable,
            'type': detected_type,
            'database': detected_database,
            'confidence': max_confidence,
            'attempts': attempts,
            'successful_payloads': successful_payloads
        }

    async def _test_injection_point_hybrid(
        self,
        injection_point: InjectionPoint
    ) -> Dict:
        """
        Test injection point using hybrid generator (database + LLM + mutations)

        Returns:
            Dict with test results
        """
        attempts = 0
        max_attempts = self.config.max_attempts_per_target

        successful_payloads = []
        detected_type = SQLiType.UNKNOWN
        detected_database = DatabaseType.UNKNOWN
        max_confidence = 0

        self.logger.info(f"Using hybrid generator (database + LLM + mutations)")

        while attempts < max_attempts:
            attempts += 1

            # Generate next payload using hybrid strategy
            payload_data = self.hybrid_generator.generate_next_payload(
                attempt_number=attempts,
                max_attempts=max_attempts
            )

            payload = payload_data['payload']
            technique = payload_data['technique']
            phase = payload_data['phase']

            self.logger.info(f"[{phase.upper()}] Attempt {attempts}/{max_attempts}: {technique}")
            self.logger.debug(f"Payload: {payload[:70]}...")

            # Test payload
            result = await self.verifier.verify(
                self.target_url,
                injection_point.parameter,
                payload,
                SQLiType.UNKNOWN,
                injection_point.location
            )

            # Update hybrid generator with result
            error_msg = '\n'.join(result.error_messages) if result.error_messages else ""
            self.hybrid_generator.update_from_response(
                payload=payload,
                vulnerable=result.vulnerable,
                error_message=error_msg,
                confidence=result.confidence
            )

            # Check if vulnerable
            if result.vulnerable and result.confidence >= self.config.min_confidence_threshold:
                self.logger.info(f"✓ SUCCESS! Payload worked: {payload[:50]}...")

                successful_payloads.append({
                    'payload': payload,
                    'type': result.injection_type.value,
                    'confidence': result.confidence,
                    'database': result.database_type.value,
                    'technique': technique,
                    'error_messages': result.error_messages,
                    'phase': phase
                })

                # Update detection info
                if result.confidence > max_confidence:
                    max_confidence = result.confidence
                    detected_type = result.injection_type
                    detected_database = result.database_type

                # If high confidence, we can stop
                if result.confidence >= 95:
                    self.logger.info(f"High confidence detection ({result.confidence}%), stopping tests")
                    break

            # Small delay
            await asyncio.sleep(0.3)

        vulnerable = len(successful_payloads) > 0

        return {
            'vulnerable': vulnerable,
            'type': detected_type,
            'database': detected_database,
            'confidence': max_confidence,
            'attempts': attempts,
            'successful_payloads': successful_payloads
        }

    async def _test_injection_point_proper(
        self,
        injection_point: InjectionPoint
    ) -> Dict:
        """
        ADAPTIVE injection point testing with intelligent technique selection

        Key improvements over static pipeline:
        1. ADAPTIVE: Stops early when 2+ techniques confirmed (no false positives)
        2. SMART ORDERING: Tests fast techniques first (Boolean, UNION, then Time)
        3. EARLY TERMINATION: Stops if responses indicate heavy filtering
        4. HYBRID MODE: Uses LLM to adapt payloads if use_hybrid is enabled

        Returns:
            Dict with test results
        """
        # AGGRESSIVE MODE: Use fast SQLMap-style testing
        if self.use_aggressive:
            self.logger.info(f"[AGGRESSIVE TESTING] Fast SQLMap-style testing on {injection_point.parameter}")
            self.logger.info("   Mode: AGGRESSIVE (Error→UNION→Boolean→Time)")

            try:
                result = await self.aggressive_verifier.verify_aggressive(
                    self.target_url,
                    injection_point.parameter,
                    injection_point.location
                )

                if result['vulnerable']:
                    self.logger.info(f"[✓✓✓] AGGRESSIVE MODE: Found {result['type']} SQLi!")
                    self.logger.info(f"    Confidence: {result['confidence']}%")

                    # Show extracted data if available
                    if result.get('extracted_data'):
                        self.logger.info("[✓✓✓] DATA EXTRACTED:")
                        for key, value in result['extracted_data'].items():
                            self.logger.info(f"    {key}: {str(value)[:100]}")

                    # Transform result to expected format
                    # Map type string to SQLiType enum
                    type_mapping = {
                        'error_based': SQLiType.ERROR_BASED,
                        'union_based': SQLiType.UNION_BASED,
                        'boolean_blind': SQLiType.BOOLEAN_BLIND,
                        'time_blind': SQLiType.TIME_BLIND
                    }
                    detected_type = type_mapping.get(result['type'], SQLiType.UNKNOWN)

                    # Map database string to DatabaseType enum
                    db_mapping = {
                        'mysql': DatabaseType.MYSQL,
                        'postgresql': DatabaseType.POSTGRESQL,
                        'mssql': DatabaseType.MSSQL,
                        'oracle': DatabaseType.ORACLE,
                        'sqlite': DatabaseType.SQLITE
                    }
                    detected_db = db_mapping.get(result.get('database', 'unknown'), DatabaseType.UNKNOWN)

                    # Build successful_payloads list
                    successful_payloads = [{
                        'payload': result.get('payload', ''),
                        'type': result['type'],
                        'confidence': result['confidence'],
                        'database': result.get('database', 'unknown'),
                        'technique': result['type'],
                        'error_messages': [result.get('error_message', '')],
                        'extracted_data': result.get('extracted_data', {})
                    }]

                    return {
                        'vulnerable': True,
                        'type': detected_type,
                        'database': detected_db,
                        'confidence': result['confidence'],
                        'attempts': 1,  # Aggressive mode is very fast
                        'successful_payloads': successful_payloads,
                        'extracted_data': result.get('extracted_data', {})
                    }
                else:
                    self.logger.info("[✗] AGGRESSIVE MODE: Not vulnerable")
                    return {
                        'vulnerable': False,
                        'type': SQLiType.UNKNOWN,
                        'database': DatabaseType.UNKNOWN,
                        'confidence': 0,
                        'attempts': 1,
                        'successful_payloads': []
                    }

            except Exception as e:
                self.logger.error(f"[AGGRESSIVE] Error: {e}")
                self.logger.info("[AGGRESSIVE] Falling back to adaptive mode...")
                # Fall through to adaptive mode

        self.logger.info(f"[ADAPTIVE TESTING] Testing {injection_point.parameter}")
        if self.use_hybrid:
            self.logger.info("   Mode: HYBRID (database + LLM adaptation)")
        else:
            self.logger.info("   Mode: ADAPTIVE (smart technique ordering)")

        successful_payloads = []
        detected_type = SQLiType.UNKNOWN
        detected_database = DatabaseType.UNKNOWN
        max_confidence = 0
        attempts = 0

        # ADAPTIVE TECHNIQUE ORDERING:
        # 1. Boolean (fast, reliable)
        # 2. UNION (fast if successful, provides database info)
        # 3. Time-based (SLOW, only if others fail)
        #
        # STOP early if:
        # - 2 techniques confirmed (prevents false positives)
        # - All responses identical (heavy WAF/filtering detected)

        # Track if we need to continue testing
        continue_testing = True

        # Test 1: Boolean-based blind SQLi (FAST - test first)
        self.logger.info("[1/3] Testing Boolean-based (TRUE vs FALSE logic)...")
        attempts += 1
        boolean_result = await self.verifier_v2.verify_boolean_based(
            self.target_url,
            injection_point.parameter,
            injection_point.location
        )

        if boolean_result.vulnerable and boolean_result.confidence >= self.config.min_confidence_threshold:
            self.logger.info(f"[✓] BOOLEAN-BASED CONFIRMED! (confidence: {boolean_result.confidence}%)")
            successful_payloads.append({
                'payload': boolean_result.payload,
                'type': boolean_result.injection_type.value,
                'confidence': boolean_result.confidence,
                'database': boolean_result.database_type.value,
                'technique': 'boolean_blind',
                'error_messages': boolean_result.error_messages
            })

            if boolean_result.confidence > max_confidence:
                max_confidence = boolean_result.confidence
                detected_type = boolean_result.injection_type
                detected_database = boolean_result.database_type
        else:
            self.logger.info(f"[✗] Boolean-based: Not confirmed")

        # ADAPTIVE DECISION: If 1 technique confirmed, continue to verify with second technique
        # This prevents false positives from boolean-only detection

        # Test 2: UNION-based SQLi (FAST if successful - test before time-based)
        self.logger.info("[2/3] Testing UNION-based (data extraction)...")
        attempts += 1
        union_result = await self.verifier_v2.verify_union_based(
            self.target_url,
            injection_point.parameter,
            injection_point.location
        )

        if union_result.vulnerable and union_result.confidence >= self.config.min_confidence_threshold:
            self.logger.info(f"[✓] UNION-BASED CONFIRMED! (confidence: {union_result.confidence}%)")
            successful_payloads.append({
                'payload': union_result.payload,
                'type': union_result.injection_type.value,
                'confidence': union_result.confidence,
                'database': union_result.database_type.value,
                'technique': 'union_based',
                'error_messages': union_result.error_messages
            })

            if union_result.confidence > max_confidence:
                max_confidence = union_result.confidence
                detected_type = union_result.injection_type
                detected_database = union_result.database_type
        else:
            self.logger.info(f"[✗] UNION-based: Not confirmed")

        # ADAPTIVE EARLY TERMINATION:
        # If we have 2+ techniques confirmed, STOP (high confidence, no false positive)
        if len(successful_payloads) >= 2:
            self.logger.info(f"[ADAPTIVE] ✓ 2+ techniques confirmed - skipping time-based (already high confidence)")
            continue_testing = False

        # Test 3: Time-based blind SQLi (SLOW - only test if needed)
        if continue_testing:
            self.logger.info("[3/3] Testing Time-based (SLEEP duration verification)...")
            self.logger.info("   (This is slow - only testing because <2 techniques confirmed)")
            attempts += 1
            time_result = await self.verifier_v2.verify_time_based(
                self.target_url,
                injection_point.parameter,
                injection_point.location
            )

            if time_result.vulnerable and time_result.confidence >= self.config.min_confidence_threshold:
                self.logger.info(f"[✓] TIME-BASED CONFIRMED! (confidence: {time_result.confidence}%)")
                successful_payloads.append({
                    'payload': time_result.payload,
                    'type': time_result.injection_type.value,
                    'confidence': time_result.confidence,
                    'database': time_result.database_type.value,
                    'technique': 'time_blind',
                    'error_messages': time_result.error_messages
                })

                if time_result.confidence > max_confidence:
                    max_confidence = time_result.confidence
                    detected_type = time_result.injection_type
                    detected_database = time_result.database_type
            else:
                self.logger.info(f"[✗] Time-based: Not confirmed")
        else:
            self.logger.info("[3/3] ⏭️ Skipping Time-based (adaptive early termination)")

        # HYBRID MODE: If use_hybrid enabled and no techniques worked, try LLM-adapted payloads
        if self.use_hybrid and len(successful_payloads) == 0 and self.hybrid_generator:
            self.logger.info("[HYBRID] No standard techniques worked - activating iterative LLM refinement...")

            # Collect failed payloads from standard technique tests
            failed_payloads = []
            if boolean_result and not boolean_result.vulnerable:
                failed_payloads.append({
                    'payload': boolean_result.payload if boolean_result.payload else "boolean test",
                    'technique': 'boolean_blind',
                    'result': 'failed'
                })
            if union_result and not union_result.vulnerable:
                failed_payloads.append({
                    'payload': union_result.payload if union_result.payload else "union test",
                    'technique': 'union_based',
                    'result': 'failed'
                })
            if 'time_result' in locals() and not time_result.vulnerable:
                failed_payloads.append({
                    'payload': time_result.payload if time_result.payload else "time test",
                    'technique': 'time_blind',
                    'result': 'failed'
                })

            # Create test callback for hybrid generator
            async def test_hybrid_payload(payload: str, param: str, location: str):
                """Test a payload and return (vulnerable, response_analysis)"""
                import time as time_module
                from playwright.async_api import async_playwright
                from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

                # Helper to inject payload
                def inject_payload(url: str, parameter: str, payload: str) -> str:
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    params[parameter] = [payload]
                    new_query = urlencode(params, doseq=True)
                    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

                # Test the payload directly
                try:
                    async with async_playwright() as p:
                        browser = await p.chromium.launch(headless=True)
                        context = await browser.new_context()
                        page = await context.new_page()

                        try:
                            # Inject and fetch
                            test_url = inject_payload(self.target_url, param, payload)
                            start_time = time_module.time()
                            await page.goto(test_url, wait_until='networkidle', timeout=15000)
                            response_time = time_module.time() - start_time
                            response_html = await page.content()

                            # Check for SQL errors
                            has_sql_error = any(
                                re.search(pattern, response_html, re.IGNORECASE)
                                for patterns in self.verifier_v2.SQL_ERROR_PATTERNS.values()
                                for pattern in patterns
                            )

                            # Perform deep response analysis using hybrid generator
                            response_analysis = self.hybrid_generator.analyze_response(
                                payload=payload,
                                response_html=response_html,
                                response_time=response_time,
                                error_message="" if not has_sql_error else "SQL error detected"
                            )

                            # Check if vulnerable (basic heuristic)
                            # UNION success if new content appeared
                            # Time-based success if delayed
                            # Boolean success if response differs
                            vulnerable = False

                            if 'UNION' in payload.upper() and 'SELECT' in payload.upper():
                                # Check if new data appeared
                                new_paragraphs = re.findall(r'<p>([^<]+)</p>', response_html)
                                if len(new_paragraphs) > 2:  # More than baseline
                                    vulnerable = True
                            elif 'SLEEP' in payload.upper() or 'pg_sleep' in payload.upper():
                                # Check if delayed
                                if response_time > 3.0:  # Significant delay
                                    vulnerable = True
                            elif not has_sql_error and response_analysis.get('database_fingerprint'):
                                # Database fingerprint detected = potential SQLi
                                vulnerable = True

                            return vulnerable, response_analysis

                        finally:
                            await browser.close()

                except Exception as e:
                    self.logger.debug(f"Error testing payload: {e}")
                    return False, {
                        'summary': f"Test error: {str(e)}",
                        'transformation': None,
                        'blocked_chars': [],
                        'encoding_detected': [],
                        'waf_signature': None,
                        'database_fingerprint': None
                    }

            # Call iterative refinement
            try:
                refinement_result = await self.hybrid_generator.iterative_refinement(
                    target_url=self.target_url,
                    injection_point=injection_point.parameter,
                    parameter_location=injection_point.location,
                    failed_payloads=failed_payloads,
                    test_callback=test_hybrid_payload,
                    max_iterations=5
                )

                if refinement_result:
                    self.logger.info(f"[✓✓✓] HYBRID MODE SUCCESS! LLM found working payload")
                    successful_payloads.append({
                        'payload': refinement_result['payload'],
                        'type': refinement_result.get('technique', 'llm_refined'),
                        'confidence': 90,
                        'database': detected_database.value if detected_database else 'unknown',
                        'technique': 'iterative_llm',
                        'error_messages': [refinement_result.get('reasoning', '')]
                    })

                    # Update state
                    max_confidence = 90
                    detected_type = SQLiType.UNION_BASED  # Assume UNION for LLM success

                    self.logger.info(f"    Payload: {refinement_result['payload'][:80]}...")
                    self.logger.info(f"    Reasoning: {refinement_result.get('reasoning', 'N/A')}")
                else:
                    self.logger.info("[HYBRID] Iterative refinement completed - no success")

            except Exception as e:
                self.logger.error(f"[HYBRID] Error during iterative refinement: {e}")
                import traceback
                self.logger.error(traceback.format_exc())

        # CRITICAL FIX: Require multiple techniques to confirm SQLi (prevent false positives)
        # EXCEPT when a single technique has VERY HIGH confidence (85%+)
        num_techniques = len(successful_payloads)

        # Accept single high-confidence techniques OR multiple techniques
        if num_techniques == 0:
            vulnerable = False
        elif num_techniques == 1 and max_confidence >= 85:
            # Single technique with HIGH confidence (85%+) = Accept
            vulnerable = True
            self.logger.info(f"[✓] SINGLE HIGH-CONFIDENCE TECHNIQUE ACCEPTED")
            self.logger.info(f"    Confidence: {max_confidence}% (≥85% threshold)")
        elif num_techniques >= 2:
            # Multiple techniques = Always accept
            vulnerable = True
        else:
            # Single technique with LOW confidence = Reject
            vulnerable = False

        # Adjust confidence based on number of confirmed techniques
        if num_techniques == 1 and max_confidence < 85:
            # Single technique with LOW confidence = Likely false positive
            adjusted_confidence = min(max_confidence, 40)
            self.logger.warning(f"[!] SINGLE TECHNIQUE WITH LOW CONFIDENCE")
            self.logger.warning(f"    Only {num_techniques} technique confirmed (need ≥2 for high confidence)")
            self.logger.warning(f"    Adjusted confidence: {adjusted_confidence}% (was {max_confidence}%)")
            self.logger.warning(f"    Marking as NOT VULNERABLE (requires multiple technique confirmation)")
        elif num_techniques == 2:
            # Two techniques = MEDIUM-HIGH confidence
            adjusted_confidence = min(max_confidence, 75)
            self.logger.info(f"[✓✓] MULTIPLE TECHNIQUES CONFIRMED!")
            self.logger.info(f"    Found {num_techniques} working exploitation techniques")
            self.logger.info(f"    Confidence: {adjusted_confidence}%")
        else:
            # Three+ techniques = HIGH confidence
            adjusted_confidence = max_confidence
            self.logger.info(f"[✓✓✓] EXPLOITATION CONFIRMED!")
            self.logger.info(f"    Found {num_techniques} working exploitation techniques")
            self.logger.info(f"    Confidence: {adjusted_confidence}%")

        # Override confidence with adjusted value
        max_confidence = adjusted_confidence if not vulnerable else max_confidence

        if not vulnerable and num_techniques > 0:
            self.logger.info(f"[✗] Insufficient confirmation - marked as NOT vulnerable")
            self.logger.info(f"    Reason: Only {num_techniques} technique(s) confirmed, need ≥2")
        elif not vulnerable:
            self.logger.info(f"[✗] No exploitation confirmed - not vulnerable")

        return {
            'vulnerable': vulnerable,
            'type': detected_type,
            'database': detected_database,
            'confidence': max_confidence,
            'attempts': attempts,
            'successful_payloads': successful_payloads
        }

    def _map_technique_type(self, technique_type_str: str) -> SQLiType:
        """Map technique type string to SQLiType enum"""
        mapping = {
            'error_based': SQLiType.ERROR_BASED,
            'union_based': SQLiType.UNION_BASED,
            'time_blind': SQLiType.TIME_BLIND,
            'boolean_blind': SQLiType.BOOLEAN_BLIND,
            'stacked_queries': SQLiType.STACKED_QUERIES,
            'waf_bypass': SQLiType.ERROR_BASED,  # WAF bypass can be any type
        }
        return mapping.get(technique_type_str, SQLiType.UNKNOWN)

    def _create_result(
        self,
        vulnerable: bool,
        total_attempts: int = 0,
        time_elapsed: float = 0.0,
        nuclei_findings: Optional[List] = None
    ) -> SQLiSessionResult:
        """Create final session result"""

        # If Nuclei found vulnerabilities, add them to successful payloads
        if nuclei_findings:
            for finding in nuclei_findings:
                self.successful_payloads.append({
                    'payload': finding.get('template_id', 'nuclei'),
                    'type': 'nuclei_detected',
                    'confidence': 95 if finding['severity'] in ['critical', 'high'] else 80,
                    'database': 'unknown',
                    'technique': finding.get('template_name', 'Nuclei SQLi Template'),
                    'error_messages': [finding.get('description', '')]
                })

        # Determine injection types found
        injection_types = []
        for payload_data in self.successful_payloads:
            inj_type_str = payload_data.get('type')
            try:
                inj_type = SQLiType(inj_type_str)
                if inj_type not in injection_types:
                    injection_types.append(inj_type)
            except:
                pass

        # Collect all error messages
        all_errors = []
        for payload_data in self.successful_payloads:
            all_errors.extend(payload_data.get('error_messages', []))

        notes_parts = []
        if nuclei_findings:
            notes_parts.append(f"Nuclei detected {len(nuclei_findings)} vulnerabilities")
        if self.injection_points:
            notes_parts.append(f"Tested {len(self.injection_points)} parameter(s) with {total_attempts} total attempts")

        result = SQLiSessionResult(
            target_url=self.target_url,
            vulnerable=vulnerable,
            injection_points=self.injection_points,
            successful_payloads=self.successful_payloads,
            database_type=self.detected_database,
            injection_types=injection_types,
            total_attempts=total_attempts,
            successful_attempts=len(self.successful_payloads),
            time_elapsed=time_elapsed,
            error_messages=list(set(all_errors))[:10],  # Unique, limited
            notes='; '.join(notes_parts) if notes_parts else "No testing performed"
        )

        return result


async def test_sqli(
    target_url: str,
    config_preset: str = "default",
    use_hybrid: bool = False,
    memory_manager=None,
    reasoning_tracker=None,
    reasoning_session_id=None
) -> SQLiSessionResult:
    """
    Convenience function to test SQL injection

    Args:
        target_url: Target URL to test
        config_preset: Configuration preset (default, fast, aggressive, conservative)
        use_hybrid: Enable hybrid generator (database + LLM + mutations)
        memory_manager: Memory manager for learning across scans
        reasoning_tracker: Reasoning transparency tracker
        reasoning_session_id: Session ID for reasoning logging

    Returns:
        SQLiSessionResult with findings
    """
    # Select configuration
    config_map = {
        'default': SQLiAnalysisConfig.default(),
        'fast': SQLiAnalysisConfig.fast(),
        'aggressive': SQLiAnalysisConfig.aggressive(),
        'conservative': SQLiAnalysisConfig.conservative()
    }

    config = config_map.get(config_preset, SQLiAnalysisConfig.default())

    # Run orchestrator with hybrid mode if requested
    orchestrator = SQLiOrchestrator(
        target_url=target_url,
        config=config,
        use_hybrid=use_hybrid,
        memory_manager=memory_manager,
        reasoning_tracker=reasoning_tracker,
        reasoning_session_id=reasoning_session_id
    )
    result = await orchestrator.run()

    return result
