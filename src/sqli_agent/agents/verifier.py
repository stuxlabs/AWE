"""
SQL Injection Verification Agent

Multi-strategy SQL injection detection using Playwright.
Implements error-based, time-based, boolean-based, and UNION-based detection.
"""
import asyncio
import logging
import os
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


class SQLiVerifierAgent:
    """Agent responsible for testing SQL injection payloads with multiple detection strategies"""

    # SQL error patterns for different databases
    SQL_ERROR_PATTERNS = {
        DatabaseType.MYSQL: [
            r"You have an error in your SQL syntax",
            r"Warning: mysql_",
            r"MySQLSyntaxErrorException",
            r"com\.mysql\.jdbc",
            r"MySQL server version",
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"check the manual that corresponds to your (MySQL|MariaDB) server version",
            r"MySqlClient\.",
            r"com\.mysql\.jdbc\.exceptions"
        ],
        DatabaseType.POSTGRESQL: [
            r"PostgreSQL.*ERROR",
            r"pg_query\(\).*error",
            r"PSQLException",
            r"org\.postgresql",
            r"ERROR.*syntax error",
            r"unterminated quoted string",
            r"pg_.*\(\).*failed"
        ],
        DatabaseType.MSSQL: [
            r"Microsoft SQL Server.*error",
            r"ODBC SQL Server Driver",
            r"SQLServer JDBC Driver",
            r"com\.microsoft\.sqlserver",
            r"\[SQL Server\]",
            r"Unclosed quotation mark",
            r"Incorrect syntax near",
            r"SqlException",
            r"System\.Data\.SqlClient"
        ],
        DatabaseType.ORACLE: [
            r"ORA-\d{5}",
            r"Oracle.*error",
            r"Oracle.*Driver",
            r"java\.sql\.SQLException: ORA-",
            r"oracle\.jdbc",
            r"OracleException",
            r"quoted string not properly terminated"
        ],
        DatabaseType.SQLITE: [
            r"SQLite.*error",
            r"sqlite3\.OperationalError",
            r"SQLITE_ERROR",
            r"SQL logic error"
        ]
    }

    # Generic SQL error patterns
    GENERIC_SQL_ERRORS = [
        r"SQL syntax",
        r"syntax error",
        r"database error",
        r"SQL error",
        r"mysql_fetch",
        r"num_rows",
        r"pg_exec",
        r"supplied argument is not a valid",
        r"unterminated string",
        r"unexpected end of SQL command",
        r"invalid query",
        r"SQL command not properly ended"
    ]

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.screenshot_dir = Path("screenshots")
        self.screenshot_dir.mkdir(exist_ok=True)
        self.html_captures_dir = Path("html_captures")
        self.html_captures_dir.mkdir(exist_ok=True)

    async def verify(
        self,
        target_url: str,
        parameter: str,
        payload: str,
        injection_type: SQLiType = SQLiType.UNKNOWN,
        parameter_location: str = "query"
    ) -> SQLiVerificationResult:
        """
        Verify SQL injection with multi-strategy detection

        Args:
            target_url: Target URL
            parameter: Parameter to inject into
            payload: SQL injection payload
            injection_type: Expected injection type (for optimization)

        Returns:
            SQLiVerificationResult with detection results
        """
        self.logger.info(f"\n{'='*80}")
        self.logger.info(f"Testing SQLi on {target_url}")
        self.logger.info(f"Parameter: {parameter} (location: {parameter_location})")
        self.logger.info(f"Payload: {payload}")
        self.logger.info(f"{'='*80}")

        # Store parameter location for later use
        self.parameter_location = parameter_location

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()

            try:
                # Get baseline response first (for comparison)
                self.logger.info("[*] Fetching baseline response...")
                baseline_html, baseline_time, baseline_status = await self._fetch_baseline(
                    page, target_url, parameter, parameter_location
                )
                self.logger.info(f"[*] Baseline: status={baseline_status}, time={baseline_time:.2f}s, length={len(baseline_html)}")

                # Test payload based on parameter location
                start_time = time.time()

                if parameter_location == "query":
                    # URL query parameter
                    test_url = self._inject_payload(target_url, parameter, payload)
                    self.logger.info(f"[*] Test URL: {test_url}")
                    response = await page.goto(test_url, wait_until='networkidle', timeout=15000)
                else:
                    # POST parameter - navigate first, then submit form
                    await page.goto(target_url, wait_until='networkidle', timeout=15000)
                    await page.wait_for_timeout(1000)

                    # Fill form field with payload
                    try:
                        input_selector = f'input[name="{parameter}"], textarea[name="{parameter}"]'
                        self.logger.info(f"[*] Filling form field '{parameter}' with payload: {payload}")
                        await page.fill(input_selector, payload)

                        # Submit form
                        submit_btn = await page.query_selector('button[type="submit"], input[type="submit"]')
                        if submit_btn:
                            self.logger.info(f"[*] Submitting form via button...")
                            await submit_btn.click()
                            await page.wait_for_load_state('networkidle', timeout=15000)
                        else:
                            # Try form submit
                            form = await page.query_selector(f'form:has({input_selector})')
                            if form:
                                self.logger.info(f"[*] Submitting form via JavaScript...")
                                await form.evaluate('(form) => form.submit()')
                                await page.wait_for_load_state('networkidle', timeout=15000)

                        response = page.response
                    except Exception as form_error:
                        self.logger.error(f"Form submission error: {form_error}")
                        response = None

                response_time = time.time() - start_time

                await page.wait_for_timeout(1000)

                test_url = page.url  # Get actual URL after potential redirects
                self.logger.info(f"[*] Final URL: {test_url}")

                # Get response data
                page_content = await page.content()
                response_status = response.status if response else 0
                response_headers = response.headers if response else {}

                self.logger.info(f"[*] Response: status={response_status}, time={response_time:.2f}s, length={len(page_content)}")

                # Save HTML content
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                html_file_path = self.html_captures_dir / f"sqli_{timestamp}.html"
                self._save_html_content(
                    html_file_path, test_url, payload, page_content,
                    response_status, response_headers
                )

                # Run detection strategies with baseline comparison
                self.logger.info("[*] Running detection strategies...")
                error_result = self._detect_error_based(
                    page_content, baseline_html, payload
                )
                time_result = self._detect_time_based(response_time, baseline_time)
                boolean_result = self._detect_boolean_based(
                    page_content, baseline_html, payload
                )

                # Determine if vulnerable
                vulnerable = (
                    error_result['vulnerable'] or
                    time_result['vulnerable'] or
                    boolean_result['vulnerable']
                )

                # Determine injection type and database type
                detected_type = error_result.get('type', time_result.get('type', SQLiType.UNKNOWN))
                database_type = error_result.get('database', DatabaseType.UNKNOWN)

                # Calculate confidence
                confidence = self._calculate_confidence(
                    error_result, time_result, boolean_result
                )

                # Take screenshot
                screenshot_path = self.screenshot_dir / f"sqli_{timestamp}_{detected_type.value}.png"
                await page.screenshot(path=str(screenshot_path), full_page=True)

                # Compile error messages
                all_errors = (
                    error_result.get('errors', []) +
                    time_result.get('errors', []) +
                    boolean_result.get('errors', [])
                )

                result = SQLiVerificationResult(
                    url=test_url,
                    parameter=parameter,
                    payload=payload,
                    vulnerable=vulnerable,
                    injection_type=detected_type,
                    confidence=confidence,
                    database_type=database_type,
                    error_messages=all_errors,
                    response_time=response_time,
                    baseline_time=baseline_time,
                    response_diff=boolean_result.get('diff'),
                    timestamp=timestamp,
                    screenshot_path=str(screenshot_path),
                    page_content=page_content[:1000] if len(page_content) > 1000 else page_content,
                    page_content_file=str(html_file_path),
                    response_status=response_status,
                    response_headers=dict(response_headers)
                )

                if vulnerable:
                    self.logger.info(f"[✓] VULNERABLE: {detected_type.value} (confidence: {confidence}%)")
                    self.logger.info(f"[✓] Database: {database_type.value}")
                    self.logger.info(f"[✓] Evidence: {', '.join(all_errors[:3])}")
                else:
                    self.logger.info(f"[✗] NOT VULNERABLE (confidence: {confidence}%)")

                return result

            except Exception as e:
                self.logger.error(f"Verification error: {e}")
                return self._create_error_result(target_url, parameter, payload, str(e))

            finally:
                await browser.close()

    def _inject_payload(self, url: str, parameter: str, payload: str) -> str:
        """Inject payload into URL parameter"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # Inject into specified parameter
        params[parameter] = [payload]

        # Rebuild URL
        new_query = urlencode(params, doseq=True)
        new_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))

        return new_url

    async def _fetch_baseline(
        self,
        page,
        url: str,
        parameter: str,
        parameter_location: str = "query"
    ) -> Tuple[str, float, int]:
        """Fetch baseline response for comparison"""
        try:
            start_time = time.time()

            if parameter_location == "query":
                # Use a benign value
                baseline_url = self._inject_payload(url, parameter, "1")
                response = await page.goto(baseline_url, wait_until='networkidle', timeout=10000)
            else:
                # POST - navigate and submit with benign value
                await page.goto(url, wait_until='networkidle', timeout=10000)
                await page.wait_for_timeout(500)

                try:
                    input_selector = f'input[name="{parameter}"], textarea[name="{parameter}"]'
                    await page.fill(input_selector, "1")

                    submit_btn = await page.query_selector('button[type="submit"], input[type="submit"]')
                    if submit_btn:
                        await submit_btn.click()
                        await page.wait_for_load_state('networkidle', timeout=10000)

                    response = page.response
                except:
                    response = None

            baseline_time = time.time() - start_time

            await page.wait_for_timeout(500)

            baseline_html = await page.content()
            baseline_status = response.status if response else 200

            return baseline_html, baseline_time, baseline_status

        except Exception as e:
            self.logger.warning(f"Failed to fetch baseline: {e}")
            return "", 1.0, 200

    def _detect_error_based(
        self,
        html_content: str,
        baseline_html: str,
        payload: str
    ) -> Dict:
        """
        Detect error-based SQL injection with baseline comparison and payload reflection

        Args:
            html_content: Response HTML with payload
            baseline_html: Baseline response HTML
            payload: The SQL injection payload

        Returns:
            Dict with detection results
        """
        errors_found = []
        detected_database = DatabaseType.UNKNOWN
        baseline_errors = []

        # Check database-specific patterns in response
        for db_type, patterns in self.SQL_ERROR_PATTERNS.items():
            for pattern in patterns:
                matches = re.findall(pattern, html_content, re.IGNORECASE)
                if matches:
                    errors_found.extend(matches)
                    detected_database = db_type
                    self.logger.info(f"[+] Detected {db_type.value} error: {matches[0][:100]}")

                # Check if same error exists in baseline (false positive indicator)
                if baseline_html:
                    baseline_matches = re.findall(pattern, baseline_html, re.IGNORECASE)
                    if baseline_matches:
                        baseline_errors.extend(baseline_matches)

        # Check generic patterns if no specific DB detected
        if not errors_found:
            for pattern in self.GENERIC_SQL_ERRORS:
                matches = re.findall(pattern, html_content, re.IGNORECASE)
                if matches:
                    errors_found.extend(matches)
                    self.logger.info(f"[+] Detected generic SQL error: {matches[0][:100]}")

                # Check baseline
                if baseline_html:
                    baseline_matches = re.findall(pattern, baseline_html, re.IGNORECASE)
                    if baseline_matches:
                        baseline_errors.extend(baseline_matches)

        # FALSE POSITIVE CHECK 1: Errors also in baseline (generic error page)
        if baseline_errors:
            self.logger.warning(f"[!] SQL errors also found in baseline response - likely a generic error page")
            self.logger.warning(f"[!] Baseline errors: {baseline_errors[:2]}")
            return {
                'vulnerable': False,
                'type': SQLiType.UNKNOWN,
                'database': DatabaseType.UNKNOWN,
                'errors': [],
                'confidence': 0,
                'reason': 'Errors also present in baseline (generic error page)'
            }

        # FALSE POSITIVE CHECK 2: Payload reflection (strong evidence)
        payload_reflected = self._check_payload_reflection(html_content, payload)

        if not errors_found:
            return {
                'vulnerable': False,
                'type': SQLiType.UNKNOWN,
                'database': DatabaseType.UNKNOWN,
                'errors': [],
                'confidence': 0
            }

        # Calculate confidence based on evidence strength
        base_confidence = 95 if detected_database != DatabaseType.UNKNOWN else 70

        # Boost confidence if payload is reflected in error message
        if payload_reflected:
            self.logger.info(f"[✓] Payload reflection detected - strong evidence of SQLi")
            confidence = min(100, base_confidence + 5)
        else:
            self.logger.warning(f"[!] Payload NOT reflected in error - lower confidence")
            confidence = base_confidence - 20  # Reduce confidence if no reflection

        vulnerable = len(errors_found) > 0 and confidence >= 50

        return {
            'vulnerable': vulnerable,
            'type': SQLiType.ERROR_BASED if vulnerable else SQLiType.UNKNOWN,
            'database': detected_database,
            'errors': errors_found[:5],  # Limit to first 5
            'confidence': confidence,
            'payload_reflected': payload_reflected
        }

    def _check_payload_reflection(self, html_content: str, payload: str) -> bool:
        """
        Check if the payload is reflected/visible in the response

        This is strong evidence that the payload was actually processed.
        """
        if not payload or len(payload) < 2:
            return False

        # Check for exact payload match
        if payload in html_content:
            return True

        # Check for escaped/encoded versions
        import html as html_lib
        escaped_payload = html_lib.escape(payload)
        if escaped_payload in html_content and escaped_payload != payload:
            return True

        # Check for URL-encoded version
        from urllib.parse import quote
        url_encoded = quote(payload)
        if url_encoded in html_content and url_encoded != payload:
            return True

        # For single quotes, check common escape patterns
        if payload == "'" or payload == '"':
            # Single char payloads are too generic to reliably detect
            return False

        # Check if significant portion of payload appears (for longer payloads)
        if len(payload) > 10:
            # Check if 70% of the payload appears
            chunk_size = int(len(payload) * 0.7)
            if payload[:chunk_size] in html_content:
                return True

        return False

    def _detect_time_based(self, response_time: float, baseline_time: float) -> Dict:
        """Detect time-based blind SQL injection"""
        time_diff = response_time - baseline_time

        # Check for significant delay (>4 seconds suggests SLEEP or WAITFOR)
        vulnerable = time_diff >= 4.0

        if vulnerable:
            self.logger.info(f"Time-based SQLi detected: delay of {time_diff:.2f}s")

        return {
            'vulnerable': vulnerable,
            'type': SQLiType.TIME_BLIND if vulnerable else SQLiType.UNKNOWN,
            'time_diff': time_diff,
            'errors': [f"Response delayed by {time_diff:.2f} seconds"],
            'confidence': 90 if vulnerable else 0
        }

    def _detect_boolean_based(
        self,
        html_content: str,
        baseline_html: str,
        payload: str
    ) -> Dict:
        """Detect boolean-based blind SQL injection"""
        if not baseline_html:
            return {'vulnerable': False, 'confidence': 0}

        # Calculate content difference
        baseline_len = len(baseline_html)
        response_len = len(html_content)
        len_diff = abs(response_len - baseline_len)

        # Check for significant difference
        # If payload contains "1=1" vs "1=2", responses should differ
        has_true_condition = any(x in payload.lower() for x in ["1=1", "'='", "or 1", "or true"])
        has_false_condition = any(x in payload.lower() for x in ["1=2", "'!='", "and 0", "and false"])

        # Significant difference suggests boolean-based
        significant_diff = len_diff > (baseline_len * 0.1)  # 10% difference

        vulnerable = significant_diff and (has_true_condition or has_false_condition)

        if vulnerable:
            self.logger.info(f"Boolean-based SQLi suspected: {len_diff} byte difference")

        return {
            'vulnerable': vulnerable,
            'type': SQLiType.BOOLEAN_BLIND if vulnerable else SQLiType.UNKNOWN,
            'diff': {'baseline_len': baseline_len, 'response_len': response_len, 'diff': len_diff},
            'errors': [f"Content length differs by {len_diff} bytes"],
            'confidence': 70 if vulnerable else 0
        }

    def _calculate_confidence(
        self,
        error_result: Dict,
        time_result: Dict,
        boolean_result: Dict
    ) -> int:
        """Calculate overall confidence score"""
        max_confidence = max(
            error_result.get('confidence', 0),
            time_result.get('confidence', 0),
            boolean_result.get('confidence', 0)
        )

        # Boost confidence if multiple methods agree
        detection_count = sum([
            error_result.get('vulnerable', False),
            time_result.get('vulnerable', False),
            boolean_result.get('vulnerable', False)
        ])

        if detection_count > 1:
            max_confidence = min(100, max_confidence + 10 * (detection_count - 1))

        return max_confidence

    def _save_html_content(
        self,
        file_path: Path,
        url: str,
        payload: str,
        content: str,
        status: int,
        headers: Dict
    ):
        """Save HTML content to file"""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(f"<!-- URL: {url} -->\n")
                f.write(f"<!-- Payload: {payload} -->\n")
                f.write(f"<!-- Response Status: {status} -->\n")
                f.write("<!-- Response Headers:\n")
                for key, value in headers.items():
                    f.write(f"{key}: {value}\n")
                f.write("-->\n\n")
                f.write(content)

            self.logger.debug(f"Saved HTML content to {file_path}")

        except Exception as e:
            self.logger.error(f"Failed to save HTML: {e}")

    def _create_error_result(
        self,
        url: str,
        parameter: str,
        payload: str,
        error: str
    ) -> SQLiVerificationResult:
        """Create error result when verification fails"""
        return SQLiVerificationResult(
            url=url,
            parameter=parameter,
            payload=payload,
            vulnerable=False,
            injection_type=SQLiType.UNKNOWN,
            confidence=0,
            error=error,
            timestamp=datetime.now().isoformat()
        )
