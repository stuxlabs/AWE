"""
SAST (Static Application Security Testing) Analyzer for SQLi

Performs static analysis before dynamic testing to:
1. Discover application intelligence (database type, query patterns, API structure)
2. Extract hints from source code, JavaScript, API docs
3. Build a context profile for intelligent DAST testing

This makes testing INTELLIGENT instead of RANDOM.
"""
import logging
import re
import json
from typing import Dict, List, Optional, Set
from pathlib import Path
from urllib.parse import urlparse, urljoin
import asyncio
from playwright.async_api import async_playwright


class SASTProfile:
    """Application intelligence profile built from SAST analysis"""

    def __init__(self):
        self.database_type: Optional[str] = None
        self.database_confidence: int = 0

        # Discovered from API docs, JavaScript, etc.
        self.api_endpoints: List[Dict] = []
        self.parameter_hints: Dict[str, Dict] = {}  # param_name -> {type, description, table_hint, column_hint}

        # Query structure hints
        self.query_patterns: List[str] = []  # Discovered query structures
        self.table_names: Set[str] = set()
        self.column_names: Set[str] = set()

        # Protection hints
        self.waf_detected: Optional[str] = None
        self.input_validation: List[str] = []  # Detected validation patterns
        self.encoding_methods: List[str] = []

        # Source code hints
        self.backend_framework: Optional[str] = None
        self.orm_detected: Optional[str] = None  # SQLAlchemy, Sequelize, etc.

        # Error disclosure
        self.error_disclosure_level: str = "unknown"  # none, partial, full

    def to_dict(self) -> Dict:
        """Convert profile to dict"""
        return {
            'database_type': self.database_type,
            'database_confidence': self.database_confidence,
            'api_endpoints': self.api_endpoints,
            'parameter_hints': self.parameter_hints,
            'query_patterns': self.query_patterns,
            'table_names': list(self.table_names),
            'column_names': list(self.column_names),
            'waf_detected': self.waf_detected,
            'input_validation': self.input_validation,
            'encoding_methods': self.encoding_methods,
            'backend_framework': self.backend_framework,
            'orm_detected': self.orm_detected,
            'error_disclosure_level': self.error_disclosure_level
        }

    def get_summary(self) -> str:
        """Get human-readable summary"""
        lines = ["=== SAST Intelligence Profile ==="]

        if self.database_type:
            lines.append(f"Database: {self.database_type.upper()} (confidence: {self.database_confidence}%)")

        if self.backend_framework:
            lines.append(f"Backend: {self.backend_framework}")

        if self.orm_detected:
            lines.append(f"ORM: {self.orm_detected}")

        if self.api_endpoints:
            lines.append(f"API Endpoints: {len(self.api_endpoints)} discovered")

        if self.parameter_hints:
            lines.append(f"Parameter Intel: {len(self.parameter_hints)} parameters")
            for param, hints in list(self.parameter_hints.items())[:3]:
                table = hints.get('table_hint', '?')
                col = hints.get('column_hint', '?')
                lines.append(f"  • {param}: {table}.{col}")

        if self.table_names:
            lines.append(f"Tables: {', '.join(list(self.table_names)[:5])}")

        if self.waf_detected:
            lines.append(f"⚠️  WAF: {self.waf_detected}")

        if self.input_validation:
            lines.append(f"Validation: {', '.join(self.input_validation[:3])}")

        return "\n".join(lines)


class SQLiSASTAnalyzer:
    """
    SAST analyzer for SQL injection testing

    Performs reconnaissance and static analysis before dynamic testing:
    1. Crawl application for intelligence
    2. Analyze JavaScript code for backend hints
    3. Check for API documentation (OpenAPI, Swagger)
    4. Extract database hints from errors, responses, headers
    5. Build context profile for intelligent DAST
    """

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.profile = SASTProfile()

    async def analyze(self, target_url: str) -> SASTProfile:
        """
        Perform comprehensive SAST analysis on target

        Args:
            target_url: Target URL to analyze

        Returns:
            SASTProfile with discovered intelligence
        """
        self.logger.info(f"[SAST] Starting static analysis on {target_url}")

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()

            try:
                # Step 1: Crawl main page
                # Use 'load' instead of 'networkidle' - more reliable for sites with continuous network activity
                try:
                    await page.goto(target_url, wait_until='load', timeout=20000)
                except Exception as e:
                    # Fallback: try with domcontentloaded
                    self.logger.warning(f"[SAST] Load timeout, trying domcontentloaded: {str(e)[:100]}")
                    await page.goto(target_url, wait_until='domcontentloaded', timeout=15000)

                html = await page.content()

                # Step 2: Extract intelligence
                await self._analyze_html(html, target_url)
                await self._analyze_javascript(page, target_url)
                await self._check_api_docs(page, target_url)
                await self._check_common_files(page, target_url)
                await self._fingerprint_database(page, target_url)
                await self._detect_framework(html, page)

                self.logger.info("[SAST] Analysis complete")
                self.logger.info(f"\n{self.profile.get_summary()}")

            finally:
                await browser.close()

        return self.profile

    async def _analyze_html(self, html: str, base_url: str):
        """Extract hints from HTML"""
        self.logger.info("[SAST] Analyzing HTML...")

        # Look for table/column hints in HTML comments
        comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
        for comment in comments:
            # Look for SQL-related comments
            if any(keyword in comment.lower() for keyword in ['table', 'column', 'database', 'query']):
                self.logger.info(f"[SAST] Found SQL hint in comment: {comment[:100]}")
                self._extract_table_column_hints(comment)

        # Look for data-* attributes that might reveal backend structure
        data_attrs = re.findall(r'data-([a-z-]+)=["\']([^"\']+)["\']', html, re.IGNORECASE)
        for attr_name, attr_value in data_attrs:
            if 'table' in attr_name or 'column' in attr_name or 'field' in attr_name:
                self.logger.info(f"[SAST] Found data attribute: data-{attr_name}={attr_value}")
                if 'table' in attr_name:
                    self.profile.table_names.add(attr_value)
                elif 'column' in attr_name or 'field' in attr_name:
                    self.profile.column_names.add(attr_value)

        # Check for error disclosure
        error_keywords = ['error', 'exception', 'stack trace', 'traceback']
        if any(keyword in html.lower() for keyword in error_keywords):
            self.profile.error_disclosure_level = "partial"
            self.logger.warning("[SAST] Error disclosure detected")

    async def _analyze_javascript(self, page, base_url: str):
        """Analyze JavaScript for backend API hints"""
        self.logger.info("[SAST] Analyzing JavaScript...")

        try:
            # Get all script tags
            scripts = await page.evaluate('''() => {
                return Array.from(document.querySelectorAll('script'))
                    .map(s => s.textContent)
                    .filter(t => t && t.length > 0);
            }''')

            for script in scripts:
                # Look for API endpoints
                api_patterns = [
                    r'/api/[a-zA-Z0-9_/-]+',
                    r'fetch\(["\']([^"\']+)["\']',
                    r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']',
                    r'\.ajax\({[^}]*url:\s*["\']([^"\']+)["\']',
                ]

                for pattern in api_patterns:
                    matches = re.findall(pattern, script)
                    for match in matches:
                        endpoint = match if isinstance(match, str) else match[-1]
                        if endpoint and not endpoint.startswith('http'):
                            full_url = urljoin(base_url, endpoint)
                            self.profile.api_endpoints.append({
                                'url': full_url,
                                'path': endpoint
                            })
                            self.logger.info(f"[SAST] Found API endpoint: {endpoint}")

                # Look for parameter hints in JavaScript
                param_patterns = [
                    r'params\s*:\s*{\s*([a-zA-Z_]+)\s*:',
                    r'data\s*:\s*{\s*([a-zA-Z_]+)\s*:',
                    r'["\']([a-zA-Z_]+)["\']\s*:\s*["\']?\w+["\']?',
                ]

                for pattern in param_patterns:
                    params = re.findall(pattern, script)
                    for param in params:
                        if param not in ['name', 'value', 'type', 'id']:  # Skip common generic names
                            if param not in self.profile.parameter_hints:
                                self.profile.parameter_hints[param] = {'source': 'javascript'}
                                self.logger.info(f"[SAST] Found parameter: {param}")

        except Exception as e:
            self.logger.debug(f"[SAST] JavaScript analysis error: {e}")

    async def _check_api_docs(self, page, base_url: str):
        """Check for API documentation (OpenAPI, Swagger, etc.)"""
        self.logger.info("[SAST] Checking for API documentation...")

        common_doc_paths = [
            '/api/docs',
            '/api-docs',
            '/swagger',
            '/swagger.json',
            '/swagger-ui',
            '/openapi.json',
            '/api/swagger.json',
            '/api/openapi.json',
            '/v1/api-docs',
            '/docs',
        ]

        for doc_path in common_doc_paths:
            try:
                doc_url = urljoin(base_url, doc_path)
                response = await page.goto(doc_url, wait_until='domcontentloaded', timeout=5000)

                if response and response.ok:
                    content = await page.content()

                    # Check if it's OpenAPI/Swagger
                    if 'swagger' in content.lower() or 'openapi' in content.lower():
                        self.logger.info(f"[SAST] ✓ Found API docs at: {doc_path}")

                        # Try to parse as JSON
                        try:
                            if doc_path.endswith('.json'):
                                json_content = await page.evaluate('() => document.body.textContent')
                                api_spec = json.loads(json_content)
                                self._parse_openapi_spec(api_spec)
                        except:
                            pass

                        break
            except:
                continue

    def _parse_openapi_spec(self, spec: Dict):
        """Parse OpenAPI/Swagger specification"""
        self.logger.info("[SAST] Parsing OpenAPI specification...")

        # Extract paths and parameters
        paths = spec.get('paths', {})
        for path, methods in paths.items():
            for method, details in methods.items():
                if isinstance(details, dict):
                    # Extract parameters
                    parameters = details.get('parameters', [])
                    for param in parameters:
                        param_name = param.get('name')
                        param_in = param.get('in')  # query, path, header, body
                        param_schema = param.get('schema', {})
                        param_type = param_schema.get('type')

                        if param_name and param_in == 'query':
                            self.profile.parameter_hints[param_name] = {
                                'type': param_type,
                                'location': param_in,
                                'source': 'openapi',
                                'endpoint': path
                            }
                            self.logger.info(f"[SAST] API parameter: {param_name} ({param_type})")

    async def _check_common_files(self, page, base_url: str):
        """Check for common files that might reveal information"""
        self.logger.info("[SAST] Checking common files...")

        common_files = [
            '/robots.txt',
            '/.env',
            '/package.json',
            '/composer.json',
            '/requirements.txt',
            '/.git/config',
            '/config.json',
        ]

        for file_path in common_files:
            try:
                file_url = urljoin(base_url, file_path)
                response = await page.goto(file_url, wait_until='domcontentloaded', timeout=3000)

                if response and response.ok:
                    content = await page.content()
                    self.logger.info(f"[SAST] ✓ Found: {file_path}")

                    # Extract hints from content
                    if 'postgres' in content.lower() or 'pg' in content.lower():
                        self._update_database_hint('postgresql', 60)
                    elif 'mysql' in content.lower():
                        self._update_database_hint('mysql', 60)
                    elif 'mongodb' in content.lower():
                        self._update_database_hint('mongodb', 60)
                    elif 'sqlite' in content.lower():
                        self._update_database_hint('sqlite', 60)
            except:
                continue

    async def _fingerprint_database(self, page, base_url: str):
        """Try to fingerprint database type"""
        self.logger.info("[SAST] Fingerprinting database...")

        # Try error-based fingerprinting
        test_params = [
            ("search", "'"),
            ("id", "1'"),
            ("q", "test'"),
        ]

        for param, value in test_params:
            try:
                test_url = f"{base_url}?{param}={value}"
                await page.goto(test_url, wait_until='domcontentloaded', timeout=5000)
                content = await page.content()

                # Check for database-specific errors
                if 'postgresql' in content.lower() or 'psql' in content.lower():
                    self._update_database_hint('postgresql', 90)
                    self.profile.error_disclosure_level = "full"
                    break
                elif 'mysql' in content.lower() or 'mariadb' in content.lower():
                    self._update_database_hint('mysql', 90)
                    self.profile.error_disclosure_level = "full"
                    break
                elif 'microsoft sql' in content.lower() or 'mssql' in content.lower():
                    self._update_database_hint('mssql', 90)
                    self.profile.error_disclosure_level = "full"
                    break
                elif 'sqlite' in content.lower():
                    self._update_database_hint('sqlite', 90)
                    self.profile.error_disclosure_level = "full"
                    break
                elif 'oracle' in content.lower() or 'ora-' in content.lower():
                    self._update_database_hint('oracle', 90)
                    self.profile.error_disclosure_level = "full"
                    break
            except:
                continue

    async def _detect_framework(self, html: str, page):
        """Detect backend framework"""
        self.logger.info("[SAST] Detecting framework...")

        # Check response headers
        try:
            response = await page.evaluate('() => document.location.href')
            # Headers are harder to get in Playwright, but we can check HTML
        except:
            pass

        # Check HTML for framework hints
        framework_hints = {
            'django': ['csrfmiddlewaretoken', 'django', '__admin'],
            'flask': ['werkzeug', 'flask'],
            'express': ['x-powered-by: express'],
            'rails': ['csrf-param', 'rails', 'action_dispatch'],
            'laravel': ['laravel', 'csrf-token'],
            'spring': ['spring', 'jsessionid'],
        }

        html_lower = html.lower()
        for framework, hints in framework_hints.items():
            if any(hint in html_lower for hint in hints):
                self.profile.backend_framework = framework
                self.logger.info(f"[SAST] Detected framework: {framework}")
                break

    def _update_database_hint(self, db_type: str, confidence: int):
        """Update database type hint with confidence"""
        if self.profile.database_confidence < confidence:
            self.profile.database_type = db_type
            self.profile.database_confidence = confidence
            self.logger.info(f"[SAST] Database fingerprint: {db_type.upper()} (confidence: {confidence}%)")

    def _extract_table_column_hints(self, text: str):
        """Extract table and column names from text"""
        # Look for patterns like "users table", "email column", etc.
        table_patterns = [
            r'(\w+)\s+table',
            r'table\s+(\w+)',
            r'from\s+(\w+)',
            r'insert\s+into\s+(\w+)',
        ]

        column_patterns = [
            r'(\w+)\s+column',
            r'column\s+(\w+)',
            r'field\s+(\w+)',
        ]

        for pattern in table_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if len(match) > 2 and match not in ['the', 'a', 'an']:
                    self.profile.table_names.add(match.lower())

        for pattern in column_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if len(match) > 2 and match not in ['the', 'a', 'an']:
                    self.profile.column_names.add(match.lower())
