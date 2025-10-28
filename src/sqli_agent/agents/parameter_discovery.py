"""
Parameter Discovery Agent

Discovers injectable parameters from forms, POST data, cookies, and URL.
"""
import logging
from typing import List, Dict, Optional
from playwright.async_api import async_playwright, Page
from urllib.parse import urlparse, parse_qs
from ..models import InjectionPoint


class ParameterDiscoveryAgent:
    """Discovers parameters that can be tested for SQL injection"""

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)

    async def discover_parameters(self, target_url: str) -> List[InjectionPoint]:
        """
        Discover all testable parameters from target URL

        Returns:
            List of InjectionPoint objects
        """
        self.logger.info(f"Discovering parameters from {target_url}")

        injection_points = []

        # 1. Discover from URL query string
        url_params = self._discover_from_url(target_url)
        injection_points.extend(url_params)

        # 2. Discover from page forms using Playwright
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()

            try:
                # Use 'load' instead of 'networkidle' for better reliability
                try:
                    await page.goto(target_url, wait_until='load', timeout=15000)
                except Exception as e:
                    self.logger.warning(f"Load timeout, trying domcontentloaded: {str(e)[:80]}")
                    await page.goto(target_url, wait_until='domcontentloaded', timeout=10000)

                await page.wait_for_timeout(2000)

                # Discover form fields
                form_params = await self._discover_from_forms(page, target_url)
                injection_points.extend(form_params)

                # Discover input fields (not in forms)
                input_params = await self._discover_from_inputs(page, target_url)
                injection_points.extend(input_params)

            except Exception as e:
                self.logger.error(f"Error during page analysis: {e}")
                self.logger.info("Falling back to URL-based parameter discovery...")

                # Fallback: Try to discover from URL parameters without loading the page
                try:
                    from urllib.parse import urlparse, parse_qs
                    parsed = urlparse(target_url)
                    url_params = parse_qs(parsed.query)

                    for param_name in url_params.keys():
                        value = url_params[param_name][0] if url_params[param_name] else ""
                        injection_points.append(InjectionPoint(
                            parameter=param_name,
                            location="query",
                            original_value=value,
                            parameter_type="string",
                            confidence=70,  # Lower confidence for URL-based discovery
                            notes="Discovered from URL (page load failed)"
                        ))
                        self.logger.info(f"  Found URL parameter: {param_name}")

                    # If still no parameters, add common test parameters
                    if not injection_points:
                        self.logger.info("No parameters found in URL, adding common test parameters...")
                        # Prioritize 'search' and 'q' as they're most likely to be vulnerable
                        common_params = ['search', 'q', 'query', 'id', 'user', 'name', 'page']

                        for param in common_params:
                            injection_points.append(InjectionPoint(
                                parameter=param,
                                location="query",
                                original_value="test",
                                parameter_type="string",
                                confidence=30,  # Very low confidence
                                notes="Common parameter (guessed)"
                            ))

                except Exception as fallback_e:
                    self.logger.error(f"Fallback discovery also failed: {fallback_e}")

            finally:
                await browser.close()

        # CRITICAL: If no parameters found at all, analyze URL and add intelligent guesses
        if len(injection_points) == 0:
            self.logger.warning("No parameters discovered via any method")
            self.logger.info("Falling back to URL pattern analysis...")

            from urllib.parse import urlparse
            parsed = urlparse(target_url)
            path = parsed.path.lower()

            # Detect common URL patterns and suggest appropriate parameters
            if 'sqli' in path or 'sql' in path:
                # SQL injection testing page - likely has 'id' parameter
                suggested = [('id', 90, 'SQLi test page pattern')]
            elif 'search' in path or 'query' in path:
                suggested = [('search', 80, 'Search page pattern'), ('q', 80, 'Query pattern')]
            elif 'user' in path or 'profile' in path:
                suggested = [('user', 70, 'User page pattern'), ('id', 70, 'Profile ID')]
            elif 'product' in path or 'item' in path:
                suggested = [('id', 80, 'Product/item page'), ('pid', 70, 'Product ID')]
            elif 'article' in path or 'post' in path or 'page' in path:
                suggested = [('id', 75, 'Article/post page'), ('page', 60, 'Page number')]
            else:
                # Generic fallback
                suggested = [
                    ('id', 50, 'Generic fallback'),
                    ('search', 50, 'Generic fallback'),
                    ('q', 40, 'Generic fallback')
                ]

            self.logger.info(f"URL pattern suggests {len(suggested)} likely parameters:")
            for param, conf, reason in suggested:
                injection_points.append(InjectionPoint(
                    parameter=param,
                    location="query",
                    original_value="1",  # Numeric default
                    parameter_type="numeric" if param == 'id' else "string",
                    confidence=conf,
                    notes=f"URL pattern: {reason}"
                ))
                self.logger.info(f"  + {param} (confidence: {conf}%, reason: {reason})")

        # Log discovery results
        self.logger.info(f"Discovered {len(injection_points)} injection points:")
        for ip in injection_points:
            self.logger.info(f"  - {ip.parameter} ({ip.location}, type: {ip.parameter_type})")

        return injection_points

    def _discover_from_url(self, url: str) -> List[InjectionPoint]:
        """Discover parameters from URL query string"""
        injection_points = []

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for param_name, param_values in params.items():
            original_value = param_values[0] if param_values else ""
            param_type = self._infer_parameter_type(original_value)

            injection_points.append(InjectionPoint(
                parameter=param_name,
                location="query",
                original_value=original_value,
                parameter_type=param_type,
                notes="Discovered from URL query string"
            ))

        return injection_points

    async def _discover_from_forms(self, page: Page, url: str) -> List[InjectionPoint]:
        """Discover parameters from HTML forms"""
        injection_points = []

        try:
            # Find all forms on the page
            forms = await page.query_selector_all('form')

            self.logger.info(f"Found {len(forms)} form(s) on page")

            for idx, form in enumerate(forms):
                # Get form action
                action = await form.get_attribute('action')
                method = await form.get_attribute('method') or 'GET'

                self.logger.info(f"Form {idx+1}: action={action}, method={method}")

                # Find all input fields in this form
                inputs = await form.query_selector_all('input, textarea, select')

                for input_elem in inputs:
                    input_type = await input_elem.get_attribute('type') or 'text'
                    name = await input_elem.get_attribute('name')
                    value = await input_elem.get_attribute('value') or ""

                    # Skip buttons and hidden fields without value
                    if input_type in ['submit', 'button', 'reset', 'image']:
                        continue

                    if not name:
                        continue

                    param_type = self._infer_parameter_type(value)
                    location = "post" if method.upper() == "POST" else "query"

                    injection_points.append(InjectionPoint(
                        parameter=name,
                        location=location,
                        original_value=value,
                        parameter_type=param_type,
                        notes=f"Discovered from form (method: {method}, type: {input_type})"
                    ))

        except Exception as e:
            self.logger.error(f"Error discovering form parameters: {e}")

        return injection_points

    async def _discover_from_inputs(self, page: Page, url: str) -> List[InjectionPoint]:
        """Discover parameters from input fields not in forms"""
        injection_points = []

        try:
            # Find inputs not inside forms
            inputs = await page.query_selector_all('input:not(form input), textarea:not(form textarea)')

            for input_elem in inputs:
                input_type = await input_elem.get_attribute('type') or 'text'
                name = await input_elem.get_attribute('name')
                input_id = await input_elem.get_attribute('id')
                value = await input_elem.get_attribute('value') or ""

                # Skip buttons
                if input_type in ['submit', 'button', 'reset']:
                    continue

                # Use name or id
                param_name = name or input_id
                if not param_name:
                    continue

                param_type = self._infer_parameter_type(value)

                injection_points.append(InjectionPoint(
                    parameter=param_name,
                    location="post",  # Assume POST for standalone inputs
                    original_value=value,
                    parameter_type=param_type,
                    notes=f"Discovered from standalone input (type: {input_type})"
                ))

        except Exception as e:
            self.logger.error(f"Error discovering standalone inputs: {e}")

        return injection_points

    def _infer_parameter_type(self, value: str) -> str:
        """Infer parameter type from value"""
        if not value:
            return "string"

        if value.isdigit():
            return "numeric"

        if value.lower() in ['true', 'false', '1', '0']:
            return "boolean"

        return "string"

    async def test_parameter(
        self,
        page: Page,
        injection_point: InjectionPoint,
        test_value: str
    ) -> Dict:
        """
        Test a parameter by submitting a value

        Returns:
            Dict with response data
        """
        try:
            if injection_point.location == "query":
                # For query parameters, modify URL
                return await self._test_query_param(page, injection_point, test_value)

            elif injection_point.location == "post":
                # For POST parameters, submit form
                return await self._test_post_param(page, injection_point, test_value)

        except Exception as e:
            self.logger.error(f"Error testing parameter {injection_point.parameter}: {e}")
            return {'success': False, 'error': str(e)}

    async def _test_query_param(
        self,
        page: Page,
        injection_point: InjectionPoint,
        test_value: str
    ) -> Dict:
        """Test URL query parameter"""
        # Build URL with test value
        current_url = page.url
        parsed = urlparse(current_url)
        params = parse_qs(parsed.query)
        params[injection_point.parameter] = [test_value]

        # Build new URL
        from urllib.parse import urlencode, urlunparse
        new_query = urlencode(params, doseq=True)
        new_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))

        # Navigate and get response - use 'load' for better reliability
        try:
            response = await page.goto(new_url, wait_until='load', timeout=15000)
        except:
            response = await page.goto(new_url, wait_until='domcontentloaded', timeout=10000)

        content = await page.content()

        return {
            'success': True,
            'url': new_url,
            'status': response.status,
            'content': content
        }

    async def _test_post_param(
        self,
        page: Page,
        injection_point: InjectionPoint,
        test_value: str
    ) -> Dict:
        """Test POST parameter via form submission"""
        try:
            # Find form containing this parameter
            form = await page.query_selector(f'form:has(input[name="{injection_point.parameter}"])')

            if not form:
                # Try standalone input
                input_elem = await page.query_selector(f'input[name="{injection_point.parameter}"]')
                if not input_elem:
                    return {'success': False, 'error': 'Input not found'}

                # Fill the input
                await input_elem.fill(test_value)

                # Try to find and click submit button
                submit_btn = await page.query_selector('button[type="submit"], input[type="submit"]')
                if submit_btn:
                    await submit_btn.click()
                    await page.wait_for_load_state('networkidle')

                content = await page.content()
                return {
                    'success': True,
                    'content': content
                }

            # Fill form field
            input_selector = f'input[name="{injection_point.parameter}"], textarea[name="{injection_point.parameter}"]'
            await form.fill(input_selector, test_value)

            # Submit form
            await form.evaluate('(form) => form.submit()')
            await page.wait_for_load_state('networkidle')

            content = await page.content()

            return {
                'success': True,
                'content': content
            }

        except Exception as e:
            self.logger.error(f"Error submitting form: {e}")
            return {'success': False, 'error': str(e)}
