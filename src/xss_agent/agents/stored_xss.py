"""
Stored XSS Testing Agent for form-based vulnerability detection
"""
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
from playwright.async_api import async_playwright, ConsoleMessage
from agno.agent import Agent

from ..models import FormCandidate, FormField, StoredXSSAttempt, VerificationResult


class StoredXSSAgent(Agent):
    """Agent responsible for stored XSS testing via form submission"""

    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.screenshot_dir = Path("screenshots")
        self.screenshot_dir.mkdir(exist_ok=True)

    async def test_stored_xss(self, form_candidate: FormCandidate, payload: str, proxy_agent=None) -> StoredXSSAttempt:
        """Test a form for stored XSS vulnerability"""
        self.logger.info(f"Testing stored XSS on form {form_candidate.form_id} with payload: {payload[:50]}...")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Create directories
        os.makedirs("./screenshots", exist_ok=True)
        os.makedirs("./html_captures", exist_ok=True)

        # Determine the best field to inject payload
        injection_field = self._select_injection_field(form_candidate)

        attempt = StoredXSSAttempt(
            form_candidate=form_candidate,
            payload=payload,
            injection_field=injection_field,
            timestamp=timestamp
        )

        try:
            # Step 1: Submit payload via form
            submission_result = await self._submit_form_with_payload(form_candidate, payload, injection_field, proxy_agent)
            attempt.submission_result = submission_result

            if not submission_result.get('success', False):
                self.logger.warning(f"Form submission failed: {submission_result.get('error')}")
                return attempt

            # Step 2: Verify if payload was stored and executes
            verification_result = await self._verify_stored_payload(form_candidate, payload, proxy_agent)
            attempt.verification_result = verification_result
            attempt.successful = verification_result.executed if verification_result else False

            if attempt.successful:
                self.logger.info(f"SUCCESS: Stored XSS confirmed in form {form_candidate.form_id}")
            else:
                self.logger.info(f"FAILED: No stored XSS execution detected in form {form_candidate.form_id}")

            return attempt

        except Exception as e:
            self.logger.error(f"Error testing stored XSS: {e}")
            attempt.submission_result = {'success': False, 'error': str(e)}
            return attempt

    def _select_injection_field(self, form: FormCandidate) -> str:
        """Select the best field to inject XSS payload"""
        # Priority: textarea > text > email > url > search
        priority_types = ['textarea', 'text', 'email', 'url', 'search']

        for field_type in priority_types:
            for field in form.fields:
                if field.field_type == field_type and field.name:
                    return field.name

        # Fallback to first non-hidden field
        for field in form.fields:
            if field.field_type != 'hidden' and field.name:
                return field.name

        # Last resort - use first field with a name
        for field in form.fields:
            if field.name:
                return field.name

        return "unknown"

    async def _submit_form_with_payload(self, form: FormCandidate, payload: str, injection_field: str, proxy_agent=None) -> Dict[str, Any]:
        """Submit form with XSS payload"""

        # Check if proxy is available and running
        if proxy_agent and not proxy_agent.running:
            self.logger.info("Proxy agent provided but not running - attempting to start")
            try:
                if proxy_agent.is_available():
                    proxy_agent.start()
                else:
                    self.logger.warning("mitmproxy not available - continuing without proxy")
                    proxy_agent = None
            except Exception as e:
                self.logger.error(f"Failed to start proxy: {e}")
                proxy_agent = None  # Disable proxy for this session
        elif proxy_agent and proxy_agent.running:
            self.logger.info("Using already running proxy for form submission traffic capture")

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)

            # Configure browser context with or without proxy
            context_options = {}
            if proxy_agent and proxy_agent.running:
                proxy_url = proxy_agent.get_proxy_url()
                context_options['proxy'] = {'server': proxy_url}
                self.logger.info(f"Form submission using proxy: {proxy_url}")

            context = await browser.new_context(**context_options)
            page = await context.new_page()

            try:
                # Navigate to the page containing the form (not the action URL)
                # Extract base URL from action URL
                from urllib.parse import urljoin, urlparse
                parsed_action = urlparse(form.action_url)

                if parsed_action.netloc:
                    # Action URL is absolute, derive base URL
                    base_url = f"{parsed_action.scheme}://{parsed_action.netloc}" + '/'.join(parsed_action.path.split('/')[:-1])
                    if not base_url.endswith('/'):
                        base_url += '/'
                else:
                    # Action URL is relative, use the action URL itself
                    base_url = form.action_url

                await page.goto(base_url, wait_until='networkidle', timeout=30000)

                # Find the form
                form_selector = 'form'
                if len(await page.query_selector_all('form')) > 1:
                    # If multiple forms, try to find the specific one
                    form_selector = f'form:has(input[name="{injection_field}"])'

                form_element = await page.query_selector(form_selector)
                if not form_element:
                    return {'success': False, 'error': 'Form not found on page'}

                # Fill form fields
                fill_data = self._generate_form_data(form, payload, injection_field)

                for field_name, field_value in fill_data.items():
                    try:
                        field_selector = f'input[name="{field_name}"], textarea[name="{field_name}"], select[name="{field_name}"]'
                        await page.fill(field_selector, str(field_value))
                        self.logger.debug(f"Filled field {field_name} with: {str(field_value)[:50]}...")
                    except Exception as e:
                        self.logger.warning(f"Could not fill field {field_name}: {e}")

                # Submit the form
                submit_button_selector = 'input[type="submit"], button[type="submit"]'
                submit_button = await page.query_selector(submit_button_selector)

                if submit_button:
                    await submit_button.click()
                else:
                    # Try submitting via form element
                    await form_element.evaluate('form => form.submit()')

                # Wait for navigation or response
                try:
                    await page.wait_for_load_state('networkidle', timeout=10000)
                except:
                    pass  # Continue even if timeout

                # Capture response details
                final_url = page.url
                page_content = await page.content()

                return {
                    'success': True,
                    'final_url': final_url,
                    'response_length': len(page_content),
                    'form_data': fill_data,
                    'injection_field': injection_field,
                    'payload': payload
                }

            except Exception as e:
                return {'success': False, 'error': str(e)}
            finally:
                await browser.close()

    def _generate_form_data(self, form: FormCandidate, payload: str, injection_field: str) -> Dict[str, str]:
        """Generate form data with payload in the specified field"""
        form_data = {}

        for field in form.fields:
            if field.name == injection_field:
                # Inject the payload
                form_data[field.name] = payload
            elif field.field_type == 'hidden':
                # Keep hidden field values
                form_data[field.name] = field.default_value or ''
            elif field.required or field.field_type in ['text', 'textarea']:
                # Fill required fields with dummy data
                dummy_value = self._generate_dummy_value(field)
                form_data[field.name] = dummy_value

        # Include CSRF token if present
        if form.csrf_token:
            csrf_field_names = ['csrf_token', '_token', 'authenticity_token']
            for csrf_name in csrf_field_names:
                if any(field.name == csrf_name for field in form.fields):
                    form_data[csrf_name] = form.csrf_token
                    break

        return form_data

    def _generate_dummy_value(self, field: FormField) -> str:
        """Generate appropriate dummy data for a field"""
        if field.field_type == 'email':
            return 'test@example.com'
        elif field.field_type == 'url':
            return 'https://example.com'
        elif field.field_type == 'tel':
            return '123-456-7890'
        elif field.field_type == 'number':
            return '42'
        elif field.field_type == 'textarea':
            return 'Test message content'
        else:
            # Default for text, search, etc.
            placeholder_hint = field.placeholder or field.name or 'test'
            if 'name' in placeholder_hint.lower():
                return 'TestUser'
            elif 'email' in placeholder_hint.lower():
                return 'test@example.com'
            elif 'message' in placeholder_hint.lower() or 'comment' in placeholder_hint.lower():
                return 'Test comment'
            else:
                return 'TestValue'

    async def _verify_stored_payload(self, form: FormCandidate, payload: str, proxy_agent=None) -> Optional[VerificationResult]:
        """Verify if the stored payload executes when viewing the page"""
        # For stored XSS, we need to revisit the page (or a display page) to see if payload executes
        # This could be the same form page or a different page that displays stored content

        verification_urls = [
            form.action_url,  # Try the form action URL
        ]

        # If action URL is different from base URL, also try base URL
        if '/' in form.action_url:
            base_url = '/'.join(form.action_url.split('/')[:-1]) + '/'
            if base_url != form.action_url:
                verification_urls.append(base_url)

        for url in verification_urls:
            try:
                result = await self._check_payload_execution(url, payload, proxy_agent)
                if result and result.executed:
                    return result
            except Exception as e:
                self.logger.warning(f"Error verifying stored payload at {url}: {e}")
                continue

        # If no execution found, return the last result for analysis
        try:
            return await self._check_payload_execution(verification_urls[0], payload, proxy_agent)
        except:
            return None

    async def _check_payload_execution(self, url: str, payload: str, proxy_agent=None) -> Optional[VerificationResult]:
        """Check if payload executes on a given URL"""

        # Check if proxy is available and running
        if proxy_agent and not proxy_agent.running:
            self.logger.info("Proxy agent provided but not running - attempting to start")
            try:
                if proxy_agent.is_available():
                    proxy_agent.start()
                else:
                    self.logger.warning("mitmproxy not available - continuing without proxy")
                    proxy_agent = None
            except Exception as e:
                self.logger.error(f"Failed to start proxy: {e}")
                proxy_agent = None  # Disable proxy for this session
        elif proxy_agent and proxy_agent.running:
            self.logger.info("Using already running proxy for payload verification")

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)

            # Configure browser context with or without proxy
            context_options = {}
            if proxy_agent and proxy_agent.running:
                proxy_url = proxy_agent.get_proxy_url()
                context_options['proxy'] = {'server': proxy_url}

            context = await browser.new_context(**context_options)
            page = await context.new_page()

            # Set up monitoring
            alerts_caught = []
            console_logs = []
            response_status = None
            response_headers = {}

            # Monitor responses
            def handle_response(response):
                nonlocal response_status, response_headers
                if response.url == url:
                    response_status = response.status
                    response_headers = response.headers

            page.on("response", handle_response)

            # Monitor dialogs
            async def handle_dialog(dialog):
                alerts_caught.append(dialog.message)
                await dialog.accept()

            page.on("dialog", handle_dialog)

            # Monitor console
            def handle_console(msg: ConsoleMessage):
                console_logs.append({
                    'type': msg.type,
                    'text': msg.text,
                    'location': str(msg.location) if msg.location else None
                })

            page.on("console", handle_console)

            try:
                # Navigate to verification URL
                response = await page.goto(url, wait_until='networkidle', timeout=30000)
                if response:
                    response_status = response.status
                    response_headers = response.headers

                # Wait for potential execution
                await page.wait_for_timeout(3000)

                # Get page content
                page_content = await page.content()
                reflection_found = payload in page_content

                # Check if payload executed
                executed = False
                execution_method = None

                if alerts_caught:
                    executed = True
                    execution_method = "alert"
                elif any('XSS' in log.get('text', '') or 'xss' in log.get('text', '').lower() for log in console_logs):
                    executed = True
                    execution_method = "console"
                elif reflection_found and any(tag in payload.lower() for tag in ['<script>', '<svg', '<img', '<iframe']):
                    # Additional checks for DOM execution
                    script_elements = await page.query_selector_all('script, svg, img[onerror]')
                    if script_elements:
                        executed = True
                        execution_method = "dom"

                # Take screenshot
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                screenshot_name = f"stored_xss_{timestamp}_{execution_method or 'failed'}.png"
                screenshot_path = f"./screenshots/{screenshot_name}"
                await page.screenshot(path=screenshot_path, full_page=True)

                # Save HTML content
                html_filename = f"stored_xss_verification_{timestamp}.html"
                html_file_path = f"./html_captures/{html_filename}"

                with open(html_file_path, 'w', encoding='utf-8') as f:
                    f.write(f"<!-- STORED XSS VERIFICATION -->\n")
                    f.write(f"<!-- URL: {url} -->\n")
                    f.write(f"<!-- Payload: {payload} -->\n")
                    f.write(f"<!-- Executed: {executed} -->\n")
                    f.write(f"<!-- Timestamp: {timestamp} -->\n\n")
                    f.write(page_content)

                return VerificationResult(
                    url=url,
                    payload=payload,
                    executed=executed,
                    reflection_found=reflection_found,
                    execution_method=execution_method,
                    screenshot_path=screenshot_path,
                    timestamp=timestamp,
                    console_logs=console_logs,
                    alerts_caught=alerts_caught,
                    page_content=page_content[:1000] + "..." if len(page_content) > 1000 else page_content,
                    page_content_file=html_file_path,
                    response_status=response_status,
                    response_headers=response_headers
                )

            except Exception as e:
                self.logger.error(f"Error checking payload execution: {e}")
                return None
            finally:
                await browser.close()