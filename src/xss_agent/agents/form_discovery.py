"""
Form Discovery Agent for identifying potential stored XSS targets
"""
import logging
from typing import List, Optional
from playwright.async_api import async_playwright, Page
from agno.agent import Agent

from ..models import FormField, FormCandidate


class FormDiscoveryAgent(Agent):
    """Agent responsible for discovering and analyzing forms for stored XSS testing"""

    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)

    async def discover_forms(self, target_url: str) -> List[FormCandidate]:
        """Discover all forms on the target page that could be vulnerable to stored XSS"""
        self.logger.info(f"Discovering forms on {target_url}")

        forms = []

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()

            try:
                # Navigate to the page
                await page.goto(target_url, wait_until='networkidle', timeout=30000)

                # Find all forms
                form_elements = await page.query_selector_all('form')

                for i, form_element in enumerate(form_elements):
                    try:
                        form_candidate = await self._analyze_form(page, form_element, i, target_url)
                        if form_candidate and self._is_potential_xss_target(form_candidate):
                            forms.append(form_candidate)
                            self.logger.info(f"Found potential XSS form: {form_candidate.form_id}")
                    except Exception as e:
                        self.logger.warning(f"Error analyzing form {i}: {e}")
                        continue

            except Exception as e:
                self.logger.error(f"Error discovering forms: {e}")
            finally:
                await browser.close()

        self.logger.info(f"Discovered {len(forms)} potential XSS forms")
        return forms

    async def _analyze_form(self, page: Page, form_element, form_index: int, base_url: str) -> Optional[FormCandidate]:
        """Analyze a single form element and extract its details"""
        try:
            # Get form attributes
            action = await form_element.get_attribute('action') or ''
            method = (await form_element.get_attribute('method') or 'GET').upper()

            # Resolve relative action URLs
            if action:
                from urllib.parse import urljoin
                action_url = urljoin(base_url, action)
            else:
                action_url = base_url

            # Find all input fields
            input_elements = await form_element.query_selector_all('input, textarea, select')
            fields = []

            for input_elem in input_elements:
                field = await self._analyze_form_field(input_elem)
                if field:
                    fields.append(field)

            # Find submit buttons
            submit_buttons = []
            button_elements = await form_element.query_selector_all('input[type="submit"], button[type="submit"], button:not([type])')

            for button in button_elements:
                button_value = await button.get_attribute('value') or await button.inner_text() or 'Submit'
                submit_buttons.append(button_value.strip())

            # Look for CSRF tokens
            csrf_token = await self._find_csrf_token(form_element)

            # Get form HTML for debugging
            form_html = await form_element.inner_html()

            form_id = f"form_{form_index}_{hash(action_url + str(len(fields)))}"

            return FormCandidate(
                form_id=form_id,
                action_url=action_url,
                method=method,
                fields=fields,
                submit_buttons=submit_buttons,
                csrf_token=csrf_token,
                form_element_html=form_html[:500]  # Truncate for storage
            )

        except Exception as e:
            self.logger.error(f"Error analyzing form: {e}")
            return None

    async def _analyze_form_field(self, input_element) -> Optional[FormField]:
        """Analyze a single form field"""
        try:
            name = await input_element.get_attribute('name')
            if not name:
                return None

            field_type = await input_element.get_attribute('type') or 'text'
            tag_name = await input_element.evaluate('el => el.tagName.toLowerCase()')

            if tag_name == 'textarea':
                field_type = 'textarea'
            elif tag_name == 'select':
                field_type = 'select'

            required = await input_element.get_attribute('required') is not None
            max_length_attr = await input_element.get_attribute('maxlength')
            max_length = int(max_length_attr) if max_length_attr and max_length_attr.isdigit() else None

            placeholder = await input_element.get_attribute('placeholder')
            default_value = await input_element.get_attribute('value')

            return FormField(
                name=name,
                field_type=field_type,
                required=required,
                max_length=max_length,
                placeholder=placeholder,
                default_value=default_value
            )

        except Exception as e:
            self.logger.error(f"Error analyzing form field: {e}")
            return None

    async def _find_csrf_token(self, form_element) -> Optional[str]:
        """Look for CSRF tokens in the form"""
        try:
            # Common CSRF token field names
            csrf_selectors = [
                'input[name*="csrf"]',
                'input[name*="token"]',
                'input[name*="_token"]',
                'input[name="authenticity_token"]',
                'input[type="hidden"][name*="csrf"]',
                'input[type="hidden"][name*="token"]'
            ]

            for selector in csrf_selectors:
                csrf_element = await form_element.query_selector(selector)
                if csrf_element:
                    token_value = await csrf_element.get_attribute('value')
                    if token_value:
                        return token_value

            return None

        except Exception:
            return None

    def _is_potential_xss_target(self, form: FormCandidate) -> bool:
        """Determine if a form is a potential target for stored XSS"""
        # Look for text-based input fields that could store user content
        text_field_types = {'text', 'textarea', 'email', 'url', 'search'}

        has_text_fields = any(
            field.field_type in text_field_types
            for field in form.fields
        )

        # Skip forms that are likely authentication/login forms
        auth_indicators = ['password', 'login', 'signin', 'auth']
        field_names = [field.name.lower() for field in form.fields]

        is_auth_form = any(
            any(indicator in name for indicator in auth_indicators)
            for name in field_names
        )

        # Skip forms with only hidden fields
        visible_fields = [f for f in form.fields if f.field_type != 'hidden']

        return has_text_fields and not is_auth_form and len(visible_fields) > 0