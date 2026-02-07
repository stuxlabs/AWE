"""
Detects login forms in HTML pages
"""
from dataclasses import dataclass
from typing import List, Optional, Set
from bs4 import BeautifulSoup
import re


@dataclass
class LoginForm:
    """Represents a detected login form"""
    action: str
    method: str
    username_field: str
    password_field: Optional[str]
    additional_fields: dict
    form_html: str
    confidence: float


class FormDetector:
    """Detects login forms using heuristics"""

    # Common field names for usernames
    USERNAME_PATTERNS = [
        r'user(name)?',
        r'email',
        r'login',
        r'account',
        r'id',
        r'uid',
        r'usr',
    ]

    # Common field names for passwords
    PASSWORD_PATTERNS = [
        r'pass(word)?',
        r'pwd',
        r'secret',
        r'pin',
    ]

    # Keywords that suggest login forms
    LOGIN_KEYWORDS = {
        'login', 'signin', 'sign in', 'log in', 'authenticate',
        'credentials', 'password', 'username', 'email'
    }

    def __init__(self):
        self.username_regex = re.compile('|'.join(self.USERNAME_PATTERNS), re.IGNORECASE)
        self.password_regex = re.compile('|'.join(self.PASSWORD_PATTERNS), re.IGNORECASE)

    def find_login_forms(self, html: str, base_url: str = "") -> List[LoginForm]:
        """
        Find all potential login forms in HTML

        Args:
            html: HTML content to analyze
            base_url: Base URL for resolving relative URLs

        Returns:
            List of detected login forms
        """
        soup = BeautifulSoup(html, 'html.parser')
        forms = soup.find_all('form')

        login_forms = []

        for form in forms:
            result = self._analyze_form(form, base_url)
            if result:
                login_forms.append(result)

        return login_forms

    def _analyze_form(self, form, base_url: str) -> Optional[LoginForm]:
        """Analyze a single form to determine if it's a login form"""

        # Get form attributes
        action = form.get('action', '')
        method = form.get('method', 'get').lower()

        # Make action absolute
        if action and not action.startswith('http'):
            if action.startswith('/'):
                action = base_url.rstrip('/') + action
            else:
                action = base_url.rstrip('/') + '/' + action
        elif not action:
            action = base_url

        # Find all input fields
        inputs = form.find_all('input')

        username_field = None
        password_field = None
        additional_fields = {}
        confidence = 0.0

        for inp in inputs:
            name = inp.get('name', '')
            input_type = inp.get('type', 'text').lower()
            input_id = inp.get('id', '')
            placeholder = inp.get('placeholder', '')

            # Check for password field
            if input_type == 'password':
                password_field = name
                confidence += 0.5
            # Check for username field
            elif (self.username_regex.search(name) or
                  self.username_regex.search(input_id) or
                  self.username_regex.search(placeholder)):
                username_field = name
                confidence += 0.3
            # Check if it's a text/email field that might be username
            elif input_type in ['text', 'email'] and not username_field:
                username_field = name
                confidence += 0.1
            # Store other fields
            elif input_type not in ['submit', 'button']:
                additional_fields[name] = inp.get('value', '')

        # Check form context for login keywords
        form_text = form.get_text().lower()
        keyword_matches = sum(1 for kw in self.LOGIN_KEYWORDS if kw in form_text)
        confidence += keyword_matches * 0.1

        # Check action URL for login keywords
        action_lower = action.lower()
        if any(kw in action_lower for kw in self.LOGIN_KEYWORDS):
            confidence += 0.2

        # Must have at least a username field to be considered
        if not username_field:
            return None

        # Boost confidence if we have both username and password
        if username_field and password_field:
            confidence += 0.3

        # Cap confidence at 1.0
        confidence = min(confidence, 1.0)

        # Only return forms with reasonable confidence (>0.3)
        if confidence < 0.3:
            return None

        return LoginForm(
            action=action,
            method=method,
            username_field=username_field,
            password_field=password_field,
            additional_fields=additional_fields,
            form_html=str(form),
            confidence=confidence
        )

    def extract_csrf_token(self, html: str, form_html: str) -> Optional[dict]:
        """Extract CSRF tokens from form"""
        soup = BeautifulSoup(form_html, 'html.parser')
        csrf_fields = {}

        # Common CSRF token field names
        csrf_patterns = [
            r'csrf', r'token', r'_token', r'authenticity_token',
            r'__RequestVerificationToken'
        ]

        for inp in soup.find_all('input', type='hidden'):
            name = inp.get('name', '')
            value = inp.get('value', '')

            for pattern in csrf_patterns:
                if re.search(pattern, name, re.IGNORECASE):
                    csrf_fields[name] = value
                    break

        return csrf_fields if csrf_fields else None
