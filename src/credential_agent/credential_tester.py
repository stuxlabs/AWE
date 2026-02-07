"""
Tests default credentials against login forms
"""
import asyncio
from dataclasses import dataclass
from typing import List, Optional, Set
from playwright.async_api import Page, async_playwright
from pathlib import Path
import re


@dataclass
class CredentialResult:
    """Result of a credential test"""
    username: str
    password: str
    success: bool
    response_url: str
    response_code: int
    indicators: List[str]
    response_text: str


class CredentialTester:
    """Tests credentials against login forms"""

    # Indicators of successful login
    SUCCESS_INDICATORS = [
        r'logout',
        r'sign out',
        r'dashboard',
        r'welcome',
        r'profile',
        r'account',
        r'settings',
        r'admin panel',
        r'successfully logged in',
        r'logged in as',
    ]

    # Indicators of failed login
    FAILURE_INDICATORS = [
        r'invalid',
        r'incorrect',
        r'wrong',
        r'failed',
        r'error',
        r'denied',
        r'unauthorized',
        r'try again',
        r'login failed',
        r'bad credentials',
        r'authentication failed',
    ]

    def __init__(self, max_attempts: int = 100):
        """
        Args:
            max_attempts: Maximum number of credential combinations to try
        """
        self.max_attempts = max_attempts
        self.success_regex = re.compile('|'.join(self.SUCCESS_INDICATORS), re.IGNORECASE)
        self.failure_regex = re.compile('|'.join(self.FAILURE_INDICATORS), re.IGNORECASE)

    def load_wordlist(self, filepath: str, limit: Optional[int] = None) -> List[str]:
        """Load wordlist from file"""
        path = Path(filepath)
        if not path.exists():
            return []

        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [line.strip() for line in f if line.strip()]

        if limit:
            return lines[:limit]
        return lines

    async def test_credentials(
        self,
        page: Page,
        form_action: str,
        form_method: str,
        username_field: str,
        password_field: Optional[str],
        additional_fields: dict,
        usernames: List[str],
        passwords: List[str],
        csrf_fields: Optional[dict] = None
    ) -> Optional[CredentialResult]:
        """
        Test username/password combinations against a login form

        Args:
            page: Playwright page object
            form_action: Form submission URL
            form_method: HTTP method (get/post)
            username_field: Name of username field
            password_field: Name of password field
            additional_fields: Other form fields to include
            usernames: List of usernames to try
            passwords: List of passwords to try
            csrf_fields: CSRF token fields if present

        Returns:
            CredentialResult if successful login found, None otherwise
        """
        attempts = 0
        initial_url = page.url

        for username in usernames:
            for password in passwords:
                if attempts >= self.max_attempts:
                    print(f"    Reached max attempts ({self.max_attempts})")
                    return None

                attempts += 1

                if attempts % 10 == 0:
                    print(f"    Tried {attempts} combinations...")

                # Navigate to login page
                try:
                    await page.goto(initial_url, wait_until="load", timeout=10000)
                    await asyncio.sleep(0.5)
                except Exception as e:
                    print(f"    Error navigating: {e}")
                    continue

                # Fill form fields
                try:
                    # Fill username
                    await page.fill(f'input[name="{username_field}"]', username)

                    # Fill password if field exists
                    if password_field:
                        await page.fill(f'input[name="{password_field}"]', password)

                    # Fill additional fields
                    for field_name, field_value in additional_fields.items():
                        try:
                            await page.fill(f'input[name="{field_name}"]', field_value)
                        except:
                            pass

                    # Submit form
                    await page.click('input[type="submit"], button[type="submit"]')
                    await page.wait_for_load_state("load", timeout=10000)
                    await asyncio.sleep(1)

                    # Check result
                    response_url = page.url
                    response_text = await page.content()

                    # Determine if login was successful
                    result = self._analyze_response(
                        username,
                        password,
                        initial_url,
                        response_url,
                        response_text
                    )

                    if result and result.success:
                        return result

                except Exception as e:
                    # Likely form submission failed or page error
                    continue

        return None

    def _analyze_response(
        self,
        username: str,
        password: str,
        initial_url: str,
        response_url: str,
        response_text: str
    ) -> CredentialResult:
        """Analyze response to determine if login was successful"""

        indicators = []
        success_score = 0
        failure_score = 0

        # Check for URL change (redirect after login)
        if response_url != initial_url:
            indicators.append("URL changed")
            success_score += 2

        # Check for success indicators in response
        response_lower = response_text.lower()
        success_matches = self.success_regex.findall(response_lower)
        if success_matches:
            indicators.append(f"Success keywords: {', '.join(set(success_matches[:3]))}")
            success_score += len(success_matches)

        # Check for failure indicators
        failure_matches = self.failure_regex.findall(response_lower)
        if failure_matches:
            indicators.append(f"Failure keywords: {', '.join(set(failure_matches[:3]))}")
            failure_score += len(failure_matches) * 2

        # Check if login form is still present (suggests failed login)
        if 'type="password"' in response_text or 'type=password' in response_text:
            indicators.append("Password field still present")
            failure_score += 1

        # Determine success
        is_success = success_score > failure_score and success_score > 0

        return CredentialResult(
            username=username,
            password=password,
            success=is_success,
            response_url=response_url,
            response_code=200,  # Playwright doesn't easily expose this
            indicators=indicators,
            response_text=response_text[:1000]  # First 1000 chars
        )

    async def test_form(
        self,
        target_url: str,
        form_action: str,
        form_method: str,
        username_field: str,
        password_field: Optional[str],
        additional_fields: dict,
        username_wordlist: str,
        password_wordlist: str,
        password_limit: int = 100
    ) -> Optional[CredentialResult]:
        """
        Test a login form with credential wordlists

        Args:
            target_url: URL of the login page
            form_action: Form submission URL
            form_method: HTTP method
            username_field: Username field name
            password_field: Password field name
            additional_fields: Other form fields
            username_wordlist: Path to username wordlist
            password_wordlist: Path to password wordlist
            password_limit: Max passwords to try per username

        Returns:
            CredentialResult if successful, None otherwise
        """
        # Load wordlists
        usernames = self.load_wordlist(username_wordlist)
        passwords = self.load_wordlist(password_wordlist, limit=password_limit)

        if not usernames:
            print(f"    ✗ Could not load usernames from {username_wordlist}")
            return None

        if not passwords:
            print(f"    ✗ Could not load passwords from {password_wordlist}")
            return None

        print(f"    Loaded {len(usernames)} usernames and {len(passwords)} passwords")
        print(f"    Will try up to {min(len(usernames) * len(passwords), self.max_attempts)} combinations")

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()

            try:
                # Navigate to login page
                await page.goto(target_url, wait_until="load", timeout=30000)

                # Test credentials
                result = await self.test_credentials(
                    page,
                    form_action,
                    form_method,
                    username_field,
                    password_field,
                    additional_fields,
                    usernames,
                    passwords
                )

                await browser.close()
                return result

            except Exception as e:
                print(f"    ✗ Error: {e}")
                await browser.close()
                return None
