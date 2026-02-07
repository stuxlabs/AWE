"""
Universal parameter discovery for all injection types
Automatically discovers URL parameters, form inputs, and fuzzes for hidden parameters using Arjun
"""
from dataclasses import dataclass
from typing import List, Dict, Optional, Set
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode
from playwright.async_api import Page
import re
import asyncio
import aiohttp
import subprocess
import json
import tempfile
import os


@dataclass
class DiscoveredParameter:
    """A discovered parameter"""
    name: str
    location: str  # 'url', 'form', 'cookie', 'header'
    input_type: str  # 'text', 'hidden', 'password', 'textarea', 'select', etc.
    form_action: Optional[str] = None
    form_method: Optional[str] = None
    default_value: Optional[str] = None


class ParameterDiscovery:
    """Discovers all testable parameters on a page"""

    async def discover_all(self, page: Page, url: str) -> List[DiscoveredParameter]:
        """
        Discover all parameters from URL and forms

        Args:
            page: Playwright page object
            url: Target URL

        Returns:
            List of discovered parameters
        """
        parameters = []

        # 1. URL parameters
        url_params = self.discover_url_parameters(url)
        parameters.extend(url_params)

        # 2. Form parameters
        html = await page.content()
        form_params = self.discover_form_parameters(html, url)
        parameters.extend(form_params)

        # Remove duplicates (prefer form over URL if same name)
        seen = {}
        for param in parameters:
            if param.name not in seen:
                seen[param.name] = param
            elif param.location == 'form' and seen[param.name].location == 'url':
                # Prefer form parameters over URL parameters
                seen[param.name] = param

        return list(seen.values())

    def discover_url_parameters(self, url: str) -> List[DiscoveredParameter]:
        """Extract parameters from URL query string"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        discovered = []
        for name, values in params.items():
            discovered.append(DiscoveredParameter(
                name=name,
                location='url',
                input_type='query',
                default_value=values[0] if values else None
            ))

        return discovered

    def discover_form_parameters(self, html: str, base_url: str) -> List[DiscoveredParameter]:
        """Extract parameters from HTML forms"""
        soup = BeautifulSoup(html, 'html.parser')
        forms = soup.find_all('form')

        discovered = []

        for form in forms:
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
            inputs = form.find_all(['input', 'textarea', 'select'])

            for inp in inputs:
                name = inp.get('name', '')
                if not name:
                    continue

                input_type = inp.get('type', 'text').lower()
                default_value = inp.get('value', '')

                # Skip submit buttons
                if input_type in ['submit', 'button', 'image']:
                    continue

                # Handle textarea
                if inp.name == 'textarea':
                    input_type = 'textarea'
                    default_value = inp.get_text()

                # Handle select
                if inp.name == 'select':
                    input_type = 'select'
                    selected = inp.find('option', selected=True)
                    if selected:
                        default_value = selected.get('value', '')

                discovered.append(DiscoveredParameter(
                    name=name,
                    location='form',
                    input_type=input_type,
                    form_action=action,
                    form_method=method,
                    default_value=default_value
                ))

        return discovered

    def get_testable_parameters(self, parameters: List[DiscoveredParameter]) -> List[DiscoveredParameter]:
        """
        Filter to only testable parameters (exclude CSRF tokens, etc.)

        Args:
            parameters: All discovered parameters

        Returns:
            Filtered list of testable parameters
        """
        # Skip common CSRF and session token patterns
        skip_patterns = [
            r'csrf',
            r'token',
            r'_token',
            r'authenticity_token',
            r'__RequestVerificationToken',
            r'session',
            r'sid',
            r'jsessionid',
        ]

        testable = []
        for param in parameters:
            # Check if parameter name matches skip patterns
            skip = False
            for pattern in skip_patterns:
                if re.search(pattern, param.name, re.IGNORECASE):
                    skip = True
                    break

            if not skip:
                testable.append(param)

        return testable

    async def discover_and_filter(self, page: Page, url: str) -> List[DiscoveredParameter]:
        """
        Discover all parameters and filter to testable ones

        Args:
            page: Playwright page object
            url: Target URL

        Returns:
            List of testable parameters
        """
        all_params = await self.discover_all(page, url)
        testable_params = self.get_testable_parameters(all_params)
        return testable_params


async def discover_parameters(page: Page, url: str, fuzz_hidden: bool = False) -> List[DiscoveredParameter]:
    """
    Convenience function to discover parameters

    Args:
        page: Playwright page object
        url: Target URL
        fuzz_hidden: Whether to fuzz for hidden parameters (slower but thorough)

    Returns:
        List of testable parameters
    """
    discovery = ParameterDiscovery()
    params = await discovery.discover_and_filter(page, url)

    # If no params found and fuzzing enabled, try to find hidden params
    if not params and fuzz_hidden:
        fuzzed = await fuzz_parameters(url)
        params.extend(fuzzed)

    return params


def run_arjun(url: str, method: str = "GET", timeout: int = 30) -> List[DiscoveredParameter]:
    """
    Run Arjun to discover hidden parameters.

    Args:
        url: Target URL
        method: HTTP method (GET or POST)
        timeout: Timeout in seconds

    Returns:
        List of discovered parameters
    """
    discovered = []

    try:
        # Create temp file for JSON output
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_file = f.name

        # Run Arjun with small wordlist for speed
        cmd = [
            "arjun",
            "-u", url,
            "-m", method,
            "-oJ", output_file,
            "-w", "small",  # use built-in small wordlist
            "-t", "5",      # threads
            "-T", "10",     # request timeout
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        # Parse output
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                try:
                    data = json.load(f)
                    # Arjun JSON format: {url: {headers: {}, method: "", params: [...]}}
                    for target_url, url_data in data.items():
                        # params is a list inside the url_data dict
                        params = url_data.get('params', [])
                        for param in params:
                            discovered.append(DiscoveredParameter(
                                name=param,
                                location='url' if method == 'GET' else 'form',
                                input_type='arjun',
                                default_value=None
                            ))
                except json.JSONDecodeError:
                    pass
            os.unlink(output_file)

    except FileNotFoundError:
        print("    [!] Arjun not installed - falling back to basic fuzzing")
        return []
    except subprocess.TimeoutExpired:
        print("    [!] Arjun timed out")
        return []
    except Exception as e:
        print(f"    [!] Arjun error: {e}")
        return []

    return discovered


async def fuzz_parameters(url: str, method: str = "GET") -> List[DiscoveredParameter]:
    """
    Fuzz for hidden parameters using Arjun.

    Args:
        url: Target URL
        method: HTTP method

    Returns:
        List of discovered hidden parameters
    """
    # Run Arjun in a thread pool to not block async
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, run_arjun, url, method)


