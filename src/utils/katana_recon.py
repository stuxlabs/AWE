#!/usr/bin/env python3
"""
Katana-based reconnaissance tool
Uses ProjectDiscovery's Katana for deep web crawling and endpoint discovery
"""

import subprocess
import json
import re
import asyncio
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs


@dataclass
class KatanaEndpoint:
    """Discovered endpoint from Katana"""
    url: str
    method: str = "GET"
    parameters: List[str] = field(default_factory=list)
    source: str = "crawl"  # crawl, js, form, etc.
    content_type: Optional[str] = None
    technologies: List[str] = field(default_factory=list)


@dataclass
class KatanaReconResult:
    """Full reconnaissance result from Katana"""
    target_url: str
    endpoints: List[KatanaEndpoint] = field(default_factory=list)
    forms: List[Dict] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    parameters_found: Set[str] = field(default_factory=set)
    paths_found: Set[str] = field(default_factory=set)
    technologies: Set[str] = field(default_factory=set)
    xml_endpoints: List[str] = field(default_factory=list)
    file_parameters: Set[str] = field(default_factory=set)
    login_forms: List[Dict] = field(default_factory=list)

    def get_injectable_endpoints(self) -> List[KatanaEndpoint]:
        """Get endpoints that have parameters (injectable)"""
        return [ep for ep in self.endpoints if ep.parameters]

    def get_summary(self) -> str:
        """Human-readable summary"""
        lines = [
            f"Target: {self.target_url}",
            f"Endpoints discovered: {len(self.endpoints)}",
            f"Injectable endpoints: {len(self.get_injectable_endpoints())}",
            f"Parameters found: {len(self.parameters_found)}",
            f"JS files: {len(self.js_files)}",
            f"Forms: {len(self.forms)}",
            f"Login forms: {len(self.login_forms)}",
            f"XML/SOAP endpoints: {len(self.xml_endpoints)}",
            f"File-related parameters: {len(self.file_parameters)}",
        ]
        if self.technologies:
            lines.append(f"Technologies: {', '.join(list(self.technologies)[:5])}")
        return "\n".join(lines)


class KatanaRecon:
    """
    Katana-based reconnaissance

    Uses katana for deep crawling with JS parsing, headless mode, and form detection
    """

    def __init__(self,
                 depth: int = 3,
                 js_crawl: bool = True,
                 headless: bool = True,
                 timeout: int = 30,
                 rate_limit: int = 100,
                 concurrency: int = 10):
        self.depth = depth
        self.js_crawl = js_crawl
        self.headless = headless
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.concurrency = concurrency

        # File-related parameter names that suggest LFI
        self.file_param_patterns = [
            'file', 'path', 'page', 'document', 'doc', 'pdf', 'include',
            'template', 'view', 'content', 'load', 'read', 'fetch',
            'src', 'source', 'url', 'uri', 'location', 'dir', 'folder'
        ]

        # XML/SOAP indicators
        self.xml_indicators = [
            'soap', 'xml', 'wsdl', 'api/xml', 'xmlrpc', 'webservice',
            'ws/', 'service', 'endpoint'
        ]

    async def run(self, target_url: str) -> KatanaReconResult:
        """
        Run Katana reconnaissance on target

        Returns structured recon results
        """
        print(f"\n[*] Starting Katana reconnaissance on {target_url}")
        print(f"    Depth: {self.depth}, JS crawl: {self.js_crawl}, Headless: {self.headless}")

        # Try Katana with headless first
        result = await self._run_katana(target_url, headless=self.headless)

        # If headless returned nothing, try without headless
        if not result.endpoints and not result.forms and not result.login_forms:
            if self.headless:
                print(f"\n    [!] Katana headless returned no results - trying standard mode...")
                result = await self._run_katana(target_url, headless=False)

        # If Katana found URLs but no forms, enhance with Playwright form detection
        if result.endpoints and not result.login_forms:
            print(f"\n    [*] Katana found URLs but no forms - using Playwright for form detection...")
            await self._enhance_with_playwright_forms(target_url, result)

        # If still nothing, fall back to Playwright completely
        if not result.endpoints and not result.forms and not result.login_forms:
            print(f"\n    [!] Katana returned no results - falling back to Playwright")
            result = await self._fallback_recon(target_url)

        return result

    async def _enhance_with_playwright_forms(self, target_url: str, result: KatanaReconResult):
        """Use Playwright to detect forms on Katana-discovered URLs"""
        from playwright.async_api import async_playwright
        from urllib.parse import urljoin

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()

                # Check base URL and discovered endpoints for forms
                urls_to_check = [target_url] + [ep.url for ep in result.endpoints[:5]]
                urls_to_check = list(set(urls_to_check))  # Dedupe

                for url in urls_to_check:
                    try:
                        await page.goto(url, wait_until="load", timeout=10000)

                        forms = await page.query_selector_all('form')
                        for form in forms:
                            action_attr = await form.get_attribute('action') or ''
                            action = urljoin(url, action_attr) if action_attr else url
                            method = (await form.get_attribute('method') or 'GET').upper()

                            inputs = await form.query_selector_all('input, select, textarea')
                            input_data = []
                            for inp in inputs:
                                name = await inp.get_attribute('name')
                                inp_type = await inp.get_attribute('type') or 'text'
                                if name:
                                    input_data.append({'name': name, 'type': inp_type})
                                    result.parameters_found.add(name)

                            if input_data:
                                form_data = {
                                    'action': action,
                                    'method': method,
                                    'inputs': input_data
                                }
                                result.forms.append(form_data)

                                # Check for login form
                                input_names = [inp['name'].lower() for inp in input_data]
                                if any(n in input_names for n in ['username', 'user', 'password', 'pass', 'email']):
                                    result.login_forms.append(form_data)
                                    print(f"        ✓ Found login form: {action}")

                                # Create endpoint from form
                                params = [inp['name'] for inp in input_data if inp['name']]
                                endpoint = KatanaEndpoint(
                                    url=action,
                                    method=method,
                                    parameters=params,
                                    source='form'
                                )
                                result.endpoints.append(endpoint)

                    except Exception as e:
                        pass  # Continue with other URLs

                await browser.close()

                if result.login_forms:
                    print(f"        Playwright enhancement found: {len(result.login_forms)} login form(s)")

        except Exception as e:
            print(f"        [!] Playwright enhancement error: {e}")

    async def _run_katana(self, target_url: str, headless: bool) -> KatanaReconResult:
        """Execute Katana with specified settings"""
        result = KatanaReconResult(target_url=target_url)

        # Build katana command
        cmd = self._build_command(target_url, headless=headless)
        mode = "headless" if headless else "standard"
        print(f"    Command ({mode}): {' '.join(cmd)}")

        try:
            # Run katana
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.timeout * 10  # Allow time for full crawl
            )

            output = stdout.decode('utf-8', errors='ignore')
            error_output = stderr.decode('utf-8', errors='ignore')

            # Debug: show what Katana returned
            if error_output:
                print(f"    [Katana stderr]: {error_output[:500]}")
            if not output.strip():
                print(f"    [!] Katana returned no output")
            else:
                print(f"    [Katana output]: {len(output)} bytes, {len(output.strip().split(chr(10)))} lines")

            # Parse JSON lines output
            urls_found = []
            for line in output.strip().split('\n'):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    self._process_katana_result(data, result)
                    if data.get('request', {}).get('endpoint'):
                        urls_found.append(data['request']['endpoint'])
                except json.JSONDecodeError:
                    # Plain URL output (non-jsonl)
                    if line.startswith('http'):
                        self._process_url(line, result)
                        urls_found.append(line.strip())

            # Debug: show discovered URLs
            if urls_found:
                print(f"    [URLs found]: {urls_found[:5]}")

            # Also run parameter extraction
            await self._extract_parameters(target_url, result)

            # Identify special endpoints
            self._identify_special_endpoints(result)

            print(f"\n[✓] Katana reconnaissance complete ({mode})")
            print(f"    {result.get_summary()}")

        except asyncio.TimeoutError:
            print(f"    [!] Katana timed out after {self.timeout * 10}s")
        except FileNotFoundError:
            print(f"    [!] Katana not found")
        except Exception as e:
            print(f"    [!] Katana error: {e}")

        return result

    def _build_command(self, target_url: str, headless: bool = None) -> List[str]:
        """Build katana command with options

        Katana flags (from katana -h):
        -u: target URL
        -d: crawl depth
        -jc: enable JavaScript crawling
        -hl: headless mode
        -jsonl: JSON Lines output
        -silent: silent mode
        -nc: no color
        -aff: automatic form fill
        -system-chrome: use system Chrome
        """
        use_headless = headless if headless is not None else self.headless

        cmd = [
            'katana',
            '-u', target_url,
            '-d', str(self.depth),
            '-jsonl',  # JSON lines output
            '-nc',  # No color
            '-aff',  # Automatic form fill
        ]

        if self.js_crawl:
            cmd.append('-jc')  # JavaScript crawling

        if use_headless:
            cmd.append('-hl')  # Headless browser mode
            cmd.append('-system-chrome')  # Use system Chrome

        return cmd

    def _process_katana_result(self, data: Dict, result: KatanaReconResult):
        """Process a single Katana JSON result"""

        # Extract request info
        request = data.get('request', {})
        response = data.get('response', {})

        url = request.get('endpoint', data.get('url', ''))
        method = request.get('method', 'GET')

        if not url:
            return

        # Extract parameters from URL
        params = self._extract_params_from_url(url)

        # Create endpoint
        endpoint = KatanaEndpoint(
            url=url,
            method=method,
            parameters=params,
            source='katana',
            technologies=response.get('technologies', [])
        )

        result.endpoints.append(endpoint)
        result.parameters_found.update(params)

        # Extract path
        parsed = urlparse(url)
        result.paths_found.add(parsed.path)

        # Technologies
        if response.get('technologies'):
            result.technologies.update(response['technologies'])

        # Check for JS files
        if url.endswith('.js') or '/js/' in url:
            result.js_files.append(url)

        # Check for forms in response
        if data.get('form'):
            result.forms.append(data['form'])
            self._process_form(data['form'], result)

    def _process_url(self, url: str, result: KatanaReconResult):
        """Process a plain URL from katana output"""
        params = self._extract_params_from_url(url)

        endpoint = KatanaEndpoint(
            url=url,
            parameters=params,
            source='crawl'
        )
        result.endpoints.append(endpoint)
        result.parameters_found.update(params)

        parsed = urlparse(url)
        result.paths_found.add(parsed.path)

        if url.endswith('.js'):
            result.js_files.append(url)

    def _process_form(self, form: Dict, result: KatanaReconResult):
        """Process form data"""
        action = form.get('action', '')
        method = form.get('method', 'GET').upper()
        inputs = form.get('inputs', [])

        # Check if it's a login form
        input_names = [inp.get('name', '').lower() for inp in inputs]
        is_login = any(name in input_names for name in ['username', 'user', 'email', 'login', 'password', 'pass', 'pwd'])

        if is_login:
            result.login_forms.append(form)

        # Extract parameters
        for inp in inputs:
            name = inp.get('name', '')
            if name:
                result.parameters_found.add(name)

    def _extract_params_from_url(self, url: str) -> List[str]:
        """Extract parameter names from URL query string"""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            return list(params.keys())
        except:
            return []

    async def _extract_parameters(self, target_url: str, result: KatanaReconResult):
        """Run katana specifically for parameter extraction"""
        try:
            # Extract keys
            cmd = [
                'katana', '-u', target_url,
                '-d', '2',
                '-silent', '-nc',
                '-f', 'kv',  # Key-value pairs
            ]

            if self.headless:
                cmd.extend(['-hl', '-nos'])

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=60)

            for line in stdout.decode('utf-8', errors='ignore').split('\n'):
                if '=' in line:
                    key = line.split('=')[0].strip()
                    if key:
                        result.parameters_found.add(key)

        except Exception as e:
            pass  # Parameter extraction is optional

    def _identify_special_endpoints(self, result: KatanaReconResult):
        """Identify XML endpoints and file-related parameters"""

        for endpoint in result.endpoints:
            url_lower = endpoint.url.lower()

            # Check for XML/SOAP
            if any(ind in url_lower for ind in self.xml_indicators):
                result.xml_endpoints.append(endpoint.url)

            # Check for file parameters
            for param in endpoint.parameters:
                param_lower = param.lower()
                if any(fp in param_lower for fp in self.file_param_patterns):
                    result.file_parameters.add(param)

        # Also check all discovered parameters
        for param in result.parameters_found:
            param_lower = param.lower()
            if any(fp in param_lower for fp in self.file_param_patterns):
                result.file_parameters.add(param)

    async def _fallback_recon(self, target_url: str) -> KatanaReconResult:
        """Fallback to basic reconnaissance if katana not available"""
        from src.utils.endpoint_discovery import discover_all_endpoints
        from playwright.async_api import async_playwright
        from urllib.parse import urljoin

        print("    [*] Using fallback Playwright-based reconnaissance")

        result = KatanaReconResult(target_url=target_url)

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                await page.goto(target_url, wait_until="load", timeout=30000)

                endpoints = await discover_all_endpoints(
                    page, target_url,
                    max_depth=2,
                    max_endpoints=30,
                    check_common_paths=True
                )

                for ep in endpoints:
                    endpoint = KatanaEndpoint(
                        url=ep.url,
                        method=ep.method,
                        parameters=ep.parameters,
                        source=ep.source
                    )
                    result.endpoints.append(endpoint)
                    result.parameters_found.update(ep.parameters)

                # Check for forms
                forms = await page.query_selector_all('form')
                for form in forms:
                    action_attr = await form.get_attribute('action') or ''
                    # Resolve relative URLs
                    action = urljoin(target_url, action_attr) if action_attr else target_url
                    method = (await form.get_attribute('method') or 'GET').upper()

                    inputs = await form.query_selector_all('input, select, textarea')
                    input_data = []
                    for inp in inputs:
                        name = await inp.get_attribute('name')
                        inp_type = await inp.get_attribute('type') or 'text'
                        if name:
                            input_data.append({'name': name, 'type': inp_type})
                            result.parameters_found.add(name)

                    form_data = {
                        'action': action,
                        'method': method,
                        'inputs': input_data
                    }
                    result.forms.append(form_data)

                    # Check for login form
                    input_names = [inp['name'].lower() for inp in input_data]
                    if any(n in input_names for n in ['username', 'user', 'password', 'pass', 'email']):
                        result.login_forms.append(form_data)
                        print(f"        ✓ Found login form: {action}")

                # Also create endpoints from forms
                for form_data in result.forms:
                    params = [inp['name'] for inp in form_data['inputs'] if inp['name']]
                    if params:
                        endpoint = KatanaEndpoint(
                            url=form_data['action'],
                            method=form_data['method'],
                            parameters=params,
                            source='form'
                        )
                        result.endpoints.append(endpoint)

                await browser.close()

                print(f"        Fallback found: {len(result.endpoints)} endpoints, {len(result.login_forms)} login forms")

        except Exception as e:
            print(f"    [!] Fallback recon error: {e}")

        self._identify_special_endpoints(result)
        return result


async def run_katana_recon(target_url: str,
                          depth: int = 3,
                          js_crawl: bool = True,
                          headless: bool = True) -> KatanaReconResult:
    """
    Convenience function to run Katana reconnaissance
    """
    recon = KatanaRecon(depth=depth, js_crawl=js_crawl, headless=headless)
    return await recon.run(target_url)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python katana_recon.py <URL>")
        sys.exit(1)

    target = sys.argv[1]
    result = asyncio.run(run_katana_recon(target))

    print("\n" + "="*70)
    print("RECONNAISSANCE RESULTS")
    print("="*70)
    print(result.get_summary())

    if result.get_injectable_endpoints():
        print("\nInjectable Endpoints:")
        for ep in result.get_injectable_endpoints()[:10]:
            print(f"  {ep.method} {ep.url}")
            print(f"      Params: {', '.join(ep.parameters)}")
