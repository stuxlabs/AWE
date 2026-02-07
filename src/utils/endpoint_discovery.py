"""
Endpoint Discovery and Web Crawling
Discovers all testable endpoints from a base URL
Integrates Arjun for hidden parameter discovery
"""
from dataclasses import dataclass
from typing import List, Set
from urllib.parse import urljoin, urlparse, parse_qs
from playwright.async_api import Page
from bs4 import BeautifulSoup
import asyncio
from .parameter_discovery import run_arjun, DiscoveredParameter


@dataclass
class DiscoveredEndpoint:
    """Represents a discovered endpoint"""
    url: str
    method: str  # GET, POST
    source: str  # link, form, sitemap, etc.
    parameters: List[str]  # List of parameter names
    has_query_params: bool
    form_action: str = None


class EndpointDiscoverer:
    """Discovers endpoints by crawling and analyzing a web application"""

    def __init__(self, max_depth: int = 2, max_endpoints: int = 50):
        self.max_depth = max_depth
        self.max_endpoints = max_endpoints
        self.visited_urls: Set[str] = set()
        self.discovered_endpoints: List[DiscoveredEndpoint] = []

    def normalize_url(self, url: str) -> str:
        """Normalize URL by removing fragments and trailing slashes"""
        parsed = urlparse(url)
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        return normalized.rstrip('/')

    def is_same_domain(self, url1: str, url2: str) -> bool:
        """Check if two URLs belong to the same domain"""
        return urlparse(url1).netloc == urlparse(url2).netloc

    async def discover_from_html(self, html: str, base_url: str) -> List[DiscoveredEndpoint]:
        """Extract endpoints from HTML content"""
        soup = BeautifulSoup(html, 'html.parser')
        endpoints = []

        # Security-relevant keywords in links (these should always be discovered)
        security_keywords = [
            'admin', 'dashboard', 'profile', 'settings', 'upload', 'download',
            'file', 'document', 'api', 'soap', 'xml', 'service', 'export', 'import',
            'backup', 'config', 'debug', 'test', 'user', 'account', 'edit', 'delete',
            'manage', 'panel', 'console', 'control', 'private', 'internal', 'secret'
        ]

        # 1. Extract links (GET endpoints) from various tags
        # Check <a href>, <link href>, <script src>, <img src>, etc.
        url_sources = [
            ('a', 'href'),
            ('link', 'href'),
            ('script', 'src'),
            ('img', 'src'),
            ('iframe', 'src'),
        ]

        for tag_name, attr_name in url_sources:
            for tag in soup.find_all(tag_name):
                url_attr = tag.get(attr_name)
                if not url_attr:
                    continue

                full_url = urljoin(base_url, url_attr)

                # Only same domain
                if not self.is_same_domain(base_url, full_url):
                    continue

                normalized = self.normalize_url(full_url)
                if normalized in self.visited_urls:
                    continue

                # Parse query parameters
                parsed = urlparse(full_url)
                params = list(parse_qs(parsed.query).keys()) if parsed.query else []

                # Get link text for <a> tags (useful for identifying interesting endpoints)
                link_text = ""
                if tag_name == 'a':
                    link_text = tag.get_text(strip=True).lower()

                # Check if URL or link text contains security-relevant keywords
                url_lower = full_url.lower()
                is_security_relevant = any(kw in url_lower or kw in link_text for kw in security_keywords)

                # Add if: has parameters, is a navigable link, OR is security-relevant
                if len(params) > 0 or tag_name == 'a' or is_security_relevant:
                    endpoint = DiscoveredEndpoint(
                        url=full_url.split('?')[0] if params else full_url,  # URL without specific values
                        method='GET',
                        source=f'{tag_name}_{attr_name}',
                        parameters=params,
                        has_query_params=len(params) > 0
                    )
                    endpoints.append(endpoint)

        # 2. Extract forms (POST/GET endpoints)
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()

            # Get form action URL
            if action:
                form_url = urljoin(base_url, action)
            else:
                form_url = base_url

            # Only same domain
            if not self.is_same_domain(base_url, form_url):
                continue

            # Extract form parameters
            params = []
            for input_field in form.find_all(['input', 'textarea', 'select']):
                name = input_field.get('name')
                input_type = input_field.get('type', 'text')

                # Skip buttons and submit
                if input_type in ['submit', 'button', 'image']:
                    continue

                if name:
                    params.append(name)

            endpoint = DiscoveredEndpoint(
                url=form_url,
                method=method,
                source='form',
                parameters=params,
                has_query_params=False,
                form_action=action
            )
            endpoints.append(endpoint)

        return endpoints

    async def crawl_page(self, page: Page, url: str, depth: int = 0) -> List[DiscoveredEndpoint]:
        """Crawl a single page and extract endpoints"""
        if depth > self.max_depth or len(self.discovered_endpoints) >= self.max_endpoints:
            return []

        normalized = self.normalize_url(url)
        if normalized in self.visited_urls:
            return []

        print(f"  [Crawl] Depth {depth}: {url}")
        self.visited_urls.add(normalized)

        try:
            await page.goto(url, wait_until="load", timeout=15000)
            await asyncio.sleep(0.5)

            html = await page.content()
            endpoints = await self.discover_from_html(html, url)

            # Add to discovered list
            for endpoint in endpoints:
                # Avoid duplicates
                if not any(e.url == endpoint.url and e.method == endpoint.method
                          for e in self.discovered_endpoints):
                    self.discovered_endpoints.append(endpoint)
                    print(f"    → Found: {endpoint.method} {endpoint.url} " +
                          f"(params: {len(endpoint.parameters)})")

            # Recursively crawl linked pages (only GET links, not forms)
            if depth < self.max_depth:
                for endpoint in endpoints:
                    if (endpoint.method == 'GET' and
                        endpoint.source.startswith('a_') and  # Fixed: was 'link' but source is 'a_href'
                        len(self.discovered_endpoints) < self.max_endpoints):
                        await self.crawl_page(page, endpoint.url, depth + 1)

            return endpoints

        except Exception as e:
            print(f"    ✗ Error crawling {url}: {e}")
            return []

    async def discover_endpoints(self, page: Page, base_url: str) -> List[DiscoveredEndpoint]:
        """
        Main entry point: Discover all endpoints from a base URL

        Args:
            page: Playwright page instance
            base_url: Starting URL to crawl from

        Returns:
            List of discovered endpoints with parameters
        """
        print(f"\n[*] Starting endpoint discovery from: {base_url}")
        print(f"    Max depth: {self.max_depth}, Max endpoints: {self.max_endpoints}")

        # Start crawling
        await self.crawl_page(page, base_url, depth=0)

        # Separate injectable vs navigation endpoints
        injectable_endpoints = [
            e for e in self.discovered_endpoints
            if len(e.parameters) > 0 or e.has_query_params
        ]

        print(f"\n[✓] Discovery complete:")
        print(f"    Total endpoints: {len(self.discovered_endpoints)}")
        print(f"    Injectable endpoints: {len(injectable_endpoints)}")

        # Return ALL endpoints - some pages without params are important (like /soap_service)
        return self.discovered_endpoints

    async def discover_common_paths(self, page: Page, base_url: str) -> List[DiscoveredEndpoint]:
        """Try common vulnerable paths"""
        common_paths = [
            # Search/query endpoints (SQLi, XSS)
            '/search', '/search.php', '/query', '/find',
            # Template endpoints (SSTI)
            '/render', '/template', '/greet', '/hello', '/preview',
            # User/profile endpoints (IDOR)
            '/user', '/profile', '/account', '/settings', '/dashboard',
            '/admin', '/admin.php', '/administrator',
            # Hidden/restricted pages (often vulnerable)
            '/private', '/private.php', '/secret', '/secret.php',
            '/hidden', '/internal', '/restricted', '/secure',
            # File endpoints (LFI)
            '/view', '/page', '/file', '/document', '/download', '/read',
            '/include', '/load', '/fetch', '/view.php', '/file.php',
            # XML/SOAP endpoints (XXE)
            '/soap', '/soap_service', '/xml', '/xmlrpc', '/wsdl',
            '/api/xml', '/webservice', '/ws', '/service',
            # API endpoints
            '/api', '/api/v1', '/api/v2', '/api/search', '/api/query',
            '/api/user', '/api/data', '/graphql',
            # Upload endpoints
            '/upload', '/import', '/file_upload',
            # Other security-relevant
            '/debug', '/test', '/dev', '/backup', '/config',
            '/robots.txt', '/sitemap.xml', '/.env', '/phpinfo.php',
        ]

        print(f"\n[*] Checking common vulnerable paths...")
        endpoints = []

        for path in common_paths:
            test_url = urljoin(base_url, path)

            try:
                response = await page.goto(test_url, wait_until="load", timeout=10000)

                # Check if page exists (not 404)
                if response and response.status < 400:
                    print(f"    ✓ Found: {test_url} (status: {response.status})")

                    # ADD THE PATH ITSELF as an endpoint (important for /wsdl, /soap, etc.)
                    path_endpoint = DiscoveredEndpoint(
                        url=test_url,
                        method='GET',
                        source='common_path',
                        parameters=[],
                        has_query_params=False
                    )
                    endpoints.append(path_endpoint)

                    # Also try to extract sub-endpoints from the page HTML
                    html = await page.content()
                    page_endpoints = await self.discover_from_html(html, test_url)
                    for ep in page_endpoints:
                        # Avoid duplicates - check both URL AND method (GET /profile != POST /profile)
                        if not any(e.url == ep.url and e.method == ep.method for e in endpoints):
                            endpoints.append(ep)

            except Exception:
                pass

        print(f"    Discovered {len(endpoints)} endpoints from common paths")
        return endpoints


async def discover_all_endpoints(page: Page, target_url: str,
                                 max_depth: int = 2,
                                 max_endpoints: int = 50,
                                 check_common_paths: bool = True,
                                 use_arjun: bool = True) -> List[DiscoveredEndpoint]:
    """
    Convenience function to discover all endpoints

    Args:
        page: Playwright page instance
        target_url: Base URL to start discovery from
        max_depth: Maximum crawl depth
        max_endpoints: Maximum endpoints to discover
        check_common_paths: Also check common vulnerable paths
        use_arjun: Run Arjun for hidden parameter discovery

    Returns:
        List of discovered endpoints with injectable parameters
    """
    discoverer = EndpointDiscoverer(max_depth=max_depth, max_endpoints=max_endpoints)

    # Main crawl
    endpoints = await discoverer.discover_endpoints(page, target_url)

    # Also check common paths
    if check_common_paths:
        common_endpoints = await discoverer.discover_common_paths(page, target_url)

        # Merge with existing endpoints (avoid duplicates)
        for endpoint in common_endpoints:
            if not any(e.url == endpoint.url and e.method == endpoint.method
                      for e in endpoints):
                endpoints.append(endpoint)

    # Run Arjun for hidden parameter discovery
    if use_arjun:
        injectable_count = sum(1 for e in endpoints if e.parameters)

        # Security-relevant keywords - prioritize these for Arjun
        priority_keywords = ['private', 'secret', 'admin', 'file', 'view', 'read',
                            'download', 'include', 'load', 'page', 'document']

        # Get unique URLs to test with Arjun, prioritizing security-relevant ones
        priority_urls = []
        other_urls = []

        for ep in endpoints:
            if not ep.parameters:
                url = ep.url.split('?')[0]
                url_lower = url.lower()
                if any(kw in url_lower for kw in priority_keywords):
                    priority_urls.append(url)
                else:
                    other_urls.append(url)

        # Add base URL to other
        base = target_url.split('?')[0]
        if base not in priority_urls:
            other_urls.append(base)

        # Combine: priority first, then others, limit to 8
        urls_to_test = list(dict.fromkeys(priority_urls + other_urls))[:8]

        if urls_to_test:
            print(f"\n[*] Running Arjun for hidden parameter discovery on {len(urls_to_test)} URL(s)...")

            # Run Arjun in executor to not block
            loop = asyncio.get_event_loop()

            for url in urls_to_test:
                try:
                    arjun_params = await loop.run_in_executor(None, run_arjun, url, "GET", 30)

                    if arjun_params:
                        param_names = [p.name for p in arjun_params]
                        print(f"    ✓ Arjun found on {url}: {param_names}")

                        # Add/update endpoint with discovered params
                        existing = next((e for e in endpoints if e.url.split('?')[0] == url), None)
                        if existing:
                            # Add params to existing endpoint
                            for p in param_names:
                                if p not in existing.parameters:
                                    existing.parameters.append(p)
                        else:
                            # Create new endpoint
                            endpoints.append(DiscoveredEndpoint(
                                url=url,
                                method='GET',
                                source='arjun',
                                parameters=param_names,
                                has_query_params=True
                            ))
                except Exception as e:
                    print(f"    [!] Arjun error on {url}: {e}")

    return endpoints
