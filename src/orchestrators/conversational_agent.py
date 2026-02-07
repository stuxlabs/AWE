#!/usr/bin/env python3
"""
Conversational Security Agent - Like Claude Code for Web Security

An intelligent, iterative agent that:
- Explores vulnerabilities conversationally
- Uses tool results to inform next steps
- Can work interactively (asks you) or autonomously (decides itself)
- Builds context as it goes

Example Interactive Mode:
    Agent: Found login forms. Should I test default credentials?
    User: Yes
    Agent: [tests] Found admin:admin123! Now test SQLi?
    User: Yes, focus on authenticated pages
    Agent: [tests SQLi] Found time-based blind SQLi...

Example Auto Mode:
    Agent: Found login forms, testing default credentials...
    Agent: Success! admin:admin123 found
    Agent: Now I have auth access, testing SQLi in authenticated context...
    Agent: No SQLi found, moving to file parameters for LFI...
    Agent: Found LFI! Reading /etc/passwd...
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Callable, Tuple
from datetime import datetime
from enum import Enum

# Token tracking for cost calculation
try:
    from src.utils.token_tracker import TokenTracker, TrackedTimer, get_tracker
    TOKEN_TRACKING_AVAILABLE = True
except ImportError:
    TOKEN_TRACKING_AVAILABLE = False


class ToolType(Enum):
    """Types of security testing tools"""
    RECONNAISSANCE = "reconnaissance"
    AUTHENTICATION = "authentication"
    INJECTION = "injection"
    FILE_OPERATION = "file_operation"
    AUTHORIZATION = "authorization"
    INFORMATION = "information"


@dataclass
class ToolResult:
    """Result from executing a tool"""
    tool_name: str
    success: bool
    findings: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    execution_time: float = 0.0

    def summary(self) -> str:
        """Human-readable summary"""
        if not self.success or not self.findings:
            return f"{self.tool_name}: No findings"

        # Filter out non-vulnerability findings (recon, info)
        vuln_findings = [f for f in self.findings
                        if f.get('type') not in ['reconnaissance', 'info', None]]

        if not vuln_findings:
            return f"{self.tool_name}: Completed (info gathered)"

        count = len(vuln_findings)
        return f"{self.tool_name}: Found {count} finding(s)"


@dataclass
class AgentState:
    """Tracks agent's current knowledge and progress"""
    target_url: str

    # What we've discovered
    reconnaissance_done: bool = False
    recon_findings: Dict[str, Any] = field(default_factory=dict)

    # What we've tested
    tools_executed: List[str] = field(default_factory=list)
    tool_results: List[ToolResult] = field(default_factory=list)

    # What we've found
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    credentials_found: List[Dict[str, str]] = field(default_factory=list)
    authenticated: bool = False
    flags_found: List[str] = field(default_factory=list)

    # Exploit chain tracking
    privilege_escalated: bool = False  # Became admin via IDOR or other
    database_access: bool = False  # Can query database via SQLi

    # Conversation history
    conversation: List[Dict[str, str]] = field(default_factory=list)

    # Decision tracking
    next_suggested_actions: List[str] = field(default_factory=list)
    completed_objectives: List[str] = field(default_factory=list)

    def add_message(self, role: str, content: str):
        """Add to conversation history"""
        self.conversation.append({
            "role": role,
            "content": content,
            "timestamp": datetime.now().isoformat()
        })

    def add_result(self, result: ToolResult):
        """Record tool execution result"""
        self.tools_executed.append(result.tool_name)
        self.tool_results.append(result)

        # Update state based on results
        if result.success and result.findings:
            # Don't add reconnaissance findings to vulnerabilities (it's just info gathering)
            if result.tool_name != 'reconnaissance':
                # Only add findings that are actual vulnerabilities
                for finding in result.findings:
                    # Skip info-only findings (no type or generic findings)
                    if finding.get('type') and finding.get('type') not in ['info', 'reconnaissance']:
                        self.vulnerabilities.append(finding)

                    # Track special capabilities gained
                    vuln_type = finding.get('type', '')
                    if vuln_type == 'sqli':
                        self.database_access = True
                    elif vuln_type == 'idor' and 'privilege_escalation' in finding.get('description', '').lower():
                        self.privilege_escalated = True

            # Check for credentials
            for finding in result.findings:
                if 'credentials' in finding:
                    creds = finding['credentials']
                    self.credentials_found.append(creds)
                    self.authenticated = True
                # Handle Hydra-style credential findings
                elif finding.get('type') == 'credentials' and finding.get('username'):
                    creds = {
                        'username': finding.get('username'),
                        'password': finding.get('password', '')
                    }
                    self.credentials_found.append(creds)
                    self.authenticated = True

                # Check for flags in findings
                if 'flag' in finding:
                    flag = finding['flag']
                    if flag and flag not in self.flags_found:
                        self.flags_found.append(flag)

    def get_summary(self) -> str:
        """Get current state summary"""
        summary = []
        summary.append(f"Target: {self.target_url}")
        summary.append(f"\nProgress:")
        summary.append(f"  - Reconnaissance: {'✓' if self.reconnaissance_done else '✗'}")

        # Show what was discovered during recon
        if self.reconnaissance_done and self.recon_findings:
            discovered = []
            if self.recon_findings.get('login_forms'):
                discovered.append(f"{len(self.recon_findings['login_forms'])} login form(s)")
            if self.recon_findings.get('file_parameters'):
                discovered.append(f"{len(self.recon_findings['file_parameters'])} file parameter(s)")
            if self.recon_findings.get('xml_endpoints'):
                discovered.append(f"{len(self.recon_findings['xml_endpoints'])} XML endpoint(s)")

            if discovered:
                summary.append(f"    Discovered: {', '.join(discovered)}")

        summary.append(f"  - Tools run: {len(self.tools_executed)}")
        summary.append(f"  - Vulnerabilities found: {len(self.vulnerabilities)}")

        if self.authenticated:
            summary.append(f"  - Authenticated: ✓ ({len(self.credentials_found)} credential(s))")

        if self.privilege_escalated:
            summary.append(f"  - Privilege Escalated: ✓ (admin access)")

        if self.database_access:
            summary.append(f"  - Database Access: ✓ (via SQLi)")

        if self.flags_found:
            summary.append(f"  - 🚩 Flags Found: {len(self.flags_found)}")

        if self.vulnerabilities:
            summary.append(f"\nFindings:")
            for vuln in self.vulnerabilities[:5]:  # Show first 5
                vuln_type = vuln.get('type', 'unknown')
                severity = vuln.get('severity', 'unknown')
                summary.append(f"  - {vuln_type} ({severity})")

        return "\n".join(summary)

    def has_tested(self, tool_name: str) -> bool:
        """Check if tool was already executed"""
        return tool_name in self.tools_executed

    def get_context_for_llm(self) -> str:
        """Get state formatted for LLM decision-making"""
        context = []

        context.append(f"Target: {self.target_url}")
        context.append(f"\nReconnaissance: {'Done' if self.reconnaissance_done else 'Not done'}")

        if self.recon_findings:
            context.append("\nDiscovered:")
            if self.recon_findings.get('login_forms'):
                context.append(f"  - {len(self.recon_findings['login_forms'])} login form(s)")
            if self.recon_findings.get('file_parameters'):
                context.append(f"  - {len(self.recon_findings['file_parameters'])} file-related parameter(s)")
            if self.recon_findings.get('xml_endpoints'):
                context.append(f"  - {len(self.recon_findings['xml_endpoints'])} XML/SOAP endpoint(s)")

        context.append(f"\nTested so far: {', '.join(self.tools_executed) if self.tools_executed else 'None'}")

        if self.vulnerabilities:
            context.append(f"\nVulnerabilities found: {len(self.vulnerabilities)}")
            for vuln in self.vulnerabilities[:3]:
                context.append(f"  - {vuln.get('type', 'unknown')}: {vuln.get('description', 'N/A')}")

        if self.credentials_found:
            context.append(f"\nCredentials found: {len(self.credentials_found)}")
            context.append(f"  Authenticated: Yes")

        if self.privilege_escalated:
            context.append(f"  Privilege Escalated: Yes (admin access)")

        if self.database_access:
            context.append(f"  Database Access: Yes (via SQLi)")

        if self.flags_found:
            context.append(f"\n🚩 Flags captured: {len(self.flags_found)}")

        return "\n".join(context)


def detect_flags(text: str) -> List[str]:
    """Detect flags in text (FLAG{...}, XBEN{...}, etc.)"""
    import re
    if not text:
        return []

    # Convert to string if needed
    if not isinstance(text, str):
        text = str(text)

    # Flag patterns
    patterns = [
        r'FLAG\{[^}]+\}',
        r'flag\{[^}]+\}',
        r'XBEN\{[^}]+\}',
        r'xben\{[^}]+\}',
        r'CTF\{[^}]+\}',
        r'ctf\{[^}]+\}',
    ]

    flags = []
    for pattern in patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        flags.extend(matches)

    return list(set(flags))  # Remove duplicates


class Tool:
    """Base class for security testing tools"""

    def __init__(self,
                 name: str,
                 description: str,
                 tool_type: ToolType,
                 execute_func: Callable,
                 requires_auth: bool = False):
        self.name = name
        self.description = description
        self.tool_type = tool_type
        self.execute_func = execute_func
        self.requires_auth = requires_auth

    async def execute(self, target_url: str, **kwargs) -> ToolResult:
        """Execute the tool"""
        start_time = asyncio.get_event_loop().time()

        try:
            result = await self.execute_func(target_url, **kwargs)

            # Parse result based on type
            # Handle SQLiSessionResult objects (from SQLi agent)
            if hasattr(result, 'vulnerable'):
                success = result.vulnerable
                findings = []
                if success:
                    # Extract database info (check extracted_data first for actual database name)
                    database_info = result.database_type.value  # DBMS type (mysql, postgresql, etc.)
                    database_name = None

                    # Look for actual database name in extracted data
                    for payload_data in result.successful_payloads:
                        if 'extracted_data' in payload_data:
                            extracted = payload_data.get('extracted_data', {})
                            if 'current_database' in extracted:
                                database_name = extracted['current_database']
                                break

                    # Build description
                    db_desc = f"Database: {database_name}" if database_name else f"DBMS: {database_info}"

                    # Extract vulnerability details
                    vuln_finding = {
                        'type': 'sqli',
                        'severity': 'high',
                        'description': f"SQL injection ({', '.join([t.value for t in result.injection_types])}) - {db_desc}",
                        'database_type': database_info,
                        'database_name': database_name,
                        'injection_types': [t.value for t in result.injection_types],
                        'injection_points': [
                            {
                                'parameter': ip.parameter,
                                'location': ip.location,
                                'confidence': ip.confidence
                            }
                            for ip in result.injection_points if ip.confidence > 0
                        ],
                        'successful_payloads': result.successful_payloads[:3]  # First 3
                    }
                    findings.append(vuln_finding)

                    # Check for extracted credentials
                    for payload_data in result.successful_payloads:
                        if 'extracted_data' in payload_data:
                            extracted = payload_data.get('extracted_data', {})
                            if extracted and any(k.lower() in ['username', 'password', 'user', 'pass'] for k in extracted.keys()):
                                findings.append({
                                    'type': 'credentials',
                                    'credentials': extracted
                                })
                                break

            # Handle boolean results
            elif isinstance(result, bool):
                success = result
                findings = [{"found": result}] if result else []

            # Handle dict results
            elif isinstance(result, dict):
                success = result.get('success', result.get('vulnerable', False))
                findings = result.get('findings', [])

                # Handle LFI results with flag
                if result.get('flag'):
                    findings.append({
                        'type': 'flag',
                        'severity': 'critical',
                        'description': f'Flag found via LFI',
                        'flag': result['flag'],
                        'parameter': result.get('parameter', 'unknown'),
                        'found_by': self.name
                    })
                    success = True

                # Handle Hydra credential results
                if result.get('credentials'):
                    for cred in result['credentials']:
                        findings.append({
                            'type': 'credentials',
                            'severity': 'critical',
                            'description': f"Default credentials found: {cred.get('username')}:{cred.get('password')}",
                            'username': cred.get('username'),
                            'password': cred.get('password'),
                            'form_action': cred.get('form_action', '')
                        })
                    success = True

            # Handle list results
            elif isinstance(result, list):
                success = len(result) > 0
                findings = result

            # Unknown result type
            else:
                success = False
                findings = []

            # Scan all findings for flags (but avoid duplicates)
            result_text = json.dumps(result, default=str) if result else ""
            detected_flags = detect_flags(result_text)

            if detected_flags:
                # Get flags already in findings
                existing_flags = set()
                for f in findings:
                    if isinstance(f, dict) and f.get('flag'):
                        existing_flags.add(f.get('flag'))

                # Add only NEW flags to findings
                for flag in detected_flags:
                    if flag not in existing_flags:
                        findings.append({
                            'type': 'flag',
                            'severity': 'critical',
                            'description': f'Flag detected in response',
                            'flag': flag,
                            'found_by': self.name
                        })
                success = True  # Finding a flag is always a success

            execution_time = asyncio.get_event_loop().time() - start_time

            return ToolResult(
                tool_name=self.name,
                success=success,
                findings=findings,
                execution_time=execution_time
            )

        except Exception as e:
            execution_time = asyncio.get_event_loop().time() - start_time
            return ToolResult(
                tool_name=self.name,
                success=False,
                findings=[],
                metadata={"error": str(e)},
                execution_time=execution_time
            )


class ToolRegistry:
    """Registry of available security testing tools"""

    def __init__(self):
        self.tools: Dict[str, Tool] = {}
        self.logger = logging.getLogger(self.__class__.__name__)

    def register(self, tool: Tool):
        """Register a tool"""
        self.tools[tool.name] = tool
        self.logger.debug(f"Registered tool: {tool.name}")

    def get_tool(self, name: str) -> Optional[Tool]:
        """Get a tool by name"""
        return self.tools.get(name)

    def get_available_tools(self, is_authenticated: bool = False) -> List[Tool]:
        """Get all available tools based on authentication state"""
        if is_authenticated:
            # User is authenticated - return ALL tools (including auth-required ones like IDOR)
            return list(self.tools.values())
        else:
            # User is NOT authenticated - only return tools that don't require auth
            return [t for t in self.tools.values() if not t.requires_auth]

    def get_tools_by_type(self, tool_type: ToolType) -> List[Tool]:
        """Get tools by type"""
        return [t for t in self.tools.values() if t.tool_type == tool_type]

    def get_tool_descriptions(self) -> str:
        """Get formatted list of all tools"""
        descriptions = []
        for tool in self.tools.values():
            auth_req = " [requires auth]" if tool.requires_auth else ""
            descriptions.append(f"- {tool.name}: {tool.description}{auth_req}")
        return "\n".join(descriptions)


class ConversationalAgent:
    """
    Intelligent, conversational security testing agent

    Works in two modes:
    1. Interactive: Asks user what to do next
    2. Auto: Decides autonomously using LLM
    """

    def __init__(self,
                 mode: str = "interactive",  # "interactive" or "auto"
                 max_iterations: int = 20):
        """
        Initialize conversational agent

        Args:
            mode: "interactive" (asks user) or "auto" (autonomous)
            max_iterations: Max tool executions to prevent infinite loops
        """
        self.mode = mode
        self.max_iterations = max_iterations
        self.logger = logging.getLogger(self.__class__.__name__)

        # Tool registry
        self.registry = ToolRegistry()
        self._register_tools()

        # State
        self.state: Optional[AgentState] = None

        # LLM client (for auto mode)
        self.llm_client = None
        if mode == "auto":
            self._init_llm_client()

    def _init_llm_client(self):
        """Initialize LLM client for autonomous decision-making"""
        try:
            from src.xss_agent.llm_client import get_llm_client
            self.llm_client = get_llm_client()
            self.logger.info("LLM client initialized for autonomous mode")
        except Exception as e:
            self.logger.warning(f"Failed to initialize LLM client: {e}")
            self.logger.warning("Falling back to interactive mode")
            self.mode = "interactive"

    def _register_tools(self):
        """Register all available security testing tools"""

        # Import agents
        try:
            from test_lfi import test_lfi
            self.registry.register(Tool(
                name="lfi",
                description="Test for Local File Inclusion vulnerabilities",
                tool_type=ToolType.FILE_OPERATION,
                execute_func=test_lfi
            ))
        except ImportError:
            pass

        try:
            from test_xxe import test_xxe
            self.registry.register(Tool(
                name="xxe",
                description="Test for XML External Entity injection",
                tool_type=ToolType.INJECTION,
                execute_func=test_xxe
            ))
        except ImportError:
            pass

        try:
            from src.sqli_agent.sqli_orchestrator import test_sqli
            self.registry.register(Tool(
                name="sqli",
                description="Test for SQL injection vulnerabilities",
                tool_type=ToolType.INJECTION,
                execute_func=test_sqli
            ))
        except ImportError:
            pass

        try:
            from src.credential_agent.hydra_tester import test_default_credentials_hydra
            self.registry.register(Tool(
                name="default_credentials",
                description="Test common default credentials on login forms (fast, uses Hydra)",
                tool_type=ToolType.AUTHENTICATION,
                execute_func=test_default_credentials_hydra
            ))
        except ImportError:
            pass

        try:
            from test_ssti import test_ssti
            self.registry.register(Tool(
                name="ssti",
                description="Test for Server-Side Template Injection",
                tool_type=ToolType.INJECTION,
                execute_func=test_ssti
            ))
        except ImportError:
            pass

        try:
            from test_idor import test_idor
            self.registry.register(Tool(
                name="idor",
                description="Test for Insecure Direct Object References",
                tool_type=ToolType.AUTHORIZATION,
                execute_func=test_idor,
                requires_auth=True
            ))
        except ImportError:
            pass

        try:
            from test_info_disclosure import test_info_disclosure
            self.registry.register(Tool(
                name="info_disclosure",
                description="Check for exposed secrets, API keys, sensitive data",
                tool_type=ToolType.INFORMATION,
                execute_func=test_info_disclosure
            ))
        except ImportError:
            pass

        try:
            from test_ssrf import test_ssrf
            self.registry.register(Tool(
                name="ssrf",
                description="Test for Server-Side Request Forgery (internal services, cloud metadata, localhost bypass)",
                tool_type=ToolType.INJECTION,
                execute_func=test_ssrf
            ))
        except ImportError:
            pass

        # XSS tool - Context-aware XSS testing with LLM payload generation
        try:
            import re
            from urllib.parse import urlparse, urlencode, urljoin

            async def test_xss(target_url, recon_endpoints=None):
                """Test for XSS using context-aware LLM-based detection"""

                print("="*70)
                print("XSS (CROSS-SITE SCRIPTING) TEST - Context-Aware")
                print("="*70)
                print(f"Target: {target_url}")
                print()

                findings = []

                # Use recon endpoints if available
                endpoints_to_test = []
                if recon_endpoints:
                    print(f"[1] Using {len(recon_endpoints)} endpoint(s) from reconnaissance...")
                    for ep in recon_endpoints:
                        url = ep.get('url', target_url)
                        if not url.startswith('http'):
                            url = urljoin(target_url, url)
                        params = ep.get('parameters', [])
                        method = ep.get('method', 'GET')  # Include method info
                        if params:
                            endpoints_to_test.append({'url': url, 'params': params, 'type': ep.get('type', 'unknown'), 'method': method})
                else:
                    # Fallback: discover endpoints
                    print("[1] No recon data, discovering endpoints...")
                    from playwright.async_api import async_playwright
                    from src.utils.endpoint_discovery import discover_all_endpoints

                    async with async_playwright() as p:
                        browser = await p.chromium.launch(headless=True)
                        page = await browser.new_page()
                        try:
                            await page.goto(target_url, wait_until="load", timeout=30000)
                            discovered = await discover_all_endpoints(page, target_url, max_depth=2, max_endpoints=20)
                            for ep in discovered:
                                if ep.parameters:
                                    endpoints_to_test.append({'url': ep.url, 'params': ep.parameters, 'type': ep.source, 'method': getattr(ep, 'method', 'GET')})
                        finally:
                            await browser.close()

                if not endpoints_to_test:
                    print("    ✗ No endpoints with parameters found")
                    return {'success': False, 'findings': []}

                print(f"    ✓ Found {len(endpoints_to_test)} endpoint(s) to test")

                # Try context-aware tester first
                try:
                    from src.xss_agent.llm_client import get_llm_client
                    from src.xss_agent.agents.context_aware_xss_tester import ContextAwareXSSTester

                    print(f"\n[2] Initializing context-aware XSS tester...")
                    llm_client = get_llm_client()
                    tester = ContextAwareXSSTester(llm_client)
                    print(f"    ✓ LLM client and tester initialized")

                    print(f"\n[3] Running context-aware XSS analysis...")
                    print("    (Reflection analysis → Filter detection → LLM payload generation → Browser verification)")

                    for idx, ep in enumerate(endpoints_to_test, 1):
                        url = ep['url']
                        params = ep['params']
                        ep_type = ep['type']
                        method = ep.get('method', 'GET')  # Get method, default to GET

                        print(f"\n    [{idx}/{len(endpoints_to_test)}] Testing: {url}")
                        print(f"        Type: {ep_type}")
                        print(f"        Method: {method}")
                        print(f"        Parameters: {', '.join(params)}")

                        # Build parameter dict with dummy values
                        param_dict = {p: "test" for p in params}

                        try:
                            vulns = await tester.test_reflected_xss(url, param_dict, method)

                            for vuln in vulns:
                                flag = getattr(vuln, 'flag', None)
                                finding = {
                                    'type': 'xss',
                                    'severity': 'high',
                                    'description': f'Context-aware XSS in "{vuln.parameter}" ({vuln.context})',
                                    'url': vuln.url,
                                    'parameter': vuln.parameter,
                                    'payload': vuln.payload,
                                    'technique': vuln.technique,
                                    'confidence': vuln.confidence,
                                    'reasoning': vuln.reasoning,
                                    'flag': flag
                                }
                                findings.append(finding)
                                print(f"        🎯 FOUND: {vuln.technique} XSS in '{vuln.parameter}'")
                                print(f"        📝 Payload: {vuln.payload}")
                                if flag:
                                    print(f"        🚩 FLAG: {flag}")
                                    # Add to state flags
                                    if hasattr(self, 'state') and hasattr(self.state, 'flags_found'):
                                        if flag not in self.state.flags_found:
                                            self.state.flags_found.append(flag)

                        except Exception as e:
                            print(f"        ⚠️  Context-aware test error: {e}")
                            # Fallback to simple reflection test
                            await _simple_xss_test(url, params, findings)

                except ImportError as e:
                    print(f"    ⚠️  Context-aware tester not available (import error): {e}")
                    print("    Falling back to simple reflection testing...")

                    # Fallback to simple testing
                    for idx, ep in enumerate(endpoints_to_test, 1):
                        await _simple_xss_test(ep['url'], ep['params'], findings)
                except Exception as e:
                    import traceback
                    print(f"    ⚠️  Context-aware tester initialization failed: {e}")
                    print(f"    Traceback: {traceback.format_exc()}")
                    print("    Falling back to simple reflection testing...")

                    # Fallback to simple testing
                    for idx, ep in enumerate(endpoints_to_test, 1):
                        await _simple_xss_test(ep['url'], ep['params'], findings)

                # Report results
                if findings:
                    print(f"\n{'='*70}")
                    print(f"XSS VULNERABILITIES FOUND: {len(findings)}")
                    print(f"{'='*70}")
                    return {'success': True, 'findings': findings}
                else:
                    print(f"\n{'='*70}")
                    print("No XSS vulnerabilities detected")
                    print(f"{'='*70}")
                    return {'success': False, 'findings': []}

            async def _simple_xss_test(url, params, findings):
                """Simple reflection-based XSS test as fallback"""
                import aiohttp

                xss_payloads = [
                    '<script>alert(1)</script>',
                    '<img src=x onerror=alert(1)>',
                    '<svg onload=alert(1)>',
                    '"><script>alert(1)</script>',
                    "'-alert(1)-'",
                    '<a href="javascript:alert(1)">click</a>',
                ]

                for param in params:
                    for payload in xss_payloads:
                        parsed = urlparse(url)
                        test_params = {param: payload}
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"

                        try:
                            async with aiohttp.ClientSession() as session:
                                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                                    text = await resp.text()

                                    if payload in text:
                                        finding = {
                                            'type': 'xss',
                                            'severity': 'high',
                                            'description': f'Reflected XSS in "{param}"',
                                            'url': test_url,
                                            'parameter': param,
                                            'payload': payload
                                        }

                                        flag_match = re.search(r'FLAG\{[^}]+\}|flag\{[^}]+\}|CTF\{[^}]+\}', text, re.IGNORECASE)
                                        if flag_match:
                                            finding['flag'] = flag_match.group(0)
                                            finding['type'] = 'flag'
                                            finding['severity'] = 'critical'

                                        findings.append(finding)
                                        break
                        except:
                            continue

            self.registry.register(Tool(
                name="xss",
                description="Test for XSS with context-aware LLM payload generation",
                tool_type=ToolType.INJECTION,
                execute_func=test_xss
            ))
        except ImportError as e:
            self.logger.warning(f"XSS tool not available: {e}")

        # Reconnaissance tool - Comprehensive Playwright-based discovery
        async def run_recon(target_url):
            """Comprehensive reconnaissance for maximum attack surface discovery"""
            from playwright.async_api import async_playwright
            from src.utils.endpoint_discovery import discover_all_endpoints
            from urllib.parse import urljoin, urlparse, parse_qs
            import re
            import aiohttp

            print("\n[*] Running comprehensive reconnaissance...")
            print("    Features: Form detection, JS analysis, endpoint crawling, LLM page analysis")

            login_forms = []
            other_forms = []
            file_params = set()
            xml_endpoints = []
            all_parameters = set()
            discovered_endpoints = []
            api_endpoints = []
            js_files = []
            technologies = set()
            page_summaries = {}  # LLM summaries of pages for context

            # Patterns for vulnerability detection
            file_param_patterns = [
                'file', 'path', 'page', 'document', 'doc', 'pdf', 'include',
                'template', 'view', 'content', 'load', 'read', 'fetch',
                'src', 'source', 'url', 'uri', 'location', 'dir', 'folder',
                'download', 'img', 'image', 'attachment', 'resource'
            ]

            xml_indicators = ['soap', 'xml', 'wsdl', 'api/xml', 'xmlrpc', 'webservice', 'rss', 'feed', 'atom']
            api_indicators = ['/api/', '/v1/', '/v2/', '/rest/', '/graphql', '/query', '/search']

            def is_login_form(params, url=''):
                """Detect if parameters suggest a login form"""
                param_names = [p.lower() for p in params]
                url_lower = url.lower()

                # Check URL patterns
                if any(x in url_lower for x in ['/login', '/signin', '/auth', '/session', '/token']):
                    return True

                # Check parameter patterns - need both username-like and password-like
                has_user = any(any(lp in p for lp in ['user', 'email', 'login', 'name', 'uname']) for p in param_names)
                has_pass = any(any(lp in p for lp in ['pass', 'pwd', 'password', 'secret']) for p in param_names)

                return has_user and has_pass

            def extract_js_endpoints(js_content, base_url):
                """Extract API endpoints from JavaScript"""
                endpoints = []
                patterns = [
                    r'fetch\([\'"]([^\'"]+)[\'"]',
                    r'axios\.[a-z]+\([\'"]([^\'"]+)[\'"]',
                    r'\.ajax\(\{[^}]*url:\s*[\'"]([^\'"]+)[\'"]',
                    r'XMLHttpRequest.*open\([\'"][A-Z]+[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]',
                    r'[\'"](/api/[^\'"]+)[\'"]',
                    r'[\'"](/v[0-9]/[^\'"]+)[\'"]',
                    r'endpoint[\'"]?\s*[:=]\s*[\'"]([^\'"]+)[\'"]',
                ]
                for pattern in patterns:
                    matches = re.findall(pattern, js_content, re.IGNORECASE)
                    for match in matches:
                        if match.startswith('/') or match.startswith('http'):
                            full_url = urljoin(base_url, match)
                            endpoints.append(full_url)
                return list(set(endpoints))

            async def get_page_summary_for_llm(page_obj, url):
                """Generate LLM-friendly summary by extracting visible text and key elements"""
                summary_parts = []

                try:
                    # Get page title
                    title = await page_obj.title()
                    if title:
                        summary_parts.append(f"Page: {title.strip()}")

                    # Extract VISIBLE text only (what a user sees, after JS rendering)
                    visible_text = await page_obj.inner_text('body')
                    visible_text = ' '.join(visible_text.split())[:1500]  # Clean whitespace, limit length

                    if visible_text:
                        summary_parts.append(f"Content: {visible_text[:500]}")

                    # Count interactive elements
                    form_count = await page_obj.locator('form').count()
                    if form_count:
                        summary_parts.append(f"Forms: {form_count}")

                    # Get input field names (visible to automation)
                    inputs = await page_obj.locator('input[name], textarea[name], select[name]').all()
                    input_names = []
                    for inp in inputs[:15]:
                        name = await inp.get_attribute('name')
                        inp_type = await inp.get_attribute('type') or 'text'
                        if name:
                            input_names.append(f"{name}({inp_type})")
                    if input_names:
                        summary_parts.append(f"Inputs: {', '.join(input_names)}")

                    # Get visible links text (navigation options)
                    links = await page_obj.locator('a').all()
                    link_texts = []
                    for link in links[:10]:
                        text = await link.inner_text()
                        href = await link.get_attribute('href') or ''
                        if text.strip() and len(text.strip()) < 50:
                            link_texts.append(text.strip())
                    if link_texts:
                        summary_parts.append(f"Navigation: {', '.join(set(link_texts))}")

                    # Check for file upload capability
                    file_inputs = await page_obj.locator('input[type="file"]').count()
                    if file_inputs:
                        summary_parts.append(f"File upload: {file_inputs} field(s)")

                    # Check for buttons/actions
                    buttons = await page_obj.locator('button, input[type="submit"]').all()
                    button_texts = []
                    for btn in buttons[:5]:
                        text = await btn.inner_text() or await btn.get_attribute('value') or ''
                        if text.strip():
                            button_texts.append(text.strip())
                    if button_texts:
                        summary_parts.append(f"Actions: {', '.join(button_texts)}")

                except Exception as e:
                    summary_parts.append(f"(Error extracting: {str(e)[:50]})")

                return " | ".join(summary_parts) if summary_parts else "Basic page"

            try:
                async with async_playwright() as p:
                    browser = await p.chromium.launch(headless=True)
                    page = await browser.new_page()

                    # Capture network requests for API discovery
                    captured_requests = []
                    async def capture_request(request):
                        if request.resource_type in ['xhr', 'fetch']:
                            captured_requests.append({
                                'url': request.url,
                                'method': request.method,
                                'post_data': request.post_data
                            })
                    page.on('request', capture_request)

                    # ===== PHASE 1: Initial page analysis =====
                    print("\n    [1/6] Loading and analyzing main page...")
                    await page.goto(target_url, wait_until="networkidle", timeout=30000)
                    html_content = await page.content()

                    # Get LLM-friendly summary of main page (uses visible text extraction)
                    main_summary = await get_page_summary_for_llm(page, target_url)
                    page_summaries[target_url] = main_summary
                    print(f"        📄 Main page: {main_summary[:150]}...")

                    # ===== PHASE 2: Form detection on main page =====
                    print("    [2/6] Detecting forms on main page...")
                    forms = await page.query_selector_all('form')
                    for form in forms:
                        action_attr = await form.get_attribute('action') or ''
                        action = urljoin(target_url, action_attr) if action_attr else target_url
                        method = (await form.get_attribute('method') or 'POST').upper()

                        inputs = await form.query_selector_all('input, select, textarea')
                        input_data = []
                        param_names = []
                        for inp in inputs:
                            name = await inp.get_attribute('name')
                            inp_type = await inp.get_attribute('type') or 'text'
                            if name:
                                input_data.append({'name': name, 'type': inp_type})
                                param_names.append(name)
                                all_parameters.add(name)

                                # Check for file parameters
                                if any(fp in name.lower() for fp in file_param_patterns):
                                    file_params.add(name)

                        if input_data:
                            form_data = {'action': action, 'method': method, 'inputs': input_data}

                            # Classify form
                            if is_login_form(param_names, action):
                                login_forms.append(form_data)
                                print(f"        ✓ Login form: {action} (fields: {', '.join(param_names)})")
                            else:
                                other_forms.append(form_data)
                                print(f"        ✓ Form: {action} ({len(input_data)} fields: {', '.join(param_names)})")

                            # Add as endpoint
                            discovered_endpoints.append({
                                'url': action,
                                'method': method,
                                'parameters': param_names,
                                'type': 'form'
                            })

                    # ===== PHASE 3: JavaScript analysis =====
                    print("    [3/6] Analyzing JavaScript...")
                    scripts = await page.query_selector_all('script')
                    for script in scripts:
                        src = await script.get_attribute('src')
                        if src:
                            js_url = urljoin(target_url, src)
                            js_files.append(js_url)

                        # Inline script content
                        content = await script.inner_text()
                        if content:
                            js_endpoints = extract_js_endpoints(content, target_url)
                            for js_ep in js_endpoints:
                                if not any(e['url'] == js_ep for e in discovered_endpoints):
                                    api_endpoints.append(js_ep)
                                    discovered_endpoints.append({
                                        'url': js_ep,
                                        'method': 'GET',
                                        'parameters': [],
                                        'type': 'js'
                                    })
                                    print(f"        ✓ JS endpoint: {js_ep}")

                    # ===== PHASE 4: Crawl for more endpoints =====
                    print("    [4/6] Crawling for additional endpoints...")
                    # Re-navigate to target for fresh crawl
                    await page.goto(target_url, wait_until="load", timeout=30000)

                    endpoints = await discover_all_endpoints(
                        page, target_url,
                        max_depth=2,
                        max_endpoints=30,
                        check_common_paths=True
                    )

                    for ep in endpoints:
                        # Skip if already found
                        if any(e['url'] == ep.url and e['method'] == ep.method for e in discovered_endpoints):
                            continue

                        ep_data = {
                            'url': ep.url,
                            'method': ep.method,
                            'parameters': ep.parameters,
                            'type': ep.source
                        }
                        discovered_endpoints.append(ep_data)
                        all_parameters.update(ep.parameters)

                        # Classify endpoint
                        if is_login_form(ep.parameters, ep.url):
                            if not any(lf['action'] == ep.url for lf in login_forms):
                                form_data = {'action': ep.url, 'method': ep.method, 'inputs': [{'name': p, 'type': 'text'} for p in ep.parameters]}
                                login_forms.append(form_data)
                                print(f"        ✓ Login endpoint: {ep.url}")

                        # Check for file parameters
                        for param in ep.parameters:
                            param_lower = param.lower()
                            if any(fp in param_lower for fp in file_param_patterns):
                                file_params.add(param)

                        # Check for XML/API endpoints
                        url_lower = ep.url.lower()
                        if any(ind in url_lower for ind in xml_indicators):
                            xml_endpoints.append(ep.url)
                        if any(ind in url_lower for ind in api_indicators):
                            api_endpoints.append(ep.url)

                    # ===== PHASE 5: Analyze discovered pages =====
                    print("    [5/6] Analyzing discovered pages...")
                    pages_to_analyze = [ep['url'] for ep in discovered_endpoints if ep['type'] != 'form'][:5]
                    for page_url in pages_to_analyze:
                        if page_url in page_summaries:
                            continue
                        try:
                            await page.goto(page_url, wait_until="load", timeout=10000)
                            summary = await get_page_summary_for_llm(page, page_url)
                            page_summaries[page_url] = summary
                            print(f"        📄 {page_url}: {summary[:100]}...")

                            # Also check for forms on this page
                            page_forms = await page.query_selector_all('form')
                            for form in page_forms:
                                action_attr = await form.get_attribute('action') or ''
                                action = urljoin(page_url, action_attr) if action_attr else page_url
                                if any(lf['action'] == action for lf in login_forms) or any(f['action'] == action for f in other_forms):
                                    continue

                                method = (await form.get_attribute('method') or 'POST').upper()
                                inputs = await form.query_selector_all('input, select, textarea')
                                input_data = []
                                param_names = []
                                for inp in inputs:
                                    name = await inp.get_attribute('name')
                                    if name:
                                        input_data.append({'name': name, 'type': await inp.get_attribute('type') or 'text'})
                                        param_names.append(name)
                                        all_parameters.add(name)

                                if input_data:
                                    form_data = {'action': action, 'method': method, 'inputs': input_data}
                                    if is_login_form(param_names, action):
                                        login_forms.append(form_data)
                                        print(f"        ✓ Login form found: {action}")
                                    else:
                                        other_forms.append(form_data)
                                        print(f"        ✓ Form found: {action}")

                                    # FIX: Also add to discovered_endpoints for tool chaining (XSS, SQLi, etc.)
                                    if not any(e['url'] == action and e['method'] == method for e in discovered_endpoints):
                                        discovered_endpoints.append({
                                            'url': action,
                                            'method': method,
                                            'parameters': param_names,
                                            'type': 'form'
                                        })
                                        print(f"          → Added to endpoints: {', '.join(param_names)}")
                        except:
                            pass

                    # ===== PHASE 6: Technology detection & network analysis =====
                    print("    [6/6] Technology detection & network analysis...")

                    # Check captured XHR/Fetch requests
                    for req in captured_requests:
                        if not any(e['url'] == req['url'] for e in discovered_endpoints):
                            params = []
                            if req['post_data']:
                                try:
                                    import json
                                    data = json.loads(req['post_data'])
                                    params = list(data.keys())
                                except:
                                    params = [p.split('=')[0] for p in req['post_data'].split('&') if '=' in p]

                            discovered_endpoints.append({
                                'url': req['url'],
                                'method': req['method'],
                                'parameters': params,
                                'type': 'xhr'
                            })
                            all_parameters.update(params)
                            print(f"        ✓ XHR: {req['method']} {req['url']}")

                    # Technology detection
                    tech_patterns = {
                        'Flask': ['flask', 'werkzeug', 'jinja'],
                        'Django': ['django', 'csrftoken'],
                        'Express': ['express', 'x-powered-by: express'],
                        'PHP': ['.php', 'phpsessid'],
                        'ASP.NET': ['.aspx', 'asp.net', '__viewstate'],
                        'Java': ['.jsp', 'jsessionid', 'java'],
                        'Ruby': ['rails', 'ruby', '_session_id'],
                    }
                    html_lower = html_content.lower()
                    for tech, patterns in tech_patterns.items():
                        if any(p in html_lower for p in patterns):
                            technologies.add(tech)
                            print(f"        ✓ Technology: {tech}")

                    await browser.close()

            except Exception as e:
                print(f"    [!] Recon error: {e}")
                import traceback
                traceback.print_exc()

            # Create findings object
            class ReconFindings:
                def __init__(self):
                    self.target_url = target_url
                    self.login_forms = login_forms
                    self.other_forms = other_forms
                    self.file_related_params = file_params
                    self.xml_endpoints = xml_endpoints
                    self.get_parameters = all_parameters
                    self.post_parameters = set()
                    self.discovered_endpoints = discovered_endpoints
                    self.api_endpoints = api_endpoints
                    self.js_files = js_files
                    self.technologies = technologies
                    self.page_summaries = page_summaries

                def get_summary(self):
                    lines = [
                        f"Target: {target_url}",
                        f"Endpoints discovered: {len(discovered_endpoints)}",
                        f"Parameters found: {len(all_parameters)}",
                        f"Login forms: {len(login_forms)}",
                        f"Other forms: {len(other_forms)}",
                        f"File-related parameters: {len(file_params)}",
                        f"XML/SOAP endpoints: {len(xml_endpoints)}",
                        f"API endpoints: {len(api_endpoints)}",
                        f"JS files: {len(js_files)}",
                        f"Pages analyzed: {len(page_summaries)}",
                    ]
                    if technologies:
                        lines.append(f"Technologies: {', '.join(technologies)}")
                    return "\n".join(lines)

                def get_llm_context(self):
                    """Get detailed context for LLM decision making"""
                    context = [f"=== Security Reconnaissance Report ==="]
                    context.append(f"Target: {target_url}")

                    if page_summaries:
                        context.append(f"\n--- Page Analysis ---")
                        for url, summary in list(page_summaries.items())[:5]:
                            context.append(f"• {url}: {summary}")

                    if login_forms:
                        context.append(f"\n--- Login Forms ({len(login_forms)}) ---")
                        for lf in login_forms:
                            fields = [i['name'] for i in lf['inputs']]
                            context.append(f"• {lf['action']} [{lf['method']}] - Fields: {', '.join(fields)}")

                    if other_forms:
                        context.append(f"\n--- Other Forms ({len(other_forms)}) ---")
                        for f in other_forms:
                            fields = [i['name'] for i in f['inputs']]
                            context.append(f"• {f['action']} [{f['method']}] - Fields: {', '.join(fields)}")

                    if file_params:
                        context.append(f"\n--- File-Related Parameters (LFI candidates) ---")
                        context.append(f"• {', '.join(file_params)}")

                    if xml_endpoints:
                        context.append(f"\n--- XML/SOAP Endpoints (XXE candidates) ---")
                        for ep in xml_endpoints:
                            context.append(f"• {ep}")

                    if api_endpoints:
                        context.append(f"\n--- API Endpoints ---")
                        for ep in api_endpoints[:5]:
                            context.append(f"• {ep}")

                    if technologies:
                        context.append(f"\n--- Technologies ---")
                        context.append(f"• {', '.join(technologies)}")

                    return "\n".join(context)

            findings = ReconFindings()

            print(f"\n[✓] Reconnaissance complete")
            print(f"    {findings.get_summary()}")

            # Print LLM context for debugging
            print(f"\n    --- LLM Context Preview ---")
            llm_context = findings.get_llm_context()
            for line in llm_context.split('\n')[:15]:
                print(f"    {line}")
            if len(llm_context.split('\n')) > 15:
                print(f"    ... ({len(llm_context.split(chr(10))) - 15} more lines)")

            return {
                'success': True,
                'findings': [{
                    'type': 'reconnaissance',
                    'summary': findings.get_summary(),
                    'recon_data': findings
                }]
            }

        self.registry.register(Tool(
            name="reconnaissance",
            description="Discover attack surface (forms, parameters, endpoints)",
            tool_type=ToolType.RECONNAISSANCE,
            execute_func=run_recon
        ))

        self.logger.info(f"Registered {len(self.registry.tools)} tools")

    async def run(self, target_url: str, challenge_description: str = None):
        """
        Main conversational loop

        Args:
            target_url: Target to test
            challenge_description: Optional challenge description for guided testing
        """
        # Initialize state
        self.state = AgentState(target_url=target_url)

        # Ask for challenge description if not provided
        if challenge_description is None:
            print("\n" + "="*70)
            print("📋 CHALLENGE DESCRIPTION (optional)")
            print("="*70)
            print("Paste the challenge description below for guided testing.")
            print("This helps the agent focus on the right vulnerability type.")
            print("Press Enter twice to skip, or paste and press Enter twice to submit.")
            print("-"*70)

            lines = []
            while True:
                line = input()
                if line == "":
                    if lines:
                        break  # Empty line after content = done
                    else:
                        break  # Just Enter = skip
                lines.append(line)

            challenge_description = "\n".join(lines).strip()

        # Store challenge description
        self.challenge_description = challenge_description if challenge_description else ""

        if self.challenge_description:
            print(f"\n✓ Challenge context loaded ({len(self.challenge_description)} chars)")

        # Welcome message
        self._print_welcome()

        # Start conversation
        iteration = 0

        while iteration < self.max_iterations:
            iteration += 1

            # Get next action
            if self.mode == "auto":
                action = await self._decide_next_action_auto()
            else:
                action = await self._decide_next_action_interactive()

            # Check if done
            if action.get('done', False):
                break

            # Execute tool
            tool_name = action.get('tool')
            if tool_name:
                await self._execute_tool_and_update(tool_name, action.get('params', {}))

            # Check stopping condition
            if self._should_stop():
                break

        # Final report
        self._print_final_report()

    def _print_welcome(self):
        """Print welcome message"""
        print("\n" + "="*70)
        print("🤖 CONVERSATIONAL SECURITY AGENT")
        print("="*70)
        print(f"Target: {self.state.target_url}")
        print(f"Mode: {self.mode.capitalize()}")
        print(f"Available tools: {len(self.registry.tools)}")
        print("="*70 + "\n")

        if self.mode == "interactive":
            print("💬 I'll ask you what to do at each step")
        else:
            print("🤖 I'll decide autonomously what to test")

        print()

    async def _decide_next_action_interactive(self) -> Dict[str, Any]:
        """Interactive mode: Ask user what to do next"""

        # Show current state
        print("\n" + "-"*70)
        print("📊 Current State:")
        print("-"*70)
        print(self.state.get_summary())
        print()

        # First action: always start with recon
        if not self.state.reconnaissance_done:
            print("🔍 I need to do reconnaissance first to discover the attack surface.")
            response = input("Should I run reconnaissance? [Y/n]: ").strip().lower()

            if response in ['', 'y', 'yes']:
                return {'tool': 'reconnaissance', 'params': {}}
            else:
                return {'done': True}

        # Show options
        print("🤔 What should I do next?\n")

        # Get all available tools (including previously tested ones)
        # User can re-run any tool to get fresh results
        available_tools = self.registry.get_available_tools(self.state.authenticated)

        # Show suggestions based on recon
        suggestions = self._get_suggestions()
        if suggestions:
            print("💡 My suggestions based on what I found:")
            for i, suggestion in enumerate(suggestions, 1):
                print(f"   {i}. {suggestion}")
            print()

        # Show all options
        print("📋 Available tools:")
        for i, tool in enumerate(available_tools, 1):
            tested = "✓" if self.state.has_tested(tool.name) else " "
            print(f"   [{tested}] {i}. {tool.name}: {tool.description}")

        print(f"\n   {len(available_tools) + 1}. Stop testing")
        print()

        # Get user choice
        while True:
            try:
                choice = input("Choose an option (number): ").strip()
                choice_num = int(choice)

                if choice_num == len(available_tools) + 1:
                    return {'done': True}

                if 1 <= choice_num <= len(available_tools):
                    selected_tool = available_tools[choice_num - 1]
                    return {'tool': selected_tool.name, 'params': {}}
                else:
                    print("Invalid choice, try again")
            except (ValueError, IndexError):
                print("Invalid input, enter a number")

    async def _decide_next_action_auto(self) -> Dict[str, Any]:
        """Auto mode: Use LLM to decide next action"""

        # First action: always recon
        if not self.state.reconnaissance_done:
            print("🔍 Running reconnaissance to discover attack surface...")
            return {'tool': 'reconnaissance', 'params': {}}

        # Use LLM to decide
        print("\n🤔 Analyzing findings and deciding next step...")

        # Get context
        context = self.state.get_context_for_llm()

        # Get available tools - exclude already tested ones
        all_tools = self.registry.get_available_tools(self.state.authenticated)
        available_tools = [t for t in all_tools if not self.state.has_tested(t.name)]

        # EXPLOIT CHAIN LOGIC: After gaining auth, re-enable auth-required tools!
        # This is critical - IDOR needs to be tested after we get credentials
        if self.state.authenticated:
            auth_tools = ['idor']  # Tools that should be re-tested after auth
            for tool_name in auth_tools:
                tool = self.registry.get_tool(tool_name)
                if tool and tool not in available_tools and not self.state.has_tested(tool_name):
                    available_tools.append(tool)
                    print(f"   🔓 Unlocked: {tool_name} (now authenticated)")

        if not available_tools:
            print("✓ All tools tested, analysis complete")
            return {'done': True}

        # Build LLM prompt
        tool_list = "\n".join([f"- {t.name}: {t.description}" for t in available_tools])

        # Build detailed recon context
        recon = self.state.recon_findings

        # Use rich LLM context if available (from enhanced reconnaissance)
        if recon.get('llm_context'):
            recon_summary = recon['llm_context']
        else:
            # Fallback to basic context building
            recon_details = []

            if recon.get('login_forms'):
                recon_details.append(f"• {len(recon['login_forms'])} login form(s) detected - authentication possible")
            if recon.get('file_parameters'):
                params = list(recon['file_parameters'])[:5]
                recon_details.append(f"• {len(recon['file_parameters'])} file-related parameter(s): {', '.join(params)} - LFI highly likely")
            if recon.get('xml_endpoints'):
                recon_details.append(f"• {len(recon['xml_endpoints'])} XML/SOAP endpoint(s) - XXE highly likely")
            if recon.get('all_endpoints'):
                param_count = sum(len(ep.get('parameters', [])) for ep in recon['all_endpoints'])
                recon_details.append(f"• {len(recon['all_endpoints'])} injectable endpoint(s) with {param_count} parameter(s)")
            if recon.get('js_files'):
                recon_details.append(f"• {len(recon['js_files'])} JavaScript file(s) analyzed")
            if recon.get('technologies'):
                techs = list(recon['technologies'])[:5]
                recon_details.append(f"• Technologies: {', '.join(techs)}")
            if recon.get('parameters_count', 0) > 0:
                recon_details.append(f"• {recon['parameters_count']} unique parameter(s) discovered")

            recon_summary = "\n".join(recon_details) if recon_details else "• Basic web application, minimal attack surface detected"

        # Build challenge context section if available
        challenge_section = ""
        if hasattr(self, 'challenge_description') and self.challenge_description:
            challenge_section = f"""
=== CHALLENGE DESCRIPTION ===
{self.challenge_description}

⚠️ IMPORTANT: The challenge description tells you EXACTLY what to look for!
Focus your testing on the vulnerability type mentioned above.
"""

        # Build a structured prompt for better LLM decisions
        prompt = f"""You are a penetration tester. Analyze the findings and select the BEST next tool.
{challenge_section}
=== CURRENT STATE ===
{context}

=== RECONNAISSANCE FINDINGS ===
{recon_summary}

=== AVAILABLE TOOLS ===
{tool_list}

=== DECISION RULES ===

1. **If authenticated + IDOR not tested** → Test IDOR (flags usually here!)
2. **If login forms found + not authenticated** → Test default_credentials first
3. **If file/path/include parameters found** → Test LFI (can leak creds/source)
4. **If XML/SOAP endpoints found** → Test XXE
5. **If url/callback/redirect parameters found** → Test SSRF
6. **If Flask/Jinja/Django/Twig detected** → Test SSTI
7. **If database interaction suspected** → Test SQLi
8. **If input reflection suspected** → Test XSS

=== EXPLOIT CHAINS ===
- Get credentials → Unlock IDOR → Find flag
- LFI → Leak source/creds → More attacks
- SQLi → Dump passwords → Login → IDOR → Flag

=== YOUR TASK ===
Pick ONE tool that has the HIGHEST probability of success based on the findings.

Respond with ONLY this JSON (no other text):
{{"reasoning": "brief explanation", "tool": "tool_name", "done": false}}

Or if done: {{"reasoning": "why", "done": true}}"""

        response_text = ""  # Initialize for error handling
        try:
            # Use chat_completion with messages format
            from src.xss_agent.llm_client import get_default_model
            messages = [{"role": "user", "content": prompt}]

            # Token tracking is handled automatically by aws_model.py
            response_data = self.llm_client.chat_completion(
                model=get_default_model(),  # Use default model from env/config
                messages=messages,
                max_tokens=500,
                temperature=0.3
            )

            # Extract text from response (OpenAI-style format)
            response_text = response_data.get('choices', [{}])[0].get('message', {}).get('content', '').strip()

            # Debug: Show what we got from LLM
            self.logger.debug(f"LLM raw response_text (first 500 chars): {response_text[:500] if response_text else 'EMPTY'}")

            # Handle empty LLM response - use smart fallback instead of crashing
            if not response_text:
                self.logger.warning(f"Empty LLM response. Raw data: {response_data}")
                print("⚠️  LLM returned empty response, using smart fallback")
                return self._smart_fallback(available_tools)

            # Clean up markdown code blocks if present
            if response_text.startswith('```'):
                lines = response_text.split('\n')
                response_text = '\n'.join(lines[1:-1] if lines[-1].startswith('```') else lines[1:])
                response_text = response_text.replace('```json', '').replace('```', '')

            # Also try to extract JSON from text if it contains other content
            # Sometimes LLM adds explanation before/after the JSON
            if not response_text.startswith('{'):
                import re
                json_match = re.search(r'\{[^{}]*"tool"[^{}]*\}', response_text, re.DOTALL)
                if json_match:
                    response_text = json_match.group(0)
                    self.logger.debug(f"Extracted JSON from response: {response_text}")

            # Try to parse JSON
            decision = json.loads(response_text)

            # Show reasoning
            print(f"💭 Decision: {decision.get('reasoning', 'N/A')}")

            if decision.get('done', False):
                return {'done': True}

            tool_name = decision.get('tool')
            if tool_name and tool_name in [t.name for t in available_tools]:
                print(f"⚡ Testing: {tool_name}")
                return {'tool': tool_name, 'params': {}}
            else:
                # Smart fallback when LLM decision is unclear
                print("⚠️  LLM decision unclear, using smart fallback")
                return self._smart_fallback(available_tools)

        except json.JSONDecodeError as e:
            # Show what the LLM actually returned so we can debug
            resp_preview = response_text[:300] if response_text else 'EMPTY'
            self.logger.error(f"LLM decision failed (JSON parse error): {e}")
            self.logger.error(f"LLM response was: {resp_preview}")
            print(f"⚠️  LLM returned invalid JSON, using smart fallback")
            print(f"    Response preview: {resp_preview[:100]}...")
            return self._smart_fallback(available_tools)
        except Exception as e:
            self.logger.error(f"LLM decision failed: {e}")
            # Smart fallback based on context
            return self._smart_fallback(available_tools)

    def _smart_fallback(self, available_tools: list) -> Dict[str, Any]:
        """Context-aware fallback when LLM fails - uses exploit chain logic"""
        tool_names = [t.name for t in available_tools]
        recon = self.state.recon_findings or {}

        # Get all endpoints for analysis
        endpoints = recon.get('all_endpoints', []) or recon.get('endpoints', [])
        all_params = []
        for ep in endpoints:
            all_params.extend([p.lower() for p in ep.get('parameters', [])])

        # === PRIORITY 0: Challenge description tells us what to do! ===
        if hasattr(self, 'challenge_description') and self.challenge_description:
            desc_lower = self.challenge_description.lower()

            # Map keywords to tools
            keyword_tool_map = [
                (['xss', 'cross-site', 'script', 'alert(', 'onerror', 'onclick'], 'xss'),
                (['sql', 'injection', 'sqli', 'database', 'query', 'union', 'select'], 'sqli'),
                (['ssti', 'template', 'jinja', 'twig', '{{', '}}', 'render'], 'ssti'),
                (['ssrf', 'server-side request', 'internal', 'localhost', 'metadata'], 'ssrf'),
                (['lfi', 'file inclusion', 'path traversal', '../', 'etc/passwd', 'read file'], 'lfi'),
                (['xxe', 'xml', 'external entity', 'dtd', 'entity'], 'xxe'),
                (['idor', 'insecure direct', 'object reference', 'authorization', 'access control'], 'idor'),
                (['credential', 'password', 'login', 'default', 'admin'], 'default_credentials'),
            ]

            for keywords, tool in keyword_tool_map:
                if any(kw in desc_lower for kw in keywords) and tool in tool_names:
                    print(f"⚡ Smart fallback: Testing {tool.upper()} (mentioned in challenge description!)")
                    return {'tool': tool, 'params': {}}

        # === EXPLOIT CHAIN PRIORITY ===
        # The goal is: Recon → Auth → Privilege Escalation → Flag

        # Priority 1: If we have creds but haven't tested IDOR → IDOR (flags are usually here!)
        if self.state.authenticated and 'idor' in tool_names:
            print("⚡ Smart fallback: Testing IDOR (authenticated - hunting for flag!)")
            return {'tool': 'idor', 'params': {}}

        # Priority 2: Get authentication first (enables IDOR and auth-required tests)
        if not self.state.authenticated:
            # 2a: Try default credentials if login form exists
            if recon.get('login_forms') and 'default_credentials' in tool_names:
                print("⚡ Smart fallback: Testing default credentials (login form found)")
                return {'tool': 'default_credentials', 'params': {}}

            # 2b: Try SQLi for auth bypass if no default creds
            if 'sqli' in tool_names:
                print("⚡ Smart fallback: Testing SQLi (may bypass auth or dump creds)")
                return {'tool': 'sqli', 'params': {}}

        # Priority 3: High-value targets based on recon findings

        # 3a: File parameters → LFI (can leak creds, source, configs)
        file_params = recon.get('file_parameters', [])
        file_param_names = ['file', 'path', 'page', 'doc', 'include', 'template', 'load', 'read']
        has_file_params = file_params or any(any(fp in p for fp in file_param_names) for p in all_params)
        if has_file_params and 'lfi' in tool_names:
            print("⚡ Smart fallback: Testing LFI (file parameters detected)")
            return {'tool': 'lfi', 'params': {}}

        # 3b: XML endpoints → XXE
        if recon.get('xml_endpoints') and 'xxe' in tool_names:
            print("⚡ Smart fallback: Testing XXE (XML endpoints detected)")
            return {'tool': 'xxe', 'params': {}}

        # 3c: URL-like parameters → SSRF
        url_param_names = ['url', 'uri', 'link', 'src', 'href', 'callback', 'redirect', 'fetch', 'proxy', 'target']
        has_url_params = any(any(up in p for up in url_param_names) for p in all_params)
        if has_url_params and 'ssrf' in tool_names:
            print("⚡ Smart fallback: Testing SSRF (URL parameters detected)")
            return {'tool': 'ssrf', 'params': {}}

        # 3d: Template engines (Flask/Jinja, Django, etc.) → SSTI
        technologies = recon.get('technologies', [])
        template_techs = ['flask', 'jinja', 'django', 'twig', 'freemarker', 'velocity', 'erb']
        has_template_engine = any(t.lower() in [tech.lower() for tech in technologies] for t in template_techs)
        if has_template_engine and 'ssti' in tool_names:
            print("⚡ Smart fallback: Testing SSTI (template engine detected)")
            return {'tool': 'ssti', 'params': {}}

        # Priority 4: General injection tests (XSS, SQLi, SSTI)
        if 'xss' in tool_names and endpoints:
            print("⚡ Smart fallback: Testing XSS (parameters found)")
            return {'tool': 'xss', 'params': {}}

        if 'sqli' in tool_names:
            print("⚡ Smart fallback: Testing SQLi")
            return {'tool': 'sqli', 'params': {}}

        if 'ssti' in tool_names:
            print("⚡ Smart fallback: Testing SSTI")
            return {'tool': 'ssti', 'params': {}}

        # Priority 5: Info disclosure (might reveal secrets)
        if 'info_disclosure' in tool_names:
            print("⚡ Smart fallback: Testing info disclosure")
            return {'tool': 'info_disclosure', 'params': {}}

        # Last resort: first untested tool
        if available_tools:
            print(f"⚡ Smart fallback: Testing {available_tools[0].name}")
            return {'tool': available_tools[0].name, 'params': {}}

        return {'done': True}

    def _get_tool(self, name: str) -> Optional[Tool]:
        """Get a tool by name from the registry"""
        return self.registry.get_tool(name)

    def _get_suggestions(self) -> List[str]:
        """Get intelligent exploit chain suggestions based on current state"""
        suggestions = []

        if not self.state.reconnaissance_done:
            return ["Run reconnaissance first"]

        recon = self.state.recon_findings

        # Debug: Log recon state
        self.logger.debug(f"Generating suggestions with recon_findings: {recon}")
        self.logger.debug(f"Authenticated: {self.state.authenticated}, Login forms: {len(recon.get('login_forms', []))}")

        # EXPLOIT CHAIN LOGIC - Follow the attack path
        # Chain: LFI (for intel) → Default Creds → Auth → IDOR → Privilege Escalation → Flag

        # Priority 0: ALWAYS test LFI first (can reveal creds, configs, secrets)
        if not self.state.has_tested('lfi'):
            suggestions.append("⭐ Test LFI FIRST (may reveal credentials, configs, API keys - critical intel for other attacks)")

        # Priority 1: Get authentication (critical for chains)
        if not self.state.authenticated and recon.get('login_forms'):
            if not self.state.has_tested('default_credentials'):
                count = len(recon['login_forms'])
                self.logger.info(f"Suggesting default credentials test for {count} login form(s)")
                suggestions.append(f"⭐ Test default credentials (found {count} login form(s) - needed for exploit chain)")
            else:
                suggestions.append("Try SQLi for auth bypass (default creds didn't work)")
        elif not self.state.authenticated and recon.get('login_forms') is not None:
            # Login forms exist but list is empty
            self.logger.debug(f"Login forms found but empty: {recon.get('login_forms')}")

        # Priority 2: If authenticated, escalate privileges via IDOR
        if self.state.authenticated and not self.state.privilege_escalated:
            if not self.state.has_tested('idor'):
                suggestions.append("⭐ Test IDOR for privilege escalation (you're authenticated - try to become admin)")
            else:
                suggestions.append("Re-test IDOR with different parameters (try /edit_profile/<id>)")

        # Priority 3: If privileged, look for sensitive data
        if self.state.authenticated:
            if not self.state.has_tested('info_disclosure'):
                priv_msg = " (you have admin access!)" if self.state.privilege_escalated else " (check for private data)"
                suggestions.append(f"Check for information disclosure{priv_msg}")

        # Priority 4: Database access can extract flags
        if self.state.database_access and not self.state.flags_found:
            suggestions.append("⭐ Use SQLi to extract flags (you have database access)")

        # Priority 5: Standard vulnerability tests
        if not self.state.has_tested('sqli') and not self.state.database_access:
            suggestions.append("Test for SQL injection (may give database access)")

        if recon.get('file_parameters') and not self.state.has_tested('lfi'):
            count = len(recon['file_parameters'])
            suggestions.append(f"Test for LFI (found {count} file-related parameter(s))")

        if recon.get('xml_endpoints') and not self.state.has_tested('xxe'):
            count = len(recon['xml_endpoints'])
            suggestions.append(f"Test for XXE (found {count} XML endpoint(s))")

        if not self.state.has_tested('ssti'):
            suggestions.append("Test for SSTI (Server-Side Template Injection)")

        # Check for SSRF - look for URL-like parameters
        if not self.state.has_tested('ssrf'):
            endpoints = recon.get('endpoints', [])
            url_params = ['url', 'uri', 'link', 'src', 'href', 'callback', 'redirect', 'fetch', 'load', 'proxy', 'image', 'picture']
            url_param_count = sum(
                1 for ep in endpoints
                for p in ep.get('parameters', [])
                if any(up in p.lower() for up in url_params)
            )
            if url_param_count > 0:
                suggestions.append(f"⭐ Test for SSRF (found {url_param_count} URL-like parameter(s) - may access internal services)")
            else:
                suggestions.append("Test for SSRF (check for internal service access)")

        # Remove duplicates while preserving order
        seen = set()
        unique_suggestions = []
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                unique_suggestions.append(s)

        return unique_suggestions[:4]  # Top 4 suggestions

    async def _execute_tool_and_update(self, tool_name: str, params: Dict[str, Any]):
        """Execute a tool and update state"""

        tool = self.registry.get_tool(tool_name)
        if not tool:
            print(f"❌ Tool not found: {tool_name}")
            return

        print(f"\n⚡ Executing: {tool.name}")
        print(f"   {tool.description}")
        print()

        # For auth-required tools, automatically pass found credentials
        if tool.requires_auth and self.state.credentials_found:
            # Use the first found credential
            creds = self.state.credentials_found[0]
            params['credentials'] = creds
            print(f"   🔑 Using found credentials: {creds.get('username')}:***")
            print()

        # Pass recon data to tools that can use it - tool chaining
        if tool_name in ['xss', 'sqli', 'ssti', 'ssrf', 'lfi'] and self.state.recon_findings:
            params['recon_endpoints'] = self.state.recon_findings.get('all_endpoints', [])
            if params['recon_endpoints']:
                print(f"   📡 Using {len(params['recon_endpoints'])} discovered endpoint(s) from reconnaissance")
                print()

        # SSRF benefits from credentials even if not strictly required (authenticated pages may have SSRF)
        if tool_name == 'ssrf' and self.state.credentials_found and 'credentials' not in params:
            creds = self.state.credentials_found[0]
            params['credentials'] = creds
            print(f"   🔑 Using found credentials for authenticated SSRF testing: {creds.get('username')}:***")
            print()

        # Execute
        result = await tool.execute(self.state.target_url, **params)

        # Handle reconnaissance specially
        if tool_name == "reconnaissance":
            self.state.reconnaissance_done = True
            if result.success and result.findings:
                # Store recon data
                recon_data = result.findings[0].get('recon_data')
                if recon_data:
                    # Debug: Show what we found
                    login_forms_count = len(recon_data.login_forms) if hasattr(recon_data, 'login_forms') else 0
                    file_params_count = len(recon_data.file_related_params) if hasattr(recon_data, 'file_related_params') else 0
                    xml_endpoints_count = len(recon_data.xml_endpoints) if hasattr(recon_data, 'xml_endpoints') else 0

                    self.logger.info(f"Reconnaissance found: {login_forms_count} login forms, {file_params_count} file params, {xml_endpoints_count} XML endpoints")

                    # Use discovered endpoints from endpoint_discovery tool (most reliable)
                    all_endpoints = getattr(recon_data, 'discovered_endpoints', [])

                    # If no endpoints from discovery, fall back to form-based extraction
                    if not all_endpoints:
                        # Add login forms
                        for form in (recon_data.login_forms if hasattr(recon_data, 'login_forms') else []):
                            params = [inp.get('name') for inp in form.get('inputs', []) if inp.get('name')]
                            if params:
                                all_endpoints.append({
                                    'url': form.get('action', recon_data.target_url),
                                    'method': form.get('method', 'POST'),
                                    'parameters': params,
                                    'type': 'login'
                                })

                        # Add other forms
                        for form in (recon_data.other_forms if hasattr(recon_data, 'other_forms') else []):
                            params = [inp.get('name') for inp in form.get('inputs', []) if inp.get('name')]
                            if params:
                                all_endpoints.append({
                                    'url': form.get('action', recon_data.target_url),
                                    'method': form.get('method', 'GET'),
                                    'parameters': params,
                                    'type': 'other'
                                })

                    # Get LLM context if available
                    llm_context = recon_data.get_llm_context() if hasattr(recon_data, 'get_llm_context') else None

                    self.state.recon_findings = {
                        'login_forms': recon_data.login_forms if hasattr(recon_data, 'login_forms') else [],
                        'file_parameters': list(recon_data.file_related_params) if hasattr(recon_data, 'file_related_params') else [],
                        'xml_endpoints': recon_data.xml_endpoints if hasattr(recon_data, 'xml_endpoints') else [],
                        'forms_count': (len(recon_data.login_forms) if hasattr(recon_data, 'login_forms') else 0) + (len(recon_data.other_forms) if hasattr(recon_data, 'other_forms') else 0),
                        'parameters_count': (len(recon_data.get_parameters) if hasattr(recon_data, 'get_parameters') else 0) + (len(recon_data.post_parameters) if hasattr(recon_data, 'post_parameters') else 0),
                        'all_endpoints': all_endpoints,  # For tool chaining (XSS, SQLi, etc.)
                        'llm_context': llm_context,  # Rich context for LLM decision making
                        'page_summaries': recon_data.page_summaries if hasattr(recon_data, 'page_summaries') else {},
                        'technologies': list(recon_data.technologies) if hasattr(recon_data, 'technologies') else [],
                        'api_endpoints': recon_data.api_endpoints if hasattr(recon_data, 'api_endpoints') else [],
                        'js_files': recon_data.js_files if hasattr(recon_data, 'js_files') else []
                    }

                    # Print discovery summary for user visibility
                    print(f"\n🔍 Reconnaissance Discovery:")
                    if login_forms_count > 0:
                        print(f"   • Found {login_forms_count} login form(s)")
                    if file_params_count > 0:
                        print(f"   • Found {file_params_count} file-related parameter(s)")
                    if xml_endpoints_count > 0:
                        print(f"   • Found {xml_endpoints_count} XML endpoint(s)")
                    if all_endpoints:
                        total_params = sum(len(ep.get('parameters', [])) for ep in all_endpoints)
                        print(f"   • Discovered {len(all_endpoints)} endpoint(s) with {total_params} parameter(s) for testing")

                    # Debug: Show stored state
                    self.logger.debug(f"Stored recon_findings: {self.state.recon_findings}")

                    # Auto-run info disclosure after recon to find credentials, secrets, exposed files
                    print("\n🔎 Auto-running info disclosure scan (finds credentials, secrets, exposed files)...")
                    try:
                        info_tool = self._get_tool("info_disclosure")
                        if info_tool:
                            info_result = await info_tool.execute(self.state.target_url)
                            if info_result.success and info_result.findings:
                                print(f"   ✓ Info disclosure found {len(info_result.findings)} item(s)")
                                self.state.add_result(info_result)
                            else:
                                print(f"   • No sensitive info disclosed")
                    except Exception as e:
                        self.logger.debug(f"Info disclosure auto-scan failed: {e}")

        # Update state
        self.state.add_result(result)

        # Show result
        print(f"\n📊 Result: {result.summary()}")

        if result.success and result.findings:
            # Filter out non-vulnerability findings (recon, info)
            vuln_findings = [f for f in result.findings
                           if f.get('type') not in ['reconnaissance', 'info', None]]

            if vuln_findings:
                print(f"\n🎯 Found {len(vuln_findings)} finding(s):\n")
                for idx, finding in enumerate(vuln_findings, 1):
                    vuln_type = finding.get('type', 'unknown')
                    severity = finding.get('severity', 'unknown')
                    desc = finding.get('description', 'N/A')

                    print(f"[{idx}] {vuln_type.upper()} ({severity})")
                    print(f"    {desc}")

                    # Show SQLi-specific details
                    if vuln_type == 'sqli':
                        if finding.get('injection_points'):
                            print(f"    Vulnerable parameters:")
                            for ip in finding['injection_points'][:3]:
                                print(f"      • {ip['parameter']} ({ip['location']}) - {ip['confidence']}% confidence")

                        if finding.get('database_name'):
                            print(f"    Database: {finding['database_name']}")

                        if finding.get('successful_payloads'):
                            print(f"    Sample payloads:")
                            for payload_data in finding['successful_payloads'][:2]:
                                payload = payload_data.get('payload', '')
                                if len(payload) > 100:
                                    payload = payload[:100] + "..."
                                print(f"      • {payload}")
                                if payload_data.get('extracted_data'):
                                    print(f"        Extracted: {payload_data['extracted_data']}")

                    # Show flags prominently
                    if vuln_type == 'flag':
                        flag = finding.get('flag', '')
                        url = finding.get('url', 'unknown')
                        print(f"    🚩 {flag}")
                        print(f"    URL: {url}")

                    print()

            # Check for credentials and flags
            flags_in_results = []
            creds_in_results = []

            for finding in result.findings:
                if not isinstance(finding, dict):
                    continue  # Skip non-dict findings

                # Handle both credential styles
                if 'credentials' in finding:
                    creds_in_results.append(finding['credentials'])
                elif finding.get('type') == 'credentials' and finding.get('username'):
                    creds_in_results.append({
                        'username': finding.get('username'),
                        'password': finding.get('password', '')
                    })

                if finding.get('type') == 'flag':
                    flags_in_results.append(finding.get('flag'))

            # Show credentials prominently
            if creds_in_results:
                for creds in creds_in_results:
                    if isinstance(creds, dict):
                        print(f"✨ Credentials found: {creds.get('username')}:{creds.get('password')}")
                        print(f"   You now have authenticated access!\n")

            # Show flags VERY prominently and add to state
            if flags_in_results:
                print("="*70)
                print("🚩🚩🚩 FLAG(S) FOUND! 🚩🚩🚩")
                print("="*70)
                for flag in flags_in_results:
                    print(f"  {flag}")
                    # Add to state.flags_found for stopping logic
                    if flag and flag not in self.state.flags_found:
                        self.state.flags_found.append(flag)
                print("="*70)
                print()

        print()

    def _should_stop(self) -> bool:
        """Check if we should stop testing"""
        # In interactive mode, never auto-stop (let user decide)
        if self.mode == "interactive":
            return False

        # In auto mode, stop immediately if we found a flag
        if self.state.flags_found:
            print(f"\n🎯 FLAG FOUND! Stopping autonomous testing.")
            return True

        # In auto mode, stop if all tools tested once
        all_tools = self.registry.get_available_tools(self.state.authenticated)
        untested = [t for t in all_tools if not self.state.has_tested(t.name)]

        return len(untested) == 0

    def _print_final_report(self):
        """Print final report"""
        print("\n" + "="*70)
        print("📊 FINAL REPORT")
        print("="*70)
        print(self.state.get_summary())

        if self.state.vulnerabilities:
            print("\n" + "-"*70)
            print("🎯 Vulnerabilities Found:")
            print("-"*70)
            for i, vuln in enumerate(self.state.vulnerabilities, 1):
                vuln_type = vuln.get('type', 'unknown')
                severity = vuln.get('severity', 'unknown')
                desc = vuln.get('description', 'N/A')
                print(f"\n{i}. {vuln_type.upper()} ({severity})")
                print(f"   {desc}")

                # Show SQLi details
                if vuln_type == 'sqli':
                    if vuln.get('injection_points'):
                        print(f"\n   Vulnerable parameters:")
                        for ip in vuln['injection_points']:
                            print(f"     • {ip['parameter']} ({ip['location']}) - {ip['confidence']}% confidence")

                    if vuln.get('database_name'):
                        print(f"   Database: {vuln['database_name']}")

                    if vuln.get('successful_payloads'):
                        print(f"\n   Working payloads:")
                        for payload_data in vuln['successful_payloads'][:2]:
                            payload = payload_data.get('payload', '')
                            if len(payload) > 80:
                                payload = payload[:80] + "..."
                            print(f"     • {payload}")
                            if payload_data.get('extracted_data'):
                                extracted = payload_data['extracted_data']
                                print(f"       Extracted: {extracted}")

                # Show XSS details
                if vuln_type == 'xss':
                    if vuln.get('payload'):
                        payload = vuln['payload']
                        if len(payload) > 100:
                            payload = payload[:100] + "..."
                        print(f"   Payload: {payload}")
                    if vuln.get('flag'):
                        print(f"   🚩 FLAG: {vuln['flag']}")

        if self.state.credentials_found:
            print("\n" + "-"*70)
            print("🔑 Credentials Found:")
            print("-"*70)
            for creds in self.state.credentials_found:
                if isinstance(creds, dict):
                    print(f"   - {creds.get('username')}:{creds.get('password')}")
                elif isinstance(creds, str):
                    print(f"   - {creds}")

        if self.state.flags_found:
            print("\n" + "="*70)
            print("🚩🚩🚩 FLAGS CAPTURED! 🚩🚩🚩")
            print("="*70)
            for i, flag in enumerate(self.state.flags_found, 1):
                print(f"  [{i}] {flag}")
            print("="*70)

        print("\n" + "="*70)
        print(f"Tools executed: {len(self.state.tools_executed)}")
        print(f"Total vulnerabilities: {len(self.state.vulnerabilities)}")
        if self.state.flags_found:
            print(f"🚩 Flags captured: {len(self.state.flags_found)}")
        print("="*70)

        # Print token usage and cost summary
        if TOKEN_TRACKING_AVAILABLE:
            tracker = get_tracker()
            if tracker.call_count > 0:
                print("\n" + tracker.get_summary())
            else:
                print("\n💡 No LLM API calls were made during this session.")
        print()


async def main():
    """Test the conversational agent"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python conversational_agent.py <URL> [--auto] [--challenge \"description\"]")
        print("\nModes:")
        print("  (default)  Interactive mode - asks you what to do")
        print("  --auto     Autonomous mode - decides itself")
        print("\nOptions:")
        print("  --challenge \"desc\"  Provide challenge description for guided testing")
        print("  --no-prompt         Skip the challenge description prompt")
        sys.exit(1)

    target_url = sys.argv[1]
    mode = "auto" if "--auto" in sys.argv else "interactive"

    # Parse challenge description from CLI if provided
    challenge_description = None
    if "--challenge" in sys.argv:
        idx = sys.argv.index("--challenge")
        if idx + 1 < len(sys.argv):
            challenge_description = sys.argv[idx + 1]
    elif "--no-prompt" in sys.argv:
        challenge_description = ""  # Empty string = skip prompt

    # Create and run agent
    agent = ConversationalAgent(mode=mode)
    await agent.run(target_url, challenge_description=challenge_description)


if __name__ == "__main__":
    asyncio.run(main())
