#!/usr/bin/env python3
"""
Intelligent Orchestrator - Smart Agent Selection

Automatically discovers attack surface and intelligently selects
which vulnerability agents to run based on LLM analysis.

Features:
- Smart reconnaissance (crawl + technology detection)
- LLM-driven agent selection with reasoning
- Priority-based execution (P1, P2, P3)
- Early exit on high-severity findings
- Real-time progress updates
- Cost tracking and estimation
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, urljoin
from collections import defaultdict

# Import agents
try:
    from src.lfi_agent.lfi_detector import LFIDetector
    LFI_AVAILABLE = True
    async def test_lfi(url, parameter=None):
        detector = LFIDetector()
        result = await detector.test_url(url)
        return result.get('vulnerable', False) if result else False
except ImportError:
    LFI_AVAILABLE = False

try:
    from src.xxe_agent.orchestrator import test_xxe
    XXE_AVAILABLE = True
except ImportError:
    XXE_AVAILABLE = False

try:
    from src.ssti_agent.context_aware_orchestrator import ContextAwareSSTIOrchestrator
    SSTI_AVAILABLE = True
    async def test_ssti(url):
        orchestrator = ContextAwareSSTIOrchestrator()
        result = await orchestrator.test_parameter(url, None, None)
        return result.get('vulnerable', False) if result else False
except ImportError:
    SSTI_AVAILABLE = False

try:
    from src.command_injection_agent.context_aware_orchestrator import ContextAwareCommandInjectionOrchestrator
    COMMAND_INJECTION_AVAILABLE = True
    async def test_command_injection(url, parameter=None):
        orchestrator = ContextAwareCommandInjectionOrchestrator()
        result = await orchestrator.test_parameter(url, parameter, None)
        return result.get('vulnerable', False) if result else False
except ImportError:
    COMMAND_INJECTION_AVAILABLE = False

try:
    from src.credential_agent.credential_tester import CredentialTester
    DEFAULT_CREDS_AVAILABLE = True
    async def test_default_credentials(url, max_passwords=100):
        tester = CredentialTester()
        result = await tester.test_url(url, max_passwords=max_passwords)
        return result.get('success', False) if result else False
except ImportError:
    DEFAULT_CREDS_AVAILABLE = False

try:
    from src.info_disclosure_agent.info_detector import InfoDisclosureDetector
    INFO_DISCLOSURE_AVAILABLE = True
    async def test_info_disclosure(url):
        detector = InfoDisclosureDetector()
        result = await detector.scan(url)
        return result.get('vulnerable', False) if result else False
except ImportError:
    INFO_DISCLOSURE_AVAILABLE = False

try:
    from src.idor_agent.context_aware_orchestrator import ContextAwareIDOROrchestrator
    IDOR_AVAILABLE = True
    async def test_idor(url):
        orchestrator = ContextAwareIDOROrchestrator()
        result = await orchestrator.test_url(url)
        return result.get('vulnerable', False) if result else False
except ImportError:
    IDOR_AVAILABLE = False

try:
    from src.sqli_agent.sqli_orchestrator import test_sqli
    SQLI_AVAILABLE = True
except ImportError:
    SQLI_AVAILABLE = False

try:
    from src.xss_agent.orchestrator import DynamicXSSOrchestrator
    XSS_AVAILABLE = True
except ImportError:
    XSS_AVAILABLE = False


@dataclass
class ReconFindings:
    """Stores reconnaissance findings about the target"""
    target_url: str

    # Forms and inputs
    login_forms: List[Dict[str, Any]] = field(default_factory=list)
    search_forms: List[Dict[str, Any]] = field(default_factory=list)
    upload_forms: List[Dict[str, Any]] = field(default_factory=list)
    comment_forms: List[Dict[str, Any]] = field(default_factory=list)
    other_forms: List[Dict[str, Any]] = field(default_factory=list)

    # Parameters
    get_parameters: Set[str] = field(default_factory=set)
    post_parameters: Set[str] = field(default_factory=set)
    file_related_params: Set[str] = field(default_factory=set)

    # Technologies detected
    has_xml_endpoints: bool = False
    has_soap_endpoints: bool = False
    has_json_api: bool = False
    has_graphql: bool = False
    xml_endpoints: List[str] = field(default_factory=list)

    # Template engines
    template_indicators: List[str] = field(default_factory=list)
    has_template_engines: bool = False

    # User input reflection
    reflection_points: int = 0
    reflected_parameters: List[str] = field(default_factory=list)

    # Authentication
    has_authentication: bool = False
    auth_endpoints: List[str] = field(default_factory=list)

    # File operations
    has_file_operations: bool = False
    file_endpoints: List[str] = field(default_factory=list)

    # URLs discovered
    discovered_urls: Set[str] = field(default_factory=set)

    # Technologies
    server_header: Optional[str] = None
    powered_by: Optional[str] = None
    technologies: List[str] = field(default_factory=list)

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of findings for display"""
        return {
            'forms': {
                'login': len(self.login_forms),
                'search': len(self.search_forms),
                'upload': len(self.upload_forms),
                'comment': len(self.comment_forms),
                'other': len(self.other_forms)
            },
            'parameters': {
                'get': len(self.get_parameters),
                'post': len(self.post_parameters),
                'file_related': len(self.file_related_params)
            },
            'technologies': {
                'xml_endpoints': len(self.xml_endpoints),
                'has_soap': self.has_soap_endpoints,
                'has_json_api': self.has_json_api,
                'has_graphql': self.has_graphql,
                'template_engines': self.template_indicators
            },
            'attack_surface': {
                'reflection_points': self.reflection_points,
                'has_authentication': self.has_authentication,
                'has_file_operations': self.has_file_operations,
                'urls_discovered': len(self.discovered_urls)
            }
        }


@dataclass
class AgentDecision:
    """LLM decision on which agents to run"""
    priority_1: List[str] = field(default_factory=list)  # Must run
    priority_2: List[str] = field(default_factory=list)  # Should run
    priority_3: List[str] = field(default_factory=list)  # Optional
    skip: List[str] = field(default_factory=list)        # Unlikely to find anything

    reasoning: Dict[str, str] = field(default_factory=dict)
    estimated_time_minutes: str = "3-5"
    estimated_cost_usd: str = "$0.50-1.00"
    confidence_score: float = 0.8


@dataclass
class AgentResult:
    """Result from running an agent"""
    agent_name: str
    success: bool
    vulnerabilities_found: int
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"
    execution_time: float
    cost: float
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


class IntelligentOrchestrator:
    """
    Intelligent orchestrator that automatically decides which agents to run
    based on reconnaissance and LLM analysis.
    """

    AGENT_REGISTRY = {
        'xss': {'available': XSS_AVAILABLE, 'func': None, 'async': True},
        'sqli': {'available': SQLI_AVAILABLE, 'func': test_sqli, 'async': True},
        'xxe': {'available': XXE_AVAILABLE, 'func': test_xxe, 'async': True},
        'lfi': {'available': LFI_AVAILABLE, 'func': test_lfi, 'async': True},
        'ssti': {'available': SSTI_AVAILABLE, 'func': test_ssti, 'async': True},
        'command_injection': {'available': COMMAND_INJECTION_AVAILABLE, 'func': test_command_injection, 'async': True},
        'idor': {'available': IDOR_AVAILABLE, 'func': test_idor, 'async': True},
        'default_credentials': {'available': DEFAULT_CREDS_AVAILABLE, 'func': test_default_credentials, 'async': True},
        'info_disclosure': {'available': INFO_DISCLOSURE_AVAILABLE, 'func': test_info_disclosure, 'async': True}
    }

    def __init__(self,
                 mode: str = 'default',
                 use_llm_decision: bool = True,
                 focus_agents: Optional[List[str]] = None,
                 skip_agents: Optional[List[str]] = None):
        """
        Initialize intelligent orchestrator

        Args:
            mode: Orchestration mode ('default', 'aggressive', 'fast', 'interactive')
            use_llm_decision: Use LLM for agent selection (vs rule-based)
            focus_agents: Only run these agents (overrides LLM)
            skip_agents: Never run these agents
        """
        self.mode = mode
        self.use_llm_decision = use_llm_decision
        self.focus_agents = focus_agents
        self.skip_agents = skip_agents or []

        self.logger = logging.getLogger(self.__class__.__name__)

        # Mode configurations
        self.config = self._get_mode_config()

        # Results storage
        self.recon_findings: Optional[ReconFindings] = None
        self.agent_decision: Optional[AgentDecision] = None
        self.results: List[AgentResult] = []

        # Timing
        self.start_time = None
        self.recon_time = 0
        self.decision_time = 0
        self.execution_time = 0

    def _get_mode_config(self) -> Dict[str, Any]:
        """Get configuration for the selected mode"""
        configs = {
            'default': {
                'recon_depth': 2,
                'auto_start': False,      # Show preview first
                'early_exit': True,       # Stop after HIGH findings
                'parallel_p1': True,
                'parallel_p2': True,
                'run_p3': False,          # Skip Priority 3 by default
                'max_recon_urls': 30
            },
            'aggressive': {
                'recon_depth': 3,
                'auto_start': True,       # No preview
                'early_exit': False,      # Run everything
                'parallel_p1': True,
                'parallel_p2': True,
                'run_p3': True,
                'max_recon_urls': 50
            },
            'fast': {
                'recon_depth': 1,
                'auto_start': True,
                'early_exit': True,
                'parallel_p1': True,
                'parallel_p2': False,     # Sequential P2
                'run_p3': False,
                'max_recon_urls': 15
            },
            'interactive': {
                'recon_depth': 2,
                'auto_start': False,
                'early_exit': False,
                'ask_before_each_phase': True,
                'parallel_p1': False,     # User sees each result
                'parallel_p2': False,
                'run_p3': True,
                'max_recon_urls': 30
            }
        }
        return configs.get(self.mode, configs['default'])

    async def run(self, target_url: str) -> Dict[str, Any]:
        """
        Main orchestration flow

        Args:
            target_url: Target URL to test

        Returns:
            Dictionary with complete results
        """
        self.start_time = time.time()

        try:
            # Phase 1: Reconnaissance
            self.logger.info(f"Starting intelligent orchestration for {target_url}")
            print("\n" + "="*70)
            print("🤖 INTELLIGENT ORCHESTRATION")
            print("="*70)
            print(f"Target: {target_url}")
            print(f"Mode: {self.mode}")
            print("="*70 + "\n")

            recon_start = time.time()
            print("📡 Phase 1: Reconnaissance")
            print("-" * 70)
            self.recon_findings = await self.reconnaissance(target_url)
            self.recon_time = time.time() - recon_start

            # Display findings
            self._display_recon_findings()

            # Phase 2: Decision
            decision_start = time.time()
            print("\n🧠 Phase 2: Agent Selection")
            print("-" * 70)

            if self.focus_agents:
                # User override
                self.agent_decision = self._manual_agent_selection(self.focus_agents)
                print(f"✓ Manual selection: {', '.join(self.focus_agents)}")
            else:
                # LLM or rule-based decision
                self.agent_decision = await self.decide_agents(self.recon_findings)

            self.decision_time = time.time() - decision_start

            # Display decision
            self._display_agent_decision()

            # Confirmation (if not auto-start)
            if not self.config['auto_start']:
                response = input("\n[Press Enter to start, or Ctrl+C to cancel]: ")

            # Phase 3: Execution
            exec_start = time.time()
            print("\n⚡ Phase 3: Execution")
            print("-" * 70)

            await self.execute_agents(target_url)

            self.execution_time = time.time() - exec_start

            # Final report
            self._display_final_report()

            return self._get_results_summary()

        except KeyboardInterrupt:
            print("\n\n⚠️  Scan cancelled by user")
            return self._get_results_summary()
        except Exception as e:
            self.logger.error(f"Orchestration failed: {e}", exc_info=True)
            print(f"\n❌ Error: {e}")
            return self._get_results_summary()

    async def reconnaissance(self, target_url: str) -> ReconFindings:
        """
        Phase 1: Discover attack surface

        This is FREE - no LLM calls, just crawling and analysis
        """
        findings = ReconFindings(target_url=target_url)

        print(f"Crawling target (depth={self.config['recon_depth']}, max_urls={self.config['max_recon_urls']})...")

        try:
            from playwright.async_api import async_playwright
            from bs4 import BeautifulSoup

            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()

                visited = set()
                to_visit = {target_url}
                depth = 0

                while to_visit and depth < self.config['recon_depth'] and len(visited) < self.config['max_recon_urls']:
                    current_level = list(to_visit)
                    to_visit.clear()

                    for url in current_level:
                        if url in visited or len(visited) >= self.config['max_recon_urls']:
                            continue

                        try:
                            await page.goto(url, wait_until='domcontentloaded', timeout=10000)
                            visited.add(url)
                            findings.discovered_urls.add(url)

                            # Get page content
                            content = await page.content()
                            soup = BeautifulSoup(content, 'html.parser')

                            # Analyze forms
                            forms = soup.find_all('form')
                            for form in forms:
                                form_data = self._analyze_form(form, url)

                                # Categorize form
                                if self._is_login_form(form_data):
                                    findings.login_forms.append(form_data)
                                    findings.has_authentication = True
                                elif self._is_upload_form(form_data):
                                    findings.upload_forms.append(form_data)
                                    findings.has_file_operations = True
                                elif self._is_search_form(form_data):
                                    findings.search_forms.append(form_data)
                                elif self._is_comment_form(form_data):
                                    findings.comment_forms.append(form_data)
                                else:
                                    findings.other_forms.append(form_data)

                                # Extract parameters
                                for input_field in form_data.get('inputs', []):
                                    name = input_field.get('name', '')
                                    if name:
                                        if form_data.get('method', 'GET').upper() == 'POST':
                                            findings.post_parameters.add(name)
                                        else:
                                            findings.get_parameters.add(name)

                                        # Check for file-related params
                                        if any(keyword in name.lower() for keyword in ['file', 'path', 'page', 'doc', 'resource']):
                                            findings.file_related_params.add(name)

                            # Extract links for next depth
                            if depth < self.config['recon_depth'] - 1:
                                for link in soup.find_all('a', href=True):
                                    href = link['href']
                                    absolute_url = urljoin(url, href)

                                    # Only follow same-domain links
                                    if urlparse(absolute_url).netloc == urlparse(target_url).netloc:
                                        if absolute_url not in visited:
                                            to_visit.add(absolute_url)

                            # Check for XML/SOAP endpoints
                            if 'soap' in content.lower() or '<soap:' in content.lower():
                                findings.has_soap_endpoints = True

                            if any(keyword in content.lower() for keyword in ['<?xml', '<xml', 'application/xml']):
                                findings.has_xml_endpoints = True

                            # Check for template indicators
                            template_patterns = ['{{', '{%', '${', '<%', 'render(']
                            for pattern in template_patterns:
                                if pattern in content:
                                    findings.template_indicators.append(pattern)
                                    findings.has_template_engines = True

                            # Check server headers
                            if not findings.server_header:
                                try:
                                    response = await page.evaluate('() => ({ headers: window.performance.getEntries()[0].serverTiming })')
                                except:
                                    pass

                            await asyncio.sleep(0.1)  # Be nice to the server

                        except Exception as e:
                            self.logger.debug(f"Failed to analyze {url}: {e}")
                            continue

                    depth += 1

                await browser.close()

            print(f"✓ Discovered {len(visited)} pages, {len(findings.login_forms) + len(findings.other_forms)} forms")

        except Exception as e:
            self.logger.error(f"Reconnaissance failed: {e}")
            print(f"✗ Reconnaissance error: {e}")

        return findings

    def _analyze_form(self, form, base_url: str) -> Dict[str, Any]:
        """Analyze a form element"""
        action = form.get('action', '')
        method = form.get('method', 'GET').upper()

        # Get absolute action URL
        action_url = urljoin(base_url, action) if action else base_url

        inputs = []
        for input_elem in form.find_all(['input', 'textarea', 'select']):
            input_data = {
                'name': input_elem.get('name', ''),
                'type': input_elem.get('type', 'text'),
                'id': input_elem.get('id', ''),
                'placeholder': input_elem.get('placeholder', '')
            }
            inputs.append(input_data)

        return {
            'action': action_url,
            'method': method,
            'inputs': inputs,
            'form_html': str(form)[:200]  # First 200 chars for context
        }

    def _is_login_form(self, form_data: Dict[str, Any]) -> bool:
        """Detect if form is a login form"""
        inputs = form_data.get('inputs', [])
        has_password = any(inp.get('type') == 'password' for inp in inputs)
        has_username = any(
            any(keyword in inp.get('name', '').lower() for keyword in ['user', 'email', 'login'])
            for inp in inputs
        )
        return has_password and has_username

    def _is_upload_form(self, form_data: Dict[str, Any]) -> bool:
        """Detect if form has file upload"""
        return any(inp.get('type') == 'file' for inp in form_data.get('inputs', []))

    def _is_search_form(self, form_data: Dict[str, Any]) -> bool:
        """Detect if form is a search form"""
        inputs = form_data.get('inputs', [])
        return any(
            any(keyword in inp.get('name', '').lower() for keyword in ['search', 'query', 'q', 'find'])
            for inp in inputs
        )

    def _is_comment_form(self, form_data: Dict[str, Any]) -> bool:
        """Detect if form is for comments/posts"""
        inputs = form_data.get('inputs', [])
        return any(
            inp.get('type') == 'textarea' or
            any(keyword in inp.get('name', '').lower() for keyword in ['comment', 'message', 'post', 'content'])
            for inp in inputs
        )

    async def decide_agents(self, findings: ReconFindings) -> AgentDecision:
        """
        Phase 2: Decide which agents to run

        Uses rule-based heuristics first, then LLM for refinement if needed
        """

        if self.use_llm_decision:
            # Try LLM-based decision
            try:
                return await self._llm_agent_decision(findings)
            except Exception as e:
                self.logger.warning(f"LLM decision failed, falling back to rules: {e}")
                return self._rule_based_decision(findings)
        else:
            # Use rule-based decision
            return self._rule_based_decision(findings)

    def _rule_based_decision(self, findings: ReconFindings) -> AgentDecision:
        """
        Rule-based agent selection (no LLM, FREE)
        """
        decision = AgentDecision()
        reasoning = {}

        # Rule 1: Login forms → Default Credentials + SQLi
        if findings.login_forms:
            if 'default_credentials' not in self.skip_agents and DEFAULT_CREDS_AVAILABLE:
                decision.priority_1.append('default_credentials')
                reasoning['default_credentials'] = f"Found {len(findings.login_forms)} login form(s)"

            if 'sqli' not in self.skip_agents and SQLI_AVAILABLE:
                decision.priority_1.append('sqli')
                reasoning['sqli'] = f"Login forms present, testing for SQL injection"

        # Rule 2: Any forms or parameters → XSS + SQLi
        total_params = len(findings.get_parameters) + len(findings.post_parameters)
        if total_params > 0:
            if 'xss' not in self.skip_agents and XSS_AVAILABLE:
                decision.priority_1.append('xss')
                reasoning['xss'] = f"Found {total_params} input parameter(s)"

            if 'sqli' not in decision.priority_1 and 'sqli' not in self.skip_agents and SQLI_AVAILABLE:
                decision.priority_1.append('sqli')
                reasoning['sqli'] = f"Testing {total_params} parameter(s) for SQL injection"

        # Rule 3: XML/SOAP endpoints → XXE
        if findings.has_xml_endpoints or findings.has_soap_endpoints:
            if 'xxe' not in self.skip_agents and XXE_AVAILABLE:
                decision.priority_2.append('xxe')
                reasoning['xxe'] = f"Found XML/SOAP endpoints"

        # Rule 4: File-related parameters → LFI
        if findings.file_related_params:
            if 'lfi' not in self.skip_agents and LFI_AVAILABLE:
                decision.priority_2.append('lfi')
                reasoning['lfi'] = f"Found {len(findings.file_related_params)} file-related parameter(s)"

        # Rule 5: File upload forms → XXE (SVG)
        if findings.upload_forms:
            if 'xxe' not in decision.priority_2 and 'xxe' not in self.skip_agents and XXE_AVAILABLE:
                decision.priority_2.append('xxe')
                reasoning['xxe'] = f"Found {len(findings.upload_forms)} file upload form(s)"

        # Rule 6: Template indicators → SSTI
        if findings.has_template_engines:
            if 'ssti' not in self.skip_agents and SSTI_AVAILABLE:
                decision.priority_2.append('ssti')
                reasoning['ssti'] = f"Template engine indicators found: {', '.join(findings.template_indicators[:3])}"

        # Rule 7: Always worth checking → Info Disclosure (low cost)
        if 'info_disclosure' not in self.skip_agents and INFO_DISCLOSURE_AVAILABLE:
            decision.priority_3.append('info_disclosure')
            reasoning['info_disclosure'] = "Checking for exposed secrets/API keys"

        # Rule 8: Authentication present → IDOR
        if findings.has_authentication:
            if 'idor' not in self.skip_agents and IDOR_AVAILABLE:
                decision.priority_3.append('idor')
                reasoning['idor'] = "Authentication detected, testing authorization"

        decision.reasoning = reasoning

        # Estimate time and cost
        agent_count = len(decision.priority_1) + len(decision.priority_2)
        decision.estimated_time_minutes = f"{agent_count * 1}-{agent_count * 2}"
        decision.estimated_cost_usd = f"${agent_count * 0.20:.2f}-${agent_count * 0.40:.2f}"

        return decision

    async def _llm_agent_decision(self, findings: ReconFindings) -> AgentDecision:
        """
        LLM-based agent selection (SMART, costs ~$0.01)

        Uses LLM to analyze reconnaissance and decide which agents to run
        """
        try:
            # Import LLM client
            from src.xss_agent.llm_client import get_llm_client

            llm_client = get_llm_client()

            # Build prompt
            summary = findings.get_summary()

            available_agents = []
            for name, info in self.AGENT_REGISTRY.items():
                if info['available'] and name not in self.skip_agents:
                    available_agents.append(name)

            prompt = f"""You are a web security expert analyzing a target for vulnerability testing.

Target: {findings.target_url}

Reconnaissance Findings:
{json.dumps(summary, indent=2)}

Available Agents:
1. xss - Context-aware XSS detection (LLM-driven, cost: $0.05-0.10 per param)
2. sqli - Database-aware SQL injection (LLM-driven, cost: $0.05-0.10 per param)
3. xxe - Multi-vector XXE detection (SOAP + SVG + Textarea)
4. lfi - Local File Inclusion (70K payloads, concurrent)
5. ssti - Server-Side Template Injection (engine detection)
6. command_injection - Command injection (OS-aware)
7. idor - Authorization testing (LLM-driven)
8. default_credentials - Credential testing (wordlist-based)
9. info_disclosure - Information disclosure (secrets, API keys)

Prioritize agents based on:
1. Likelihood of success (what vulnerabilities are most probable given the findings?)
2. Impact (which findings would be most valuable?)
3. Efficiency (cost vs benefit)

Respond ONLY with a valid JSON object (no markdown, no explanation):
{{
  "priority_1": ["agent1", "agent2"],
  "priority_2": ["agent3"],
  "priority_3": ["agent4"],
  "skip": ["agent5", "agent6"],
  "reasoning": {{
    "agent1": "reason why this should run first",
    "agent2": "reason why this should run first",
    "skip_agent5": "reason to skip"
  }},
  "estimated_time_minutes": "3-5",
  "estimated_cost_usd": "$0.50-1.00",
  "confidence_score": 0.8
}}"""

            # Get LLM response
            print("Analyzing with LLM... ", end='', flush=True)
            response = await llm_client.generate_text(
                prompt=prompt,
                max_tokens=1000,
                temperature=0.3
            )
            print("✓")

            # Parse response
            # Clean up response (remove markdown if present)
            response_text = response.strip()
            if response_text.startswith('```'):
                # Remove markdown code blocks
                lines = response_text.split('\n')
                response_text = '\n'.join(lines[1:-1] if lines[-1].startswith('```') else lines[1:])
                response_text = response_text.replace('```json', '').replace('```', '')

            decision_data = json.loads(response_text)

            # Create AgentDecision object
            decision = AgentDecision(
                priority_1=decision_data.get('priority_1', []),
                priority_2=decision_data.get('priority_2', []),
                priority_3=decision_data.get('priority_3', []),
                skip=decision_data.get('skip', []),
                reasoning=decision_data.get('reasoning', {}),
                estimated_time_minutes=decision_data.get('estimated_time_minutes', '3-5'),
                estimated_cost_usd=decision_data.get('estimated_cost_usd', '$0.50-1.00'),
                confidence_score=decision_data.get('confidence_score', 0.8)
            )

            return decision

        except Exception as e:
            self.logger.error(f"LLM agent decision failed: {e}")
            raise

    def _manual_agent_selection(self, agents: List[str]) -> AgentDecision:
        """Create decision from manual agent selection"""
        decision = AgentDecision()
        decision.priority_1 = agents
        decision.reasoning = {agent: "Manual selection" for agent in agents}
        return decision

    async def execute_agents(self, target_url: str):
        """
        Phase 3: Execute selected agents in priority order
        """

        # Execute Priority 1 (Critical)
        if self.agent_decision.priority_1:
            print(f"\n🔴 Priority 1 (Critical): {', '.join(self.agent_decision.priority_1)}")
            await self._execute_agent_group(target_url, self.agent_decision.priority_1, parallel=self.config['parallel_p1'])

            # Check for early exit
            if self.config['early_exit'] and self._has_high_severity_findings():
                print(f"\n⚠️  High-severity findings detected!")
                if not self.config['auto_start']:
                    response = input("Continue to Priority 2 tests? [y/N]: ")
                    if response.lower() != 'y':
                        print("Stopping early as requested.")
                        return

        # Execute Priority 2 (High)
        if self.agent_decision.priority_2:
            print(f"\n🟡 Priority 2 (High): {', '.join(self.agent_decision.priority_2)}")
            await self._execute_agent_group(target_url, self.agent_decision.priority_2, parallel=self.config['parallel_p2'])

        # Execute Priority 3 (Medium) - only if configured
        if self.config['run_p3'] and self.agent_decision.priority_3:
            print(f"\n🟢 Priority 3 (Medium): {', '.join(self.agent_decision.priority_3)}")
            await self._execute_agent_group(target_url, self.agent_decision.priority_3, parallel=False)

    async def _execute_agent_group(self, target_url: str, agents: List[str], parallel: bool = True):
        """Execute a group of agents"""

        if parallel:
            # Run all agents in parallel
            tasks = []
            for agent_name in agents:
                tasks.append(self._execute_single_agent(target_url, agent_name))

            await asyncio.gather(*tasks, return_exceptions=True)
        else:
            # Run agents sequentially
            for agent_name in agents:
                await self._execute_single_agent(target_url, agent_name)

                # Interactive mode: pause between agents
                if self.config.get('ask_before_each_phase', False):
                    input(f"\n[Press Enter to continue to next agent, or Ctrl+C to stop]: ")

    async def _execute_single_agent(self, target_url: str, agent_name: str):
        """Execute a single agent"""

        agent_info = self.AGENT_REGISTRY.get(agent_name)
        if not agent_info or not agent_info['available']:
            print(f"  ⚠️  {agent_name}: Not available")
            return

        print(f"\n  ⚡ {agent_name}: Starting...")
        start_time = time.time()

        try:
            # Execute agent
            agent_func = agent_info['func']

            if agent_name == 'xss':
                # XSS agent uses orchestrator
                orchestrator = DynamicXSSOrchestrator()
                result = await orchestrator.verify_xss(target_url)
                # verify_xss returns List[Dict], so check length
                success = len(result) > 0 if isinstance(result, list) else False
                vuln_count = len(result) if isinstance(result, list) else 0
            else:
                # Other agents
                if agent_info['async']:
                    result = await agent_func(target_url)
                else:
                    result = agent_func(target_url)

                success = result if isinstance(result, bool) else result.get('success', False)
                vuln_count = 1 if success else 0

            execution_time = time.time() - start_time

            # Determine severity
            severity = "HIGH" if success else "NONE"

            # Store result
            agent_result = AgentResult(
                agent_name=agent_name,
                success=success,
                vulnerabilities_found=vuln_count,
                severity=severity,
                execution_time=execution_time,
                cost=0.05,  # Estimate
                details=result if isinstance(result, dict) else {}
            )
            self.results.append(agent_result)

            # Display result
            if success:
                print(f"  🎯 {agent_name}: VULNERABLE ({vuln_count} finding(s)) [{execution_time:.1f}s]")
            else:
                print(f"  ✓ {agent_name}: Not vulnerable [{execution_time:.1f}s]")

        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"Agent {agent_name} failed: {e}")

            agent_result = AgentResult(
                agent_name=agent_name,
                success=False,
                vulnerabilities_found=0,
                severity="NONE",
                execution_time=execution_time,
                cost=0.0,
                error=str(e)
            )
            self.results.append(agent_result)

            print(f"  ✗ {agent_name}: Error - {e} [{execution_time:.1f}s]")

    def _has_high_severity_findings(self) -> bool:
        """Check if we have any high-severity findings"""
        return any(r.severity in ["CRITICAL", "HIGH"] for r in self.results)

    def _display_recon_findings(self):
        """Display reconnaissance findings to user"""
        summary = self.recon_findings.get_summary()

        print(f"\n✓ Reconnaissance Complete ({self.recon_time:.1f}s)")
        print("\nFound:")

        # Forms
        forms = summary['forms']
        if forms['login'] > 0:
            print(f"  ✓ {forms['login']} login form(s) → Will test: Default Credentials, SQLi")
        if forms['search'] > 0:
            print(f"  ✓ {forms['search']} search form(s) → Will test: XSS, SQLi")
        if forms['upload'] > 0:
            print(f"  ✓ {forms['upload']} file upload form(s) → Will test: XXE, Arbitrary Upload")
        if forms['comment'] > 0:
            print(f"  ✓ {forms['comment']} comment form(s) → Will test: XSS, Stored XSS")

        # Parameters
        params = summary['parameters']
        total_params = params['get'] + params['post']
        if total_params > 0:
            print(f"  ✓ {total_params} parameter(s) with user input → Will test: XSS, SQLi")

        if params['file_related'] > 0:
            print(f"  ✓ {params['file_related']} file-related parameter(s) → Will test: LFI")

        # Technologies
        tech = summary['technologies']
        if tech['xml_endpoints'] > 0:
            print(f"  ✓ {tech['xml_endpoints']} XML/SOAP endpoint(s) → Will test: XXE")

        if tech['template_engines']:
            print(f"  ✓ Template engine indicators → Will test: SSTI")

        # Attack surface score
        attack_surface_score = min(10, len(self.recon_findings.login_forms) * 2 +
                                         len(self.recon_findings.other_forms) +
                                         len(self.recon_findings.get_parameters) // 3)
        print(f"\nAttack Surface Score: {attack_surface_score}/10 ({'High' if attack_surface_score >= 7 else 'Medium' if attack_surface_score >= 4 else 'Low'})")

    def _display_agent_decision(self):
        """Display agent selection decision"""

        print(f"\n✓ Agent Selection Complete ({self.decision_time:.1f}s)")

        if self.agent_decision.priority_1:
            print(f"\n🔴 Priority 1 (Must Run): {', '.join(self.agent_decision.priority_1)}")
            for agent in self.agent_decision.priority_1:
                if agent in self.agent_decision.reasoning:
                    print(f"   • {agent}: {self.agent_decision.reasoning[agent]}")

        if self.agent_decision.priority_2:
            print(f"\n🟡 Priority 2 (Should Run): {', '.join(self.agent_decision.priority_2)}")
            for agent in self.agent_decision.priority_2:
                if agent in self.agent_decision.reasoning:
                    print(f"   • {agent}: {self.agent_decision.reasoning[agent]}")

        if self.agent_decision.priority_3:
            print(f"\n🟢 Priority 3 (Optional): {', '.join(self.agent_decision.priority_3)}")
            for agent in self.agent_decision.priority_3:
                if agent in self.agent_decision.reasoning:
                    print(f"   • {agent}: {self.agent_decision.reasoning[agent]}")

        if self.agent_decision.skip:
            print(f"\n⚪ Skipping: {', '.join(self.agent_decision.skip)}")

        print(f"\nEstimated Time: {self.agent_decision.estimated_time_minutes} minutes")
        print(f"Estimated Cost: {self.agent_decision.estimated_cost_usd}")

    def _display_final_report(self):
        """Display final report"""
        total_time = time.time() - self.start_time

        print("\n" + "="*70)
        print("📊 FINAL REPORT")
        print("="*70)

        # Summary stats
        total_agents = len(self.results)
        vulnerable_agents = sum(1 for r in self.results if r.success)
        total_vulns = sum(r.vulnerabilities_found for r in self.results)

        print(f"\nAgents Run: {total_agents}")
        print(f"Vulnerabilities Found: {total_vulns}")
        print(f"Total Time: {total_time:.1f}s")
        print(f"  - Reconnaissance: {self.recon_time:.1f}s")
        print(f"  - Decision: {self.decision_time:.1f}s")
        print(f"  - Execution: {self.execution_time:.1f}s")

        # Findings by severity
        if self.results:
            print("\n" + "-"*70)
            print("Findings:")
            print("-"*70)

            for result in self.results:
                status = "🎯 VULNERABLE" if result.success else "✓ Not vulnerable"
                print(f"{result.agent_name:20s} {status:20s} ({result.execution_time:.1f}s)")

                if result.success and result.vulnerabilities_found > 0:
                    print(f"  → {result.vulnerabilities_found} vulnerability/ies found")

        print("\n" + "="*70)

    def _get_results_summary(self) -> Dict[str, Any]:
        """Get results summary for programmatic use"""
        return {
            'target_url': self.recon_findings.target_url if self.recon_findings else None,
            'mode': self.mode,
            'timing': {
                'total': time.time() - self.start_time if self.start_time else 0,
                'reconnaissance': self.recon_time,
                'decision': self.decision_time,
                'execution': self.execution_time
            },
            'recon_findings': self.recon_findings.get_summary() if self.recon_findings else {},
            'agent_decision': {
                'priority_1': self.agent_decision.priority_1 if self.agent_decision else [],
                'priority_2': self.agent_decision.priority_2 if self.agent_decision else [],
                'priority_3': self.agent_decision.priority_3 if self.agent_decision else [],
                'skip': self.agent_decision.skip if self.agent_decision else [],
                'reasoning': self.agent_decision.reasoning if self.agent_decision else {}
            },
            'results': [
                {
                    'agent': r.agent_name,
                    'success': r.success,
                    'vulnerabilities': r.vulnerabilities_found,
                    'severity': r.severity,
                    'time': r.execution_time,
                    'error': r.error
                }
                for r in self.results
            ],
            'summary': {
                'agents_run': len(self.results),
                'vulnerabilities_found': sum(r.vulnerabilities_found for r in self.results),
                'high_severity_count': sum(1 for r in self.results if r.severity in ["CRITICAL", "HIGH"])
            }
        }


async def main():
    """Test the intelligent orchestrator"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python intelligent_orchestrator.py <URL> [--mode MODE] [--focus AGENTS] [--skip AGENTS]")
        print("\nModes: default, aggressive, fast, interactive")
        print("Example: python intelligent_orchestrator.py https://example.com --mode aggressive")
        print("Example: python intelligent_orchestrator.py https://example.com --focus sqli,xss")
        sys.exit(1)

    target_url = sys.argv[1]
    mode = 'default'
    focus = None
    skip = None

    # Parse args
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '--mode' and i + 1 < len(sys.argv):
            mode = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--focus' and i + 1 < len(sys.argv):
            focus = sys.argv[i + 1].split(',')
            i += 2
        elif sys.argv[i] == '--skip' and i + 1 < len(sys.argv):
            skip = sys.argv[i + 1].split(',')
            i += 2
        else:
            i += 1

    # Create and run orchestrator
    orchestrator = IntelligentOrchestrator(
        mode=mode,
        focus_agents=focus,
        skip_agents=skip
    )

    results = await orchestrator.run(target_url)

    # Save results
    output_file = f"results/intelligent_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    Path("results").mkdir(exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\n✓ Results saved to: {output_file}")


if __name__ == "__main__":
    asyncio.run(main())
