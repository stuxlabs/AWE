"""
Context-Aware IDOR Orchestrator - Purely LLM-Driven

IDOR is inherently context-dependent, requiring understanding of:
- Application business logic
- Object ownership and access control
- What data should be protected

Therefore, IDOR testing is PURELY context-aware from the start:
1. Discover & analyze endpoints (light reconnaissance)
2. Generate LLM test cases (context-aware)
3. LLM analyzes responses (intelligent detection)
"""
from dataclasses import dataclass
from typing import List, Optional, Callable, Awaitable, Dict, Tuple
import asyncio

from .analyzers.context_analyzer import IDORContextAnalyzer, IDOREndpoint, ApplicationContext
from .analyzers.llm_idor_engine import IDORLLMEngine, IDORTestCase, IDORVulnerability


@dataclass
class IDORTestResult:
    """Result of IDOR testing"""
    vulnerable: bool
    vulnerabilities: List[IDORVulnerability]
    endpoints_tested: int
    test_cases_generated: int
    test_cases_executed: int
    reasoning: str


class ContextAwareIDOROrchestrator:
    """
    Orchestrates IDOR testing with pure LLM-driven approach

    No rule-based phase - IDOR requires context understanding from the start
    """

    def __init__(self, llm_client, cost_tracker=None):
        self.context_analyzer = IDORContextAnalyzer()
        self.llm_engine = IDORLLMEngine(llm_client, cost_tracker)
        self.cost_tracker = cost_tracker

    async def test_application(
        self,
        base_url: str,
        discovered_endpoints: List[Dict],  # List of {url, method, params, response, ...}
        auth_header: Optional[str] = None,
        submit_func: Callable[[str, str, Dict], Awaitable[Tuple[str, int]]] = None  # (url, method, params) -> (response, status)
    ) -> IDORTestResult:
        """
        Test application for IDOR vulnerabilities

        Args:
            base_url: Base URL of application
            discovered_endpoints: List of discovered endpoints with their details
            auth_header: Authentication header (cookie, JWT, etc.)
            submit_func: Function to submit test requests

        Returns:
            IDORTestResult
        """

        print(f"\n{'='*70}")
        print(f"IDOR TESTING (Pure Context-Aware)")
        print(f"{'='*70}\n")

        vulnerabilities = []
        test_cases_generated = 0
        test_cases_executed = 0

        # ========================================================================
        # PHASE 1: Endpoint Discovery & Analysis
        # ========================================================================
        print("📍 PHASE 1: Endpoint Discovery & Context Analysis")
        print("-" * 70)

        # Analyze each endpoint to find IDOR candidates
        idor_endpoints = []

        for endpoint_data in discovered_endpoints:
            url = endpoint_data.get('url')
            method = endpoint_data.get('method', 'GET')
            params = endpoint_data.get('params', {})
            response = endpoint_data.get('response', '')
            response_size = len(response)

            print(f"  Analyzing: {method} {url}")

            # Check if this endpoint is an IDOR candidate
            idor_endpoint = self.context_analyzer.analyze_endpoint(
                url=url,
                method=method,
                parameters=params,
                response=response,
                response_size=response_size,
                auth_header=auth_header
            )

            if idor_endpoint:
                idor_endpoints.append(idor_endpoint)
                print(f"    ✅ IDOR candidate found!")
                print(f"       Parameter: {idor_endpoint.id_parameter}")
                print(f"       ID Format: {idor_endpoint.id_format.value}")
                print(f"       Object Type: {idor_endpoint.object_type.value}")

        if not idor_endpoints:
            print("  ❌ No IDOR candidates found")
            return IDORTestResult(
                vulnerable=False,
                vulnerabilities=[],
                endpoints_tested=len(discovered_endpoints),
                test_cases_generated=0,
                test_cases_executed=0,
                reasoning="No endpoints with ID parameters found"
            )

        print(f"\n  ✅ Found {len(idor_endpoints)} IDOR candidate(s)")

        # Build application context
        app_context = self.context_analyzer.build_application_context(
            endpoints=idor_endpoints,
            auth_header=auth_header
        )

        print(f"\n  Application Context:")
        print(f"    Auth Mechanism: {app_context.auth_mechanism}")
        print(f"    ID Formats: {', '.join(set(f.value for f in app_context.id_patterns.values()))}")
        print(f"    Object Types: {', '.join(set(t.value for t in app_context.object_types.values()))}")

        # ========================================================================
        # PHASE 1.5: Privilege Escalation Detection & Testing
        # ========================================================================
        print(f"\n📍 PHASE 1.5: Privilege Escalation Testing (Vertical IDOR)")
        print("-" * 70)

        priv_esc_results = await self._test_privilege_escalation(
            discovered_endpoints=discovered_endpoints,
            idor_endpoints=idor_endpoints,
            submit_func=submit_func
        )

        if priv_esc_results['vulnerable']:
            vulnerabilities.extend(priv_esc_results['vulnerabilities'])
            print(f"  🚨 Found {len(priv_esc_results['vulnerabilities'])} privilege escalation vulnerability(ies)!")

        # ========================================================================
        # PHASE 2: LLM Test Case Generation (Context-Aware)
        # ========================================================================
        print(f"\n📍 PHASE 2: LLM Test Case Generation (Horizontal IDOR)")
        print("-" * 70)

        all_test_cases = []

        for endpoint in idor_endpoints:
            print(f"\n  Generating tests for: {endpoint.url}")
            print(f"    Parameter: {endpoint.id_parameter} = {endpoint.id_value}")

            # Generate context-aware test cases
            test_cases = await self.llm_engine.generate_test_cases(
                app_context=app_context,
                target_endpoint=endpoint,
                num_tests=10
            )

            if not test_cases:
                print(f"    ❌ Failed to generate test cases")
                continue

            print(f"    ✅ Generated {len(test_cases)} test cases")
            test_cases_generated += len(test_cases)

            # Add baseline info to test cases
            for test_case in test_cases:
                test_case.baseline_id = endpoint.id_value
                test_case.baseline_response = endpoint  # Store endpoint ref

            all_test_cases.extend(test_cases)

        if not all_test_cases:
            print("\n  ❌ No test cases generated")
            return IDORTestResult(
                vulnerable=False,
                vulnerabilities=[],
                endpoints_tested=len(idor_endpoints),
                test_cases_generated=0,
                test_cases_executed=0,
                reasoning="LLM failed to generate test cases"
            )

        print(f"\n  ✅ Total test cases: {len(all_test_cases)}")

        # ========================================================================
        # PHASE 3: Execute Tests & LLM Analysis
        # ========================================================================
        print(f"\n📍 PHASE 3: Test Execution & Analysis")
        print("-" * 70)

        if not submit_func:
            print("  ⚠️  No submit function provided, cannot execute tests")
            return IDORTestResult(
                vulnerable=False,
                vulnerabilities=[],
                endpoints_tested=len(idor_endpoints),
                test_cases_generated=test_cases_generated,
                test_cases_executed=0,
                reasoning="No submit function provided"
            )

        # Execute tests
        for i, test_case in enumerate(all_test_cases, 1):
            print(f"\n  Test {i}/{len(all_test_cases)}:")
            print(f"    Endpoint: {test_case.target_endpoint}")
            print(f"    Parameter: {test_case.parameter}")
            print(f"    Test ID: {test_case.test_id}")
            print(f"    Technique: {test_case.technique}")
            print(f"    Confidence: {test_case.confidence}")
            print(f"    Reasoning: {test_case.reasoning[:100]}...")

            try:
                # Find original endpoint for baseline
                original_endpoint = next(
                    (ep for ep in idor_endpoints if ep.url == test_case.target_endpoint),
                    None
                )

                if not original_endpoint:
                    print(f"    ❌ Cannot find baseline endpoint")
                    continue

                # Get baseline response (with original ID)
                baseline_params = {test_case.parameter: original_endpoint.id_value}
                baseline_response, baseline_status = await submit_func(
                    original_endpoint.url,
                    original_endpoint.method,
                    baseline_params
                )

                # Execute test with modified ID
                test_params = {test_case.parameter: test_case.test_id}
                test_response, test_status = await submit_func(
                    test_case.target_endpoint,
                    original_endpoint.method,
                    test_params
                )

                test_cases_executed += 1

                print(f"    Response Status: {test_status}")
                print(f"    Response Length: {len(test_response)} bytes")

                # Quick check: if 403/401, likely not vulnerable
                if test_status in [401, 403]:
                    print(f"    ✓ Blocked by authorization (status {test_status})")
                    continue

                # LLM analyzes the response
                print(f"    Analyzing response with LLM...")
                vulnerability = await self.llm_engine.analyze_response(
                    test_case=test_case,
                    baseline_response=baseline_response,
                    test_response=test_response,
                    baseline_auth=auth_header or "",
                    original_id=original_endpoint.id_value
                )

                if vulnerability:
                    print(f"    🚨 VULNERABILITY DETECTED!")
                    print(f"       Severity: {vulnerability.severity}")
                    print(f"       Evidence: {vulnerability.evidence[:150]}...")
                    print(f"       Impact: {vulnerability.business_impact[:150]}...")
                    vulnerabilities.append(vulnerability)
                else:
                    print(f"    ✓ Not vulnerable")

            except Exception as e:
                print(f"    ❌ Test execution error: {e}")
                continue

        # ========================================================================
        # Final Report
        # ========================================================================
        print(f"\n{'='*70}")
        print(f"IDOR TESTING COMPLETE")
        print(f"{'='*70}")

        vulnerable = len(vulnerabilities) > 0

        if vulnerable:
            print(f"\n🚨 VULNERABILITIES FOUND: {len(vulnerabilities)}")
            for vuln in vulnerabilities:
                print(f"\n  Endpoint: {vuln.endpoint}")
                print(f"  Parameter: {vuln.parameter}")
                print(f"  Severity: {vuln.severity.upper()}")
                print(f"  Technique: {vuln.technique}")
                print(f"  Evidence: {vuln.evidence}")
                print(f"  Impact: {vuln.business_impact}")
        else:
            print(f"\n✓ No IDOR vulnerabilities detected")

        return IDORTestResult(
            vulnerable=vulnerable,
            vulnerabilities=vulnerabilities,
            endpoints_tested=len(idor_endpoints),
            test_cases_generated=test_cases_generated,
            test_cases_executed=test_cases_executed,
            reasoning=f"Tested {test_cases_executed} cases, found {len(vulnerabilities)} vulnerabilities"
        )

    async def _test_privilege_escalation(
        self,
        discovered_endpoints: List[Dict],
        idor_endpoints: List[IDOREndpoint],
        submit_func: Optional[Callable] = None
    ) -> Dict:
        """
        Test for privilege escalation (vertical IDOR) vulnerabilities

        Detects fields like is_admin, role, permissions and tests setting them to escalated values
        Then chains with accessing restricted resources
        """

        vulnerabilities = []

        if not submit_func:
            return {'vulnerable': False, 'vulnerabilities': []}

        # Privilege escalation field patterns
        priv_fields = ['is_admin', 'admin', 'is_superuser', 'superuser', 'role',
                       'privileges', 'permissions', 'is_staff', 'staff', 'access_level']

        # Find endpoints with privilege fields
        priv_endpoints = []
        for ep_data in discovered_endpoints:
            form_fields = ep_data.get('form_fields', [])

            # Check if any form field is a privilege field
            for field in form_fields:
                if any(priv_pattern in field.lower() for priv_pattern in priv_fields):
                    priv_endpoints.append({
                        'endpoint': ep_data,
                        'priv_field': field
                    })
                    print(f"  ✅ Found privilege field '{field}' in {ep_data['url']}")
                    break

        if not priv_endpoints:
            print(f"  ℹ️  No privilege escalation fields detected")
            return {'vulnerable': False, 'vulnerabilities': []}

        print(f"  ✅ Found {len(priv_endpoints)} endpoint(s) with privilege fields")

        # Test each privilege escalation opportunity
        for priv_ep in priv_endpoints:
            ep_data = priv_ep['endpoint']
            priv_field = priv_ep['priv_field']

            url = ep_data['url']
            method = ep_data['method']
            form_fields = ep_data['form_fields']

            print(f"\n  Testing privilege escalation: {url}")
            print(f"    Field: {priv_field}")

            # Build params with privilege escalation
            escalated_params = {}

            # Fill form fields with test values
            for field in form_fields:
                if field == priv_field:
                    # Set privilege field to escalated value
                    if 'role' in field.lower():
                        escalated_params[field] = 'admin'
                    else:
                        escalated_params[field] = '1'  # or 'true'
                elif 'name' in field.lower():
                    escalated_params[field] = 'test_user'
                else:
                    escalated_params[field] = 'test'

            print(f"    Setting {priv_field}={escalated_params[priv_field]}")

            try:
                # Execute privilege escalation
                esc_response, esc_status = await submit_func(url, method, escalated_params)

                print(f"    Response status: {esc_status}")

                # Now test accessing restricted resources
                print(f"    Testing access to restricted resources...")

                # Find other endpoints that might be restricted
                restricted_endpoints = []
                for ep in discovered_endpoints:
                    ep_url = ep['url']
                    # Look for admin/company/private/job endpoints
                    if any(keyword in ep_url.lower() for keyword in ['admin', 'company', 'jobs', 'private', 'settings']):
                        if ep_url != url:  # Don't test the escalation endpoint itself
                            restricted_endpoints.append(ep)

                if not restricted_endpoints:
                    print(f"    ⚠️  No restricted endpoints found to test")
                    continue

                # Test accessing restricted resources
                for restricted_ep in restricted_endpoints:
                    rest_url = restricted_ep['url']
                    rest_method = restricted_ep.get('method', 'GET')
                    rest_params = restricted_ep.get('params', {})

                    print(f"      → Testing access to: {rest_url}")

                    try:
                        rest_response, rest_status = await submit_func(rest_url, rest_method, rest_params)

                        # Check if response contains sensitive data/flags
                        if 'FLAG{' in rest_response or 'flag{' in rest_response:
                            print(f"        🚨 FLAG FOUND! Privilege escalation successful!")

                            # Extract flag
                            import re
                            flag_match = re.search(r'FLAG\{[^\}]+\}', rest_response, re.IGNORECASE)
                            flag = flag_match.group(0) if flag_match else "FLAG detected"

                            vuln = IDORVulnerability(
                                endpoint=url,
                                parameter=priv_field,
                                original_id='user',
                                vulnerable_id='admin',
                                technique='Vertical Privilege Escalation',
                                evidence=f"Set {priv_field}=1, then accessed {rest_url} and found: {flag}",
                                severity='critical',
                                business_impact=f"Attacker can escalate to admin privileges and access all restricted data including flags"
                            )
                            vulnerabilities.append(vuln)

                        # Check for other indicators of success
                        elif ('private' in rest_response.lower() or
                              'confidential' in rest_response.lower() or
                              len(rest_response) > 500):  # Substantial response
                            print(f"        ⚠️  Potentially sensitive data accessed (response: {len(rest_response)} bytes)")

                    except Exception as e:
                        print(f"        ✗ Error testing {rest_url}: {e}")
                        continue

            except Exception as e:
                print(f"    ✗ Error during privilege escalation: {e}")
                continue

        return {
            'vulnerable': len(vulnerabilities) > 0,
            'vulnerabilities': vulnerabilities
        }

    def generate_report(self, result: IDORTestResult) -> str:
        """Generate detailed IDOR testing report"""

        report = []
        report.append("\n" + "="*70)
        report.append("IDOR TESTING REPORT")
        report.append("="*70)

        report.append(f"\n🎯 Result: {'VULNERABLE' if result.vulnerable else 'NOT VULNERABLE'}")
        report.append(f"📊 Endpoints Tested: {result.endpoints_tested}")
        report.append(f"🧪 Test Cases Generated: {result.test_cases_generated}")
        report.append(f"⚡ Test Cases Executed: {result.test_cases_executed}")

        if result.vulnerabilities:
            report.append(f"\n🚨 VULNERABILITIES FOUND: {len(result.vulnerabilities)}")

            for i, vuln in enumerate(result.vulnerabilities, 1):
                report.append(f"\n  --- Vulnerability {i} ---")
                report.append(f"  Endpoint: {vuln.endpoint}")
                report.append(f"  Parameter: {vuln.parameter}")
                report.append(f"  Original ID: {vuln.original_id}")
                report.append(f"  Vulnerable ID: {vuln.vulnerable_id}")
                report.append(f"  Severity: {vuln.severity.upper()}")
                report.append(f"  Technique: {vuln.technique}")
                report.append(f"  Evidence: {vuln.evidence}")
                report.append(f"  Business Impact: {vuln.business_impact}")

        report.append(f"\n💡 Summary: {result.reasoning}")
        report.append("\n" + "="*70)

        return "\n".join(report)
