"""
LLM-powered IDOR testing with context understanding
"""
from dataclasses import dataclass
from typing import List, Dict, Optional
from .context_analyzer import IDOREndpoint, ApplicationContext, IDFormat, ObjectType


@dataclass
class IDORTestCase:
    """A generated IDOR test case"""
    target_endpoint: str
    parameter: str
    test_id: str
    technique: str
    reasoning: str
    expected_behavior: str  # What should happen if NOT vulnerable
    vulnerability_indicator: str  # What indicates it IS vulnerable
    confidence: float


@dataclass
class IDORVulnerability:
    """Detected IDOR vulnerability"""
    endpoint: str
    parameter: str
    original_id: str
    vulnerable_id: str
    technique: str
    evidence: str
    severity: str  # critical, high, medium, low
    business_impact: str


class IDORLLMEngine:
    """Generates intelligent IDOR test cases using LLM understanding"""

    def __init__(self, llm_client, cost_tracker=None):
        self.llm_client = llm_client
        self.cost_tracker = cost_tracker

    async def generate_test_cases(
        self,
        app_context: ApplicationContext,
        target_endpoint: IDOREndpoint,
        num_tests: int = 10
    ) -> List[IDORTestCase]:
        """
        Generate intelligent IDOR test cases based on application context

        Args:
            app_context: Full application context
            target_endpoint: Specific endpoint to test
            num_tests: Number of test cases to generate

        Returns:
            List of IDORTestCase objects
        """

        prompt = self._build_test_generation_prompt(
            app_context, target_endpoint, num_tests
        )

        try:
            # Get model and call LLM properly
            from src.xss_agent.llm_client import get_default_model
            model = get_default_model()

            messages = [{"role": "user", "content": prompt}]

            llm_response = self.llm_client.chat_completion(
                model=model,
                messages=messages,
                max_tokens=3000,
                temperature=0.7
            )

            response = llm_response["choices"][0]["message"]["content"]

            if self.cost_tracker:
                self.cost_tracker.add_call("idor_test_generation", tokens=3000)

            return self._parse_test_cases(response, target_endpoint)

        except Exception as e:
            print(f"    ❌ LLM test generation failed: {e}")
            return []

    def _build_test_generation_prompt(
        self,
        app_context: ApplicationContext,
        endpoint: IDOREndpoint,
        num_tests: int
    ) -> str:
        """Build prompt for generating IDOR test cases"""

        prompt = f"""You are a penetration testing expert specializing in IDOR (Insecure Direct Object Reference) vulnerabilities.

APPLICATION CONTEXT:
"""

        # Add endpoint information
        prompt += f"""
TARGET ENDPOINT:
- URL: {endpoint.url}
- Method: {endpoint.method}
- ID Parameter: {endpoint.id_parameter}
- Current ID: {endpoint.id_value}
- ID Format: {endpoint.id_format.value}
- Object Type: {endpoint.object_type.value}
- Requires Auth: {endpoint.requires_auth}
- Response Size: {endpoint.response_size} bytes
"""

        if endpoint.response_indicators:
            prompt += f"- Success Indicators: {', '.join(endpoint.response_indicators)}\n"

        # Add application-wide context
        prompt += f"""
APPLICATION PATTERNS:
- Auth Mechanism: {app_context.auth_mechanism}
- Total Endpoints: {len(app_context.endpoints)}
- ID Formats Seen: {', '.join(f.value for f in set(app_context.id_patterns.values()))}
- Object Types: {', '.join(t.value for t in set(app_context.object_types.values()))}
"""

        # Add IDOR-specific guidance
        prompt += f"""
IDOR VULNERABILITY EXPLANATION:
IDOR occurs when an application uses user-supplied input (like an ID) to access objects
directly without proper authorization checks. An attacker can manipulate IDs to access
other users' data.

TESTING STRATEGY:
"""

        if endpoint.id_format == IDFormat.NUMERIC:
            prompt += """
For NUMERIC IDs:
- Try sequential IDs: 1, 2, 3 (if current is 5, try 4, 6, etc.)
- Try common IDs: 0, 1, 100, 1000
- Try negative IDs: -1, -100
- Try large IDs: 999999, 2147483647
- Business logic: Lower IDs often belong to admin/first users
"""
        elif endpoint.id_format == IDFormat.UUID:
            prompt += """
For UUID IDs:
- Try null UUID: 00000000-0000-0000-0000-000000000000
- Try sequential UUIDs: increment last segment
- UUIDs are harder to guess, but may still lack authorization checks
"""
        elif endpoint.id_format == IDFormat.USERNAME:
            prompt += """
For USERNAME IDs:
- Try common usernames: admin, root, administrator, test, demo
- Try service accounts: support, moderator, system
- Try enumerating from other endpoints
"""

        # Object-specific guidance
        if endpoint.object_type == ObjectType.USER:
            prompt += """
For USER objects:
- Critical: Accessing other users' profiles, emails, personal info
- Try admin/root users
- Look for privilege escalation opportunities
"""
        elif endpoint.object_type == ObjectType.ORDER:
            prompt += """
For ORDER objects:
- Critical: Accessing other users' orders, financial data
- Try sequential order IDs
- Business impact: Financial loss, privacy breach
"""
        elif endpoint.object_type == ObjectType.FILE:
            prompt += """
For FILE objects:
- Critical: Accessing confidential documents
- Try traversal: ../file, ../../file
- Try common file names: flag, secret, admin
"""

        prompt += f"""
TASK: Generate {num_tests} IDOR test cases for this endpoint.

For each test case, consider:
1. What ID should be tested and why?
2. What authorization check is likely missing?
3. What response indicates successful unauthorized access?
4. What is the business impact if successful?

IMPORTANT:
- Focus on realistic IDs that might exist
- Consider the business context (order IDs, user IDs, etc.)
- Think about what an attacker would try
- Prioritize high-impact tests

FORMAT (exactly as shown):
TEST_ID: <the_id_value_to_test>
TECHNIQUE: <testing_technique_name>
REASONING: <why_test_this_id>
EXPECTED_BEHAVIOR: <what_should_happen_if_secure>
VULNERABILITY_INDICATOR: <what_indicates_IDOR>
CONFIDENCE: <0.0-1.0>
---

Generate {num_tests} test cases ordered by priority (most likely to find IDOR first).
"""

        return prompt

    def _parse_test_cases(self, response: str, endpoint: IDOREndpoint) -> List[IDORTestCase]:
        """Parse LLM response into test cases"""

        test_cases = []
        blocks = response.split('---')

        for block in blocks:
            block = block.strip()
            if not block:
                continue

            test_id = None
            technique = None
            reasoning = ""
            expected = ""
            indicator = ""
            confidence = 0.5

            for line in block.split('\n'):
                line = line.strip()
                if line.startswith('TEST_ID:'):
                    test_id = line[8:].strip()
                elif line.startswith('TECHNIQUE:'):
                    technique = line[10:].strip()
                elif line.startswith('REASONING:'):
                    reasoning = line[10:].strip()
                elif line.startswith('EXPECTED_BEHAVIOR:'):
                    expected = line[18:].strip()
                elif line.startswith('VULNERABILITY_INDICATOR:'):
                    indicator = line[24:].strip()
                elif line.startswith('CONFIDENCE:'):
                    try:
                        confidence = float(line[11:].strip())
                    except:
                        confidence = 0.5

            if test_id and technique:
                test_cases.append(IDORTestCase(
                    target_endpoint=endpoint.url,
                    parameter=endpoint.id_parameter,
                    test_id=test_id,
                    technique=technique,
                    reasoning=reasoning,
                    expected_behavior=expected,
                    vulnerability_indicator=indicator,
                    confidence=confidence
                ))

        return test_cases

    async def analyze_response(
        self,
        test_case: IDORTestCase,
        baseline_response: str,
        test_response: str,
        baseline_auth: str,
        original_id: str
    ) -> Optional[IDORVulnerability]:
        """
        Analyze if a test response indicates IDOR vulnerability

        Args:
            test_case: The test case that was executed
            baseline_response: Response with original ID
            test_response: Response with test ID
            baseline_auth: Auth used (to confirm we're testing with same user)
            original_id: Original ID value

        Returns:
            IDORVulnerability if detected, None otherwise
        """

        prompt = f"""You are analyzing a potential IDOR (Insecure Direct Object Reference) vulnerability.

TEST CONTEXT:
- Endpoint: {test_case.target_endpoint}
- Parameter: {test_case.parameter}
- Original ID: {original_id}
- Test ID: {test_case.test_id}
- Technique: {test_case.technique}
- Expected Secure Behavior: {test_case.expected_behavior}
- Vulnerability Indicator: {test_case.vulnerability_indicator}

BASELINE RESPONSE (with original ID = {original_id}):
Length: {len(baseline_response)} bytes
Content (first 1000 chars):
{baseline_response[:1000]}

TEST RESPONSE (with test ID = {test_case.test_id}):
Length: {len(test_response)} bytes
Content (first 1000 chars):
{test_response[:1000]}

TASK: Analyze if this is a confirmed IDOR vulnerability.

Consider:
1. Did we successfully access data belonging to ID {test_case.test_id}?
2. Is the data different from our original data (ID {original_id})?
3. Should we have been able to access this data?
4. What is the business impact?

VULNERABLE if:
- Response contains data for {test_case.test_id}
- Response is successful (200 OK, valid JSON/HTML)
- Data is different from baseline
- No authorization error (403, 401)

NOT VULNERABLE if:
- Response shows error (403 Forbidden, 401 Unauthorized, 404 Not Found)
- Response is empty or error message
- Response is identical to baseline
- Response size indicates no data returned

Respond ONLY with one of:
1. VULNERABLE - <severity> - <evidence> - <impact>
2. NOT_VULNERABLE - <reason>

Where:
- severity: critical, high, medium, low
- evidence: What proves unauthorized access
- impact: Business impact description
- reason: Why it's not vulnerable

Example:
VULNERABLE - critical - Response contains email 'admin@test.com' for user_id=1 while authenticated as user_id=5 - Attacker can access any user's profile including admins

Or:
NOT_VULNERABLE - Received 403 Forbidden response
"""

        try:
            # Get model and call LLM properly
            from src.xss_agent.llm_client import get_default_model
            model = get_default_model()

            messages = [{"role": "user", "content": prompt}]

            llm_response = self.llm_client.chat_completion(
                model=model,
                messages=messages,
                max_tokens=500,
                temperature=0.3  # Lower temp for analysis
            )

            response = llm_response["choices"][0]["message"]["content"]
            response = response.strip()

            if response.startswith('VULNERABLE'):
                # Parse: VULNERABLE - severity - evidence - impact
                parts = response.split(' - ', 3)
                if len(parts) >= 4:
                    severity = parts[1].strip()
                    evidence = parts[2].strip()
                    impact = parts[3].strip()

                    return IDORVulnerability(
                        endpoint=test_case.target_endpoint,
                        parameter=test_case.parameter,
                        original_id=original_id,
                        vulnerable_id=test_case.test_id,
                        technique=test_case.technique,
                        evidence=evidence,
                        severity=severity,
                        business_impact=impact
                    )

            return None

        except Exception as e:
            print(f"    ❌ Response analysis failed: {e}")
            return None
