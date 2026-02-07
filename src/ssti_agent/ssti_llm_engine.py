"""
LLM-powered SSTI payload generation
"""
from dataclasses import dataclass
from typing import List
from .ssti_detector import TemplateEngine


@dataclass
class SSTIPayload:
    """Generated SSTI payload"""
    payload: str
    technique: str
    confidence: float
    reasoning: str
    expected_output: str


class SSTILLMEngine:
    """Generates SSTI payloads using LLM"""

    def __init__(self, llm_client):
        self.llm_client = llm_client

    async def generate_rce_payloads(
        self,
        engine: TemplateEngine,
        context_before: str,
        context_after: str,
        num_payloads: int = 5
    ) -> List[SSTIPayload]:
        """
        Generate context-aware SSTI RCE payloads

        Args:
            engine: Detected template engine
            context_before: Text before injection point
            context_after: Text after injection point
            num_payloads: Number of payloads to generate

        Returns:
            List of SSTIPayload objects
        """

        prompt = f"""You are a penetration testing expert specializing in Server-Side Template Injection (SSTI).

DETECTED TEMPLATE ENGINE: {engine.value}

INJECTION CONTEXT:
Before: ...{context_before[-100:]}
After: {context_after[:100]}...

TASK: Generate {num_payloads} SSTI payloads for remote code execution that will:
1. Execute the command "cat /flag.txt" or "cat /flag" or find flag files
2. Be syntactically correct for {engine.value}
3. Work in the given injection context
4. Bypass common filters if present

For each payload, provide:
1. The exact payload string
2. The technique used
3. Confidence (0.0-1.0)
4. Brief reasoning
5. Expected output pattern

Format each payload as:
PAYLOAD: <payload>
TECHNIQUE: <technique>
CONFIDENCE: <0.0-1.0>
REASONING: <why this might work>
EXPECTED: <what output to look for>
---

Generate {num_payloads} different payloads with varying techniques."""

        try:
            response = await self.llm_client.generate(
                prompt=prompt,
                max_tokens=2000,
                temperature=0.7
            )

            return self._parse_llm_response(response)

        except Exception as e:
            print(f"    LLM generation failed: {e}")
            return []

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
