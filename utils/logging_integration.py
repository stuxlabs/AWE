#!/usr/bin/env python3
"""
Logging Integration Module

This module provides integration points for adding forensic logging to existing
XSS testing agents without modifying their core functionality.
"""

import functools
import json
import uuid
from datetime import datetime
from typing import Any, Callable, Dict, Optional
from pathlib import Path

from utils.forensic_logger import ForensicLoggerManager


class LoggingIntegration:
    """
    Integration wrapper that adds forensic logging to existing agents
    """
    
    def __init__(self, logger_manager: ForensicLoggerManager):
        """
        Initialize integration with logger manager
        
        Args:
            logger_manager: Configured ForensicLoggerManager instance
        """
        self.logger_manager = logger_manager
        self.current_attempt_id: Optional[str] = None
        self.current_vulnerability_id: Optional[str] = None
    
    def start_attempt(self, vulnerability_id: str, context: Dict[str, Any]) -> str:
        """
        Start tracking a new payload attempt
        
        Args:
            vulnerability_id: ID of the vulnerability being tested
            context: Context information for the attempt
            
        Returns:
            Generated attempt ID
        """
        self.current_attempt_id = str(uuid.uuid4())[:12]  # Short UUID
        self.current_vulnerability_id = vulnerability_id
        
        # Log attempt start
        self.logger_manager.log_attempt_started(
            self.current_attempt_id,
            vulnerability_id,
            context
        )
        
        return self.current_attempt_id
    
    def log_llm_call(self, prompt: str, response: str, model: str = None, interaction_type: str = 'generation'):
        """
        Log an LLM interaction
        
        Args:
            prompt: Prompt sent to LLM
            response: Response from LLM
            model: Model name
            interaction_type: Type of interaction
        """
        return self.logger_manager.log_llm_interaction(
            prompt=prompt,
            response=response,
            model=model,
            attempt_id=self.current_attempt_id,
            interaction_type=interaction_type
        )
    
    def log_http_call(self, request: Dict[str, Any], response: Dict[str, Any]):
        """
        Log HTTP request/response
        
        Args:
            request: Request data
            response: Response data
        """
        return self.logger_manager.log_http_request_response(
            request=request,
            response=response,
            attempt_id=self.current_attempt_id
        )
    
    def log_verification(self, verification_data: Dict[str, Any]):
        """
        Log Playwright verification
        
        Args:
            verification_data: Verification result data
        """
        return self.logger_manager.log_playwright_verification(
            verification_data=verification_data,
            attempt_id=self.current_attempt_id
        )
    
    def log_failure(self, payload: str, failure_report: Dict[str, Any]):
        """
        Log failure analysis
        
        Args:
            payload: Failed payload
            failure_report: Failure analysis report
        """
        self.logger_manager.log_failure_analysis(
            payload=payload,
            failure_report=failure_report,
            attempt_id=self.current_attempt_id
        )
    
    def finish_attempt(self, payload: str, result: str, artifacts: Dict[str, Any] = None):
        """
        Complete the current attempt
        
        Args:
            payload: The tested payload
            result: Result status
            artifacts: Additional artifacts
        """
        if self.current_attempt_id:
            self.logger_manager.log_attempt_finished(
                self.current_attempt_id,
                payload,
                result,
                artifacts
            )
            
            # Reset for next attempt
            self.current_attempt_id = None


def with_forensic_logging(logger_integration: LoggingIntegration):
    """
    Decorator to add forensic logging to methods
    
    Args:
        logger_integration: LoggingIntegration instance
    """
    def decorator(func: Callable):
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            # Extract context from method arguments
            method_name = func.__name__
            class_name = args[0].__class__.__name__ if args else 'Unknown'
            
            # Log method entry
            logger_integration.logger_manager.log_event(f'method.{method_name}.started', {
                'class': class_name,
                'method': method_name,
                'args_count': len(args),
                'kwargs_keys': list(kwargs.keys())
            })
            
            try:
                result = await func(*args, **kwargs)
                
                # Log successful completion
                logger_integration.logger_manager.log_event(f'method.{method_name}.completed', {
                    'class': class_name,
                    'method': method_name,
                    'success': True
                })
                
                return result
                
            except Exception as e:
                # Log error
                logger_integration.logger_manager.log_event(f'method.{method_name}.error', {
                    'class': class_name,
                    'method': method_name,
                    'error': str(e),
                    'error_type': type(e).__name__
                })
                raise
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            # Similar logic for synchronous functions
            method_name = func.__name__
            class_name = args[0].__class__.__name__ if args else 'Unknown'
            
            logger_integration.logger_manager.log_event(f'method.{method_name}.started', {
                'class': class_name,
                'method': method_name,
                'args_count': len(args),
                'kwargs_keys': list(kwargs.keys())
            })
            
            try:
                result = func(*args, **kwargs)
                
                logger_integration.logger_manager.log_event(f'method.{method_name}.completed', {
                    'class': class_name,
                    'method': method_name,
                    'success': True
                })
                
                return result
                
            except Exception as e:
                logger_integration.logger_manager.log_event(f'method.{method_name}.error', {
                    'class': class_name,
                    'method': method_name,
                    'error': str(e),
                    'error_type': type(e).__name__
                })
                raise
        
        # Return appropriate wrapper based on function type
        if hasattr(func, '__code__') and func.__code__.co_flags & 0x80:  # CO_COROUTINE
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


class EnhancedOrchestrator:
    """
    Enhanced orchestrator that wraps existing orchestrator with forensic logging
    """
    
    def __init__(self, original_orchestrator, forensic_logger: ForensicLoggerManager):
        """
        Initialize enhanced orchestrator
        
        Args:
            original_orchestrator: Original DynamicXSSOrchestrator instance
            forensic_logger: ForensicLoggerManager instance
        """
        self.original = original_orchestrator
        self.forensic_logger = forensic_logger
        self.integration = LoggingIntegration(forensic_logger)
        
        # Store original methods for delegation
        self._original_verify_xss = original_orchestrator.verify_xss
        self._original_cleanup = original_orchestrator.cleanup
        self._original_save_results = original_orchestrator.save_results
    
    async def verify_xss(self, target_url: str) -> Dict[str, Any]:
        """Enhanced verify_xss with comprehensive logging"""
        
        # Start forensic logging run
        correlation_id = self.forensic_logger.start_run(target_url)
        
        try:
            # Log the start of verification
            self.forensic_logger.log_event('verification.started', {
                'target_url': target_url,
                'correlation_id': correlation_id
            })
            
            # Call original method with enhanced logging
            results = await self._enhanced_verify_xss_with_logging(target_url)
            
            # Log successful completion
            self.forensic_logger.log_event('verification.completed', {
                'target_url': target_url,
                'correlation_id': correlation_id,
                'vulnerabilities_found': len(results),
                'successful_exploits': sum(1 for r in results if r.get('successful', False))
            })
            
            return results
            
        except Exception as e:
            # Log error
            self.forensic_logger.log_event('verification.error', {
                'target_url': target_url,
                'correlation_id': correlation_id,
                'error': str(e),
                'error_type': type(e).__name__
            })
            raise
            
        finally:
            # Finish forensic logging run
            self.forensic_logger.finish_run()
    
    async def _enhanced_verify_xss_with_logging(self, target_url: str) -> Dict[str, Any]:
        """Enhanced verification with detailed logging at each step"""
        
        # Step 1: Enhanced Reconnaissance with logging
        nuclei_results = await self._enhanced_recon_with_logging(target_url)
        
        if not nuclei_results:
            self.forensic_logger.log_event('recon.no_vulnerabilities', {
                'target_url': target_url
            })
            return []
        
        # Step 2: Process each vulnerability with detailed attempt logging
        all_results = []
        
        for i, finding in enumerate(nuclei_results):
            vulnerability_id = f"vuln_{i}_{finding.template_id}"
            
            self.forensic_logger.log_event('vulnerability.processing_started', {
                'vulnerability_id': vulnerability_id,
                'template_name': finding.template_name,
                'matched_url': finding.matched_url
            })
            
            # Enhanced vulnerability processing
            result = await self._process_vulnerability_with_logging(finding, vulnerability_id)
            all_results.append(result)
        
        return all_results
    
    async def _enhanced_recon_with_logging(self, target_url: str):
        """Enhanced reconnaissance with logging"""
        self.forensic_logger.log_event('recon.started', {'target_url': target_url})
        
        try:
            # Call original recon agent
            results = await self.original.recon_agent.run(target_url)
            
            # Log nuclei results
            if results:
                # Save nuclei raw output to our logging structure
                nuclei_data = [
                    {
                        'template_id': r.template_id,
                        'template_name': r.template_name,
                        'severity': r.severity,
                        'description': r.description,
                        'matched_url': r.matched_url,
                        'injection_point': r.injection_point,
                        'raw_data': r.raw_data
                    }
                    for r in results
                ]
                
                # Save to nuclei directory
                nuclei_file = self.forensic_logger.current_run_dir / 'nuclei' / 'results.json'
                with open(nuclei_file, 'w') as f:
                    json.dump(nuclei_data, f, indent=2, default=str)
            
            self.forensic_logger.log_event('recon.completed', {
                'target_url': target_url,
                'vulnerabilities_found': len(results)
            })
            
            return results
            
        except Exception as e:
            self.forensic_logger.log_event('recon.error', {
                'target_url': target_url,
                'error': str(e)
            })
            raise
    
    async def _process_vulnerability_with_logging(self, finding, vulnerability_id: str):
        """Process a single vulnerability with comprehensive attempt logging"""
        
        # Create vulnerability context (from original code)
        from dynamic_xss_agent import VulnerabilityContext, PayloadAttempt
        
        vulnerability_context = VulnerabilityContext(
            nuclei_result=finding,
            attempt_history=[],
            current_attempt=0,
            max_attempts=5
        )
        
        # Dynamic testing loop with enhanced logging
        while vulnerability_context.current_attempt < vulnerability_context.max_attempts:
            try:
                # Start attempt logging
                attempt_id = self.integration.start_attempt(vulnerability_id, {
                    'template_id': finding.template_id,
                    'template_name': finding.template_name,
                    'matched_url': finding.matched_url,
                    'attempt_number': vulnerability_context.current_attempt + 1
                })
                
                # Generate or improve payload
                if vulnerability_context.current_attempt == 0:
                    attempt = await self._enhanced_generate_initial_payload(vulnerability_context, attempt_id)
                else:
                    last_result = vulnerability_context.attempt_history[-1].playwright_response
                    attempt = await self._enhanced_improve_payload(vulnerability_context, last_result, attempt_id)
                
                vulnerability_context.current_attempt = attempt.attempt
                
                # Test payload with enhanced verification logging
                playwright_result = await self._enhanced_verify_payload(
                    finding.matched_url, 
                    attempt.payload,
                    attempt_id
                )
                
                # Update attempt with result
                attempt.result = "success" if playwright_result.executed else "failure"
                attempt.playwright_response = playwright_result
                
                # Log failure analysis if failed
                if not playwright_result.executed:
                    failure_report = self.original.payload_agent.failure_analyzer.analyze(
                        attempt.payload, 
                        playwright_result
                    )
                    
                    self.integration.log_failure(attempt.payload, {
                        'reason': failure_report.reason,
                        'details': failure_report.details,
                        'confidence': failure_report.confidence
                    })
                
                # Finish attempt logging
                self.integration.finish_attempt(
                    attempt.payload,
                    attempt.result,
                    {
                        'executed': playwright_result.executed,
                        'reflection_found': playwright_result.reflection_found,
                        'execution_method': playwright_result.execution_method,
                        'screenshot_path': playwright_result.screenshot_path,
                        'html_file': playwright_result.page_content_file
                    }
                )
                
                # Add to history
                vulnerability_context.attempt_history.append(attempt)
                
                if playwright_result.executed:
                    vulnerability_context.successful_payload = attempt.payload
                    break
                    
            except Exception as e:
                self.forensic_logger.log_event('attempt.error', {
                    'vulnerability_id': vulnerability_id,
                    'attempt_number': vulnerability_context.current_attempt + 1,
                    'error': str(e)
                })
                
                # Create failed attempt record
                failed_attempt = PayloadAttempt(
                    attempt=vulnerability_context.current_attempt + 1,
                    payload="",
                    reasoning=f"Failed to generate payload: {e}",
                    result="error",
                    timestamp=datetime.now().isoformat()
                )
                
                vulnerability_context.attempt_history.append(failed_attempt)
                vulnerability_context.current_attempt += 1
        
        # Compile results
        vulnerability_result = {
            "vulnerability": {
                'template_id': finding.template_id,
                'template_name': finding.template_name,
                'severity': finding.severity,
                'description': finding.description,
                'matched_url': finding.matched_url,
                'injection_point': finding.injection_point
            },
            "successful": vulnerability_context.successful_payload is not None,
            "successful_payload": vulnerability_context.successful_payload,
            "total_attempts": len(vulnerability_context.attempt_history),
            "attempt_history": [
                {
                    'attempt': a.attempt,
                    'payload': a.payload,
                    'reasoning': a.reasoning,
                    'result': a.result,
                    'timestamp': a.timestamp
                }
                for a in vulnerability_context.attempt_history
            ],
            "final_status": "success" if vulnerability_context.successful_payload else "failed_after_max_attempts"
        }
        
        return vulnerability_result
    
    async def _enhanced_generate_initial_payload(self, vulnerability_context, attempt_id: str):
        """Generate initial payload with LLM logging"""
        
        # Log LLM interaction for initial payload generation
        context_info = self.original.payload_agent.context_extractor.extract(vulnerability_context.nuclei_result)
        
        # Build prompt (similar to original but captured for logging)
        finding = vulnerability_context.nuclei_result
        nuclei_payload = self.original.payload_agent._extract_nuclei_payload(finding)
        context_guidance = self.original.payload_agent._get_context_guidance(context_info)
        
        prompt = f"""
        You are a security testing expert analyzing XSS vulnerabilities for educational purposes in a controlled lab environment.

        VULNERABILITY ANALYSIS:
        - Target URL: {finding.matched_url}
        - Vulnerability Type: {finding.template_name}
        - Description: {finding.description}
        - Nuclei Working Payload: {nuclei_payload}
        - Severity: {finding.severity}

        INJECTION CONTEXT ANALYSIS:
        - Context Location: {context_info.location}
        - Parameter: {context_info.param or 'N/A'}
        - Evidence: {context_info.evidence}
        
        CONTEXT-SPECIFIC GUIDANCE:
        {context_guidance}

        TASK: Generate an initial XSS payload for testing this vulnerability.

        REQUIREMENTS:
        1. Analyze the injection context ({context_info.location}) to understand where the payload will be injected
        2. Create a payload that should work based on the specific context and vulnerability details
        3. Consider the context-specific guidance above
        4. Provide clear reasoning for why this payload should be effective for this context
        5. Respond in JSON format only

        RESPONSE FORMAT:
        {{
            "attempt": 1,
            "payload": "<your_generated_payload>",
            "reasoning": "Detailed explanation of why this payload should work based on the {context_info.location} context and vulnerability details",
            "result": "pending",
            "next_action": "Test this payload in the browser"
        }}
        """
        
        # Call LLM and log interaction
        response = self.original.payload_agent.bedrock_client.simple_chat(
            model="llama3.3-70b",
            message=prompt,
            temperature=0.7
        )
        
        # Log the LLM interaction
        llm_files = self.integration.log_llm_call(
            prompt=prompt,
            response=response,
            model="llama3.3-70b",
            interaction_type="initial_generation"
        )
        
        # Parse response (original logic)
        try:
            cleaned_response = self.original.payload_agent._clean_json_response(response)
            payload_data = json.loads(cleaned_response)
            
            from dynamic_xss_agent import PayloadAttempt
            attempt = PayloadAttempt(
                attempt=1,
                payload=payload_data["payload"],
                reasoning=payload_data["reasoning"],
                result="pending",
                next_action=payload_data.get("next_action", "Test payload"),
                timestamp=datetime.now().isoformat()
            )
            
            return attempt
            
        except Exception as parse_error:
            self.forensic_logger.log_event('llm.parse_error', {
                'attempt_id': attempt_id,
                'error': str(parse_error),
                'raw_response_preview': response[:200] if response else None
            })
            raise Exception(f"LLM response parsing failed: {parse_error}")
    
    async def _enhanced_improve_payload(self, vulnerability_context, playwright_result, attempt_id: str):
        """Improve payload with LLM logging"""
        
        # Similar to initial generation but for improvement
        finding = vulnerability_context.nuclei_result
        history = vulnerability_context.attempt_history
        current_attempt = vulnerability_context.current_attempt + 1
        
        last_payload = history[-1].payload if history else ""
        
        # Analyze failure
        failure_report = self.original.payload_agent.failure_analyzer.analyze(
            last_payload, 
            playwright_result
        )
        
        # Build improvement prompt
        history_text = "\n".join([
            f"Attempt {h.attempt}: Payload='{h.payload}' | Result={h.result} | Reasoning: {h.reasoning}"
            for h in history
        ])
        
        prompt = f"""
        You are a security testing expert improving XSS payloads for educational testing in a controlled lab environment.

        VULNERABILITY CONTEXT:
        - Target URL: {finding.matched_url}
        - Vulnerability Type: {finding.template_name}
        - Description: {finding.description}

        ATTEMPT HISTORY:
        {history_text}

        FAILURE ANALYSIS REPORT:
        - Failure Reason: {failure_report.reason}
        - Analysis Details: {failure_report.details}
        - Confidence Level: {failure_report.confidence:.2f}

        TASK: Generate an improved payload that specifically addresses the identified failure reason.

        RESPONSE FORMAT:
        {{
            "attempt": {current_attempt},
            "payload": "<improved_payload>",
            "reasoning": "Based on failure analysis (reason={failure_report.reason}), this payload addresses the issue by: [specific bypass technique explanation]",
            "result": "pending",
            "next_action": "Test improved payload targeting {failure_report.reason} failure"
        }}
        """
        
        # Call LLM
        response = self.original.payload_agent.bedrock_client.simple_chat(
            model="llama3.3-70b",
            message=prompt,
            temperature=0.8
        )
        
        # Log LLM interaction
        llm_files = self.integration.log_llm_call(
            prompt=prompt,
            response=response,
            model="llama3.3-70b",
            interaction_type="payload_improvement"
        )
        
        # Parse response
        try:
            cleaned_response = self.original.payload_agent._clean_json_response(response)
            payload_data = json.loads(cleaned_response)
            
            from dynamic_xss_agent import PayloadAttempt
            attempt = PayloadAttempt(
                attempt=current_attempt,
                payload=payload_data["payload"],
                reasoning=payload_data.get("reasoning", f"Generated payload for attempt {current_attempt}"),
                result="pending",
                next_action=payload_data.get("next_action", "Test improved payload"),
                timestamp=datetime.now().isoformat()
            )
            
            return attempt
            
        except Exception as parse_error:
            self.forensic_logger.log_event('llm.parse_error', {
                'attempt_id': attempt_id,
                'error': str(parse_error),
                'interaction_type': 'improvement'
            })
            raise Exception(f"LLM response parsing failed: {parse_error}")
    
    async def _enhanced_verify_payload(self, target_url: str, payload: str, attempt_id: str):
        """Verify payload with enhanced logging"""
        
        # Call original verifier but capture more data for logging
        result = await self.original.verifier_agent.run(target_url, payload, self.original.proxy_agent)
        
        # Convert result to dict for logging
        verification_data = {
            'url': result.url,
            'payload': result.payload,
            'executed': result.executed,
            'reflection_found': result.reflection_found,
            'execution_method': result.execution_method,
            'screenshot_path': result.screenshot_path,
            'error': result.error,
            'timestamp': result.timestamp,
            'console_logs': result.console_logs,
            'alerts_caught': result.alerts_caught,
            'page_content': result.page_content,
            'page_content_file': result.page_content_file,
            'response_status': result.response_status,
            'response_headers': result.response_headers
        }
        
        # Log verification
        self.integration.log_verification(verification_data)
        
        return result
    
    def cleanup(self):
        """Enhanced cleanup"""
        try:
            # Call original cleanup
            self.original.cleanup()
        finally:
            # Ensure forensic logging is finished
            if self.forensic_logger.current_cid:
                self.forensic_logger.finish_run()
    
    def save_results(self, results, output_file: str = None):
        """Enhanced save results with forensic data"""
        
        # Call original save
        self.original.save_results(results, output_file)
        
        # Also save to forensic log structure
        if self.forensic_logger.current_cid:
            self.forensic_logger.finish_run(results)


def create_enhanced_orchestrator(original_orchestrator, save_raw_llm: bool = False, retention_days: int = 30) -> EnhancedOrchestrator:
    """
    Create an enhanced orchestrator with forensic logging
    
    Args:
        original_orchestrator: Original DynamicXSSOrchestrator instance
        save_raw_llm: Whether to save raw LLM responses
        retention_days: Log retention period
        
    Returns:
        Enhanced orchestrator with forensic logging
    """
    from utils.forensic_logger import ForensicLoggerManager
    
    forensic_logger = ForensicLoggerManager(
        save_raw_llm=save_raw_llm,
        retention_days=retention_days
    )
    
    return EnhancedOrchestrator(original_orchestrator, forensic_logger)