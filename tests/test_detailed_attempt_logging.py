#!/usr/bin/env python3
"""
Test Detailed Attempt Logging

This test file validates that the forensic logging system correctly captures
all aspects of XSS testing attempts including LLM interactions, HTTP requests/responses,
Playwright verifications, and attempt artifacts.
"""

import asyncio
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, AsyncMock, patch

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.forensic_logger import ForensicLoggerManager
from utils.logging_integration import LoggingIntegration
from utils.http_logging import EnhancedHttpxClient
from utils.playwright_logging import PlaywrightForensicLogger


class MockBedrock:
    """Mock Bedrock client for testing"""
    
    def simple_chat(self, model, message, temperature=0.7):
        """Mock LLM response"""
        return '{"attempt": 1, "payload": "<script>alert(1)</script>", "reasoning": "Basic XSS test", "result": "pending", "next_action": "Test payload"}'


class MockVerificationResult:
    """Mock Playwright verification result"""
    
    def __init__(self):
        self.url = "http://test.local/vuln?q=<script>alert(1)</script>"
        self.payload = "<script>alert(1)</script>"
        self.executed = True
        self.reflection_found = True
        self.execution_method = "alert"
        self.screenshot_path = "/tmp/screenshot.png"
        self.error = None
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.console_logs = [
            {"type": "log", "text": "Script executed"},
            {"type": "error", "text": "Test error"}
        ]
        self.alerts_caught = ["XSS Alert"]
        self.page_content = "<html><body>Test content</body></html>"
        self.page_content_file = "/tmp/content.html"
        self.response_status = 200
        self.response_headers = {"Content-Type": "text/html"}


class TestDetailedAttemptLogging(unittest.TestCase):
    """Test comprehensive attempt logging functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp(prefix="forensic_test_")
        self.logger_manager = ForensicLoggerManager(
            base_log_dir=self.temp_dir,
            save_raw_llm=True,
            retention_days=1
        )
        
        # Set a test encryption key
        os.environ['LLM_RAW_KEY'] = 'test-key-for-encryption-testing'
        
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        
        # Clean up environment
        if 'LLM_RAW_KEY' in os.environ:
            del os.environ['LLM_RAW_KEY']
    
    def test_complete_attempt_workflow(self):
        """Test complete attempt logging workflow"""
        
        # Start a logging run
        cid = self.logger_manager.start_run("http://test.local/vulnerable")
        self.assertIsNotNone(cid)
        self.assertIsNotNone(self.logger_manager.current_run_dir)
        
        # Verify directory structure was created
        run_dir = self.logger_manager.current_run_dir
        expected_dirs = [
            'nuclei', 'proxy', 'playwright', 'attempts', 'replay', 'results',
            'llm/raw', 'llm/redacted'
        ]
        
        for expected_dir in expected_dirs:
            dir_path = run_dir / expected_dir
            self.assertTrue(dir_path.exists(), f"Directory {expected_dir} should exist")
        
        # Test attempt logging
        integration = LoggingIntegration(self.logger_manager)
        attempt_id = integration.start_attempt("vuln_1", {
            'template_id': 'test-xss-1',
            'template_name': 'Test XSS',
            'matched_url': 'http://test.local/vulnerable'
        })
        
        self.assertIsNotNone(attempt_id)
        
        # Test LLM logging
        llm_files = integration.log_llm_call(
            prompt="Generate XSS payload",
            response='{"payload": "<script>alert(1)</script>"}',
            model="test-model",
            interaction_type="generation"
        )
        
        # Verify LLM files were created
        self.assertIn('prompt_file', llm_files)
        self.assertIn('response_redacted_file', llm_files)
        self.assertIn('response_raw_file', llm_files)
        
        # Check that files exist
        prompt_path = run_dir / llm_files['prompt_file']
        redacted_path = run_dir / llm_files['response_redacted_file']
        raw_path = run_dir / llm_files['response_raw_file']
        
        self.assertTrue(prompt_path.exists())
        self.assertTrue(redacted_path.exists())
        self.assertTrue(raw_path.exists())
        
        # Test HTTP logging
        http_file = integration.log_http_call(
            request={
                'method': 'GET',
                'url': 'http://test.local/vulnerable?q=<script>alert(1)</script>',
                'headers': {'User-Agent': 'TestAgent'},
                'body': ''
            },
            response={
                'status': 200,
                'headers': {'Content-Type': 'text/html'},
                'body': '<html><body>Test</body></html>'
            }
        )
        
        self.assertIsNotNone(http_file)
        
        # Test verification logging
        mock_result = MockVerificationResult()
        artifacts = integration.log_verification(mock_result.__dict__)
        
        self.assertIsInstance(artifacts, dict)
        
        # Test failure logging
        integration.log_failure(
            payload="<script>alert(1)</script>",
            failure_report={
                'reason': 'blocked',
                'details': 'WAF blocked the request',
                'confidence': 0.9
            }
        )
        
        # Finish attempt
        integration.finish_attempt(
            payload="<script>alert(1)</script>",
            result="success",
            artifacts={
                'screenshot': '/tmp/screenshot.png',
                'html': '/tmp/content.html'
            }
        )
        
        # Check events.jsonl was created and has content
        events_file = run_dir / 'events.jsonl'
        self.assertTrue(events_file.exists())
        
        with open(events_file, 'r') as f:
            events = [json.loads(line) for line in f]
        
        self.assertGreater(len(events), 0)
        
        # Verify event types
        event_types = {event['event_type'] for event in events}
        expected_events = {
            'run.started', 'attempt.started', 'llm.interaction', 
            'http.request_response', 'verification.completed',
            'failure.analysis', 'attempt.finished'
        }
        
        for expected_event in expected_events:
            self.assertIn(expected_event, event_types, f"Event type {expected_event} should be logged")
        
        # Finish the run
        self.logger_manager.finish_run({'test': 'results'})
    
    def test_llm_encryption_and_redaction(self):
        """Test LLM response encryption and redaction"""
        
        cid = self.logger_manager.start_run("http://test.local/test")
        
        # Test with sensitive content
        sensitive_prompt = "Generate payload with API key: sk-12345 and token: abc123def456"
        sensitive_response = '{"payload": "test", "api_key": "sk-12345", "token": "abc123def456"}'
        
        integration = LoggingIntegration(self.logger_manager)
        attempt_id = integration.start_attempt("test_vuln", {})
        
        llm_files = integration.log_llm_call(
            prompt=sensitive_prompt,
            response=sensitive_response,
            model="test-model"
        )
        
        run_dir = self.logger_manager.current_run_dir
        
        # Check redacted files don't contain sensitive data
        redacted_prompt_path = run_dir / llm_files['prompt_file']
        redacted_response_path = run_dir / llm_files['response_redacted_file']
        
        with open(redacted_prompt_path, 'r') as f:
            redacted_prompt_content = f.read()
        
        with open(redacted_response_path, 'r') as f:
            redacted_response_content = f.read()
        
        # Sensitive data should be redacted
        self.assertNotIn('sk-12345', redacted_prompt_content)
        self.assertNotIn('abc123def456', redacted_response_content)
        self.assertIn('<REDACTED', redacted_prompt_content)
        
        # Raw file should be encrypted (binary content)
        raw_path = run_dir / llm_files['response_raw_file']
        with open(raw_path, 'rb') as f:
            raw_content = f.read()
        
        # Should be binary (encrypted) content
        self.assertIsInstance(raw_content, bytes)
        
        # Should not contain plaintext sensitive data
        try:
            decoded_content = raw_content.decode('utf-8')
            self.assertNotIn('sk-12345', decoded_content)
        except UnicodeDecodeError:
            # This is expected for encrypted content
            pass
        
        self.logger_manager.finish_run()
    
    def test_attempt_file_creation(self):
        """Test that individual attempt files are created correctly"""
        
        cid = self.logger_manager.start_run("http://test.local/test")
        integration = LoggingIntegration(self.logger_manager)
        
        # Create multiple attempts
        for i in range(3):
            attempt_id = integration.start_attempt(f"vuln_{i}", {
                'template_id': f'test-{i}',
                'attempt_number': i + 1
            })
            
            # Log some activity
            integration.log_llm_call(
                f"Prompt for attempt {i}",
                f'{{"payload": "test{i}"}}',
                "test-model"
            )
            
            integration.finish_attempt(
                f"<script>alert({i})</script>",
                "success" if i == 1 else "failure",
                {'attempt_index': i}
            )
        
        # Check attempt files were created
        attempts_dir = self.logger_manager.current_run_dir / 'attempts'
        attempt_files = list(attempts_dir.glob('*.json'))
        
        self.assertEqual(len(attempt_files), 3)
        
        # Check content of attempt files
        for attempt_file in attempt_files:
            with open(attempt_file, 'r') as f:
                attempt_data = json.load(f)
            
            # Verify required fields
            required_fields = ['attempt_id', 'correlation_id', 'payload', 'result', 'timestamp']
            for field in required_fields:
                self.assertIn(field, attempt_data, f"Field {field} should be in attempt data")
        
        self.logger_manager.finish_run()
    
    def test_concurrent_logging(self):
        """Test concurrent access to logging system"""
        
        cid = self.logger_manager.start_run("http://test.local/concurrent")
        
        async def concurrent_logging_task(task_id):
            """Simulate concurrent logging operations"""
            integration = LoggingIntegration(self.logger_manager)
            attempt_id = integration.start_attempt(f"concurrent_vuln_{task_id}", {
                'task_id': task_id
            })
            
            # Simulate multiple rapid operations
            for i in range(5):
                integration.log_llm_call(
                    f"Concurrent prompt {task_id}-{i}",
                    f'{{"payload": "test{task_id}-{i}"}}',
                    "test-model"
                )
                
                integration.log_http_call(
                    {
                        'method': 'GET',
                        'url': f'http://test.local/test{task_id}-{i}',
                        'headers': {},
                        'body': ''
                    },
                    {
                        'status': 200,
                        'headers': {},
                        'body': 'response'
                    }
                )
            
            integration.finish_attempt(f"payload{task_id}", "success", {})
            return task_id
        
        async def run_concurrent_test():
            """Run concurrent logging test"""
            tasks = [concurrent_logging_task(i) for i in range(5)]
            results = await asyncio.gather(*tasks)
            return results
        
        # Run the concurrent test
        results = asyncio.run(run_concurrent_test())
        self.assertEqual(len(results), 5)
        
        # Verify events.jsonl integrity
        events_file = self.logger_manager.current_run_dir / 'events.jsonl'
        self.assertTrue(events_file.exists())
        
        with open(events_file, 'r') as f:
            lines = f.readlines()
        
        # Each line should be valid JSON
        events = []
        for line in lines:
            try:
                event = json.loads(line.strip())
                events.append(event)
            except json.JSONDecodeError as e:
                self.fail(f"Invalid JSON line in events.jsonl: {line[:100]}...")
        
        # Should have events from all concurrent tasks
        self.assertGreater(len(events), 20)  # At least 5 tasks * 4+ events per task
        
        self.logger_manager.finish_run()
    
    def test_artifact_file_permissions(self):
        """Test that sensitive files have proper permissions"""
        
        cid = self.logger_manager.start_run("http://test.local/permissions")
        integration = LoggingIntegration(self.logger_manager)
        
        attempt_id = integration.start_attempt("perm_test", {})
        
        # Create LLM files
        llm_files = integration.log_llm_call(
            "Test prompt",
            '{"payload": "test"}',
            "test-model"
        )
        
        # Check permissions on raw LLM directory
        raw_dir = self.logger_manager.current_run_dir / 'llm/raw'
        raw_permissions = oct(raw_dir.stat().st_mode)[-3:]
        self.assertEqual(raw_permissions, '700', "Raw LLM directory should have 700 permissions")
        
        # Check permissions on raw LLM files
        raw_file = self.logger_manager.current_run_dir / llm_files['response_raw_file']
        if raw_file.exists():
            raw_file_permissions = oct(raw_file.stat().st_mode)[-3:]
            self.assertEqual(raw_file_permissions, '600', "Raw LLM files should have 600 permissions")
        
        self.logger_manager.finish_run()
    
    def test_error_handling_and_recovery(self):
        """Test error handling and recovery in logging system"""
        
        cid = self.logger_manager.start_run("http://test.local/error")
        integration = LoggingIntegration(self.logger_manager)
        
        # Test invalid JSON in LLM response
        attempt_id = integration.start_attempt("error_test", {})
        
        try:
            llm_files = integration.log_llm_call(
                "Test prompt",
                "Invalid JSON response {not json",  # Invalid JSON
                "test-model"
            )
            
            # Should still create files even with invalid JSON
            run_dir = self.logger_manager.current_run_dir
            prompt_path = run_dir / llm_files['prompt_file']
            redacted_path = run_dir / llm_files['response_redacted_file']
            
            self.assertTrue(prompt_path.exists())
            self.assertTrue(redacted_path.exists())
            
        except Exception as e:
            self.fail(f"Logging should handle invalid JSON gracefully: {e}")
        
        # Test recovery after errors
        try:
            # This should work normally
            integration.log_http_call(
                {'method': 'GET', 'url': 'http://test.local', 'headers': {}, 'body': ''},
                {'status': 200, 'headers': {}, 'body': 'OK'}
            )
        except Exception as e:
            self.fail(f"Logging should recover from previous errors: {e}")
        
        self.logger_manager.finish_run()


if __name__ == '__main__':
    # Check for required dependencies
    try:
        import cryptography
    except ImportError:
        print("Missing cryptography dependency - install with: pip install cryptography")
        sys.exit(1)
    
    # Run tests
    unittest.main(verbosity=2)