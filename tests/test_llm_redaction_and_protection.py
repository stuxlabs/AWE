#!/usr/bin/env python3
"""
Test LLM Redaction and Protection

This test file validates that the forensic logging system properly redacts
sensitive information and encrypts raw LLM responses when configured to do so.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.forensic_logger import SecurityRedactor, EncryptionManager, ForensicLoggerManager


class TestSecurityRedactor(unittest.TestCase):
    """Test security redaction functionality"""
    
    def test_redact_sensitive_headers(self):
        """Test redaction of sensitive headers"""
        
        test_headers = {
            'Authorization': 'Bearer sk-1234567890abcdef',
            'Cookie': 'session=abc123; auth_token=xyz789',
            'X-API-Key': 'api_key_12345',
            'Content-Type': 'application/json',
            'User-Agent': 'TestAgent/1.0',
            'x-auth-token': 'secret_token_here'
        }
        
        redacted = SecurityRedactor.redact_sensitive(test_headers)
        
        # Sensitive headers should be redacted
        self.assertEqual(redacted['Authorization'], '<REDACTED>')
        self.assertEqual(redacted['Cookie'], '<REDACTED>')
        self.assertEqual(redacted['X-API-Key'], '<REDACTED>')
        self.assertEqual(redacted['x-auth-token'], '<REDACTED>')
        
        # Non-sensitive headers should remain
        self.assertEqual(redacted['Content-Type'], 'application/json')
        self.assertEqual(redacted['User-Agent'], 'TestAgent/1.0')
    
    def test_redact_sensitive_patterns_in_strings(self):
        """Test redaction of sensitive patterns in strings"""
        
        test_cases = [
            # API Keys
            ('The API key is sk-1234567890abcdef1234567890', '<REDACTED_TOKEN>'),
            ('AWS key: AKIAIOSFODNN7EXAMPLE', '<REDACTED_AWS_KEY>'),
            
            # JWTs
            ('JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c', '<REDACTED_JWT>'),
            
            # Long secrets
            ('Secret: YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkw', '<REDACTED_SECRET>'),
            
            # Interactsh/OAST tokens
            ('Callback: abc123def456.interact.sh', '<REDACTED_CALLBACK>'),
            ('OAST: test123.burpcollaborator.net', '<REDACTED_CALLBACK>'),
        ]
        
        for original, expected_pattern in test_cases:
            redacted = SecurityRedactor.redact_sensitive(original)
            self.assertIn(expected_pattern, redacted, f"Pattern should be redacted in: {original}")
            
            # Original sensitive content should not remain
            if 'sk-' in original:
                self.assertNotIn('sk-', redacted)
            if 'AKIA' in original:
                self.assertNotIn('AKIA', redacted)
    
    def test_redact_nested_structures(self):
        """Test redaction in nested data structures"""
        
        test_data = {
            'request': {
                'headers': {
                    'Authorization': 'Bearer token123',
                    'Content-Type': 'application/json'
                },
                'body': {
                    'api_key': 'sk-abcdef1234567890',
                    'data': ['item1', 'sk-anothersecret123', 'item3']
                }
            },
            'response': {
                'status': 200,
                'data': 'JWT: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.test'
            }
        }
        
        redacted = SecurityRedactor.redact_sensitive(test_data)
        
        # Check nested redaction
        self.assertEqual(redacted['request']['headers']['Authorization'], '<REDACTED>')
        self.assertEqual(redacted['request']['headers']['Content-Type'], 'application/json')
        
        # Check array redaction
        redacted_array = redacted['request']['body']['data']
        self.assertEqual(redacted_array[0], 'item1')  # Normal item preserved
        self.assertIn('<REDACTED_TOKEN>', redacted_array[1])  # Secret redacted
        self.assertEqual(redacted_array[2], 'item3')  # Normal item preserved
        
        # Check JWT redaction
        self.assertIn('<REDACTED_JWT>', redacted['response']['data'])
    
    def test_preserve_normal_content(self):
        """Test that normal content is preserved during redaction"""
        
        normal_content = {
            'user_id': '12345',
            'email': 'test@example.com',
            'message': 'This is a normal message with no secrets',
            'url': 'https://example.com/path?param=value',
            'headers': {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
        }
        
        redacted = SecurityRedactor.redact_sensitive(normal_content)
        
        # Normal content should be unchanged
        self.assertEqual(redacted, normal_content)


class TestEncryptionManager(unittest.TestCase):
    """Test encryption functionality"""
    
    def test_encryption_without_key(self):
        """Test encryption manager without key"""
        
        manager = EncryptionManager()
        self.assertFalse(manager.is_enabled)
        
        with self.assertRaises(ValueError):
            manager.encrypt("test data")
    
    def test_encryption_with_key(self):
        """Test encryption manager with key"""
        
        manager = EncryptionManager("test-encryption-key")
        self.assertTrue(manager.is_enabled)
        
        test_data = "Sensitive LLM response with API key: sk-12345"
        
        # Encrypt the data
        encrypted = manager.encrypt(test_data)
        self.assertIsInstance(encrypted, bytes)
        self.assertNotIn(b'sk-12345', encrypted)  # Should not contain plaintext
        
        # Decrypt the data
        decrypted = manager.decrypt(encrypted)
        self.assertEqual(decrypted, test_data)
    
    def test_encryption_consistency(self):
        """Test that encryption is consistent with same key"""
        
        key = "consistent-test-key"
        manager1 = EncryptionManager(key)
        manager2 = EncryptionManager(key)
        
        test_data = "Test data for consistency"
        
        encrypted1 = manager1.encrypt(test_data)
        encrypted2 = manager2.encrypt(test_data)
        
        # Different encryption instances should be able to decrypt each other's data
        decrypted1 = manager1.decrypt(encrypted2)
        decrypted2 = manager2.decrypt(encrypted1)
        
        self.assertEqual(decrypted1, test_data)
        self.assertEqual(decrypted2, test_data)
    
    def test_encryption_with_different_keys(self):
        """Test that different keys produce different results"""
        
        manager1 = EncryptionManager("key1")
        manager2 = EncryptionManager("key2")
        
        test_data = "Same test data"
        
        encrypted1 = manager1.encrypt(test_data)
        encrypted2 = manager2.encrypt(test_data)
        
        # Same data with different keys should produce different encrypted results
        self.assertNotEqual(encrypted1, encrypted2)
        
        # Each manager should only be able to decrypt its own data
        decrypted1 = manager1.decrypt(encrypted1)
        self.assertEqual(decrypted1, test_data)
        
        # Different key should fail to decrypt
        with self.assertRaises(Exception):  # Fernet will raise an exception
            manager1.decrypt(encrypted2)


class TestForensicLoggerRedaction(unittest.TestCase):
    """Test redaction in forensic logger context"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp(prefix="redaction_test_")
        
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        
        # Clean up environment variables
        if 'LLM_RAW_KEY' in os.environ:
            del os.environ['LLM_RAW_KEY']
    
    def test_llm_redaction_without_encryption(self):
        """Test LLM logging without encryption"""
        
        logger_manager = ForensicLoggerManager(
            base_log_dir=self.temp_dir,
            save_raw_llm=True,  # Raw saving enabled but no key
            retention_days=1
        )
        
        cid = logger_manager.start_run("http://test.local")
        
        sensitive_prompt = "Generate payload with API key: sk-abcdef1234567890"
        sensitive_response = '{"payload": "<script>alert(1)</script>", "api_key": "sk-abcdef1234567890"}'
        
        # This should work but issue a warning about no encryption
        llm_files = logger_manager.log_llm_interaction(
            prompt=sensitive_prompt,
            response=sensitive_response,
            model="test-model"
        )
        
        run_dir = logger_manager.current_run_dir
        
        # Check redacted files
        redacted_prompt_path = run_dir / llm_files['prompt_file']
        redacted_response_path = run_dir / llm_files['response_redacted_file']
        
        with open(redacted_prompt_path, 'r') as f:
            redacted_prompt = f.read()
        
        with open(redacted_response_path, 'r') as f:
            redacted_response = f.read()
        
        # Sensitive data should be redacted
        self.assertNotIn('sk-abcdef1234567890', redacted_prompt)
        self.assertNotIn('sk-abcdef1234567890', redacted_response)
        self.assertIn('<REDACTED_TOKEN>', redacted_prompt)
        
        # Raw file should exist but unencrypted (with warning issued)
        raw_path = run_dir / llm_files['response_raw_file']
        self.assertTrue(raw_path.exists())
        
        # Check permissions
        permissions = oct(raw_path.stat().st_mode)[-3:]
        self.assertEqual(permissions, '600')
        
        logger_manager.finish_run()
    
    def test_llm_redaction_with_encryption(self):
        """Test LLM logging with proper encryption"""
        
        # Set encryption key
        os.environ['LLM_RAW_KEY'] = 'test-encryption-key-for-llm-responses'
        
        logger_manager = ForensicLoggerManager(
            base_log_dir=self.temp_dir,
            save_raw_llm=True,
            retention_days=1
        )
        
        # Verify encryption is enabled
        self.assertTrue(logger_manager.encryption.is_enabled)
        
        cid = logger_manager.start_run("http://test.local")
        
        sensitive_prompt = "Use this API key: sk-1234567890abcdef and JWT: eyJ0eXAiOiJKV1QifQ.test.signature"
        sensitive_response = '''
        {
            "payload": "<script>alert(document.cookie)</script>", 
            "reasoning": "Using API key sk-1234567890abcdef for authentication",
            "jwt_token": "eyJ0eXAiOiJKV1QifQ.test.signature"
        }
        '''
        
        llm_files = logger_manager.log_llm_interaction(
            prompt=sensitive_prompt,
            response=sensitive_response,
            model="gpt-4"
        )
        
        run_dir = logger_manager.current_run_dir
        
        # Check redacted files don't contain sensitive data
        redacted_prompt_path = run_dir / llm_files['prompt_file']
        redacted_response_path = run_dir / llm_files['response_redacted_file']
        
        with open(redacted_prompt_path, 'r') as f:
            redacted_prompt = f.read()
        
        with open(redacted_response_path, 'r') as f:
            redacted_response = f.read()
        
        # Verify redaction
        self.assertNotIn('sk-1234567890abcdef', redacted_prompt)
        self.assertNotIn('sk-1234567890abcdef', redacted_response)
        self.assertNotIn('eyJ0eXAiOiJKV1QifQ.test.signature', redacted_response)
        self.assertIn('<REDACTED_TOKEN>', redacted_prompt)
        self.assertIn('<REDACTED_JWT>', redacted_response)
        
        # Check raw file is encrypted
        raw_path = run_dir / llm_files['response_raw_file']
        self.assertTrue(raw_path.exists())
        
        with open(raw_path, 'rb') as f:
            raw_content = f.read()
        
        # Should be binary encrypted content
        self.assertIsInstance(raw_content, bytes)
        
        # Should not contain plaintext sensitive data
        self.assertNotIn(b'sk-1234567890abcdef', raw_content)
        self.assertNotIn(b'eyJ0eXAiOiJKV1Q', raw_content)
        
        # Verify we can decrypt it
        decrypted_content = logger_manager.encryption.decrypt(raw_content)
        self.assertIn('sk-1234567890abcdef', decrypted_content)
        self.assertIn('eyJ0eXAiOiJKV1QifQ.test.signature', decrypted_content)
        
        logger_manager.finish_run()
    
    def test_http_request_response_redaction(self):
        """Test redaction in HTTP request/response logging"""
        
        logger_manager = ForensicLoggerManager(
            base_log_dir=self.temp_dir,
            redact_full_bodies=False  # Test header redaction only
        )
        
        cid = logger_manager.start_run("http://test.local")
        
        # Test request with sensitive headers
        request_data = {
            'method': 'POST',
            'url': 'http://api.example.com/endpoint',
            'headers': {
                'Authorization': 'Bearer sk-api-key-123456789',
                'Cookie': 'session_id=abc123; auth_token=xyz789',
                'X-API-Key': 'secret-key-here',
                'Content-Type': 'application/json',
                'User-Agent': 'XSSAgent/1.0'
            },
            'body': '{"data": "normal content", "api_key": "sk-embedded-key-here"}'
        }
        
        response_data = {
            'status': 200,
            'headers': {
                'Set-Cookie': 'new_session=def456; HttpOnly',
                'X-Auth-Token': 'response-token-123',
                'Content-Type': 'application/json'
            },
            'body': '{"success": true, "token": "response-sk-token-abc"}'
        }
        
        http_file = logger_manager.log_http_request_response(
            request=request_data,
            response=response_data
        )
        
        run_dir = logger_manager.current_run_dir
        
        # Check that request file exists and is redacted
        request_file = run_dir / http_file
        self.assertTrue(request_file.exists())
        
        with open(request_file, 'r') as f:
            saved_request = f.read()
        
        # Sensitive headers should be redacted
        self.assertNotIn('sk-api-key-123456789', saved_request)
        self.assertNotIn('session_id=abc123', saved_request)
        self.assertNotIn('secret-key-here', saved_request)
        self.assertIn('<REDACTED>', saved_request)
        
        # Non-sensitive headers should remain
        self.assertIn('application/json', saved_request)
        self.assertIn('XSSAgent/1.0', saved_request)
        
        # Body content should be redacted for sensitive patterns
        self.assertNotIn('sk-embedded-key-here', saved_request)
        self.assertIn('<REDACTED_TOKEN>', saved_request)
        
        logger_manager.finish_run()
    
    def test_full_body_redaction_mode(self):
        """Test full body redaction mode"""
        
        logger_manager = ForensicLoggerManager(
            base_log_dir=self.temp_dir,
            redact_full_bodies=True  # Enable full body redaction
        )
        
        cid = logger_manager.start_run("http://test.local")
        
        large_body = "x" * 10000  # Large body content
        
        request_data = {
            'method': 'POST',
            'url': 'http://api.example.com/upload',
            'headers': {'Content-Type': 'application/octet-stream'},
            'body': large_body
        }
        
        response_data = {
            'status': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': '{"result": "success", "size": 12345}'
        }
        
        http_file = logger_manager.log_http_request_response(
            request=request_data,
            response=response_data
        )
        
        run_dir = logger_manager.current_run_dir
        request_file = run_dir / http_file
        
        with open(request_file, 'r') as f:
            saved_data = f.read()
        
        # Body should be replaced with size indicator
        self.assertNotIn(large_body, saved_data)
        self.assertIn('<REDACTED_BODY_SIZE_10000>', saved_data)
        
        logger_manager.finish_run()


if __name__ == '__main__':
    # Check for required dependencies
    try:
        import cryptography
    except ImportError:
        print("Missing cryptography dependency - install with: pip install cryptography")
        sys.exit(1)
    
    # Run tests
    unittest.main(verbosity=2)