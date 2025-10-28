#!/usr/bin/env python3
"""
Offline Unit Tests for OAST Triggering Feature
Tests all OAST functionality without requiring network access
"""

import asyncio
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, Mock, patch
from dataclasses import asdict
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from persistence import PersistenceCandidate, PersistenceScorer, PersistenceCandidateExtractor
from oast_agent import OASTAgent, LocalOASTServer, OASTCallback
from dynamic_xss_agent import DynamicXSSOrchestrator


class TestPersistenceScoring(unittest.TestCase):
    """Test persistence candidate scoring logic"""
    
    def setUp(self):
        self.scorer = PersistenceScorer()
    
    def test_high_score_post_form(self):
        """Test that POST forms with multiple fields get high scores"""
        candidate = PersistenceCandidate(
            id="test_form",
            url="http://test.com/comment",
            method="POST",
            params={"comment": "test", "author": "user"},
            field_names=["comment", "author"],
            has_file_upload=False,
            requires_auth=False,
            js_templating_score=0.3,
            path_keywords_score=0.8,  # "comment" in path
            evidence_snippet="<form method=POST>"
        )
        
        score = self.scorer.compute_persistence_score(candidate)
        
        # Should get: +0.4 (POST) +0.25 (fields) +0.06 (JS) +0.12 (path) = 0.83
        self.assertGreater(score, 0.6, "POST form with good keywords should score high")
    
    def test_low_score_get_request(self):
        """Test that simple GET requests get low scores"""
        candidate = PersistenceCandidate(
            id="test_get",
            url="http://test.com/info",
            method="GET",
            params={"q": "search"},
            field_names=[],
            has_file_upload=False,
            requires_auth=False,
            js_templating_score=0.1,
            path_keywords_score=0.1,
            evidence_snippet="<a href=/info>"
        )
        
        score = self.scorer.compute_persistence_score(candidate)
        
        # Should get: +0.0 (GET) +0.0 (no fields) +0.02 (JS) +0.015 (path) = 0.035
        self.assertLess(score, 0.6, "Simple GET request should score low")
    
    def test_waf_penalty(self):
        """Test that WAF detection reduces score"""
        candidate = PersistenceCandidate(
            id="test_waf",
            url="http://test.com/admin",
            method="POST",
            params={"data": "test"},
            field_names=["data"],
            has_file_upload=False,
            requires_auth=True,
            js_templating_score=0.5,
            path_keywords_score=0.5,
            evidence_snippet="Admin form"
        )
        
        # Without WAF
        score_clean = self.scorer.compute_persistence_score(candidate)
        
        # With WAF response
        waf_response = "Access denied by CloudFlare security rules"
        score_waf = self.scorer.compute_persistence_score(
            candidate, 
            response_content=waf_response, 
            response_status=403
        )
        
        self.assertLess(score_waf, score_clean, "WAF detection should reduce score")
        self.assertLess(score_waf, 0.6, "WAF-protected endpoint should score below threshold")
    
    def test_file_upload_bonus(self):
        """Test that file upload forms get bonus points"""
        candidate = PersistenceCandidate(
            id="test_upload",
            url="http://test.com/upload",
            method="POST",
            params={"file": "test.txt"},
            field_names=["file"],
            has_file_upload=True,
            requires_auth=False,
            js_templating_score=0.2,
            path_keywords_score=0.6,  # "upload" in path
            evidence_snippet="<input type=file>"
        )
        
        score = self.scorer.compute_persistence_score(candidate)
        
        # Should get high score due to file upload + POST + path keywords
        self.assertGreater(score, 0.7, "File upload forms should score very high")


class TestPersistenceCandidateExtraction(unittest.TestCase):
    """Test extraction of persistence candidates from HTML"""
    
    def setUp(self):
        self.extractor = PersistenceCandidateExtractor()
    
    def test_extract_simple_form(self):
        """Test extraction of basic HTML form"""
        html = """
        <html>
        <body>
            <form method="POST" action="/submit">
                <input type="text" name="username" />
                <input type="password" name="password" />
                <textarea name="comment"></textarea>
                <input type="submit" value="Submit" />
            </form>
        </body>
        </html>
        """
        
        candidates = self.extractor.extract_from_html("http://test.com/form", html)
        
        self.assertEqual(len(candidates), 1)
        form_candidate = candidates[0]
        self.assertEqual(form_candidate.method, "POST")
        self.assertEqual(form_candidate.url, "http://test.com/submit")
        self.assertIn("username", form_candidate.field_names)
        self.assertIn("password", form_candidate.field_names) 
        self.assertIn("comment", form_candidate.field_names)
        self.assertFalse(form_candidate.has_file_upload)
    
    def test_extract_file_upload_form(self):
        """Test extraction of file upload form"""
        html = """
        <form method="post" action="/upload" enctype="multipart/form-data">
            <input type="file" name="document" />
            <input type="text" name="description" />
        </form>
        """
        
        candidates = self.extractor.extract_from_html("http://test.com/", html)
        
        self.assertEqual(len(candidates), 1)
        form_candidate = candidates[0]
        self.assertTrue(form_candidate.has_file_upload)
        self.assertEqual(form_candidate.method, "POST")
    
    def test_extract_ajax_endpoints(self):
        """Test extraction of AJAX endpoints from JavaScript"""
        html = """
        <html>
        <script>
            $.post('/api/comment', {text: 'hello'});
            fetch('/api/upload', {method: 'POST'});
            axios.post('/api/message', data);
        </script>
        </html>
        """
        
        candidates = self.extractor.extract_from_html("http://test.com/page", html)
        
        # Should find AJAX endpoints
        ajax_urls = [c.url for c in candidates if c.method == "POST"]
        self.assertTrue(any("/api/comment" in url for url in ajax_urls))
        self.assertTrue(any("/api/upload" in url for url in ajax_urls))
        self.assertTrue(any("/api/message" in url for url in ajax_urls))
    
    def test_base_url_candidate_generation(self):
        """Test generation of base URL candidate with good indicators"""
        html = """
        <html>
        <script>
            document.getElementById('content').innerHTML = userInput;
            // Template engine: {{title}}
        </script>
        <body>
        <h1>User Profile</h1>
        </body>
        </html>
        """
        
        candidates = self.extractor.extract_from_html("http://test.com/profile", html)
        
        # Should create base URL candidate due to JS templating and path keywords
        base_candidates = [c for c in candidates if c.method == "GET"]
        self.assertGreater(len(base_candidates), 0)
        
        base_candidate = base_candidates[0]
        self.assertGreater(base_candidate.js_templating_score, 0.2)
        self.assertGreater(base_candidate.path_keywords_score, 0.3)


class TestOASTAgent(unittest.TestCase):
    """Test OAST agent functionality"""
    
    def setUp(self):
        self.config = {
            'oast_mode': 'auto',
            'oast_threshold': 0.6,
            'oast_max_per_host': 3,
            'oast_poll_timeout': 10,
            'oast_whitelist': ['127.0.0.1', 'localhost', '*.test']
        }
        self.agent = OASTAgent(config=self.config)
    
    def test_host_whitelist_validation(self):
        """Test host whitelist validation"""
        # Allowed hosts
        self.assertTrue(self.agent.is_host_allowed("http://127.0.0.1/test"))
        self.assertTrue(self.agent.is_host_allowed("http://localhost/page"))
        self.assertTrue(self.agent.is_host_allowed("http://app.test/api"))
        
        # Disallowed hosts
        self.assertFalse(self.agent.is_host_allowed("http://evil.com/test"))
        self.assertFalse(self.agent.is_host_allowed("http://example.org/page"))
    
    def test_rate_limiting(self):
        """Test per-host rate limiting"""
        test_url = "http://localhost/test"
        
        # Should allow up to max_per_host attempts
        for i in range(self.config['oast_max_per_host']):
            self.assertTrue(self.agent.can_inject_for_host(test_url))
            self.agent.increment_host_counter(test_url)
        
        # Should block additional attempts
        self.assertFalse(self.agent.can_inject_for_host(test_url))
    
    async def test_token_registration_local(self):
        """Test OAST token registration with local backend"""
        metadata = {'test': 'data', 'timestamp': 'now'}
        
        callback_url = await self.agent.register_token(metadata)
        
        self.assertIn("127.0.0.1", callback_url)
        self.assertTrue(callback_url.startswith("http://"))
    
    def test_payload_generation(self):
        """Test OAST payload generation for different contexts"""
        callback_id = "test123.oast.pro"
        
        # Test different contexts
        contexts = [
            {'location': 'query', 'method': 'GET'},
            {'location': 'post', 'method': 'POST'},
            {'location': 'json', 'method': 'POST'},
            {'location': 'dom', 'method': 'GET'},
        ]
        
        for context in contexts:
            payload = self.agent.generate_payload_for_context(context, callback_id)
            
            # Payload should contain the callback identifier
            self.assertIn("test123", payload)
            
            # Payload should be appropriate for context
            if context['location'] == 'query':
                self.assertIn("<script>", payload)
                self.assertIn("fetch", payload)
            elif context['location'] == 'json':
                self.assertIn('"},', payload)  # JSON breaking
            elif context['location'] == 'dom':
                self.assertIn("<svg", payload)
    
    async def test_callback_polling(self):
        """Test callback polling functionality"""
        # Use local backend for testing
        if isinstance(self.agent.backend, LocalOASTServer):
            # Register a token
            callback_url = await self.agent.register_token({'test': 'polling'})
            
            # Extract token from URL
            token = callback_url.split('/')[-1]
            
            # Should initially have no callbacks
            callbacks = await self.agent.poll_for_callbacks(callback_url, timeout=1)
            self.assertEqual(len(callbacks), 0)
            
            # Record a test callback
            test_request = {
                'source_ip': '192.168.1.100',
                'user_agent': 'Mozilla/5.0 (Test Browser)',
                'headers': {'Host': 'test.local'},
                'body': 'callback data'
            }
            self.agent.backend.record_callback(token, test_request)
            
            # Should now have one callback
            callbacks = await self.agent.poll_for_callbacks(callback_url, timeout=1)
            self.assertEqual(len(callbacks), 1)
            
            callback = callbacks[0]
            self.assertEqual(callback.token, token)
            self.assertEqual(callback.source_ip, '192.168.1.100')
            self.assertIn('Test Browser', callback.user_agent)


class TestOASTOrchestration(unittest.TestCase):
    """Test OAST integration with main orchestrator"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.config = {
            'oast_mode': 'auto',
            'oast_threshold': 0.5,  # Lower threshold for testing
            'oast_max_per_host': 2,
            'oast_poll_timeout': 1,  # Short timeout for testing
            'oast_whitelist': ['127.0.0.1', 'localhost', 'test.local']
        }
    
    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @patch('dynamic_xss_agent.ReconAgent')
    @patch('dynamic_xss_agent.DynamicPayloadAgent')
    @patch('dynamic_xss_agent.DynamicVerifierAgent')
    async def test_no_oast_when_nuclei_hits_confirmed(self, mock_verifier, mock_payload, mock_recon):
        """Test that OAST is not triggered when Nuclei finds confirmed exploits"""
        
        # Mock Nuclei finding a confirmed vulnerability
        from dynamic_xss_agent import NucleiResult, VulnerabilityContext, PayloadAttempt, VerificationResult
        
        mock_nuclei_result = NucleiResult(
            template_id="xss-reflected",
            template_name="Reflected XSS",
            severity="high",
            description="Test XSS vulnerability",
            matched_url="http://localhost/test?q=<script>alert(1)</script>",
            injection_point="q"
        )
        
        mock_recon.return_value.run = AsyncMock(return_value=[mock_nuclei_result])
        
        # Mock successful payload verification
        mock_verification = VerificationResult(
            url="http://localhost/test",
            payload="<script>alert(1)</script>",
            executed=True,  # Confirmed exploit
            reflection_found=True,
            execution_method="alert"
        )
        
        mock_payload_attempt = PayloadAttempt(
            attempt=1,
            payload="<script>alert(1)</script>",
            reasoning="Test payload",
            result="success",
            playwright_response=mock_verification
        )
        
        mock_payload.return_value.generate_initial_payload = AsyncMock(return_value=mock_payload_attempt)
        mock_verifier.return_value.run = AsyncMock(return_value=mock_verification)
        
        # Mock get_persistence_candidates to ensure it's not called
        mock_recon.return_value.get_persistence_candidates = AsyncMock(return_value=[])
        
        orchestrator = DynamicXSSOrchestrator(config=self.config)
        results = await orchestrator.verify_xss("http://localhost/test")
        
        # Should have one successful result from Nuclei
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]['successful'])
        
        # get_persistence_candidates should NOT have been called
        mock_recon.return_value.get_persistence_candidates.assert_not_called()
    
    @patch('dynamic_xss_agent.ReconAgent')
    @patch('dynamic_xss_agent.DynamicPayloadAgent') 
    @patch('dynamic_xss_agent.DynamicVerifierAgent')
    async def test_oast_trigger_on_high_score_candidate(self, mock_verifier, mock_payload, mock_recon):
        """Test OAST triggering when high-score candidates are found"""
        
        # Mock no Nuclei results (to trigger OAST)
        mock_recon.return_value.run = AsyncMock(return_value=[])
        
        # Mock high-scoring persistence candidate
        high_score_candidate = PersistenceCandidate(
            id="high_score_form",
            url="http://localhost/comment",
            method="POST",
            params={"comment": "test", "name": "user"},
            field_names=["comment", "name"],
            has_file_upload=False,
            requires_auth=False,
            js_templating_score=0.6,
            path_keywords_score=0.8,
            evidence_snippet="<form method=POST action=/comment>"
        )
        
        mock_recon.return_value.get_persistence_candidates = AsyncMock(
            return_value=[high_score_candidate]
        )
        
        # Mock verifier for OAST payload injection
        mock_injection_result = VerificationResult(
            url="http://localhost/comment?xss=<payload>",
            payload="<script>fetch('http://127.0.0.1:8090/token123')</script>",
            executed=False,  # OAST payload doesn't execute immediately
            reflection_found=True,
            response_status=200
        )
        
        mock_verifier.return_value.run = AsyncMock(return_value=mock_injection_result)
        
        # Create orchestrator with OAST enabled
        orchestrator = DynamicXSSOrchestrator(config=self.config)
        
        # Mock OAST agent to simulate successful callback
        if orchestrator.oast_agent:
            orchestrator.oast_agent.register_token = AsyncMock(return_value="http://127.0.0.1:8090/token123")
            
            # Mock callback received
            mock_callback = OASTCallback(
                token="token123",
                callback_time="2025-01-01T12:00:00Z",
                source_ip="127.0.0.1",
                user_agent="Test Browser",
                headers={"Host": "test"},
                body="callback received",
                callback_type="http",
                raw_data={}
            )
            
            orchestrator.oast_agent.poll_for_callbacks = AsyncMock(return_value=[mock_callback])
        
        results = await orchestrator.verify_xss("http://localhost/test")
        
        # Should have OAST results
        self.assertGreater(len(results), 0)
        
        # Check for OAST attempt in results
        oast_results = [r for r in results if r.get('type') == 'oast_attempt']
        self.assertGreater(len(oast_results), 0)
        
        oast_result = oast_results[0]
        self.assertTrue(oast_result['successful'])
        self.assertGreater(len(oast_result['callbacks']), 0)
    
    @patch('dynamic_xss_agent.ReconAgent')
    async def test_oast_skipped_on_low_score_or_waf(self, mock_recon):
        """Test OAST skipping when candidates have low scores or WAF detected"""
        
        # Mock no Nuclei results
        mock_recon.return_value.run = AsyncMock(return_value=[])
        
        # Mock low-scoring candidate
        low_score_candidate = PersistenceCandidate(
            id="low_score",
            url="http://localhost/info",
            method="GET", 
            params={"page": "info"},
            field_names=[],
            has_file_upload=False,
            requires_auth=False,
            js_templating_score=0.1,
            path_keywords_score=0.1,
            evidence_snippet="<a href=/info>Info</a>"
        )
        
        mock_recon.return_value.get_persistence_candidates = AsyncMock(
            return_value=[low_score_candidate]
        )
        
        orchestrator = DynamicXSSOrchestrator(config=self.config)
        results = await orchestrator.verify_xss("http://localhost/test")
        
        # Should have no OAST attempts due to low scores
        oast_results = [r for r in results if r.get('type') == 'oast_attempt']
        self.assertEqual(len(oast_results), 0)
    
    @patch('dynamic_xss_agent.ReconAgent')
    async def test_oast_rate_limit_enforced(self, mock_recon):
        """Test OAST rate limiting per host"""
        
        # Mock no Nuclei results
        mock_recon.return_value.run = AsyncMock(return_value=[])
        
        # Create multiple high-scoring candidates for same host
        candidates = []
        for i in range(5):  # More than max_per_host (2)
            candidate = PersistenceCandidate(
                id=f"candidate_{i}",
                url=f"http://localhost/form{i}",
                method="POST",
                params={"data": "test"},
                field_names=["data"],
                has_file_upload=False,
                requires_auth=False,
                js_templating_score=0.7,
                path_keywords_score=0.8,
                evidence_snippet=f"<form {i}>"
            )
            candidates.append(candidate)
        
        mock_recon.return_value.get_persistence_candidates = AsyncMock(
            return_value=candidates
        )
        
        orchestrator = DynamicXSSOrchestrator(config=self.config)
        
        # Mock OAST agent
        if orchestrator.oast_agent:
            orchestrator.oast_agent.register_token = AsyncMock(return_value="http://127.0.0.1:8090/token")
            orchestrator.oast_agent.poll_for_callbacks = AsyncMock(return_value=[])
        
        results = await orchestrator.verify_xss("http://localhost/test")
        
        # Should only have attempted max_per_host (2) OAST tests
        oast_results = [r for r in results if r.get('type') == 'oast_attempt']
        self.assertEqual(len(oast_results), self.config['oast_max_per_host'])


class TestOASTNeverMode(unittest.TestCase):
    """Test OAST never mode functionality"""
    
    @patch('dynamic_xss_agent.ReconAgent')
    async def test_oast_never_mode_disables_all_oast(self, mock_recon):
        """Test that OAST mode 'never' completely disables OAST testing"""
        
        # Mock no Nuclei results (would normally trigger OAST)
        mock_recon.return_value.run = AsyncMock(return_value=[])
        
        config = {
            'oast_mode': 'never',  # Disable OAST
            'oast_threshold': 0.1,
            'oast_whitelist': ['localhost']
        }
        
        orchestrator = DynamicXSSOrchestrator(config=config)
        results = await orchestrator.verify_xss("http://localhost/test")
        
        # Should have no results and no OAST attempts
        self.assertEqual(len(results), 0)
        
        # get_persistence_candidates should not be called
        mock_recon.return_value.get_persistence_candidates.assert_not_called()


if __name__ == '__main__':
    # Create test directories
    os.makedirs('tests', exist_ok=True)
    
    # Run tests
    unittest.main(verbosity=2)