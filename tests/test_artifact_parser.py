#!/usr/bin/env python3
"""
Comprehensive Unit Tests for XSS Artifact Parser

Tests all major functionality with embedded sample data to run offline.
"""

import json
import tempfile
import unittest
from pathlib import Path
from datetime import datetime

# Add parent directory to path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from artifact_parser import ArtifactParser, PayloadAnalyzer, HarEntry, Finding


class TestSampleData:
    """Container for embedded test data"""

    # Sample HAR data for different scenarios
    HAR_STORED_RAW = {
        "log": {
            "version": "1.2",
            "creator": {"name": "test", "version": "1.0"},
            "entries": [{
                "startedDateTime": "2025-09-16T17:37:39.147004+00:00",
                "time": 100,
                "request": {
                    "method": "POST",
                    "url": "http://example.com/submit",
                    "httpVersion": "HTTP/1.1",
                    "headers": [
                        {"name": "Content-Type", "value": "application/x-www-form-urlencoded"}
                    ],
                    "postData": {
                        "mimeType": "application/x-www-form-urlencoded",
                        "text": "comment=<script>alert(1)</script>&submit=Submit"
                    }
                },
                "response": {
                    "status": 200,
                    "statusText": "OK",
                    "httpVersion": "HTTP/1.1",
                    "headers": [
                        {"name": "Content-Type", "value": "text/html"}
                    ],
                    "content": {
                        "size": 500,
                        "mimeType": "text/html",
                        "text": "<html><body><h1>Comments</h1><div class='comment'><script>alert(1)</script></div></body></html>"
                    }
                }
            }]
        }
    }

    HAR_STORED_ESCAPED = {
        "log": {
            "version": "1.2",
            "creator": {"name": "test", "version": "1.0"},
            "entries": [{
                "startedDateTime": "2025-09-16T17:37:40.147004+00:00",
                "time": 100,
                "request": {
                    "method": "POST",
                    "url": "http://example.com/submit",
                    "httpVersion": "HTTP/1.1",
                    "headers": [
                        {"name": "Content-Type", "value": "application/x-www-form-urlencoded"}
                    ],
                    "postData": {
                        "mimeType": "application/x-www-form-urlencoded",
                        "text": "comment=<script>alert(1)</script>&submit=Submit"
                    }
                },
                "response": {
                    "status": 200,
                    "statusText": "OK",
                    "httpVersion": "HTTP/1.1",
                    "headers": [
                        {"name": "Content-Type", "value": "text/html"}
                    ],
                    "content": {
                        "size": 500,
                        "mimeType": "text/html",
                        "text": "<html><body><h1>Comments</h1><div class='comment'>&lt;script&gt;alert(1)&lt;/script&gt;</div></body></html>"
                    }
                }
            }]
        }
    }

    HAR_STORED_ENCODED = {
        "log": {
            "version": "1.2",
            "creator": {"name": "test", "version": "1.0"},
            "entries": [{
                "startedDateTime": "2025-09-16T17:37:41.147004+00:00",
                "time": 100,
                "request": {
                    "method": "GET",
                    "url": "http://example.com/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
                    "httpVersion": "HTTP/1.1",
                    "headers": [
                        {"name": "Accept", "value": "text/html"}
                    ]
                },
                "response": {
                    "status": 200,
                    "statusText": "OK",
                    "httpVersion": "HTTP/1.1",
                    "headers": [
                        {"name": "Content-Type", "value": "text/html"}
                    ],
                    "content": {
                        "size": 500,
                        "mimeType": "text/html",
                        "text": "<html><body><h1>Search Results</h1><p>You searched for: %3Cscript%3Ealert(1)%3C/script%3E</p></body></html>"
                    }
                }
            }]
        }
    }

    HAR_NOT_STORED = {
        "log": {
            "version": "1.2",
            "creator": {"name": "test", "version": "1.0"},
            "entries": [{
                "startedDateTime": "2025-09-16T17:37:42.147004+00:00",
                "time": 100,
                "request": {
                    "method": "POST",
                    "url": "http://example.com/submit",
                    "httpVersion": "HTTP/1.1",
                    "headers": [
                        {"name": "Content-Type", "value": "application/x-www-form-urlencoded"}
                    ],
                    "postData": {
                        "mimeType": "application/x-www-form-urlencoded",
                        "text": "comment=<script>alert(1)</script>&submit=Submit"
                    }
                },
                "response": {
                    "status": 200,
                    "statusText": "OK",
                    "httpVersion": "HTTP/1.1",
                    "headers": [
                        {"name": "Content-Type", "value": "text/html"}
                    ],
                    "content": {
                        "size": 500,
                        "mimeType": "text/html",
                        "text": "<html><body><h1>Comments</h1><div class='comment'>Thank you for your comment!</div></body></html>"
                    }
                }
            }]
        }
    }

    HAR_NOT_SUBMITTED = {
        "log": {
            "version": "1.2",
            "creator": {"name": "test", "version": "1.0"},
            "entries": [{
                "startedDateTime": "2025-09-16T17:37:43.147004+00:00",
                "time": 100,
                "request": {
                    "method": "GET",
                    "url": "http://example.com/page",
                    "httpVersion": "HTTP/1.1",
                    "headers": [
                        {"name": "Accept", "value": "text/html"}
                    ]
                },
                "response": {
                    "status": 200,
                    "statusText": "OK",
                    "httpVersion": "HTTP/1.1",
                    "headers": [
                        {"name": "Content-Type", "value": "text/html"}
                    ],
                    "content": {
                        "size": 300,
                        "mimeType": "text/html",
                        "text": "<html><body><h1>Regular Page</h1><p>Nothing here.</p></body></html>"
                    }
                }
            }]
        }
    }

    # Sample HTML captures
    HTML_STORED_RAW = "<html><body><div class='comments'><p>User said: <script>alert(1)</script></p></div></body></html>"
    HTML_STORED_ESCAPED = "<html><body><div class='comments'><p>User said: &lt;script&gt;alert(1)&lt;/script&gt;</p></div></body></html>"
    HTML_STORED_ENCODED = "<html><body><div class='comments'><p>You searched for: %3Cscript%3Ealert(1)%3C/script%3E</p></div></body></html>"
    HTML_STORED_MODIFIED = "<html><body><div class='comments'><p>User said: &lt;img src=x onerror=[removed]&gt;</p></div></body></html>"
    HTML_NOT_STORED = "<html><body><div class='comments'><p>No comments yet.</p></div></body></html>"
    HTML_NOT_SUBMITTED = "<html><body><div class='comments'><p>Regular page content.</p></div></body></html>"

    # Sample attempt metadata
    ATTEMPT_METADATA = {
        "attempt_id": "attempt_001",
        "vulnerability_id": "vuln_001",
        "cid": "20250916_173713_test",
        "url": "http://example.com/submit",
        "method": "POST",
        "parameter": "comment",
        "payload": "<script>alert(1)</script>",
        "submitted_payload": "<script>alert(1)</script>",
        "injection_type": "form_field",
        "timestamp": "2025-09-16T17:37:39.000000"
    }


class TestPayloadAnalyzer(unittest.TestCase):
    """Test the AI-powered payload analyzer"""

    def setUp(self):
        self.analyzer = PayloadAnalyzer()
        self.payload = "<script>alert(1)</script>"

    def test_analyze_stored_raw(self):
        """Test detection of raw stored payload"""
        content = TestSampleData.HTML_STORED_RAW
        result = self.analyzer.analyze_payload_transformation(self.payload, content)

        self.assertEqual(result['transformation_type'], 'stored_raw')
        self.assertEqual(result['confidence'], 1.0)

    def test_analyze_html_entity_encoding(self):
        """Test detection of HTML entity encoding"""
        content = TestSampleData.HTML_STORED_ESCAPED
        result = self.analyzer.analyze_payload_transformation(self.payload, content)

        self.assertEqual(result['transformation_type'], 'html_entity_encoded')
        self.assertGreater(result['confidence'], 0.9)
        self.assertEqual(result['encoding_method'], 'html_entities')
        self.assertIn('HTML entity breaking', ' '.join(result['bypass_suggestions']))

    def test_analyze_url_encoding(self):
        """Test detection of URL encoding"""
        content = "Search results for: %3Cscript%3Ealert(1)%3C/script%3E"
        result = self.analyzer.analyze_payload_transformation(self.payload, content)

        self.assertEqual(result['transformation_type'], 'url_encoded')
        self.assertGreater(result['confidence'], 0.8)
        self.assertEqual(result['encoding_method'], 'percent_encoding')

    def test_analyze_modified_payload(self):
        """Test detection of modified/filtered payload"""
        content = TestSampleData.HTML_STORED_MODIFIED
        result = self.analyzer.analyze_payload_transformation("<img src=x onerror=alert(1)>", content)

        self.assertIn(result['transformation_type'], ['modified_or_filtered', 'partially_modified'])
        self.assertGreater(result['confidence'], 0.3)
        self.assertIn('bypass', ' '.join(result['bypass_suggestions']).lower())

    def test_analyze_removed_payload(self):
        """Test detection of completely removed payload"""
        content = TestSampleData.HTML_NOT_STORED
        result = self.analyzer.analyze_payload_transformation(self.payload, content)

        self.assertEqual(result['transformation_type'], 'removed_or_filtered')
        self.assertGreater(result['confidence'], 0.8)
        self.assertIn('alternative', ' '.join(result['bypass_suggestions']).lower())


class TestHarEntry(unittest.TestCase):
    """Test HAR entry parsing"""

    def test_har_entry_creation(self):
        """Test creation of HarEntry from HAR JSON"""
        har_entry_json = TestSampleData.HAR_STORED_RAW['log']['entries'][0]
        har_entry = HarEntry.from_har_entry(har_entry_json)

        self.assertEqual(har_entry.method, 'POST')
        self.assertEqual(har_entry.url, 'http://example.com/submit')
        self.assertEqual(har_entry.response_status, 200)
        self.assertIn('<script>alert(1)</script>', har_entry.request_body)
        self.assertIn('<script>alert(1)</script>', har_entry.response_body)

    def test_har_entry_headers(self):
        """Test HAR entry header parsing"""
        har_entry_json = TestSampleData.HAR_STORED_RAW['log']['entries'][0]
        har_entry = HarEntry.from_har_entry(har_entry_json)

        self.assertIn('Content-Type', har_entry.request_headers)
        self.assertEqual(har_entry.request_headers['Content-Type'], 'application/x-www-form-urlencoded')


class TestArtifactParser(unittest.TestCase):
    """Test the main artifact parser"""

    def setUp(self):
        self.parser = ArtifactParser()
        self.temp_dir = tempfile.mkdtemp()
        self.temp_path = Path(self.temp_dir)

    def tearDown(self):
        # Clean up temp files
        import shutil
        shutil.rmtree(self.temp_dir)

    def _create_test_files(self, scenario: str):
        """Create test files for a specific scenario"""
        # Create HAR file
        har_data = getattr(TestSampleData, f'HAR_{scenario}')
        har_path = self.temp_path / 'test.har'
        with open(har_path, 'w') as f:
            json.dump(har_data, f)

        # Create HTML file
        html_content = getattr(TestSampleData, f'HTML_{scenario}')
        html_path = self.temp_path / 'test.html'
        with open(html_path, 'w') as f:
            f.write(html_content)

        # Create attempt metadata file
        attempt_data = TestSampleData.ATTEMPT_METADATA.copy()
        attempt_data['scenario'] = scenario
        attempt_path = self.temp_path / 'attempt.json'
        with open(attempt_path, 'w') as f:
            json.dump(attempt_data, f)

        return str(attempt_path), [str(har_path)], [str(html_path)]

    def test_load_har(self):
        """Test HAR file loading"""
        har_path = self.temp_path / 'test.har'
        with open(har_path, 'w') as f:
            json.dump(TestSampleData.HAR_STORED_RAW, f)

        entries = self.parser.load_har(str(har_path))
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].method, 'POST')

    def test_load_html(self):
        """Test HTML file loading"""
        html_path = self.temp_path / 'test.html'
        with open(html_path, 'w') as f:
            f.write(TestSampleData.HTML_STORED_RAW)

        content = self.parser.load_html(str(html_path))
        self.assertIn('<script>alert(1)</script>', content)

    def test_analyze_attempt_stored_raw(self):
        """Test analysis of stored raw payload scenario"""
        attempt_path, har_paths, html_paths = self._create_test_files('STORED_RAW')

        finding = self.parser.analyze_attempt(attempt_path, har_paths, html_paths)

        self.assertEqual(finding.difference_summary, 'stored_raw')
        self.assertEqual(finding.submitted_payload, '<script>alert(1)</script>')
        self.assertTrue(finding.request_seen_in_har)
        self.assertTrue(finding.stored_in_response)
        self.assertIn('SUCCESS', finding.recommendation)
        self.assertGreater(finding.confidence_score, 0.9)

    def test_analyze_attempt_stored_escaped(self):
        """Test analysis of HTML entity escaped payload scenario"""
        attempt_path, har_paths, html_paths = self._create_test_files('STORED_ESCAPED')

        finding = self.parser.analyze_attempt(attempt_path, har_paths, html_paths)

        self.assertEqual(finding.difference_summary, 'stored_escaped')
        self.assertTrue(finding.escaped)
        self.assertTrue(finding.request_seen_in_har)
        self.assertTrue(finding.stored_in_response)
        self.assertIn('entity', finding.recommendation.lower())
        self.assertIn('polyglot', finding.recommendation.lower())

    def test_analyze_attempt_stored_encoded(self):
        """Test analysis of URL encoded payload scenario"""
        attempt_path, har_paths, html_paths = self._create_test_files('STORED_ENCODED')

        finding = self.parser.analyze_attempt(attempt_path, har_paths, html_paths)

        self.assertEqual(finding.difference_summary, 'stored_encoded')
        self.assertTrue(finding.encoded)
        self.assertTrue(finding.request_seen_in_har)

    def test_analyze_attempt_not_stored(self):
        """Test analysis of payload not stored scenario"""
        attempt_path, har_paths, html_paths = self._create_test_files('NOT_STORED')

        finding = self.parser.analyze_attempt(attempt_path, har_paths, html_paths)

        self.assertEqual(finding.difference_summary, 'not_stored')
        self.assertTrue(finding.request_seen_in_har)
        self.assertFalse(finding.stored_in_response)
        self.assertIn('endpoint', finding.recommendation.lower())

    def test_analyze_attempt_not_submitted(self):
        """Test analysis of payload not submitted scenario"""
        attempt_path, har_paths, html_paths = self._create_test_files('NOT_SUBMITTED')

        finding = self.parser.analyze_attempt(attempt_path, har_paths, html_paths)

        self.assertEqual(finding.difference_summary, 'not_submitted')
        self.assertFalse(finding.request_seen_in_har)
        self.assertIn('proxy', finding.recommendation.lower())

    def test_extract_context_snippet(self):
        """Test context snippet extraction"""
        content = "Before text <script>alert(1)</script> after text"
        payload = "<script>alert(1)</script>"

        snippet = self.parser._extract_context_snippet(content, payload, context_size=10)
        self.assertIn(payload, snippet)
        self.assertIn('Before', snippet)
        self.assertIn('after', snippet)

    def test_save_findings(self):
        """Test saving findings to files"""
        # Create a sample finding
        finding = Finding(
            attempt_id="test_001",
            vulnerability_id="vuln_001",
            cid="test_cid",
            injection_point={"url": "http://example.com", "method": "POST", "parameter": "test"},
            submitted_payload="<script>alert(1)</script>",
            request_seen_in_har=True,
            response_status=200,
            stored_in_response=True,
            stored_snippet="<script>alert(1)</script>",
            escaped=False,
            encoded=False,
            modified=False,
            difference_summary="stored_raw",
            recommendation="SUCCESS: Raw payload stored",
            evidence_paths=["/test/path"],
            confidence_score=1.0,
            ai_analysis={"transformation_type": "stored_raw"}
        )

        output_dir = self.temp_path / "output"
        self.parser.save_findings([finding], str(output_dir))

        # Check files were created
        self.assertTrue((output_dir / "diagnostics.jsonl").exists())
        self.assertTrue((output_dir / "report.txt").exists())

        # Check JSONL content
        with open(output_dir / "diagnostics.jsonl", 'r') as f:
            data = json.loads(f.readline())
            self.assertEqual(data['attempt_id'], 'test_001')
            self.assertEqual(data['difference_summary'], 'stored_raw')

        # Check report content
        with open(output_dir / "report.txt", 'r') as f:
            report = f.read()
            self.assertIn('XSS Artifact Analysis Report', report)
            self.assertIn('stored_raw: 1', report)
            self.assertIn('test_001', report)


class TestIntegration(unittest.TestCase):
    """Integration tests with realistic scenarios"""

    def setUp(self):
        self.parser = ArtifactParser()
        self.temp_dir = tempfile.mkdtemp()
        self.temp_path = Path(self.temp_dir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir)

    def test_full_session_analysis(self):
        """Test analysis of a complete session directory structure"""
        # Create session directory structure
        session_dir = self.temp_path / "logs" / "20250916_173713_test"
        attempts_dir = session_dir / "attempts"
        attempts_dir.mkdir(parents=True)

        # Create multiple attempt files
        for i, scenario in enumerate(['STORED_RAW', 'STORED_ESCAPED', 'NOT_STORED'], 1):
            # HAR data
            har_data = getattr(TestSampleData, f'HAR_{scenario}')

            # HTML data
            html_content = getattr(TestSampleData, f'HTML_{scenario}')

            # Attempt metadata
            attempt_data = TestSampleData.ATTEMPT_METADATA.copy()
            attempt_data['attempt_id'] = f'attempt_{i:03d}'
            attempt_data['payload'] = f'<script>alert({i})</script>'

            # Save attempt file
            attempt_file = attempts_dir / f'attempt_{i:03d}.json'
            with open(attempt_file, 'w') as f:
                json.dump(attempt_data, f)

        # Create proxy captures directory with HAR files
        proxy_dir = self.temp_path / "proxy_captures"
        proxy_dir.mkdir()

        for i, scenario in enumerate(['STORED_RAW', 'STORED_ESCAPED', 'NOT_STORED'], 1):
            har_data = getattr(TestSampleData, f'HAR_{scenario}')
            har_file = proxy_dir / f'capture_{i}.har'
            with open(har_file, 'w') as f:
                json.dump(har_data, f)

        # Analyze the session
        findings = self.parser.analyze_run(str(session_dir))

        # Verify results
        self.assertEqual(len(findings), 3)

        summaries = [f.difference_summary for f in findings]
        self.assertIn('stored_raw', summaries)
        self.assertIn('stored_escaped', summaries)
        self.assertIn('not_stored', summaries)

    def test_recommendation_quality(self):
        """Test that AI recommendations contain expected keywords"""
        test_cases = [
            ('stored_raw', ['SUCCESS', 'exploit', 'confirmed']),
            ('stored_escaped', ['entity', 'polyglot', 'attribute']),
            ('stored_encoded', ['encoding', 'double', 'unicode']),
            ('not_stored', ['endpoint', 'authentication', 'CSRF']),
            ('not_submitted', ['proxy', 'network', 'routing'])
        ]

        for summary, expected_keywords in test_cases:
            # Create mock AI analysis
            ai_analysis = {
                'transformation_type': summary.replace('stored_', ''),
                'bypass_suggestions': ['Try alternative methods', 'Test encoding variations']
            }

            recommendation = self.parser._generate_recommendation(summary, ai_analysis)

            # Check that at least one expected keyword appears
            recommendation_lower = recommendation.lower()
            keyword_found = any(keyword.lower() in recommendation_lower for keyword in expected_keywords)

            self.assertTrue(keyword_found,
                          f"None of {expected_keywords} found in recommendation: {recommendation}")


def run_tests_manual():
    """Manual test runner for when pytest is not available"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    for test_class in [TestPayloadAnalyzer, TestHarEntry, TestArtifactParser, TestIntegration]:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Print summary
    print(f"\n=== Test Summary ===")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")

    if result.failures:
        print("\nFailures:")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback}")

    if result.errors:
        print("\nErrors:")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback}")

    return result.wasSuccessful()


if __name__ == '__main__':
    # Try pytest first, fall back to manual runner
    try:
        import pytest
        pytest.main([__file__, '-v'])
    except ImportError:
        print("pytest not available, using manual test runner...")
        success = run_tests_manual()
        exit(0 if success else 1)