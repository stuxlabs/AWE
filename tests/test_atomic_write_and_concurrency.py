#!/usr/bin/env python3
"""
Test Atomic Write and Concurrency

This test file validates that the forensic logging system handles concurrent
operations correctly and performs atomic file operations to prevent data corruption.
"""

import asyncio
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.forensic_logger import AtomicFileWriter, ForensicLoggerManager
from utils.logging_integration import LoggingIntegration


class TestAtomicFileWriter(unittest.TestCase):
    """Test atomic file writing operations"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp(prefix="atomic_test_")
        
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_atomic_write_file(self):
        """Test basic atomic file writing"""
        
        test_file = Path(self.temp_dir) / 'test.txt'
        test_content = "Test atomic write content"
        
        # Write atomically
        AtomicFileWriter.write_file(test_file, test_content)
        
        # File should exist and have correct content
        self.assertTrue(test_file.exists())
        
        with open(test_file, 'r') as f:
            content = f.read()
        
        self.assertEqual(content, test_content)
    
    def test_atomic_write_binary_file(self):
        """Test atomic binary file writing"""
        
        test_file = Path(self.temp_dir) / 'test.bin'
        test_content = b"Binary content \x00\x01\x02"
        
        # Write atomically
        AtomicFileWriter.write_binary_file(test_file, test_content)
        
        # File should exist and have correct content
        self.assertTrue(test_file.exists())
        
        with open(test_file, 'rb') as f:
            content = f.read()
        
        self.assertEqual(content, test_content)
    
    def test_atomic_write_creates_directories(self):
        """Test that atomic write creates necessary directories"""
        
        nested_file = Path(self.temp_dir) / 'deep' / 'nested' / 'path' / 'test.txt'
        test_content = "Nested file content"
        
        # Write to nested path (directories don't exist yet)
        AtomicFileWriter.write_file(nested_file, test_content)
        
        # File and directories should exist
        self.assertTrue(nested_file.exists())
        self.assertTrue(nested_file.parent.exists())
        
        with open(nested_file, 'r') as f:
            content = f.read()
        
        self.assertEqual(content, test_content)
    
    def test_atomic_write_overwrites_existing(self):
        """Test that atomic write correctly overwrites existing files"""
        
        test_file = Path(self.temp_dir) / 'overwrite_test.txt'
        
        # Create initial file
        initial_content = "Initial content"
        AtomicFileWriter.write_file(test_file, initial_content)
        
        # Verify initial content
        with open(test_file, 'r') as f:
            content = f.read()
        self.assertEqual(content, initial_content)
        
        # Overwrite with new content
        new_content = "New content that replaces the old"
        AtomicFileWriter.write_file(test_file, new_content)
        
        # Verify new content
        with open(test_file, 'r') as f:
            content = f.read()
        self.assertEqual(content, new_content)
    
    def test_append_with_lock(self):
        """Test thread-safe appending with file locking"""
        
        test_file = Path(self.temp_dir) / 'append_test.txt'
        
        # Single append operation
        with AtomicFileWriter.append_with_lock(test_file) as f:
            f.write("Line 1\n")
        
        with AtomicFileWriter.append_with_lock(test_file) as f:
            f.write("Line 2\n")
        
        # Verify content
        with open(test_file, 'r') as f:
            content = f.read()
        
        self.assertEqual(content, "Line 1\nLine 2\n")


class TestConcurrentLogging(unittest.TestCase):
    """Test concurrent access to logging system"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp(prefix="concurrent_test_")
        
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_concurrent_events_jsonl_writes(self):
        """Test concurrent writing to events.jsonl file"""
        
        logger_manager = ForensicLoggerManager(base_log_dir=self.temp_dir)
        cid = logger_manager.start_run("http://test.local/concurrent")
        
        num_threads = 10
        events_per_thread = 20
        
        def write_events(thread_id):
            """Write events from a single thread"""
            for i in range(events_per_thread):
                logger_manager.log_event(f'test.concurrent.thread_{thread_id}', {
                    'thread_id': thread_id,
                    'event_number': i,
                    'timestamp': time.time(),
                    'data': f'test_data_{thread_id}_{i}'
                })
                # Small delay to increase chance of concurrency conflicts
                time.sleep(0.001)
        
        # Run concurrent writes
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(write_events, i) for i in range(num_threads)]
            
            # Wait for all threads to complete
            for future in futures:
                future.result()
        
        # Verify events.jsonl integrity
        events_file = logger_manager.current_run_dir / 'events.jsonl'
        self.assertTrue(events_file.exists())
        
        # Read and validate all events
        events = []
        with open(events_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                try:
                    event = json.loads(line.strip())
                    events.append(event)
                except json.JSONDecodeError as e:
                    self.fail(f"Invalid JSON at line {line_num}: {e}\nLine content: {line[:100]}")
        
        # Should have all expected events plus the run.started event
        expected_events = num_threads * events_per_thread
        actual_events = len([e for e in events if e['event_type'].startswith('test.concurrent')])
        
        self.assertEqual(actual_events, expected_events, 
                         f"Expected {expected_events} events, got {actual_events}")
        
        # Verify all threads contributed
        thread_ids = set()
        for event in events:
            if event['event_type'].startswith('test.concurrent'):
                thread_ids.add(event['payload']['thread_id'])
        
        self.assertEqual(len(thread_ids), num_threads, "All threads should have contributed events")
        
        logger_manager.finish_run()
    
    def test_concurrent_attempt_logging(self):
        """Test concurrent attempt logging operations"""
        
        logger_manager = ForensicLoggerManager(base_log_dir=self.temp_dir)
        cid = logger_manager.start_run("http://test.local/attempts")
        
        num_concurrent_attempts = 5
        
        def simulate_attempt(attempt_num):
            """Simulate a complete attempt with all logging operations"""
            integration = LoggingIntegration(logger_manager)
            
            # Start attempt
            attempt_id = integration.start_attempt(f"vuln_{attempt_num}", {
                'attempt_number': attempt_num,
                'vulnerability_id': f'test_vuln_{attempt_num}'
            })
            
            # Log LLM interaction
            integration.log_llm_call(
                prompt=f"Generate payload for attempt {attempt_num}",
                response=f'{{"payload": "test{attempt_num}", "reasoning": "test"}}',
                model="test-model"
            )
            
            # Log HTTP request/response
            integration.log_http_call(
                request={
                    'method': 'GET',
                    'url': f'http://test.local/vuln{attempt_num}',
                    'headers': {'User-Agent': f'TestAgent{attempt_num}'},
                    'body': ''
                },
                response={
                    'status': 200,
                    'headers': {'Content-Type': 'text/html'},
                    'body': f'<html>Response {attempt_num}</html>'
                }
            )
            
            # Log verification
            integration.log_verification({
                'url': f'http://test.local/vuln{attempt_num}',
                'payload': f'<script>alert({attempt_num})</script>',
                'executed': attempt_num % 2 == 0,  # Alternate success/failure
                'reflection_found': True,
                'console_logs': [{'type': 'log', 'text': f'Console {attempt_num}'}],
                'alerts_caught': [f'Alert {attempt_num}'] if attempt_num % 2 == 0 else []
            })
            
            # Finish attempt
            integration.finish_attempt(
                payload=f'<script>alert({attempt_num})</script>',
                result="success" if attempt_num % 2 == 0 else "failure",
                artifacts={'test': f'artifact_{attempt_num}'}
            )
            
            return attempt_id
        
        # Run concurrent attempts
        with ThreadPoolExecutor(max_workers=num_concurrent_attempts) as executor:
            futures = [executor.submit(simulate_attempt, i) for i in range(num_concurrent_attempts)]
            
            # Collect results
            attempt_ids = [future.result() for future in futures]
        
        # Verify all attempts completed
        self.assertEqual(len(attempt_ids), num_concurrent_attempts)
        self.assertEqual(len(set(attempt_ids)), num_concurrent_attempts)  # All unique
        
        # Verify attempt files were created
        attempts_dir = logger_manager.current_run_dir / 'attempts'
        attempt_files = list(attempts_dir.glob('*.json'))
        self.assertEqual(len(attempt_files), num_concurrent_attempts)
        
        # Verify each attempt file is valid JSON
        for attempt_file in attempt_files:
            with open(attempt_file, 'r') as f:
                attempt_data = json.load(f)
            
            # Verify required fields
            required_fields = ['attempt_id', 'correlation_id', 'payload', 'result']
            for field in required_fields:
                self.assertIn(field, attempt_data)
        
        # Verify LLM files were created (both raw and redacted)
        llm_redacted_dir = logger_manager.current_run_dir / 'llm/redacted'
        redacted_files = list(llm_redacted_dir.glob('*.txt'))
        self.assertGreater(len(redacted_files), 0)
        
        # Verify HTTP request files were created
        replay_dir = logger_manager.current_run_dir / 'replay'
        replay_files = list(replay_dir.glob('*.json'))
        self.assertGreater(len(replay_files), 0)
        
        logger_manager.finish_run()
    
    def test_concurrent_file_operations_integrity(self):
        """Test that concurrent file operations maintain data integrity"""
        
        logger_manager = ForensicLoggerManager(base_log_dir=self.temp_dir)
        cid = logger_manager.start_run("http://test.local/integrity")
        
        # Track all operations for verification
        operation_log = []
        lock = threading.Lock()
        
        def log_operation(op_type, file_path, content_id):
            with lock:
                operation_log.append({
                    'operation': op_type,
                    'file': str(file_path),
                    'content_id': content_id,
                    'timestamp': time.time(),
                    'thread_id': threading.get_ident()
                })
        
        def concurrent_file_writer(writer_id):
            """Write multiple files concurrently"""
            integration = LoggingIntegration(logger_manager)
            
            for i in range(10):
                content_id = f"{writer_id}_{i}"
                
                # Log LLM interaction
                llm_files = integration.log_llm_call(
                    prompt=f"Prompt {content_id}",
                    response=f'{{"content_id": "{content_id}", "data": "test"}}',
                    model="test-model"
                )
                
                log_operation('llm', llm_files['response_redacted_file'], content_id)
                
                # Log HTTP call
                http_file = integration.log_http_call(
                    request={
                        'method': 'GET',
                        'url': f'http://test.local/{content_id}',
                        'headers': {},
                        'body': ''
                    },
                    response={
                        'status': 200,
                        'headers': {},
                        'body': f'Response for {content_id}'
                    }
                )
                
                log_operation('http', http_file, content_id)
                
                # Small delay to increase concurrency
                time.sleep(0.002)
        
        # Run concurrent writers
        num_writers = 8
        with ThreadPoolExecutor(max_workers=num_writers) as executor:
            futures = [executor.submit(concurrent_file_writer, i) for i in range(num_writers)]
            
            for future in futures:
                future.result()
        
        # Verify all operations completed
        expected_operations = num_writers * 10 * 2  # 2 operations per iteration
        self.assertEqual(len(operation_log), expected_operations)
        
        # Verify file contents match expected content IDs
        for operation in operation_log:
            file_path = logger_manager.current_run_dir / operation['file']
            content_id = operation['content_id']
            
            self.assertTrue(file_path.exists(), f"File should exist: {file_path}")
            
            with open(file_path, 'r') as f:
                file_content = f.read()
            
            # Content should contain the expected content ID
            self.assertIn(content_id, file_content, 
                         f"File {file_path} should contain {content_id}")
        
        logger_manager.finish_run()
    
    def test_atomic_write_interruption_safety(self):
        """Test that atomic writes are safe even with interruption"""
        
        test_file = Path(self.temp_dir) / 'interruption_test.txt'
        
        # Simulate interruption during write
        class SimulatedInterruption(Exception):
            pass
        
        original_write = AtomicFileWriter.write_file
        
        def interrupted_write(filepath, content, mode='w'):
            """Simulate interruption during atomic write"""
            if "interrupt" in content:
                # Call original to create temp file, then raise exception
                try:
                    # Create temp file but don't complete the operation
                    temp_path = Path(str(filepath) + '.tmp')
                    with open(temp_path, mode, encoding='utf-8' if 'b' not in mode else None) as f:
                        f.write(content[:len(content)//2])  # Partial write
                    raise SimulatedInterruption("Simulated interruption")
                except SimulatedInterruption:
                    raise
            else:
                # Normal write
                return original_write(filepath, content, mode)
        
        # Patch the write method
        AtomicFileWriter.write_file = interrupted_write
        
        try:
            # First, write normal content
            AtomicFileWriter.write_file(test_file, "Normal content")
            
            # Verify normal write worked
            with open(test_file, 'r') as f:
                content = f.read()
            self.assertEqual(content, "Normal content")
            
            # Now try interrupted write
            with self.assertRaises(SimulatedInterruption):
                AtomicFileWriter.write_file(test_file, "interrupt this write")
            
            # Original file should still exist with original content
            self.assertTrue(test_file.exists())
            with open(test_file, 'r') as f:
                content = f.read()
            self.assertEqual(content, "Normal content")
            
            # No temp files should remain
            temp_files = list(test_file.parent.glob('*.tmp'))
            self.assertEqual(len(temp_files), 0, "No temp files should remain after interruption")
            
        finally:
            # Restore original method
            AtomicFileWriter.write_file = original_write


class TestAsyncConcurrency(unittest.TestCase):
    """Test async concurrency in forensic logging"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp(prefix="async_test_")
        
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_async_concurrent_logging(self):
        """Test concurrent async logging operations"""
        
        async def async_logging_task(task_id, logger_manager):
            """Async task that performs logging operations"""
            integration = LoggingIntegration(logger_manager)
            
            # Start attempt
            attempt_id = integration.start_attempt(f"async_vuln_{task_id}", {
                'task_id': task_id,
                'is_async': True
            })
            
            # Simulate some async work
            await asyncio.sleep(0.01)
            
            # Log multiple operations
            for i in range(5):
                integration.log_llm_call(
                    prompt=f"Async prompt {task_id}-{i}",
                    response=f'{{"task_id": {task_id}, "iteration": {i}}}',
                    model="async-model"
                )
                
                # Small async delay
                await asyncio.sleep(0.005)
            
            # Finish attempt
            integration.finish_attempt(
                payload=f"async_payload_{task_id}",
                result="success",
                artifacts={'async': True, 'task_id': task_id}
            )
            
            return task_id
        
        async def run_async_test():
            """Run the async concurrency test"""
            logger_manager = ForensicLoggerManager(base_log_dir=self.temp_dir)
            cid = logger_manager.start_run("http://test.local/async")
            
            # Run multiple async tasks concurrently
            num_tasks = 10
            tasks = [async_logging_task(i, logger_manager) for i in range(num_tasks)]
            
            results = await asyncio.gather(*tasks)
            
            logger_manager.finish_run()
            return results, logger_manager
        
        # Run the test
        results, logger_manager = asyncio.run(run_async_test())
        
        # Verify results
        self.assertEqual(len(results), 10)
        self.assertEqual(sorted(results), list(range(10)))
        
        # Verify files were created correctly
        attempts_dir = logger_manager.current_run_dir / 'attempts'
        attempt_files = list(attempts_dir.glob('*.json'))
        self.assertEqual(len(attempt_files), 10)
        
        # Verify events.jsonl integrity
        events_file = logger_manager.current_run_dir / 'events.jsonl'
        with open(events_file, 'r') as f:
            events = [json.loads(line) for line in f]
        
        # Should have events from all async tasks
        async_events = [e for e in events if 'async' in str(e.get('payload', {}))]
        self.assertGreater(len(async_events), 0)


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)