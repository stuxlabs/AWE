"""
Unit tests for Agent Memory System

Tests MemoryStorage, MemoryManager, and integration with reasoning
"""

import pytest
import tempfile
import time
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.memory_storage import MemoryStorage
from utils.memory_manager import MemoryManager


class TestMemoryStorage:
    """Test MemoryStorage SQLite backend"""

    @pytest.fixture
    def storage(self):
        """Create temporary storage for testing"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name

        storage = MemoryStorage(db_path)
        yield storage
        storage.close()

        # Cleanup
        Path(db_path).unlink(missing_ok=True)

    def test_storage_creation(self, storage):
        """Test storage initialization"""
        assert storage is not None
        assert storage.db_path.exists()

    def test_record_payload_attempt(self, storage):
        """Test recording payload attempts"""
        attempt_id = storage.record_payload_attempt(
            session_id="test-session",
            target_url="https://example.com/test",
            payload="<script>alert(1)</script>",
            payload_type="xss",
            strategy="basic",
            success=False,
            transformation="&lt;script&gt;",
            detected_filter="script_block",
            confidence=0.8
        )

        assert attempt_id > 0

    def test_record_detected_filter(self, storage):
        """Test recording detected filters"""
        storage.record_detected_filter(
            target_domain="example.com",
            filter_type="script_block",
            filter_signature="<script>",
            notes="Blocks script tags"
        )

        filters = storage.get_detected_filters("example.com")
        assert len(filters) > 0
        assert filters[0]['filter_type'] == "script_block"

    def test_filter_detection_count_increment(self, storage):
        """Test that filter detection count increments"""
        storage.record_detected_filter(
            target_domain="example.com",
            filter_type="script_block",
            filter_signature="<script>"
        )

        storage.record_detected_filter(
            target_domain="example.com",
            filter_type="script_block",
            filter_signature="<script>"
        )

        filters = storage.get_detected_filters("example.com")
        assert filters[0]['detection_count'] == 2

    def test_record_successful_bypass(self, storage):
        """Test recording successful bypasses"""
        storage.record_successful_bypass(
            target_domain="example.com",
            filter_type="script_block",
            bypass_technique="svg_method",
            payload_example="<svg onload=alert(1)>",
            metadata={"confidence": 0.9}
        )

        bypasses = storage.get_effective_bypasses("script_block")
        assert len(bypasses) > 0
        assert bypasses[0]['bypass_technique'] == "svg_method"
        assert bypasses[0]['effectiveness_score'] == 1.0

    def test_update_strategy_effectiveness(self, storage):
        """Test updating strategy effectiveness"""
        storage.update_strategy_effectiveness(
            strategy_name="basic_test",
            target_type="generic",
            success=True,
            time_to_success=2.5
        )

        storage.update_strategy_effectiveness(
            strategy_name="basic_test",
            target_type="generic",
            success=False
        )

        strategies = storage.get_best_strategies("generic")
        assert len(strategies) > 0
        assert strategies[0]['strategy_name'] == "basic_test"
        assert strategies[0]['success_count'] == 1
        assert strategies[0]['failure_count'] == 1
        assert strategies[0]['effectiveness_score'] == 0.5

    def test_check_payload_tested(self, storage):
        """Test checking if payload was tested"""
        storage.record_payload_attempt(
            session_id="test",
            target_url="https://example.com",
            payload="test_payload",
            payload_type="xss",
            strategy="test",
            success=True,
            confidence=0.9
        )

        result = storage.check_payload_tested("example.com", "test_payload")
        assert result is not None
        assert result['success'] == 1  # SQLite returns boolean as integer

        result = storage.check_payload_tested("example.com", "nonexistent")
        assert result is None

    def test_get_similar_payloads(self, storage):
        """Test retrieving similar payloads"""
        for i in range(3):
            storage.record_payload_attempt(
                session_id="test",
                target_url="https://example.com",
                payload=f"payload_{i}",
                payload_type="xss",
                strategy="test",
                success=i % 2 == 0,
                confidence=0.8
            )

        similar = storage.get_similar_payloads("example.com", limit=5)
        assert len(similar) == 3

        similar_xss = storage.get_similar_payloads("example.com", payload_type="xss", limit=2)
        assert len(similar_xss) == 2

    def test_target_intelligence(self, storage):
        """Test target intelligence operations"""
        storage.update_target_intelligence(
            target_domain="example.com",
            technology_stack="PHP, Apache",
            waf_detected="ModSecurity",
            vulnerability_count=2,
            notes="Test notes"
        )

        intel = storage.get_target_intelligence("example.com")
        assert intel is not None
        assert intel['technology_stack'] == "PHP, Apache"
        assert intel['waf_detected'] == "ModSecurity"
        assert intel['vulnerability_count'] == 2

        # Update again
        storage.update_target_intelligence(
            target_domain="example.com",
            vulnerability_count=3
        )

        intel = storage.get_target_intelligence("example.com")
        assert intel['vulnerability_count'] == 3

    def test_get_statistics(self, storage):
        """Test getting database statistics"""
        # Add some data
        storage.record_payload_attempt(
            session_id="test",
            target_url="https://example.com",
            payload="test",
            payload_type="xss",
            strategy="test",
            success=True,
            confidence=0.8
        )

        stats = storage.get_statistics()
        assert 'payload_attempts' in stats
        assert stats['payload_attempts'] >= 1

    def test_cleanup_old_memories(self, storage):
        """Test cleaning up old memories"""
        # This test is hard to implement without mocking time
        # Just verify the method exists and runs
        deleted = storage.cleanup_old_memories(days=1)
        assert deleted >= 0


class TestMemoryManager:
    """Test MemoryManager high-level interface"""

    @pytest.fixture
    def memory(self):
        """Create temporary memory manager for testing"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name

        memory = MemoryManager(
            session_id="test-session",
            target_url="https://example.com/test",
            db_path=db_path,
            enabled=True
        )

        yield memory
        memory.close()

        # Cleanup
        Path(db_path).unlink(missing_ok=True)

    def test_memory_manager_creation(self, memory):
        """Test memory manager initialization"""
        assert memory.session_id == "test-session"
        assert memory.target_domain == "example.com"
        assert memory.enabled is True

    def test_remember_attempt(self, memory):
        """Test remembering attempts"""
        memory.remember_attempt(
            payload="<script>alert(1)</script>",
            payload_type="xss",
            strategy="basic",
            success=False,
            transformation="&lt;script&gt;",
            detected_filter="script_block",
            confidence=0.8
        )

        assert len(memory.session_memory['tested_payloads']) == 1
        assert memory.session_memory['failure_count'] == 1
        assert "script_block" in memory.session_memory['detected_filters']

    def test_was_payload_tested_session(self, memory):
        """Test checking if payload was tested in current session"""
        payload = "<img src=x>"

        # Not tested yet
        result = memory.was_payload_tested(payload)
        assert result is None

        # Test it
        memory.remember_attempt(
            payload=payload,
            payload_type="xss",
            strategy="test",
            success=True,
            confidence=0.9
        )

        # Should find it now
        result = memory.was_payload_tested(payload)
        assert result is not None
        assert result['source'] == 'session'
        assert result['success'] is True

    def test_get_detected_filters(self, memory):
        """Test getting detected filters"""
        memory.remember_attempt(
            payload="test1",
            payload_type="xss",
            strategy="test",
            success=False,
            detected_filter="filter1",
            confidence=0.5
        )

        memory.remember_attempt(
            payload="test2",
            payload_type="xss",
            strategy="test",
            success=False,
            detected_filter="filter2",
            confidence=0.5
        )

        filters = memory.get_detected_filters()
        assert len(filters) >= 2
        assert "filter1" in filters
        assert "filter2" in filters

    def test_learn_from_success(self, memory):
        """Test learning from successful attempts"""
        memory.learn_from_success(
            strategy="svg_bypass",
            payload="<svg onload=alert(1)>",
            time_elapsed=2.5
        )

        # Verify it was recorded (check storage directly)
        strategies = memory.storage.get_best_strategies("generic")
        assert any(s['strategy_name'] == "svg_bypass" for s in strategies)

    def test_learn_from_failure(self, memory):
        """Test learning from failed attempts"""
        memory.learn_from_failure("basic_script")

        strategies = memory.storage.get_best_strategies("generic")
        assert any(s['strategy_name'] == "basic_script" for s in strategies)

    def test_should_skip_payload(self, memory):
        """Test payload skipping logic"""
        payload = "<script>alert(1)</script>"

        # Not tested - should not skip
        should_skip, reason = memory.should_skip_payload(payload)
        assert should_skip is False
        assert reason is None

        # Test and fail
        memory.remember_attempt(
            payload=payload,
            payload_type="xss",
            strategy="test",
            success=False,
            confidence=0.5
        )

        # Should skip because it failed
        should_skip, reason = memory.should_skip_payload(payload, skip_if_failed=True)
        assert should_skip is True
        assert "failed" in reason.lower()

    def test_should_skip_successful_payload(self, memory):
        """Test skipping payload that already succeeded"""
        payload = "<svg onload=alert(1)>"

        memory.remember_attempt(
            payload=payload,
            payload_type="xss",
            strategy="test",
            success=True,
            confidence=0.9
        )

        # Should always skip successful payloads
        should_skip, reason = memory.should_skip_payload(payload, skip_if_failed=False)
        assert should_skip is True
        assert "succeeded" in reason.lower()

    def test_get_memory_insights(self, memory):
        """Test getting memory insights"""
        # Add some test data
        memory.remember_attempt(
            payload="test",
            payload_type="xss",
            strategy="test",
            success=True,
            confidence=0.8
        )

        insights = memory.get_memory_insights()
        assert insights['enabled'] is True
        assert 'session_summary' in insights
        assert 'detected_filters' in insights

    def test_get_session_summary(self, memory):
        """Test session summary"""
        memory.remember_attempt(
            payload="test1",
            payload_type="xss",
            strategy="test",
            success=True,
            confidence=0.8
        )

        memory.remember_attempt(
            payload="test2",
            payload_type="xss",
            strategy="test",
            success=False,
            confidence=0.5
        )

        summary = memory.get_session_summary()
        assert summary['tested_payloads'] == 2
        assert summary['success_count'] == 1
        assert summary['failure_count'] == 1
        assert summary['success_rate'] == 0.5

    def test_update_target_intelligence(self, memory):
        """Test updating target intelligence"""
        memory.update_target_intelligence(
            technology_stack="Node.js",
            waf_detected="Cloudflare",
            vulnerability_found=True,
            notes="Test"
        )

        intel = memory.get_target_intelligence()
        assert intel['technology_stack'] == "Node.js"
        assert intel['waf_detected'] == "Cloudflare"
        assert intel['vulnerability_count'] == 1

    def test_finalize_session(self, memory):
        """Test session finalization"""
        memory.remember_attempt(
            payload="test",
            payload_type="xss",
            strategy="test",
            success=True,
            detected_filter="test_filter",
            confidence=0.8
        )

        memory.finalize_session()

        # Verify intelligence was updated
        intel = memory.get_target_intelligence()
        assert "test_filter" in intel.get('notes', '')


class TestMemoryIntegration:
    """Test memory integration with other components"""

    def test_disabled_memory(self):
        """Test that disabled memory doesn't break anything"""
        memory = MemoryManager(
            session_id="test",
            target_url="https://example.com",
            enabled=False
        )

        # Should not crash
        memory.remember_attempt("test", "xss", "test", True, confidence=0.8)
        result = memory.was_payload_tested("test")
        assert result is None

        memory.close()

    def test_memory_persistence_across_sessions(self):
        """Test that memory persists across sessions"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name

        try:
            # Session 1: Record some attempts
            memory1 = MemoryManager(
                session_id="session-1",
                target_url="https://example.com",
                db_path=db_path,
                enabled=True
            )

            memory1.remember_attempt(
                payload="<script>alert(1)</script>",
                payload_type="xss",
                strategy="basic",
                success=False,
                detected_filter="script_block",
                confidence=0.5
            )

            memory1.close()

            # Session 2: Should recall from session 1
            memory2 = MemoryManager(
                session_id="session-2",
                target_url="https://example.com",
                db_path=db_path,
                enabled=True
            )

            result = memory2.was_payload_tested("<script>alert(1)</script>")
            assert result is not None
            assert result['source'] == 'history'
            assert result['detected_filter'] == 'script_block'

            memory2.close()

        finally:
            Path(db_path).unlink(missing_ok=True)

    def test_export_session_memory(self):
        """Test exporting session memory"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name

        try:
            memory = MemoryManager(
                session_id="test",
                target_url="https://example.com",
                db_path=db_path,
                enabled=True
            )

            memory.remember_attempt(
                payload="test",
                payload_type="xss",
                strategy="test",
                success=True,
                confidence=0.8
            )

            export = memory.export_session_memory()
            assert export['session_id'] == "test"
            assert export['target_domain'] == "example.com"
            assert len(export['tested_payloads']) == 1

            memory.close()

        finally:
            Path(db_path).unlink(missing_ok=True)


def test_memory_statistics():
    """Test memory statistics retrieval"""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = f.name

    try:
        memory = MemoryManager(
            session_id="test",
            target_url="https://example.com",
            db_path=db_path,
            enabled=True
        )

        memory.remember_attempt(
            payload="test",
            payload_type="xss",
            strategy="test",
            success=True,
            confidence=0.8
        )

        stats = memory.get_statistics()
        assert 'payload_attempts' in stats
        assert stats['payload_attempts'] >= 1

        memory.close()

    finally:
        Path(db_path).unlink(missing_ok=True)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
