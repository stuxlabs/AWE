"""
Unit tests for reasoning transparency system

Tests ReasoningTracker, ReasoningContext, and TransparentAgent wrapper
"""

import pytest
import json
import tempfile
from pathlib import Path
from datetime import datetime

# Import system path setup
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.reasoning_tracker import (
    ReasoningTracker,
    ReasoningContext,
    ReasoningStep,
    ConsoleFormatter,
    JSONWriter
)
from utils.transparent_agent import TransparentAgent, wrap_agent


class TestReasoningStep:
    """Test ReasoningStep dataclass"""

    def test_step_creation(self):
        """Test basic step creation"""
        step = ReasoningStep(
            step=1,
            type="observation",
            content="Test observation"
        )
        assert step.step == 1
        assert step.type == "observation"
        assert step.content == "Test observation"
        assert step.timestamp is not None

    def test_step_to_dict(self):
        """Test conversion to dictionary"""
        step = ReasoningStep(
            step=1,
            type="hypothesis",
            content="Test hypothesis",
            confidence=0.8,
            reasoning="Because of X"
        )
        data = step.to_dict()
        assert data['step'] == 1
        assert data['type'] == "hypothesis"
        assert data['confidence'] == 0.8
        assert data['reasoning'] == "Because of X"
        # None values should be excluded
        assert 'payload' not in data

    def test_step_with_all_fields(self):
        """Test step with all optional fields"""
        step = ReasoningStep(
            step=1,
            type="action",
            content="Test action",
            payload="<script>alert(1)</script>",
            strategy="database_phase_1",
            confidence=0.9,
            reasoning="High confidence based on signature",
            success=True,
            transformation="&lt;script&gt;alert(1)&lt;/script&gt;",
            detected_filter="html_entity_encoding"
        )
        data = step.to_dict()
        assert len(data) > 5  # Should have many fields


class TestReasoningContext:
    """Test ReasoningContext class"""

    def test_context_creation(self):
        """Test basic context creation"""
        context = ReasoningContext(
            session_id="test-123",
            agent_type="TestAgent",
            target="https://example.com"
        )
        assert context.session_id == "test-123"
        assert context.agent_type == "TestAgent"
        assert context.target == "https://example.com"
        assert len(context.reasoning_chain) == 0

    def test_add_step(self):
        """Test adding steps to context"""
        context = ReasoningContext("test", "TestAgent", "https://example.com")
        step = ReasoningStep(step=1, type="observation", content="Test")
        context.add_step(step)
        assert len(context.reasoning_chain) == 1
        assert context.reasoning_chain[0].content == "Test"

    def test_context_to_dict(self):
        """Test context serialization"""
        context = ReasoningContext("test", "TestAgent", "https://example.com")
        step1 = ReasoningStep(step=1, type="observation", content="Observation")
        step2 = ReasoningStep(step=2, type="hypothesis", content="Hypothesis")
        context.add_step(step1)
        context.add_step(step2)

        data = context.to_dict()
        assert data['session_id'] == "test"
        assert data['agent_type'] == "TestAgent"
        assert len(data['reasoning_chain']) == 2


class TestConsoleFormatter:
    """Test ConsoleFormatter class"""

    def test_formatter_creation(self):
        """Test formatter creation"""
        formatter = ConsoleFormatter(use_color=True)
        assert formatter.use_color is True

        formatter_no_color = ConsoleFormatter(use_color=False)
        assert formatter_no_color.use_color is False

    def test_format_observation(self):
        """Test formatting observation step"""
        formatter = ConsoleFormatter(use_color=True)
        step = ReasoningStep(
            step=1,
            type="observation",
            content="Found input field",
            context={"sources": ["input#search"], "sinks": ["innerHTML"]}
        )
        output = formatter.format_step(step, "TestAgent")
        assert "OBSERVATION" in output
        assert "Found input field" in output
        assert "🔍" in output

    def test_format_hypothesis(self):
        """Test formatting hypothesis step"""
        formatter = ConsoleFormatter(use_color=True)
        step = ReasoningStep(
            step=2,
            type="hypothesis",
            content="May be vulnerable",
            confidence=0.7,
            reasoning="No sanitization detected"
        )
        output = formatter.format_step(step, "TestAgent")
        assert "HYPOTHESIS" in output
        assert "May be vulnerable" in output
        assert "70%" in output

    def test_format_action(self):
        """Test formatting action step"""
        formatter = ConsoleFormatter(use_color=True)
        step = ReasoningStep(
            step=3,
            type="action",
            content="Testing payload",
            payload="<img src=x>",
            strategy="database_phase_1"
        )
        output = formatter.format_step(step, "TestAgent")
        assert "ACTION" in output
        assert "Testing payload" in output
        assert "<img src=x>" in output

    def test_format_result_success(self):
        """Test formatting successful result"""
        formatter = ConsoleFormatter(use_color=True)
        step = ReasoningStep(
            step=4,
            type="result",
            content="Payload executed",
            success=True
        )
        output = formatter.format_step(step, "TestAgent")
        assert "RESULT" in output
        assert "Payload executed" in output
        assert "✅" in output

    def test_format_result_failure(self):
        """Test formatting failed result"""
        formatter = ConsoleFormatter(use_color=True)
        step = ReasoningStep(
            step=4,
            type="result",
            content="Payload blocked",
            success=False,
            transformation="&lt;img src=x&gt;",
            detected_filter="html_entity_encoding"
        )
        output = formatter.format_step(step, "TestAgent")
        assert "RESULT" in output
        assert "Payload blocked" in output
        assert "❌" in output

    def test_format_plain(self):
        """Test formatting without colors"""
        formatter = ConsoleFormatter(use_color=False)
        step = ReasoningStep(step=1, type="observation", content="Test")
        output = formatter.format_step(step, "TestAgent")
        # Should not contain ANSI color codes
        assert "\033[" not in output
        assert "OBSERVATION" in output


class TestJSONWriter:
    """Test JSONWriter class"""

    def test_writer_creation(self):
        """Test JSON writer creation"""
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = JSONWriter(output_dir=tmpdir)
            assert writer.output_dir == Path(tmpdir)
            assert writer.output_dir.exists()

    def test_write_context(self):
        """Test writing context to JSON file"""
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = JSONWriter(output_dir=tmpdir)
            context = ReasoningContext("test-session", "TestAgent", "https://example.com")
            step = ReasoningStep(step=1, type="observation", content="Test observation")
            context.add_step(step)

            filepath = writer.write(context)
            assert filepath.exists()
            assert filepath.suffix == ".json"

            # Verify JSON content
            with open(filepath, 'r') as f:
                data = json.load(f)
                assert data['session_id'] == "test-session"
                assert data['agent_type'] == "TestAgent"
                assert len(data['reasoning_chain']) == 1


class TestReasoningTracker:
    """Test ReasoningTracker class"""

    def test_tracker_creation(self):
        """Test tracker creation"""
        tracker = ReasoningTracker(
            mode="verbose",
            console_output=False,
            json_output=False
        )
        assert tracker.mode == "verbose"
        assert tracker.console_output is False

    def test_create_context(self):
        """Test creating reasoning context"""
        tracker = ReasoningTracker(console_output=False, json_output=False)
        session_id = tracker.create_context("TestAgent", "https://example.com")
        assert session_id in tracker.active_contexts
        context = tracker.get_context(session_id)
        assert context.agent_type == "TestAgent"

    def test_log_observation(self):
        """Test logging observation"""
        tracker = ReasoningTracker(console_output=False, json_output=False)
        session_id = tracker.create_context("TestAgent", "https://example.com")
        tracker.log_observation(session_id, "Test observation", context={"key": "value"})

        context = tracker.get_context(session_id)
        assert len(context.reasoning_chain) == 1
        assert context.reasoning_chain[0].type == "observation"
        assert context.reasoning_chain[0].content == "Test observation"

    def test_log_hypothesis(self):
        """Test logging hypothesis"""
        tracker = ReasoningTracker(console_output=False, json_output=False)
        session_id = tracker.create_context("TestAgent", "https://example.com")
        tracker.log_hypothesis(session_id, "Test hypothesis", confidence=0.8, reasoning="Because X")

        context = tracker.get_context(session_id)
        assert len(context.reasoning_chain) == 1
        assert context.reasoning_chain[0].type == "hypothesis"
        assert context.reasoning_chain[0].confidence == 0.8

    def test_log_action(self):
        """Test logging action"""
        tracker = ReasoningTracker(console_output=False, json_output=False)
        session_id = tracker.create_context("TestAgent", "https://example.com")
        tracker.log_action(session_id, "Testing payload", payload="<script>", strategy="test")

        context = tracker.get_context(session_id)
        assert len(context.reasoning_chain) == 1
        assert context.reasoning_chain[0].type == "action"
        assert context.reasoning_chain[0].payload == "<script>"

    def test_log_result(self):
        """Test logging result"""
        tracker = ReasoningTracker(console_output=False, json_output=False)
        session_id = tracker.create_context("TestAgent", "https://example.com")
        tracker.log_result(session_id, "Success", success=True)

        context = tracker.get_context(session_id)
        assert len(context.reasoning_chain) == 1
        assert context.reasoning_chain[0].type == "result"
        assert context.reasoning_chain[0].success is True

    def test_log_analysis(self):
        """Test logging analysis"""
        tracker = ReasoningTracker(console_output=False, json_output=False)
        session_id = tracker.create_context("TestAgent", "https://example.com")
        tracker.log_analysis(
            session_id,
            "Filter detected",
            detected_filters=["html_encoding"],
            next_strategy="javascript_context"
        )

        context = tracker.get_context(session_id)
        assert len(context.reasoning_chain) == 1
        assert context.reasoning_chain[0].type == "analysis"
        assert "html_encoding" in context.reasoning_chain[0].detected_filters

    def test_finalize_context(self):
        """Test finalizing context"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = ReasoningTracker(
                console_output=False,
                json_output=True,
                output_dir=tmpdir
            )
            session_id = tracker.create_context("TestAgent", "https://example.com")
            tracker.log_observation(session_id, "Test")

            filepath = tracker.finalize_context(session_id)
            assert filepath is not None
            assert filepath.exists()
            assert session_id not in tracker.active_contexts

    def test_full_reasoning_chain(self):
        """Test logging a complete reasoning chain"""
        tracker = ReasoningTracker(console_output=False, json_output=False)
        session_id = tracker.create_context("TestAgent", "https://example.com")

        # Log complete chain
        tracker.log_observation(session_id, "Found input field")
        tracker.log_hypothesis(session_id, "May be vulnerable", confidence=0.7)
        tracker.log_action(session_id, "Testing payload", payload="<img src=x>")
        tracker.log_result(session_id, "Blocked", success=False, detected_filter="html_encoding")
        tracker.log_analysis(session_id, "Switching strategy", next_strategy="javascript_context")

        context = tracker.get_context(session_id)
        assert len(context.reasoning_chain) == 5
        assert context.reasoning_chain[0].type == "observation"
        assert context.reasoning_chain[1].type == "hypothesis"
        assert context.reasoning_chain[2].type == "action"
        assert context.reasoning_chain[3].type == "result"
        assert context.reasoning_chain[4].type == "analysis"


class TestTransparentAgent:
    """Test TransparentAgent wrapper"""

    class MockAgent:
        """Mock agent for testing"""
        def __init__(self):
            self.value = 0

        def increment(self):
            """Increment value"""
            self.value += 1
            return self.value

        def get_value(self):
            """Get current value"""
            return self.value

        def process_data(self, data: str):
            """Process some data"""
            return f"processed: {data}"

        def failing_method(self):
            """Method that raises exception"""
            raise ValueError("Test error")

    def test_wrapper_creation(self):
        """Test creating transparent agent wrapper"""
        tracker = ReasoningTracker(console_output=False, json_output=False)
        session_id = tracker.create_context("MockAgent", "test")
        agent = self.MockAgent()

        wrapped = TransparentAgent(agent, tracker, session_id)
        assert wrapped._agent is agent
        assert wrapped._reasoning_tracker is tracker

    def test_method_call_logging(self):
        """Test that method calls are logged"""
        tracker = ReasoningTracker(console_output=False, json_output=False)
        session_id = tracker.create_context("MockAgent", "test")
        agent = self.MockAgent()
        wrapped = TransparentAgent(agent, tracker, session_id)

        # Call method
        result = wrapped.increment()
        assert result == 1

        # Check logging
        context = tracker.get_context(session_id)
        assert len(context.reasoning_chain) > 0

    def test_method_call_passthrough(self):
        """Test that method calls work correctly"""
        tracker = ReasoningTracker(console_output=False, json_output=False)
        session_id = tracker.create_context("MockAgent", "test")
        agent = self.MockAgent()
        wrapped = TransparentAgent(agent, tracker, session_id)

        # Test multiple calls
        wrapped.increment()
        wrapped.increment()
        result = wrapped.get_value()
        assert result == 2

    def test_method_with_args(self):
        """Test method calls with arguments"""
        tracker = ReasoningTracker(console_output=False, json_output=False)
        session_id = tracker.create_context("MockAgent", "test")
        agent = self.MockAgent()
        wrapped = TransparentAgent(agent, tracker, session_id)

        result = wrapped.process_data("test data")
        assert result == "processed: test data"

    def test_exception_handling(self):
        """Test that exceptions are logged and re-raised"""
        tracker = ReasoningTracker(console_output=False, json_output=False)
        session_id = tracker.create_context("MockAgent", "test")
        agent = self.MockAgent()
        wrapped = TransparentAgent(agent, tracker, session_id)

        with pytest.raises(ValueError):
            wrapped.failing_method()

        # Check that failure was logged
        context = tracker.get_context(session_id)
        # Should have observation and result (failure)
        assert len(context.reasoning_chain) > 0

    def test_wrap_agent_helper(self):
        """Test wrap_agent convenience function"""
        tracker = ReasoningTracker(console_output=False, json_output=False)
        agent = self.MockAgent()

        wrapped = wrap_agent(agent, tracker, "MockAgent", "test_target")
        assert isinstance(wrapped, TransparentAgent)
        assert wrapped._agent is agent

        # Test functionality
        result = wrapped.increment()
        assert result == 1

    def test_custom_logging_methods(self):
        """Test custom logging methods"""
        tracker = ReasoningTracker(console_output=False, json_output=False)
        session_id = tracker.create_context("MockAgent", "test")
        agent = self.MockAgent()
        wrapped = TransparentAgent(agent, tracker, session_id)

        # Test custom logging
        wrapped.log_custom_observation("Custom observation")
        wrapped.log_custom_hypothesis("Custom hypothesis", confidence=0.9)
        wrapped.log_custom_action("Custom action", payload="test")
        wrapped.log_custom_result("Custom result", success=True)
        wrapped.log_custom_analysis("Custom analysis", next_strategy="test")

        context = tracker.get_context(session_id)
        assert len(context.reasoning_chain) == 5


def test_integration_full_workflow():
    """Integration test: full reasoning transparency workflow"""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create tracker
        tracker = ReasoningTracker(
            mode="verbose",
            console_output=False,
            json_output=True,
            output_dir=tmpdir
        )

        # Create and wrap agent
        agent = TestTransparentAgent.MockAgent()
        wrapped = wrap_agent(agent, tracker, "TestAgent", "https://example.com")

        # Perform operations
        wrapped.log_custom_observation("Starting test")
        wrapped.log_custom_hypothesis("Expecting success", confidence=0.8)
        wrapped.increment()
        wrapped.log_custom_result("Operation succeeded", success=True)
        wrapped.log_custom_analysis("Test completed", next_strategy="none")

        # Finalize and save
        filepath = tracker.finalize_context(wrapped._session_id)

        # Verify JSON file
        assert filepath.exists()
        with open(filepath, 'r') as f:
            data = json.load(f)
            assert data['agent_type'] == "TestAgent"
            assert len(data['reasoning_chain']) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
