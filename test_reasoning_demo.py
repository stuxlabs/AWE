#!/usr/bin/env python3
"""
Demo script to test reasoning transparency system

This demonstrates the reasoning transparency feature with a simulated agent workflow.
"""

import sys
from pathlib import Path

# Add utils to path
sys.path.insert(0, str(Path(__file__).parent))

from utils.reasoning_tracker import ReasoningTracker
from utils.transparent_agent import wrap_agent


class SimulatedXSSAgent:
    """
    Simulated XSS detection agent for demonstrating reasoning transparency
    """

    def __init__(self):
        self.tested_payloads = []
        self.detected_filters = []

    def analyze_input_field(self, url: str, field_name: str):
        """Analyze an input field for XSS vulnerabilities"""
        print(f"\n→ Analyzing input field '{field_name}' on {url}")
        return {
            "field": field_name,
            "sources": [f"input#{field_name}"],
            "sinks": ["innerHTML"],
            "has_sanitization": False
        }

    def test_payload(self, payload: str, strategy: str):
        """Test a payload against the target"""
        self.tested_payloads.append(payload)
        print(f"\n→ Testing payload: {payload}")

        # Simulate different responses
        if "<script>" in payload:
            # Simulate filter detection
            self.detected_filters.append("script_tag_blocked")
            return {
                "success": False,
                "transformed": payload.replace("<script>", "&lt;script&gt;"),
                "filter": "script_tag_blocked"
            }
        elif "<img" in payload and "onerror" in payload:
            # Simulate another filter
            self.detected_filters.append("img_onerror_blocked")
            return {
                "success": False,
                "transformed": "",
                "filter": "img_onerror_blocked"
            }
        else:
            # Simulate success
            return {
                "success": True,
                "transformed": payload,
                "filter": None
            }

    def determine_next_strategy(self):
        """Determine the next testing strategy based on detected filters"""
        if "script_tag_blocked" in self.detected_filters:
            return "javascript_context_bypass"
        elif "img_onerror_blocked" in self.detected_filters:
            return "event_handler_alternatives"
        else:
            return "continue_testing"

    def verify_execution(self, url: str, payload: str):
        """Verify if payload executed successfully"""
        print(f"\n→ Verifying payload execution")
        # Simulate browser verification
        return True


def main():
    """Main demo function"""
    print("=" * 80)
    print("REASONING TRANSPARENCY DEMO")
    print("=" * 80)

    # Create reasoning tracker
    print("\n[1] Initializing reasoning transparency system...")
    tracker = ReasoningTracker(
        mode="verbose",
        console_output=True,
        json_output=True,
        output_dir="logs/reasoning",
        color_output=True
    )
    print("✓ Reasoning tracker initialized")

    # Create agent
    print("\n[2] Creating XSS detection agent...")
    agent = SimulatedXSSAgent()
    print("✓ Agent created")

    # Wrap agent with reasoning transparency
    print("\n[3] Wrapping agent with reasoning transparency...")
    target_url = "https://vulnerable-site.example.com/search"
    wrapped_agent = wrap_agent(
        agent,
        tracker,
        "SimulatedXSSAgent",
        target_url
    )
    print("✓ Agent wrapped with transparency")

    print("\n" + "=" * 80)
    print("STARTING XSS DETECTION WITH REASONING TRANSPARENCY")
    print("=" * 80)

    # Simulate a complete XSS detection workflow with manual reasoning logs

    # Step 1: Observation
    wrapped_agent.log_custom_observation(
        "Analyzing target page for XSS vulnerabilities",
        context={"url": target_url, "method": "GET"}
    )

    # Analyze input field
    field_info = wrapped_agent.analyze_input_field(target_url, "search")

    wrapped_agent.log_custom_observation(
        f"Found input field '{field_info['field']}' with innerHTML sink",
        context={
            "sources": field_info['sources'],
            "sinks": field_info['sinks']
        }
    )

    # Step 2: Hypothesis
    wrapped_agent.log_custom_hypothesis(
        "Input field may be vulnerable to DOM XSS if no sanitization present",
        confidence=0.7,
        reasoning="Direct innerHTML assignment without visible sanitization"
    )

    # Step 3: Action - Test basic script tag
    wrapped_agent.log_custom_action(
        "Testing basic script tag payload",
        payload="<script>alert(1)</script>",
        strategy="database_phase_1"
    )

    result1 = wrapped_agent.test_payload("<script>alert(1)</script>", "database_phase_1")

    # Step 4: Result
    wrapped_agent.log_custom_result(
        "Payload blocked - script tag filter detected",
        success=False,
        transformation=result1['transformed'],
        detected_filter=result1['filter']
    )

    # Step 5: Analysis
    wrapped_agent.log_custom_analysis(
        "Server applying script tag blocking. Switching to event handler strategy.",
        detected_filters=[result1['filter']],
        next_strategy="event_handler_bypass"
    )

    # Step 6: New hypothesis
    wrapped_agent.log_custom_hypothesis(
        "Event handler-based payload may bypass script tag filter",
        confidence=0.6,
        reasoning="Script tags blocked, but event handlers may be allowed"
    )

    # Step 7: Action - Test image with onerror
    wrapped_agent.log_custom_action(
        "Testing image tag with onerror event handler",
        payload='<img src=x onerror=alert(1)>',
        strategy="event_handler_bypass"
    )

    result2 = wrapped_agent.test_payload('<img src=x onerror=alert(1)>', "event_handler_bypass")

    # Step 8: Result
    wrapped_agent.log_custom_result(
        "Payload blocked - onerror event handler filtered",
        success=False,
        transformation=result2['transformed'],
        detected_filter=result2['filter']
    )

    # Step 9: Analysis
    wrapped_agent.log_custom_analysis(
        "Multiple filters detected. Attempting advanced bypass technique.",
        detected_filters=[result1['filter'], result2['filter']],
        next_strategy="advanced_bypass"
    )

    # Step 10: Hypothesis for advanced bypass
    wrapped_agent.log_custom_hypothesis(
        "SVG-based payload with alternative event may bypass both filters",
        confidence=0.8,
        reasoning="SVG tags and onload events less commonly filtered"
    )

    # Step 11: Action - Test SVG payload
    wrapped_agent.log_custom_action(
        "Testing SVG-based payload with onload event",
        payload='<svg onload=alert(1)>',
        strategy="advanced_bypass"
    )

    result3 = wrapped_agent.test_payload('<svg onload=alert(1)>', "advanced_bypass")

    # Step 12: Result - Success!
    wrapped_agent.log_custom_result(
        "Payload executed successfully!",
        success=True,
        transformation=result3['transformed'],
        detected_filter=None
    )

    # Step 13: Verification
    wrapped_agent.log_custom_action(
        "Verifying payload execution in browser",
        payload='<svg onload=alert(1)>',
        strategy="browser_verification"
    )

    verification = wrapped_agent.verify_execution(target_url, '<svg onload=alert(1)>')

    wrapped_agent.log_custom_result(
        "Browser verification confirmed XSS execution",
        success=True
    )

    # Step 14: Final analysis
    wrapped_agent.log_custom_analysis(
        "XSS vulnerability confirmed. SVG-based payload successfully bypassed filters.",
        detected_filters=wrapped_agent.get_wrapped_agent().detected_filters,
        next_strategy="report_generation"
    )

    # Finalize reasoning context
    print("\n" + "=" * 80)
    print("FINALIZING REASONING CONTEXT")
    print("=" * 80)

    json_path = tracker.finalize_context(wrapped_agent._session_id)

    print(f"\n✓ Reasoning chain completed successfully!")
    print(f"✓ Total reasoning steps: 14")
    print(f"✓ Detected filters: {len(wrapped_agent.get_wrapped_agent().detected_filters)}")
    print(f"✓ Tested payloads: {len(wrapped_agent.get_wrapped_agent().tested_payloads)}")
    if json_path:
        print(f"✓ Reasoning log saved to: {json_path}")

    print("\n" + "=" * 80)
    print("DEMO COMPLETED")
    print("=" * 80)
    print("\n📚 The reasoning log shows:")
    print("  • Complete decision-making process")
    print("  • Hypothesis formation and testing")
    print("  • Filter detection and adaptation")
    print("  • Strategy evolution based on results")
    print("  • Final successful exploitation")
    print("\n🔍 This makes the 'black box' into a 'glass box'!")


if __name__ == "__main__":
    main()
