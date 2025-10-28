#!/usr/bin/env python3
"""
Intelligent Agent Integration Demo

Shows how memory and reasoning work together in the actual scanning pipeline.
This demonstrates REAL integration, not just passive logging!
"""

import sys
import time
import asyncio
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from utils.memory_manager import MemoryManager
from utils.reasoning_tracker import ReasoningTracker
from utils.intelligent_agent import IntelligentAgent


class DemoXSSAgent(IntelligentAgent):
    """
    Demo XSS agent showing full integration with memory and reasoning

    This agent:
    - Uses memory to skip tested payloads
    - Reorders payloads based on memory
    - Detects filters and learns
    - Uses bypass recommendations
    - Logs reasoning at every step
    """

    def __init__(self, memory_manager=None, reasoning_tracker=None, reasoning_session=None):
        super().__init__(memory_manager, reasoning_tracker, reasoning_session)

        # XSS payload database
        self.payloads = [
            # Basic payloads (likely to be blocked)
            ("<script>alert(1)</script>", "basic_script"),
            ('<img src=x onerror=alert(1)>', "event_handler"),
            ('<iframe src="javascript:alert(1)"></iframe>', "iframe_javascript"),

            # Bypass payloads
            ('<svg onload=alert(1)>', "svg_bypass"),
            ('<svg/onload=alert(1)>', "svg_slash_bypass"),
            ('<img src onerror=alert(1)>', "img_broken_attribute"),
            ('<details open ontoggle=alert(1)>', "details_bypass"),
            ('<marquee onstart=alert(1)>', "marquee_bypass"),

            # Advanced bypasses
            ('<input onfocus=alert(1) autofocus>', "autofocus_bypass"),
            ('<select onfocus=alert(1) autofocus>', "select_bypass"),
            ('<textarea onfocus=alert(1) autofocus>', "textarea_bypass"),
        ]

    async def scan_target(self, target_url: str) -> dict:
        """
        Main scanning workflow with full memory and reasoning integration
        """
        print(f"\n{'='*80}")
        print(f"INTELLIGENT AGENT SCAN: {target_url}")
        print(f"{'='*80}\n")

        # Announce scan start
        self.announce_scan_start(target_url)

        # Get memory insights BEFORE starting
        if self.memory:
            insights = self.get_memory_insights()
            print("\n💡 MEMORY INSIGHTS:")
            print(f"   • Known filters: {insights.get('detected_filters', [])}")
            print(f"   • Recommended strategies: {insights.get('recommended_strategies', [])}")

        # SMART PAYLOAD SELECTION
        print(f"\n📋 SMART PAYLOAD SELECTION:")
        print(f"   • Original payload count: {len(self.payloads)}")

        # Reorder payloads based on memory
        ordered_payloads = self._get_smart_payloads()
        print(f"   • After memory optimization: {len(ordered_payloads)} payloads")

        # TEST PAYLOADS WITH LEARNING
        vulnerabilities = []

        for i, (payload, strategy) in enumerate(ordered_payloads, 1):
            print(f"\n--- Testing Payload {i}/{len(ordered_payloads)} ---")

            # Check if we should skip this payload
            should_test, reason = self.should_test_payload(payload, "xss")

            if not should_test:
                print(f"⏭️  SKIPPING: {payload[:50]}")
                print(f"   Reason: {reason}")
                continue

            # Log action with reasoning
            self._log_action(
                f"Testing {strategy} payload",
                payload=payload,
                strategy=strategy
            )

            # Simulate testing
            result = await self._test_payload(target_url, payload, strategy)

            # Log result
            self._log_result(
                f"Payload {'succeeded' if result['success'] else 'failed'}",
                success=result['success'],
                transformation=result.get('transformed'),
                detected_filter=result.get('filter')
            )

            # Remember the result
            self.remember_test_result(
                payload=payload,
                payload_type="xss",
                strategy=strategy,
                success=result['success'],
                transformation=result.get('transformed'),
                detected_filter=result.get('filter'),
                confidence=result.get('confidence', 0.8)
            )

            if result['success']:
                vulnerabilities.append({
                    'payload': payload,
                    'strategy': strategy,
                    'confidence': result['confidence']
                })

                print(f"✅ SUCCESS: {payload}")
                print(f"   Strategy: {strategy}")

                # If we found a bypass for a known filter, log it
                if result.get('bypassed_filter'):
                    print(f"   🎯 Bypassed filter: {result['bypassed_filter']}")

            else:
                print(f"❌ FAILED: {payload[:50]}")

                if result.get('filter'):
                    print(f"   Filter detected: {result['filter']}")

                    # Get bypass recommendations
                    if self.memory:
                        bypasses = self.get_bypass_recommendations(result['filter'], limit=2)
                        if bypasses:
                            print(f"   💡 Memory suggests trying:")
                            for bypass in bypasses:
                                print(f"      • {bypass['bypass_technique']} ({bypass['effectiveness_score']:.0%} effective)")

            # Small delay for visibility
            await asyncio.sleep(0.1)

        # Announce completion
        self.announce_scan_complete()

        # Final summary
        print(f"\n{'='*80}")
        print(f"SCAN COMPLETE")
        print(f"{'='*80}")

        return {
            'target': target_url,
            'tested': len(self.payloads_tested),
            'successful': len(self.successful_payloads),
            'filters_detected': list(self.detected_filters),
            'vulnerabilities': vulnerabilities
        }

    def _get_smart_payloads(self):
        """Get payloads ordered by memory intelligence"""
        payload_list = [p for p in self.payloads]

        if self.memory:
            # Use memory to reorder
            payload_strings = [p[0] for p in self.payloads]
            ordered_strings = self.get_smart_payload_order(payload_strings, "xss")

            # Rebuild with strategies
            ordered = []
            for payload_str in ordered_strings:
                for orig_payload, strategy in self.payloads:
                    if orig_payload == payload_str:
                        ordered.append((orig_payload, strategy))
                        break

            return ordered

        return payload_list

    async def _test_payload(self, target_url: str, payload: str, strategy: str) -> dict:
        """
        Simulate testing a payload

        In real agent, this would:
        - Send HTTP request
        - Check response
        - Verify execution
        """
        # Simulate different scenarios
        await asyncio.sleep(0.05)  # Simulate network delay

        # Simulate filter detection
        if '<script>' in payload.lower():
            return {
                'success': False,
                'filter': 'script_tag_blocked',
                'transformed': payload.replace('<script>', '&lt;script&gt;'),
                'confidence': 0.5
            }
        elif 'onerror' in payload.lower() and '<img' in payload.lower():
            return {
                'success': False,
                'filter': 'img_onerror_blocked',
                'transformed': '',
                'confidence': 0.5
            }
        elif 'javascript:' in payload.lower():
            return {
                'success': False,
                'filter': 'javascript_protocol_blocked',
                'transformed': '',
                'confidence': 0.5
            }
        elif '<svg' in payload.lower() and 'onload' in payload.lower():
            # SVG bypass works!
            return {
                'success': True,
                'confidence': 0.9,
                'bypassed_filter': 'script_tag_blocked' if self.detected_filters else None
            }
        elif '<details' in payload.lower() or '<marquee' in payload.lower():
            # Alternative bypasses
            return {
                'success': True,
                'confidence': 0.85,
                'bypassed_filter': 'event_handler_blocked' if self.detected_filters else None
            }
        elif 'autofocus' in payload.lower():
            # Advanced bypass
            return {
                'success': True,
                'confidence': 0.95,
                'bypassed_filter': 'img_onerror_blocked' if self.detected_filters else None
            }
        else:
            # Random other payloads
            return {
                'success': False,
                'filter': None,
                'transformed': None,
                'confidence': 0.3
            }


async def main():
    """Main demo function"""
    print("="*80)
    print("INTELLIGENT AGENT INTEGRATION DEMO")
    print("="*80)
    print("\nThis demo shows REAL integration of memory and reasoning!")
    print("Watch how the agent:")
    print("  • Uses memory to skip tested payloads")
    print("  • Reorders payloads based on memory")
    print("  • Detects filters and learns from them")
    print("  • Gets bypass recommendations")
    print("  • Logs reasoning at every decision")

    # Create memory and reasoning systems
    print("\n[1] Initializing systems...")
    memory = MemoryManager(
        session_id="intelligent-demo",
        target_url="https://vulnerable-app.example.com",
        db_path="memory/intelligent_demo.db",
        enabled=True
    )

    reasoning = ReasoningTracker(
        mode="verbose",
        console_output=True,
        json_output=True,
        output_dir="logs/reasoning",
        color_output=True
    )

    # Create session
    session_id = reasoning.create_context(
        "DemoXSSAgent",
        "https://vulnerable-app.example.com"
    )

    print("✓ Systems initialized")

    # Create intelligent agent
    print("\n[2] Creating intelligent agent...")
    agent = DemoXSSAgent(
        memory_manager=memory,
        reasoning_tracker=reasoning,
        reasoning_session=session_id
    )
    print("✓ Agent created with memory and reasoning")

    # Run scan
    print("\n[3] Running intelligent scan...")
    print("\n" + "="*80)

    result = await agent.scan_target("https://vulnerable-app.example.com/search")

    # Print final results
    print(f"\n{'='*80}")
    print(f"FINAL RESULTS")
    print(f"{'='*80}")
    print(f"Target: {result['target']}")
    print(f"Payloads tested: {result['tested']}")
    print(f"Successful: {result['successful']}")
    if result['tested'] > 0:
        print(f"Success rate: {result['successful']/result['tested']*100:.1f}%")
    else:
        print(f"Success rate: N/A (all payloads skipped by memory)")
    print(f"Filters detected: {result['filters_detected']}")
    print(f"Vulnerabilities found: {len(result['vulnerabilities'])}")

    if result['vulnerabilities']:
        print(f"\nWorking payloads:")
        for vuln in result['vulnerabilities']:
            print(f"  • {vuln['payload'][:50]} ({vuln['strategy']})")

    # Finalize
    reasoning.finalize_context(session_id)
    memory.finalize_session()

    # Show what was saved
    print(f"\n{'='*80}")
    print(f"SAVED DATA")
    print(f"{'='*80}")

    memory_stats = memory.get_statistics()
    print(f"Memory database statistics:")
    for table, count in memory_stats.items():
        print(f"  • {table}: {count} records")

    print(f"\nReasoning log saved to: logs/reasoning/")

    memory.close()

    # Show how to run again to see memory in action
    print(f"\n{'='*80}")
    print(f"RUN AGAIN TO SEE MEMORY IN ACTION!")
    print(f"{'='*80}")
    print("The second run will:")
    print("  • Skip known failures")
    print("  • Try bypasses first")
    print("  • Use learned strategies")
    print("  • Be much faster!")
    print(f"\n  python test_intelligent_agent_demo.py")


if __name__ == "__main__":
    asyncio.run(main())
