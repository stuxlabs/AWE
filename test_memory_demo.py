#!/usr/bin/env python3
"""
Agent Memory System Demo

Demonstrates the memory system with learning, recall, and recommendations.
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from utils.memory_manager import MemoryManager
from utils.memory_storage import MemoryStorage


def print_section(title: str):
    """Print section header"""
    print(f"\n{'='*80}")
    print(f"  {title}")
    print(f"{'='*80}\n")


def demo_basic_memory():
    """Demonstrate basic memory operations"""
    print_section("1. BASIC MEMORY OPERATIONS")

    # Create memory manager
    memory = MemoryManager(
        session_id="demo-session-1",
        target_url="https://example.com/search",
        db_path="memory/demo_memory.db",
        enabled=True
    )

    print("✓ Memory manager created")
    print(f"  Target: {memory.target_domain}")
    print(f"  Session: {memory.session_id}\n")

    # Remember some payload attempts
    print("📝 Recording payload attempts...\n")

    attempts = [
        ("  <script>alert(1)</script>", "xss", "basic_script", False, "&lt;script&gt;alert(1)&lt;/script&gt;", "script_tag_blocked"),
        ('<img src=x onerror=alert(1)>', "xss", "event_handler", False, "", "img_onerror_blocked"),
        ('<svg onload=alert(1)>', "xss", "svg_bypass", True, '<svg onload=alert(1)>', None),
    ]

    for payload, ptype, strategy, success, transform, filt in attempts:
        memory.remember_attempt(
            payload=payload,
            payload_type=ptype,
            strategy=strategy,
            success=success,
            transformation=transform,
            detected_filter=filt,
            confidence=0.8 if success else 0.5
        )

        status = "✅ SUCCESS" if success else "❌ FAILED"
        print(f"  {status}: {payload[:50]}")
        if filt:
            print(f"           Filter detected: {filt}")

    print(f"\n✓ Recorded {len(attempts)} payload attempts")

    # Check if payload was tested
    print("\n🔍 Checking memory for previously tested payload...")
    result = memory.was_payload_tested("<script>alert(1)</script>")
    if result:
        print(f"  ✓ Found in memory!")
        print(f"    Source: {result['source']}")
        print(f"    Success: {result['success']}")
        print(f"    Filter: {result.get('detected_filter', 'None')}")

    # Get detected filters
    print("\n🛡️  Detected filters:")
    filters = memory.get_detected_filters()
    for f in filters:
        print(f"  • {f}")

    memory.close()
    print("\n✓ Demo 1 complete!")


def demo_learning_and_recommendations():
    """Demonstrate learning from attempts and getting recommendations"""
    print_section("2. LEARNING & RECOMMENDATIONS")

    memory = MemoryManager(
        session_id="demo-session-2",
        target_url="https://example.com/search",
        db_path="memory/demo_memory.db",
        enabled=True
    )

    print("💡 Memory is learning from previous attempts...")

    # Learn from successes and failures
    print("\n📚 Recording strategy effectiveness...")

    strategies = [
        ("basic_script", False, None),
        ("event_handler", False, None),
        ("svg_bypass", True, 2.5),
        ("svg_bypass", True, 1.8),
        ("mutation_fuzzing", False, None),
    ]

    for strategy, success, time_elapsed in strategies:
        if success:
            memory.learn_from_success(strategy, f"payload_{strategy}", time_elapsed)
            print(f"  ✅ Learned from successful {strategy} (took {time_elapsed}s)")
        else:
            memory.learn_from_failure(strategy)
            print(f"  ❌ Learned from failed {strategy}")

    # Get strategy recommendations
    print("\n💡 Getting strategy recommendations...")
    recommended = memory.get_strategy_recommendations(limit=3)
    if recommended:
        print("  Best strategies based on history:")
        for i, strategy in enumerate(recommended, 1):
            print(f"    {i}. {strategy}")
    else:
        print("  (Not enough data yet)")

    # Get bypass recommendations
    print("\n💡 Getting bypass recommendations for detected filters...")
    filters = memory.get_detected_filters()
    for filter_type in filters[:2]:  # Show top 2
        print(f"\n  For filter '{filter_type}':")
        bypasses = memory.get_bypass_recommendations(filter_type, limit=2)
        if bypasses:
            for bypass in bypasses:
                print(f"    • {bypass['bypass_technique']}")
                print(f"      Effectiveness: {bypass['effectiveness_score']:.1%}")
                print(f"      Example: {bypass['payload_example'][:50]}")
        else:
            print("    (No known bypasses yet)")

    memory.close()
    print("\n✓ Demo 2 complete!")


def demo_memory_insights():
    """Demonstrate memory insights and intelligence"""
    print_section("3. MEMORY INSIGHTS & INTELLIGENCE")

    memory = MemoryManager(
        session_id="demo-session-3",
        target_url="https://example.com/search",
        db_path="memory/demo_memory.db",
        enabled=True
    )

    # Update target intelligence
    print("🎯 Updating target intelligence...")
    memory.update_target_intelligence(
        technology_stack="PHP 7.4, Apache 2.4",
        waf_detected="ModSecurity",
        vulnerability_found=True,
        notes="Vulnerable to SVG-based XSS"
    )
    print("  ✓ Intelligence updated\n")

    # Get memory insights
    print("📊 Retrieving memory insights...")
    insights = memory.get_memory_insights()

    print(f"\n  Session Summary:")
    summary = insights['session_summary']
    print(f"    • Payloads tested: {summary['tested_payloads']}")
    print(f"    • Success rate: {summary['success_rate']:.1%}")
    print(f"    • Success count: {summary['success_count']}")
    print(f"    • Failure count: {summary['failure_count']}")

    if insights.get('detected_filters'):
        print(f"\n  Detected Filters:")
        for filt in insights['detected_filters']:
            print(f"    • {filt}")

    if insights.get('recommended_strategies'):
        print(f"\n  Recommended Strategies:")
        for strategy in insights['recommended_strategies']:
            print(f"    • {strategy}")

    intel = insights.get('target_intelligence', {})
    if intel:
        print(f"\n  Target Intelligence:")
        if intel.get('technology_stack'):
            print(f"    • Tech Stack: {intel['technology_stack']}")
        if intel.get('waf_detected'):
            print(f"    • WAF: {intel['waf_detected']}")
        if intel.get('vulnerability_count'):
            print(f"    • Vulnerabilities Found: {intel['vulnerability_count']}")

    # Get session summary
    print("\n📈 Session Statistics:")
    session_summary = memory.get_session_summary()
    print(f"  • Elapsed time: {session_summary['elapsed_time']:.2f}s")
    print(f"  • Detected filters: {len(session_summary['detected_filters'])}")

    memory.close()
    print("\n✓ Demo 3 complete!")


def demo_skip_tested_payloads():
    """Demonstrate skipping previously tested payloads"""
    print_section("4. SMART PAYLOAD SKIPPING")

    memory = MemoryManager(
        session_id="demo-session-4",
        target_url="https://example.com/search",
        db_path="memory/demo_memory.db",
        enabled=True
    )

    print("🧠 Checking if payloads should be skipped based on memory...\n")

    test_payloads = [
        "<script>alert(1)</script>",  # Previously failed
        '<svg onload=alert(1)>',      # Previously succeeded
        '<iframe src=javascript:alert(1)>',  # Never tested
    ]

    for payload in test_payloads:
        should_skip, reason = memory.should_skip_payload(payload)

        if should_skip:
            print(f"⏭️  SKIP: {payload[:50]}")
            print(f"         Reason: {reason}")
        else:
            print(f"✅ TEST: {payload[:50]}")
            if reason:
                print(f"         Note: {reason}")
            else:
                print(f"         Note: Not tested before")

        print()

    memory.close()
    print("✓ Demo 4 complete!")


def demo_statistics():
    """Demonstrate memory statistics"""
    print_section("5. MEMORY DATABASE STATISTICS")

    storage = MemoryStorage("memory/demo_memory.db")

    print("📊 Memory database statistics:\n")

    stats = storage.get_statistics()
    for table, count in stats.items():
        table_name = table.replace('_', ' ').title()
        print(f"  {table_name:.<35} {count:>5} records")

    print("\n✓ Demo 5 complete!")

    storage.close()


def demo_similar_attempts():
    """Demonstrate retrieving similar attempts"""
    print_section("6. SIMILAR ATTEMPTS RECALL")

    memory = MemoryManager(
        session_id="demo-session-5",
        target_url="https://example.com/search",
        db_path="memory/demo_memory.db",
        enabled=True
    )

    print("🔍 Recalling similar attempts from memory...\n")

    similar = memory.get_similar_attempts(payload_type="xss", limit=5)

    if similar:
        print(f"  Found {len(similar)} similar attempts:")
        for i, attempt in enumerate(similar, 1):
            status = "✅" if attempt['success'] else "❌"
            print(f"\n  {i}. {status} {attempt['payload'][:50]}")
            print(f"     Strategy: {attempt['strategy']}")
            print(f"     Confidence: {attempt['confidence']:.1%}")
            if attempt.get('detected_filter'):
                print(f"     Filter: {attempt['detected_filter']}")
    else:
        print("  No similar attempts found")

    memory.close()
    print("\n✓ Demo 6 complete!")


def main():
    """Main demo function"""
    print("="*80)
    print("  AGENT MEMORY SYSTEM DEMONSTRATION")
    print("="*80)
    print("\nThis demo shows how agents learn and remember across scans.")
    print("Memory is persistent - data survives across sessions!")

    try:
        demo_basic_memory()
        time.sleep(0.5)

        demo_learning_and_recommendations()
        time.sleep(0.5)

        demo_memory_insights()
        time.sleep(0.5)

        demo_skip_tested_payloads()
        time.sleep(0.5)

        demo_statistics()
        time.sleep(0.5)

        demo_similar_attempts()

        print_section("DEMONSTRATION COMPLETE")

        print("🎉 All demos completed successfully!")
        print("\n📁 Memory database saved to: memory/demo_memory.db")
        print("💡 Run this demo again to see memory persistence in action!")
        print("\n🧹 To clear demo memory:")
        print("   rm memory/demo_memory.db")

    except Exception as e:
        print(f"\n❌ Error during demo: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
