#!/usr/bin/env python3
"""
Test script for DOM XSS Agent

This script demonstrates the DOM XSS detection capabilities.
"""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.xss_agent.agents.dom_xss import DOMXSSAgent
from src.xss_agent.analyzers.sink_detector import SinkDetectorAnalyzer


async def test_dom_xss_detection():
    """
    Test DOM XSS detection on various scenarios
    """
    print("="*80)
    print("DOM XSS Agent Test Suite")
    print("="*80)

    # Initialize agent
    agent = DOMXSSAgent()
    print("\n[✓] DOM XSS Agent initialized")

    # Test 1: Sink Detector
    print("\n" + "="*80)
    print("Test 1: JavaScript Sink Detection")
    print("="*80)

    analyzer = SinkDetectorAnalyzer()

    # Sample vulnerable JavaScript
    vulnerable_code = """
    // Vulnerable code examples
    function handleHash() {
        var content = location.hash.substring(1);
        document.getElementById('output').innerHTML = content;  // SINK!
    }

    function jsonpHandler() {
        var callback = new URLSearchParams(location.search).get('callback');
        if (callback) {
            eval(callback + '()');  // DANGEROUS SINK!
        }
    }

    function updateTitle() {
        document.title = location.hash;  // Less dangerous but still tracked
    }

    $(document).ready(function() {
        var userContent = location.search.split('=')[1];
        $('#content').html(userContent);  // jQuery sink
    });
    """

    print("\n[*] Analyzing JavaScript code for dangerous sinks...")
    detected_sinks = analyzer.analyze_javascript_code(vulnerable_code, "vulnerable.js")

    print(f"\n[✓] Found {len(detected_sinks)} dangerous sinks:\n")
    for i, sink in enumerate(detected_sinks, 1):
        print(f"{i}. [{sink.severity.upper()}] {sink.sink_name}")
        print(f"   Location: {sink.location}")
        print(f"   Code: {sink.code_snippet.strip()[:80]}...")
        print(f"   Confidence: {sink.confidence:.2f}")
        if sink.taint_analysis:
            print(f"   Exploitable: {sink.taint_analysis.get('exploitable', 'Unknown')}")
        print()

    # Test 2: Generate Exploitation Strategy
    print("="*80)
    print("Test 2: AI-Powered Exploitation Strategy")
    print("="*80)

    print("\n[*] Generating exploitation strategy...")
    strategy = analyzer.generate_exploitation_strategy(detected_sinks)

    print("\n[✓] Strategy generated:")
    import json
    print(json.dumps(strategy, indent=2))

    # Test 3: Test with actual target (if provided)
    print("\n" + "="*80)
    print("Test 3: Live DOM XSS Detection")
    print("="*80)

    if len(sys.argv) > 1:
        target_url = sys.argv[1]
        print(f"\n[*] Testing target: {target_url}")

        print("[*] Analyzing page for DOM sources and sinks...")
        vulnerabilities = await agent.detect_dom_xss(target_url)

        print(f"\n[✓] Detection complete!")
        print(f"[✓] Found {len(vulnerabilities)} DOM XSS vulnerabilities")

        for vuln in vulnerabilities:
            print(f"\n[!] VULNERABILITY CONFIRMED")
            print(f"    Source: {vuln.source.source_type}")
            print(f"    Sink: {vuln.sink.sink_type}")
            print(f"    Payload: {vuln.payload}")
            print(f"    Severity: {vuln.severity.upper()}")
            print(f"    Recommendation: {vuln.recommendation}")

        if vulnerabilities:
            agent.save_results(vulnerabilities)
            print(f"\n[✓] Results saved to dom_xss_results.json")
    else:
        print("\n[i] To test a live target, run: python test_dom_xss_agent.py <URL>")
        print("[i] Example: python test_dom_xss_agent.py http://testphp.vulnweb.com/")

    print("\n" + "="*80)
    print("Test Suite Complete!")
    print("="*80)


def test_sink_patterns():
    """
    Test sink pattern detection
    """
    print("\n" + "="*80)
    print("Bonus: Sink Pattern Database")
    print("="*80)

    analyzer = SinkDetectorAnalyzer()

    print(f"\n[✓] Loaded {len(analyzer.sink_patterns)} sink patterns:\n")

    # Group by severity
    by_severity = {'critical': [], 'high': [], 'medium': [], 'low': []}
    for pattern in analyzer.sink_patterns:
        by_severity[pattern.severity].append(pattern)

    for severity in ['critical', 'high', 'medium', 'low']:
        patterns = by_severity[severity]
        if patterns:
            print(f"\n{severity.upper()} Severity ({len(patterns)} patterns):")
            for pattern in patterns:
                print(f"  • {pattern.name}: {pattern.description}")


async def main():
    """Main test runner"""
    try:
        # Run main test suite
        await test_dom_xss_detection()

        # Show sink patterns
        test_sink_patterns()

        print("\n[✓] All tests completed successfully!")

    except KeyboardInterrupt:
        print("\n\n[!] Tests interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n[✗] Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                        DOM XSS Agent Test Suite                             ║
║                   Advanced DOM-Based XSS Detection                           ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)

    asyncio.run(main())
