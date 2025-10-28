#!/usr/bin/env python3
"""
Direct DOM XSS test - bypasses test suite for real testing
"""
import asyncio
import sys
import logging
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.xss_agent.agents.dom_xss import DOMXSSAgent

async def test_real_target(target_url):
    """Test real DOM XSS target with detailed output"""

    print(f"\n{'='*80}")
    print(f"Testing: {target_url}")
    print(f"{'='*80}\n")

    agent = DOMXSSAgent()

    print("[1] Analyzing page JavaScript...")

    # Use the full detect_dom_xss method which includes form following
    print("[*] Running full DOM XSS detection (includes form following)...")
    vulnerabilities = await agent.detect_dom_xss(target_url)

    if vulnerabilities:
        print(f"\n{'='*80}")
        print(f"✓✓✓ SUCCESS! Found {len(vulnerabilities)} vulnerabilities")
        print(f"{'='*80}\n")

        for vuln in vulnerabilities:
            print(f"[!] VULNERABILITY:")
            print(f"    Source: {vuln.source.source_type}")
            print(f"    Sink: {vuln.sink.sink_type}")
            print(f"    Payload: {vuln.payload}")
            print(f"    URL: {vuln.url}")
            print(f"    Evidence: {vuln.execution_evidence}")

        agent.save_results(vulnerabilities)
        return

    # If no vulns, show detailed analysis
    print("\n[*] No vulnerabilities found, showing detailed analysis...")
    analysis = await agent._analyze_page_javascript(target_url)

    print(f"\n[✓] Analysis complete:")
    print(f"    Sources detected: {len(analysis['sources'])}")
    for src in analysis['sources']:
        print(f"      - {src['source_type']}: {src.get('value', 'N/A')[:50]}")

    print(f"\n    Sinks detected: {len(analysis['sinks'])}")
    for sink in analysis['sinks']:
        print(f"      - {sink['sink_type']} at {sink['sink_location']}")

    print(f"\n    Parameters discovered: {len(analysis['parameters'])}")
    for param in analysis['parameters']:
        print(f"      - {param['name']} ({param['source']})")

    print(f"\n    Frameworks: {', '.join(analysis['frameworks']) or 'None'}")
    print(f"    JS files: {len(analysis['javascript_files'])}")
    print(f"    Inline scripts: {len(analysis['inline_scripts'])}")

    if not analysis['sources'] and not analysis['sinks']:
        print("\n[!] No sources or sinks detected - page may not be vulnerable or needs interaction")
        return

    print("\n[2] Generating test vectors...")
    vectors = await agent._generate_dom_test_vectors(target_url, analysis)

    print(f"\n[✓] Generated {len(vectors)} test vectors:")
    for i, vec in enumerate(vectors, 1):
        print(f"    {i}. {vec['source']} -> {vec['sink']}")
        print(f"       Payload: {vec['payload']}")
        print(f"       Reason: {vec.get('reasoning', 'N/A')}")

    print("\n[3] Testing vectors...")
    vulnerabilities = []

    for i, vector in enumerate(vectors, 1):
        print(f"\n    Testing vector {i}/{len(vectors)}: {vector['source']} -> {vector['sink']}")
        vuln = await agent._test_dom_vector(target_url, vector)

        if vuln:
            vulnerabilities.append(vuln)
            print(f"    ✓ EXPLOITED!")
        else:
            print(f"    ✗ Failed")

    print(f"\n{'='*80}")
    print(f"Results: {len(vulnerabilities)} vulnerabilities confirmed")
    print(f"{'='*80}\n")

    if vulnerabilities:
        for vuln in vulnerabilities:
            print(f"[!] VULNERABILITY:")
            print(f"    Source: {vuln.source.source_type}")
            print(f"    Sink: {vuln.sink.sink_type}")
            print(f"    Payload: {vuln.payload}")
            print(f"    URL: {vuln.url}")
            print(f"    Evidence: {vuln.execution_evidence}")

        agent.save_results(vulnerabilities)
        print(f"\n[✓] Results saved!")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python test_real_dom.py <URL>")
        sys.exit(1)

    target = sys.argv[1]
    asyncio.run(test_real_target(target))
