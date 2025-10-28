#!/usr/bin/env python3
"""
Dynamic XSS Agent - Main Entry Point

A modular, comprehensive XSS vulnerability detection and exploitation tool.

Features:
- Reflected XSS detection via Nuclei + AI-powered payload generation
- Stored XSS detection via intelligent form discovery and submission
- Blind XSS detection via OAST (Out-of-Band Application Security Testing)
- DOM XSS detection via source/sink analysis + iterative LLM refinement
- Comprehensive reporting with screenshots and detailed logs

Usage:
    python main.py <target_url> [options]

Examples:
    python main.py http://testphp.vulnweb.com/search.php?test=query
    python main.py http://dvwa.local/vulnerabilities/xss_s/ --proxy
    python main.py http://example.com/forms --config config.json
    # Note: Agent automatically cascades: Nuclei → DOM XSS → Dynamic LLM
"""

import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path

# Add src directory to Python path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.xss_agent.orchestrator import DynamicXSSOrchestrator
from src.xss_agent.agents.dom_xss import DOMXSSAgent
from src.xss_agent.utils.env_loader import load_env_file

# Import reasoning transparency system
from utils.reasoning_tracker import ReasoningTracker
from utils.transparent_agent import wrap_agent

# Import memory system
from utils.memory_manager import MemoryManager

# Try to import framework agent (v3)
try:
    from src.xss_agent.agents.dom_xss_v3 import DOMXSSAgentV3
    FRAMEWORK_AVAILABLE = True
except ImportError:
    FRAMEWORK_AVAILABLE = False

# Try to import SQLi agent
try:
    from src.sqli_agent.sqli_orchestrator import SQLiOrchestrator, test_sqli
    from src.sqli_agent.analysis_framework.config import SQLiAnalysisConfig
    SQLI_AVAILABLE = True
except ImportError:
    SQLI_AVAILABLE = False


def setup_logging(log_level: str = "INFO"):
    """Configure logging for the application"""
    # Create logs directory
    os.makedirs("./logs", exist_ok=True)

    # Configure logging
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    # File handler
    file_handler = logging.FileHandler('./logs/dynamic_xss_agent.log')
    file_handler.setFormatter(logging.Formatter(log_format))

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(log_format))

    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper()))
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)


def load_config(config_path: str) -> dict:
    """Load configuration from JSON file"""
    if not os.path.exists(config_path):
        return {}

    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logging.warning(f"Failed to load config from {config_path}: {e}")
        return {}


def print_banner():
    """Print application banner"""
    banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                           AutoHack Agent v2.1                               ║
║                    XSS & SQLi Detection & Exploitation                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  XSS Detection:                                                              ║
║  • Reflected XSS: Nuclei + AI payload generation                            ║
║  • Stored XSS: Smart form discovery + submission testing                    ║
║  • Blind XSS: OAST-based out-of-band detection                             ║
║  • DOM XSS: Source/sink analysis + iterative LLM refinement                 ║
║                                                                              ║
║  SQLi Detection:                                                             ║
║  • Error-based: Database error signature detection                          ║
║  • Time-based blind: SLEEP/WAITFOR delay detection                          ║
║  • Boolean-based blind: Response differential analysis                      ║
║  • UNION-based: Data extraction via UNION SELECT                            ║
║                                                                              ║
║  • Advanced: Proxy integration + comprehensive reporting                     ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)


async def main():
    """Main application entry point"""
    parser = argparse.ArgumentParser(
        description="Dynamic XSS Agent - Comprehensive XSS vulnerability detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s http://testphp.vulnweb.com/search.php?test=query
  %(prog)s http://dvwa.local/vulnerabilities/xss_s/ --proxy
  %(prog)s http://example.com/forms --config config.json --log-level DEBUG
        """
    )

    parser.add_argument(
        "target_url",
        help="Target URL to test for XSS vulnerabilities"
    )

    parser.add_argument(
        "--proxy",
        action="store_true",
        help="Enable proxy mode for traffic capture and analysis"
    )

    parser.add_argument(
        "--proxy-port",
        type=int,
        default=8080,
        help="Port for proxy server (default: 8080)"
    )

    parser.add_argument(
        "--config",
        default="config.json",
        help="Path to configuration file (default: config.json)"
    )

    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level (default: INFO)"
    )

    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress banner output"
    )

    parser.add_argument(
        "--dom",
        action="store_true",
        help="Skip Nuclei scan and go directly to DOM XSS detection (faster if you know it's DOM-only)"
    )

    parser.add_argument(
        "--sqli",
        action="store_true",
        help="Run SQL injection detection (error/time/boolean/union-based)"
    )

    parser.add_argument(
        "--sqli-config",
        choices=["default", "fast", "aggressive", "conservative"],
        default="aggressive",
        help="SQLi configuration preset (default: default)"
    )

    parser.add_argument(
        "--sqli-hybrid",
        action="store_true",
        help="Enable hybrid generator for SQLi (database + LLM + mutations)"
    )

    parser.add_argument(
        "--use-framework",
        action="store_true",
        help="Use Analysis Framework v3.0 for DOM XSS testing (enhanced)"
    )

    parser.add_argument(
        "--framework-config",
        choices=["default", "aggressive", "fast", "conservative"],
        default="default",
        help="Framework configuration preset (default: default)"
    )

    parser.add_argument(
        "--hybrid",
        action="store_true",
        default=True,
        help="Use hybrid generator (database + LLM + mutation) - enabled by default"
    )

    parser.add_argument(
        "--no-hybrid",
        action="store_true",
        help="Disable hybrid generator and use pure LLM generation instead"
    )

    # Reasoning transparency arguments
    parser.add_argument(
        "--reasoning-mode",
        choices=["off", "verbose"],
        default="off",
        help="Enable reasoning transparency mode (default: off)"
    )

    parser.add_argument(
        "--reasoning-output",
        default="logs/reasoning",
        help="Directory for reasoning JSON logs (default: logs/reasoning)"
    )

    parser.add_argument(
        "--no-reasoning-color",
        action="store_true",
        help="Disable colored output for reasoning transparency"
    )

    # Memory system arguments
    parser.add_argument(
        "--memory",
        action="store_true",
        help="Enable agent memory system for learning across scans"
    )

    parser.add_argument(
        "--memory-db",
        default="memory/agent_memory.db",
        help="Path to memory database file (default: memory/agent_memory.db)"
    )

    parser.add_argument(
        "--no-memory-learning",
        action="store_true",
        help="Disable automatic learning from test results"
    )

    args = parser.parse_args()

    # Handle hybrid flag logic
    if args.no_hybrid:
        args.hybrid = False

    # Setup logging
    setup_logging(args.log_level)

    # Print banner
    if not args.no_banner:
        print_banner()

    # Load environment variables
    load_env_file()

    # Load configuration
    config = load_config(args.config)

    # Initialize reasoning tracker if enabled
    reasoning_tracker = None
    if args.reasoning_mode == "verbose":
        reasoning_tracker = ReasoningTracker(
            mode=args.reasoning_mode,
            console_output=True,
            json_output=True,
            output_dir=args.reasoning_output,
            color_output=not args.no_reasoning_color
        )
        print(f"🧠 Reasoning transparency enabled (mode: {args.reasoning_mode})")
        print(f"📁 Reasoning logs will be saved to: {args.reasoning_output}/")

    # Initialize memory manager if enabled
    memory_manager = None
    if args.memory:
        # Create unique session ID for memory
        import uuid
        memory_session_id = str(uuid.uuid4())

        memory_manager = MemoryManager(
            session_id=memory_session_id,
            target_url=args.target_url,
            db_path=args.memory_db,
            enabled=True
        )
        print(f"💾 Agent memory enabled")
        print(f"📊 Memory database: {args.memory_db}")

        # Show memory statistics
        stats = memory_manager.get_statistics()
        if stats:
            print(f"📈 Memory contains: {stats.get('payload_attempts', 0)} attempts, "
                  f"{stats.get('detected_filters', 0)} filters, "
                  f"{stats.get('successful_bypasses', 0)} bypasses")

    # Print startup information
    if args.sqli:
        print("🚀 SQL Injection detection mode")
    elif args.dom:
        print("🚀 DOM XSS detection mode")
    else:
        mode = "🚀 Proxy mode" if args.proxy else "🚀 Standard mode (no proxy)"
        print(mode)

    # Initialize and run appropriate agent
    try:
        if args.sqli:
            # Run SQL injection detection
            if not SQLI_AVAILABLE:
                print("❌ Error: SQLi Agent not available")
                print("   Make sure src/sqli_agent/ directory exists")
                sys.exit(1)

            print(f"\n[*] Starting SQL injection detection on {args.target_url}")
            print(f"   Configuration: {args.sqli_config}")
            if args.sqli_hybrid:
                print(f"   Generator: HYBRID (database + LLM + mutations)")
            else:
                print(f"   Generator: Database only")
            print()

            # Create reasoning context if enabled
            reasoning_session_id = None
            if reasoning_tracker:
                reasoning_session_id = reasoning_tracker.create_context("SQLiOrchestrator", args.target_url)

            # Run SQLi testing with hybrid mode if requested
            result = await test_sqli(
                target_url=args.target_url,
                config_preset=args.sqli_config,
                use_hybrid=args.sqli_hybrid,
                memory_manager=memory_manager,
                reasoning_tracker=reasoning_tracker,
                reasoning_session_id=reasoning_session_id
            )

            # Print results
            if result.vulnerable:
                print(f"\n{'='*80}")
                print(f"✓✓✓ SUCCESS! Found SQL injection vulnerabilities")
                print(f"{'='*80}\n")

                print(f"Target: {result.target_url}")
                print(f"Database: {result.database_type.value.upper()}")
                print(f"Injection Types: {', '.join([t.value for t in result.injection_types])}")
                print(f"Total Attempts: {result.total_attempts}")
                print(f"Successful: {result.successful_attempts}")
                print(f"Time Elapsed: {result.time_elapsed:.2f}s")
                print()

                print(f"[+] Vulnerable Parameters:")
                for inj_point in result.injection_points:
                    if inj_point.confidence > 0:
                        print(f"    • {inj_point.parameter} (confidence: {inj_point.confidence}%)")

                print()
                print(f"[+] Working Payloads:")
                for idx, payload_data in enumerate(result.successful_payloads[:5], 1):
                    payload = payload_data['payload']
                    print(f"    [{idx}] {payload[:80]}...")
                    print(f"        Type: {payload_data['type']}, Confidence: {payload_data['confidence']}%")

                    # Build and print the exploit URL
                    from urllib.parse import urlencode, urlparse, urlunparse, parse_qs
                    parsed = urlparse(result.target_url)
                    params = parse_qs(parsed.query) if parsed.query else {}

                    # Get the parameter that was exploited
                    if result.injection_points:
                        param_name = result.injection_points[0].parameter
                        params[param_name] = [payload]

                        new_query = urlencode(params, doseq=True)
                        exploit_url = urlunparse((
                            parsed.scheme,
                            parsed.netloc,
                            parsed.path,
                            parsed.params,
                            new_query,
                            parsed.fragment
                        ))
                        print(f"        🔗 Exploit URL: {exploit_url}")

                # Save results to current directory and results directory
                output_file = "sqli_results.json"
                results_dir = Path("./results")
                results_dir.mkdir(exist_ok=True)
                results_file = results_dir / "sqli_results.json"

                # Save to both locations
                with open(output_file, 'w') as f:
                    # Convert result to dict for JSON serialization
                    result_dict = {
                        'target_url': result.target_url,
                        'vulnerable': result.vulnerable,
                        'database_type': result.database_type.value,
                        'injection_types': [t.value for t in result.injection_types],
                        'injection_points': [
                            {
                                'parameter': ip.parameter,
                                'location': ip.location,
                                'confidence': ip.confidence
                            }
                            for ip in result.injection_points if ip.confidence > 0
                        ],
                        'successful_payloads': result.successful_payloads,
                        'total_attempts': result.total_attempts,
                        'successful_attempts': result.successful_attempts,
                        'time_elapsed': result.time_elapsed,
                        'notes': result.notes
                    }
                    json.dump(result_dict, f, indent=2)

                # Also save to results directory
                with open(results_file, 'w') as f:
                    json.dump(result_dict, f, indent=2)

                print()
                print(f"[✓] Results saved to: {output_file}")
                print(f"[✓] Results also saved to: {results_file}")
                print(f"[✓] Screenshots saved to: screenshots/")
                print(f"[✓] HTML captures saved to: html_captures/")
                print(f"[✓] Debug logs saved to: logs/")

                sys.exit(0)
            else:
                print(f"\n[!] No SQL injection vulnerabilities found on {args.target_url}")
                print(f"[*] Tested {result.total_attempts} payloads across {len(result.injection_points)} parameter(s)")

                # Save negative results too
                output_file = "sqli_results.json"
                results_dir = Path("./results")
                results_dir.mkdir(exist_ok=True)
                results_file = results_dir / "sqli_results.json"

                result_dict = {
                    'target_url': result.target_url,
                    'vulnerable': False,
                    'injection_points': [
                        {'parameter': ip.parameter, 'location': ip.location}
                        for ip in result.injection_points
                    ],
                    'total_attempts': result.total_attempts,
                    'time_elapsed': result.time_elapsed,
                    'notes': result.notes
                }

                with open(output_file, 'w') as f:
                    json.dump(result_dict, f, indent=2)

                with open(results_file, 'w') as f:
                    json.dump(result_dict, f, indent=2)

                print(f"[*] Results saved to: {output_file}")
                print(f"[*] Results also saved to: {results_file}")
                sys.exit(1)

        else:
            # === CASCADING XSS DETECTION WORKFLOW ===
            # 1. Nuclei scan (fast, template-based) - Reflected/Stored/Blind
            # 2. If found → Report & Done
            # 3. If not found → DOM XSS detection (source/sink analysis)
            # 4. If DOM basic fails → Dynamic LLM payload generation

            # Check if user wants to skip Nuclei and go directly to DOM XSS
            if not args.dom:
                print(f"\n{'='*80}")
                print(f"🔍 PHASE 1: Nuclei Scan (Reflected, Stored, Blind XSS)")
                print(f"{'='*80}")

                orchestrator = DynamicXSSOrchestrator(
                    use_proxy=args.proxy,
                    proxy_port=args.proxy_port,
                    config=config
                )

                # Print OAST configuration if available
                if hasattr(orchestrator, 'oast_agent') and orchestrator.oast_agent:
                    print(f"🎯 OAST mode: {orchestrator.oast_agent.mode}")
                    print(f"📊 OAST threshold: {orchestrator.oast_agent.threshold}")
                    print(f"🛡️  OAST whitelist: {', '.join(orchestrator.oast_agent.whitelist)}")

                # Start Nuclei + Form testing
                nuclei_results = await orchestrator.verify_xss(args.target_url)

                # Check if vulnerabilities found
                successful_nuclei = sum(1 for r in nuclei_results if r.get('successful', False))

                if successful_nuclei > 0:
                    # Found vulnerabilities with Nuclei - report and exit
                    print(f"\n{'='*80}")
                    print(f"✓✓✓ SUCCESS! Found {len(nuclei_results)} XSS vulnerabilities with Nuclei")
                    print(f"{'='*80}\n")

                    total_attempts = sum(r.get('total_attempts', 1) for r in nuclei_results)
                    print(f"Vulnerabilities found: {len(nuclei_results)}")
                    print(f"Successfully exploited: {successful_nuclei}")
                    print(f"Success rate: {(successful_nuclei/len(nuclei_results)*100):.1f}%")
                    print(f"Total attempts made: {total_attempts}")
                    print(f"\n[✓] Results saved to: dynamic_xss_results.json")
                    print(f"[✓] Screenshots saved to: screenshots/")
                    print(f"[✓] Debug logs saved to: logs/")

                    sys.exit(0)

                # No vulnerabilities found with Nuclei - proceed to DOM XSS
                total_attempts = sum(r.get('total_attempts', 1) for r in nuclei_results)
                print(f"\n[*] Nuclei completed scan - found 0 vulnerabilities")
                if total_attempts > 0:
                    print(f"[*] Tested {total_attempts} attack vectors")
                print(f"\n{'='*80}")
                print(f"🔍 PHASE 2: DOM XSS Detection (Source/Sink Analysis)")
                print(f"{'='*80}\n")
            else:
                # User specified --dom flag, skip Nuclei
                print(f"\n{'='*80}")
                print(f"🔍 DOM XSS Detection (Source/Sink Analysis + Adaptive LLM)")
                print(f"{'='*80}")
                print(f"[*] Skipping Nuclei scan (--dom flag specified)\n")

            # Choose DOM XSS agent version
            if args.use_framework:
                if not FRAMEWORK_AVAILABLE:
                    print("❌ Error: Analysis Framework v3.0 not available")
                    print("   Make sure src/xss_agent/analysis_framework/ exists")
                    sys.exit(1)

                generator_type = "HYBRID (database + LLM + mutation)" if args.hybrid else "LLM-only"
                print(f"   Using Analysis Framework v3.0 ({args.framework_config} config)")
                print(f"   Generator: {generator_type}")
                dom_agent = DOMXSSAgentV3(
                    framework_config=args.framework_config,
                    use_hybrid=args.hybrid
                )
            else:
                print("   Using Classic Detection v2.2")

                # Create reasoning session if reasoning is enabled
                reasoning_session_id = None
                if reasoning_tracker:
                    reasoning_session_id = reasoning_tracker.create_context("DOMXSSAgent", args.target_url)

                # Create agent with memory and reasoning built-in
                dom_agent = DOMXSSAgent(
                    memory_manager=memory_manager,
                    reasoning_tracker=reasoning_tracker,
                    reasoning_session_id=reasoning_session_id
                )

            # Show memory insights before starting DOM XSS
            if memory_manager:
                insights = memory_manager.get_memory_insights()
                if insights.get('detected_filters'):
                    print(f"\n💡 Memory recalls: Detected filters on this target before:")
                    for filter_type in insights['detected_filters']:
                        print(f"   • {filter_type}")

                if insights.get('recommended_strategies'):
                    print(f"\n💡 Memory suggests trying these strategies:")
                    for strategy in insights['recommended_strategies']:
                        print(f"   • {strategy}")

            # Run DOM XSS detection
            dom_vulnerabilities = await dom_agent.detect_dom_xss(args.target_url)

            # Finalize reasoning context if enabled
            if reasoning_tracker and dom_agent.reasoning_session:
                json_path = reasoning_tracker.finalize_context(dom_agent.reasoning_session)
                if json_path:
                    print(f"\n[✓] Reasoning log saved to: {json_path}")

            # Finalize memory if enabled
            if memory_manager:
                memory_manager.finalize_session()
                summary = memory_manager.get_session_summary()
                print(f"\n💾 Memory session summary:")
                print(f"   • Tested payloads: {summary['tested_payloads']}")
                print(f"   • Success rate: {summary['success_rate']:.1%}")
                print(f"   • Detected filters: {len(summary['detected_filters'])}")
                memory_manager.close()

            # Print DOM XSS results
            if dom_vulnerabilities:
                print(f"\n{'='*80}")
                print(f"✓✓✓ SUCCESS! Found {len(dom_vulnerabilities)} DOM XSS vulnerabilities")
                print(f"{'='*80}\n")

                for i, vuln in enumerate(dom_vulnerabilities, 1):
                    print(f"[{i}] VULNERABILITY:")
                    print(f"    Source: {vuln.source.source_type}")
                    if vuln.source.parameter:
                        print(f"    Parameter: {vuln.source.parameter}")
                    print(f"    Sink: {vuln.sink.sink_type}")
                    print(f"    Payload: {vuln.payload}")
                    print(f"    URL: {vuln.url}")
                    print(f"    Severity: {vuln.severity.upper()}")
                    if vuln.execution_evidence:
                        print(f"    Evidence: {', '.join(vuln.execution_evidence)}")
                    print(f"    Recommendation: {vuln.recommendation}")
                    print()

                # Save results
                dom_agent.save_results(dom_vulnerabilities)

                print(f"[✓] Results saved to: dom_xss_results.json")
                print(f"[✓] Screenshots saved to: screenshots/")
                print(f"[✓] Debug logs saved to: logs/")

                sys.exit(0)
            else:
                print(f"\n[!] No XSS vulnerabilities found on {args.target_url}")
                print(f"[*] Tested with Nuclei and DOM XSS detection")
                print(f"[*] Results saved to: dom_xss_results.json")
                sys.exit(1)

    except KeyboardInterrupt:
        print("\n🛑 Operation cancelled by user")
        sys.exit(130)
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        print(f"\n❌ Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    # Ensure we're running with Python 3.8+
    if sys.version_info < (3, 8):
        print("❌ Error: Python 3.8 or higher is required")
        sys.exit(1)

    # Run the async main function
    asyncio.run(main())
