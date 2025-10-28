#!/usr/bin/env python3
"""
CLI Script for XSS Artifact Parser

Usage:
    python scripts/parse_artifacts.py --run ./logs/<cid>/ --output ./logs/<cid>/artifacts/report.txt
    python scripts/parse_artifacts.py --session 20250913_121921_af130fed --verbose
    python scripts/parse_artifacts.py --har proxy_captures/capture_20250916_173713.har --payload "<script>alert(1)</script>"

Examples:
    # Analyze a complete session
    python scripts/parse_artifacts.py --session 20250913_121921_af130fed

    # Analyze specific run directory
    python scripts/parse_artifacts.py --run ./logs/20250913_121921_af130fed/ --output ./logs/20250913_121921_af130fed/artifacts/

    # Quick HAR analysis
    python scripts/parse_artifacts.py --har proxy_captures/capture_20250916_173713.har --payload "<script>alert('XSS')</script>"
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import List, Dict, Any

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from artifact_parser import ArtifactParser, create_parser_with_logging


def setup_logging(verbose: bool = False) -> None:
    """Setup logging configuration"""
    level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )


def find_session_directory(session_id: str, base_logs_dir: str = "./logs") -> Path:
    """Find the session directory by session ID"""
    logs_path = Path(base_logs_dir)

    if not logs_path.exists():
        raise FileNotFoundError(f"Logs directory not found: {base_logs_dir}")

    # Look for directory containing the session ID
    for session_dir in logs_path.iterdir():
        if session_dir.is_dir() and session_id in session_dir.name:
            return session_dir

    raise FileNotFoundError(f"Session directory not found for session ID: {session_id}")


def analyze_session(session_id: str, output_dir: str = None, verbose: bool = False) -> Dict[str, Any]:
    """Analyze a complete session by session ID"""
    logger = logging.getLogger(__name__)

    try:
        # Find session directory
        session_path = find_session_directory(session_id)
        logger.info(f"Found session directory: {session_path}")

        # Set default output directory
        if not output_dir:
            output_dir = str(session_path / "artifacts")

        # Create parser and analyze
        parser = create_parser_with_logging(str(session_path / "parser_logs"))
        findings = parser.analyze_run(str(session_path))

        # Save results
        parser.save_findings(findings, output_dir)

        # Return summary
        summary = {
            "session_id": session_id,
            "session_path": str(session_path),
            "total_findings": len(findings),
            "output_directory": output_dir,
            "summary_by_outcome": {}
        }

        # Calculate outcome statistics
        for finding in findings:
            outcome = finding.difference_summary
            summary["summary_by_outcome"][outcome] = summary["summary_by_outcome"].get(outcome, 0) + 1

        return summary

    except Exception as e:
        logger.error(f"Failed to analyze session {session_id}: {e}")
        raise


def analyze_run_directory(run_dir: str, output_dir: str = None, verbose: bool = False) -> Dict[str, Any]:
    """Analyze a specific run directory"""
    logger = logging.getLogger(__name__)

    run_path = Path(run_dir)
    if not run_path.exists():
        raise FileNotFoundError(f"Run directory not found: {run_dir}")

    # Set default output directory
    if not output_dir:
        output_dir = str(run_path / "artifacts")

    # Create parser and analyze
    parser = create_parser_with_logging(str(run_path / "parser_logs"))
    findings = parser.analyze_run(run_dir)

    # Save results
    parser.save_findings(findings, output_dir)

    logger.info(f"Analysis complete. Results saved to {output_dir}")

    # Return summary
    summary = {
        "run_directory": run_dir,
        "total_findings": len(findings),
        "output_directory": output_dir,
        "summary_by_outcome": {}
    }

    # Calculate outcome statistics
    for finding in findings:
        outcome = finding.difference_summary
        summary["summary_by_outcome"][outcome] = summary["summary_by_outcome"].get(outcome, 0) + 1

    return summary


def analyze_har_file(har_path: str, payload: str, output_file: str = None) -> Dict[str, Any]:
    """Quick analysis of a single HAR file with specific payload"""
    logger = logging.getLogger(__name__)

    har_file = Path(har_path)
    if not har_file.exists():
        raise FileNotFoundError(f"HAR file not found: {har_path}")

    # Create parser
    parser = ArtifactParser()

    # Load HAR entries
    har_entries = parser.load_har(har_path)

    if not har_entries:
        logger.warning(f"No entries found in HAR file: {har_path}")
        return {"error": "No HAR entries found"}

    # Analyze each entry for the payload
    results = []
    for entry in har_entries:
        # Check if payload appears in request or response
        payload_in_request = (payload in entry.request_body or
                            payload in entry.url or
                            payload in str(entry.request_headers))

        payload_in_response = payload in entry.response_body

        if payload_in_request or payload_in_response:
            # Use AI analyzer for transformation analysis
            ai_analysis = parser.payload_analyzer.analyze_payload_transformation(
                payload, entry.response_body
            )

            result = {
                "url": entry.url,
                "method": entry.method,
                "status": entry.response_status,
                "payload_in_request": payload_in_request,
                "payload_in_response": payload_in_response,
                "transformation_analysis": ai_analysis,
                "context_snippet": parser._extract_context_snippet(entry.response_body, payload)
            }
            results.append(result)

    # Save results if output file specified
    if output_file:
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump({
                "har_file": har_path,
                "payload": payload,
                "total_entries": len(har_entries),
                "matching_entries": len(results),
                "results": results
            }, f, indent=2, default=str)

        logger.info(f"HAR analysis saved to {output_file}")

    return {
        "har_file": har_path,
        "payload": payload,
        "total_entries": len(har_entries),
        "matching_entries": len(results),
        "results": results
    }


def print_summary(summary: Dict[str, Any]) -> None:
    """Print analysis summary to console"""
    print("\n=== XSS Artifact Analysis Summary ===")

    if "session_id" in summary:
        print(f"Session ID: {summary['session_id']}")
        print(f"Session Path: {summary['session_path']}")
    elif "run_directory" in summary:
        print(f"Run Directory: {summary['run_directory']}")
    elif "har_file" in summary:
        print(f"HAR File: {summary['har_file']}")
        print(f"Payload: {summary['payload']}")
        print(f"Total HAR Entries: {summary['total_entries']}")
        print(f"Matching Entries: {summary['matching_entries']}")
        return

    print(f"Total Findings: {summary['total_findings']}")
    print(f"Output Directory: {summary['output_directory']}")

    if summary.get('summary_by_outcome'):
        print("\nFindings by Outcome:")
        for outcome, count in summary['summary_by_outcome'].items():
            print(f"  {outcome}: {count}")

    print("\nFiles generated:")
    output_dir = Path(summary['output_directory'])
    print(f"  - {output_dir / 'diagnostics.jsonl'} (machine-readable)")
    print(f"  - {output_dir / 'report.txt'} (human-readable)")


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="XSS Artifact Parser - Analyze HAR files, HTML captures, and replay logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a complete session by ID
  %(prog)s --session 20250913_121921_af130fed

  # Analyze specific run directory
  %(prog)s --run ./logs/20250913_121921_af130fed/ --output ./artifacts/

  # Quick HAR file analysis
  %(prog)s --har proxy_captures/capture_20250916_173713.har --payload "<script>alert('XSS')</script>"

  # Filter diagnostics.jsonl results
  jq 'select(.difference_summary=="stored_escaped")' logs/session_id/artifacts/diagnostics.jsonl

Sample jq queries:
  # Show all successful exploits
  jq 'select(.difference_summary=="stored_raw")' diagnostics.jsonl

  # Show high-confidence findings
  jq 'select(.confidence_score > 0.8)' diagnostics.jsonl

  # Show findings with AI bypass suggestions
  jq 'select(.ai_analysis.bypass_suggestions | length > 0)' diagnostics.jsonl
        """
    )

    # Mutually exclusive groups for different analysis modes
    mode_group = parser.add_mutually_exclusive_group(required=True)

    mode_group.add_argument(
        "--session",
        help="Analyze complete session by session ID (looks in ./logs/<session_id>/)"
    )

    mode_group.add_argument(
        "--run",
        help="Analyze specific run directory path"
    )

    mode_group.add_argument(
        "--har",
        help="Quick analysis of single HAR file (requires --payload)"
    )

    # Optional arguments
    parser.add_argument(
        "--payload",
        help="Payload to search for (required with --har mode)"
    )

    parser.add_argument(
        "--output",
        help="Output directory or file path (default: <input>/artifacts/)"
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )

    parser.add_argument(
        "--logs-dir",
        default="./logs",
        help="Base logs directory (default: ./logs)"
    )

    args = parser.parse_args()

    # Validate arguments
    if args.har and not args.payload:
        parser.error("--payload is required when using --har mode")

    # Setup logging
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)

    try:
        # Execute appropriate analysis mode
        if args.session:
            logger.info(f"Analyzing session: {args.session}")
            summary = analyze_session(args.session, args.output, args.verbose)

        elif args.run:
            logger.info(f"Analyzing run directory: {args.run}")
            summary = analyze_run_directory(args.run, args.output, args.verbose)

        elif args.har:
            logger.info(f"Analyzing HAR file: {args.har} with payload: {args.payload[:50]}...")
            summary = analyze_har_file(args.har, args.payload, args.output)

        # Print summary
        print_summary(summary)

        # Success
        logger.info("Analysis completed successfully")

    except KeyboardInterrupt:
        logger.info("Analysis interrupted by user")
        sys.exit(130)

    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()