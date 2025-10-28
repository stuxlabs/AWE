#!/usr/bin/env python3
"""
Enhanced XSS Agent Runner with Forensic Logging

This script provides an enhanced version of the dynamic XSS agent with comprehensive
forensic logging capabilities, including LLM interactions, HTTP requests/responses,
Playwright verifications, and failure analysis.
"""

import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from dynamic_xss_agent import DynamicXSSOrchestrator
from utils.logging_integration import create_enhanced_orchestrator
from utils.forensic_logger import ForensicLoggerManager


def setup_logging(verbose: bool = False):
    """Setup basic logging configuration"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )


def validate_url(url: str) -> bool:
    """Validate URL format"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


async def main():
    """Main entry point with enhanced forensic logging"""
    
    parser = argparse.ArgumentParser(
        description='Dynamic XSS Verification Agent with Comprehensive Forensic Logging',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan with forensic logging
  python scripts/run_with_logging.py http://target.local/vulnerable.php
  
  # Enable raw LLM response saving with encryption
  export LLM_RAW_KEY="your-encryption-key"
  python scripts/run_with_logging.py --save-raw-llm http://target.local/vulnerable.php
  
  # Use proxy for enhanced network capture
  python scripts/run_with_logging.py --use-proxy --proxy-port 8080 http://target.local/vulnerable.php
  
  # Set custom retention and redaction policies
  python scripts/run_with_logging.py --retention-days 7 --redact-full-bodies http://target.local/vulnerable.php

Security Notes:
  - Raw LLM responses contain unredacted data and require LLM_RAW_KEY environment variable for encryption
  - Proxy capture is limited to whitelisted hosts for security
  - All sensitive headers and credentials are automatically redacted in regular logs
        """
    )
    
    # Target URL
    parser.add_argument(
        'target_url', 
        help='Target URL to test for XSS vulnerabilities'
    )
    
    # Forensic logging options
    parser.add_argument(
        '--save-raw-llm', 
        action='store_true',
        help='Save raw LLM responses (requires LLM_RAW_KEY environment variable for encryption)'
    )
    
    parser.add_argument(
        '--retention-days', 
        type=int, 
        default=30,
        help='Number of days to retain forensic logs (default: 30, 0 = keep forever)'
    )
    
    parser.add_argument(
        '--redact-full-bodies', 
        action='store_true',
        help='Redact full HTTP request/response bodies, keeping only size information'
    )
    
    parser.add_argument(
        '--log-dir', 
        type=str, 
        default='./logs',
        help='Base directory for forensic logs (default: ./logs)'
    )
    
    # Proxy options
    parser.add_argument(
        '--use-proxy', 
        action='store_true',
        help='Enable proxy agent for enhanced network capture and analysis'
    )
    
    parser.add_argument(
        '--proxy-port', 
        type=int, 
        default=8080,
        help='Port for proxy agent (default: 8080)'
    )
    
    parser.add_argument(
        '--proxy-whitelist', 
        nargs='+',
        default=['127.0.0.1', 'localhost'],
        help='Whitelist of allowed hosts for proxy capture (default: localhost only)'
    )
    
    # Output options
    parser.add_argument(
        '--output-file', 
        type=str,
        help='Output file for results (default: auto-generated based on timestamp)'
    )
    
    parser.add_argument(
        '--verbose', 
        action='store_true',
        help='Enable verbose logging output'
    )
    
    # Advanced options
    parser.add_argument(
        '--max-attempts', 
        type=int, 
        default=5,
        help='Maximum payload attempts per vulnerability (default: 5)'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)
    
    # Validate arguments
    if not validate_url(args.target_url):
        logger.error(f"Invalid URL: {args.target_url}")
        sys.exit(1)
    
    # Check LLM raw key if raw saving is enabled
    if args.save_raw_llm:
        raw_key = os.environ.get('LLM_RAW_KEY')
        if not raw_key:
            logger.error(
                "Raw LLM saving enabled but LLM_RAW_KEY environment variable not set!\n"
                "Either:\n"
                "  1. Set LLM_RAW_KEY environment variable with encryption key\n"
                "  2. Remove --save-raw-llm flag\n"
                "\nWARNING: Raw LLM responses may contain sensitive information!"
            )
            sys.exit(1)
        else:
            logger.info("Raw LLM response saving enabled with encryption")
    
    # Validate retention days
    if args.retention_days < 0:
        logger.error("Retention days must be >= 0 (0 = keep forever)")
        sys.exit(1)
    
    # Print configuration summary
    logger.info("=" * 60)
    logger.info("Enhanced XSS Agent with Forensic Logging")
    logger.info("=" * 60)
    logger.info(f"Target URL: {args.target_url}")
    logger.info(f"Log Directory: {args.log_dir}")
    logger.info(f"Save Raw LLM: {args.save_raw_llm}")
    logger.info(f"Retention Days: {args.retention_days} {'(forever)' if args.retention_days == 0 else ''}")
    logger.info(f"Redact Bodies: {args.redact_full_bodies}")
    logger.info(f"Proxy Enabled: {args.use_proxy}")
    if args.use_proxy:
        logger.info(f"Proxy Port: {args.proxy_port}")
        logger.info(f"Proxy Whitelist: {', '.join(args.proxy_whitelist)}")
    logger.info("=" * 60)
    
    try:
        # Create original orchestrator
        original_orchestrator = DynamicXSSOrchestrator(
            use_proxy=args.use_proxy,
            proxy_port=args.proxy_port
        )
        
        # Update proxy whitelist if using proxy
        if args.use_proxy and original_orchestrator.proxy_agent:
            original_orchestrator.proxy_agent.whitelist = args.proxy_whitelist
        
        # Create enhanced orchestrator with forensic logging
        logger.info("Initializing forensic logging system...")
        enhanced_orchestrator = create_enhanced_orchestrator(
            original_orchestrator=original_orchestrator,
            save_raw_llm=args.save_raw_llm,
            retention_days=args.retention_days
        )
        
        # Configure forensic logger
        enhanced_orchestrator.forensic_logger.redact_full_bodies = args.redact_full_bodies
        
        logger.info("Starting XSS verification with forensic logging...")
        
        # Run verification with enhanced logging
        results = await enhanced_orchestrator.verify_xss(args.target_url)
        
        # Generate output filename if not provided
        if not args.output_file:
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            args.output_file = f"xss_results_{timestamp}.json"
        
        # Save results
        enhanced_orchestrator.save_results(results, args.output_file)
        
        # Print summary
        successful = sum(1 for r in results if r.get('successful', False))
        total_attempts = sum(r.get('total_attempts', 0) for r in results)
        
        logger.info("=" * 60)
        logger.info("FORENSIC XSS VERIFICATION SUMMARY")
        logger.info("=" * 60)
        logger.info(f"Vulnerabilities Found: {len(results)}")
        logger.info(f"Successfully Exploited: {successful}")
        logger.info(f"Success Rate: {(successful/len(results)*100):.1f}%" if results else "0%")
        logger.info(f"Total Attempts Made: {total_attempts}")
        logger.info(f"Average Attempts per Vulnerability: {(total_attempts/len(results)):.1f}" if results else "0")
        logger.info("=" * 60)
        logger.info("FORENSIC DATA LOCATIONS:")
        
        # Get forensic summary
        forensic_summary = enhanced_orchestrator.forensic_logger.get_run_summary()
        if forensic_summary:
            logger.info(f"Run Directory: {forensic_summary['run_directory']}")
            logger.info(f"Correlation ID: {forensic_summary['correlation_id']}")
            logger.info(f"LLM Interactions: {forensic_summary['counters']['llm_interactions']}")
            logger.info(f"HTTP Requests: {forensic_summary['counters']['http_requests']}")
            logger.info(f"Playwright Verifications: {forensic_summary['counters']['verifications']}")
            logger.info(f"Payload Attempts: {forensic_summary['counters']['attempts']}")
            
            # File counts
            for key, value in forensic_summary.items():
                if key.endswith('_files'):
                    logger.info(f"{key.replace('_', ' ').title()}: {value}")
        
        logger.info("=" * 60)
        logger.info(f"Results saved to: {args.output_file}")
        
        if args.use_proxy:
            logger.info("Proxy captures included in forensic logs")
        
        logger.info("Forensic logging completed successfully!")
        
    except KeyboardInterrupt:
        logger.warning("\nOperation interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        if args.verbose:
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
        sys.exit(1)
    finally:
        # Cleanup
        try:
            if 'enhanced_orchestrator' in locals():
                enhanced_orchestrator.cleanup()
        except Exception as e:
            logger.warning(f"Cleanup error: {e}")


if __name__ == "__main__":
    # Check for required dependencies
    try:
        import cryptography
        import playwright
        import httpx
    except ImportError as e:
        print(f"Missing required dependency: {e}")
        print("Please install missing dependencies:")
        print("  pip install cryptography playwright httpx")
        sys.exit(1)
    
    asyncio.run(main())