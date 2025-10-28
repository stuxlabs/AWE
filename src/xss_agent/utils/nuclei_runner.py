"""
Nuclei runner utilities for XSS detection
"""
import json
import logging
import os
import subprocess
from typing import List
from pathlib import Path

from ..models import NucleiResult


logger = logging.getLogger(__name__)


def run_nuclei_direct(target_url: str, output_file: str) -> bool:
    """Run Nuclei binary directly against target URL"""
    try:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        logger.info(f"Running Nuclei against {target_url}")
        cmd = [
            'nuclei',
            '-u', target_url,
            '-tags', 'xss',
            '-jsonl',
            '-o', output_file,
            '-silent'
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        if result.returncode == 0:
            # Nuclei ran successfully - even if it found nothing
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                logger.info(f"Nuclei completed successfully with findings")
            else:
                logger.info(f"Nuclei completed successfully - no vulnerabilities found")
            return True  # Success means Nuclei ran, not necessarily that it found something
        else:
            logger.error(f"Nuclei failed with return code {result.returncode}")
            if result.stderr:
                logger.error(f"Nuclei stderr: {result.stderr}")
            return False

    except subprocess.TimeoutExpired:
        logger.error("Nuclei scan timeout after 120 seconds")
        return False
    except FileNotFoundError:
        logger.error("Nuclei binary not found. Please ensure Nuclei is installed.")
        return False
    except Exception as e:
        logger.error(f"Unexpected error running Nuclei: {e}")
        return False


def parse_nuclei_results(raw_json_file: str) -> List[NucleiResult]:
    """Parse Nuclei JSON output into structured results"""
    results = []

    try:
        # Check if file exists and has content
        if not os.path.exists(raw_json_file):
            logger.debug(f"Nuclei results file not found (no findings): {raw_json_file}")
            return []

        if os.path.getsize(raw_json_file) == 0:
            logger.debug(f"Nuclei results file is empty (no findings)")
            return []

        with open(raw_json_file, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line.strip())

                    result = NucleiResult(
                        template_id=data.get('template-id', 'unknown'),
                        template_name=data.get('info', {}).get('name', 'Unknown'),
                        severity=data.get('info', {}).get('severity', 'unknown'),
                        description=data.get('info', {}).get('description', 'No description'),
                        matched_url=data.get('matched-at', data.get('host', '')),
                        injection_point=data.get('extracted-results', [None])[0] if data.get('extracted-results') else None,
                        raw_data=data
                    )
                    results.append(result)

                except json.JSONDecodeError:
                    continue

    except Exception as e:
        logger.error(f"Error parsing Nuclei results: {e}")

    return results