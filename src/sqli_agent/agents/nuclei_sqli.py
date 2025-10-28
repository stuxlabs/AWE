"""
Nuclei SQL Injection Scanner

Leverages Nuclei's extensive SQLi template collection for initial discovery.
Runs before database/LLM phases to quickly identify known vulnerabilities.
"""
import json
import logging
import os
import subprocess
from typing import List, Dict, Optional
from pathlib import Path


class NucleiSQLiScanner:
    """
    Runs Nuclei with SQLi templates to detect known SQL injection patterns.

    Nuclei has 100+ SQLi templates covering:
    - Error-based SQLi
    - Time-based blind SQLi
    - Boolean-based blind SQLi
    - UNION-based SQLi
    - Stacked queries
    - Second-order SQLi
    - NoSQL injection
    - Framework-specific SQLi (WordPress, Joomla, etc.)
    """

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.output_dir = Path("nuclei_sqli_results")
        self.output_dir.mkdir(exist_ok=True)

        # Ensure Nuclei templates are available
        self._ensure_templates()

    async def scan(self, target_url: str, severity: str = "info") -> Dict:
        """
        Run Nuclei SQLi scan against target.

        Args:
            target_url: Target URL to scan
            severity: Minimum severity level (info, low, medium, high, critical)

        Returns:
            Dict with scan results:
            {
                'vulnerable': bool,
                'findings': List[Dict],
                'payloads': List[str],
                'total_templates': int,
                'execution_time': float
            }
        """
        self.logger.info(f"Starting Nuclei SQLi scan on {target_url}")

        output_file = self.output_dir / "nuclei_sqli_scan.jsonl"

        # Run Nuclei
        success = self._run_nuclei(target_url, str(output_file), severity)

        if not success:
            self.logger.warning("Nuclei scan failed or found nothing")
            return {
                'vulnerable': False,
                'findings': [],
                'payloads': [],
                'total_templates': 0,
                'execution_time': 0.0
            }

        # Parse results
        findings = self._parse_results(str(output_file))

        # Extract payloads for further testing
        payloads = self._extract_payloads(findings)

        vulnerable = len(findings) > 0

        if vulnerable:
            self.logger.info(f"✓ Nuclei found {len(findings)} SQLi vulnerabilities!")
            for finding in findings[:5]:
                self.logger.info(f"  - {finding['template_name']} (severity: {finding['severity']})")
        else:
            self.logger.info("Nuclei did not detect any SQLi vulnerabilities")

        return {
            'vulnerable': vulnerable,
            'findings': findings,
            'payloads': payloads,
            'total_templates': len(findings),
            'execution_time': 0.0  # TODO: track execution time
        }

    def _run_nuclei(self, target_url: str, output_file: str, severity: str) -> bool:
        """
        Execute Nuclei with SQLi templates.

        Returns:
            True if scan completed successfully, False otherwise
        """
        try:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)

            # Nuclei command with SQLi-specific tags
            cmd = [
                'nuclei',
                '-u', target_url,
                '-tags', 'sqli,sql,injection',  # SQLi-related tags
                '-severity', severity,
                '-jsonl',
                '-o', output_file,
                '-silent',
                '-rate-limit', '10',  # Limit to 10 requests/sec to avoid detection
                '-timeout', '15'      # 15 second timeout per request
            ]

            self.logger.debug(f"Running: {' '.join(cmd)}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180  # 3 minute timeout
            )

            # Log Nuclei output for debugging
            if result.stdout:
                self.logger.debug(f"Nuclei stdout: {result.stdout[:500]}")
            if result.stderr:
                self.logger.debug(f"Nuclei stderr: {result.stderr[:500]}")

            # Nuclei returns 1 when no vulnerabilities found, which is normal
            # We only care if the output file has results
            if result.returncode in [0, 1]:
                # Check if output file exists and has content
                if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                    self.logger.debug(f"Nuclei scan completed with findings")
                    return True
                else:
                    self.logger.info("Nuclei completed but found no vulnerabilities")
                    return False
            else:
                self.logger.error(f"Nuclei failed with return code {result.returncode}")
                if result.stderr:
                    self.logger.error(f"Error: {result.stderr[:200]}")
                return False

        except subprocess.TimeoutExpired:
            self.logger.error("Nuclei scan timeout after 180 seconds")
            return False
        except FileNotFoundError:
            self.logger.error("Nuclei binary not found - make sure it's installed")
            return False
        except Exception as e:
            self.logger.error(f"Error running Nuclei: {e}")
            return False

    def _parse_results(self, output_file: str) -> List[Dict]:
        """
        Parse Nuclei JSONL output into structured findings.

        Returns:
            List of finding dictionaries
        """
        findings = []

        try:
            with open(output_file, 'r') as f:
                for line in f:
                    if not line.strip():
                        continue

                    try:
                        data = json.loads(line.strip())

                        # Extract key information
                        finding = {
                            'template_id': data.get('template-id', 'unknown'),
                            'template_name': data.get('info', {}).get('name', 'Unknown SQLi'),
                            'severity': data.get('info', {}).get('severity', 'unknown'),
                            'description': data.get('info', {}).get('description', ''),
                            'matched_url': data.get('matched-at', data.get('host', '')),
                            'type': data.get('type', 'http'),
                            'extracted_results': data.get('extracted-results', []),
                            'curl_command': data.get('curl-command', ''),
                            'request': data.get('request', ''),
                            'response': data.get('response', ''),
                            'matcher_name': data.get('matcher-name', ''),
                            'timestamp': data.get('timestamp', ''),
                            'raw_data': data
                        }

                        findings.append(finding)

                    except json.JSONDecodeError as e:
                        self.logger.debug(f"Failed to parse JSON line: {e}")
                        continue

        except FileNotFoundError:
            self.logger.error(f"Results file not found: {output_file}")
        except Exception as e:
            self.logger.error(f"Error parsing Nuclei results: {e}")

        return findings

    def _extract_payloads(self, findings: List[Dict]) -> List[str]:
        """
        Extract SQL injection payloads from Nuclei findings.

        Tries to extract actual payloads from:
        - extracted-results
        - curl-command
        - request data
        - matcher patterns

        Returns:
            List of extracted payloads
        """
        payloads = set()

        for finding in findings:
            # Method 1: Extracted results
            extracted = finding.get('extracted_results', [])
            if extracted:
                payloads.update(extracted)

            # Method 2: Parse from curl command
            curl_cmd = finding.get('curl_command', '')
            if curl_cmd:
                # Extract from query parameters
                if '?' in curl_cmd:
                    query_part = curl_cmd.split('?', 1)[1]
                    if ' ' in query_part:
                        query_part = query_part.split(' ', 1)[0]

                    # Parse query parameters
                    for param in query_part.split('&'):
                        if '=' in param:
                            value = param.split('=', 1)[1]
                            # Check if it looks like SQLi
                            if any(sql_kw in value.lower() for sql_kw in ['or', 'and', 'union', 'select', 'sleep', "'", '"', '--']):
                                # URL decode
                                import urllib.parse
                                decoded = urllib.parse.unquote(value)
                                payloads.add(decoded)

            # Method 3: Parse from request
            request = finding.get('request', '')
            if request and ('GET' in request or 'POST' in request):
                # Extract from first line (usually contains query params)
                lines = request.split('\n')
                if lines:
                    first_line = lines[0]
                    if '?' in first_line:
                        query_part = first_line.split('?', 1)[1].split(' ')[0]
                        for param in query_part.split('&'):
                            if '=' in param:
                                value = param.split('=', 1)[1]
                                if any(sql_kw in value.lower() for sql_kw in ['or', 'and', 'union', 'select', 'sleep', "'", '"']):
                                    import urllib.parse
                                    decoded = urllib.parse.unquote(value)
                                    payloads.add(decoded)

        payloads_list = list(payloads)
        self.logger.info(f"Extracted {len(payloads_list)} unique payloads from Nuclei findings")

        return payloads_list[:50]  # Limit to top 50

    def get_summary(self, scan_result: Dict) -> str:
        """
        Generate human-readable summary of scan results.

        Args:
            scan_result: Result dict from scan()

        Returns:
            Formatted summary string
        """
        findings = scan_result['findings']

        if not findings:
            return "No SQLi vulnerabilities detected by Nuclei"

        summary = []
        summary.append(f"\n{'='*80}")
        summary.append(f"NUCLEI SQLi SCAN RESULTS")
        summary.append(f"{'='*80}\n")
        summary.append(f"Total Findings: {len(findings)}")

        # Group by severity
        by_severity = {}
        for f in findings:
            sev = f['severity']
            by_severity[sev] = by_severity.get(sev, 0) + 1

        summary.append("\nBy Severity:")
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            count = by_severity.get(sev, 0)
            if count > 0:
                summary.append(f"  {sev.upper()}: {count}")

        summary.append(f"\nTop Findings:")
        for i, finding in enumerate(findings[:10], 1):
            summary.append(f"  [{i}] {finding['template_name']}")
            summary.append(f"      Severity: {finding['severity'].upper()}")
            summary.append(f"      URL: {finding['matched_url'][:70]}")

        if scan_result['payloads']:
            summary.append(f"\nExtracted {len(scan_result['payloads'])} payloads for further testing")

        summary.append(f"\n{'='*80}\n")

        return '\n'.join(summary)

    def _ensure_templates(self):
        """
        Ensure Nuclei templates are downloaded and up-to-date.

        Nuclei needs templates to run scans. This checks if templates exist
        and updates them if needed.
        """
        try:
            # Check if Nuclei is installed
            check_cmd = ['nuclei', '-version']
            result = subprocess.run(
                check_cmd,
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                self.logger.warning("Nuclei not installed or not in PATH")
                return

            # Check if templates directory exists
            # Nuclei stores templates in ~/.nuclei-templates by default
            home = Path.home()
            templates_dir = home / '.nuclei-templates'

            if not templates_dir.exists():
                self.logger.info("Nuclei templates not found - downloading...")
                self._update_templates()
            else:
                # Check if templates are old (update once per day)
                import time
                template_age = time.time() - templates_dir.stat().st_mtime
                if template_age > 86400:  # 24 hours
                    self.logger.info("Nuclei templates are old - updating...")
                    self._update_templates()
                else:
                    self.logger.debug("Nuclei templates are up-to-date")

        except Exception as e:
            self.logger.warning(f"Could not check Nuclei templates: {e}")

    def _update_templates(self):
        """Update Nuclei templates"""
        try:
            update_cmd = ['nuclei', '-update-templates', '-silent']
            result = subprocess.run(
                update_cmd,
                capture_output=True,
                text=True,
                timeout=120  # 2 minute timeout for template download
            )

            if result.returncode == 0:
                self.logger.info("Nuclei templates updated successfully")
            else:
                self.logger.warning(f"Template update returned code {result.returncode}")

        except subprocess.TimeoutExpired:
            self.logger.warning("Template update timeout - continuing anyway")
        except Exception as e:
            self.logger.warning(f"Could not update templates: {e}")
