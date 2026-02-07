"""
Detects command injection vulnerabilities
"""
from dataclasses import dataclass
from typing import List, Optional, Tuple
from enum import Enum
import time
import re

from .cmd_payloads import get_flag_extraction_payloads as get_flag_payloads_db, mutate_payload


class InjectionTechnique(Enum):
    """Command injection techniques"""
    SEMICOLON = "Semicolon separator (;)"
    PIPE = "Pipe (|)"
    AND = "AND operator (&&)"
    OR = "OR operator (||)"
    AMPERSAND = "Background (&)"
    BACKTICKS = "Backticks (`)"
    COMMAND_SUB = "Command substitution $()"
    NEWLINE = "Newline (\\n)"


@dataclass
class CMDInjectionProbe:
    """A command injection probe"""
    payload: str
    technique: InjectionTechnique
    detection_method: str  # 'output', 'timing', 'error'
    expected_marker: Optional[str]
    sleep_time: Optional[float]
    description: str


@dataclass
class CMDInjectionResult:
    """Result of command injection test"""
    vulnerable: bool
    technique: InjectionTechnique
    payload: str
    evidence: str
    response_time: float
    response_excerpt: str


class CMDInjectionDetector:
    """Detects command injection vulnerabilities"""

    def __init__(self):
        self.marker = "CMD1NJ3CT10N"

    def get_probes(self, parameter_value: str = "test") -> List[CMDInjectionProbe]:
        """
        Generate command injection probes

        Args:
            parameter_value: Original parameter value to preserve functionality

        Returns:
            List of command injection probes
        """
        marker = self.marker

        probes = [
            # Output-based detection with semicolon
            CMDInjectionProbe(
                payload=f"{parameter_value};echo {marker}",
                technique=InjectionTechnique.SEMICOLON,
                detection_method="output",
                expected_marker=marker,
                sleep_time=None,
                description="Echo marker after command"
            ),

            # Output-based with pipe
            CMDInjectionProbe(
                payload=f"{parameter_value}|echo {marker}",
                technique=InjectionTechnique.PIPE,
                detection_method="output",
                expected_marker=marker,
                sleep_time=None,
                description="Pipe to echo"
            ),

            # Output-based with AND
            CMDInjectionProbe(
                payload=f"{parameter_value}&&echo {marker}",
                technique=InjectionTechnique.AND,
                detection_method="output",
                expected_marker=marker,
                sleep_time=None,
                description="AND with echo"
            ),

            # Output-based with OR
            CMDInjectionProbe(
                payload=f"invalid||echo {marker}",
                technique=InjectionTechnique.OR,
                detection_method="output",
                expected_marker=marker,
                sleep_time=None,
                description="OR with echo after invalid command"
            ),

            # Backticks
            CMDInjectionProbe(
                payload=f"{parameter_value}`echo {marker}`",
                technique=InjectionTechnique.BACKTICKS,
                detection_method="output",
                expected_marker=marker,
                sleep_time=None,
                description="Backtick command substitution"
            ),

            # Command substitution
            CMDInjectionProbe(
                payload=f"{parameter_value}$(echo {marker})",
                technique=InjectionTechnique.COMMAND_SUB,
                detection_method="output",
                expected_marker=marker,
                sleep_time=None,
                description="Dollar-paren command substitution"
            ),

            # Timing-based with semicolon
            CMDInjectionProbe(
                payload=f"{parameter_value};sleep 3",
                technique=InjectionTechnique.SEMICOLON,
                detection_method="timing",
                expected_marker=None,
                sleep_time=3.0,
                description="Sleep 3 seconds"
            ),

            # Timing-based with AND
            CMDInjectionProbe(
                payload=f"{parameter_value}&&sleep 3",
                technique=InjectionTechnique.AND,
                detection_method="timing",
                expected_marker=None,
                sleep_time=3.0,
                description="AND sleep 3 seconds"
            ),

            # Command output - whoami
            CMDInjectionProbe(
                payload=f"{parameter_value};whoami",
                technique=InjectionTechnique.SEMICOLON,
                detection_method="output",
                expected_marker=None,  # Look for typical usernames
                sleep_time=None,
                description="Execute whoami"
            ),

            # Command output - id
            CMDInjectionProbe(
                payload=f"{parameter_value};id",
                technique=InjectionTechnique.SEMICOLON,
                detection_method="output",
                expected_marker=None,  # Look for uid=
                sleep_time=None,
                description="Execute id"
            ),
        ]

        return probes

    def get_flag_extraction_payloads(self, parameter_value: str = "test") -> List[str]:
        """
        Get payloads specifically for flag extraction

        Args:
            parameter_value: Original parameter value

        Returns:
            List of flag extraction payloads
        """
        # Use comprehensive payload database (50+ payloads with mutations)
        return get_flag_payloads_db(parameter_value)

    def analyze_response(
        self,
        probe: CMDInjectionProbe,
        response_text: str,
        response_time: float
    ) -> CMDInjectionResult:
        """
        Analyze response to determine if command injection succeeded

        Args:
            probe: The probe that was used
            response_text: Response body
            response_time: Response time in seconds

        Returns:
            CMDInjectionResult
        """

        vulnerable = False
        evidence = ""

        if probe.detection_method == "output":
            if probe.expected_marker:
                # Look for our marker
                if probe.expected_marker in response_text:
                    vulnerable = True
                    evidence = f"Marker '{probe.expected_marker}' found in response"
            else:
                # Look for command output patterns
                if "whoami" in probe.payload.lower():
                    # Look for typical usernames
                    if any(user in response_text.lower() for user in ['root', 'www-data', 'nginx', 'apache', 'admin', 'user']):
                        vulnerable = True
                        evidence = "Possible username in response"
                elif "id" in probe.payload.lower():
                    # Look for uid= pattern
                    if re.search(r'uid=\d+', response_text):
                        vulnerable = True
                        evidence = "uid= pattern found in response"

        elif probe.detection_method == "timing":
            if probe.sleep_time:
                # Check if response time is close to sleep time
                if response_time >= (probe.sleep_time * 0.8):  # 80% threshold
                    vulnerable = True
                    evidence = f"Response time ({response_time:.2f}s) matches sleep time ({probe.sleep_time}s)"

        return CMDInjectionResult(
            vulnerable=vulnerable,
            technique=probe.technique,
            payload=probe.payload,
            evidence=evidence,
            response_time=response_time,
            response_excerpt=response_text[:500]
        )

    def check_flag_in_response(self, response_text: str) -> Optional[str]:
        """
        Check if flag is present in response

        Args:
            response_text: Response body

        Returns:
            Flag string if found, None otherwise
        """
        # Look for common flag formats
        flag_patterns = [
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
