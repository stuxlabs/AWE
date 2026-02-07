"""
Detects information disclosure vulnerabilities
"""
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple
import re
import base64
from urllib.parse import urljoin, urlparse


@dataclass
class DisclosurePattern:
    """A pattern to detect information disclosure"""
    name: str
    pattern: str
    category: str
    severity: str
    description: str


@dataclass
class DisclosureResult:
    """Result of information disclosure scan"""
    found: bool
    findings: List[Dict[str, str]]
    total_score: float


class InfoDisclosureDetector:
    """Detects information disclosure vulnerabilities"""

    # Sensitive information patterns
    PATTERNS = [
        # Flags (highest priority)
        DisclosurePattern(
            name="CTF Flag",
            pattern=r'(FLAG|flag|CTF|ctf)\{[^}]{10,}\}',
            category="flag",
            severity="critical",
            description="CTF flag found in response"
        ),

        # API Keys and Tokens
        DisclosurePattern(
            name="AWS Access Key",
            pattern=r'AKIA[0-9A-Z]{16}',
            category="credentials",
            severity="high",
            description="AWS access key ID"
        ),
        DisclosurePattern(
            name="AWS Secret Key",
            pattern=r"aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]",
            category="credentials",
            severity="high",
            description="AWS secret access key"
        ),
        DisclosurePattern(
            name="Generic API Key",
            pattern=r"(api[_-]?key|apikey|api[_-]?token)[\s:=]+['\"]?[a-zA-Z0-9_\-]{20,}['\"]?",
            category="credentials",
            severity="high",
            description="Generic API key"
        ),
        DisclosurePattern(
            name="JWT Token",
            pattern=r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
            category="credentials",
            severity="medium",
            description="JWT token"
        ),

        # Database Credentials
        DisclosurePattern(
            name="Database Connection String",
            pattern=r'(mysql|postgresql|mongodb|redis)://[^:]+:[^@]+@[^/]+',
            category="credentials",
            severity="high",
            description="Database connection string with credentials"
        ),
        DisclosurePattern(
            name="Password in Config",
            pattern=r"(password|passwd|pwd)[\s:=]+['\"]([^'\"\s]{6,})['\"]",
            category="credentials",
            severity="high",
            description="Password in configuration"
        ),

        # SSH Credentials
        DisclosurePattern(
            name="SSH Username",
            pattern=r"(username|user)[\s:=]+['\"]?([a-zA-Z0-9_-]+)['\"]?",
            category="ssh_credentials",
            severity="high",
            description="SSH/system username found"
        ),
        DisclosurePattern(
            name="Base64 Password",
            pattern=r"base64[._]?decode\s*\(['\"]([A-Za-z0-9+/=]+)['\"]",
            category="ssh_credentials",
            severity="critical",
            description="Base64 encoded password found"
        ),
        DisclosurePattern(
            name="Paramiko SSH",
            pattern=r"paramiko|client\.connect\s*\(",
            category="ssh_credentials",
            severity="medium",
            description="SSH/Paramiko connection code found"
        ),

        # Private Keys
        DisclosurePattern(
            name="Private Key",
            pattern=r'-----BEGIN (RSA |DSA )?PRIVATE KEY-----',
            category="credentials",
            severity="critical",
            description="Private key disclosed"
        ),

        # Source Code
        DisclosurePattern(
            name="PHP Source Code",
            pattern=r'<\?php',
            category="source_code",
            severity="medium",
            description="PHP source code visible"
        ),
        DisclosurePattern(
            name="Python Source Code",
            pattern=r'(import\s+\w+|from\s+\w+\s+import|def\s+\w+\s*\()',
            category="source_code",
            severity="low",
            description="Python source code visible"
        ),

        # Directory Listings
        DisclosurePattern(
            name="Directory Listing",
            pattern=r'Index of /|<title>Index of|Directory listing for',
            category="directory",
            severity="medium",
            description="Directory listing enabled"
        ),

        # Error Messages
        DisclosurePattern(
            name="SQL Error",
            pattern=r'(SQL syntax.*MySQL|Warning.*mysql_|MySQLSyntaxErrorException|PostgreSQL.*ERROR|SQLite.*error)',
            category="error",
            severity="medium",
            description="SQL error message"
        ),
        DisclosurePattern(
            name="Stack Trace",
            pattern=r'(Traceback \(most recent call last\)|at \w+\.\w+\([^)]+\.java:\d+\)|Fatal error:.*in /)',
            category="error",
            severity="medium",
            description="Stack trace disclosed"
        ),

        # Version Information
        DisclosurePattern(
            name="PHP Version",
            pattern=r'PHP/\d+\.\d+\.\d+',
            category="version",
            severity="low",
            description="PHP version disclosed"
        ),
        DisclosurePattern(
            name="Server Version",
            pattern=r'(Apache/\d+\.\d+\.\d+|nginx/\d+\.\d+\.\d+)',
            category="version",
            severity="low",
            description="Web server version disclosed"
        ),

        # Sensitive Files
        DisclosurePattern(
            name="/etc/passwd",
            pattern=r'root:.*:0:0:|daemon:.*:|www-data:.*:',
            category="sensitive_file",
            severity="critical",
            description="/etc/passwd file disclosed"
        ),
        DisclosurePattern(
            name="Environment Variables",
            pattern=r'(PATH|HOME|USER)=/|HTTP_HOST=',
            category="sensitive_file",
            severity="medium",
            description="Environment variables disclosed"
        ),

        # Internal IP Addresses
        DisclosurePattern(
            name="Internal IP",
            pattern=r'(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})',
            category="network",
            severity="low",
            description="Internal IP address disclosed"
        ),
    ]

    # Common sensitive file paths to check
    SENSITIVE_PATHS = [
        "/.env",
        "/.git/config",
        "/.git/HEAD",
        "/config.php",
        "/config.json",
        "/config.yml",
        "/database.yml",
        "/.DS_Store",
        "/phpinfo.php",
        "/info.php",
        "/test.php",
        "/backup.zip",
        "/backup.tar.gz",
        "/db_backup.sql",
        "/.htaccess",
        "/web.config",
        "/.aws/credentials",
        "/id_rsa",
        "/id_rsa.pub",
        "/.ssh/id_rsa",
        "/flag.txt",
        "/flag",
        "/robots.txt",
        "/.well-known/security.txt",
    ]

    def __init__(self):
        # Compile patterns for efficiency
        self.compiled_patterns = [
            (p, re.compile(p.pattern, re.IGNORECASE | re.MULTILINE))
            for p in self.PATTERNS
        ]

    def scan_response(self, response_text: str, response_headers: Dict[str, str] = None) -> DisclosureResult:
        """
        Scan response for information disclosure

        Args:
            response_text: Response body
            response_headers: Response headers (optional)

        Returns:
            DisclosureResult with findings
        """
        findings = []
        total_score = 0.0

        # Severity scores
        severity_scores = {
            "critical": 10.0,
            "high": 7.0,
            "medium": 4.0,
            "low": 1.0,
        }

        # Scan response body
        for pattern_obj, compiled_pattern in self.compiled_patterns:
            matches = compiled_pattern.finditer(response_text)

            for match in matches:
                matched_text = match.group(0)

                findings.append({
                    "name": pattern_obj.name,
                    "category": pattern_obj.category,
                    "severity": pattern_obj.severity,
                    "description": pattern_obj.description,
                    "matched_text": matched_text[:100],  # Truncate long matches
                    "position": match.start()
                })

                total_score += severity_scores.get(pattern_obj.severity, 0)

                # If we found a flag, that's the most important finding
                if pattern_obj.category == "flag":
                    total_score += 100  # Boost score significantly

        # Scan headers if provided
        if response_headers:
            for header, value in response_headers.items():
                header_lower = header.lower()

                # Check for server version disclosure
                if header_lower == "server":
                    findings.append({
                        "name": "Server Header",
                        "category": "version",
                        "severity": "low",
                        "description": f"Server header discloses: {value}",
                        "matched_text": value,
                        "position": -1
                    })
                    total_score += 1.0

                # Check for sensitive info in headers
                if header_lower == "x-powered-by":
                    findings.append({
                        "name": "X-Powered-By Header",
                        "category": "version",
                        "severity": "low",
                        "description": f"Technology disclosed: {value}",
                        "matched_text": value,
                        "position": -1
                    })
                    total_score += 1.0

        return DisclosureResult(
            found=len(findings) > 0,
            findings=findings,
            total_score=total_score
        )

    def get_sensitive_paths(self, base_url: str) -> List[str]:
        """
        Get list of sensitive file URLs to check

        Args:
            base_url: Base URL of the target

        Returns:
            List of full URLs to sensitive files
        """
        return [urljoin(base_url, path) for path in self.SENSITIVE_PATHS]

    def check_flag(self, response_text: str) -> Optional[str]:
        """
        Extract flag from response

        Args:
            response_text: Response body

        Returns:
            Flag string if found, None otherwise
        """
        flag_patterns = [
            r'(FLAG|flag|CTF|ctf)\{[^}]+\}',
        ]

        for pattern in flag_patterns:
            match = re.search(pattern, response_text)
            if match:
                return match.group(0)

        return None

    def extract_ssh_credentials(self, response_text: str) -> Optional[Dict[str, str]]:
        """
        Extract SSH credentials from source code or response

        Looks for patterns like:
        - client.connect(hostname, username='user', password='pass')
        - username = 'user' / password = 'pass'
        - base64.b64decode('encoded_password')

        Args:
            response_text: Response body (likely source code)

        Returns:
            Dict with 'username', 'password', 'host' if found, None otherwise
        """
        credentials = {}

        # Pattern 1: Paramiko-style client.connect()
        # client.connect(host, username='user', password=base64.b64decode('..').decode())
        connect_pattern = r"client\.connect\s*\(\s*['\"]?([^'\"]+)['\"]?\s*,\s*username\s*=\s*['\"]([^'\"]+)['\"]"
        connect_match = re.search(connect_pattern, response_text)
        if connect_match:
            credentials['host'] = connect_match.group(1)
            credentials['username'] = connect_match.group(2)

        # Pattern 2: Direct username/password assignment
        user_patterns = [
            r"username\s*=\s*['\"]([^'\"]+)['\"]",
            r"user\s*=\s*['\"]([^'\"]+)['\"]",
            r"ssh_user\s*=\s*['\"]([^'\"]+)['\"]",
        ]
        for pattern in user_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match and 'username' not in credentials:
                credentials['username'] = match.group(1)
                break

        # Pattern 3: Base64-encoded password (common CTF pattern)
        # base64.b64decode('QUhlYXZ5U2FuZGJhZyE=') or base64.b64decode(b'...')
        # Also handles: base64.b64decode(b'...').decode('utf-8') + '!'
        b64_pattern = r"base64\.b64decode\s*\(\s*b?['\"]([A-Za-z0-9+/=]+)['\"]\s*\)(?:\.decode\([^)]*\))?\s*(?:\+\s*['\"]([^'\"]+)['\"])?"
        b64_match = re.search(b64_pattern, response_text)
        if b64_match:
            try:
                encoded = b64_match.group(1)
                decoded = base64.b64decode(encoded).decode('utf-8')
                # Check for suffix like + '!'
                suffix = b64_match.group(2) if b64_match.lastindex >= 2 and b64_match.group(2) else ''
                credentials['password'] = decoded + suffix
                credentials['password_encoded'] = encoded
            except Exception:
                pass

        # Pattern 4: Direct password assignment
        pass_patterns = [
            r"password\s*=\s*['\"]([^'\"]+)['\"]",
            r"passwd\s*=\s*['\"]([^'\"]+)['\"]",
            r"ssh_pass\s*=\s*['\"]([^'\"]+)['\"]",
        ]
        for pattern in pass_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match and 'password' not in credentials:
                credentials['password'] = match.group(1)
                break

        # Pattern 5: SSH host from code
        host_patterns = [
            r"ssh_host\s*=\s*['\"]([^'\"]+)['\"]",
            r"hostname\s*=\s*['\"]([^'\"]+)['\"]",
            r"host\s*=\s*['\"]([^'\"]+)['\"]",
        ]
        for pattern in host_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match and 'host' not in credentials:
                credentials['host'] = match.group(1)
                break

        # Only return if we have at least username and password
        if credentials.get('username') and credentials.get('password'):
            return credentials

        return None
