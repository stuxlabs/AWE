"""
IDOR Context Analyzer - Understands application structure and access patterns
"""
from dataclasses import dataclass
from typing import List, Dict, Optional, Set
from enum import Enum
import re
from urllib.parse import urlparse, parse_qs


class IDFormat(Enum):
    """Format of object identifiers"""
    NUMERIC = "numeric"  # 1, 2, 3, 123
    UUID = "uuid"  # a1b2c3d4-...
    HASH = "hash"  # md5, sha1, etc
    BASE64 = "base64"  # encoded strings
    USERNAME = "username"  # john, admin, etc
    EMAIL = "email"  # user@example.com
    CUSTOM = "custom"  # custom format
    UNKNOWN = "unknown"


class ObjectType(Enum):
    """Type of objects being accessed"""
    USER = "user"  # User profiles, accounts
    ORDER = "order"  # Orders, purchases
    FILE = "file"  # Files, documents
    MESSAGE = "message"  # Messages, emails
    POST = "post"  # Posts, articles
    TRANSACTION = "transaction"  # Financial transactions
    RESOURCE = "resource"  # Generic resources
    UNKNOWN = "unknown"


@dataclass
class IDOREndpoint:
    """An endpoint that may be vulnerable to IDOR"""
    url: str
    method: str  # GET, POST, PUT, DELETE
    id_parameter: str  # Which parameter contains the ID
    id_value: str  # Current ID value
    id_format: IDFormat
    object_type: ObjectType
    requires_auth: bool
    response_size: int
    response_indicators: List[str]  # Indicators of successful access


@dataclass
class ApplicationContext:
    """Understanding of the application structure"""
    endpoints: List[IDOREndpoint]
    id_patterns: Dict[str, IDFormat]  # parameter_name -> format
    object_types: Dict[str, ObjectType]  # parameter_name -> object type
    auth_mechanism: str  # cookie, jwt, header, etc
    auth_value: Optional[str]  # Current auth token/cookie
    user_indicators: List[str]  # Patterns that indicate user-specific data


class IDORContextAnalyzer:
    """Analyzes application to understand IDOR attack surface"""

    def __init__(self):
        # Common ID parameter names
        self.id_params = [
            'id', 'user_id', 'userId', 'uid', 'account_id', 'accountId',
            'order_id', 'orderId', 'file_id', 'fileId', 'doc_id', 'docId',
            'message_id', 'messageId', 'post_id', 'postId', 'item_id', 'itemId',
            'resource_id', 'resourceId', 'object_id', 'objectId',
            'username', 'user', 'account', 'profile', 'email'
        ]

        # Patterns for different ID formats
        self.id_patterns = {
            IDFormat.NUMERIC: r'^\d+$',
            IDFormat.UUID: r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$',
            IDFormat.HASH: r'^[a-f0-9]{32,64}$',
            IDFormat.BASE64: r'^[A-Za-z0-9+/]+=*$',
            IDFormat.EMAIL: r'^[^@]+@[^@]+\.[^@]+$',
        }

    def analyze_endpoint(
        self,
        url: str,
        method: str,
        parameters: Dict[str, str],
        response: str,
        response_size: int,
        auth_header: Optional[str] = None
    ) -> Optional[IDOREndpoint]:
        """
        Analyze an endpoint to see if it's vulnerable to IDOR

        Args:
            url: Endpoint URL
            method: HTTP method
            parameters: Query/body parameters
            response: Response body
            response_size: Response size
            auth_header: Authentication header if present

        Returns:
            IDOREndpoint if this looks like an IDOR target, None otherwise
        """

        # Check if any parameters look like IDs
        for param_name, param_value in parameters.items():
            if self._is_id_parameter(param_name, param_value):
                # Identify ID format
                id_format = self._identify_id_format(param_value)

                # Identify object type
                object_type = self._identify_object_type(param_name, url, response)

                # Extract response indicators
                indicators = self._extract_response_indicators(response, param_value)

                # Check if requires auth
                requires_auth = auth_header is not None

                return IDOREndpoint(
                    url=url,
                    method=method,
                    id_parameter=param_name,
                    id_value=param_value,
                    id_format=id_format,
                    object_type=object_type,
                    requires_auth=requires_auth,
                    response_size=response_size,
                    response_indicators=indicators
                )

        return None

    def _is_id_parameter(self, param_name: str, param_value: str) -> bool:
        """Check if parameter looks like an ID"""

        # Check parameter name
        param_lower = param_name.lower()
        if any(id_param in param_lower for id_param in self.id_params):
            return True

        # Check value format
        if re.match(self.id_patterns[IDFormat.NUMERIC], param_value):
            return True
        if re.match(self.id_patterns[IDFormat.UUID], param_value):
            return True
        if re.match(self.id_patterns[IDFormat.HASH], param_value):
            return True

        return False

    def _identify_id_format(self, id_value: str) -> IDFormat:
        """Identify the format of an ID"""

        for format_type, pattern in self.id_patterns.items():
            if re.match(pattern, id_value, re.IGNORECASE):
                return format_type

        # Check for username pattern (alphanumeric, no special chars)
        if re.match(r'^[a-zA-Z0-9_-]+$', id_value):
            return IDFormat.USERNAME

        return IDFormat.CUSTOM

    def _identify_object_type(self, param_name: str, url: str, response: str) -> ObjectType:
        """Identify what type of object is being accessed"""

        # Check parameter name and URL
        combined = (param_name + url).lower()

        if any(keyword in combined for keyword in ['user', 'account', 'profile', 'member']):
            return ObjectType.USER
        elif any(keyword in combined for keyword in ['order', 'purchase', 'cart']):
            return ObjectType.ORDER
        elif any(keyword in combined for keyword in ['file', 'document', 'doc', 'download']):
            return ObjectType.FILE
        elif any(keyword in combined for keyword in ['message', 'mail', 'email', 'chat']):
            return ObjectType.MESSAGE
        elif any(keyword in combined for keyword in ['post', 'article', 'blog']):
            return ObjectType.POST
        elif any(keyword in combined for keyword in ['transaction', 'payment', 'invoice']):
            return ObjectType.TRANSACTION

        # Check response content
        response_lower = response.lower()
        if any(keyword in response_lower for keyword in ['username', 'email', 'profile']):
            return ObjectType.USER

        return ObjectType.RESOURCE

    def _extract_response_indicators(self, response: str, id_value: str) -> List[str]:
        """Extract indicators that show successful object access"""

        indicators = []

        # Look for the ID in response
        if id_value in response:
            indicators.append(f"id_reflected:{id_value}")

        # Look for common success indicators
        success_patterns = [
            (r'"status"\s*:\s*"success"', "status:success"),
            (r'"status"\s*:\s*200', "status:200"),
            (r'"data"\s*:', "has_data_field"),
            (r'<title>.*?Profile.*?</title>', "profile_title"),
            (r'"username"\s*:', "has_username"),
            (r'"email"\s*:', "has_email"),
            (r'"order_id"\s*:', "has_order"),
        ]

        for pattern, indicator in success_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                indicators.append(indicator)

        return indicators

    def build_application_context(
        self,
        endpoints: List[IDOREndpoint],
        auth_header: Optional[str] = None
    ) -> ApplicationContext:
        """
        Build a comprehensive understanding of the application

        Args:
            endpoints: List of discovered IDOR endpoints
            auth_header: Authentication header

        Returns:
            ApplicationContext
        """

        # Extract ID patterns
        id_patterns = {}
        for endpoint in endpoints:
            id_patterns[endpoint.id_parameter] = endpoint.id_format

        # Extract object types
        object_types = {}
        for endpoint in endpoints:
            object_types[endpoint.id_parameter] = endpoint.object_type

        # Detect auth mechanism
        auth_mechanism = "unknown"
        auth_value = None

        if auth_header:
            if auth_header.startswith("Bearer "):
                auth_mechanism = "jwt"
                auth_value = auth_header[7:]
            elif "=" in auth_header:
                auth_mechanism = "cookie"
                auth_value = auth_header
            else:
                auth_mechanism = "custom"
                auth_value = auth_header

        # Extract user indicators from all responses
        user_indicators = set()
        for endpoint in endpoints:
            user_indicators.update(endpoint.response_indicators)

        return ApplicationContext(
            endpoints=endpoints,
            id_patterns=id_patterns,
            object_types=object_types,
            auth_mechanism=auth_mechanism,
            auth_value=auth_value,
            user_indicators=list(user_indicators)
        )

    def suggest_test_ids(self, current_id: str, id_format: IDFormat, count: int = 10) -> List[str]:
        """
        Suggest alternative IDs to test for IDOR

        Args:
            current_id: Current ID value
            id_format: Format of the ID
            count: Number of alternatives to generate

        Returns:
            List of alternative IDs to test
        """

        alternatives = []

        if id_format == IDFormat.NUMERIC:
            current = int(current_id)
            # Try nearby IDs
            alternatives.extend([str(current - 1), str(current + 1)])
            # Try sequential IDs
            alternatives.extend([str(i) for i in range(1, min(count, 20))])
            # Try common IDs
            alternatives.extend(['0', '1', '100', '1000'])

        elif id_format == IDFormat.USERNAME:
            # Try common usernames
            alternatives.extend([
                'admin', 'administrator', 'root', 'user', 'test',
                'demo', 'guest', 'moderator', 'support'
            ])

        elif id_format == IDFormat.EMAIL:
            # Try common emails
            alternatives.extend([
                'admin@localhost', 'admin@example.com', 'user@localhost',
                'test@test.com', 'root@localhost'
            ])

        elif id_format == IDFormat.UUID:
            # Try null/zero UUIDs
            alternatives.extend([
                '00000000-0000-0000-0000-000000000000',
                '11111111-1111-1111-1111-111111111111',
            ])

        # Remove duplicates and current ID
        alternatives = [alt for alt in alternatives if alt != current_id]
        return list(dict.fromkeys(alternatives))[:count]
