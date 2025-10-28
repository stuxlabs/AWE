"""
SQL Context Analyzer

Determines the SQL query context where injection occurs.
Critical for generating appropriate bypass payloads.
"""
import logging
import re
from typing import Optional, Dict, List
from ..models import SQLContext, SQLContextInfo


class SQLContextAnalyzer:
    """Analyzes SQL injection context from responses"""

    # Context detection patterns from error messages
    CONTEXT_PATTERNS = {
        SQLContext.WHERE_CLAUSE: [
            r'WHERE.*syntax error',
            r'in WHERE clause',
            r'WHERE.*invalid',
            r'at or near "WHERE"'
        ],
        SQLContext.ORDER_BY: [
            r'ORDER BY.*syntax error',
            r'in ORDER BY clause',
            r'unknown column.*in.*order clause',
            r'invalid.*ORDER BY',
            r'at or near "ORDER"'
        ],
        SQLContext.LIMIT: [
            r'LIMIT.*syntax error',
            r'in LIMIT clause',
            r'invalid.*LIMIT',
            r'LIMIT.*must be'
        ],
        SQLContext.INSERT_VALUES: [
            r'INSERT.*syntax error',
            r'in VALUES clause',
            r'INSERT INTO.*VALUES',
            r'at or near "INSERT"',
            r'column count'
        ],
        SQLContext.UPDATE_SET: [
            r'UPDATE.*syntax error',
            r'in UPDATE clause',
            r'UPDATE.*SET',
            r'at or near "UPDATE"'
        ],
        SQLContext.SELECT_COLUMN: [
            r'SELECT.*syntax error',
            r'in select list',
            r'unknown column.*in.*field list',
            r'at or near "SELECT"'
        ],
        SQLContext.LIKE_PATTERN: [
            r'LIKE.*syntax error',
            r'in LIKE pattern',
            r'LIKE.*invalid'
        ],
        SQLContext.IN_CLAUSE: [
            r'IN.*syntax error',
            r'in IN clause',
            r'at or near "IN"'
        ]
    }

    # Payloads for detecting quote type
    QUOTE_DETECTION_PAYLOADS = [
        ("'", "single_quote"),
        ('"', "double_quote"),
        ("1", "numeric")
    ]

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)

    def analyze_context_from_error(
        self,
        error_message: str,
        payload: str
    ) -> SQLContextInfo:
        """Analyze SQL context from error message"""

        error_lower = error_message.lower()

        # Detect context from error patterns
        detected_context = SQLContext.UNKNOWN
        matching_patterns = []

        for context, patterns in self.CONTEXT_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, error_message, re.IGNORECASE):
                    detected_context = context
                    matching_patterns.append(pattern)
                    break
            if detected_context != SQLContext.UNKNOWN:
                break

        # Detect quote type from payload and error
        quote_type = self._detect_quote_type(error_message, payload)

        # Detect if closure is needed (e.g., closing parenthesis)
        requires_closure = self._detect_closure_requirement(error_message, payload)

        # Detect query type from error
        query_type = self._detect_query_type(error_message)

        # Calculate confidence
        confidence = 85 if detected_context != SQLContext.UNKNOWN else 30

        reasoning = f"Detected from error: {matching_patterns[0][:50] if matching_patterns else 'heuristic'}"

        return SQLContextInfo(
            context=detected_context,
            confidence=confidence,
            quote_type=quote_type,
            requires_closure=requires_closure,
            detected_query_type=query_type,
            reasoning=reasoning
        )

    def analyze_context_from_behavior(
        self,
        baseline_response: str,
        test_responses: Dict[str, str]
    ) -> SQLContextInfo:
        """Analyze SQL context from response behavior with different payloads"""

        # Test with different quote types
        single_quote_diff = self._calculate_diff(baseline_response, test_responses.get("'", ""))
        double_quote_diff = self._calculate_diff(baseline_response, test_responses.get('"', ""))
        numeric_diff = self._calculate_diff(baseline_response, test_responses.get("1 OR 1=1", ""))

        # Determine quote type based on which caused largest change
        if single_quote_diff > double_quote_diff and single_quote_diff > numeric_diff:
            quote_type = "single_quote"
            confidence = 75
        elif double_quote_diff > single_quote_diff and double_quote_diff > numeric_diff:
            quote_type = "double_quote"
            confidence = 75
        elif numeric_diff > max(single_quote_diff, double_quote_diff):
            quote_type = "numeric"
            confidence = 70
        else:
            quote_type = None
            confidence = 30

        # Detect if ORDER BY context (test with ORDER BY 1)
        order_by_response = test_responses.get("ORDER BY 1", "")
        is_order_by = "syntax" not in order_by_response.lower() and len(order_by_response) > 100

        # Detect if UNION context (test with UNION SELECT)
        union_response = test_responses.get("UNION SELECT NULL", "")
        is_union_compatible = "syntax" not in union_response.lower() and len(union_response) > 100

        # Determine context
        if is_order_by:
            context = SQLContext.ORDER_BY
            confidence = 80
        elif is_union_compatible:
            context = SQLContext.WHERE_CLAUSE
            confidence = 75
        else:
            context = SQLContext.UNKNOWN
            confidence = 40

        return SQLContextInfo(
            context=context,
            confidence=confidence,
            quote_type=quote_type,
            requires_closure=False,  # Hard to detect without errors
            reasoning="Detected from response behavior analysis"
        )

    def detect_column_count(
        self,
        error_messages: List[str]
    ) -> Optional[int]:
        """Detect column count from UNION injection errors"""

        for error in error_messages:
            # MySQL/MariaDB
            match = re.search(r'The used SELECT statements have a different number of columns', error, re.IGNORECASE)
            if match:
                # Try to extract column count hint
                count_match = re.search(r'(\d+)', error)
                if count_match:
                    return int(count_match.group(1))

            # PostgreSQL
            match = re.search(r'each UNION query must have the same number of columns', error, re.IGNORECASE)
            if match:
                return None  # No specific count given

            # Generic column count errors
            match = re.search(r'(\d+)\s+(?:column|value)s?', error, re.IGNORECASE)
            if match:
                return int(match.group(1))

        return None

    def analyze_union_position(
        self,
        response_with_union: str,
        injected_markers: List[str]
    ) -> Optional[int]:
        """Detect which UNION SELECT position is reflected in response"""

        for idx, marker in enumerate(injected_markers, 1):
            if marker in response_with_union:
                self.logger.info(f"UNION position {idx} reflected in response")
                return idx

        return None

    def _detect_quote_type(self, error_message: str, payload: str) -> Optional[str]:
        """Detect quote type from error message"""
        error_lower = error_message.lower()

        # Check for quote-related errors
        if "unterminated string" in error_lower or "quoted string" in error_lower:
            if "'" in payload or "'" in error_message:
                return "single_quote"
            elif '"' in payload or '"' in error_message:
                return "double_quote"

        # Check for syntax errors with quotes
        if re.search(r"near\s+['\"]", error_message):
            match = re.search(r"near\s+(['\"])", error_message)
            if match:
                quote_char = match.group(1)
                return "single_quote" if quote_char == "'" else "double_quote"

        # If numeric payload works, might be numeric context
        if payload.strip().isdigit() and "syntax" not in error_lower:
            return "numeric"

        return None

    def _detect_closure_requirement(self, error_message: str, payload: str) -> bool:
        """Detect if parenthesis closure is needed"""
        error_lower = error_message.lower()

        # Check for unclosed parenthesis errors
        if any(pattern in error_lower for pattern in [
            "unclosed", "expected ')'", "missing )",
            "unbalanced parenthesis", "right parenthesis"
        ]):
            return True

        # Check if error mentions unmatched quotes
        if "unmatched" in error_lower or "unclosed" in error_lower:
            return True

        return False

    def _detect_query_type(self, error_message: str) -> Optional[str]:
        """Detect SQL query type from error"""
        error_upper = error_message.upper()

        query_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'REPLACE']

        for keyword in query_keywords:
            if keyword in error_upper:
                return keyword

        return None

    def _calculate_diff(self, text1: str, text2: str) -> int:
        """Calculate difference between two text strings"""
        return abs(len(text1) - len(text2))
