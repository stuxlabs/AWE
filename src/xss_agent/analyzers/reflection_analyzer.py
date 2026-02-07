"""
Reflection Analyzer - Finds where user input is reflected in responses
Critical component for context-aware XSS detection
"""

import re
import logging
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import html
import urllib.parse

logger = logging.getLogger(__name__)


class ReflectionContext(Enum):
    """Types of contexts where input can be reflected"""
    HTML_BODY = "html_body"
    HTML_ATTRIBUTE = "html_attribute"
    HTML_ATTRIBUTE_QUOTED = "html_attribute_quoted"
    HTML_ATTRIBUTE_UNQUOTED = "html_attribute_unquoted"
    JS_STRING_SINGLE = "js_string_single"
    JS_STRING_DOUBLE = "js_string_double"
    JS_STRING_TEMPLATE = "js_string_template"
    JS_CODE = "js_code"
    HTML_COMMENT = "html_comment"
    JS_COMMENT = "js_comment"
    CSS_CONTEXT = "css_context"
    URL_CONTEXT = "url_context"
    JSON_CONTEXT = "json_context"
    UNKNOWN = "unknown"


class EncodingType(Enum):
    """Types of encoding that can be applied"""
    NONE = "none"
    HTML_ENTITY = "html_entity"
    URL_ENCODE = "url_encode"
    JS_ENCODE = "js_encode"
    BASE64 = "base64"
    UNICODE = "unicode"
    PARTIAL_ENCODING = "partial"


@dataclass
class ReflectionPoint:
    """Represents a location where user input is reflected"""
    position: int
    context: ReflectionContext
    context_before: str  # 100 chars before reflection
    context_after: str   # 100 chars after reflection
    encoding_applied: List[EncodingType]
    reflected_value: str
    original_value: str
    tag_name: Optional[str] = None
    attribute_name: Optional[str] = None
    quote_char: Optional[str] = None
    breakout_sequence: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "position": self.position,
            "context": self.context.value,
            "context_before": self.context_before,
            "context_after": self.context_after,
            "encoding": [e.value for e in self.encoding_applied],
            "reflected_value": self.reflected_value,
            "original_value": self.original_value,
            "tag_name": self.tag_name,
            "attribute_name": self.attribute_name,
            "quote_char": self.quote_char,
            "breakout_sequence": self.breakout_sequence
        }


class ReflectionAnalyzer:
    """
    Analyzes HTTP responses to find where and how user input is reflected

    This is the foundation for context-aware XSS detection
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def find_reflections(self,
                        response_text: str,
                        canary: str,
                        check_encoded: bool = True) -> List[ReflectionPoint]:
        """
        Find all locations where the canary is reflected in the response

        Args:
            response_text: The HTTP response body
            canary: The unique marker to search for
            check_encoded: Also check for encoded versions

        Returns:
            List of ReflectionPoint objects
        """
        reflections = []

        # Find exact matches
        exact_matches = self._find_all_occurrences(response_text, canary)
        for pos in exact_matches:
            context = self._analyze_context(response_text, pos, len(canary))
            reflection = self._create_reflection_point(
                response_text, pos, len(canary), canary, canary, context
            )
            reflections.append(reflection)
            self.logger.info(f"Found reflection at position {pos}, context: {context.value}")

        if check_encoded:
            # Check for HTML entity encoded
            html_encoded = html.escape(canary)
            if html_encoded != canary:
                for pos in self._find_all_occurrences(response_text, html_encoded):
                    context = self._analyze_context(response_text, pos, len(html_encoded))
                    reflection = self._create_reflection_point(
                        response_text, pos, len(html_encoded),
                        html_encoded, canary, context,
                        encoding=[EncodingType.HTML_ENTITY]
                    )
                    reflections.append(reflection)
                    self.logger.info(f"Found HTML-encoded reflection at {pos}")

            # Check for URL encoded
            url_encoded = urllib.parse.quote(canary)
            if url_encoded != canary:
                for pos in self._find_all_occurrences(response_text, url_encoded):
                    context = self._analyze_context(response_text, pos, len(url_encoded))
                    reflection = self._create_reflection_point(
                        response_text, pos, len(url_encoded),
                        url_encoded, canary, context,
                        encoding=[EncodingType.URL_ENCODE]
                    )
                    reflections.append(reflection)
                    self.logger.info(f"Found URL-encoded reflection at {pos}")

            # Check for JS encoded
            js_encoded = self._js_encode(canary)
            if js_encoded != canary:
                for pos in self._find_all_occurrences(response_text, js_encoded):
                    context = self._analyze_context(response_text, pos, len(js_encoded))
                    reflection = self._create_reflection_point(
                        response_text, pos, len(js_encoded),
                        js_encoded, canary, context,
                        encoding=[EncodingType.JS_ENCODE]
                    )
                    reflections.append(reflection)
                    self.logger.info(f"Found JS-encoded reflection at {pos}")

        self.logger.info(f"Total reflections found: {len(reflections)}")
        return reflections

    def _find_all_occurrences(self, text: str, substring: str) -> List[int]:
        """Find all positions where substring occurs in text"""
        positions = []
        start = 0
        while True:
            pos = text.find(substring, start)
            if pos == -1:
                break
            positions.append(pos)
            start = pos + 1
        return positions

    def _analyze_context(self, text: str, position: int, length: int) -> ReflectionContext:
        """
        Determine the context of the reflection

        This is the core intelligence - understanding WHERE the input landed
        """
        before = text[max(0, position-200):position]
        after = text[position+length:min(len(text), position+length+200)]

        # Check if inside script tag
        if self._is_inside_tag(before, after, 'script'):
            # Inside <script>, determine if in string or code
            return self._analyze_js_context(before, after)

        # Check if inside style tag
        if self._is_inside_tag(before, after, 'style'):
            return ReflectionContext.CSS_CONTEXT

        # Check if inside HTML comment
        if '<!--' in before and '-->' not in before:
            return ReflectionContext.HTML_COMMENT

        # Check if inside JS comment
        if '//' in before and '\n' not in before:
            return ReflectionContext.JS_COMMENT
        if '/*' in before and '*/' not in before:
            return ReflectionContext.JS_COMMENT

        # Check if inside HTML attribute
        attr_context = self._analyze_attribute_context(before, after)
        if attr_context != ReflectionContext.UNKNOWN:
            return attr_context

        # Check if inside URL
        if self._is_url_context(before, after):
            return ReflectionContext.URL_CONTEXT

        # Check if JSON
        if self._is_json_context(before, after):
            return ReflectionContext.JSON_CONTEXT

        # Default to HTML body
        return ReflectionContext.HTML_BODY

    def _is_inside_tag(self, before: str, after: str, tag: str) -> bool:
        """Check if position is inside a specific HTML tag"""
        open_tag = f'<{tag}'
        close_tag = f'</{tag}>'

        # Look for opening tag before and closing tag after
        last_open = before.rfind(open_tag)
        last_close = before.rfind(close_tag)
        next_close = after.find(close_tag)

        return last_open > last_close and next_close != -1

    def _analyze_js_context(self, before: str, after: str) -> ReflectionContext:
        """Analyze JavaScript context - string vs code"""
        # Count quotes before reflection point
        single_quotes = before.count("'") - before.count("\\'")
        double_quotes = before.count('"') - before.count('\\"')
        backticks = before.count('`') - before.count('\\`')

        # Check if inside single-quoted string
        if single_quotes % 2 == 1:
            return ReflectionContext.JS_STRING_SINGLE

        # Check if inside double-quoted string
        if double_quotes % 2 == 1:
            return ReflectionContext.JS_STRING_DOUBLE

        # Check if inside template literal
        if backticks % 2 == 1:
            return ReflectionContext.JS_STRING_TEMPLATE

        # In JS code context
        return ReflectionContext.JS_CODE

    def _analyze_attribute_context(self, before: str, after: str) -> ReflectionContext:
        """Analyze if reflection is inside an HTML attribute"""
        # Look for tag opening before reflection
        last_open_bracket = before.rfind('<')
        last_close_bracket = before.rfind('>')

        # Not in a tag if > came after <
        if last_close_bracket > last_open_bracket:
            return ReflectionContext.UNKNOWN

        # We're inside a tag, check if in attribute
        after_open = before[last_open_bracket:]

        # Check for = before reflection (indicates attribute)
        if '=' not in after_open:
            return ReflectionContext.UNKNOWN

        last_equals = after_open.rfind('=')
        after_equals = after_open[last_equals+1:].lstrip()

        # Determine quote type
        if after_equals.startswith('"'):
            return ReflectionContext.HTML_ATTRIBUTE_QUOTED
        elif after_equals.startswith("'"):
            return ReflectionContext.HTML_ATTRIBUTE_QUOTED
        else:
            return ReflectionContext.HTML_ATTRIBUTE_UNQUOTED

    def _is_url_context(self, before: str, after: str) -> bool:
        """Check if reflection is in URL context"""
        url_indicators = ['href=', 'src=', 'action=', 'data=', 'formaction=']
        return any(indicator in before[-50:] for indicator in url_indicators)

    def _is_json_context(self, before: str, after: str) -> bool:
        """Check if reflection is in JSON context"""
        # Look for JSON patterns
        json_patterns = [r'"\s*:\s*"', r'{\s*"', r',\s*"']
        combined = before[-50:] + after[:50]
        return any(re.search(pattern, combined) for pattern in json_patterns)

    def _create_reflection_point(self,
                                 text: str,
                                 position: int,
                                 length: int,
                                 reflected_value: str,
                                 original_value: str,
                                 context: ReflectionContext,
                                 encoding: Optional[List[EncodingType]] = None) -> ReflectionPoint:
        """Create a ReflectionPoint object with full context analysis"""

        before = text[max(0, position-100):position]
        after = text[position+length:min(len(text), position+length+100)]

        # Detect encoding if not provided
        if encoding is None:
            encoding = self._detect_encoding(original_value, reflected_value)

        # Extract tag and attribute info for HTML contexts
        tag_name, attribute_name, quote_char = None, None, None
        if context in [ReflectionContext.HTML_ATTRIBUTE_QUOTED,
                       ReflectionContext.HTML_ATTRIBUTE_UNQUOTED]:
            tag_name = self._extract_tag_name(before)
            attribute_name = self._extract_attribute_name(before)
            quote_char = self._extract_quote_char(before)

        # Determine breakout sequence needed
        breakout = self._determine_breakout_sequence(context, quote_char)

        return ReflectionPoint(
            position=position,
            context=context,
            context_before=before,
            context_after=after,
            encoding_applied=encoding,
            reflected_value=reflected_value,
            original_value=original_value,
            tag_name=tag_name,
            attribute_name=attribute_name,
            quote_char=quote_char,
            breakout_sequence=breakout
        )

    def _detect_encoding(self, original: str, reflected: str) -> List[EncodingType]:
        """Detect what encoding was applied"""
        encodings = []

        if original == reflected:
            return [EncodingType.NONE]

        if html.escape(original) == reflected:
            encodings.append(EncodingType.HTML_ENTITY)

        if urllib.parse.quote(original) == reflected:
            encodings.append(EncodingType.URL_ENCODE)

        if self._js_encode(original) == reflected:
            encodings.append(EncodingType.JS_ENCODE)

        # Check for partial encoding
        if not encodings and original != reflected:
            encodings.append(EncodingType.PARTIAL_ENCODING)

        return encodings if encodings else [EncodingType.NONE]

    def _extract_tag_name(self, before: str) -> Optional[str]:
        """Extract the HTML tag name"""
        match = re.search(r'<(\w+)[>\s]', before)
        return match.group(1) if match else None

    def _extract_attribute_name(self, before: str) -> Optional[str]:
        """Extract the attribute name"""
        match = re.search(r'(\w+)\s*=\s*["\']?$', before)
        return match.group(1) if match else None

    def _extract_quote_char(self, before: str) -> Optional[str]:
        """Extract the quote character used in attribute"""
        if before.endswith('"'):
            return '"'
        elif before.endswith("'"):
            return "'"
        return None

    def _determine_breakout_sequence(self,
                                    context: ReflectionContext,
                                    quote_char: Optional[str]) -> str:
        """Determine what sequence is needed to break out of context"""

        if context == ReflectionContext.HTML_BODY:
            return ""  # No breakout needed

        elif context == ReflectionContext.HTML_ATTRIBUTE_QUOTED:
            return f"{quote_char}>"

        elif context == ReflectionContext.HTML_ATTRIBUTE_UNQUOTED:
            return ">"

        elif context == ReflectionContext.JS_STRING_SINGLE:
            return "';"

        elif context == ReflectionContext.JS_STRING_DOUBLE:
            return '";;'

        elif context == ReflectionContext.JS_STRING_TEMPLATE:
            return "`;"

        elif context == ReflectionContext.HTML_COMMENT:
            return "-->"

        elif context == ReflectionContext.JS_COMMENT:
            return "\n" or "*/"

        return ""

    def _js_encode(self, text: str) -> str:
        """JavaScript string encoding"""
        return text.replace('\\', '\\\\').replace('"', '\\"').replace("'", "\\'")

    def generate_report(self, reflections: List[ReflectionPoint]) -> Dict:
        """Generate a comprehensive report of all reflections"""
        return {
            "total_reflections": len(reflections),
            "contexts": {
                context.value: len([r for r in reflections if r.context == context])
                for context in ReflectionContext
            },
            "reflections": [r.to_dict() for r in reflections]
        }
