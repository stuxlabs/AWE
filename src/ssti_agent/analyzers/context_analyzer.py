"""
SSTI Context Analyzer - Detects WHERE template injection occurs
"""
from dataclasses import dataclass
from typing import List, Optional
from enum import Enum
import re


class TemplateContext(Enum):
    """Template injection contexts"""
    TEMPLATE_BODY = "template_body"  # Directly in template: {{ HERE }}
    TEMPLATE_STRING = "template_string"  # Inside string: {{"string with HERE"}}
    TEMPLATE_FILTER = "template_filter"  # In filter: {{value|filter:HERE}}
    TEMPLATE_EXPRESSION = "template_expression"  # In expression: {{1 + HERE}}
    TEMPLATE_BLOCK = "template_block"  # In block: {% block HERE %}
    TEMPLATE_COMMENT = "template_comment"  # In comment: {# HERE #}
    TEMPLATE_VARIABLE = "template_variable"  # As variable name: {{HERE}}
    UNKNOWN = "unknown"


@dataclass
class TemplateReflection:
    """A detected template reflection point"""
    context: TemplateContext
    position: int
    context_before: str
    context_after: str
    in_quotes: bool
    quote_type: Optional[str]  # 'single', 'double', None
    surrounding_syntax: str  # e.g., "{{ }}", "{% %}", "{# #}"
    breakout_needed: str  # What's needed to break out of current context


class SSTIContextAnalyzer:
    """Analyzes WHERE template injection occurs and its context"""

    def __init__(self):
        # Template syntax patterns for different engines
        self.template_patterns = [
            (r'\{\{.*?\}\}', 'jinja2/twig/django'),  # {{ }}
            (r'\{%.*?%\}', 'jinja2/django'),  # {% %}
            (r'\{#.*?#\}', 'jinja2/twig'),  # {# #}
            (r'<\$.*?\$>', 'mako'),  # <$ $>
            (r'\$\{.*?\}', 'freemarker/velocity/mako'),  # ${ }
            (r'<%.*?%>', 'erb/jsp'),  # <% %>
            (r'\[\[.*?\]\]', 'thymeleaf'),  # [[ ]]
        ]

    def find_reflections(
        self,
        response_text: str,
        canary: str
    ) -> List[TemplateReflection]:
        """
        Find WHERE the canary is reflected in the template

        Args:
            response_text: HTML/template response
            canary: Unique canary string that was injected

        Returns:
            List of TemplateReflection objects
        """
        reflections = []

        # Find all occurrences of canary
        for match in re.finditer(re.escape(canary), response_text):
            position = match.start()

            # Get context around reflection
            context_start = max(0, position - 100)
            context_end = min(len(response_text), position + len(canary) + 100)

            before = response_text[context_start:position]
            after = response_text[position + len(canary):context_end]

            # Analyze context
            context_type = self._identify_context(response_text, position, before, after)
            in_quotes, quote_type = self._check_if_in_quotes(before, after)
            surrounding = self._identify_surrounding_syntax(before, after)
            breakout = self._determine_breakout(context_type, in_quotes, quote_type, surrounding)

            reflections.append(TemplateReflection(
                context=context_type,
                position=position,
                context_before=before[-50:] if len(before) > 50 else before,
                context_after=after[:50] if len(after) > 50 else after,
                in_quotes=in_quotes,
                quote_type=quote_type,
                surrounding_syntax=surrounding,
                breakout_needed=breakout
            ))

        return reflections

    def _identify_context(
        self,
        full_text: str,
        position: int,
        before: str,
        after: str
    ) -> TemplateContext:
        """Identify what type of template context the injection is in"""

        # Check if inside template syntax
        for pattern, engine in self.template_patterns:
            # Expand search window to catch full syntax
            window_start = max(0, position - 200)
            window_end = min(len(full_text), position + 200)
            window = full_text[window_start:window_end]

            for match in re.finditer(pattern, window):
                # Check if our position is inside this template syntax
                match_start = window_start + match.start()
                match_end = window_start + match.end()

                if match_start <= position <= match_end:
                    # We're inside template syntax
                    template_content = match.group(0)

                    # Check specific context within template
                    if re.match(r'\{\{', template_content):
                        if '|' in template_content:
                            return TemplateContext.TEMPLATE_FILTER
                        elif any(op in template_content for op in ['+', '-', '*', '/', '%']):
                            return TemplateContext.TEMPLATE_EXPRESSION
                        else:
                            return TemplateContext.TEMPLATE_VARIABLE
                    elif re.match(r'\{%', template_content):
                        return TemplateContext.TEMPLATE_BLOCK
                    elif re.match(r'\{#', template_content):
                        return TemplateContext.TEMPLATE_COMMENT

        # Check if in HTML context (outside template syntax)
        # This could be reflected in normal HTML, which might still be processed as template
        return TemplateContext.TEMPLATE_BODY

    def _check_if_in_quotes(self, before: str, after: str) -> tuple[bool, Optional[str]]:
        """Check if reflection is inside quotes"""

        # Count quotes before reflection
        single_before = before.count("'") - before.count("\\'")
        double_before = before.count('"') - before.count('\\"')

        # Odd count means we're inside quotes
        if single_before % 2 == 1:
            return True, 'single'
        elif double_before % 2 == 1:
            return True, 'double'

        return False, None

    def _identify_surrounding_syntax(self, before: str, after: str) -> str:
        """Identify the template syntax surrounding the injection"""

        # Look for template delimiters
        syntax_patterns = [
            ('{{', '}}'),  # Jinja2/Twig/Django
            ('{%', '%}'),  # Jinja2/Django blocks
            ('{#', '#}'),  # Jinja2/Twig comments
            ('${', '}'),   # Freemarker/Velocity/Mako
            ('<%', '%>'),  # ERB/JSP
            ('[[', ']]'),  # Thymeleaf
        ]

        for open_delim, close_delim in syntax_patterns:
            if open_delim in before and close_delim in after:
                return f"{open_delim} {close_delim}"

        return "none"

    def _determine_breakout(
        self,
        context: TemplateContext,
        in_quotes: bool,
        quote_type: Optional[str],
        surrounding: str
    ) -> str:
        """Determine what's needed to break out of current context"""

        breakout = ""

        # First, break out of quotes if needed
        if in_quotes:
            if quote_type == 'single':
                breakout += "'"
            elif quote_type == 'double':
                breakout += '"'

        # Then, handle template syntax
        if context == TemplateContext.TEMPLATE_BODY:
            # Need to inject template syntax
            breakout += "{{" if not surrounding else ""
        elif context in [TemplateContext.TEMPLATE_VARIABLE, TemplateContext.TEMPLATE_EXPRESSION]:
            # Already in template, might need to close and reopen
            if "{{" in surrounding and "}}" in surrounding:
                breakout += "}}"  # Close current, will inject new
        elif context == TemplateContext.TEMPLATE_FILTER:
            # In filter context, need to break out of filter
            breakout += "}}"
        elif context == TemplateContext.TEMPLATE_BLOCK:
            breakout += "%}"
        elif context == TemplateContext.TEMPLATE_COMMENT:
            breakout += "#}"

        return breakout if breakout else "none"
