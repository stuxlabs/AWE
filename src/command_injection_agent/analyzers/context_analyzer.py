"""
Command Injection Context Analyzer - Detects WHERE command injection occurs
"""
from dataclasses import dataclass
from typing import List, Optional
from enum import Enum
import re


class CommandContext(Enum):
    """Command injection contexts"""
    SHELL_ARGUMENT = "shell_argument"  # As argument: command ARG
    SHELL_QUOTED_SINGLE = "shell_quoted_single"  # Inside single quotes: 'HERE'
    SHELL_QUOTED_DOUBLE = "shell_quoted_double"  # Inside double quotes: "HERE"
    SHELL_VARIABLE = "shell_variable"  # As variable: $HERE
    SHELL_COMMAND_SUB = "shell_command_sub"  # In command substitution: $(HERE)
    SHELL_BACKTICKS = "shell_backticks"  # In backticks: `HERE`
    SHELL_PIPE = "shell_pipe"  # After pipe: | HERE
    SHELL_REDIRECT = "shell_redirect"  # In redirect: > HERE
    CODE_EVAL = "code_eval"  # In eval(): eval("HERE")
    CODE_SYSTEM = "code_system"  # In system(): system("HERE")
    CODE_EXEC = "code_exec"  # In exec(): exec("HERE")
    UNKNOWN = "unknown"


@dataclass
class CommandReflection:
    """A detected command injection reflection point"""
    context: CommandContext
    position: int
    context_before: str
    context_after: str
    in_quotes: bool
    quote_type: Optional[str]  # 'single', 'double', None
    command_prefix: str  # The command being executed (if detectable)
    os_type: str  # 'linux', 'windows', 'unknown'
    breakout_needed: str  # What's needed to break out


class CMDContextAnalyzer:
    """Analyzes WHERE command injection occurs and its context"""

    def __init__(self):
        # Patterns to detect command execution context
        self.exec_patterns = [
            (r'exec\s*\([^)]*', 'code_exec'),
            (r'system\s*\([^)]*', 'code_system'),
            (r'eval\s*\([^)]*', 'code_eval'),
            (r'popen\s*\([^)]*', 'code_system'),
            (r'subprocess\.[^(]+\([^)]*', 'code_system'),
            (r'\$\([^)]*', 'shell_command_sub'),
            (r'`[^`]*', 'shell_backticks'),
        ]

        # OS detection patterns
        self.os_indicators = {
            'linux': ['/bin/', '/usr/', '/etc/', '/home/', '/var/', 'bash', 'sh', 'cat', 'ls'],
            'windows': ['cmd.exe', 'powershell', 'C:\\', 'dir', 'type', 'ping'],
        }

    def find_reflections(
        self,
        response_text: str,
        canary: str,
        error_output: Optional[str] = None
    ) -> List[CommandReflection]:
        """
        Find WHERE the canary appears in command execution context

        Args:
            response_text: Response body
            canary: Unique canary string that was injected
            error_output: Any error messages (may reveal context)

        Returns:
            List of CommandReflection objects
        """
        reflections = []

        # Search in both response and error output
        search_texts = [('response', response_text)]
        if error_output:
            search_texts.append(('error', error_output))

        for source, text in search_texts:
            # Find all occurrences of canary
            for match in re.finditer(re.escape(canary), text):
                position = match.start()

                # Get context around reflection
                context_start = max(0, position - 150)
                context_end = min(len(text), position + len(canary) + 150)

                before = text[context_start:position]
                after = text[position + len(canary):context_end]

                # Analyze context
                context_type = self._identify_context(text, position, before, after)
                in_quotes, quote_type = self._check_if_in_quotes(before, after)
                command_prefix = self._extract_command_prefix(before)
                os_type = self._detect_os(text, before, after)
                breakout = self._determine_breakout(context_type, in_quotes, quote_type, os_type)

                reflections.append(CommandReflection(
                    context=context_type,
                    position=position,
                    context_before=before[-80:] if len(before) > 80 else before,
                    context_after=after[:80] if len(after) > 80 else after,
                    in_quotes=in_quotes,
                    quote_type=quote_type,
                    command_prefix=command_prefix,
                    os_type=os_type,
                    breakout_needed=breakout
                ))

        return reflections

    def _identify_context(
        self,
        full_text: str,
        position: int,
        before: str,
        after: str
    ) -> CommandContext:
        """Identify what type of command context the injection is in"""

        # Check for code execution contexts
        for pattern, context_name in self.exec_patterns:
            # Look backward to find if we're inside this pattern
            window_start = max(0, position - 300)
            window = full_text[window_start:position + 50]

            if re.search(pattern, window):
                if context_name == 'code_exec':
                    return CommandContext.CODE_EXEC
                elif context_name == 'code_system':
                    return CommandContext.CODE_SYSTEM
                elif context_name == 'code_eval':
                    return CommandContext.CODE_EVAL
                elif context_name == 'shell_command_sub':
                    return CommandContext.SHELL_COMMAND_SUB
                elif context_name == 'shell_backticks':
                    return CommandContext.SHELL_BACKTICKS

        # Check for shell contexts
        if '|' in before[-20:]:
            return CommandContext.SHELL_PIPE
        elif '>' in before[-10:] or '>>' in before[-10:]:
            return CommandContext.SHELL_REDIRECT
        elif '$' in before[-5:]:
            return CommandContext.SHELL_VARIABLE

        # Check quotes
        in_quotes, quote_type = self._check_if_in_quotes(before, after)
        if in_quotes:
            if quote_type == 'single':
                return CommandContext.SHELL_QUOTED_SINGLE
            elif quote_type == 'double':
                return CommandContext.SHELL_QUOTED_DOUBLE

        # Default: shell argument
        return CommandContext.SHELL_ARGUMENT

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

    def _extract_command_prefix(self, before: str) -> str:
        """Extract the command being executed"""

        # Look for common command patterns
        commands = ['ping', 'curl', 'wget', 'cat', 'echo', 'ls', 'dir', 'find', 'grep']

        # Search in the context before
        for cmd in commands:
            if cmd in before.lower()[-50:]:
                return cmd

        return "unknown"

    def _detect_os(self, full_text: str, before: str, after: str) -> str:
        """Detect the operating system"""

        # Check combined context
        context = (before + after).lower()

        linux_score = sum(1 for indicator in self.os_indicators['linux'] if indicator in context)
        windows_score = sum(1 for indicator in self.os_indicators['windows'] if indicator in context)

        if linux_score > windows_score:
            return 'linux'
        elif windows_score > linux_score:
            return 'windows'
        else:
            return 'unknown'

    def _determine_breakout(
        self,
        context: CommandContext,
        in_quotes: bool,
        quote_type: Optional[str],
        os_type: str
    ) -> str:
        """Determine what's needed to break out of current context"""

        breakout_parts = []

        # First, break out of quotes if needed
        if in_quotes:
            if quote_type == 'single':
                breakout_parts.append("'")
            elif quote_type == 'double':
                breakout_parts.append('"')

        # Then, handle command context
        if context == CommandContext.SHELL_ARGUMENT:
            # Can directly inject separators
            if os_type == 'windows':
                breakout_parts.append('&' if not breakout_parts else ' & ')
            else:
                breakout_parts.append(';' if not breakout_parts else ' ; ')

        elif context in [CommandContext.SHELL_QUOTED_SINGLE, CommandContext.SHELL_QUOTED_DOUBLE]:
            # Need to close quotes and add separator
            if os_type == 'windows':
                breakout_parts.append(' & ')
            else:
                breakout_parts.append(' ; ')

        elif context == CommandContext.SHELL_COMMAND_SUB:
            breakout_parts.append(')')  # Close command substitution

        elif context == CommandContext.SHELL_BACKTICKS:
            breakout_parts.append('`')  # Close backticks

        elif context in [CommandContext.CODE_EVAL, CommandContext.CODE_EXEC, CommandContext.CODE_SYSTEM]:
            # In code context, need to break out of string first
            if not in_quotes:
                breakout_parts.append('"')  # Assume double quotes
            breakout_parts.append(';' if os_type == 'linux' else '&')

        return ''.join(breakout_parts) if breakout_parts else "none"
