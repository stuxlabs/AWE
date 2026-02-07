"""
Command Injection Payload Database

NOTE: Static payload databases removed for security purposes.
The framework uses LLM-driven payload generation instead.
See: src/command_injection_agent/analyzers/llm_cmd_engine.py
"""

# Payload lists removed for security purposes
CMD_INJECTION_PAYLOADS = []
BLIND_PAYLOADS = []
PING_CONTEXT_PAYLOADS = []


def mutate_payload(base_payload: str, base_value: str = "") -> list[str]:
    """Generate mutations of a payload - delegated to LLM engine"""
    return []


def get_flag_extraction_payloads(base_value: str = "") -> list[str]:
    """Get payloads for extracting flags - delegated to LLM engine"""
    return []
