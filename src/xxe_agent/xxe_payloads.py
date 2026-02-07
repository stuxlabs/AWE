"""
XXE Payload Database

NOTE: Static payload databases removed for security purposes.
The framework uses LLM-driven payload generation instead.
See: src/xxe_agent/xxe_llm_generator.py
"""

# Payload templates removed for security purposes
FILE_DISCLOSURE_PAYLOADS = {}
COMMON_FLAG_PATHS = []
SSRF_PAYLOADS = {}


def get_xxe_payload(payload_type: str, file_path: str = "/etc/passwd") -> str:
    """Get XXE payload - delegated to LLM engine"""
    return ""


def get_all_payloads(file_path: str = "/etc/passwd") -> list[str]:
    """Get all XXE payloads - delegated to LLM engine"""
    return []
