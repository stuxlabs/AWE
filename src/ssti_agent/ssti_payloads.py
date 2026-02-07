"""
SSTI Payload Database and Mutation Engine

NOTE: Static payload databases removed for security purposes.
The framework uses LLM-driven payload generation instead.
See: src/ssti_agent/analyzers/llm_ssti_engine.py
"""
from typing import List, Dict
from enum import Enum


class SSTIPayloadCategory(Enum):
    """Categories of SSTI payloads"""
    DETECTION = "detection"
    JINJA2 = "jinja2"
    DJANGO = "django"
    TWIG = "twig"
    FREEMARKER = "freemarker"
    VELOCITY = "velocity"
    SMARTY = "smarty"
    MAKO = "mako"
    ERB = "erb"
    THYMELEAF = "thymeleaf"
    SPRING = "spring"


# Payload database removed for security purposes
SSTI_PAYLOAD_DB = {category: [] for category in SSTIPayloadCategory}


class SSTIPayloadMutator:
    """Mutator for SSTI payloads - delegated to LLM engine"""

    def __init__(self):
        pass

    def get_payloads(self, category: SSTIPayloadCategory) -> List[str]:
        """Get payloads - delegated to LLM engine"""
        return []

    def mutate(self, payload: str) -> List[str]:
        """Mutate payload - delegated to LLM engine"""
        return []

    def get_all_payloads(self) -> List[Dict]:
        """Get all payloads - delegated to LLM engine"""
        return []
