"""
Nuclei-related data models
"""
from dataclasses import dataclass
from typing import Dict, Any, Optional


@dataclass
class NucleiResult:
    """Represents a single Nuclei finding"""
    template_id: str
    template_name: str
    severity: str
    description: str
    matched_url: str
    injection_point: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None