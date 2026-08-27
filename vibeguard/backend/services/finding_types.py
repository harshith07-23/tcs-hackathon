"""
Internal, tool-agnostic finding representation.

All scanners (semgrep, bandit, secret scanner, dependency scanner, custom
pattern rules) normalize their output into RawFinding before it reaches the
risk engine or database.
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class RawFinding:
    title: str
    category: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    confidence: int  # 0-100
    file_path: str
    line_number: Optional[int]
    description: str
    impact: str
    recommendation: str
    example_fix: Optional[str] = None
    source_tool: str = "vibeguard"
    code_snippet: Optional[str] = None
    attack_path: List[str] = field(default_factory=list)
