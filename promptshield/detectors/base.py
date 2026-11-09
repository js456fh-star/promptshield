from __future__ import annotations

from dataclasses import dataclass, asdict


@dataclass
class Finding:
    detector: str      # e.g. "heuristic", "classifier", "dlp"
    rule: str          # rule id, e.g. "ignore_previous"
    score: float       # 0..1 contribution
    evidence: str = "" # matched snippet (truncated)

    def to_dict(self) -> dict:
        return asdict(self)
