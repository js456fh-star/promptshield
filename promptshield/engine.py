"""The firewall engine: runs detectors and turns findings into verdicts."""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from .detectors.base import Finding
from .detectors.dlp import OutputScanner
from .detectors.heuristics import HeuristicDetector


@dataclass
class Verdict:
    blocked: bool
    score: float
    findings: list[Finding] = field(default_factory=list)
    latency_ms: float = 0.0
    direction: str = "input"   # "input" or "output"

    @property
    def reasons(self) -> list[str]:
        return sorted({f.rule for f in self.findings})

    def to_dict(self) -> dict:
        return {
            "blocked": self.blocked,
            "score": round(self.score, 4),
            "direction": self.direction,
            "reasons": self.reasons,
            "findings": [f.to_dict() for f in self.findings],
            "latency_ms": round(self.latency_ms, 3),
        }


class Firewall:
    """Combine detectors. The input score is max(heuristic, classifier):
    either a confident rule hit or a confident model prediction is enough."""

    def __init__(self, threshold: float = 0.5, classifier=None,
                 use_heuristics: bool = True, output_threshold: float = 0.8):
        self.threshold = threshold
        self.output_threshold = output_threshold
        self.heuristics = HeuristicDetector() if use_heuristics else None
        self.classifier = classifier
        self.output = OutputScanner()

    @classmethod
    def from_settings(cls, settings) -> "Firewall":
        clf = None
        if settings.model_path:
            from .detectors.classifier import ClassifierDetector
            clf = ClassifierDetector.load(settings.model_path)
        return cls(threshold=settings.threshold, classifier=clf)

    def score_text(self, text: str) -> tuple[float, list[Finding]]:
        findings: list[Finding] = []
        scores = [0.0]
        if self.heuristics:
            h = self.heuristics.scan(text)
            findings += h
            scores.append(HeuristicDetector.combine(h))
        if self.classifier:
            c = self.classifier.scan(text)
            findings += c
            scores.append(max((f.score for f in c), default=0.0))
        return max(scores), findings

    def scan_input(self, text: str) -> Verdict:
        t0 = time.perf_counter()
        score, findings = self.score_text(text)
        return Verdict(score >= self.threshold, score, findings,
                       (time.perf_counter() - t0) * 1000, "input")

    def scan_output(self, text: str, canary: str | None = None,
                    system_prompt: str | None = None) -> Verdict:
        t0 = time.perf_counter()
        findings = self.output.scan(text, canary=canary, system_prompt=system_prompt)
        score = max((f.score for f in findings), default=0.0)
        return Verdict(score >= self.output_threshold, score, findings,
                       (time.perf_counter() - t0) * 1000, "output")
