"""Score a Firewall against a labelled dataset."""
from __future__ import annotations

import statistics
from dataclasses import dataclass, field

from ..engine import Firewall
from .datasets import Example


@dataclass
class Report:
    name: str
    n: int
    tp: int
    fp: int
    tn: int
    fn: int
    latencies_ms: list[float] = field(default_factory=list, repr=False)
    misses: list[str] = field(default_factory=list, repr=False)
    false_alarms: list[str] = field(default_factory=list, repr=False)

    @property
    def precision(self): return self.tp / (self.tp + self.fp) if self.tp + self.fp else 0.0
    @property
    def recall(self): return self.tp / (self.tp + self.fn) if self.tp + self.fn else 0.0
    @property
    def f1(self):
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0
    @property
    def fpr(self): return self.fp / (self.fp + self.tn) if self.fp + self.tn else 0.0
    @property
    def accuracy(self): return (self.tp + self.tn) / self.n if self.n else 0.0

    def p(self, q: float) -> float:
        if not self.latencies_ms:
            return 0.0
        s = sorted(self.latencies_ms)
        return s[min(len(s) - 1, int(q * len(s)))]

    def to_dict(self) -> dict:
        return {"name": self.name, "n": self.n, "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
                "precision": round(self.precision, 4), "recall": round(self.recall, 4),
                "f1": round(self.f1, 4), "fpr": round(self.fpr, 4), "accuracy": round(self.accuracy, 4),
                "latency_ms_p50": round(self.p(0.5), 3), "latency_ms_p95": round(self.p(0.95), 3),
                "latency_ms_mean": round(statistics.fmean(self.latencies_ms), 3) if self.latencies_ms else 0}


def evaluate(fw: Firewall, data: list[Example], name: str = "firewall") -> Report:
    r = Report(name, len(data), 0, 0, 0, 0)
    for ex in data:
        v = fw.scan_input(ex.text)
        r.latencies_ms.append(v.latency_ms)
        pred = int(v.blocked)
        if pred and ex.label:
            r.tp += 1
        elif pred:
            r.fp += 1
            r.false_alarms.append(ex.text)
        elif ex.label:
            r.fn += 1
            r.misses.append(ex.text)
        else:
            r.tn += 1
    return r


def markdown(reports: list[Report], dataset: str) -> str:
    lines = [f"## PromptShield benchmark — `{dataset}`", "",
             "| Config | N | Precision | Recall | F1 | FPR | Accuracy | p50 ms | p95 ms |",
             "|---|---|---|---|---|---|---|---|---|"]
    for r in reports:
        lines.append(f"| {r.name} | {r.n} | {r.precision:.3f} | {r.recall:.3f} | {r.f1:.3f} | "
                     f"{r.fpr:.3f} | {r.accuracy:.3f} | {r.p(0.5):.2f} | {r.p(0.95):.2f} |")
    return "\n".join(lines) + "\n"
