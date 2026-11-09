"""Weighted rule-based prompt-injection detector.

Each rule has a weight in (0, 1]. Matched weights are combined with a noisy-OR
(score = 1 - prod(1 - w)), so several weak signals add up while one strong
signal is enough on its own. Rules cover English and German, because the
reference benchmark (deepset/prompt-injections) contains both.
"""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass

from .base import Finding
from .normalize import has_invisible_chars, normalize


@dataclass(frozen=True)
class Rule:
    id: str
    weight: float
    pattern: re.Pattern
    description: str


def _r(id: str, weight: float, regex: str, description: str) -> Rule:
    return Rule(id, weight, re.compile(regex, re.IGNORECASE), description)


_PRIOR = r"(?:all |any |the |your |my |these |those |of )*(?:previous|prior|above|earlier|preceding|initial|original|former|old|system|given|existing)?"
_INSTR = r"(?:instructions?|directions?|prompts?|rules?|directives?|guidelines?|commands?|context|messages?|orders?|tasks?|text|information|everything)"

RULES: list[Rule] = [
    # --- Instruction override -------------------------------------------------
    _r("ignore_previous", 0.85,
       rf"\b(?:ignore|disregard|forget|skip|override|bypass|drop|abandon|discard|neglect)\b\s+{_PRIOR}\s*{_INSTR}",
       "Asks the model to ignore its prior instructions"),
    _r("forget_everything", 0.7,
       r"\b(?:forget|ignore|disregard)\s+(?:about\s+)?(?:everything|all\s+(?:that|of\s+that|this)|what\s+(?:i|you)\s+(?:said|were\s+told))",
       "Wipe-the-slate phrasing"),
    _r("new_instructions", 0.55,
       r"\b(?:new|updated|real|actual|true|revised)\s+(?:instructions?|task|rules?|directive|prompt|objective)s?\s*(?:[:\-]|are|is|follow)",
       "Introduces replacement instructions"),
    _r("instead_do", 0.35,
       r"\b(?:instead|rather)\s*,?\s+(?:you\s+(?:will|must|should)|now|just|please)\b",
       "Redirects the task"),
    _r("from_now_on", 0.4,
       r"\b(?:from\s+now\s+on|starting\s+now|for\s+the\s+rest\s+of\s+(?:this|the)\s+conversation)\b",
       "Persistent behaviour change"),
    _r("stop_task", 0.45,
       r"\b(?:stop|end|cancel|abort)\b.{0,20}\b(?:what\s+you\s+are\s+doing|the\s+(?:current\s+)?task|everything)\b",
       "Tells the model to abandon its task"),

    # --- Role / persona hijacking --------------------------------------------
    _r("role_override", 0.55,
       r"\b(?:you\s+are\s+(?:now|no\s+longer)|from\s+now\s+on\s+you\s+are|act\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:an?\s+)?(?:unrestricted|unfiltered|evil|jailbroken|different)|you\s+will\s+(?:now\s+)?(?:act|behave|respond)\s+as)\b",
       "Assigns the model a new identity"),
    _r("pretend_persona", 0.3,
       r"\b(?:pretend\s+(?:to\s+be|you\s+are)|roleplay\s+as)\b",
       "Persona request (weak on its own; benign role-play is common)"),
    _r("jailbreak_persona", 0.9,
       r"\b(?:DAN|do\s+anything\s+now|developer\s+mode|jailbreak(?:ed)?|god\s*mode|STAN|DUDE|AIM\s+mode|evil\s+confidant|no\s+(?:restrictions|limitations|filters|rules|guidelines))\b",
       "Known jailbreak persona or framing"),
    _r("disable_safety", 0.7,
       r"\b(?:disable|turn\s+off|deactivate|remove|ignore|without)\b.{0,25}\b(?:safety|content\s+polic(?:y|ies)|guardrails?|filters?|moderation|censorship|ethical\s+guidelines|restrictions)\b",
       "Asks to disable safety controls"),

    # --- System-prompt / secret extraction -----------------------------------
    _r("prompt_extraction", 0.8,
       r"\b(?:reveal|show|print|output|repeat|display|tell\s+me|give\s+me|leak|dump|share|write\s+(?:out|down)|what\s+(?:is|are|was|were))\b.{0,40}\b(?:system\s+prompt|initial\s+prompt|(?:your|the)\s+(?:hidden\s+|secret\s+|original\s+|initial\s+)?(?:instructions|prompt|rules|guidelines|configuration)|everything\s+above|text\s+above|words\s+above|password|secret\s+key|api\s+key)\b",
       "Tries to extract the system prompt or secrets"),
    _r("repeat_above", 0.6,
       r"\b(?:repeat|print|output|echo|copy)\b.{0,30}\b(?:above|before\s+this|preceding|verbatim|word\s+for\s+word)\b",
       "Asks to echo prior context"),

    # --- Delimiter / format smuggling ----------------------------------------
    _r("fake_system_tag", 0.7,
       r"(?:<\|?(?:im_start|im_end|system|endoftext|eot_id|start_header_id)\|?>|\[/?(?:INST|SYS)\]|<</?SYS>>|^\s*#{2,}\s*(?:system|instruction)|^\s*(?:system|assistant)\s*:)",
       "Injects chat-template or role delimiters"),
    _r("end_of_prompt", 0.5,
       r"\b(?:end\s+of\s+(?:the\s+)?(?:prompt|instructions|input|document|context)|---+\s*(?:new|end)|=+\s*end)\b",
       "Pretends the trusted context has ended"),

    # --- Indirect injection (content addressed to the model) -----------------
    _r("addressed_to_ai", 0.5,
       r"\b(?:attention|note|important|message)\s+(?:to\s+)?(?:the\s+)?(?:ai|assistant|llm|language\s+model|chatbot|gpt|model)\b|\b(?:if\s+you\s+are\s+an?\s+(?:ai|llm|language\s+model|assistant))\b",
       "Text that speaks to the model, typical of indirect injection"),
    _r("exfil_markdown", 0.75,
       r"!\[[^\]]*\]\(\s*https?://[^)]*(?:\{|%7b|\?[^)]*=)",
       "Markdown image with templated query string (data exfiltration)"),
    _r("exfil_instruction", 0.6,
       r"\b(?:send|post|forward|upload|exfiltrate|email|transmit)\b.{0,40}\b(?:conversation|chat\s+history|user\s+data|credentials|password|api\s+key|secrets?|tokens?)\b.{0,40}\b(?:to|at)\b",
       "Instructs the model to send data somewhere"),

    # --- German (deepset/prompt-injections includes German samples) ---------
    _r("de_ignore", 0.85,
       r"\b(?:ignoriere|ignorieren|vergiss|vergessen|vergesse|missachte|übergehe)\b.{0,40}\b(?:anweisungen|anweisung|befehle|aufgaben|aufgabe|alles|vorherigen|bisherigen|obigen|regeln|instruktionen)\b",
       "German: ignore/forget previous instructions"),
    _r("de_new_task", 0.5,
       r"\b(?:neue\s+(?:aufgabe|anweisung|instruktion)|jetzt\s+(?:bist\s+du|kommt)|nun\s+(?:bist\s+du|folgt)|du\s+bist\s+(?:jetzt|nun))\b",
       "German: new task / role switch"),
    _r("de_extract", 0.7,
       r"\b(?:zeige|gib|nenne|verrate|wiederhole|sag)\b.{0,30}\b(?:system\s*prompt|anweisungen|passwort|geheim)\b",
       "German: prompt/secret extraction"),
]


class HeuristicDetector:
    name = "heuristic"

    def __init__(self, rules: list[Rule] | None = None):
        self.rules = rules or RULES

    def scan(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        variants = {normalize(text), normalize(text, leet=True)}
        # Also scan decoded base64 payloads, a common smuggling trick.
        decoded = list(_decode_base64_blobs(text))
        if decoded:
            findings.append(Finding(self.name, "base64_payload", 0.25, decoded[0][:80]))
            variants.update(normalize(d) for d in decoded)

        seen: set[str] = set()
        for rule in self.rules:
            for v in variants:
                m = rule.pattern.search(v)
                if m and rule.id not in seen:
                    seen.add(rule.id)
                    findings.append(Finding(self.name, rule.id, rule.weight, m.group(0)[:120]))
                    break

        if has_invisible_chars(text):
            findings.append(Finding(self.name, "invisible_chars", 0.3, "zero-width/bidi control characters"))
        return findings

    @staticmethod
    def combine(findings: list[Finding]) -> float:
        p = 1.0
        for f in findings:
            p *= 1.0 - f.score
        return 1.0 - p


_B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")


def _decode_base64_blobs(text: str):
    for m in _B64.finditer(text):
        blob = m.group(0)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            s = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if sum(c.isprintable() or c.isspace() for c in s) / max(len(s), 1) > 0.9 and " " in s:
            yield s
