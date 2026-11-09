"""PromptShield: a prompt-injection and data-leak firewall for LLM apps."""
from .engine import Firewall, Verdict

__all__ = ["Firewall", "Verdict"]
__version__ = "0.1.0"
