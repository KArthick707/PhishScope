"""Structured result types for the investigator agent.

The investigation result is appended to the standard analyze_parsed_email() dict
under an ``investigation`` key (mirroring how main.py adds meta.filename), so these
dataclasses exist mainly to keep that shape consistent and self-documenting.
"""

from dataclasses import dataclass, field, asdict

# Signal an individual piece of evidence contributes. Assigned by the deterministic
# tools (never by the LLM), so the evidence trail is verifiable.
SIGNAL_MALICIOUS = "malicious"
SIGNAL_BENIGN = "benign"
SIGNAL_NEUTRAL = "neutral"

# Verdicts the investigation can recommend. "unchanged" means the enrichment
# didn't move the needle off the pipeline's original final_verdict.
VERDICT_PHISHING = "phishing"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_BENIGN = "benign_or_low_risk"
VERDICT_UNCHANGED = "unchanged"


@dataclass
class EvidenceStep:
    """One tool execution in the investigation, as the analyst would log it."""

    step: int
    tool: str
    tool_input: dict
    finding: dict
    signal: str  # one of SIGNAL_*
    summary: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Investigation:
    """The full evidence trail plus the agent's narrative and a deterministic
    recommendation. Never overwrites the pipeline's final_verdict -- it only
    recommends, leaving the decision to a human or a later fusion step."""

    investigated: bool
    agent_summary: str = ""
    recommended_verdict: str = VERDICT_UNCHANGED
    evidence_trail: list = field(default_factory=list)  # list[EvidenceStep-as-dict]
    tools_used: list = field(default_factory=list)
    budget: dict = field(default_factory=dict)
    reason: str = ""  # populated when investigated is False

    def to_dict(self) -> dict:
        return {
            "investigated": self.investigated,
            "agent_summary": self.agent_summary,
            "recommended_verdict": self.recommended_verdict,
            "evidence_trail": self.evidence_trail,
            "tools_used": self.tools_used,
            "budget": self.budget,
            "reason": self.reason,
        }

    @classmethod
    def not_investigated(cls, reason: str) -> "Investigation":
        return cls(investigated=False, reason=reason)
