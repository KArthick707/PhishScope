"""Investigator agent package.

Public surface used by the /investigate endpoint:
  * should_investigate(final_decision) -> bool  -- the borderline-trigger gate
  * run_investigation(parsed, analysis) -> dict -- the bounded agent loop
  * InvestigatorNotConfigured                   -- raised when no API key (-> 503)
"""

from .agent import InvestigatorNotConfigured, run_investigation

# Verdicts the pipeline considers "borderline" -- the band this agent triggers on.
_BORDERLINE_VERDICTS = {"needs_review", "suspicious"}


def should_investigate(final_decision: dict) -> bool:
    """Decide whether a borderline verdict warrants spinning up the (costly,
    networked) investigator agent.

    ── LEARNING-MODE CONTRIBUTION POINT #1 ─────────────────────────────────────
    This is the same risk-appetite call the pipeline already defers to a human at
    decision_engine.py's ML_BENIGN_CEILING TODO. The default below fires only on
    the two explicitly-borderline verdicts. Consider widening it: should a
    "phishing" verdict with a *low* rule_score (ML-only) also get a second look?
    Should you pull in `rule_score` / `ml_adjusted_probability` bands directly
    rather than trusting the verdict label? A broader gate buys more
    analyst-grade evidence per inbox at more LLM/network cost per message.
    ─────────────────────────────────────────────────────────────────────────────
    """
    if not isinstance(final_decision, dict):
        return False
    return final_decision.get("final_verdict") in _BORDERLINE_VERDICTS


__all__ = ["should_investigate", "run_investigation", "InvestigatorNotConfigured"]
