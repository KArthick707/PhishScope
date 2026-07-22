"""The investigator agent: a bounded Claude tool-calling loop.

The agent observes the borderline email, decides which enrichment tools to call,
and writes an analyst narrative. It does NOT set the verdict -- the evidence trail
is built from the tools *we* execute (so it's verifiable), and the recommended
verdict is computed deterministically by fuse_recommendation() over that evidence.
That keeps autonomy bounded to read-only enrichment: the agent recommends, rules
and humans decide.

Uses the manual agentic loop (not the SDK tool runner) so budget caps -- max tool
calls and total wall-clock -- are enforced on every iteration; a crafted email
can't steer the agent into unbounded lookups or cost.
"""

import json
import time

from . import config, tools
from .schemas import (
    SIGNAL_BENIGN,
    SIGNAL_MALICIOUS,
    SIGNAL_NEUTRAL,
    VERDICT_BENIGN,
    VERDICT_PHISHING,
    VERDICT_SUSPICIOUS,
    VERDICT_UNCHANGED,
    EvidenceStep,
    Investigation,
)

MAX_TOKENS = 8000

SYSTEM_PROMPT = (
    "You are a SOC (security operations) analyst investigating a single email that an "
    "automated phishing detector flagged as borderline -- not clearly safe, not clearly "
    "malicious. Your job is to gather corroborating evidence using the available tools and "
    "then write a short, plain-language analyst narrative of what you found.\n\n"
    "Work like an analyst: look at the sender domain, the links, and whether the visible "
    "body's claims match the headers, and call the tools that would confirm or refute a "
    "phishing hypothesis. Investigate the specific things that make THIS email suspicious "
    "rather than running every tool by rote. Be efficient -- you have a limited tool budget.\n\n"
    "You do not decide the final verdict; a separate deterministic step scores the evidence "
    "you gather. So focus on collecting good evidence and explaining it clearly. When you have "
    "enough, stop calling tools and write 2-4 sentences summarizing what the evidence shows."
)


class InvestigatorNotConfigured(RuntimeError):
    """Raised when no Anthropic API key is configured. The endpoint turns this
    into a clean 503, mirroring gmail_auth's RuntimeError->503 pattern."""


def _build_client():
    """Test seam: constructing the Anthropic client. Tests monkeypatch this to
    return a fake client that yields scripted tool_use/end_turn responses."""
    import anthropic

    return anthropic.Anthropic()


def _model_kwargs(model: str) -> dict:
    """Adaptive thinking is the right default for a decision-making agent, but it
    (and the effort parameter) 400 on Haiku. Enable it only on model families
    that support it so a configured cheaper model still works."""
    if model.lower().startswith(("claude-opus", "claude-sonnet", "claude-fable", "claude-mythos")):
        return {"thinking": {"type": "adaptive"}}
    return {}


def _initial_context(parsed: dict, analysis: dict) -> str:
    """The email dossier handed to the agent as its first user message."""
    decision = analysis.get("final_decision", {}) or {}
    email = parsed.get("email", {}) or {}
    features = analysis.get("features", {}) or {}
    body = parsed.get("body", {}) or {}
    urls = analysis.get("urls", parsed.get("urls", [])) or []

    lines = [
        "A borderline email needs investigation. Here is what the pipeline already knows:",
        "",
        f"- Pipeline verdict: {decision.get('final_verdict')} (confidence {decision.get('confidence')})",
        f"- Rule score: {decision.get('rule_score')} / 100",
        f"- ML phishing probability (adjusted): {decision.get('ml_adjusted_probability')}",
        f"- From: {email.get('from', '')}",
        f"- Return-Path: {email.get('return_path', '')}",
        f"- Reply-To: {email.get('reply_to', '')}",
        f"- Subject: {email.get('subject', '')}",
        f"- Sender domain (parsed): {features.get('sender_domain', '')}",
        f"- SPF fail: {features.get('spf_fail')}, DKIM missing: {features.get('dkim_missing')}, "
        f"DMARC fail: {features.get('dmarc_fail')}",
        f"- URLs in body ({len(urls)}): {', '.join(urls[:10]) if urls else 'none'}",
        "",
        "Body preview:",
        (str(body.get("preview", "")) or "(empty)")[:800],
    ]
    return "\n".join(lines)


def fuse_recommendation(evidence_trail: list, analysis: dict) -> str:
    """Deterministically map the agent-gathered evidence to a recommended verdict.

    ── LEARNING-MODE CONTRIBUTION POINT #2 ─────────────────────────────────────
    This is a real security judgment call: how much is each signal worth, and what
    combination should escalate all the way to "phishing"? It's the deterministic
    sanity layer on top of the LLM -- even a perfectly-worded phishing email can't
    talk its way past these rules, because the LLM never sets the verdict.

    The default below is a sensible starting point. Consider tuning it: should a
    single fresh-domain finding alone escalate to "phishing"? Should a benign
    WHOIS age be allowed to *down*grade a verdict the rules were worried about, or
    only ever hold steady? Your call changes the tool's false-positive vs
    false-negative posture -- the same risk-appetite decision the pipeline already
    defers to a human in decision_engine.py (ML_BENIGN_CEILING).
    ─────────────────────────────────────────────────────────────────────────────
    """
    malicious = [s for s in evidence_trail if s.get("signal") == SIGNAL_MALICIOUS]
    benign = [s for s in evidence_trail if s.get("signal") == SIGNAL_BENIGN]

    fresh_domain = any(
        s.get("tool") == "whois_domain_age"
        and isinstance(s.get("finding", {}).get("age_days"), int)
        and s["finding"]["age_days"] < 7
        for s in evidence_trail
    )
    impersonation = any(
        s.get("tool") == "cross_check_headers" and s.get("finding", {}).get("impersonated_brands")
        for s in evidence_trail
    )

    # Strongest combination an analyst would act on: a brand-new domain that is
    # also impersonating a known brand.
    if fresh_domain and impersonation:
        return VERDICT_PHISHING
    if len(malicious) >= 2:
        return VERDICT_PHISHING
    if len(malicious) == 1:
        return VERDICT_SUSPICIOUS
    if len(benign) >= 2 and not malicious:
        return VERDICT_BENIGN
    return VERDICT_UNCHANGED


def _synthesize_summary(evidence_trail: list) -> str:
    """Fallback narrative if the agent stopped before writing one (e.g. budget)."""
    if not evidence_trail:
        return "The investigation ran but gathered no evidence."
    return " ".join(step.get("summary", "") for step in evidence_trail).strip()


def run_investigation(parsed: dict, analysis: dict) -> dict:
    """Run the bounded agent loop over a borderline email. Assumes the caller has
    already decided this email warrants investigation (see should_investigate)."""
    if not config.has_api_key():
        raise InvestigatorNotConfigured(
            "The investigator agent requires an Anthropic API key. Set the "
            "ANTHROPIC_API_KEY environment variable to enable /investigate."
        )

    client = _build_client()
    model = config.get_model()
    max_calls = config.get_max_tool_calls()
    timeout = config.get_total_timeout_seconds()
    model_kwargs = _model_kwargs(model)

    messages = [{"role": "user", "content": _initial_context(parsed, analysis)}]
    evidence: list = []
    tools_used: list = []
    tool_calls = 0
    step_no = 0
    agent_summary = ""
    stopped_reason = "completed"
    start = time.monotonic()

    # Hard iteration ceiling as a backstop to the budget checks below.
    for _ in range(max_calls + 3):
        if tool_calls >= max_calls:
            stopped_reason = "max_tool_calls"
            break
        if time.monotonic() - start > timeout:
            stopped_reason = "timeout"
            break

        try:
            response = client.messages.create(
                model=model,
                max_tokens=MAX_TOKENS,
                system=SYSTEM_PROMPT,
                tools=tools.TOOL_SCHEMAS,
                messages=messages,
                **model_kwargs,
            )
        except Exception as exc:  # noqa: BLE001 -- surface any SDK/transport error as a stop
            stopped_reason = f"llm_error:{type(exc).__name__}"
            break

        text = "".join(
            getattr(b, "text", "") for b in response.content if getattr(b, "type", None) == "text"
        ).strip()
        if text:
            agent_summary = text

        # Append the full assistant turn (incl. any thinking blocks) so history stays valid.
        messages.append({"role": "assistant", "content": response.content})

        tool_uses = [b for b in response.content if getattr(b, "type", None) == "tool_use"]
        if not tool_uses:
            stopped_reason = "completed"
            break

        results = []
        for block in tool_uses:
            over_budget = tool_calls >= max_calls or (time.monotonic() - start) > timeout
            if over_budget:
                results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": "Investigation budget exceeded; tool not executed.",
                    "is_error": True,
                })
                stopped_reason = "max_tool_calls" if tool_calls >= max_calls else "timeout"
                continue

            finding = tools.execute_tool(
                block.name, dict(block.input or {}), parsed=parsed, analysis=analysis
            )
            tool_calls += 1
            step_no += 1
            tools_used.append(block.name)
            evidence.append(
                EvidenceStep(
                    step=step_no,
                    tool=block.name,
                    tool_input=dict(block.input or {}),
                    finding=finding,
                    signal=finding.get("signal", SIGNAL_NEUTRAL),
                    summary=finding.get("summary", ""),
                ).to_dict()
            )
            results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": json.dumps(finding, default=str),
            })

        messages.append({"role": "user", "content": results})
        if stopped_reason in ("max_tool_calls", "timeout"):
            break

    recommended = fuse_recommendation(evidence, analysis)
    if not agent_summary:
        agent_summary = _synthesize_summary(evidence)

    investigation = Investigation(
        investigated=True,
        agent_summary=agent_summary,
        recommended_verdict=recommended,
        evidence_trail=evidence,
        tools_used=sorted(set(tools_used)),
        budget={
            "tool_calls": tool_calls,
            "max_tool_calls": max_calls,
            "elapsed_ms": int((time.monotonic() - start) * 1000),
            "stopped_reason": stopped_reason,
        },
    )
    return investigation.to_dict()
