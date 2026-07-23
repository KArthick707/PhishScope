"""Backtests the investigator agent's DETERMINISTIC layer -- the four tools plus
fuse_recommendation -- against PhishScope's real labeled corpus, restricted to the
borderline verdicts (needs_review / suspicious) the agent actually triggers on.

Deliberately excludes the LLM: no ANTHROPIC_API_KEY is configured in this
environment, and the tool-selection/summary-writing the LLM does isn't what was
flagged as risky. What was flagged is the hand-written scoring in tools.py and
agent.fuse_recommendation() (the WHOIS-age threshold, the redirect cross-domain
check, the brand list, the 2-signals-escalate rule) -- none of it validated
against real data the way decision_engine.py's thresholds were. This script does
that validation: it calls the tools directly (real WHOIS/DNS/HTTP, same as the
agent would call them) and answers, empirically, "if this had been auto-labeling
right now, what would the false-positive and false-negative rate actually be?"

Mirrors dataset_preprocessor.py's directory/label convention and hardcoded paths
so it drops into the same offline-tooling pattern as the other backend/app/*.py
dataset scripts (not imported by the API).

Run from backend/: python -m app.investigator_backtest
"""

import os
import random
import time

from app.parser import parse_eml_bytes
from app.pipeline import analyze_parsed_email
from app.investigator import tools as inv_tools
from app.investigator.agent import fuse_recommendation
from app.investigator.schemas import EvidenceStep

PHISHING_DIR = r"C:\Users\karth\Desktop\phishscope\datasets\raw\phishing"
LEGITIMATE_DIR = r"C:\Users\karth\Desktop\phishscope\datasets\raw\legitimate"
OUTPUT_CSV = r"C:\Users\karth\Desktop\phishscope\research\investigator_backtest_results.csv"

BORDERLINE_VERDICTS = {"needs_review", "suspicious"}

# Real WHOIS/DNS/HTTP calls are slow and rate-limit-prone -- bound worst-case
# runtime with a capped, reproducible sample rather than hammering external
# services with the full corpus in one run.
MAX_BORDERLINE_SAMPLE = 150
RANDOM_SEED = 2026

# Per-domain result cache -- many notification emails (LinkedIn, etc.) share a
# sender domain, and being a considerate network citizen means not re-querying
# WHOIS/DNS once per email when one lookup per unique domain answers all of them.
_whois_cache: dict[str, dict] = {}
_dns_cache: dict[str, dict] = {}


def load_labeled_emails() -> list[tuple[str, str, int]]:
    """Returns [(filename, full_path, true_label)] with the same 1=phishing,
    0=legitimate convention as dataset_preprocessor.py."""
    items = []
    for directory, label in ((PHISHING_DIR, 1), (LEGITIMATE_DIR, 0)):
        for filename in os.listdir(directory):
            if filename.endswith(".eml"):
                items.append((filename, os.path.join(directory, filename), label))
    return items


def find_borderline_population(items: list[tuple[str, str, int]]) -> list[dict]:
    """Phase 1 -- fully local, no network. Runs the real (unmodified) pipeline
    over every email and keeps only the ones landing in the borderline band,
    i.e. exactly the population should_investigate() would flag in production."""
    borderline = []
    for filename, path, true_label in items:
        try:
            with open(path, "rb") as f:
                parsed = parse_eml_bytes(f.read())
            analysis = analyze_parsed_email(parsed)
        except Exception as exc:
            print(f"[!] Skipped (parse/pipeline error): {filename} -> {exc}")
            continue

        verdict = analysis["final_decision"]["final_verdict"]
        if verdict in BORDERLINE_VERDICTS:
            borderline.append({
                "filename": filename, "true_label": true_label,
                "pipeline_verdict": verdict, "parsed": parsed, "analysis": analysis,
            })
    return borderline


def _cached_whois(domain: str) -> dict:
    if domain not in _whois_cache:
        _whois_cache[domain] = inv_tools.whois_domain_age(domain)
    return _whois_cache[domain]


def _cached_dns(domain: str) -> dict:
    if domain not in _dns_cache:
        _dns_cache[domain] = inv_tools.dns_lookup(domain)
    return _dns_cache[domain]


def investigate_deterministically(parsed: dict, analysis: dict) -> list[dict]:
    """Runs the same four tools the agent has available, but in a fixed order
    (whois -> dns -> follow first URL -> cross-check) instead of letting an LLM
    choose -- isolating exactly the hand-written scoring logic under test."""
    evidence = []
    step = 0
    sender_domain = (analysis.get("features", {}) or {}).get("sender_domain", "")

    if sender_domain:
        step += 1
        finding = _cached_whois(sender_domain)
        evidence.append(EvidenceStep(step, "whois_domain_age", {"domain": sender_domain},
                                     finding, finding.get("signal"), finding.get("summary", "")).to_dict())

        step += 1
        finding = _cached_dns(sender_domain)
        evidence.append(EvidenceStep(step, "dns_lookup", {"domain": sender_domain},
                                     finding, finding.get("signal"), finding.get("summary", "")).to_dict())

    urls = analysis.get("urls", []) or []
    if urls:
        step += 1
        finding = inv_tools.follow_redirects(urls[0])
        evidence.append(EvidenceStep(step, "follow_redirects", {"url": urls[0]},
                                     finding, finding.get("signal"), finding.get("summary", "")).to_dict())

    step += 1
    finding = inv_tools.cross_check_headers(parsed, analysis)
    evidence.append(EvidenceStep(step, "cross_check_headers", {},
                                 finding, finding.get("signal"), finding.get("summary", "")).to_dict())

    return evidence


def main():
    print("Loading labeled corpus...")
    items = load_labeled_emails()
    print(f"  {len(items)} labeled emails "
          f"({sum(1 for *_, l in items if l == 1)} phishing, "
          f"{sum(1 for *_, l in items if l == 0)} legitimate)")

    print("\nPhase 1 (local, no network): running the real pipeline to find the "
          "borderline population (needs_review / suspicious)...")
    borderline = find_borderline_population(items)
    n_phish = sum(1 for b in borderline if b["true_label"] == 1)
    n_legit = sum(1 for b in borderline if b["true_label"] == 0)
    print(f"  {len(borderline)} borderline emails out of {len(items)} total "
          f"({n_phish} truly phishing, {n_legit} truly legitimate)")

    if len(borderline) > MAX_BORDERLINE_SAMPLE:
        random.Random(RANDOM_SEED).shuffle(borderline)
        borderline = borderline[:MAX_BORDERLINE_SAMPLE]
        print(f"  Sampling {MAX_BORDERLINE_SAMPLE} of them (seed={RANDOM_SEED}) to "
              f"bound real WHOIS/DNS/HTTP call volume.")

    print(f"\nPhase 2 (real network calls): investigating {len(borderline)} "
          f"borderline emails...")
    rows = []
    t0 = time.monotonic()
    for i, item in enumerate(borderline, 1):
        evidence = investigate_deterministically(item["parsed"], item["analysis"])
        recommended = fuse_recommendation(evidence, item["analysis"])
        rows.append({
            "filename": item["filename"],
            "true_label": "phishing" if item["true_label"] == 1 else "legitimate",
            "pipeline_verdict": item["pipeline_verdict"],
            "recommended_verdict": recommended,
            "signals": ",".join(f"{e['tool']}={e['signal']}" for e in evidence),
        })
        if i % 10 == 0 or i == len(borderline):
            print(f"  {i}/{len(borderline)} ({time.monotonic() - t0:.0f}s elapsed)")

    os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
    import csv
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else [])
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nPer-email results written to {OUTPUT_CSV}")

    print("\n" + "=" * 70)
    print("RESULTS -- recommended_verdict on the borderline subset, by ground truth")
    print("=" * 70)
    for label in ("phishing", "legitimate"):
        subset = [r for r in rows if r["true_label"] == label]
        if not subset:
            continue
        print(f"\nTruly {label} ({len(subset)} borderline emails):")
        for verdict in ("phishing", "suspicious", "benign_or_low_risk", "unchanged"):
            count = sum(1 for r in subset if r["recommended_verdict"] == verdict)
            pct = 100 * count / len(subset)
            print(f"  recommended={verdict:20s} {count:4d}  ({pct:5.1f}%)")

    sampled_legit = sum(1 for r in rows if r["true_label"] == "legitimate")
    sampled_phish = sum(1 for r in rows if r["true_label"] == "phishing")
    fp = sum(1 for r in rows if r["true_label"] == "legitimate" and r["recommended_verdict"] == "phishing")
    fn = sum(1 for r in rows if r["true_label"] == "phishing" and r["recommended_verdict"] == "benign_or_low_risk")
    cleared = sum(1 for r in rows if r["true_label"] == "legitimate" and r["recommended_verdict"] == "benign_or_low_risk")
    caught = sum(1 for r in rows if r["true_label"] == "phishing" and r["recommended_verdict"] == "phishing")
    print("\n" + "-" * 70)
    print(f"False positives (legit -> recommended phishing):  {fp} / {sampled_legit}")
    print(f"False negatives (phishing -> recommended benign): {fn} / {sampled_phish}")
    print(f"Correctly auto-cleared (legit -> benign):         {cleared} / {sampled_legit}")
    print(f"Correctly auto-escalated (phishing -> phishing):  {caught} / {sampled_phish}")


if __name__ == "__main__":
    main()
