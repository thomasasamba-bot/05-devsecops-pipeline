#!/usr/bin/env python3
"""
parse_trivy_report.py — AI-Assisted Vulnerability Analysis
===========================================================
Parses Trivy JSON reports, generates prioritised remediation
recommendations, and optionally uses Claude AI to provide
context-aware fix suggestions.

Usage:
  python scripts/parse_trivy_report.py trivy-full.json
  python scripts/parse_trivy_report.py trivy-full.json --fail-on CRITICAL
  python scripts/parse_trivy_report.py trivy-full.json --ai-analysis
  python scripts/parse_trivy_report.py trivy-full.json --output report.md
"""

import argparse
import json
import sys
import os
import textwrap
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime


# ─── DATA MODELS ──────────────────────────────────────────────────────
@dataclass
class Vulnerability:
    vuln_id:     str
    pkg_name:    str
    installed:   str
    fixed:       str
    severity:    str
    title:       str
    description: str
    cvss_score:  float = 0.0
    references:  list  = field(default_factory=list)


@dataclass
class ScanSummary:
    target:         str
    scan_type:      str
    total:          int = 0
    critical:       int = 0
    high:           int = 0
    medium:         int = 0
    low:            int = 0
    vulnerabilities: list = field(default_factory=list)


SEVERITY_ORDER  = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
SEVERITY_EMOJI  = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "UNKNOWN": "⚪"}
SEVERITY_WEIGHT = {"CRITICAL": 10,   "HIGH": 5,    "MEDIUM": 2,    "LOW": 1,    "UNKNOWN": 0}


# ─── PARSER ───────────────────────────────────────────────────────────
def parse_trivy_report(filepath: str) -> list[ScanSummary]:
    with open(filepath) as f:
        data = json.load(f)

    summaries = []

    # Handle both image and filesystem scan formats
    results = data.get("Results", [])
    if not results and "Results" not in data:
        # May be a single result
        results = [data]

    for result in results:
        target    = result.get("Target", "unknown")
        scan_type = result.get("Type", "unknown")
        vulns     = result.get("Vulnerabilities", []) or []

        summary = ScanSummary(target=target, scan_type=scan_type)

        for v in vulns:
            severity = v.get("Severity", "UNKNOWN").upper()
            cvss     = 0.0

            # Extract CVSS score
            cvss_data = v.get("CVSS", {})
            for source in ["nvd", "redhat"]:
                if source in cvss_data:
                    cvss = cvss_data[source].get("V3Score",
                           cvss_data[source].get("V2Score", 0.0))
                    break

            vuln = Vulnerability(
                vuln_id     = v.get("VulnerabilityID", "UNKNOWN"),
                pkg_name    = v.get("PkgName", "unknown"),
                installed   = v.get("InstalledVersion", "unknown"),
                fixed       = v.get("FixedVersion", "not-available"),
                severity    = severity,
                title       = v.get("Title", "No title"),
                description = v.get("Description", "")[:300],
                cvss_score  = cvss,
                references  = v.get("References", [])[:3],
            )

            summary.vulnerabilities.append(vuln)
            summary.total += 1
            if severity == "CRITICAL": summary.critical += 1
            elif severity == "HIGH":   summary.high     += 1
            elif severity == "MEDIUM": summary.medium   += 1
            elif severity == "LOW":    summary.low      += 1

        summaries.append(summary)

    return summaries


# ─── REPORT GENERATION ────────────────────────────────────────────────
def generate_text_report(summaries: list[ScanSummary]) -> str:
    lines = []
    lines.append("=" * 70)
    lines.append("  TRIVY SECURITY SCAN REPORT")
    lines.append(f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append("=" * 70)

    total_critical = sum(s.critical for s in summaries)
    total_high     = sum(s.high     for s in summaries)
    total_medium   = sum(s.medium   for s in summaries)
    total_low      = sum(s.low      for s in summaries)
    grand_total    = sum(s.total    for s in summaries)

    lines.append(f"\n📊 OVERALL SUMMARY")
    lines.append(f"  🔴 CRITICAL: {total_critical}")
    lines.append(f"  🟠 HIGH:     {total_high}")
    lines.append(f"  🟡 MEDIUM:   {total_medium}")
    lines.append(f"  🟢 LOW:      {total_low}")
    lines.append(f"  📦 TOTAL:    {grand_total}")

    # Risk score
    risk_score = (total_critical * 10 + total_high * 5 +
                  total_medium * 2 + total_low * 1)
    risk_level = (
        "🔴 CRITICAL RISK" if total_critical > 0 else
        "🟠 HIGH RISK"     if total_high > 5     else
        "🟡 MEDIUM RISK"   if total_medium > 10  else
        "🟢 LOW RISK"
    )
    lines.append(f"\n  Risk Level: {risk_level} (score: {risk_score})")

    for summary in summaries:
        if not summary.vulnerabilities:
            lines.append(f"\n✅ {summary.target} — No vulnerabilities found")
            continue

        lines.append(f"\n{'─' * 70}")
        lines.append(f"📦 TARGET: {summary.target}")
        lines.append(f"   Type: {summary.scan_type} | "
                     f"CRIT: {summary.critical} | HIGH: {summary.high} | "
                     f"MED: {summary.medium} | LOW: {summary.low}")

        # Group by package for remediation efficiency
        by_package: dict[str, list[Vulnerability]] = defaultdict(list)
        for v in summary.vulnerabilities:
            by_package[v.pkg_name].append(v)

        # Show CRITICAL and HIGH first
        critical_high = [v for v in summary.vulnerabilities
                         if v.severity in ("CRITICAL", "HIGH")]
        critical_high.sort(key=lambda x: SEVERITY_WEIGHT.get(x.severity, 0), reverse=True)

        if critical_high:
            lines.append(f"\n  ⚠️  IMMEDIATE ACTION REQUIRED ({len(critical_high)} findings):")
            for v in critical_high[:10]:
                emoji = SEVERITY_EMOJI.get(v.severity, "⚪")
                lines.append(f"\n    {emoji} [{v.severity}] {v.vuln_id}")
                lines.append(f"       Package:  {v.pkg_name} {v.installed}")
                lines.append(f"       Fix:      {v.fixed if v.fixed != 'not-available' else '⚠️  No fix available'}")
                if v.cvss_score:
                    lines.append(f"       CVSS:     {v.cvss_score:.1f}")
                lines.append(f"       Title:    {v.title[:80]}")

        # Remediation recommendations
        lines.append(f"\n  🔧 REMEDIATION PLAN:")
        fixable = [(pkg, vulns) for pkg, vulns in by_package.items()
                   if any(v.fixed and v.fixed != "not-available" for v in vulns)]
        fixable.sort(
            key=lambda x: sum(SEVERITY_WEIGHT.get(v.severity, 0) for v in x[1]),
            reverse=True
        )

        for pkg, vulns in fixable[:5]:
            severities  = sorted({v.severity for v in vulns},
                                  key=lambda s: SEVERITY_WEIGHT.get(s, 0), reverse=True)
            fixed_vers  = {v.fixed for v in vulns if v.fixed and v.fixed != "not-available"}
            target_ver  = sorted(fixed_vers)[-1] if fixed_vers else "latest"
            lines.append(f"    → Upgrade {pkg} to {target_ver} "
                         f"[{', '.join(severities)}]")

    return "\n".join(lines)


# ─── AI-ASSISTED ANALYSIS (Claude API) ───────────────────────────────
def ai_analysis(summaries: list[ScanSummary]) -> str:
    """
    Uses Claude API to generate context-aware remediation guidance.
    Requires ANTHROPIC_API_KEY environment variable.
    """
    try:
        import anthropic
    except ImportError:
        return "Install anthropic: pip install anthropic"

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return "Set ANTHROPIC_API_KEY environment variable for AI analysis"

    # Prepare vulnerability summary for Claude
    critical_vulns = []
    for summary in summaries:
        for v in summary.vulnerabilities:
            if v.severity in ("CRITICAL", "HIGH"):
                critical_vulns.append({
                    "id":       v.vuln_id,
                    "package":  v.pkg_name,
                    "version":  v.installed,
                    "fix":      v.fixed,
                    "severity": v.severity,
                    "title":    v.title,
                })

    if not critical_vulns:
        return "No CRITICAL/HIGH vulnerabilities — AI analysis not required."

    prompt = f"""You are a DevSecOps engineer reviewing a Trivy container vulnerability scan.

Here are the CRITICAL and HIGH vulnerabilities found:

{json.dumps(critical_vulns[:15], indent=2)}

Please provide:
1. A brief risk assessment (2-3 sentences)
2. The top 3 most urgent fixes with specific version upgrades
3. Any patterns you notice (e.g., outdated base image, a single library causing multiple CVEs)
4. One Dockerfile best practice recommendation to reduce future exposure

Keep your response concise and actionable — this will appear in a CI/CD pipeline log."""

    client = anthropic.Anthropic(api_key=api_key)
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=600,
        messages=[{"role": "user", "content": prompt}]
    )
    return f"\n🤖 AI-ASSISTED ANALYSIS (Claude):\n{'─'*50}\n{response.content[0].text}"


# ─── MAIN ─────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Parse and analyse Trivy scan reports")
    parser.add_argument("report",          help="Path to Trivy JSON report")
    parser.add_argument("--fail-on",       default="", help="Fail if severity found (CRITICAL/HIGH)")
    parser.add_argument("--ai-analysis",   action="store_true", help="Use Claude AI for remediation advice")
    parser.add_argument("--output",        default="", help="Save markdown report to file")
    args = parser.parse_args()

    if not os.path.exists(args.report):
        print(f"Report not found: {args.report}")
        sys.exit(0)  # Don't fail if report missing — scan may not have run

    summaries = parse_trivy_report(args.report)
    report    = generate_text_report(summaries)
    print(report)

    if args.ai_analysis:
        ai_report = ai_analysis(summaries)
        print(ai_report)

    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        print(f"\n📄 Report saved to {args.output}")

    # Exit code for pipeline gate
    if args.fail_on:
        total_critical = sum(s.critical for s in summaries)
        total_high     = sum(s.high     for s in summaries)
        should_fail = (
            (args.fail_on == "CRITICAL" and total_critical > 0) or
            (args.fail_on == "HIGH"     and (total_critical + total_high) > 0)
        )
        if should_fail:
            print(f"\n❌ PIPELINE GATE FAILED: {args.fail_on} vulnerabilities found")
            print("Fix the above vulnerabilities before merging.")
            sys.exit(1)

    print("\n✅ Security scan complete")


if __name__ == "__main__":
    main()
