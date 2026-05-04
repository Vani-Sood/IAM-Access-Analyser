"""Structured IAM analysis report builder with JSON and PDF output."""
from __future__ import annotations

import json
import textwrap
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.analysis.graph_builder import GraphData
from app.analysis.privesc import DANGEROUS_ACTIONS, WILDCARD_RESOURCES, PrivescDetector

_SEVERITY_COLOR: dict[str, str] = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#d97706",
    "LOW": "#16a34a",
    "INFO": "#2563eb",
}

_SEV_RGB: dict[str, tuple[int, int, int]] = {
    "CRITICAL": (220, 38, 38),
    "HIGH": (234, 88, 12),
    "MEDIUM": (217, 119, 6),
    "LOW": (22, 163, 74),
    "INFO": (37, 99, 235),
}


@dataclass
class ReportData:
    analysis_id: int
    generated_at: str
    risk_score: float
    severity: str
    findings_count: int
    privesc_paths_count: int
    summary: dict
    findings: list[dict]
    privesc_paths: list[dict]
    recommendations: list[str]
    policy: dict = field(default_factory=dict)
    ai_suggestions: dict = field(default_factory=dict)
    compliance_results: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "analysis_id": self.analysis_id,
            "generated_at": self.generated_at,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "findings_count": self.findings_count,
            "privesc_paths_count": self.privesc_paths_count,
            "summary": self.summary,
            "findings": self.findings,
            "privesc_paths": self.privesc_paths,
            "recommendations": self.recommendations,
            "policy": self.policy,
            "ai_suggestions": self.ai_suggestions,
            "compliance_results": self.compliance_results,
        }

    def render_html(self) -> str:
        sev_color = _SEVERITY_COLOR.get(self.severity, "#6b7280")
        privesc_rows = ""
        for p in self.privesc_paths:
            sev = p.get("severity", "")
            color = _SEVERITY_COLOR.get(sev, "#6b7280")
            actions = ", ".join(p.get("dangerous_actions", []))
            privesc_rows += (
                f"<tr>"
                f"<td style='color:{color};font-weight:600'>{sev}</td>"
                f"<td>{actions}</td>"
                f"<td>{p.get('description', '')}</td>"
                f"</tr>"
            )

        finding_rows = ""
        for f in self.findings:
            fsev = f.get("severity", "")
            fcolor = _SEVERITY_COLOR.get(fsev, "#6b7280")
            finding_rows += (
                f"<tr>"
                f"<td style='color:{fcolor};font-weight:600'>{fsev}</td>"
                f"<td>{f.get('type', '')}</td>"
                f"<td>{f.get('message', '')}</td>"
                f"</tr>"
            )

        recs = "".join(f"<li>{r}</li>" for r in self.recommendations) or "<li>No recommendations.</li>"

        total_stmts = self.summary.get("total_statements", 0)
        total_actions = self.summary.get("total_actions", 0)
        dangerous = self.summary.get("dangerous_actions_count", 0)
        wildcards = self.summary.get("wildcard_resources_count", 0)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>IAM Policy Analysis Report — #{self.analysis_id}</title>
<style>
  body {{ font-family: Arial, sans-serif; margin: 40px; color: #111; font-size: 14px; }}
  h1 {{ font-size: 24px; margin-bottom: 4px; }}
  h2 {{ font-size: 18px; margin-top: 28px; border-bottom: 2px solid #e5e7eb; padding-bottom: 6px; }}
  .meta {{ color: #6b7280; font-size: 12px; margin-bottom: 24px; }}
  .score-box {{ display: inline-block; padding: 8px 20px; border-radius: 6px;
                background: {sev_color}; color: #fff; font-size: 22px; font-weight: 700; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
  th {{ background: #f3f4f6; text-align: left; padding: 8px 10px; font-size: 13px; }}
  td {{ padding: 7px 10px; border-bottom: 1px solid #e5e7eb; font-size: 13px; }}
  ul {{ margin: 8px 0 0 20px; line-height: 1.8; }}
  .stat-grid {{ display: flex; gap: 24px; margin: 16px 0; }}
  .stat {{ background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 6px;
           padding: 12px 20px; text-align: center; min-width: 100px; }}
  .stat-val {{ font-size: 28px; font-weight: 700; color: #111; }}
  .stat-lbl {{ font-size: 11px; color: #6b7280; margin-top: 2px; }}
  .empty {{ color: #9ca3af; font-style: italic; }}
</style>
</head>
<body>
<h1>IAM Policy Analysis Report</h1>
<div class="meta">Analysis #{self.analysis_id} &nbsp;·&nbsp; Generated {self.generated_at}</div>

<h2>Risk Assessment</h2>
<div class="score-box">{self.risk_score:.1f} / 10 &nbsp; {self.severity}</div>

<div class="stat-grid">
  <div class="stat"><div class="stat-val">{total_stmts}</div><div class="stat-lbl">Statements</div></div>
  <div class="stat"><div class="stat-val">{total_actions}</div><div class="stat-lbl">Actions</div></div>
  <div class="stat"><div class="stat-val">{dangerous}</div><div class="stat-lbl">Dangerous Actions</div></div>
  <div class="stat"><div class="stat-val">{wildcards}</div><div class="stat-lbl">Wildcard Resources</div></div>
</div>

<h2>Privilege Escalation Paths</h2>
{
    f'<table><thead><tr><th>Severity</th><th>Dangerous Actions</th><th>Description</th></tr></thead><tbody>{privesc_rows}</tbody></table>'
    if self.privesc_paths
    else '<p class="empty">No privilege escalation paths detected.</p>'
}

<h2>Security Findings</h2>
{
    f'<table><thead><tr><th>Severity</th><th>Type</th><th>Message</th></tr></thead><tbody>{finding_rows}</tbody></table>'
    if self.findings
    else '<p class="empty">No findings.</p>'
}

<h2>Recommendations</h2>
<ul>{recs}</ul>

</body>
</html>"""

    # ── PDF rendering ─────────────────────────────────────────────────────────

    def render_pdf(self) -> bytes:
        from fpdf import FPDF
        from fpdf.enums import XPos, YPos

        NL = {"new_x": XPos.LMARGIN, "new_y": YPos.NEXT}
        CONT = {"new_x": XPos.RIGHT, "new_y": YPos.TOP}
        W = 180  # usable width (210 - 15 - 15)

        def s(text: str) -> str:
            return text.encode("latin-1", errors="replace").decode("latin-1")

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=12)
        pdf.set_margins(15, 15, 15)

        # ── helpers ───────────────────────────────────────────────────────────

        def section(title: str) -> None:
            pdf.ln(3)
            pdf.set_font("Helvetica", "B", 12)
            pdf.set_text_color(20, 30, 60)
            pdf.cell(0, 7, s(title), **NL)
            pdf.set_draw_color(180, 190, 210)
            pdf.line(15, pdf.get_y(), 195, pdf.get_y())
            pdf.ln(2)

        def subsection(title: str) -> None:
            pdf.ln(2)
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(50, 60, 90)
            pdf.cell(0, 5, s(title), **NL)
            pdf.ln(1)

        def kv(label: str, value: str, w_label: int = 45) -> None:
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_text_color(80, 90, 110)
            pdf.cell(w_label, 5, s(label) + ":", **CONT)
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(30, 30, 30)
            pdf.multi_cell(W - w_label, 5, s(value), **NL)

        def italic(text: str) -> None:
            pdf.set_font("Helvetica", "I", 9)
            pdf.set_text_color(150, 150, 160)
            pdf.cell(0, 5, s(text), **NL)

        def table_hdr(*cols: tuple[str, int]) -> None:
            pdf.set_fill_color(230, 234, 245)
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_text_color(20, 30, 60)
            for label, w in cols:
                pdf.cell(w, 6, label, border=1, fill=True, **CONT)
            pdf.ln()

        def sev_badge(sev: str, w: int) -> None:
            r, g, b = _SEV_RGB.get(sev, (107, 114, 128))
            pdf.set_text_color(r, g, b)
            pdf.set_font("Helvetica", "B", 8)
            pdf.cell(w, 5, sev, border="B", **CONT)
            pdf.set_text_color(30, 30, 30)
            pdf.set_font("Helvetica", "", 8)

        def code_block(text: str) -> None:
            pdf.set_fill_color(245, 246, 250)
            pdf.set_draw_color(220, 222, 230)
            pdf.set_font("Courier", "", 7)
            pdf.set_text_color(30, 30, 30)
            for line in s(text).split("\n"):
                for chunk in (textwrap.wrap(line, width=108) or [""]):
                    pdf.cell(W, 3.5, chunk, fill=True, **NL)
            pdf.ln(2)

        # ════════════════════════════════════════════════════════════════════
        # Cover page
        # ════════════════════════════════════════════════════════════════════
        pdf.add_page()

        pdf.set_fill_color(20, 30, 60)
        pdf.rect(0, 0, 210, 30, style="F")
        pdf.set_font("Helvetica", "B", 17)
        pdf.set_text_color(255, 255, 255)
        pdf.set_xy(15, 9)
        pdf.cell(0, 10, "IAM Policy Analysis Report", **NL)

        pdf.set_xy(15, 33)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(100, 110, 130)
        pdf.cell(0, 4, s(f"Analysis #{self.analysis_id}   |   Generated: {self.generated_at}"), **NL)
        pdf.ln(3)

        # Risk badge
        section("Risk Assessment")
        r, g, b = _SEV_RGB.get(self.severity, (107, 114, 128))
        pdf.set_fill_color(r, g, b)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(70, 11, s(f"  {self.risk_score:.1f} / 10   {self.severity}"), fill=True, **NL)
        pdf.ln(3)

        # Stats — 3 per row, each "[ N ] Label"
        stats = [
            ("Statements",       self.summary.get("total_statements", 0)),
            ("Allowed Actions",  self.summary.get("total_actions", 0)),
            ("Dangerous Actions",self.summary.get("dangerous_actions_count", 0)),
            ("Wildcard Resources",self.summary.get("wildcard_resources_count", 0)),
            ("Findings",         self.findings_count),
            ("Privesc Paths",    self.privesc_paths_count),
        ]
        pdf.set_draw_color(200, 210, 225)
        for idx, (label, val) in enumerate(stats):
            pdf.set_fill_color(240, 244, 252)
            pdf.set_font("Helvetica", "B", 12)
            pdf.set_text_color(20, 30, 60)
            pdf.cell(18, 9, str(val), border=1, fill=True, align="C", **CONT)
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(60, 70, 90)
            # 3 cols: each takes 60mm; after 3rd go to next line
            end = (idx % 3 == 2) or (idx == len(stats) - 1)
            pdf.cell(42, 9, " " + label, border="B", **(NL if end else CONT))
            if end and idx != len(stats) - 1:
                pass  # auto newline handled by NL
        pdf.ln(3)

        # Policy JSON
        if self.policy:
            section("IAM Policy (Input)")
            code_block(json.dumps(self.policy, indent=2))

        # ════════════════════════════════════════════════════════════════════
        # Security Findings — continuous flow (no forced page break)
        # ════════════════════════════════════════════════════════════════════
        section(f"Security Findings  ({self.findings_count})")
        if self.findings:
            # Cols: Sev(22) Type(38) Resource(40) Message(80)
            table_hdr(("Severity", 22), ("Type", 38), ("Resource", 40), ("Message", 80))
            for f in self.findings:
                fsev = f.get("severity", "")
                ftype = s(f.get("type", ""))
                fres = s(f.get("resource", ""))
                fmsg = s(f.get("message", ""))
                sev_badge(fsev, 22)
                pdf.cell(38, 5, ftype[:30], border="B", **CONT)
                pdf.cell(40, 5, fres[:30], border="B", **CONT)
                # message: first 80 chars in row, wrap remainder below
                pdf.cell(80, 5, fmsg[:70], border="B", **NL)
                if len(fmsg) > 70:
                    pdf.set_font("Helvetica", "", 7)
                    pdf.set_text_color(80, 80, 100)
                    pdf.cell(22 + 38 + 40, 4, "", **CONT)
                    pdf.multi_cell(80, 4, fmsg[70:210], **NL)
                    pdf.set_text_color(30, 30, 30)
        else:
            italic("No security findings detected.")

        # ════════════════════════════════════════════════════════════════════
        # Privilege Escalation Paths
        # ════════════════════════════════════════════════════════════════════
        section(f"Privilege Escalation Paths  ({self.privesc_paths_count})")
        if self.privesc_paths:
            for i, p in enumerate(self.privesc_paths, 1):
                src = s(p.get("source_node", ""))
                tgt = s(p.get("target_node", ""))
                subsection(f"Path {i}: {src} -> {tgt}")
                kv("Severity", p.get("severity", ""))
                kv("Description", p.get("description", ""))
                kv("Dangerous Actions", ", ".join(p.get("dangerous_actions", [])))
                nodes = " -> ".join(p.get("path_nodes", []))
                if nodes:
                    kv("Path Nodes", nodes)
                pdf.ln(1)
        else:
            italic("No privilege escalation paths detected.")

        # ════════════════════════════════════════════════════════════════════
        # AI Suggestions
        # ════════════════════════════════════════════════════════════════════
        section("AI-Generated Suggestions  (Google Gemini)")
        sugg = self.ai_suggestions
        if sugg and not sugg.get("error"):
            changes = sugg.get("changes", [])
            if changes:
                subsection(f"Recommended Changes  ({len(changes)})")
                for i, ch in enumerate(changes, 1):
                    if isinstance(ch, dict):
                        reason = ch.get("reason", "")
                        original = str(ch.get("original", ""))
                        replacement = ch.get("replacement", [])
                        repl_str = ", ".join(replacement) if isinstance(replacement, list) else str(replacement)
                        pdf.set_font("Helvetica", "B", 8)
                        pdf.set_text_color(30, 30, 50)
                        pdf.multi_cell(W, 5, s(f"{i}. {reason}"), **NL)
                        kv("   Original", original)
                        kv("   Replace with", repl_str)
                        pdf.ln(1)
                    elif isinstance(ch, str) and ch.strip():
                        pdf.set_font("Helvetica", "", 8)
                        pdf.set_text_color(40, 40, 40)
                        pdf.multi_cell(W, 5, s(f"  {i}. {ch}"), **NL)

            lp = sugg.get("least_privilege_policy")
            if lp:
                subsection("Suggested Least-Privilege Policy")
                code_block(json.dumps(lp, indent=2))
        else:
            err = s(sugg.get("error", "unavailable") if sugg else "unavailable")
            italic(f"AI suggestions not available: {err}")

        # ════════════════════════════════════════════════════════════════════
        # Compliance Summary
        # ════════════════════════════════════════════════════════════════════
        if self.compliance_results:
            fw_labels = {
                "cis": "CIS AWS Benchmark v1.4",
                "nist": "NIST SP 800-53",
                "soc2": "SOC 2 CC6",
                "pci": "PCI-DSS v3.2",
                "iso27001": "ISO 27001",
            }
            section("Compliance Summary  (All Frameworks)")

            # Overview table
            table_hdr(("Framework", 58), ("Score", 18), ("Passed", 18),
                      ("Failed", 18), ("Warnings", 20), ("N/A", 16), ("Controls", 32))
            for fw_key, cr in self.compliance_results.items():
                score    = cr.get("score", 0)
                passed   = cr.get("passed", 0)
                failed   = cr.get("failed", 0)
                warnings = cr.get("warnings", 0)
                na       = cr.get("not_applicable", 0)
                total    = len(cr.get("controls", []))
                sr, sg, sb = (22, 163, 74) if score >= 80 else (217, 119, 6) if score >= 60 else (220, 38, 38)
                pdf.set_font("Helvetica", "", 8)
                pdf.set_text_color(30, 30, 30)
                pdf.cell(58, 5, fw_labels.get(fw_key, fw_key), border="B", **CONT)
                pdf.set_text_color(sr, sg, sb)
                pdf.set_font("Helvetica", "B", 8)
                pdf.cell(18, 5, f"{score}%", border="B", align="C", **CONT)
                pdf.set_text_color(22, 163, 74)
                pdf.set_font("Helvetica", "", 8)
                pdf.cell(18, 5, str(passed), border="B", align="C", **CONT)
                pdf.set_text_color(220, 38, 38)
                pdf.cell(18, 5, str(failed), border="B", align="C", **CONT)
                pdf.set_text_color(217, 119, 6)
                pdf.cell(20, 5, str(warnings), border="B", align="C", **CONT)
                pdf.set_text_color(100, 110, 130)
                pdf.cell(16, 5, str(na), border="B", align="C", **CONT)
                pdf.set_text_color(30, 30, 30)
                pdf.cell(32, 5, str(total), border="B", align="C", **NL)
            pdf.ln(4)

            # Per-framework detail tables
            for fw_key, cr in self.compliance_results.items():
                controls = cr.get("controls", [])
                if not controls:
                    continue
                subsection(f"{fw_labels.get(fw_key, fw_key)}  ({len(controls)} controls)")
                # Cols: ID(28) Title(56) Status(16) Risk(18) Details(62) — total 180
                _ID = 28
                _TI = 56
                _ST = 16
                _DT = 62
                table_hdr(("Control ID", _ID), ("Title", _TI), ("Status", _ST), ("Risk", 18), ("Details", _DT))
                _STATUS_LABEL = {
                    "PASS": "PASS",
                    "FAIL": "FAIL",
                    "WARNING": "WARN",
                    "NOT_APPLICABLE": "N/A",
                }
                for ctrl in controls:
                    status = ctrl.get("status", "")
                    st_r, st_g, st_b = {
                        "PASS": (22, 163, 74),
                        "FAIL": (220, 38, 38),
                        "WARNING": (217, 119, 6),
                        "NOT_APPLICABLE": (150, 150, 160),
                    }.get(status, (80, 80, 80))
                    risk    = ctrl.get("risk_level", "")
                    details = s("; ".join(ctrl.get("details", [])))
                    cid     = s(ctrl.get("control_id", ""))
                    title   = s(ctrl.get("title", ""))
                    st_lbl  = _STATUS_LABEL.get(status, status[:6])
                    pdf.set_font("Helvetica", "", 7)
                    pdf.set_text_color(30, 30, 30)
                    pdf.cell(_ID, 5, cid[:18], border="B", **CONT)
                    pdf.cell(_TI, 5, title[:44], border="B", **CONT)
                    pdf.set_text_color(st_r, st_g, st_b)
                    pdf.set_font("Helvetica", "B", 7)
                    pdf.cell(_ST, 5, st_lbl, border="B", **CONT)
                    pdf.set_text_color(30, 30, 30)
                    pdf.set_font("Helvetica", "", 7)
                    pdf.cell(18, 5, risk, border="B", **CONT)
                    # Details: fit first chunk in row, wrap rest on next line
                    first = details[:68]
                    pdf.cell(_DT, 5, first, border="B", **NL)
                    rest = details[68:]
                    while rest:
                        chunk, rest = rest[:75], rest[75:]
                        pdf.set_font("Helvetica", "", 7)
                        pdf.set_text_color(30, 30, 30)
                        pdf.cell(_ID + _TI + _ST + 18, 4, "", **CONT)
                        pdf.cell(_DT, 4, chunk, **NL)
                pdf.ln(2)

        # ════════════════════════════════════════════════════════════════════
        # Recommendations
        # ════════════════════════════════════════════════════════════════════
        section("Recommendations")
        recs = self.recommendations or ["Policy follows least-privilege principles. No changes required."]
        for i, rec in enumerate(recs, 1):
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_text_color(30, 30, 50)
            pdf.cell(7, 5, f"{i}.", **CONT)
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(30, 30, 30)
            pdf.multi_cell(W - 7, 5, s(rec), **NL)
            pdf.ln(0.5)

        # Footer
        pdf.ln(5)
        pdf.set_draw_color(190, 200, 215)
        pdf.line(15, pdf.get_y(), 195, pdf.get_y())
        pdf.ln(2)
        pdf.set_font("Helvetica", "I", 7)
        pdf.set_text_color(160, 165, 175)
        pdf.cell(0, 4, "IAM Policy Analyzer  |  Confidential Security Report  |  Do not distribute", **NL)

        return bytes(pdf.output())


class ReportBuilder:
    """Build a ReportData from an analysis record's components."""

    def __init__(
        self,
        analysis_id: int,
        graph: GraphData,
        findings: list[dict],
        suggestions: dict,
        risk_score: float,
        severity: str,
        created_at: str,
        policy: dict | None = None,
        compliance_results: dict | None = None,
    ) -> None:
        self._analysis_id = analysis_id
        self._graph = graph
        self._findings = findings
        self._suggestions = suggestions
        self._risk_score = risk_score
        self._severity = severity
        self._created_at = created_at
        self._policy = policy or {}
        self._compliance_results = compliance_results or {}

    def build(self) -> ReportData:
        now = datetime.now(timezone.utc).isoformat()

        privesc_paths = self._detect_privesc()
        summary = self._compute_summary()
        recommendations = self._build_recommendations(privesc_paths)

        return ReportData(
            analysis_id=self._analysis_id,
            generated_at=now,
            risk_score=self._risk_score,
            severity=self._severity,
            findings_count=len(self._findings),
            privesc_paths_count=len(privesc_paths),
            summary=summary,
            findings=self._findings,
            privesc_paths=privesc_paths,
            recommendations=recommendations,
            policy=self._policy,
            ai_suggestions=self._suggestions,
            compliance_results=self._compliance_results,
        )

    def _detect_privesc(self) -> list[dict]:
        detector = PrivescDetector(self._graph)
        paths = detector.detect()
        return [
            {
                "source_node": p.source_node,
                "target_node": p.target_node,
                "path_nodes": p.path_nodes,
                "dangerous_actions": p.dangerous_actions,
                "severity": p.severity,
                "description": p.description,
            }
            for p in paths
        ]

    def _compute_summary(self) -> dict:
        node_types: dict[str, int] = {}
        for n in self._graph.nodes:
            node_types[n.node_type] = node_types.get(n.node_type, 0) + 1

        action_nodes = [n for n in self._graph.nodes if n.node_type == "action"]
        allow_actions = [
            n for n in action_nodes
            if n.metadata.get("effect", "Allow") == "Allow"
        ]
        dangerous = [n for n in allow_actions if n.label in DANGEROUS_ACTIONS]
        resource_nodes = [n for n in self._graph.nodes if n.node_type == "resource"]
        wildcards = [n for n in resource_nodes if n.label in WILDCARD_RESOURCES]

        return {
            "total_statements": node_types.get("statement", 0),
            "total_actions": len(allow_actions),
            "dangerous_actions_count": len(dangerous),
            "wildcard_resources_count": len(wildcards),
        }

    def _build_recommendations(self, privesc_paths: list[dict]) -> list[str]:
        recs: list[str] = []

        changes = self._suggestions.get("changes", [])
        if isinstance(changes, list):
            for change in changes:
                if isinstance(change, dict):
                    reason = change.get("reason", "")
                    original = change.get("original", "")
                    replacement = change.get("replacement", [])
                    if isinstance(replacement, list):
                        replacement_str = ", ".join(replacement)
                    else:
                        replacement_str = str(replacement)
                    if reason:
                        recs.append(f"{reason}: replace '{original}' with [{replacement_str}]")
                elif isinstance(change, str) and change.strip():
                    recs.append(change.strip())

        seen_actions: set[str] = set()
        for path in privesc_paths:
            for action in path.get("dangerous_actions", []):
                if action not in seen_actions:
                    seen_actions.add(action)
                    recs.append(
                        f"Restrict '{action}' to specific resources rather than wildcard (*)"
                    )

        summary = self._compute_summary()
        if summary["wildcard_resources_count"] > 0 and not privesc_paths:
            recs.append(
                "Replace wildcard (*) resources with specific ARNs to follow least-privilege principle"
            )

        if not recs:
            recs.append("Policy follows least-privilege principles. No immediate changes required.")

        return recs
