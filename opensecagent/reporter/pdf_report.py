# OpenSecAgent - PDF report generation for vulnerability notifications
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any


def generate_vulnerability_pdf(
    finding: dict[str, Any],
    threat_id: str,
    output_path: str | Path,
    host_context: dict[str, Any] | None = None,
) -> Path:
    """Generate a PDF report for a vulnerability finding. Returns path to PDF."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib import colors
    except ImportError:
        # Fallback: write a text file with .pdf extension (viewable as text)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            f.write(f"OpenSecAgent Vulnerability Report\n")
            f.write(f"Threat ID: {threat_id}\n")
            f.write(f"Generated: {datetime.utcnow().isoformat()}Z\n\n")
            f.write(f"Title: {finding.get('title', '')}\n")
            f.write(f"Severity: {finding.get('severity', '')}\n\n")
            f.write(f"Description:\n{finding.get('description', '')}\n")
        return path

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(str(path), pagesize=A4, rightMargin=inch, leftMargin=inch, topMargin=inch, bottomMargin=inch)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("OpenSecAgent — Vulnerability Report", styles["Title"]))
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph(f"Threat ID: {threat_id}", styles["Normal"]))
    story.append(Paragraph(f"Generated: {datetime.utcnow().isoformat()}Z", styles["Normal"]))
    story.append(Spacer(1, 0.3 * inch))

    story.append(Paragraph(f"<b>Title:</b> {finding.get('title', 'N/A')}", styles["Normal"]))
    story.append(Paragraph(f"<b>Severity:</b> {finding.get('severity', 'N/A')}", styles["Normal"]))
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph("<b>Description</b>", styles["Heading2"]))
    story.append(Paragraph((finding.get("description") or "N/A").replace("\n", "<br/>"), styles["Normal"]))
    story.append(Spacer(1, 0.2 * inch))

    if finding.get("evidence"):
        story.append(Paragraph("<b>Evidence</b>", styles["Heading2"]))
        evidence = finding.get("evidence", {})
        if isinstance(evidence, dict):
            data = [["Key", "Value"]]
            for k, v in list(evidence.items())[:20]:
                data.append([str(k), str(v)[:200]])
            t = Table(data)
            t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.grey), ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke)]))
            story.append(t)
        else:
            story.append(Paragraph(str(evidence)[:1000], styles["Normal"]))
        story.append(Spacer(1, 0.2 * inch))

    if host_context:
        story.append(Paragraph("<b>Host context</b>", styles["Heading2"]))
        story.append(Paragraph(f"Hostname: {host_context.get('hostname', 'N/A')}", styles["Normal"]))
        story.append(Paragraph(f"OS: {host_context.get('os', '')} {host_context.get('os_release', '')}", styles["Normal"]))

    doc.build(story)
    return path
