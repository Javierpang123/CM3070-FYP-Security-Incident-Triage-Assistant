"""
Generates a downloadable PDF triage report from a Flashpoint triage result dict
(the same structure produced by orchestrator.late_fusion_orchestrator).

Built with reportlab — pure Python, no external binary dependency, keeping the
system fully offline-capable per the project constraint.
"""

import io
import logging
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm

# Imports from ReportLab's platypus module that helps building documents
from reportlab.platypus import (SimpleDocTemplate, 
                                Paragraph, 
                                Spacer, 
                                Table, 
                                TableStyle, 
                                ListFlowable, 
                                ListItem)

# Set up a logger for this module
logger = logging.getLogger(__name__)

# Labels for severity levels
SEVERITY_LABELS = ['', 'Informational', 'Low', 'Medium', 'High', 'Critical']

# Labels for each modality
MODALITY_LABELS = {"text": "Findings extracted from text file",
                   "vision": "Findings extracted from photo",
                   "speech": "Findings extracted from voice note"}

# Function to build a PDF triage report from a triage result dict, returning raw PDF bytes
def build_pdf_report(triage: dict) -> bytes:

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            topMargin=2 * cm, bottomMargin=2 * cm,
                            leftMargin=2 * cm, rightMargin=2 * cm)

    # Define styles for the PDF content
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="FPTitle", fontSize=18, spaceAfter=6, leading=22))
    styles.add(ParagraphStyle(name="FPSubtitle", fontSize=10, textColor=colors.grey, spaceAfter=16))
    styles.add(ParagraphStyle(name="FPHeading", fontSize=13, spaceBefore=14, spaceAfter=8))
    styles.add(ParagraphStyle(name="FPBody", fontSize=10, leading=14))

    # Build the PDF content as a list of flowable elements
    fileContent = []

    # Header Title
    fileContent.append(Paragraph("Security Incident Triage Report by Flashpoint", 
                           styles["FPTitle"]))
    
    # Time generated subtitle
    fileContent.append(Paragraph(f"Generated Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 
                           styles["FPSubtitle"]))

    # Severity / classification / confidence summary table Section
    severity = triage.get("severity", 1)
    confidence = round(triage.get("confidence", 0.0) * 100)
    tactic = triage.get("attack_classification", "Unknown")

    # Summary table data
    summary_data = [["Severity", f"{severity}/5 — {SEVERITY_LABELS[severity]}"],
                    ["MITRE ATT&CK Classification", tactic],
                    ["Fused Confidence", f"{confidence}%"]]
                
    
    # Create a table for the summary data with specified column widths
    summary_table = Table(summary_data, colWidths=[6 * cm, 10 * cm])
    
    # Apply styling to the summary table
    summary_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f2f2f2")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    
    fileContent.append(summary_table)

    # Extracted entities Section
    entities = triage.get("entities", [])
    fileContent.append(Paragraph("Extracted Entities:", styles["FPHeading"]))
    if entities:
        fileContent.append(Paragraph(", ".join(entities), styles["FPBody"]))
    else:
        fileContent.append(Paragraph("No entities were extracted.", styles["FPBody"]))

    # Recommended actions Section
    actions = triage.get("recommended_actions", [])
    fileContent.append(Paragraph("Recommended Actions", styles["FPHeading"]))
    if actions:
        fileContent.append(ListFlowable(
            [ListItem(Paragraph(a, styles["FPBody"])) for a in actions],
            bulletType="1",
        ))
    else:
        fileContent.append(Paragraph("No recommended actions available.", styles["FPBody"]))

    # Per-modality breakdown Section
    fileContent.append(Paragraph("Modality Breakdown:", styles["FPHeading"]))
    breakdown = triage.get("modality_breakdown", {})
    weights = triage.get("fusion_weights", {})

    # Loop through each modality and add its details to the PDF
    for key, label in MODALITY_LABELS.items():
        data = breakdown.get(key)
        fileContent.append(Paragraph(f"<b>{label}</b>", styles["FPBody"]))

        # If data exists for the modality, display its details
        if data:
            weight = weights.get(key)
            weight_str = f"{round(weight * 100)}%" if weight is not None else "—"
            detail = (
                f"Confidence: {round(data.get('confidence', 0.0) * 100)}% | "
                f"Tactic: {data.get('attack_classification', 'Unknown')} | "
                f"Fusion weight: {weight_str}<br/>"
                f"{data.get('summary', '')}"
            )
            fileContent.append(Paragraph(detail, styles["FPBody"]))
        
        # Else, tell user no input was provided
        else:
            fileContent.append(Paragraph("No input provided.", styles["FPBody"]))

        fileContent.append(Spacer(1, 8))

    
    # Error Section, if fusion has any error
    if triage.get("error"):
        fileContent.append(Paragraph("Notes", styles["FPHeading"]))
        fileContent.append(Paragraph(f"{triage['error']}", styles["FPBody"]))

    doc.build(fileContent)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes