import json
import io
from datetime import datetime

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import Paragraph, Frame, Table, TableStyle, Image
from reportlab.lib import colors
from reportlab.lib.units import mm

import matplotlib.pyplot as plt


# ========== Chart Helpers ==========

def fig_to_png(fig):
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", dpi=140)
    plt.close(fig)
    buf.seek(0)
    return buf


def chart_top_ips(ips):
    if not ips:
        return None
    labels = [i[0] for i in ips]
    values = [i[1] for i in ips]

    fig, ax = plt.subplots(figsize=(5, 2))
    ax.bar(labels, values)
    ax.set_title("Top IPs by Activity")
    ax.set_ylabel("Hits")
    ax.tick_params(axis='x', rotation=30)
    plt.tight_layout()
    return fig_to_png(fig)


def chart_severity(alerts):
    if not alerts:
        return None
    sev_map = {}
    for a in alerts:
        s = (a.get("severity") or "UNKNOWN")
        sev_map[s] = sev_map.get(s, 0) + 1

    fig, ax = plt.subplots(figsize=(3, 2))
    ax.pie(sev_map.values(), labels=sev_map.keys(), autopct='%1.1f%%')
    ax.set_title("Alert Severity Breakdown")
    plt.tight_layout()
    return fig_to_png(fig)


def chart_top_urls(urls):
    if not urls:
        return None
    labels = [u[0] for u in urls]
    values = [u[1] for u in urls]

    fig, ax = plt.subplots(figsize=(5, 2))
    ax.barh(labels[::-1], values[::-1])
    ax.set_title("Most Accessed URLs")
    plt.tight_layout()
    return fig_to_png(fig)


# ========== PDF Generator ==========

def generate_pdf(report_path):
    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    summary = report.get("summary", {})
    alerts = report.get("alerts", [])
    correlations = report.get("correlations", [])
    timeline = report.get("timeline", [])

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    width, height = A4

    styles = getSampleStyleSheet()
    H1 = ParagraphStyle('H1', parent=styles['Heading1'], fontSize=20, spaceAfter=12)
    H2 = ParagraphStyle('H2', parent=styles['Heading2'], fontSize=14, spaceAfter=6)
    body = ParagraphStyle('body', parent=styles['BodyText'], fontSize=10, leading=14)

    # ---------- COVER PAGE ----------
    c.setFont("Helvetica-Bold", 26)
    c.drawString(40, height - 80, "INSIGHTLOG SECURITY REPORT")

    c.setFont("Helvetica", 12)
    c.drawString(40, height - 110, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    c.setFont("Helvetica", 10)
    c.drawString(40, height - 140, "This document summarizes log activity, alerts, correlations,")
    c.drawString(40, height - 155, "and anomalies detected by the InsightLog monitoring engine.")

    c.showPage()


    # ---------- SUMMARY PAGE ----------
    frame = Frame(40, 40, width - 80, height - 80, showBoundary=0)
    story = []

    story.append(Paragraph("Executive Summary", H1))
    story.append(Paragraph(
        "The following report provides an overview of log activity, detected threats, "
        "and correlated events captured by the InsightLog engine.", body))

    story.append(Paragraph("<br/><b>Activity Statistics</b>", H2))
    story.append(Paragraph(f"Total Records: {summary.get('total_records', 0)}", body))
    story.append(Paragraph(f"Total Alerts: {len(alerts)}", body))
    story.append(Paragraph(f"Correlation Events: {len(correlations)}", body))

    frame.addFromList(story, c)
    c.showPage()


    # ---------- VISUAL ANALYTICS PAGE ----------
    c.setFont("Helvetica-Bold", 18)
    c.drawString(40, height - 40, "Visual Analytics")

    top_ips_png = chart_top_ips(summary.get("top_ips", []))
    sev_png = chart_severity(alerts)
    url_png = chart_top_urls(summary.get("top_urls", []))

    y = height - 90

    if top_ips_png:
        img = Image(top_ips_png)
        img.drawHeight = 50 * mm
        img.drawWidth = 90 * mm
        img.drawOn(c, 40, y - 50 * mm)

    if sev_png:
        img = Image(sev_png)
        img.drawHeight = 50 * mm
        img.drawWidth = 70 * mm
        img.drawOn(c, 150*mm - 30, y - 50 * mm)

    y -= 65 * mm

    if url_png:
        img = Image(url_png)
        img.drawHeight = 45 * mm
        img.drawWidth = 140 * mm
        img.drawOn(c, 40, y - 45 * mm)

    c.showPage()


    # ---------- ALERTS PAGE ----------
    c.setFont("Helvetica-Bold", 18)
    c.drawString(40, height - 40, "Security Alerts")

    table_data = [["Severity", "Type", "Message"]]
    for a in alerts[:20]:
        table_data.append([
            a.get("severity", ""),
            a.get("type", ""),
            a.get("message", "")[:100]
        ])

    table = Table(table_data, colWidths=[60*mm, 40*mm, 80*mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.lightgrey),
        ("TEXTCOLOR", (0,0), (-1,0), colors.black),
        ("GRID", (0,0), (-1,-1), 0.3, colors.grey),
        ("FONT", (0,0), (-1,-1), "Helvetica"),
        ("FONTSIZE", (0,0), (-1,-1), 9),
    ]))

    tw, th = table.wrapOn(c, width - 80, height - 120)
    table.drawOn(c, 40, height - 100 - th)

    c.showPage()


    # ---------- CORRELATIONS PAGE ----------
    c.setFont("Helvetica-Bold", 18)
    c.drawString(40, height - 40, "Correlation Events")

    y = height - 80
    c.setFont("Helvetica", 10)

    if correlations:
        for corr in correlations:
            c.drawString(40, y, f"- {corr.get('message', '')}")
            y -= 14
            if y < 60:
                c.showPage()
                y = height - 80
    else:
        c.drawString(40, y, "No correlation events detected.")


    c.showPage()


    # ---------- TIMELINE PAGE ----------
    c.setFont("Helvetica-Bold", 18)
    c.drawString(40, height - 40, "Attack Timeline")

    y = height - 80
    c.setFont("Helvetica", 10)

    for ev in timeline[-25:]:
        line = f"{ev.get('timestamp')}  |  {ev.get('severity')}  |  {ev.get('message')[:90]}"
        c.drawString(40, y, line)
        y -= 14
        if y < 60:
            c.showPage()
            y = height - 80

    c.showPage()


    # ---------- END ----------
    c.save()
    buf.seek(0)
    return buf
