from flask import Flask, jsonify, render_template, send_from_directory, send_file
import json
import os
from datetime import datetime
from io import BytesIO

# Fix: add project root to Python path (safe)
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# PDF generator
from parser.pdf_export import generate_pdf

app = Flask(__name__, template_folder="templates", static_folder="static")

# Path to report.json
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORT_PATH = os.path.abspath(os.path.join(BASE_DIR, "..", "output", "report.json"))

@app.route("/")
def index():
    return render_template("dashboard.html")

@app.route("/data/report")
def data_report():
    if not os.path.exists(REPORT_PATH):
        return jsonify({"ok": False, "error": "report.json not found"})

    try:
        with open(REPORT_PATH, "r", encoding="utf-8") as f:
            report = json.load(f)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

    summary = report.get("summary", {})
    alerts = report.get("alerts", []) or []
    correlations = report.get("correlations", []) or []
    timeline = report.get("timeline", []) or []

    # fallback for old reports
    if not timeline:
        for r in report.get("records", []):
            timeline.append({
                "timestamp": r.get("timestamp"),
                "type": "record",
                "severity": r.get("severity", "INFO"),
                "ip": r.get("ip"),
                "message": r.get("message")
            })

    return jsonify({
        "ok": True,
        "generated_at": summary.get("generated_at"),
        "summary": {
            "top_ips": summary.get("top_ips", []),
            "status_counts": summary.get("status_counts", []),
            "top_urls": summary.get("top_urls", []),
            "total_records": summary.get("total_records", 0)
        },
        "alerts": alerts,
        "correlations": correlations,
        "timeline": timeline
    })

# PDF Export
@app.route("/export/pdf")
def export_pdf():
    if not os.path.exists(REPORT_PATH):
        return "report.json not found", 404

    try:
        pdf_bytes = generate_pdf(REPORT_PATH)
        return send_file(
            pdf_bytes,
            mimetype="application/pdf",
            as_attachment=True,
            download_name="InsightLog_Report.pdf"
        )
    except Exception as e:
        return {"ok": False, "error": str(e)}, 500

@app.route("/static/<path:filename>")
def static_files(filename):
    return send_from_directory(os.path.join(app.root_path, "static"), filename)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
