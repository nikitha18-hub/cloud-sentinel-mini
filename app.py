import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from flask import Flask, jsonify, render_template, request, send_file

from scanner import calculate_score, run_scan, validate_config


ROOT_DIR = Path(__file__).resolve().parent
REPORTS_DIR = ROOT_DIR / "reports"
RESULT_FIELDS = ("check_name", "status", "risk_level", "recommendation")
VALID_STATUSES = {"SECURE", "RISK DETECTED", "NOT CHECKED"}
VALID_RISK_LEVELS = {"HIGH", "MEDIUM"}

app = Flask(
    __name__,
    template_folder="dashboard/templates",
    static_folder="dashboard",
    static_url_path="/static",
)


@app.get("/")
def home():
    return render_template("index.html")


@app.get("/api/sample")
def sample_config():
    sample_path = ROOT_DIR / "data" / "sample_config.json"
    with sample_path.open(encoding="utf-8") as sample_file:
        return jsonify(json.load(sample_file))


@app.post("/api/scan")
def scan():
    if not request.is_json:
        return jsonify({"error": "Send the configuration as JSON."}), 400

    config = request.get_json(silent=True)
    try:
        validate_config(config)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400

    results = run_scan(config)
    return jsonify(
        {
            "score": calculate_score(results),
            "risks": sum(item["status"] == "RISK DETECTED" for item in results),
            "secure": sum(item["status"] == "SECURE" for item in results),
            "not_checked": sum(item["status"] == "NOT CHECKED" for item in results),
            "results": results,
        }
    )


@app.post("/api/report")
def report():
    if not request.is_json:
        return jsonify({"error": "Send report results as JSON."}), 400

    payload = request.get_json(silent=True)
    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, list) or not results:
        return jsonify({"error": "Provide a non-empty results list."}), 400

    for result in results:
        if not isinstance(result, dict) or any(
            not isinstance(result.get(field), str) for field in RESULT_FIELDS
        ):
            return jsonify({"error": "Each result must contain all four text fields."}), 400
        if result["status"] not in VALID_STATUSES:
            return jsonify({"error": "Each result must have a valid status."}), 400
        if result["risk_level"] not in VALID_RISK_LEVELS:
            return jsonify({"error": "Each result must have a valid risk level."}), 400

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_path = REPORTS_DIR / f"cloud_sentinel_report_{timestamp}_{uuid.uuid4().hex[:8]}.csv"
    pd.DataFrame(results, columns=RESULT_FIELDS).to_csv(report_path, index=False)
    return send_file(report_path, as_attachment=True, download_name=report_path.name, mimetype="text/csv")


if __name__ == "__main__":
    app.run(debug=True)