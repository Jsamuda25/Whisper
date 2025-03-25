from flask import Blueprint, render_template, jsonify
import os
import json

app_routes = Blueprint("app_routes", __name__)

LOG_FILE = "logs/alerts.log"

@app_routes.route("/")  # Ensure homepage works
def index():
    return render_template("index.html")

@app_routes.route("/logs")  # Fix: Add route decorator
def get_logs():
    """Return the last 100 lines from the log file as JSON."""
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()

        # Convert each log line from JSON string to dictionary
        log_entries = []
        for line in lines[-100:]:  # Only process the last 100 lines
            try:
                log_entries.append(json.loads(line.strip()))  # Parse JSON
            except json.JSONDecodeError:
                continue  # Skip invalid JSON lines

        return jsonify(log_entries)  # Return as JSON response

    return jsonify({"error": "Log file not found"}), 404
