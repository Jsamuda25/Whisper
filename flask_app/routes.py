from flask import Blueprint, jsonify, request
from defender.logger import ThreatLogger
import os
import json

app_routes = Blueprint("app_routes", __name__)

LOG_FILE = "logs/alerts.log"

@app_routes.route("/logs")
def get_logs():
    """Return log entries from the file as JSON."""
    print("Getting logs in flask API")
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
        
        logs = []
        for line in lines[-100:]:  # Only process the last 100 lines
            try:
                logs.append(json.loads(line.strip()))  # Parse JSON log entry
            except json.JSONDecodeError:
                continue 

        return jsonify(logs)

    return jsonify({"error": "No logs found"}), 404

@app_routes.route("/api/logs", methods=["POST"])
def receive_log():


    """Receive log alerts from the sniffer and append them to the log file."""
    try:
        print("Received log alert in flask API")
        data = request.json
        if not data:
            return jsonify({"error": "Invalid log data"}), 400

        # Ensure logs directory exists
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

        print(f"Parsed JSON: {data}")

        # Append log entry to file
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(data) + "\n")

        return jsonify({"message": "Log received"}), 201
    
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"error": str(e)}), 500