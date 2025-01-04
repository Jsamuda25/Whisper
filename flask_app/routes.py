from flask import Blueprint, render_template, jsonify
import os

app_routes = Blueprint("app_routes", __name__)

LOG_FILE = "logs/alerts.log"

@app_routes.route("/")
def index():
    """Render the dashboard homepage."""
    return render_template("index.html")

@app_routes.route("/logs")
def get_logs():
    """Return the last 100 lines from the log file as JSON."""
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
        return jsonify(lines[-100:])
    return jsonify({"error": "Log file not found"}), 404
