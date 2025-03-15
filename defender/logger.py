import json
import logging
import time
import sys

class ThreatLogger:
    def __init__(self, log_file="logs/alerts.log", log_format="json"): 
        self.log_file   = log_file
        self.log_format = log_format

        # Configure the logging module
        logging.basicConfig(
            stream=sys.stdout,
            level=logging.INFO,
            format="%(message)s"
        )

    def log_alert(self, threat_type="", ip="", port="", severity=0, details=""):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = {
            "timestamp": timestamp,
            "threat_type": threat_type,
            "ip": ip,
            "port": port,
            "severity": severity,
            "details": details
        }

        if self.log_format == "json":
            logging.info(json.dumps(log_entry))
        else:
            log_message = f"{timestamp} | Threat: {threat_type} | Severity: {severity} | Ip:{ip} | Port: {port} | Details: {details}\n"
            logging.info(log_message)

    def log_info(self, message):
        logging.info(message)

    def log_error(self, message):
        logging.error(message)
