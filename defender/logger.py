import json
import logging
import time
import sys
import os

class ThreatLogger:
    def __init__(self,log_format="json",  log_file="logs/alerts.log"): 
        self.log_file   = log_file
        self.log_format = log_format

        # Ensure the logs directory exists
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)

        # Configure the logging module to write to a file
        logging.basicConfig(
            filename=self.log_file,  # Write to file
            level=logging.INFO,
            format="%(message)s",
            filemode="a"  # Append mode
        )

    def log_alert(self, threat_type="", ip="", port="", severity=0, details=""):
        print(f"LOGGING ALERT: {threat_type} | IP: {ip} | Port: {port} | Severity: {severity}")
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = {
            "timestamp": timestamp,
            "threat_type": threat_type,
            "ip": ip,
            "port": port,
            "severity": severity,
            "details": details
        }

        logging.info(json.dumps(log_entry))  # Log JSON entry
    

    def log_info(self, message):
        logging.info(message)

    def log_error(self, message):
        logging.error(message)
