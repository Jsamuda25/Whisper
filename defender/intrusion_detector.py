import time
import smtplib
import os
import json
from email.mime.multipart           import MIMEMultipart
from email.mime.text                import MIMEText
from dotenv                         import load_dotenv

from scapy.layers.inet              import IP, TCP
from scapy.layers.dns               import DNS
from scapy.packet                   import Raw
from .logger                         import ThreatLogger

# Load the .env file
load_dotenv()

class IntrusionDetector:
    def __init__(self):
        # Load environment variables
        self.app_password = os.getenv("APP_PASSWORD")
        self.sender_email = os.getenv("SENDER_EMAIL")
        self.receiver_email = os.getenv("RECEIVER_EMAIL")
        
        # Connection attempt dictionaries
        self.connection_attempts = {}
        self.connection_attempts_scan = {}

        # Thresholds
        self.SCAN_THRESHOLD = 5
        self.SCAN_TIME_LIMIT = 20  # secs
        self.DOS_THRESHOLD = 100
        self.DOS_TIME_LIMIT = 30  # secs

        # Threat logger
        self.logger = ThreatLogger()

        print(f"Receiver Email: {self.receiver_email}")

        self.signature = ""

    def set_signature(self, sig):
        self.signature = sig
    
    def get_signature(self):
        return self.signature

    def send_alert(self, message):
        """Send an alert via email."""
        msg = MIMEMultipart()
        msg['From'] = self.sender_email
        msg['To'] = self.receiver_email
        msg['Subject'] = "Alert: Suspicious Activity Detected"
        msg.attach(MIMEText(message, 'plain'))

        try:
            with smtplib.SMTP("smtp.gmail.com", 587) as server:
                server.starttls()
                server.login(self.sender_email, self.app_password)
                server.sendmail(self.sender_email, self.receiver_email, msg.as_string())
                server.quit()
            print(f"Alert sent: {message}")
        except Exception as e:
            print(f"Error sending alert: {e}")

    def detect_port_scan(self, packet):
        """Detect potential port scans."""
        try:
            if packet.haslayer(IP) and packet.haslayer(TCP):
                ip_src = packet[IP].src
                tcp_dport = packet[TCP].dport

                if ip_src not in self.connection_attempts_scan:
                    self.connection_attempts_scan[ip_src] = {}

                if tcp_dport not in self.connection_attempts_scan[ip_src]:
                    self.connection_attempts_scan[ip_src][tcp_dport] = {"count": 0, "last_time": time.time()}

                current_time = time.time()
                self.connection_attempts_scan[ip_src][tcp_dport]["count"] += 1

                if self.connection_attempts_scan[ip_src][tcp_dport]["count"] > self.SCAN_THRESHOLD:
                    if current_time - self.connection_attempts_scan[ip_src][tcp_dport]["last_time"] < self.SCAN_TIME_LIMIT:
                        alert_message = f"Port scan detected! IP: {ip_src} scanning port {tcp_dport}"
                        print(alert_message)
                        # self.send_alert(alert_message)
                        self.logger.log_alert(threat_type="Port Scan", ip=ip_src, port=tcp_dport, severity=1, details=alert_message)
                        self.connection_attempts_scan[ip_src][tcp_dport]["count"] = 0

                self.connection_attempts_scan[ip_src][tcp_dport]["last_time"] = current_time
        except Exception as e:
            print(f"Error in detect_port_scan: {e}")

    def detect_dos_attack(self, packet):
        """Detect potential DoS attacks."""
        try:
            if packet.haslayer(IP):
                ip_src = packet[IP].src

                if ip_src not in self.connection_attempts:
                    self.connection_attempts[ip_src] = {"count": 0, "last_time": time.time()}

                current_time = time.time()
                self.connection_attempts[ip_src]["count"] += 1

                if self.connection_attempts[ip_src]["count"] > self.DOS_THRESHOLD:
                    if current_time - self.connection_attempts[ip_src]["last_time"] < self.DOS_TIME_LIMIT:
                        alert_message = f"DoS attack detected! IP: {ip_src}"
                        print(alert_message)
                        # self.send_alert(alert_message)
                        self.logger.log_alert(threat_type="Denial of Service", ip=ip_src, severity=1, details=alert_message)
                        self.connection_attempts[ip_src]["count"] = 0
                else:
                    if current_time - self.connection_attempts[ip_src]["last_time"] >= self.DOS_TIME_LIMIT:
                        self.connection_attempts[ip_src]["count"] = 1

                self.connection_attempts[ip_src]["last_time"] = current_time
        except Exception as e:
            print(f"Error in detect_dos_attack: {e}")

    def signature_based_detection(self, packet):
        """Perform signature-based detection."""
        try:
            with open('signatures.json') as f:
                data = json.load(f)
                blocklist = data["blocklist_ip"]
                payloads = data["malicious_payloads"]
                malicious_domains = data["malicious_domains"]

            self.flag_source_ip(packet, blocklist)
            self.flag_malicious_payloads(packet, payloads)
            self.flag_malicious_domains(packet, malicious_domains)
            self.logger.log_alert(threat_type=self.get_signature(), severity=1, details=f"Signature-based detection flagged packet: \n {packet.summary()}.")

        except Exception as e:
            print(f"Error in signature_based_detection: {e}")

    def flag_source_ip(self, packet, blocklist):
        """Flag packets with source IPs from the blocklist."""
        try:
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                if src_ip in blocklist:
                    print(f"Flagged source IP detected: {src_ip}!")
                    self.set_signature("Flagged Source IP")

        except Exception as e:
            print(f"Error in flag_source_ip: {e}")

    def flag_malicious_payloads(self, packet, payloads):
        """Flag packets with malicious payloads."""
        try:
            if packet.haslayer(Raw):
                raw_data = bytes(packet[Raw].load)
                for pattern in payloads:
                    if pattern in str(raw_data):
                        print(f"Alert! Malicious payload detected: {pattern}")
                        self.set_signature("Malicious Payload")
                        break
        except Exception as e:
            print(f"Error in flag_malicious_payloads: {e}")

    def flag_malicious_domains(self, packet, malicious_domains):
        """Flag packets with domains from the malicious domain list."""
        try:
            if packet.haslayer(DNS):
                domain_name = packet[DNS].qd.qname.decode()
                if domain_name in malicious_domains:
                    print(f"Alert! Malicious domain detected: {domain_name}")
                    self.set_signature("Suspicious Domain Name")
        except Exception as e:
            print(f"Error in flag_malicious_domains: {e}")
