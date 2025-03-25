from scapy.all import sniff
import sys

from .intrusion_detector import IntrusionDetector
from .logger import ThreatLogger  # Fix spacing issue in import

class PacketSniffer:
    def __init__(self, interface="Wi-Fi", logger=None):
        self.interface = interface
        self.detector = IntrusionDetector()
        self.logger = logger if logger else ThreatLogger()  # Logger instance

    def packet_callback(self, packet):
        """Callback function to process each captured packet."""
        try:
            if packet.haslayer("IP"):
                # Get the IP layer information (source and destination IP)
                src_ip = packet["IP"].src
                dest_ip = packet["IP"].dst
                print(f"Source IP: {src_ip} -> Destination IP: {dest_ip}")

                src_port = dest_port = None
                # Check if the packet has a transport layer (TCP/UDP)
                if packet.haslayer("TCP"):
                    src_port = packet["TCP"].sport
                    dest_port = packet["TCP"].dport
                    print(f"Source Port: {src_port} -> Destination Port: {dest_port}")

                elif packet.haslayer("UDP"):
                    src_port = packet["UDP"].sport
                    dest_port = packet["UDP"].dport
                    print(f"Source Port: {src_port} -> Destination Port: {dest_port}")

                # Call intrusion detection functions and log alerts
                if self.detector.signature_based_detection(packet):
                    self.logger.log_alert(
                        threat_type="Signature Match",
                        ip=src_ip,
                        port=src_port if src_port else "N/A",
                        severity=5,
                        details="Potential malicious packet detected"
                    )

                if self.detector.detect_port_scan(packet):
                    self.logger.log_alert(
                        threat_type="Port Scan",
                        ip=src_ip,
                        port=src_port if src_port else "N/A",
                        severity=4,
                        details="Possible port scanning activity"
                    )

                if self.detector.detect_dos_attack(packet):
                    self.logger.log_alert(
                        threat_type="DoS Attack",
                        ip=src_ip,
                        port=src_port if src_port else "N/A",
                        severity=6,
                        details="Denial-of-Service attack detected"
                    )

                print("_________\n")

        except Exception as e:
            print(f"Error processing packet: {e}")
            self.logger.log_error(f"Error processing packet: {e}")

    def start(self):
        """Start sniffing packets."""
        print(f"Sniffer started on interface {self.interface}. Press Ctrl+C to stop.")

        # Start sniffing packets
        sniff(iface=self.interface, prn=self.packet_callback, store=False)
