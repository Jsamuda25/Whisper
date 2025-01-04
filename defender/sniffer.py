from scapy.all                      import sniff
import                                     sys

from .intrusion_detector             import IntrusionDetector

class PacketSniffer:
    def __init__(self, interface="Wi-Fi"):
        self.interface = interface
        self.detector = IntrusionDetector()


    def packet_callback(self, packet):
        """Callback function to process each captured packet."""
        try:
            if packet.haslayer("IP"):
                # Get the IP layer information (source and destination IP)
                src_ip  = packet["IP"].src
                dest_ip = packet["IP"].dst
                print(f"Source IP: {src_ip} -> Destination IP: {dest_ip}")

                # Check if the packet has a transport layer (TCP/UDP)
                if packet.haslayer("TCP"):
                    src_port     = packet["TCP"].sport  # Source port
                    dest_port   = packet["TCP"].dport  # Destination port
                    print(f"Source Port: {src_port} -> Destination Port: {dest_port}")

                elif packet.haslayer("UDP"):
                    src_port    = packet["UDP"].sport  # Source port
                    dest_port   = packet["UDP"].dport  # Destination port
                    print(f"Source Port: {src_port} -> Destination Port: {dest_port}")

            # Call intrusion detection functions
            self.detector.signature_based_detection(packet)
            self.detector.detect_port_scan(packet)
            self.detector.detect_dos_attack(packet)

            print("_________\n")

        except Exception as e:
            print(f"Error processing packet: {e}")

    def start(self):
        """Start sniffing packets."""
        print(f"Sniffer started on interface {self.interface}. Press Ctrl+C to stop.")

        # Start sniffing packets
        sniff(iface=self.interface, prn=self.packet_callback, store=False, count=20)
