from sniffer import PacketSniffer  # Import PacketSniffer from sniffer.py
from intrusion_detector import IntrusionDetector  # Import IntrusionDetector from intrusion_detector.py

def main():
    # Create an instance of PacketSniffer and start sniffing
    sniffer = PacketSniffer(interface="Wi-Fi")
    sniffer.start()

if __name__ == "__main__":
    main()
