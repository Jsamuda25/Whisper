from sniffer import PacketSniffer 
from intrusion_detector import IntrusionDetector  

def main():
    # Create an instance of PacketSniffer and start sniffing
    sniffer = PacketSniffer(interface="Wi-Fi")
    sniffer.start()

if __name__ == "__main__":
    main()
