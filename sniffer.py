from scapy.all import sniff, get_if_list
import                          signal
import                          sys
from intrusion_detector import detect_port_scan, detect_dos_attack, signature_based_detection #import IDS functions

# Get the list of available interfaces
interfaces = get_if_list()

# Handle graceful exit
def signal_handler(sig, frame):
    print("Gracefully stopping the packet sniffer...")
    sys.exit(0)

# Callback function for each captured packet
def packet_callback(packet):
    
    try:
        if packet.haslayer("IP"):
            # Get the IP layer information (source and destination IP)
            src_ip = packet["IP"].src
            dest_ip = packet["IP"].dst
            print(f"Source IP: {src_ip} -> Destination IP: {dest_ip}")

            # Check if the packet has a transport layer (TCP/UDP)
            if packet.haslayer("TCP"):
                src_port = packet["TCP"].sport  # Source port
                dest_port = packet["TCP"].dport  # Destination port
                print(f"Source Port: {src_port} -> Destination Port: {dest_port}")

            elif packet.haslayer("UDP"):
                src_port = packet["UDP"].sport  # Source port
                dest_port = packet["UDP"].dport  # Destination port
                print(f"Source Port: {src_port} -> Destination Port: {dest_port}")

        signature_based_detection(packet)
        detect_port_scan(packet)  # Check for port scanning
        detect_dos_attack(packet)  # Check for DoS attacks

        print("_________\n")

    except Exception as e:
        print(f"Error processing packet:{e}")

# Start sniffing packets
def start_sniffer():
    print("Sniffer started. Press Ctrl+C to stop.")
    
    # Set up signal handler for graceful exit
    signal.signal(signal.SIGINT, signal_handler)
    
    # Sniff indefinitely (without a limit on the number of packets)
    sniff(iface="Wi-Fi", prn=packet_callback, store=False, count = 20)



if __name__ == "__main__":
    start_sniffer()

