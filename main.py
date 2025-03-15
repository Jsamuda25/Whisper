from flask_app import create_app
from defender.sniffer import PacketSniffer
import threading
import signal
import sys
from scapy.all import get_if_list

def get_default_interface():
    """Detect the correct network interface based on the environment."""
    interfaces = get_if_list()
    print(f"Available interfaces: {interfaces}")

    # WSL uses "eth0", fallback to first available interface
    return "eth0" if "eth0" in interfaces else (interfaces[0] if interfaces else None)

def begin_sniffing():
    """Start the packet sniffer."""
    try:
        interface = get_default_interface()
        if not interface:
            raise ValueError("No valid network interface found!")

        print(f"Starting packet sniffer on {interface}...")
        sniffer = PacketSniffer(interface=interface)
        sniffer.start()
    except Exception as e:
        print(f"Error starting the packet sniffer: {e}")

def signal_handler(sig, frame):
    print("\nGracefully shutting down...")
    sys.exit(0)

if __name__ == "__main__":
    # Set up signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)

    # Start the packet sniffer in a background thread
    sniffer_thread = threading.Thread(target=begin_sniffing, daemon=True)
    sniffer_thread.start()

    # Start the Flask app
    app = create_app()
    app.run(debug=True, port=5000, host="0.0.0.0")