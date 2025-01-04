from flask_app import create_app
from defender.sniffer import PacketSniffer
import threading
import signal
import sys


def begin_sniffing():
    """Start the packet sniffer."""
    try:
        sniffer = PacketSniffer(interface="Wi-Fi")
        sniffer.start()
    except Exception as e:
        print(f"Error starting the packet sniffer: {e}")


def signal_handler(sig, frame):
    """Handle graceful shutdown of the Flask app and background threads."""
    print("Gracefully shutting down...")
    sys.exit(0)


if __name__ == "__main__":
    # Set up signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)

    # Start the packet sniffer in a background thread
    sniffer_thread = threading.Thread(target=begin_sniffing, daemon=True)
    sniffer_thread.start()

    # Start the Flask app
    app = create_app()
    app.run(debug=True, port=5000)
