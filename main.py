import sys
import os
import threading
import signal
import time
from scapy.all import get_if_list, ifaces
from flask_app.app import app, start_sniffer
from defender.sniffer import PacketSniffer
from defender.logger import ThreatLogger  # Ensure logger is imported

class PacketSnifferApp:
    def __init__(self):
        self.interface = None
        self.logger = ThreatLogger()  # Initialize logger

    def get_network_interface(self):
        """Prompt the user to select a valid network interface with readable names."""
        interfaces = get_if_list()  # Get list of interfaces
        iface_details = [ifaces[iface] for iface in interfaces]  # Get detailed info

        print("\nAvailable network interfaces:")
        for idx, iface in enumerate(iface_details):
            print(f"{idx}: {iface.name} ({iface.mac})")  # Show name + MAC address

        while True:
            try:
                choice = int(input("\nSelect the network interface (number): "))
                if 0 <= choice < len(iface_details):
                    self.interface = iface_details[choice].name  # Use the human-readable name
                    self.logger.log_info(f"Selected network interface: {self.interface}")
                    return
                print("Invalid choice. Please select a valid number.")
            except ValueError:
                print("Invalid input. Please enter a number.")

    def start_sniffer(self):
        """Start the packet sniffer."""
        try:
            self.get_network_interface()
            sniffer_thread = threading.Thread(target=start_sniffer, args=(self.interface,), daemon=True)
            sniffer_thread.start()
            self.logger.log_info(f"Starting packet sniffer on {self.interface}...")
            print(f"Starting packet sniffer on {self.interface}...")
        except Exception as e:
            self.logger.log_error(f"Error starting sniffer: {e}")
            print(f"Unexpected error: {e}")

def signal_handler(sig, frame):
    """Handles Ctrl+C to cleanly exit the program."""
    print("\nStopping packet sniffer and Flask app...")
    os._exit(0)  # Forcefully exit all threads and processes

if __name__ == "__main__":
    # Register Ctrl+C handler
    signal.signal(signal.SIGINT, signal_handler)

    # Initialize and start the packet sniffer
    app_instance = PacketSnifferApp()
    app_instance.start_sniffer()

    # Run Flask in a separate daemon thread
    app_thread = threading.Thread(target=app.run, kwargs={'debug': True, 'use_reloader': False}, daemon=True)
    app_thread.start()

    # Keep the main thread alive on Windows
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        signal_handler(None, None)
