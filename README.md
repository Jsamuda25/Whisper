# Whisper - IDS

This is a network intrusion detection system built using Scapy in Python.

Current capabilities:
- Captures packets from the network and prints a summary of each packet.
- Identifies potentially threatening port scans.
- Identifies potential denial of service attacks based the volume and frequency of certain requests.
- Send alert emails upon the detection of suspicious activity.

## Setup

1. Clone this repository:
   ```bash
   git clone https://github.com/Jsamuda25/whisper.git
   cd whisper

2. Create and activate a virtual environment:
    python3 -m venv venv
    source venv/bin/activate   # On Linux/macOS
    .\venv\Scripts\activate    # On Windows

3. Install dependencies:
    pip install -r requirements.txt

4. Run the sniffer:
    python sniffer.py


