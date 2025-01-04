# Network Security Monitoring System

This project is a lightweight network security monitoring system built with Python, utilizing Scapy for packet sniffing, a custom Intrusion Detection System, and a Flask dashboard for real-time monitoring of network activities and security alerts.

## Features

- **Packet Sniffing:** Captures and inspects network packets.
- **Intrusion Detection:** Detects potential threats like port scans, DoS attacks, and signature-based anomalies.
- **Real-Time Dashboard:** View network activity logs and alerts in a user-friendly interface.
- **Email Notifications:** Sends alerts for suspicious activities detected on the network.

## Setup Instructions

### 1. Clone the Repository
Clone this repository to your local machine:
```bash
git clone https://github.com/{your-username}/{your-repo-name}.git
cd {your-repo-name}
```

### 2. Set Up a Virtual Environment
Create and activate a Python virtual environment:

#### On Linux/macOS:
```bash
python3 -m venv venv
source venv/bin/activate
```

#### On Windows:
```bash
python -m venv venv
venv\Scripts\activate
```

### 3. Install Dependencies
Install the required Python libraries:
```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables
Create a `.env` file in the project root directory and configure the following variables:
```
APP_PASSWORD=<your-app-password>
SENDER_EMAIL=<your-email-address>
RECEIVER_EMAIL=<receiver-email-address>
```

### 5. Run the Application

#### Start the Sniffer and Dashboard
Run the main entry point for the application:
```bash
python main.py
```

#### Access the Dashboard
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

## Project Structure

```
{Whisper}/
|
|-- defender/                      # Core functionality of the IDS and packet sniffer
|   |-- __init__.py                # Package initializer
|   |-- intrusion_detector.py      # Intrusion detection logic
|   |-- sniffer.py                 # Packet sniffer implementation
|
|-- flask_app/                     # Flask app for the dashboard
|   |-- __init__.py                # App factory
|   |-- routes.py                  # Flask routes for the dashboard
|   |-- templates/                 # HTML templates for the dashboard
|       |-- index.html
|-- logs/                          # Directory for log files
|   |-- alerts.log                 # Log of network activity and alerts
|
|-- .env                           # Environment variables
|-- requirements.txt               # Project dependencies
|-- README.md                      # Project documentation (this file)
|-- main.py                        # Entry point to start the system
```
