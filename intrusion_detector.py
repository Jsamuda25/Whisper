import time
import smtplib
from email.mime.multipart       import MIMEMultipart
from email.mime.text            import MIMEText
from dotenv                     import load_dotenv
import os

# Load the .env file
load_dotenv()

# A dictonary to sotre connection attempts for each IP and port
connection_attempts = {}
connection_attempts_scan = {}

# Define attack thresholds 
SCAN_THRESHOLD = 5
SCAN_TIME_LIMIT = 20 # secs
DOS_THRESHOLD = 100
DOS_TIME_LIMIT = 30 # secs

# Security variables to allow emails to be sent 
APP_PASSWORD = os.getenv("APP_PASSWORD")
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
RECEIVER_EMAIL = os.getenv("RECEIVER_EMAIL")

print("Receiver Email: " + str(RECEIVER_EMAIL))


# set up email alerts
def send_alert(message):
    sender_email = SENDER_EMAIL
    receiver_email = RECEIVER_EMAIL
    app_password = APP_PASSWORD

    # Create the email message
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = "Alert: Suspicious Activity Detected"  # Subject of the email
    
    # Attach the message body
    msg.attach(MIMEText(message, 'plain'))  # Body of the email

    try:
        # Connect to Gmail's SMTP server and send the email
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()  # Upgrade the connection to secure
        server.login(sender_email, app_password)  # Use App Password for login
        server.sendmail(sender_email, receiver_email, msg.as_string())  # Send the email
        server.quit()


        print(f"Sender Email: {sender_email}")
        print(f"Recipient Email: {receiver_email}")
        print(f"Alert Message: {message}")

        print(f"Alert sent: {message}")
        
    except Exception as e:
        print(f"Error sending alert: {e}")

def detect_port_scan(packet):
    try:
        if packet.haslayer("IP") and packet.haslayer("TCP"):
            ip_src = packet["IP"].src  # Source IP address
            tcp_dport = packet["TCP"].dport  # Destination port

            if ip_src not in connection_attempts_scan:
                connection_attempts_scan[ip_src] = {}

            if tcp_dport not in connection_attempts_scan[ip_src]:
                connection_attempts_scan[ip_src][tcp_dport] = {"count": 0, "last_time": time.time()}

            current_time = time.time()
            connection_attempts_scan[ip_src][tcp_dport]["count"] += 1

            if connection_attempts_scan[ip_src][tcp_dport]["count"] > SCAN_THRESHOLD:
                if current_time - connection_attempts_scan[ip_src][tcp_dport]["last_time"] < SCAN_TIME_LIMIT:
                    alert_message = f"Port scan detected! IP: {ip_src} scanning port {tcp_dport}"
                    print(alert_message)
                    send_alert(alert_message)
                    connection_attempts_scan[ip_src][tcp_dport]["count"] = 0

            connection_attempts_scan[ip_src][tcp_dport]["last_time"] = current_time
           
    except Exception as e:
        print(f"Error in detect_port_scan: {e}")


def detect_dos_attack(packet):
    try:
        if packet.haslayer("IP"):
            ip_src = packet["IP"].src

            # Initialize entry if IP is not in connection_attempts
            if ip_src not in connection_attempts:
                connection_attempts[ip_src] = {"count": 0, "last_time": time.time()}

            current_time = time.time()
            connection_attempts[ip_src]["count"] += 1

            # Check for DoS attack
            if connection_attempts[ip_src]["count"] > DOS_THRESHOLD:
                if current_time - connection_attempts[ip_src]["last_time"] < DOS_TIME_LIMIT:
                    alert_message = f"DoS attack detected! IP: {ip_src}"
                    print(alert_message)
                    send_alert(alert_message)
                    connection_attempts_scan[ip_src][ip_src]["count"] = 0
            else:
                # Reset count if the time limit has passed
                if current_time - connection_attempts[ip_src]["last_time"] >= DOS_TIME_LIMIT:
                    connection_attempts[ip_src]["count"] = 1

            # Update last_time to current_time
            connection_attempts[ip_src]["last_time"] = current_time
    except Exception as e:
        print(f"Error processing packet: {e}")

