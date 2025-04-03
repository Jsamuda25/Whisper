from flask import Flask, render_template
import threading
from defender.sniffer import PacketSniffer
from defender.logger import ThreatLogger
from flask_app.routes import app_routes  # Import the routes blueprint

app = Flask(__name__)

# Register Blueprints
app.register_blueprint(app_routes) 

sniffer = None

@app.route('/')
def index():
    return render_template('index.html')

def start_sniffer(interface):
    global sniffer
    logger = ThreatLogger()
    sniffer = PacketSniffer(interface=interface, logger=logger)

    # Run sniffer in a background thread
    sniffer_thread = threading.Thread(target=sniffer.start)
    sniffer_thread.daemon = True  # Ensures the thread exits when Flask stops
    sniffer_thread.start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
