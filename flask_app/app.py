from flask import Flask, render_template
import threading
from defender.sniffer import PacketSniffer
from defender.logger import ThreatLogger
from flask_app.routes import app_routes  # Import the routes blueprint

app = Flask(__name__)

# Register Blueprints
app.register_blueprint(app_routes)  # <-- This is the missing line

sniffer = None

@app.route('/')
def index():
    return render_template('index.html')

def start_sniffer(interface):
    global sniffer
    logger = ThreatLogger()
    sniffer = PacketSniffer(interface=interface, logger=logger)
    sniffer.start()

if __name__ == "__main__":
    app.run(debug=True)
