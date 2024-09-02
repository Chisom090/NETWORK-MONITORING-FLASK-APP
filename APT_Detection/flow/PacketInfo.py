from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
from random import random
from time import sleep
from threading import Thread, Event
from scapy.sendrecv import sniff
import numpy as np
import pickle
import csv
import traceback
import json
import pandas as pd
import ipaddress
from urllib.request import urlopen
from tensorflow.keras.models import load_model
from tensorflow.keras.losses import MeanSquaredError
from lime import lime_tabular
import dill
import joblib
import plotly
import plotly.graph_objs
import warnings
import tensorflow as tf
import os
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


# Suppress TensorFlow info and warning logs
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
warnings.filterwarnings("ignore")

# Custom modules
from flow.Flow import Flow
from flow.PacketInfo import PacketInfo

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
app.config['DEBUG'] = True

# Initialize SocketIO
socketio = SocketIO(app, async_mode=None, logger=True, engineio_logger=True)

# Thread and event for background tasks
thread = Thread()
thread_stop_event = Event()

# CSV file handlers for logging
output_log_path = "output_logs.csv"
input_log_path = "input_logs.csv"

# Define column names for the flow DataFrame
cols = ['FlowID', 'FlowDuration', 'BwdPacketLenMax', 'BwdPacketLenMin', 'BwdPacketLenMean', 'BwdPacketLenStd',
        'FlowIATMean', 'FlowIATStd', 'FlowIATMax', 'FlowIATMin', 'FwdIATTotal', 'FwdIATMean', 'FwdIATStd', 'FwdIATMax',
        'FwdIATMin', 'BwdIATTotal', 'BwdIATMean', 'BwdIATStd', 'BwdIATMax', 'BwdIATMin', 'FwdPSHFlags', 'FwdPackets_s',
        'MaxPacketLen', 'PacketLenMean', 'PacketLenStd', 'PacketLenVar', 'FINFlagCount', 'SYNFlagCount', 'PSHFlagCount',
        'ACKFlagCount', 'URGFlagCount', 'AvgPacketSize', 'AvgBwdSegmentSize', 'InitWinBytesFwd', 'InitWinBytesBwd',
        'ActiveMin', 'IdleMean', 'IdleStd', 'IdleMax', 'IdleMin', 'Src', 'SrcPort', 'Dest', 'DestPort', 'Protocol',
        'FlowStartTime', 'FlowLastSeen', 'PName', 'PID', 'Classification', 'Probability', 'Risk']

ae_features = np.array(['FlowDuration', 'BwdPacketLengthMax', 'BwdPacketLengthMin', 'BwdPacketLengthMean',
                        'BwdPacketLengthStd', 'FlowIATMean', 'FlowIATStd', 'FlowIATMax', 'FlowIATMin', 'FwdIATTotal',
                        'FwdIATMean', 'FwdIATStd', 'FwdIATMax', 'FwdIATMin', 'BwdIATTotal', 'BwdIATMean', 'BwdIATStd',
                        'BwdIATMax', 'BwdIATMin', 'FwdPSHFlags', 'FwdPackets/s', 'PacketLengthMax', 'PacketLengthMean',
                        'PacketLengthStd', 'PacketLengthVariance', 'FINFlagCount', 'SYNFlagCount', 'PSHFlagCount',
                        'ACKFlagCount', 'URGFlagCount', 'AveragePacketSize', 'BwdSegmentSizeAvg', 'FWDInitWinBytes',
                        'BwdInitWinBytes', 'ActiveMin', 'IdleMean', 'IdleStd', 'IdleMax', 'IdleMin'])

flow_count = 0
flow_df = pd.DataFrame(columns=cols)

src_ip_dict = {}
current_flows = {}
FlowTimeout = 600

# Load models and preprocessing pipeline
ae_scaler = joblib.load("models/preprocess_pipeline_AE_39ft.save")
custom_objects = {'mse': 'mean_squared_error'}
ae_model = load_model('models/autoencoder_39ft.hdf5', custom_objects=custom_objects)

with open('models/model.pkl', 'rb') as f:
    classifier = pickle.load(f)

with open('models/explainer', 'rb') as f:
    explainer = dill.load(f)

predict_fn_rf = lambda x: classifier.predict_proba(x).astype(float)

def ipInfo(addr=''):
    """Fetch country information based on IP address."""
    try:
        url = 'https://ipinfo.io/json' if addr == '' else f'https://ipinfo.io/{addr}/json'
        res = urlopen(url)
        data = json.load(res)
        return data['country']
    except Exception as e:
        print(f"Error fetching IP info: {e}")
        return None

def classify(features):
    """Classify the flow using the loaded models and update the logs and data."""
    global flow_count
    feature_string = [str(i) for i in features[39:]]
    features = [np.nan if x in [np.inf, -np.inf] else float(x) for x in features[:39]]

    # Update src_ip_dict with the source IP
    src_ip = feature_string[0]
    if src_ip in src_ip_dict:
        src_ip_dict[src_ip] += 1
    else:
        src_ip_dict[src_ip] = 1

    # Add country flag images for IP addresses
    for i in [0, 2]:
        ip = feature_string[i]
        try:
            if not ipaddress.ip_address(ip).is_private:
                country = ipInfo(ip)
                if country:
                    img = f' <img src="static/images/blank.gif" class="flag flag-{country.lower()}" title="{country}">'
                else:
                    img = ' <img src="static/images/blank.gif" class="flag flag-unknown" title="UNKNOWN">'
            else:
                img = ' <img src="static/images/lan.gif" height="11px" style="margin-bottom: 0px" title="LAN">'
        except ValueError:
            img = ' <img src="static/images/blank.gif" class="flag flag-invalid" title="INVALID IP">'
        feature_string[i] += img

    # Check if features contain NaN values
    if any(pd.isna(x) for x in features):
        return

    try:
        # Perform classification
        result = classifier.predict([features])
        proba = predict_fn_rf([features])
        proba_score = [proba[0].max()]
        proba_risk = sum(list(proba[0, 1:]))
        
        # Determine risk level
        if proba_risk > 0.8:
            risk = "<p style=\"color:red;\">Very High</p>"
        elif proba_risk > 0.6:
            risk = "<p style=\"color:orangered;\">High</p>"
        elif proba_risk > 0.4:
            risk = "<p style=\"color:orange;\">Medium</p>"
        elif proba_risk > 0.2:
            risk = "<p style=\"color:green;\">Low</p>"
        else:
            risk = "<p style=\"color:limegreen;\">Minimal</p>"

        classification = str(result[0])
        flow_count += 1

        # Log outputs
        with open(output_log_path, 'a', newline='') as output_log:
            output_writer = csv.writer(output_log)
            output_writer.writerow(['Flow #' + str(flow_count)])
            output_writer.writerow(['Flow info:'] + feature_string)
            output_writer.writerow(['Flow features:'] + features)
            output_writer.writerow(['Prediction:', classification, 'Probability:', proba_score[0], 'Risk:', risk])
            output_writer.writerow([''] * 10)
        
        # Emit results via SocketIO
        socketio.emit('newresult', {
            'classification': classification,
            'proba_score': proba_score[0],
            'risk': risk
        })
    
    except Exception as e:
        logger.error(f"Error during classification or emitting results: {e}")


def background_thread():
    """Background thread function to sniff packets and classify flows."""
    global thread_stop_event
    while not thread_stop_event.is_set():
        try:
            packets = sniff(timeout=10)
            for packet in packets:
                if packet.haslayer(PacketInfo):
                    flow = Flow(packet)
                    features = flow.get_features()
                    classify(features)
        except Exception as e:
            print(f"Error during packet sniffing or classification: {e}")

@app.route('/')
def index():
    """Render the home page."""
    return render_template('index.html')

@app.route('/start', methods=['POST'])
def start_sniffing():
    """Start packet sniffing in a background thread."""
    global thread
    if not thread.is_alive():
        thread = Thread(target=background_thread)
        thread.start()
    return "Sniffing started", 200

@app.route('/stop', methods=['POST'])
def stop_sniffing():
    """Stop packet sniffing and terminate the background thread."""
    global thread_stop_event
    thread_stop_event.set()
    thread.join()
    return "Sniffing stopped", 200

@app.route('/log', methods=['GET'])
def get_log():
    """Return the log file content."""
    try:
        with open(output_log_path, 'r') as file:
            content = file.read()
        return content, 200
    except Exception as e:
        print(f"Error reading log file: {e}")
        return "Error reading log file", 500

@socketio.on('connect')
def handle_connect():
    """Handle new socket connections."""
    emit('response', {'data': 'Connected'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle socket disconnections."""
    print('Client disconnected')

@socketio.on('update')
def handle_update(data):
    """Handle updates from the frontend."""
    print('Update received:', data)
    emit('response', {'data': 'Update processed'})

if __name__ == '__main__':
    # Ensure directories exist
    os.makedirs("models", exist_ok=True)
    os.makedirs("static/images", exist_ok=True)
    
    # Start Flask application
    socketio.run(app, host='0.0.0.0', port=5000)