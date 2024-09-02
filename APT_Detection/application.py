### Author: Chisom

from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
from threading import Thread, Event
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
import os
import logging
import warnings
from time import sleep


# Set TensorFlow log level before importing TensorFlow
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'  # Suppress TensorFlow info and warning logs

# Define the log file paths
output_log_path = r'C:\Users\chiso\APT_Detection\output_logs.csv'
input_log_path = r'C:\Users\chiso\APT_Detection\input_logs.csv'

# Ensure the directories exist
os.makedirs(os.path.dirname(output_log_path), exist_ok=True)
os.makedirs(os.path.dirname(input_log_path), exist_ok=True)

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

warnings.filterwarnings("ignore")

# Import to avoid circular import issue
from flow.Flow import Flow

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
app.config['DEBUG'] = True

# Turn the Flask app into a SocketIO app
socketio = SocketIO(app, async_mode=None, logger=True, engineio_logger=True)

# Thread and event for background tasks
thread = Thread()
thread_stop_event = Event()

# CSV file handlers for logging
try:
    with open(output_log_path, 'w', newline='') as output_log:
        output_writer = csv.writer(output_log)
        with open(input_log_path, 'w', newline='') as input_log:
            input_writer = csv.writer(input_log)
except IOError as e:
    logger.error(f"Error opening log files: {e}")

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

# Define correct paths
classifier_path = r'C:\Users\chiso\APT_Detection\models\classifier.pkl'
autoencoder_path = r'C:\Users\chiso\APT_Detection\models\autoencoder_39ft.keras'
scaler_path = r'C:\Users\chiso\APT_Detection\models\preprocess_pipeline_AE_39ft.save'

# Load the models and scaler
try:
    classifier = joblib.load(classifier_path)  # Use joblib if saved with joblib
    autoencoder = load_model(autoencoder_path)
    scaler = joblib.load(scaler_path)
except Exception as e:
    logger.error(f"Error loading models or scaler: {e}")



# Define feature columns ( I Ensured this list matches the columns used for training the models)
features = [
    'FlowDuration', 'BwdPacketLenMax', 'BwdPacketLenMin', 'BwdPacketLenMean', 'BwdPacketLenStd',
    'FlowIATMean', 'FlowIATStd', 'FlowIATMax', 'FlowIATMin', 'FwdIATTotal', 'FwdIATMean', 
    'FwdIATStd', 'FwdIATMax', 'FwdIATMin', 'BwdIATTotal', 'BwdIATMean', 'BwdIATStd', 
    'BwdIATMax', 'BwdIATMin', 'FwdPSHFlags', 'FwdPackets_s', 'MaxPacketLen', 'PacketLenMean', 
    'PacketLenStd', 'PacketLenVar', 'FINFlagCount', 'SYNFlagCount', 'PSHFlagCount', 
    'ACKFlagCount', 'URGFlagCount', 'AvgPacketSize', 'AvgBwdSegmentSize', 'InitWinBytesFwd', 
    'InitWinBytesBwd', 'ActiveMin', 'IdleMean', 'IdleStd', 'IdleMax', 'IdleMin'
]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/details')
def details():
    return render_template('details.html')

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        df = pd.DataFrame([data])
        X = df[features]
        X_scaled = scaler.transform(X)
        predictions = classifier.predict(X_scaled)
        return jsonify(predictions.tolist())
    except Exception as e:
        logger.error(f"Error in predict route: {e}")
        return jsonify({'error': 'An error occurred'}), 500


# Define a route for anomaly detection
@app.route('/anomaly', methods=['POST'])
def anomaly():
    data = request.get_json()
    df = pd.DataFrame([data])
    X = df[features]
    X_scaled = scaler.transform(X)

    # Compute reconstruction errors
    reconstruction = autoencoder.predict(X_scaled)
    errors = np.mean(np.square(X_scaled - reconstruction), axis=1)
    
    return jsonify(errors.tolist())

# Define a route for explaining anomalies
@app.route('/explain', methods=['POST'])
def explain():
    data = request.get_json()
    df = pd.DataFrame([data])
    X = df[features]
    
    # Get explanation for the data
    errors = explain_autoencoder(X)
    
    return jsonify(errors.tolist())

# Function to explain anomalies using the explainer
def explain_autoencoder(data):
    X = scaler.transform(data)
    reconstruction = autoencoder.predict(X)
    errors = np.mean(np.square(X - reconstruction), axis=1)
    
    return errors


def ipInfo(addr=''):
    """Fetch country information based on IP address."""
    try:
        url = 'https://ipinfo.io/json' if addr == '' else f'https://ipinfo.io/{addr}/json'
        res = urlopen(url)
        data = json.load(res)
        return data.get('country', 'Unknown')  # Default to 'Unknown' if 'country' is not found
    except Exception as e:
        logger.error(f"Error fetching IP info for {addr}: {e}")
        return None


from scapy.all import sniff, IP  # Import the necessary modules from scapy

# Define paths and load models as before
classifier_path = r'C:\Users\chiso\APT_Detection\models\classifier.pkl'
autoencoder_path = r'C:\Users\chiso\APT_Detection\models\autoencoder_39ft.keras'
scaler_path = r'C:\Users\chiso\APT_Detection\models\preprocess_pipeline_AE_39ft.save'

try:
    classifier = joblib.load(classifier_path)  # Use joblib if saved with joblib
    autoencoder = load_model(autoencoder_path)
    scaler = joblib.load(scaler_path)
except Exception as e:
    logger.error(f"Error loading models or scaler: {e}")





def predict_fn_rf(features):
    """Placeholder function for getting prediction probabilities from the classifier."""
    # Implement actual logic to get prediction probabilities
    return np.array([[0.1, 0.2, 0.7]])  # Example probabilities

# Define the autoencoder scaler and model if used
ae_scaler = scaler  # Assuming the scaler used for autoencoder is the same
ae_model = autoencoder  # Assuming the autoencoder model is used directly

def classify(features):
    """Classify the flow using the loaded models and update the logs and data.
    
    Author: Chisom
    """
    global flow_count

    # Extract features and create a string representation for logging
    feature_string = [str(i) for i in features[39:]]
    features = [np.nan if x in [np.inf, -np.inf] else float(x) for x in features[:39]]

    # Update source IP dictionary
    src_ip = feature_string[0]
    if src_ip in src_ip_dict:
        src_ip_dict[src_ip] += 1
    else:
        src_ip_dict[src_ip] = 1

    # Append country flag icons to IP addresses
    for i in [0, 2]:
        ip = feature_string[i]
        if not ipaddress.ip_address(ip).is_private:
            country = ipInfo(ip)
            if country and country.lower() not in ['ano', 'unknown']:
                img = f' <img src="static/images/blank.gif" class="flag flag-{country.lower()}" title="{country}">'
            else:
                img = ' <img src="static/images/blank.gif" class="flag flag-unknown" title="UNKNOWN">'
        else:
            img = ' <img src="static/images/lan.gif" height="11px" style="margin-bottom: 0px" title="LAN">'
        feature_string[i] += img
    
    # Handle NaN values in features
    if any(pd.isna(features)):
        logger.warning(f"NaN values detected in features: {features}")
        return
    
    # Predict and compute probabilities using the classifier
    result = classifier.predict([features])
    proba = predict_fn_rf([features])
    proba_score = [proba[0].max()]
    proba_risk = sum(proba[0, 1:])

    # Compute the reconstruction error using the autoencoder
    features_array = np.array(features).reshape(1, -1)  # Reshape for the model
    scaled_features = ae_scaler.transform(features_array)  # Apply preprocessing
    reconstructed = ae_model.predict(scaled_features)
    reconstruction_error = np.mean(np.square(scaled_features - reconstructed))

    # Define a threshold for the reconstruction error
    reconstruction_threshold = 0.05  # Set an appropriate threshold
    anomaly = reconstruction_error > reconstruction_threshold

    # Determine risk level
    if anomaly:
        risk = ["<p style=\"color:red;\">Anomaly Detected</p>"]
    else:
        if proba_risk > 0.8:
            risk = ["<p style=\"color:red;\">Very High</p>"]
        elif proba_risk > 0.6:
            risk = ["<p style=\"color:orangered;\">High</p>"]
        elif proba_risk > 0.4:
            risk = ["<p style=\"color:orange;\">Medium</p>"]
        elif proba_risk > 0.2:
            risk = ["<p style=\"color:green;\">Low</p>"]
        else:
            risk = ["<p style=\"color:limegreen;\">Minimal</p>"]

    classification = ["Anomaly" if anomaly else str(result[0])]
    if result[0] != 'Benign' or anomaly:
        print(feature_string + classification + proba_score + [reconstruction_error])

    # Increment flow count
    flow_count += 1

    # Write to output log file
    try:
        with open(output_log_path, 'a', newline='') as output_log:
            output_writer = csv.writer(output_log)
            output_writer.writerow(['Flow #' + str(flow_count)])
            output_writer.writerow(['Flow info:'] + feature_string)
            output_writer.writerow(['Flow features:'] + features)
            output_writer.writerow(['Reconstruction Error:'] + [reconstruction_error])
            output_writer.writerow(['Prediction:'] + classification + proba_score)
            output_writer.writerow(['Risk Level:'] + risk)
    except Exception as e:
        logger.error(f"Error writing to output log: {e}")

    # Write to input log file
    try:
        with open(input_log_path, 'a', newline='') as input_log:
            input_writer = csv.writer(input_log)
            input_writer.writerow(['Flow #' + str(flow_count)])
            input_writer.writerow(['Flow info:'] + feature_string)
            input_writer.writerow(['Flow features:'] + features)
            input_writer.writerow(['Reconstruction Error:'] + [reconstruction_error])
            input_writer.writerow(['Prediction:'] + classification + proba_score)
            input_writer.writerow(['Risk Level:'] + risk)
    except Exception as e:
        logger.error(f"Error writing to input log: {e}")

@app.route('/start_sniffing', methods=['POST'])
def start_sniffing():
    global thread, thread_stop_event
    if not thread.is_alive():
        thread_stop_event.clear()
        thread = Thread(target=sniffing_thread, args=(thread_stop_event,))
        thread.start()
    return jsonify({'status': 'Sniffing started'})

@app.route('/stop_sniffing', methods=['POST'])
def stop_sniffing():
    global thread_stop_event
    thread_stop_event.set()
    return jsonify({'status': 'Sniffing stopped'})

def process_packet(packet):
    """Process each captured network packet.

    Author: Chisom
    """
    global flow_df
    try:
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            
            # Update source IP dictionary
            if src_ip not in src_ip_dict:
                src_ip_dict[src_ip] = 1
            else:
                src_ip_dict[src_ip] += 1

            # Extract features and classify
            features = extract_features(packet)
            if features:
                classify(features)
            else:
                logger.warning("No features extracted from packet.")
    except Exception as e:
        logger.error(f"Error processing packet: {e}")


def sniffing_thread(stop_event):
    while not stop_event.is_set():
        sniff(prn=process_packet, store=0, timeout=10)
        if stop_event.is_set():
            break

# Ensure `FlowTimeout` and `extract_features` are properly defined elsewhere

def extract_features(packet):
    """Extract features from a network packet for classification.
    
    Author: Chisom
    """
    # Placeholder for feature extraction logic
    # This should be replaced with actual feature extraction code
    return np.random.rand(39)  # Dummy features for demonstration

def run_background_thread():
    """Run the background thread for network sniffing."""
    global thread
    global thread_stop_event
    try:
        thread = Thread(target=start_sniffing)
        thread.start()
        while not thread_stop_event.is_set():
            sleep(1)
    except Exception as e:
        logger.error(f"Error running background thread: {e}")

def stop_background_thread():
    """Stop the background thread for network sniffing."""
    global thread_stop_event
    thread_stop_event.set()
    if thread.is_alive():
        thread.join()



@socketio.on('connect')
def handle_connect():
    emit('response', {'data': 'Connected'})

@socketio.on('disconnect')
def handle_disconnect():
    emit('response', {'data': 'Disconnected'})

@socketio.on('start')
def handle_start():
    emit('response', {'data': 'Start signal received'})

@socketio.on('stop')
def handle_stop():
    emit('response', {'data': 'Stop signal received'})

output_log_path = 'path/to/your/logfile.log'

@app.route('/logs')
def get_logs():
    try:
        with open(output_log_path, 'r') as log_file:
            logs = log_file.readlines()
        # Clean up logs by removing trailing newline characters
        logs = [log.strip() for log in logs]
        return jsonify({'logs': logs})
    except IOError as e:
        logger.error(f"Error reading logs: {e}")
        return jsonify({'logs': []})
if __name__ == '__main__':
    app.run(debug=True)  # Debug mode is on; remove or set to False for production


        



