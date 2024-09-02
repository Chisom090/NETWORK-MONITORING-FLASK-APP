
# Network Traffic Monitoring App

## Table of Contents
1. [Project Description](#project-description)
2. [Features](#features)
3. [Technologies Used](#technologies-used)
4. [Installation](#installation)
5. [Usage](#usage)
6. [API Endpoints](#api-endpoints)
7. [Web Interface](#web-interface)
8. [Troubleshooting](#troubleshooting)
9. [Contributing](#contributing)
10. [License](#license)

## Project Description
The **Network Traffic Monitoring App** is a web-based application designed to monitor network traffic in real-time, detect anomalies, and provide insights into network activities. It uses Flask as the backend framework and Socket.IO for real-time communication. The application allows users to start and stop network sniffing, view logs, and check for anomalies.

## Features
- **Start and Stop Network Sniffing**: Initiate or halt network traffic monitoring.
- **Real-Time Updates**: View real-time network activity using Socket.IO.
- **Log Management**: Access logs of network activities.
- **Anomaly Detection**: Check for suspicious or unusual network behavior.
- **User-Friendly Interface**: A clean and simple web interface for interaction.

## Technologies Used
- **Backend**: Flask, Python
- **Frontend**: HTML, CSS, JavaScript, Bootstrap
- **Real-Time Communication**: Socket.IO
- **Data Handling**: JSON
- **Logging**: Python's logging module

## Installation

### Prerequisites
- Python 3.x
- pip (Python package installer)
- Node.js (for running Socket.IO, if needed)

### Steps
1. **Clone the Repository**:
    ```bash
    git clone https://github.com/yourusername/network-traffic-monitoring-app.git
    cd network-traffic-monitoring-app
    ```

2. **Create a Virtual Environment** (optional but recommended):
    ```bash
    python3 -m venv venv
    source venv/bin/activate   # On Windows use `venv\Scripts\activate`
    ```

3. **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

4. **Run the Flask Application**:
    ```bash
    python app.py
    ```

5. **Access the Application**:
   Open your browser and go to `http://127.0.0.1:5000`.

## Usage

### Starting and Stopping Sniffing
- Use the "Start Sniffing" button to initiate network traffic monitoring.
- Use the "Stop Sniffing" button to halt network traffic monitoring.

### Viewing Logs
- Click the "Get Logs" button to view the recorded network traffic logs.

### Checking for Anomalies
- Navigate to the "Check Anomalies" section to input data and check for any suspicious activities.

### Real-Time Updates
- Real-time updates will be shown directly on the dashboard as network events are captured.

## API Endpoints

- **POST `/start_sniffing`**: Start the network sniffing process.
    - **Response**: `{ "status": "Sniffing started" }`
  
- **POST `/stop_sniffing`**: Stop the network sniffing process.
    - **Response**: `{ "status": "Sniffing stopped" }`
  
- **GET `/logs`**: Retrieve network traffic logs.
    - **Response**: `{ "logs": ["log entry 1", "log entry 2", ...] }`

## Web Interface
The web interface provides a user-friendly way to interact with the network monitoring app:
- **Dashboard**: Overview of network activities.
- **Log Viewer**: A section to view and manage network logs.
- **Anomaly Checker**: Interface to input data and perform anomaly detection.

## Troubleshooting

1. **No Logs Displayed**: Ensure the Flask application has write access to the log file location and that the log file path is correctly specified.
2. **Real-Time Updates Not Working**: Check that Socket.IO is correctly configured and the server is running without errors. Verify browser console for JavaScript errors.
3. **Permission Issues**: If running sniffing operations on certain operating systems, you may need administrative privileges.

## Contributing
Contributions are welcome! Please fork the repository and create a pull request with your changes. Ensure that your code follows the project's style guidelines and includes appropriate tests.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
# AUTHOR 
## CHISOM MICHEAL ERIOBU
## 09136176656


