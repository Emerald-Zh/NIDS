# Network-Intrusion-Detection-System
A custom Network Intrusion Detection System (NIDS) in Python utilizing Scapy library for real-time packet analysis with customizable rule sets.

## Overview

This project aims to provide a flexible and customizable solution for detecting and monitoring suspicious network activity. By leveraging the Scapy library, it enables users to capture, analyze, and log network packets in real-time, allowing for the detection of potential intrusions based on user-defined rules.

## Features

- **Real-time Packet Analysis**: Utilizes the Scapy library to capture and analyze network packets in real-time.
- **Customizable Rule Sets**: Users can define custom rules to specify the criteria for detecting suspicious network activity.
- **Logging and Alerting**: Logs matched packets and alerts users about potential intrusions based on predefined rules.
- **Support for Various Protocols**: Supports common network protocols such as DNS, HTTP, and UDP for comprehensive network monitoring.

## Getting Started

### Prerequisites

- Python 3.x
- Scapy library (`pip install scapy`)

### Usage

1. Clone the repository to your local machine:
git clone https://github.com/FyrasBJ/Network-Intrusion-Detection-System.git
2. Navigate to the project directory:
cd Network-Intrusion-Detection-System/
3. Modify the `rules.txt` file to define your custom rules for network intrusion detection.
4. Replace `rules.txt` with the path to your custom rules file.
5. Monitor the console output or check the `traffic_logs.log` file for logged network activity and potential intrusion alerts.


## Custom Rules

The `rules.txt` file contains sample rule definitions for detecting various types of network activity. You can modify or add new rules based on your specific requirements.


## Contributing

Contributions are welcome! Feel free to submit bug reports, feature requests, or pull requests to help improve this project.

## License

This project is licensed under the [MIT License](LICENSE).


