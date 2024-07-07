from flask import Flask, render_template, request, redirect, url_for
import pandas as pd
import re
import subprocess
import os

app = Flask(__name__)

nids_process = None

@app.route('/')
def index():
    log_data = parse_log_file('traffic_logs.log')
    return render_template('index.html', log_data=log_data)

@app.route('/start', methods=['POST'])
def start_nids():
    global nids_process
    if not nids_process:
        nids_process = subprocess.Popen(['python', 'NIDS.py'])
    return redirect(url_for('index'))

@app.route('/stop', methods=['POST'])
def stop_nids():
    global nids_process
    if nids_process:
        nids_process.terminate()
        nids_process = None
    return redirect(url_for('index'))

def parse_log_file(log_file):
    columns = ['Number', 'Timestamp', 'Level', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol']
    logs = []
    log_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+):(\d+) > (\d+\.\d+\.\d+\.\d+):(\d+).* - Destination IP: (\d+\.\d+\.\d+\.\d+)')

    if not os.path.exists(log_file):
        return pd.DataFrame(logs, columns=columns)

    with open(log_file, 'r') as f:
        counter = 1
        for line in f:
            if ' - root - INFO - ' in line:
                parts = line.split(' - root - INFO - ')
                timestamp = parts[0]
                message = parts[1].strip()
                match = log_pattern.search(message)

                if match:
                    src_ip = match.group(1)
                    src_port = match.group(2)
                    dest_ip = match.group(3)
                    dest_port = match.group(4)
                    protocol = 'TCP' if 'TCP' in message else ('UDP' if 'UDP' in message else 'Unknown')

                    logs.append({
                        'Number': counter,
                        'Timestamp': timestamp,
                        'Level': 'INFO',
                        'Source IP': src_ip,
                        'Source Port': src_port,
                        'Destination IP': dest_ip,
                        'Destination Port': dest_port,
                        'Protocol': protocol
                    })
                    counter += 1
    return pd.DataFrame(logs, columns=columns)

if __name__ == '__main__':
    app.run(debug=True)
