from flask import Flask, request, jsonify, render_template_string
import threading
import logging

app = Flask(__name__)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# In-memory "Victim" Database
users = {"admin": "password123", "user": "user"}
fake_db = [
    {"id": 1, "card": "4532-xxxx-xxxx-8812", "owner": "CFO_ROOT"},
    {"id": 2, "card": "4111-xxxx-xxxx-1029", "owner": "STRATEGIC_PLAN"}
]

@app.after_request
def add_headers(response):
    response.headers["X-CORTEX-Training"] = "Synthetic fixture; no real confidential data"
    return response

@app.route('/')
def index():
    return "<h1>Digital Twin: Vulnerable Corporate Portal [ALIVE]</h1><p>Running on: http://127.0.0.1:5555</p>"

@app.route('/login', methods=['POST', 'GET'])
def login():
    """Vulnerable Login: Susceptible to Brute Force and SQLi Simulation"""
    if request.method == 'POST':
        user = request.form.get('username')
        pw = request.form.get('password')
        if user in users and pw is not None and users[user] == pw:
            return jsonify({"status": "success", "message": f"Welcome {user}!", "token": "FAKE_SESS_TOKEN_99"}), 200
        return jsonify({"status": "failed", "message": "Invalid Credentials"}), 401
    return '<form method="post"><input name="username"><input name="password"><input type="submit"></form>'

@app.route('/upload', methods=['POST'])
def upload():
    """Vulnerable Upload: No extension check!"""
    file = request.files.get('file')
    if file:
        filename = file.filename
        if ".php" in filename or ".jsp" in filename:
            return jsonify({"status": "alert", "message": "WEBSHELL DETECTED (Simulated)", "payload": filename}), 201
        return jsonify({"status": "success", "message": f"File {filename} uploaded."}), 200
    return jsonify({"status": "error"}), 400

@app.route('/api/user/<int:id>')
def get_user(id):
    """Broken Account Level Authorization (IDOR) Simulation"""
    if id == 0:
        return jsonify({"id": 0, "role": "admin", "data": "STRATEGIC_PLAN_2024.PDF"}), 200
    return jsonify({"id": id, "role": "user", "data": "Public data"}), 200

@app.route('/admin/db')
def db_dump():
    """Fake Database Leak for Honey-Trap"""
    return jsonify(fake_db), 200

@app.route('/shell', methods=['POST'])
def fake_shell():
    """Interactive Capture Trap"""
    cmd = request.form.get('cmd')
    return jsonify({
        "status": "access_granted", 
        "output": "[SIMULATION ONLY] No command executed."
    }), 200

def run_twin():
    app.run(port=5555, debug=False, use_reloader=False)

class DigitalTwinTarget:
    def __init__(self, port=5555):
        self.port = port
        self.thread = None
        self.server = None

    def start(self):
        if not self.thread or not self.thread.is_alive():
            from werkzeug.serving import make_server
            try:
                self.server = make_server('127.0.0.1', self.port, app, threaded=True)
                self.port = self.server.server_port
            except (OSError, SystemExit) as exc:
                raise RuntimeError('Twin could not bind loopback port 5555; another service may be using it') from exc
            self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.thread.start()
        return self.get_url()

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
            self.thread = None

    def get_url(self):
        return f"http://127.0.0.1:{self.port}"
