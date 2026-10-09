"""
CORTEX ADVANCED HONEYPOT - Active Deception System
A high-interaction fake server that lures, tracks, and profiles attackers.
"""
from flask import Flask, request, render_template_string, jsonify
import threading
import logging
import datetime
import json
import os
import hashlib

app = Flask(__name__)
# Suppress Flask logs
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

ATTACK_LOGS = []
BLACKLISTED_IPS = set()
LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'honeypot_attacks.json')

# === HONEYPOT PAGES ===
FAKE_ADMIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><title>Admin Panel - System v3.4</title>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body { font-family: 'Courier New', monospace; background: #0a0a0a; color: #c0c0c0; display: flex; justify-content: center; align-items: center; height: 100vh; }
        .container { background: #111; border: 1px solid #222; border-top: 3px solid #c0392b; padding: 40px 50px; width: 420px; }
        .logo { color:#c0392b; font-size:22px; font-weight:bold; margin-bottom:5px; }
        .sub { color:#555; font-size:11px; margin-bottom:30px; letter-spacing:3px; }
        input { width:100%; background:#0a0a0a; border:1px solid #333; color:#fff; padding:12px; margin:8px 0; font-family:monospace; outline:none; }
        input:focus { border-color:#c0392b; }
        button { width:100%; background:#c0392b; color:#fff; border:none; padding:13px; cursor:pointer; font-size:14px; margin-top:10px; letter-spacing:2px; }
        button:hover { background:#a93226; }
        .notice { color:#444; font-size:10px; margin-top:15px; text-align:center; }
        .server-info { position:absolute; bottom:10px; right:15px; color:#222; font-size:9px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">⬛ CORTEX SYSTEMS</div>
        <div class="sub">RESTRICTED ADMINISTRATIVE ACCESS</div>
        <form action="/admin/login" method="POST" id="loginForm">
            <input type="text" name="user" placeholder="Username" required autocomplete="off">
            <input type="password" name="pass" placeholder="Password" required>
            <input type="hidden" name="_token" value="{{ csrf }}">
            <button type="submit">▶ AUTHENTICATE</button>
        </form>
        <div class="notice">⚠ Unauthorized access is a criminal offense. All activities are recorded and monitored.</div>
    </div>
    <div class="server-info">Apache/2.4.41 (Ubuntu) | Server ID: 0xA4F1</div>
</body>
</html>
"""

FAKE_DB_BACKUP_CONTENT = """-- MySQL Dump 8.0.21
-- Server: localhost
-- Database: cortex_users

CREATE TABLE `users` (`id` int, `username` varchar(255), `password_hash` varchar(255), `email` varchar(255));
INSERT INTO `users` VALUES (1, 'superadmin', 'e3afed0047b08059d0fada10f400c1e5', 'admin@cortex.internal');
INSERT INTO `users` VALUES (2, 'root', '5f4dcc3b5aa765d61d8327deb882cf99', 'root@localhost');
INSERT INTO `users` VALUES (3, 'sys_backup', 'd8578edf8458ce06fbc5bb76a58c5ca4', 'backup@sys.internal');
"""

FAKE_CONFIG_CONTENT = """# Application Configuration
DB_HOST=10.0.0.5
DB_USER=cortex_app
DB_PASS=Cortex!Secure@2024
DB_NAME=cortex_main
API_SECRET=sk-f82bfa71c4e0e2d1a3c5678901b34567
AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
AWS_SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
SMTP_PASS=MailPass@2024!
"""


# === ROUTES ===

@app.route('/', methods=['GET'])
def index():
    _log("HOME", "Accessed root path", severity="LOW")
    return "Server Error", 500  # Looks like a broken server to probe

@app.route('/admin', methods=['GET'])
@app.route('/administrator', methods=['GET'])
@app.route('/wp-admin', methods=['GET'])
@app.route('/phpmyadmin', methods=['GET'])
@app.route('/panel', methods=['GET'])
def admin_panel():
    """Fake admin panel - HIGH VALUE LURE"""
    csrf = hashlib.md5(request.remote_addr.encode()).hexdigest()
    _log("ADMIN_ACCESS", f"Probed admin panel at {request.path}", severity="HIGH")
    return render_template_string(FAKE_ADMIN_HTML, csrf=csrf)

@app.route('/admin/login', methods=['POST'])
def admin_login():
    """Capture login attempts"""
    user = request.form.get('user', '')
    password = request.form.get('pass', '')
    _log("LOGIN_ATTEMPT", f"User='{user}' | Pass='{password}'", severity="CRITICAL")
    # Return a fake "loading" to keep them busy
    return "<script>setTimeout(function(){window.location='/admin';},3000);</script>Authenticating...", 200

@app.route('/backup.sql', methods=['GET'])
@app.route('/db_backup.sql', methods=['GET'])
@app.route('/dump.sql', methods=['GET'])
def fake_db_dump():
    """Fake database backup - CREDENTIAL TRAP"""
    _log("FILE_ACCESS", f"Downloaded fake DB backup: {request.path}", severity="CRITICAL")
    return FAKE_DB_BACKUP_CONTENT, 200, {'Content-Type': 'text/plain'}

@app.route('/.env', methods=['GET'])
@app.route('/config.php', methods=['GET'])
@app.route('/config.ini', methods=['GET'])
def fake_config():
    """Fake config with fake credentials"""
    _log("CONFIG_STEAL", f"Accessed sensitive config: {request.path}", severity="CRITICAL")
    return FAKE_CONFIG_CONTENT, 200, {'Content-Type': 'text/plain'}

@app.route('/api/users', methods=['GET'])
@app.route('/api/v1/users', methods=['GET'])
def fake_api_users():
    """Fake API with fake user data"""
    _log("API_PROBE", f"API endpoint probed: {request.path}", severity="MEDIUM")
    return jsonify([
        {"id": 1, "name": "Admin User", "role": "superadmin", "email": "admin@cortex.internal"},
        {"id": 2, "name": "System", "role": "system", "email": "system@cortex.internal"},
    ])


def _log(attack_type: str, details: str, severity: str = "MEDIUM"):
    """Centralized logging with attacker profiling"""
    ip = request.remote_addr
    log_entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "ip": ip,
        "type": attack_type,
        "severity": severity,
        "path": request.path,
        "method": request.method,
        "details": details,
        "user_agent": request.headers.get('User-Agent', 'Unknown'),
        "referrer": request.headers.get('Referer', ''),
    }
    ATTACK_LOGS.append(log_entry)
    
    # Auto-blacklist on critical events
    if severity == "CRITICAL":
        BLACKLISTED_IPS.add(ip)
    
    # Write to persistent log
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(json.dumps(log_entry) + '\n')


def get_stats() -> dict:
    return {
        "total_attacks": len(ATTACK_LOGS),
        "blacklisted_ips": len(BLACKLISTED_IPS),
        "recent_attacks": ATTACK_LOGS[-5:]
    }


def run_honeypot(port: int = 8080):
    print(f"🍯 Advanced Honeypot running on port {port}... (Multi-route active deception)")
    app.run(host='0.0.0.0', port=port, threaded=True)


if __name__ == "__main__":
    run_honeypot()
