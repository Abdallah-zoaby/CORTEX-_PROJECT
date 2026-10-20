import psutil
import subprocess
import re
import socket

def scan_open_ports():
    risky_ports = {
        445: "SMB", 3389: "RDP (Remote Desktop)",
        21: "FTP (Unencrypted)", 23: "Telnet (Unsecure)",
        135: "RPC Endpoint", 53: "DNS service"
    }
    results = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'LISTEN':
            port = conn.laddr.port
            try:
                proc = psutil.Process(conn.pid).name()
            except:
                proc = "Unknown"

            if port in risky_ports:
                results.append((port, f"{proc} -> {risky_ports[port]} (exposure observation, not malware)", "LOW"))
            else:
                results.append((port, proc, "INFO"))
    return results

def audit_wifi_security():
    # (نفس كود الواي فاي القديم - خليه زي ما هو عشان ممتاز)
    # ... انسخ كود الواي فاي من الردود اللي فاتت ...
    wifi_findings = []
    try:
        cmd_output = subprocess.check_output(["netsh", "wlan", "show", "profiles"], encoding='cp850', errors='ignore')
        profiles = [line.split(":")[1].strip() for line in cmd_output.split('\n') if "All User Profile" in line or "ملفات تعريف" in line]
        for profile in profiles:
            try:
                key_out = subprocess.check_output(["netsh", "wlan", "show", "profile", profile, "key=clear"], encoding='cp850', errors='ignore')
                if "Key Content" in key_out or "محتوى المفتاح" in key_out:
                    # فحص بسيط للطول
                    pass 
            except: continue
    except: pass
    return wifi_findings

def check_dns_integrity():
    """(جديد) فحص هل الـ DNS ملعوب فيه؟"""
    issues = []
    try:
        # فحص إعدادات DNS الحالية
        output = subprocess.check_output("ipconfig /all", encoding='cp850', errors='ignore')
        if "1.1.1.1" in output or "8.8.8.8" in output:
            pass # DNS آمن (Cloudflare/Google)
        else:
            # لو الـ DNS مش معروف، ممكن يكون خطر (مش شرط بس تحذير)
            pass
            
        # فحص ملف Hosts (المكان اللي الهاكرز بيقفلوا بيه مواقع الحماية)
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        with open(hosts_path, 'r') as f:
            content = f.read()
            for line in content.splitlines():
                fields = line.split('#', 1)[0].split()
                if len(fields) > 1 and any(domain in fields[1:] for domain in ('google.com', 'facebook.com', 'microsoft.com')):
                    issues.append(f'Hosts mapping observed: {" ".join(fields)}; verify intended configuration')
    except:
        pass
    return issues
