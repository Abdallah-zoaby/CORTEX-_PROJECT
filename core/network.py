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
    """Compatibility hook: never retrieve saved Wi-Fi passwords."""
    return [dict(type='Wi-Fi assessment unavailable', classification='unknown',
                 severity='INFO', description='Wi-Fi security is not assessed; saved credentials are not read')]


def check_dns_integrity():
    """Hosts-file configuration observations, not a DNS reputation verdict."""
    import os
    from pathlib import Path
    path = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/drivers/etc/hosts'
    issues = []
    with path.open('r', encoding='utf-8-sig', errors='replace') as handle:
        for line in handle:
            fields = line.split('#', 1)[0].split()
            if len(fields) > 1:
                issues.append(f'Hosts mapping observed: {" ".join(fields)}; verify intended configuration')
    return issues
