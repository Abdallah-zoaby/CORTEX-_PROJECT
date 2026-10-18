import subprocess
import os
import hashlib

# قاعدة بيانات مصغرة لأشهر الفيروسات (للتجربة)
# في الواقع ممكن نربط ده بـ VirusTotal API
KNOWN_MALWARE_HASHES = [
    "44d88612fea8a8f36de82e1278abb02f", # EICAR Test File
    "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8" # Wannacry
]

def get_file_hash(file_path):
    """حساب بصمة الملف SHA256"""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except:
        return None

def check_digital_signature(file_path):
    """فحص التوقيع الرقمي باستخدام PowerShell"""
    if not file_path.lower().endswith(('.exe', '.dll')):
        return False
    try:
        cmd = f'Get-AuthenticodeSignature "{file_path}" | Select-Object -ExpandProperty Status'
        result = subprocess.check_output(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", cmd], text=True, stderr=subprocess.DEVNULL, timeout=2).strip()
        return "Valid" in result
    except:
        return False

def scan_suspicious_files(directory, max_files=15):
    suspicious_files = []
    extensions = ('.exe', '.bat', '.ps1', '.vbs', '.dll')
    ignore_dirs = {'node_modules', '.git', 'venv', '.venv', '__pycache__', '.idea', '.vscode', 'cache', 'code cache', 'gpu_cache'}
    
    print(f"      [DEBUG] Deep scanning: {directory}")
    checked = 0
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if not d.startswith('.') and d.lower() not in ignore_dirs]
        if checked >= max_files:
            dirs.clear()
            break
        for file in files:
            if file.lower().endswith(extensions):
                full_path = os.path.join(root, file)
                checked += 1
                
                # 1. فحص التوقيع
                is_signed = check_digital_signature(full_path)
                
                # 2. حساب الهاش
                file_hash = get_file_hash(full_path)
                
                risk_reason = []
                severity = "INFO"

                if not is_signed:
                    risk_reason.append("Unsigned Executable")
                    severity = "HIGH"
                
                if file_hash in KNOWN_MALWARE_HASHES:
                    risk_reason.append("KNOWN MALWARE HASH MATCH 💀")
                    severity = "CRITICAL"

                if risk_reason:
                    suspicious_files.append({
                        "path": full_path,
                        "reasons": ", ".join(risk_reason),
                        "hash": file_hash,
                        "severity": severity
                    })
                
                if checked >= max_files:
                    dirs.clear()
                    break
                    
    return suspicious_files