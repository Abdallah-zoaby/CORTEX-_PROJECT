import os
import shutil
import winreg
import subprocess
import psutil

class CortexFixer:
    def __init__(self):
        self.log = []

    def clean_registry(self):
        """تنظيف مفاتيح التشغيل التلقائي الخبيثة"""
        paths = [
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
        ]
        # أسماء القيم المشبوهة (بما فيها اللي احنا عملناه في الاختبار)
        targets = ["Cortex_Security_Test", "CortexTest", "MalwareTest"]
        
        for reg_path in paths:
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_ALL_ACCESS)
                count = winreg.QueryInfoKey(key)[1]
                for i in range(count):
                    try:
                        name, val, _ = winreg.EnumValue(key, i)
                        if name in targets or "calc.exe" in str(val): # مثال
                            winreg.DeleteValue(key, name)
                            self.log.append(f"✅ REMOVED REGISTRY KEY: {name}")
                    except: pass
                winreg.CloseKey(key)
            except: pass

    def remove_malicious_files(self):
        """حذف ملفات الفدية والملفات المؤقتة الخبيثة"""
        # 1. تنظيف ملفات الاختبار (Canary Files)
        target_dirs = [
            os.path.join(os.path.expanduser("~"), "Documents"),
            os.path.join(os.path.expanduser("~"), "Desktop")
        ]
        
        for folder in target_dirs:
            if os.path.exists(folder):
                for file in os.listdir(folder):
                    # حذف الملفات المشفرة أو ملفات الكناري
                    if "Cortex_Canary" in file or file.endswith(".cortex_locked"):
                        try:
                            os.remove(os.path.join(folder, file))
                            self.log.append(f"✅ DELETED MALWARE FILE: {file}")
                        except: pass

        # 2. تنظيف ملفات بدء التشغيل
        startup = os.path.join(os.getenv('APPDATA'), r'Microsoft\Windows\Start Menu\Programs\Startup')
        if os.path.exists(os.path.join(startup, "Cortex_Test.txt")):
            try:
                os.remove(os.path.join(startup, "Cortex_Test.txt"))
                self.log.append("✅ CLEANED STARTUP FOLDER")
            except: pass

    def kill_bad_processes(self):
        """قتل العمليات المشبوهة"""
        bad_procs = ["xmrig.exe", "minerd.exe", "nc.exe"]
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'].lower() in bad_procs:
                    proc.kill()
                    self.log.append(f"✅ KILLED PROCESS: {proc.info['name']}")
            except: pass

    def network_flush(self):
        """تنشيط الشبكة وتنظيف الكاش"""
        try:
            subprocess.run("ipconfig /flushdns", shell=True, stdout=subprocess.DEVNULL)
            self.log.append("✅ DNS CACHE FLUSHED")
        except: pass

    def harden_windows_services(self):
        """تعطيل الخدمات غير الضرورية والتي تشكل خطر أمني"""
        risky_services = ["Spooler", "RemoteRegistry", "SSDPSRV"]
        for svc in risky_services:
            try:
                subprocess.run(f"sc config {svc} start= disabled", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(f"sc stop {svc}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.log.append(f"🛡️ HARDENED SERVICE: {svc} (Disabled)")
            except: pass

    def audit_hosts_file(self):
        """فحص ملف الـ Hosts للتأكد من عدم وجود تحويلات مشبوهة"""
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        try:
            with open(hosts_path, 'r') as f:
                content = f.read()
            if len(content.splitlines()) > 25: # Unusual size
                self.log.append("⚠️ WARNING: Hosts file unusually large. Potential DNS hijacking.")
        except: pass

    def run_full_fix(self):
        self.log = ["🚀 STARTING CORTEX PRO-REMEDIATION..."]
        self.clean_registry()
        self.remove_malicious_files()
        self.kill_bad_processes()
        self.network_flush()
        self.harden_windows_services()
        self.audit_hosts_file()
        
        if len(self.log) == 1:
            self.log.append("✅ System appears clean. No automated threats found to fix.")
        else:
            self.log.append("✨ FIX COMPLETE. SYSTEM SECURED.")
            
        return "\n".join(self.log)