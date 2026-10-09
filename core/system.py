import winreg
import psutil
import subprocess
import os

def scan_startup_apps():
    """فحص برامج بدء التشغيل (القديم + تحديثات)"""
    suspicious_apps = []
    registry_paths = [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    ]
    
    for reg_path in registry_paths:
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_READ)
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    risk = "INFO"
                    lower_val = value.lower()
                    
                    # تحليل ذكي: البرامج اللي بتشتغل من AppData أو Temp غالباً فيروسات
                    if "appdata" in lower_val or "temp" in lower_val:
                        risk = "HIGH"
                    elif ".vbs" in lower_val or ".bat" in lower_val or "powershell" in lower_val:
                        risk = "CRITICAL"
                        
                    suspicious_apps.append({"name": name, "path": value, "risk": risk})
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except:
            pass
    return suspicious_apps

def scan_running_processes():
    """(جديد) فحص العمليات الشغالة في الرامات حالياً"""
    suspicious_procs = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            p_info = proc.info
            name = p_info['name']
            exe_path = p_info['exe'] or ""
            
            # 1. فحص العمليات اللي شغالة من أماكن مشبوهة
            if "AppData" in exe_path or "Temp" in exe_path:
                suspicious_procs.append({
                    "pid": p_info['pid'],
                    "name": name,
                    "reason": "Running from Temp/AppData",
                    "severity": "HIGH"
                })
            
            # 2. فحص عمليات الـ Mining (التعدين)
            if name.lower() in ["xmrig.exe", "minerd.exe", "nicehash.exe"]:
                suspicious_procs.append({
                    "pid": p_info['pid'],
                    "name": name,
                    "reason": "Crypto Miner Detected",
                    "severity": "CRITICAL"
                })
                
            # 3. فحص الباور شيل المخفي
            if name.lower() == "powershell.exe":
                cmd = p_info['cmdline'] or []
                if "-w hidden" in str(cmd).lower() or "-enc" in str(cmd).lower():
                    suspicious_procs.append({
                        "pid": p_info['pid'],
                        "name": name,
                        "reason": "Hidden PowerShell Script",
                        "severity": "CRITICAL"
                    })

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
            
    return suspicious_procs

def scan_scheduled_tasks():
    """(جديد) فحص المهام المجدولة الخبيثة"""
    risky_tasks = []
    try:
        # بنستخدم أمر الويندوز عشان نجيب كل المهام
        output = subprocess.check_output('schtasks /query /fo CSV /v', shell=True, encoding='cp850', errors='ignore')
        lines = output.split('\n')
        for line in lines:
            if "TaskName" in line: continue # Skip header
            
            # لو المهمة فيها سكريبتات مشبوهة
            lower_line = line.lower()
            if ".vbs" in lower_line or ".bat" in lower_line or "powershell" in lower_line:
                # تنظيف النص لاستخراج الاسم
                parts = line.split(',')
                if len(parts) > 0:
                    task_name = parts[0].replace('"', '')
                    risky_tasks.append(task_name)
    except:
        pass
    return risky_tasks