import winreg
import psutil
import subprocess
import os
import csv
import io
from .evidence import classify, process_signals

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
                    
                    # A writable path or script is context, not proof of malware.
                        
                    suspicious_apps.append({"name": name, "path": value, "risk": risk})
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except:
            pass
    return suspicious_apps

def scan_running_processes(inspector=None):
    """Collect process evidence; optional file inspection is explicit and bounded."""
    observations = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'ppid']):
        try:
            p_info = proc.info
            p_info = dict(p_info)
            try:
                parent = psutil.Process(p_info.get('ppid')) if p_info.get('ppid') else None
                p_info['parent_name'] = parent.name() if parent else None
                p_info['parent_path'] = parent.exe() if parent else None
            except (psutil.Error, OSError):
                p_info.update(parent_name=None, parent_path=None)
            if inspector is not None:
                observation = inspector.inspect_process(p_info)
            else:
                observation = classify(process_signals(p_info.get('name'), p_info.get('exe') or '', p_info.get('cmdline')),
                                       signature_status='NotQueried', inspected=False)
                observation.update(pid=p_info.get('pid'), name=p_info.get('name') or 'Unknown',
                                   path=p_info.get('exe'), exe=p_info.get('exe'), cmdline=p_info.get('cmdline'),
                                   parent_pid=p_info.get('ppid'), parent_name=p_info.get('parent_name'),
                                   parent_path=p_info.get('parent_path'), type='Process observation',
                                   source='CORTEX process inventory', inspection_status='metadata_only')
                observation['reason'] = '; '.join(s['reason'] for s in observation['signals']) or 'Process metadata only; contents not scanned'
            observations.append(observation)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
            
    return observations

def scan_scheduled_tasks():
    """Read scripted task observations; query failures propagate as unknown."""
    output = subprocess.check_output(
        ['schtasks', '/query', '/fo', 'CSV', '/v'], timeout=20,
        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
        encoding='cp850', errors='replace')
    observations = []
    for row in csv.DictReader(io.StringIO(output)):
        text = ' '.join(str(v or '') for v in row.values()).lower()
        if any(token in text for token in ('.vbs', '.bat', '.ps1', 'powershell')):
            values = list(row.values())
            name = row.get('TaskName') or (values[1] if len(values) > 1 else 'Name unavailable')
            observations.append(f'Scripted task observation (not a malware verdict): {name}')
    return observations
