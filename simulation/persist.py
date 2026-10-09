import winreg
import os
import shutil
import sys

class PersistenceSim:
    def __init__(self):
        # المسار اللي الفيروسات بتكتب فيه عشان تشتغل تلقائي
        self.reg_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        self.app_name = "Cortex_Security_Test"
        self.exe_path = sys.executable # بنستخدم مسار البايثون الحالي للتجربة

    def method_registry(self):
        """1. اختبار الحقن في الريجستري (Registry Injection)"""
        try:
            # محاولة فتح المفتاح للكتابة
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.reg_path, 0, winreg.KEY_SET_VALUE)
            # محاولة وضع قيمة
            winreg.SetValueEx(key, self.app_name, 0, winreg.REG_SZ, self.exe_path)
            winreg.CloseKey(key)
            return "❌ VULNERABLE: Registry Write Successful (HKCU Run)."
        except PermissionError:
            return "✅ SECURE: Registry Access Denied."
        except Exception as e:
            return f"[-] Registry Test Error: {e}"

    def method_startup_folder(self):
        """2. اختبار الكتابة في مجلد بدء التشغيل (Startup Folder)"""
        startup_dir = os.path.join(os.getenv('APPDATA'), r'Microsoft\Windows\Start Menu\Programs\Startup')
        test_file = os.path.join(startup_dir, "Cortex_Test.txt")
        
        try:
            # محاولة إنشاء ملف داخل الفولدر الحساس ده
            with open(test_file, "w") as f:
                f.write("This is a persistence test from Cortex Security.")
            
            # لو نجحنا نكتب الملف، نمسحه تاني ونبلغ بوجود ثغرة
            os.remove(test_file)
            return "❌ VULNERABLE: Startup Folder is Writable by script."
        except PermissionError:
            return "✅ SECURE: Startup Folder Protected."
        except Exception as e:
            return f"[-] Startup Test Error: {e}"

    def attempt_persistence(self):
        results = ["[*] Testing Persistence Vectors (Real Emulation)..."]
        
        # تنفيذ الاختبار الأول
        res_reg = self.method_registry()
        results.append(f"1. Registry Check: {res_reg}")
        
        # تنفيذ الاختبار الثاني
        res_folder = self.method_startup_folder()
        results.append(f"2. Startup Dir Check: {res_folder}")

        # تنظيف الأثر (لو نجح في الكتابة في الريجستري لازم نمسحه)
        if "VULNERABLE" in res_reg:
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.reg_path, 0, winreg.KEY_SET_VALUE)
                winreg.DeleteValue(key, self.app_name)
                winreg.CloseKey(key)
                results.append("[*] Cleanup: Malicious Registry key removed.")
            except: pass
            
        return "\n".join(results)