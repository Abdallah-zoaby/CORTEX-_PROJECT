import sys
import os
import time

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

from colorama import init, Fore, Style
from engine.cortex import CortexScanner
from reports.pdf_generator import generate_pdf_report

# تهيئة الألوان والترميز
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
init(autoreset=True)

def print_banner():
    # لوجو CORTEX
    banner = f"""
    {Fore.CYAN}
     █████╗ ██████╗ ██████╗  █████╗ ██╗     ██╗      █████╗ ██╗  ██╗
    ██╔══██╗██╔══██╗██╔══██╗██╔══██╗██║     ██║     ██╔══██╗██║  ██║
    ███████║██████╔╝██║  ██║███████║██║     ██║     ███████║███████║
    ██╔══██║██╔══██╗██║  ██║██╔══██║██║     ██║     ██╔══██║██╔══██║
    ██║  ██║██████╔╝██████╔╝██║  ██║███████╗███████╗██║  ██║██║  ██║
    ╚═╝  ╚═╝╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
    {Fore.WHITE}            >>> THE ULTIMATE FORENSIC AUDITOR <<<
    {Fore.YELLOW}                 Developed by: CORTEX
    """
    print(banner)
    print(f"{Fore.GREEN}    [ SYSTEM INTEGRITY CHECKER & RISK ANALYZER ]")
    print("-" * 60)

def start_cortex_system():
    os.system('cls' if os.name == 'nt' else 'clear')
    print_banner()
    
    # تشغيل الماسح (الماتور)
    scanner = CortexScanner()
    result_engine = scanner.run_full_scan()

    # عرض النتيجة النهائية
    verdict, color_name = result_engine.get_verdict()
    
    final_color = Fore.GREEN
    if color_name == "ORANGE": final_color = Fore.YELLOW
    elif color_name == "RED": final_color = Fore.RED
    elif color_name == "DARKRED": final_color = Fore.MAGENTA

    print("\n" + "="*50)
    print(f"{final_color}🎯 SYSTEM STATUS: {verdict}")
    print(f"{Fore.WHITE}📊 Total Issues Found: {len(result_engine.findings)}")
    print("="*50)

    # طباعة التقرير
    print(f"\n{Fore.BLUE}📄 Generating CORTEX Report...", end="")
    generate_pdf_report(result_engine, filename="CORTEX_Final_Report.pdf")
    print(f" {Fore.GREEN}Done!")

if __name__ == "__main__":
    try:
        start_cortex_system()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}🛑 Scan Aborted by User.")
    except Exception as e:
        print(f"\n{Fore.RED}❌ Fatal Error: {e}")