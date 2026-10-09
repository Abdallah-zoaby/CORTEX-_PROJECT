import sys
import os

# Ensure the root directory is in the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.system import scan_running_processes, scan_startup_apps
from core.network import scan_open_ports
from core.behavioral import calculate_entropy, BehavioralEngine
from core.twin import DigitalTwinTarget
from engine.scanner.main import CortexScanner, ScanConfig
from engine.scanner.api_audit import APIAuditor
from engine.scanner.mobile import MobileAPKAuditor
from engine.scanner.network_sniffer import NetworkAnomalyDetector
from engine.simulation.purple_controller import PurpleController

def run_qa():
    print("[INIT] CORTEX QA AUTOMATED TEST SUITE")
    errors = 0

    # 1. Test Core System Modules
    print("\n[+] Testing Core System Scanners...")
    try:
        procs = scan_running_processes()
        print(f"  - System Process Scan OK ({len(procs)} procs)")
        ports = scan_open_ports()
        print(f"  - Network Port Scan OK ({len(ports)} ports)")
        entropy = calculate_entropy(b"A"*1000)
        print(f"  - Entropy Calc OK ({entropy:.2f})")
    except Exception as e:
        print(f"  [!] CORE MODULE ERROR: {e}")
        errors += 1

    # 2. Test Digital Twin
    print("\n[+] Testing Digital Twin...")
    try:
        twin = DigitalTwinTarget()
        twin.start()
        print(f"  - Twin Thread Started OK ({twin.get_url()})")
    except Exception as e:
        print(f"  [!] TWIN ERROR: {e}")
        errors += 1

    # 3. Test API & Mobile Auditors
    print("\n[+] Testing API & Mobile Scanners...")
    try:
        api_scan = APIAuditor("http://127.0.0.1:5555").audit_full()
        print(f"  - API Auditor OK ({len(api_scan)} findings simulated)")
        
        # Test hardcoded secrets mock
        mobile = MobileAPKAuditor()
        secrets = mobile.find_secrets("String api_key = 'AIzaSyFakeKey123';")
        print(f"  - Mobile Auditor Secrets OK ({len(secrets)} found)")
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"  [!] MOBILE/API AUDITOR ERROR: {e}")
        errors += 1

    # 4. Test Purple Team Orchestrator
    print("\n[+] Testing Purple Team Orchestrator...")
    try:
        purple = PurpleController()
        # Non-blocking callback
        timeline = purple.run_simulation("127.0.0.1", lambda ev: None)
        print(f"  - Purple Orchestrator OK (Generated {len(timeline)} events)")
        purple.export_logs()
        print(f"  - Log Export OK")
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"  [!] PURPLE ORCHESTRATOR ERROR: {e}")
        errors += 1

    # 5. Test Deep Packet Sniffer (Simulation context)
    print("\n[+] Testing Network Sniffer...")
    try:
        sniffer = NetworkAnomalyDetector()
        print(f"  - Scapy Available: {sniffer.scapy_available}")
        sniffer.start_sniffing(lambda m, c: None)
        sniffer.stop_sniffing()
        print("  - Sniffer Start/Stop OK")
    except Exception as e:
        print(f"  [!] SNIFFER ERROR: {e}")
        errors += 1

    print("\n===============================")
    if errors == 0:
        print("[PASS] QA PASSED: ALL SYSTEMS NOMINAL")
    else:
        print(f"[FAIL] QA FAILED: {errors} MODULES ENCOUNTERED ERRORS")

if __name__ == "__main__":
    run_qa()
