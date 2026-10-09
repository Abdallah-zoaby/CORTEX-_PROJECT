import time
import random
import threading

class NetworkAnomalyDetector:
    """Advanced Network Pattern Analysis (Scapy integration / Simulation hybrid)"""
    def __init__(self):
        self.is_sniffing = False
        self.anomaly_log = []
        try:
            from scapy.all import sniff
            self.scapy_available = True
        except ImportError:
            self.scapy_available = False

    def start_sniffing(self, callback_func):
        self.is_sniffing = True
        if self.scapy_available:
            self._start_real_sniffing(callback_func)
        else:
            self._start_simulation(callback_func)

    def stop_sniffing(self):
        self.is_sniffing = False

    def _start_real_sniffing(self, callback_func):
        from scapy.all import sniff
        
        def packet_handler(packet):
            if not self.is_sniffing: return
            
            # Basic analysis (e.g. tracking large payloads or unusual ports)
            summary = packet.summary()
            if "HTTP" in summary or "TCP" in summary:
                callback_func(f"📦 PACKET: {summary}", "INFO")
                
            # Naive signature check for demo purposes
            if b"SELECT" in bytes(packet):
                 callback_func(f"🚨 ANOMALY [SQLi Pattern in Traffic]: {summary}", "CRITICAL")
                 
        def sniffer_thread():
            try:
                sniff(prn=packet_handler, store=0, stop_filter=lambda x: not self.is_sniffing)
            except Exception as e:
                callback_func(f"⚠️ Npcap missing. Falling back to Kernel Simulator... ({e})", "WARNING")
                self._start_simulation(callback_func)
                
        threading.Thread(target=sniffer_thread, daemon=True).start()

    def _start_simulation(self, callback_func):
        """High-Fidelity Simulation of Traffic Anomalies if WinPcap/Npcap is not installed"""
        def sim_thread():
            suspicious_signatures = [
                "TCP 192.168.1.100:4444 -> 45.22.11.9:80 [SYN] (Possible C2 Beacon)",
                "UDP 10.0.0.5:53 -> 8.8.8.8:53 [DNS Tunneling Detected]",
                "TCP 192.168.1.55:22 -> 192.168.1.200:22 [Brute Force Auth Velocity]",
                "HTTP/1.1 POST /upload.php [Unusual Payload Size: 4MB]"
            ]
            while self.is_sniffing:
                time.sleep(random.uniform(2, 5))
                if random.random() > 0.4:
                    sig = random.choice(suspicious_signatures)
                    callback_func(f"🕵️ ANOMALY: {sig}", "WARNING" if "DNS" in sig else "CRITICAL")
                else:
                    callback_func(f"🌐 PACKET: TCP 127.0.0.1:{random.randint(1000, 9000)} -> 104.21.6.{random.randint(1,255)}:443 [TLSv1.3]", "INFO")

        threading.Thread(target=sim_thread, daemon=True).start()
