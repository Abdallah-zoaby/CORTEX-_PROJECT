"""Optional real packet metadata capture. Never substitute fake traffic."""
import threading


class NetworkAnomalyDetector:
    def __init__(self):
        self.is_sniffing = False
        self.anomaly_log = []
        self._stop = threading.Event()
        self._thread = None
        self._lock = threading.Lock()
        try:
            from scapy.all import sniff
            self._sniff = sniff
        except ImportError:
            self._sniff = None
        self.scapy_available = self._sniff is not None

    def start_sniffing(self, callback_func, on_stopped=None):
        with self._lock:
            if self._thread and self._thread.is_alive():
                return False
            if not self.scapy_available:
                callback_func('Capture unavailable: Scapy and a supported capture driver are required. No packets inspected.', 'WARNING')
                return False
            self._stop.clear()
            self.is_sniffing = True

            def capture():
                try:
                    while not self._stop.is_set():
                        self._sniff(prn=packet, store=False, timeout=0.5)
                except Exception as exc:
                    callback_func(f'Capture failed ({type(exc).__name__}); coverage is unknown. No simulation substituted.', 'WARNING')
                finally:
                    self.is_sniffing = False
                    if on_stopped:
                        on_stopped()

            def packet(value):
                if not self._stop.is_set():
                    callback_func(f'PACKET METADATA: {value.summary()} (not a threat verdict)', 'INFO')

            self._thread = threading.Thread(target=capture, daemon=True)
            self._thread.start()
            return True

    def stop_sniffing(self):
        self._stop.set()
