"""Synthetic training only: never reads user documents or saved Wi-Fi keys."""

class DataLeakSim:
    def __init__(self):
        self.leaked_data = []

    def scan_user_files(self):
        self.leaked_data.append('[SIMULATION] Synthetic document contains an example secret; value withheld. No user files read.')

    def exfiltrate_wifi_passwords(self):
        """Compatibility entry point; credential collection has been removed."""
        self.leaked_data.append('[SIMULATION] Saved Wi-Fi credentials are not collected or displayed. Use Windows settings for authorized local review.')

    def run_simulation(self):
        self.leaked_data = ['[SIMULATION ONLY] Fictional data-loss exercise; no host data access or transmission.']
        self.scan_user_files()
        self.exfiltrate_wifi_passwords()
        return '\n'.join(self.leaked_data)
