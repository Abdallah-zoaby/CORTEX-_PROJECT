"""Persistence training uses fictional events; it never edits startup state."""

class PersistenceSim:
    def method_registry(self):
        return '[SIMULATION] Fictional HKCU Run entry observed; no registry access. User-writable startup settings alone are not vulnerabilities.'

    def method_startup_folder(self):
        return '[SIMULATION] Fictional startup item reviewed; no files created or removed.'

    def attempt_persistence(self):
        return '\n'.join(('[SIMULATION ONLY] Persistence review exercise; no host changes.',
                          self.method_registry(), self.method_startup_folder()))
