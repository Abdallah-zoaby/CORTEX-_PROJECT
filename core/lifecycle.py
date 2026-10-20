"""Cooperative stop/deadline state; an in-flight OS query has its own timeout."""
import threading
import time


class ScanStopped(RuntimeError):
    def __init__(self, status):
        self.status = status
        super().__init__(status)


class ScanControl:
    def __init__(self, max_seconds=180):
        if max_seconds <= 0:
            raise ValueError('A positive assessment deadline is required')
        self.event = threading.Event()
        self.deadline = time.monotonic() + max_seconds

    def cancel(self):
        self.event.set()

    def checkpoint(self):
        if self.event.is_set():
            raise ScanStopped('cancelled')
        if time.monotonic() >= self.deadline:
            raise ScanStopped('timed_out')
