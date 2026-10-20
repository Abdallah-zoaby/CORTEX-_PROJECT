"""Compatibility entry point for the shared scanner web API."""
from .main import TitaniumScannerV15, ScanConfig, ScanMode
from .web_interface import ScannerWebInterface


class WebInterface(ScannerWebInterface):
    def __init__(self, scanner):
        super().__init__(scanner, TitaniumScannerV15, ScanConfig, ScanMode)
