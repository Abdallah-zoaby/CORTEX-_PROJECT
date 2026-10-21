__all__ = ['CortexScanner', 'TitaniumScannerV15']


def __getattr__(name):
    # Importing a utility must not open/mutate a scanner database or load AI SDKs.
    if name in __all__:
        from .main import CortexScanner, TitaniumScannerV15
        return {'CortexScanner': CortexScanner, 'TitaniumScannerV15': TitaniumScannerV15}[name]
    raise AttributeError(name)
