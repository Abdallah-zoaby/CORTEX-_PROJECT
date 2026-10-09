
# === CONFIGURATION ===
import logging

CONFIG = {
    'DB_PATH': "sqlite:///cortex_v15.db",
    'MAX_DEPTH': 5,
    'CONCURRENCY_LIMIT': 25,
    'TIMEOUT': 15,
    'MAX_REQUESTS_PER_MINUTE': 60,
    'CACHE_TTL': 300,  # 5 minutes
    'REPORT_FORMATS': ['json', 'pdf', 'html', 'csv'],
    'PLUGIN_DIR': "plugins",
    'LOG_LEVEL': logging.INFO,
    'ENCRYPTION_KEY': None,  # Set via environment variable
}
