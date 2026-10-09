
import os
import secrets
import base64
import hashlib
import socket
import json
import datetime
from Crypto.Cipher import AES
import logging
from typing import Dict

logger = logging.getLogger("TitaniumScanner")

class SecurityManager:
    """Enhanced security and encryption manager"""
    
    def __init__(self):
        self.encryption_key = self._load_encryption_key()
        self.audit_logs = []
    
    def _load_encryption_key(self):
        """Load encryption key from environment or generate"""
        key = os.environ.get('TITANIUM_ENCRYPTION_KEY')
        if not key:
            key = secrets.token_hex(32)
            logger.warning("⚠️ Using generated encryption key. Set TITANIUM_ENCRYPTION_KEY for persistence.")
        return key.encode()
    
    def encrypt_sensitive(self, data: str) -> str:
        """Encrypt sensitive data"""
        cipher = AES.new(
            hashlib.sha256(self.encryption_key).digest()[:32],
            AES.MODE_GCM
        )
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())
        return base64.b64encode(cipher.nonce + tag + ciphertext).decode()
    
    def decrypt_sensitive(self, encrypted: str) -> str:
        """Decrypt sensitive data"""
        data = base64.b64decode(encrypted)
        nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
        cipher = AES.new(
            hashlib.sha256(self.encryption_key).digest()[:32],
            AES.MODE_GCM,
            nonce=nonce
        )
        return cipher.decrypt_and_verify(ciphertext, tag).decode()
    
    def hash_identifiable_data(self, data: str) -> str:
        """Hash identifiable data for privacy"""
        return hashlib.sha256(
            data.encode() + self.encryption_key
        ).hexdigest()
    
    def log_security_event(self, event_type: str, details: Dict):
        """Log security events"""
        event = {
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'type': event_type,
            'details': details,
            'ip': self._get_client_ip(),
            'user_agent': self._get_user_agent()
        }
        self.audit_logs.append(event)
        
        # Save to secure log file
        log_file = f"security_audit_{datetime.date.today()}.log"
        with open(log_file, 'a') as f:
            f.write(json.dumps(event) + '\n')
    
    def _get_client_ip(self) -> str:
        """Get client IP address"""
        try:
            return socket.gethostbyname(socket.gethostname())
        except:
            return "127.0.0.1"
    
    def _get_user_agent(self) -> str:
        """Get user agent"""
        return f"TitaniumScanner/15.0"
