from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json

class CTLog:
    def __init__(self, log_path: str = "./pki/audit/ct.log"):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, serial_hex: str, subject: str, cert_pem: bytes, issuer: str = None):
        fingerprint = hashlib.sha256(cert_pem).hexdigest()
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec='microseconds'),
            "serial": serial_hex,
            "subject": subject,
            "fingerprint": fingerprint,
            "issuer": issuer
        }
        with open(self.log_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry) + '\n')
            f.flush()