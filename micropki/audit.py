import json
import os
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from pathlib import Path

class AuditLogger:
    """Аудит-логгер с хеш-цепочкой (NDJSON + chain.dat)."""

    def __init__(self, log_path: str, chain_path: str = None):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        if chain_path is None:
            chain_path = self.log_path.parent / 'chain.dat'
        self.chain_path = Path(chain_path)
        self._last_hash = self._read_last_hash()

    def _read_last_hash(self) -> str:
        if self.chain_path.exists():
            return self.chain_path.read_text().strip()
        return '0' * 64

    def _write_last_hash(self, h: str):
        self.chain_path.write_text(h)

    def _compute_entry_hash(self, entry: Dict) -> str:
        # Создаём копию без поля integrity.hash
        data = {k: v for k, v in entry.items() if k != 'integrity'}
        # Сортируем ключи для каноничности
        canonical = json.dumps(data, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(canonical.encode()).hexdigest()

    def log(self, level: str, operation: str, status: str, message: str,
            metadata: Optional[Dict] = None) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec='microseconds'),
            "level": level.upper(),
            "operation": operation,
            "status": status,
            "message": message,
            "metadata": metadata or {},
            "integrity": {
                "prev_hash": self._last_hash,
                "hash": ""
            }
        }
        entry_hash = self._compute_entry_hash(entry)
        entry["integrity"]["hash"] = entry_hash

        with open(self.log_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry) + '\n')
            f.flush()
            os.fsync(f.fileno())

        self._last_hash = entry_hash
        self._write_last_hash(entry_hash)

    def verify(self) -> tuple[bool, Optional[str]]:
        if not self.log_path.exists():
            return True, None
        prev = '0' * 64
        with open(self.log_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    return False, f"Line {line_num}: invalid JSON"
                if entry.get('integrity', {}).get('prev_hash') != prev:
                    return False, f"Line {line_num}: prev_hash mismatch"
                computed = self._compute_entry_hash(entry)
                if computed != entry['integrity']['hash']:
                    return False, f"Line {line_num}: hash mismatch"
                prev = computed
        stored = self._read_last_hash()
        if prev != stored:
            return False, f"Last hash mismatch"
        return True, None

    def query(self, start_time: str = None, end_time: str = None,
              level: str = None, operation: str = None, serial: str = None,
              fmt: str = 'table') -> List[Dict]:
        results = []
        if not self.log_path.exists():
            return results
        with open(self.log_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                ts = entry['timestamp']
                if start_time and ts < start_time:
                    continue
                if end_time and ts > end_time:
                    continue
                if level and entry['level'] != level.upper():
                    continue
                if operation and entry['operation'] != operation:
                    continue
                if serial and entry.get('metadata', {}).get('serial') != serial:
                    continue
                results.append(entry)
        return results