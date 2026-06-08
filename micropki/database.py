import sqlite3
from pathlib import Path
from datetime import datetime, timezone
import hashlib
from cryptography.hazmat.primitives import serialization

SCHEMA = """
CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    serial_hex TEXT UNIQUE NOT NULL,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    cert_pem TEXT NOT NULL,
    status TEXT NOT NULL,
    revocation_reason TEXT,
    revocation_date TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_serial_hex ON certificates(serial_hex);
CREATE INDEX IF NOT EXISTS idx_status ON certificates(status);
"""

CRL_METADATA_SCHEMA = """
CREATE TABLE IF NOT EXISTS crl_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ca_subject TEXT NOT NULL UNIQUE,
    crl_number INTEGER NOT NULL,
    last_generated TEXT NOT NULL,
    next_update TEXT NOT NULL,
    crl_path TEXT NOT NULL
);
"""

COMPROMISED_KEYS_SCHEMA = """
CREATE TABLE IF NOT EXISTS compromised_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    public_key_hash TEXT UNIQUE NOT NULL,
    certificate_serial TEXT NOT NULL,
    compromise_date TEXT NOT NULL,
    compromise_reason TEXT NOT NULL,
    FOREIGN KEY (certificate_serial) REFERENCES certificates(serial_hex)
);
"""

def init_db(db_path):
    """Create database schema if not exists. Idempotent."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    conn.executescript(CRL_METADATA_SCHEMA)
    conn.executescript(COMPROMISED_KEYS_SCHEMA)
    conn.commit()
    conn.close()

def insert_certificate(db_path, cert_data):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()
    cursor.execute("""
        INSERT INTO certificates
        (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (cert_data['serial_hex'], cert_data['subject'], cert_data['issuer'],
          cert_data['not_before'], cert_data['not_after'], cert_data['cert_pem'],
          cert_data['status'], now))
    conn.commit()
    conn.close()
    return True

def get_certificate_by_serial(db_path, serial_hex):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT cert_pem FROM certificates WHERE serial_hex = ?", (serial_hex,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None

def list_certificates(db_path, status=None):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    query = "SELECT serial_hex, subject, not_before, not_after, status FROM certificates"
    params = []
    if status:
        query += " WHERE status = ?"
        params.append(status)
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    return rows

def update_certificate_status(db_path, serial_hex, status, reason=None, rev_date=None):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    if status == 'revoked':
        cursor.execute("""
            UPDATE certificates
            SET status = ?, revocation_reason = ?, revocation_date = ?
            WHERE serial_hex = ?
        """, (status, reason, rev_date.isoformat() if rev_date else None, serial_hex))
    else:
        cursor.execute("UPDATE certificates SET status = ? WHERE serial_hex = ?", (status, serial_hex))
    conn.commit()
    conn.close()

def get_certificate_status(db_path, serial_hex):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT status FROM certificates WHERE serial_hex = ?", (serial_hex,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None

def get_certificate_revocation_info(db_path, serial_hex):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT revocation_date, revocation_reason FROM certificates WHERE serial_hex = ?", (serial_hex,))
    row = cursor.fetchone()
    conn.close()
    return row[0], row[1] if row else (None, None)

def get_revoked_certificates(db_path, issuer_name=None):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT serial_hex, revocation_date FROM certificates WHERE status = 'revoked'")
    rows = cursor.fetchall()
    conn.close()
    result = []
    for row in rows:
        rev_date = datetime.fromisoformat(row[1]) if row[1] else None
        result.append((row[0], rev_date))
    return result

def get_crl_number(db_path, ca_subject):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT crl_number FROM crl_metadata WHERE ca_subject = ?", (ca_subject,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else 1

def update_crl_number(db_path, ca_subject, number, last_gen, next_upd, crl_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO crl_metadata (ca_subject, crl_number, last_generated, next_update, crl_path)
        VALUES (?, ?, ?, ?, ?)
    """, (ca_subject, number, last_gen.isoformat(), next_upd.isoformat(), crl_path))
    conn.commit()
    conn.close()

def mark_key_compromised(db_path, public_key, cert_serial, reason):
    """Записывает публичный ключ как скомпрометированный."""
    pub_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    hash_val = hashlib.sha256(pub_der).hexdigest()
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO compromised_keys (public_key_hash, certificate_serial, compromise_date, compromise_reason)
        VALUES (?, ?, ?, ?)
    """, (hash_val, cert_serial, datetime.now(timezone.utc).isoformat(), reason))
    conn.commit()
    conn.close()

def is_key_compromised(db_path, public_key):
    """Проверяет, числится ли публичный ключ в таблице compromised_keys."""
    pub_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    hash_val = hashlib.sha256(pub_der).hexdigest()
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM compromised_keys WHERE public_key_hash = ?", (hash_val,))
    found = cursor.fetchone() is not None
    conn.close()
    return found