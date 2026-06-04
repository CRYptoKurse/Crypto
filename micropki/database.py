import sqlite3
from pathlib import Path

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


def init_db(db_path):
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)   # создаёт папку, если её нет
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()

def insert_certificate(db_path, cert_data):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    from datetime import datetime, timezone
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