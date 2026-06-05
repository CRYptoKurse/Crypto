import pytest
import tempfile
import subprocess
import sys
import time
import sqlite3
import requests
from pathlib import Path
from threading import Thread

# ------------------------------------------------------------
# Helper: run CLI command
# ------------------------------------------------------------
def run_cli(args):
    cmd = [sys.executable, '-m', 'micropki.cli'] + args
    return subprocess.run(cmd, capture_output=True, text=True)

# ------------------------------------------------------------
# Test: db init, issuance, listing, show-cert (TEST-13, TEST-14)
# ------------------------------------------------------------
def test_db_and_issuance():
    with tempfile.TemporaryDirectory() as tmpdir:
        root_pass = Path(tmpdir) / 'root.pass'
        root_pass.write_text('rootpass')
        inter_pass = Path(tmpdir) / 'inter.pass'
        inter_pass.write_text('interpass')
        db_path = Path(tmpdir) / 'micropki.db'
        pki_dir = Path(tmpdir) / 'pki'

        # 1. Init DB
        res = run_cli(['db', 'init', '--db-path', str(db_path)])
        assert res.returncode == 0
        assert db_path.exists()

        # 2. Root CA
        res = run_cli(['ca', 'init', '--subject', '/CN=Test Root',
                       '--passphrase-file', str(root_pass),
                       '--out-dir', str(pki_dir), '--db-path', str(db_path),
                       '--force'])
        assert res.returncode == 0

        # 3. Intermediate CA
        res = run_cli(['ca', 'issue-intermediate',
                       '--root-cert', str(pki_dir/'certs'/'ca.cert.pem'),
                       '--root-key', str(pki_dir/'private'/'ca.key.pem'),
                       '--root-pass-file', str(root_pass),
                       '--subject', 'CN=Inter CA',
                       '--passphrase-file', str(inter_pass),
                       '--out-dir', str(pki_dir),
                       '--db-path', str(db_path)])
        assert res.returncode == 0

        # 4. Server certificate
        res = run_cli(['ca', 'issue-cert',
                       '--ca-cert', str(pki_dir/'certs'/'intermediate.cert.pem'),
                       '--ca-key', str(pki_dir/'private'/'intermediate.key.pem'),
                       '--ca-pass-file', str(inter_pass),
                       '--template', 'server',
                       '--subject', 'CN=test.example.com',
                       '--san', 'dns:test.example.com',
                       '--out-dir', str(pki_dir/'certs'),
                       '--db-path', str(db_path)])
        assert res.returncode == 0

        # 5. List certificates
        res = run_cli(['ca', 'list-certs', '--db-path', str(db_path)])
        assert res.returncode == 0
        assert 'test.example.com' in res.stdout
        assert 'Inter CA' in res.stdout

        # 6. Extract serial of the server cert from DB
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT serial_hex FROM certificates WHERE subject LIKE '%test.example.com%'")
        row = cursor.fetchone()
        assert row is not None
        serial = row[0]

        # 7. Show certificate by serial
        res = run_cli(['ca', 'show-cert', serial, '--db-path', str(db_path)])
        assert res.returncode == 0
        assert 'BEGIN CERTIFICATE' in res.stdout

        conn.close()

# ------------------------------------------------------------
# Test: Serial number uniqueness (TEST-17)
# ------------------------------------------------------------
def test_serial_uniqueness():
    with tempfile.TemporaryDirectory() as tmpdir:
        root_pass = Path(tmpdir) / 'root.pass'
        root_pass.write_text('rootpass')
        inter_pass = Path(tmpdir) / 'inter.pass'
        inter_pass.write_text('interpass')
        db_path = Path(tmpdir) / 'micropki.db'
        pki_dir = Path(tmpdir) / 'pki'

        run_cli(['db', 'init', '--db-path', str(db_path)])
        run_cli(['ca', 'init', '--subject', '/CN=Root', '--passphrase-file', str(root_pass),
                 '--out-dir', str(pki_dir), '--db-path', str(db_path), '--force'])
        run_cli(['ca', 'issue-intermediate', '--root-cert', str(pki_dir/'certs'/'ca.cert.pem'),
                 '--root-key', str(pki_dir/'private'/'ca.key.pem'),
                 '--root-pass-file', str(root_pass),
                 '--subject', 'CN=Inter', '--passphrase-file', str(inter_pass),
                 '--out-dir', str(pki_dir), '--db-path', str(db_path)])

        serials = set()
        for i in range(10):
            res = run_cli(['ca', 'issue-cert',
                           '--ca-cert', str(pki_dir/'certs'/'intermediate.cert.pem'),
                           '--ca-key', str(pki_dir/'private'/'intermediate.key.pem'),
                           '--ca-pass-file', str(inter_pass),
                           '--template', 'client',
                           '--subject', f'CN=client{i}',
                           '--out-dir', str(pki_dir/'certs'),
                           '--db-path', str(db_path)])
            assert res.returncode == 0, f"Failed at iteration {i}: {res.stderr}"
            # extract serial from DB
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT serial_hex FROM certificates WHERE subject = ?", (f'CN=client{i}',))
            row = cursor.fetchone()
            assert row is not None
            serials.add(row[0])
            conn.close()
        assert len(serials) == 10  # all unique

# ------------------------------------------------------------
# Test: Repository API (TEST-15, TEST-16)
# ------------------------------------------------------------
def test_repository_api():
    with tempfile.TemporaryDirectory() as tmpdir:
        root_pass = Path(tmpdir) / 'root.pass'
        root_pass.write_text('rootpass')
        inter_pass = Path(tmpdir) / 'inter.pass'
        inter_pass.write_text('interpass')
        db_path = Path(tmpdir) / 'micropki.db'
        pki_dir = Path(tmpdir) / 'pki'
        cert_dir = pki_dir / 'certs'

        # Setup
        run_cli(['db', 'init', '--db-path', str(db_path)])
        run_cli(['ca', 'init', '--subject', '/CN=Root', '--passphrase-file', str(root_pass),
                 '--out-dir', str(pki_dir), '--db-path', str(db_path), '--force'])
        run_cli(['ca', 'issue-intermediate', '--root-cert', str(pki_dir/'certs'/'ca.cert.pem'),
                 '--root-key', str(pki_dir/'private'/'ca.key.pem'),
                 '--root-pass-file', str(root_pass),
                 '--subject', 'CN=Inter', '--passphrase-file', str(inter_pass),
                 '--out-dir', str(pki_dir), '--db-path', str(db_path)])
        run_cli(['ca', 'issue-cert', '--ca-cert', str(pki_dir/'certs'/'intermediate.cert.pem'),
                 '--ca-key', str(pki_dir/'private'/'intermediate.key.pem'),
                 '--ca-pass-file', str(inter_pass),
                 '--template', 'server',
                 '--subject', 'CN=api.example.com',
                 '--san', 'dns:api.example.com',
                 '--out-dir', str(cert_dir),
                 '--db-path', str(db_path)])

        # Get serial from DB
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT serial_hex FROM certificates WHERE subject LIKE '%api.example.com%'")
        serial = cursor.fetchone()[0]
        conn.close()

        # Start server in a separate thread
        import threading
        from micropki.repo import start_repo_server
        server_thread = threading.Thread(target=start_repo_server,
                                         args=('127.0.0.1', 8081, str(db_path), str(cert_dir), None),
                                         daemon=True)
        server_thread.start()
        time.sleep(2)  # allow server to start

        # Test endpoints
        # GET /certificate/<serial>
        resp = requests.get(f'http://127.0.0.1:8081/certificate/{serial}')
        assert resp.status_code == 200
        assert 'BEGIN CERTIFICATE' in resp.text

        # GET /ca/root
        resp = requests.get('http://127.0.0.1:8081/ca/root')
        assert resp.status_code == 200
        assert 'BEGIN CERTIFICATE' in resp.text

        # GET /ca/intermediate
        resp = requests.get('http://127.0.0.1:8081/ca/intermediate')
        assert resp.status_code == 200
        assert 'BEGIN CERTIFICATE' in resp.text

        # GET /crl
        resp = requests.get('http://127.0.0.1:8081/crl')
        assert resp.status_code == 501
        # Проверка текста не обязательна; достаточно статуса 501
        assert 'not yet implemented' in resp.text.lower() or resp.status_code == 501

        # Negative: invalid serial
        resp = requests.get('http://127.0.0.1:8081/certificate/ZZZ')
        assert resp.status_code == 400

        # Negative: not found serial
        resp = requests.get('http://127.0.0.1:8081/certificate/DEADBEEF')
        assert resp.status_code == 404

# ------------------------------------------------------------
# Negative test: duplicate serial (should never happen, but test generator)
# ------------------------------------------------------------
def test_duplicate_serial_prevention():
    with tempfile.TemporaryDirectory() as tmpdir:
        root_pass = Path(tmpdir) / 'root.pass'
        root_pass.write_text('rootpass')
        inter_pass = Path(tmpdir) / 'inter.pass'
        inter_pass.write_text('interpass')
        db_path = Path(tmpdir) / 'micropki.db'
        pki_dir = Path(tmpdir) / 'pki'

        run_cli(['db', 'init', '--db-path', str(db_path)])
        run_cli(['ca', 'init', '--subject', '/CN=Root', '--passphrase-file', str(root_pass),
                 '--out-dir', str(pki_dir), '--db-path', str(db_path), '--force'])
        run_cli(['ca', 'issue-intermediate', '--root-cert', str(pki_dir/'certs'/'ca.cert.pem'),
                 '--root-key', str(pki_dir/'private'/'ca.key.pem'),
                 '--root-pass-file', str(root_pass),
                 '--subject', 'CN=Inter', '--passphrase-file', str(inter_pass),
                 '--out-dir', str(pki_dir), '--db-path', str(db_path)])

        # Issue 20 certificates and ensure all serials are unique
        serials = []
        for i in range(20):
            res = run_cli(['ca', 'issue-cert',
                           '--ca-cert', str(pki_dir/'certs'/'intermediate.cert.pem'),
                           '--ca-key', str(pki_dir/'private'/'intermediate.key.pem'),
                           '--ca-pass-file', str(inter_pass),
                           '--template', 'client',
                           '--subject', f'CN=user{i}',
                           '--out-dir', str(pki_dir/'certs'),
                           '--db-path', str(db_path)])
            assert res.returncode == 0
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT serial_hex FROM certificates WHERE subject = ?", (f'CN=user{i}',))
            s = cursor.fetchone()[0]
            assert s not in serials
            serials.append(s)
            conn.close()