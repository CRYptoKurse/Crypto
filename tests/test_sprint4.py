import pytest
import tempfile
import subprocess
import sys
import time
import requests
import sqlite3
from pathlib import Path

def run_cli(args):
    cmd = [sys.executable, '-m', 'micropki.cli'] + args
    return subprocess.run(cmd, capture_output=True, text=True)

def setup_full_chain(tmpdir):
    root_pass = Path(tmpdir) / 'root.pass'
    root_pass.write_text('rootpass')
    inter_pass = Path(tmpdir) / 'inter.pass'
    inter_pass.write_text('interpass')
    db_path = Path(tmpdir) / 'micropki.db'
    pki_dir = Path(tmpdir) / 'pki'
    # init db
    run_cli(['db', 'init', '--db-path', str(db_path)])
    # root ca
    run_cli(['ca', 'init', '--subject', '/CN=Root', '--passphrase-file', str(root_pass),
             '--out-dir', str(pki_dir), '--db-path', str(db_path), '--force'])
    # intermediate
    run_cli(['ca', 'issue-intermediate', '--root-cert', str(pki_dir/'certs'/'ca.cert.pem'),
             '--root-key', str(pki_dir/'private'/'ca.key.pem'), '--root-pass-file', str(root_pass),
             '--subject', 'CN=Inter', '--passphrase-file', str(inter_pass),
             '--out-dir', str(pki_dir), '--db-path', str(db_path)])
    return tmpdir, pki_dir, db_path, root_pass, inter_pass

def test_revocation_lifecycle():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir, pki_dir, db_path, root_pass, inter_pass = setup_full_chain(tmpdir)
        # 1. issue a server cert
        res = run_cli(['ca', 'issue-cert', '--ca-cert', str(pki_dir/'certs'/'intermediate.cert.pem'),
                       '--ca-key', str(pki_dir/'private'/'intermediate.key.pem'),
                       '--ca-pass-file', str(inter_pass), '--template', 'server',
                       '--subject', 'CN=test.com', '--san', 'dns:test.com',
                       '--out-dir', str(pki_dir/'certs'), '--db-path', str(db_path)])
        assert res.returncode == 0
        # get serial from db
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT serial_hex FROM certificates WHERE subject LIKE '%test.com%'")
        serial = cursor.fetchone()[0]
        conn.close()
        # 2. revoke
        res = run_cli(['ca', 'revoke', serial, '--reason', 'keyCompromise', '--db-path', str(db_path)])
        assert res.returncode == 0
        # 3. verify status in db
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT status, revocation_reason FROM certificates WHERE serial_hex = ?", (serial,))
        status, reason = cursor.fetchone()
        assert status == 'revoked'
        assert reason == 'keyCompromise'
        conn.close()
        # 4. generate CRL
        res = run_cli(['ca', 'gen-crl', '--ca', 'intermediate', '--passphrase-file', str(inter_pass),
                       '--out-dir', str(pki_dir), '--db-path', str(db_path), '--next-update', '7'])
        assert res.returncode == 0
        crl_path = pki_dir / 'crl' / 'intermediate.crl.pem'
        assert crl_path.exists()
        # 5. verify CRL with openssl (if available)
        try:
            verify_crl = subprocess.run(['openssl', 'crl', '-in', str(crl_path), '-inform', 'PEM',
                                         '-CAfile', str(pki_dir/'certs'/'intermediate.cert.pem'), '-noout'],
                                        capture_output=True)
            assert verify_crl.returncode == 0
        except FileNotFoundError:
            pytest.skip("OpenSSL not available")
        # 6. check CRL contains serial
        output = subprocess.run(['openssl', 'crl', '-in', str(crl_path), '-text', '-noout'],
                                capture_output=True, text=True)
        assert serial.lower() in output.stdout.lower()

def test_crl_distribution():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir, pki_dir, db_path, root_pass, inter_pass = setup_full_chain(tmpdir)
        # revoke a cert and generate CRL
        res = run_cli(['ca', 'issue-cert', '--ca-cert', str(pki_dir/'certs'/'intermediate.cert.pem'),
                       '--ca-key', str(pki_dir/'private'/'intermediate.key.pem'),
                       '--ca-pass-file', str(inter_pass), '--template', 'client',
                       '--subject', 'CN=revoke_me', '--out-dir', str(pki_dir/'certs'),
                       '--db-path', str(db_path)])
        assert res.returncode == 0
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT serial_hex FROM certificates WHERE subject='CN=revoke_me'")
        serial = cursor.fetchone()[0]
        conn.close()
        run_cli(['ca', 'revoke', serial, '--db-path', str(db_path)])
        run_cli(['ca', 'gen-crl', '--ca', 'intermediate', '--passphrase-file', str(inter_pass),
                 '--out-dir', str(pki_dir), '--db-path', str(db_path)])
        # start server
        import threading
        from micropki.repo import start_repo_server
        server_thread = threading.Thread(target=start_repo_server,
                                         args=('127.0.0.1', 8082, str(db_path), str(pki_dir/'certs'), None),
                                         daemon=True)
        server_thread.start()
        time.sleep(2)
        resp = requests.get('http://127.0.0.1:8082/crl?ca=intermediate')
        assert resp.status_code == 200
        assert resp.headers.get('Content-Type') == 'application/pkix-crl'
        # compare with local file
        local_crl = (pki_dir / 'crl' / 'intermediate.crl.pem').read_bytes()
        assert resp.content == local_crl

def test_negative_revoke_nonexistent():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / 'micropki.db'
        run_cli(['db', 'init', '--db-path', str(db_path)])
        res = run_cli(['ca', 'revoke', 'DEADBEEF', '--db-path', str(db_path)])
        assert res.returncode != 0
        assert 'not found' in res.stderr.lower()

def test_negative_revoke_already_revoked():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir, pki_dir, db_path, root_pass, inter_pass = setup_full_chain(tmpdir)
        # issue and revoke
        run_cli(['ca', 'issue-cert', '--ca-cert', str(pki_dir/'certs'/'intermediate.cert.pem'),
                 '--ca-key', str(pki_dir/'private'/'intermediate.key.pem'),
                 '--ca-pass-file', str(inter_pass), '--template', 'client',
                 '--subject', 'CN=twice', '--out-dir', str(pki_dir/'certs'), '--db-path', str(db_path)])
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT serial_hex FROM certificates WHERE subject='CN=twice'")
        serial = cursor.fetchone()[0]
        conn.close()
        run_cli(['ca', 'revoke', serial, '--db-path', str(db_path)])
        # second revoke
        res = run_cli(['ca', 'revoke', serial, '--db-path', str(db_path)])
        assert res.returncode == 0
        assert 'already revoked' in res.stderr.lower()