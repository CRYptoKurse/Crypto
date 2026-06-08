import pytest
import tempfile
import subprocess
import sys
import time
import sqlite3
import multiprocessing
from pathlib import Path

# ------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------
def has_openssl():
    try:
        subprocess.run(['openssl', 'version'], capture_output=True, check=True)
        return True
    except (subprocess.SubprocessError, FileNotFoundError):
        return False

skip_no_openssl = pytest.mark.skipif(not has_openssl(), reason="OpenSSL not installed")

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
    run_cli(['db', 'init', '--db-path', str(db_path)])
    run_cli(['ca', 'init', '--subject', '/CN=Root', '--passphrase-file', str(root_pass),
             '--out-dir', str(pki_dir), '--db-path', str(db_path), '--force'])
    run_cli(['ca', 'issue-intermediate', '--root-cert', str(pki_dir/'certs'/'ca.cert.pem'),
             '--root-key', str(pki_dir/'private'/'ca.key.pem'), '--root-pass-file', str(root_pass),
             '--subject', 'CN=Inter', '--passphrase-file', str(inter_pass),
             '--out-dir', str(pki_dir), '--db-path', str(db_path)])
    return tmpdir, pki_dir, db_path, root_pass, inter_pass

def wait_for_server(host, port, timeout=30):
    import socket
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect((host, port))
                return True
        except (ConnectionRefusedError, socket.timeout, OSError):
            time.sleep(0.5)
    return False

def free_port():
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def run_ocsp_server(port, db_path, responder_cert, responder_key, ca_cert):
    from micropki.ocsp_responder import start_ocsp_server
    start_ocsp_server('127.0.0.1', port, db_path, responder_cert, responder_key, ca_cert, 60, None)

# ------------------------------------------------------------
# Test 1: issue OCSP cert
# ------------------------------------------------------------
def test_issue_ocsp_cert():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir, pki_dir, db_path, root_pass, inter_pass = setup_full_chain(tmpdir)
        res = run_cli(['ca', 'issue-ocsp-cert',
                       '--ca-cert', str(pki_dir/'certs'/'intermediate.cert.pem'),
                       '--ca-key', str(pki_dir/'private'/'intermediate.key.pem'),
                       '--ca-pass-file', str(inter_pass),
                       '--subject', 'CN=OCSP Responder',
                       '--key-type', 'rsa', '--key-size', '2048',
                       '--out-dir', str(pki_dir/'certs')])
        assert res.returncode == 0, res.stderr
        cert_path = pki_dir / 'certs' / 'ocsp.cert.pem'
        key_path = pki_dir / 'certs' / 'ocsp.key.pem'
        assert cert_path.exists()
        assert key_path.exists()
        if has_openssl():
            out = subprocess.run(['openssl', 'x509', '-in', str(cert_path), '-text', '-noout'],
                                 capture_output=True, text=True)
            assert 'OCSP Signing' in out.stdout
            assert 'Digital Signature' in out.stdout

# ------------------------------------------------------------
# Test 2: OCSP good and revoked
# ------------------------------------------------------------
@skip_no_openssl
def test_ocsp_good_and_revoked():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir, pki_dir, db_path, root_pass, inter_pass = setup_full_chain(tmpdir)
        # issue OCSP responder cert
        run_cli(['ca', 'issue-ocsp-cert', '--ca-cert', str(pki_dir/'certs'/'intermediate.cert.pem'),
                 '--ca-key', str(pki_dir/'private'/'intermediate.key.pem'),
                 '--ca-pass-file', str(inter_pass),
                 '--subject', 'CN=OCSP Responder', '--key-type', 'rsa', '--key-size', '2048',
                 '--out-dir', str(pki_dir/'certs')])
        # issue a server cert
        run_cli(['ca', 'issue-cert', '--ca-cert', str(pki_dir/'certs'/'intermediate.cert.pem'),
                 '--ca-key', str(pki_dir/'private'/'intermediate.key.pem'),
                 '--ca-pass-file', str(inter_pass), '--template', 'server',
                 '--subject', 'CN=test.com', '--san', 'dns:test.com',
                 '--out-dir', str(pki_dir/'certs'), '--db-path', str(db_path)])
        # Find the certificate file
        cert_file = pki_dir / 'certs' / 'test.com.cert.pem'
        if not cert_file.exists():
            candidates = [f for f in (pki_dir/'certs').glob('*.cert.pem')
                          if f.name not in ('ca.cert.pem', 'intermediate.cert.pem', 'ocsp.cert.pem')]
            assert candidates, "No leaf certificate found"
            cert_file = candidates[0]
        # get serial from DB
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT serial_hex FROM certificates WHERE subject LIKE '%test.com%'")
        serial = cursor.fetchone()[0]
        conn.close()

        port = free_port()
        server_process = multiprocessing.Process(
            target=run_ocsp_server,
            args=(port, str(db_path),
                  str(pki_dir/'certs'/'ocsp.cert.pem'),
                  str(pki_dir/'certs'/'ocsp.key.pem'),
                  str(pki_dir/'certs'/'intermediate.cert.pem'))
        )
        server_process.start()
        time.sleep(5)   # увеличенная задержка
        assert wait_for_server('127.0.0.1', port, timeout=20), f"OCSP server did not start on port {port}"

        # Query OCSP for good cert
        cmd = ['openssl', 'ocsp', '-issuer', str(pki_dir/'certs'/'intermediate.cert.pem'),
               '-cert', str(cert_file),
               '-url', f'http://127.0.0.1:{port}/ocsp',
               '-respout', str(Path(tmpdir)/'resp.der')]
        res = subprocess.run(cmd, capture_output=True, text=True)
        output = res.stdout + res.stderr
        assert 'good' in output or 'Response verify OK' in output, f"Unexpected output: {output}"

        # Revoke certificate
        run_cli(['ca', 'revoke', serial, '--db-path', str(db_path)])

        # Wait a bit for DB update
        time.sleep(1)

        # Query again
        res2 = subprocess.run(cmd, capture_output=True, text=True)
        output2 = res2.stdout + res2.stderr
        assert 'revoked' in output2, f"Expected 'revoked', got: {output2}"

        server_process.terminate()
        server_process.join(timeout=5)

# ------------------------------------------------------------
# Test 3: Unknown certificate
# ------------------------------------------------------------
@skip_no_openssl
def test_ocsp_unknown():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir, pki_dir, db_path, root_pass, inter_pass = setup_full_chain(tmpdir)
        run_cli(['ca', 'issue-ocsp-cert', '--ca-cert', str(pki_dir/'certs'/'intermediate.cert.pem'),
                 '--ca-key', str(pki_dir/'private'/'intermediate.key.pem'),
                 '--ca-pass-file', str(inter_pass), '--subject', 'CN=OCSP',
                 '--out-dir', str(pki_dir/'certs')])

        port = free_port()
        server_process = multiprocessing.Process(
            target=run_ocsp_server,
            args=(port, str(db_path),
                  str(pki_dir/'certs'/'ocsp.cert.pem'),
                  str(pki_dir/'certs'/'ocsp.key.pem'),
                  str(pki_dir/'certs'/'intermediate.cert.pem'))
        )
        server_process.start()
        time.sleep(5)
        assert wait_for_server('127.0.0.1', port, timeout=20), f"OCSP server did not start on port {port}"

        # Create dummy certificate
        dummy_cert = Path(tmpdir)/'dummy.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(Path(tmpdir)/'dummy.key'), '-out', str(dummy_cert),
                        '-days', '1', '-subj', '/CN=dummy'], capture_output=True)

        cmd = ['openssl', 'ocsp', '-issuer', str(pki_dir/'certs'/'intermediate.cert.pem'),
               '-cert', str(dummy_cert), '-url', f'http://127.0.0.1:{port}/ocsp']
        res = subprocess.run(cmd, capture_output=True, text=True)
        output = res.stdout + res.stderr
        assert 'unknown' in output, f"Expected 'unknown', got: {output}"

        server_process.terminate()
        server_process.join(timeout=5)

# ------------------------------------------------------------
# Test 4: Nonce handling
# ------------------------------------------------------------
@skip_no_openssl
def test_ocsp_nonce():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir, pki_dir, db_path, root_pass, inter_pass = setup_full_chain(tmpdir)
        run_cli(['ca', 'issue-ocsp-cert', '--ca-cert', str(pki_dir/'certs'/'intermediate.cert.pem'),
                 '--ca-key', str(pki_dir/'private'/'intermediate.key.pem'),
                 '--ca-pass-file', str(inter_pass), '--subject', 'CN=OCSP',
                 '--out-dir', str(pki_dir/'certs')])
        run_cli(['ca', 'issue-cert', '--ca-cert', str(pki_dir/'certs'/'intermediate.cert.pem'),
                 '--ca-key', str(pki_dir/'private'/'intermediate.key.pem'),
                 '--ca-pass-file', str(inter_pass), '--template', 'client',
                 '--subject', 'CN=nonce_test', '--out-dir', str(pki_dir/'certs'),
                 '--db-path', str(db_path)])

        cert_file = pki_dir/'certs'/'nonce_test.cert.pem'
        if not cert_file.exists():
            candidates = [f for f in (pki_dir/'certs').glob('*.cert.pem')
                          if f.name not in ('ca.cert.pem', 'intermediate.cert.pem', 'ocsp.cert.pem')]
            assert candidates, "No leaf certificate found"
            cert_file = candidates[0]

        port = free_port()
        server_process = multiprocessing.Process(
            target=run_ocsp_server,
            args=(port, str(db_path),
                  str(pki_dir/'certs'/'ocsp.cert.pem'),
                  str(pki_dir/'certs'/'ocsp.key.pem'),
                  str(pki_dir/'certs'/'intermediate.cert.pem'))
        )
        server_process.start()
        time.sleep(5)
        assert wait_for_server('127.0.0.1', port, timeout=20), f"OCSP server did not start on port {port}"

        resp_file = Path(tmpdir) / 'resp.der'
        req_file = Path(tmpdir) / 'req.der'
        cmd = ['openssl', 'ocsp', '-issuer', str(pki_dir/'certs'/'intermediate.cert.pem'),
               '-cert', str(cert_file),
               '-url', f'http://127.0.0.1:{port}/ocsp',
               '-respout', str(resp_file),
               '-reqout', str(req_file),
               '-nonce']
        subprocess.run(cmd, capture_output=True, text=True, check=False)

        # Проверка с указанием сертификата подписанта
        res = subprocess.run(['openssl', 'ocsp', '-respin', str(resp_file), '-text',
                              '-VAfile', str(pki_dir/'certs'/'ocsp.cert.pem')],
                             capture_output=True, text=True)
        output = res.stdout + res.stderr
        assert 'Nonce' in output, f"Nonce not found in response: {output}"