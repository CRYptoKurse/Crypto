import pytest
import tempfile
import subprocess
import sys
import time
import sqlite3
import threading
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

def wait_for_server(host, port, timeout=5):
    import socket
    start = time.time()
    while time.time() - start < timeout:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))
            sock.close()
            return True
        except:
            time.sleep(0.2)
    return False

# ------------------------------------------------------------
# Test 1: issue OCSP cert (no OpenSSL required)
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
# Test 2: OCSP good and revoked (requires OpenSSL)
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
        # Find the actual certificate file (might be test.com.cert.pem or test.com.cert.pem)
        cert_file = pki_dir / 'certs' / 'test.com.cert.pem'
        if not cert_file.exists():
            # try to find any .cert.pem that is not ca, intermediate, ocsp
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
        # start OCSP responder
        from micropki.ocsp_responder import start_ocsp_server
        server_thread = threading.Thread(target=start_ocsp_server,
                                         args=('127.0.0.1', 8090, str(db_path),
                                               str(pki_dir/'certs'/'ocsp.cert.pem'),
                                               str(pki_dir/'certs'/'ocsp.key.pem'),
                                               str(pki_dir/'certs'/'intermediate.cert.pem'), 60, None),
                                         daemon=True)
        server_thread.start()
        assert wait_for_server('127.0.0.1', 8090), "OCSP server did not start"
        # Query OCSP for good cert
        cmd = ['openssl', 'ocsp', '-issuer', str(pki_dir/'certs'/'intermediate.cert.pem'),
               '-cert', str(cert_file),
               '-url', 'http://127.0.0.1:8090/ocsp',
               '-respout', str(Path(tmpdir)/'resp.der')]
        res = subprocess.run(cmd, capture_output=True, text=True)
        # OpenSSL on Windows may output error but still have 'good' in stderr?
        output = res.stdout + res.stderr
        assert 'good' in output or 'Response verify OK' in output, f"Unexpected output: {output}"
        # Revoke certificate
        run_cli(['ca', 'revoke', serial, '--db-path', str(db_path)])
        # Query again
        res2 = subprocess.run(cmd, capture_output=True, text=True)
        output2 = res2.stdout + res2.stderr
        assert 'revoked' in output2, f"Expected 'revoked', got: {output2}"

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
        from micropki.ocsp_responder import start_ocsp_server
        server_thread = threading.Thread(target=start_ocsp_server,
                                         args=('127.0.0.1', 8091, str(db_path),
                                               str(pki_dir/'certs'/'ocsp.cert.pem'),
                                               str(pki_dir/'certs'/'ocsp.key.pem'),
                                               str(pki_dir/'certs'/'intermediate.cert.pem'), 60, None),
                                         daemon=True)
        server_thread.start()
        assert wait_for_server('127.0.0.1', 8091), "OCSP server did not start"
        # Create dummy certificate not in DB
        dummy_cert = Path(tmpdir)/'dummy.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(Path(tmpdir)/'dummy.key'), '-out', str(dummy_cert),
                        '-days', '1', '-subj', '/CN=dummy'], capture_output=True)
        cmd = ['openssl', 'ocsp', '-issuer', str(pki_dir/'certs'/'intermediate.cert.pem'),
               '-cert', str(dummy_cert), '-url', 'http://127.0.0.1:8091/ocsp']
        res = subprocess.run(cmd, capture_output=True, text=True)
        output = res.stdout + res.stderr
        assert 'unknown' in output, f"Expected 'unknown', got: {output}"

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
        from micropki.ocsp_responder import start_ocsp_server
        server_thread = threading.Thread(target=start_ocsp_server,
                                         args=('127.0.0.1', 8092, str(db_path),
                                               str(pki_dir/'certs'/'ocsp.cert.pem'),
                                               str(pki_dir/'certs'/'ocsp.key.pem'),
                                               str(pki_dir/'certs'/'intermediate.cert.pem'), 60, None),
                                         daemon=True)
        server_thread.start()
        assert wait_for_server('127.0.0.1', 8092), "OCSP server did not start"
        # Send request with nonce
        cmd = ['openssl', 'ocsp', '-issuer', str(pki_dir/'certs'/'intermediate.cert.pem'),
               '-cert', str(cert_file),
               '-url', 'http://127.0.0.1:8092/ocsp',
               '-respout', str(Path(tmpdir)/'resp.der'),
               '-reqout', str(Path(tmpdir)/'req.der'),
               '-nonce']
        subprocess.run(cmd, capture_output=True, text=True)
        # Check response text
        res = subprocess.run(['openssl', 'ocsp', '-respin', str(Path(tmpdir)/'resp.der'),
                              '-text'], capture_output=True, text=True)
        output = res.stdout + res.stderr
        assert 'Nonce' in output, f"Nonce not found in response: {output}"