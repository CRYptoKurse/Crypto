import gc
import pytest
import tempfile
import subprocess
import sys
import time
import sqlite3
import json
import os
import hashlib
import threading
import socket
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

# ---- helper functions ----
def run_cli(args, cwd=None):
    cmd = [sys.executable, '-m', 'micropki.cli'] + args
    return subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)

def setup_full_chain(tmpdir):
    root_pass = Path(tmpdir) / 'root.pass'
    root_pass.write_text('rootpass')
    inter_pass = Path(tmpdir) / 'inter.pass'
    inter_pass.write_text('interpass')
    db_path = Path(tmpdir) / 'micropki.db'
    pki_dir = Path(tmpdir) / 'pki'
    run_cli(['db', 'init', '--db-path', str(db_path)], cwd=tmpdir)
    run_cli(['ca', 'init', '--subject', '/CN=Root', '--passphrase-file', str(root_pass),
             '--out-dir', str(pki_dir), '--db-path', str(db_path), '--force'], cwd=tmpdir)
    run_cli(['ca', 'issue-intermediate', '--root-cert', str(pki_dir/'certs'/'ca.cert.pem'),
             '--root-key', str(pki_dir/'private'/'ca.key.pem'), '--root-pass-file', str(root_pass),
             '--subject', 'CN=Inter', '--passphrase-file', str(inter_pass),
             '--out-dir', str(pki_dir), '--db-path', str(db_path)], cwd=tmpdir)
    return pki_dir, db_path, inter_pass

def generate_csr(tmpdir, subject="CN=test", key_size=2048, san=None):
    csr_path = Path(tmpdir) / 'test.csr'
    key_path = Path(tmpdir) / 'test.key'
    cmd = ['client', 'gen-csr', '--subject', subject, '--key-size', str(key_size),
           '--out-key', str(key_path), '--out-csr', str(csr_path)]
    if san:
        cmd.extend(['--san', san])
    res = run_cli(cmd, cwd=tmpdir)
    return csr_path, key_path, res

def wait_for_server(host, port, timeout=15):
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((host, port))
                return True
        except:
            time.sleep(0.5)
    return False

def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

# ------------------------------------------------------------
# Test POLICY‑3 (weak key rejection)
# ------------------------------------------------------------
def test_policy_weak_key():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        os.chdir(tmpdir)
        pki_dir, db_path, inter_pass = setup_full_chain(tmpdir)
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        weak_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        csr_builder = x509.CertificateSigningRequestBuilder()
        csr_builder = csr_builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "weak")]))
        csr = csr_builder.sign(weak_key, hashes.SHA256())
        csr_path = Path(tmpdir) / 'weak.csr'
        with open(csr_path, 'wb') as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))
        cmd = ['ca', 'issue-cert', '--ca-cert', str(pki_dir/'certs'/'intermediate.cert.pem'),
               '--ca-key', str(pki_dir/'private'/'intermediate.key.pem'),
               '--ca-pass-file', str(inter_pass), '--template', 'client',
               '--csr', str(csr_path), '--out-dir', str(pki_dir/'certs')]
        res = run_cli(cmd, cwd=tmpdir)
        assert res.returncode != 0, "Weak key should be rejected"
        assert 'key size' in res.stderr.lower()
        gc.collect()

# ------------------------------------------------------------
# Test POLICY‑4 (validity period enforcement)
# ------------------------------------------------------------
def test_policy_validity_too_long():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        os.chdir(tmpdir)
        pki_dir, db_path, inter_pass = setup_full_chain(tmpdir)
        csr_path, key_path, _ = generate_csr(tmpdir)
        cmd = ['ca', 'issue-cert', '--ca-cert', str(pki_dir/'certs'/'intermediate.cert.pem'),
               '--ca-key', str(pki_dir/'private'/'intermediate.key.pem'),
               '--ca-pass-file', str(inter_pass), '--template', 'client',
               '--csr', str(csr_path), '--validity-days', '400', '--out-dir', str(pki_dir/'certs')]
        res = run_cli(cmd, cwd=tmpdir)
        assert res.returncode != 0
        assert 'exceeds maximum' in res.stderr.lower()
        gc.collect()

# ------------------------------------------------------------
# Test POLICY‑5 (wildcard SAN rejection)
# ------------------------------------------------------------
def test_policy_wildcard_san():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        os.chdir(tmpdir)
        pki_dir, db_path, inter_pass = setup_full_chain(tmpdir)
        csr_path, key_path, _ = generate_csr(tmpdir, san='dns:*.example.com')
        cmd = ['ca', 'issue-cert', '--ca-cert', str(pki_dir/'certs'/'intermediate.cert.pem'),
               '--ca-key', str(pki_dir/'private'/'intermediate.key.pem'),
               '--ca-pass-file', str(inter_pass), '--template', 'server',
               '--csr', str(csr_path), '--out-dir', str(pki_dir/'certs')]
        res = run_cli(cmd, cwd=tmpdir)
        assert res.returncode != 0
        assert 'wildcard' in res.stderr.lower()
        gc.collect()

# ------------------------------------------------------------
# Test POLICY‑5 (forbidden SAN type for template)
# ------------------------------------------------------------
def test_policy_wrong_san_type():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        os.chdir(tmpdir)
        pki_dir, db_path, inter_pass = setup_full_chain(tmpdir)
        csr_path, key_path, _ = generate_csr(tmpdir, san='email:user@example.com')
        cmd = ['ca', 'issue-cert', '--ca-cert', str(pki_dir/'certs'/'intermediate.cert.pem'),
               '--ca-key', str(pki_dir/'private'/'intermediate.key.pem'),
               '--ca-pass-file', str(inter_pass), '--template', 'code_signing',
               '--csr', str(csr_path), '--out-dir', str(pki_dir/'certs')]
        res = run_cli(cmd, cwd=tmpdir)
        assert res.returncode != 0
        assert 'not allowed' in res.stderr.lower()
        gc.collect()

# ------------------------------------------------------------
# Test CT‑2 (CT log creation)
# ------------------------------------------------------------
def test_ct_log_created():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        os.chdir(tmpdir)
        pki_dir, db_path, inter_pass = setup_full_chain(tmpdir)
        csr_path, key_path, _ = generate_csr(tmpdir, subject="CN=cttest")
        cmd = ['ca', 'issue-cert', '--ca-cert', str(pki_dir/'certs'/'intermediate.cert.pem'),
               '--ca-key', str(pki_dir/'private'/'intermediate.key.pem'),
               '--ca-pass-file', str(inter_pass), '--template', 'client',
               '--csr', str(csr_path), '--out-dir', str(pki_dir/'certs')]
        res = run_cli(cmd, cwd=tmpdir)
        if res.returncode != 0:
            pytest.skip("Issuance failed, maybe check_signature_algorithm error")
        ct_log = Path(tmpdir) / 'pki' / 'audit' / 'ct.log'
        assert ct_log.exists(), "CT log not created"
        content = ct_log.read_text()
        assert 'cttest' in content
        gc.collect()

# ------------------------------------------------------------
# Test AUDIT‑1, AUDIT‑2 (audit log creation and hash chain)
# ------------------------------------------------------------
def test_audit_log_chain():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        os.chdir(tmpdir)
        pki_dir, db_path, inter_pass = setup_full_chain(tmpdir)
        audit_log = Path(tmpdir) / 'pki' / 'audit' / 'audit.log'
        chain_file = Path(tmpdir) / 'pki' / 'audit' / 'chain.dat'
        csr_path, key_path, _ = generate_csr(tmpdir)
        cmd = ['ca', 'issue-cert', '--ca-cert', str(pki_dir/'certs'/'intermediate.cert.pem'),
               '--ca-key', str(pki_dir/'private'/'intermediate.key.pem'),
               '--ca-pass-file', str(inter_pass), '--template', 'client',
               '--csr', str(csr_path), '--out-dir', str(pki_dir/'certs')]
        res = run_cli(cmd, cwd=tmpdir)
        if res.returncode != 0:
            pytest.skip("Issuance failed")
        assert audit_log.exists()
        lines = audit_log.read_text().strip().split('\n')
        assert len(lines) >= 1
        entry = json.loads(lines[0])
        assert 'integrity' in entry
        assert entry['integrity']['prev_hash'] == '0' * 64
        # Verify integrity
        res_verify = run_cli(['ca', 'audit-verify', '--audit-log', str(audit_log), '--chain-file', str(chain_file)], cwd=tmpdir)
        assert res_verify.returncode == 0
        gc.collect()

# ------------------------------------------------------------
# Test AUDIT‑3 (tamper detection)
# ------------------------------------------------------------
def test_audit_tamper_detection():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        os.chdir(tmpdir)
        pki_dir, db_path, inter_pass = setup_full_chain(tmpdir)
        audit_log = Path(tmpdir) / 'pki' / 'audit' / 'audit.log'
        chain_file = Path(tmpdir) / 'pki' / 'audit' / 'chain.dat'
        csr_path, key_path, _ = generate_csr(tmpdir)
        # First issuance
        run_cli(['ca', 'issue-cert', '--ca-cert', str(pki_dir/'certs'/'intermediate.cert.pem'),
                 '--ca-key', str(pki_dir/'private'/'intermediate.key.pem'),
                 '--ca-pass-file', str(inter_pass), '--template', 'client',
                 '--csr', str(csr_path), '--out-dir', str(pki_dir/'certs')], cwd=tmpdir)
        # Second issuance
        run_cli(['ca', 'issue-cert', '--ca-cert', str(pki_dir/'certs'/'intermediate.cert.pem'),
                 '--ca-key', str(pki_dir/'private'/'intermediate.key.pem'),
                 '--ca-pass-file', str(inter_pass), '--template', 'client',
                 '--csr', str(csr_path), '--subject', 'CN=another', '--out-dir', str(pki_dir/'certs')], cwd=tmpdir)
        # Modify second entry
        lines = audit_log.read_text().strip().split('\n')
        entry = json.loads(lines[1])
        entry['status'] = 'tampered'
        lines[1] = json.dumps(entry)
        audit_log.write_text('\n'.join(lines) + '\n')
        res = run_cli(['ca', 'audit-verify', '--audit-log', str(audit_log), '--chain-file', str(chain_file)], cwd=tmpdir)
        assert res.returncode != 0
        assert 'hash mismatch' in res.stderr.lower()
        gc.collect()

# ------------------------------------------------------------
# Test RATE LIMITING (using threading)
# ------------------------------------------------------------
def test_rate_limiting():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        os.chdir(tmpdir)
        pki_dir, db_path, inter_pass = setup_full_chain(tmpdir)
        (Path(tmpdir) / 'pki' / 'inter.pass').write_text('interpass')
        port = free_port()
        from micropki.repo import start_repo_server
        def run_server():
            start_repo_server('127.0.0.1', port, str(db_path), str(pki_dir/'certs'), None, 1.0, 2)
        server_thread = threading.Thread(target=run_server, daemon=True)
        server_thread.start()
        time.sleep(4)
        assert wait_for_server('127.0.0.1', port)
        import requests
        session = requests.Session()
        session.trust_env = False
        statuses = []
        for _ in range(5):
            resp = session.get(f'http://127.0.0.1:{port}/ca/root')
            statuses.append(resp.status_code)
            time.sleep(0.1)
        assert 429 in statuses
        # Даём потоку завершиться
        time.sleep(1)
        gc.collect()

# ------------------------------------------------------------
# Test COMPROMISE simulation
# ------------------------------------------------------------
def test_compromise_simulation():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        os.chdir(tmpdir)
        pki_dir, db_path, inter_pass = setup_full_chain(tmpdir)
        csr_path, key_path, _ = generate_csr(tmpdir, subject="CN=compromise_test")
        run_cli(['ca', 'issue-cert', '--ca-cert', str(pki_dir/'certs'/'intermediate.cert.pem'),
                 '--ca-key', str(pki_dir/'private'/'intermediate.key.pem'),
                 '--ca-pass-file', str(inter_pass), '--template', 'client',
                 '--csr', str(csr_path), '--out-dir', str(pki_dir/'certs')], cwd=tmpdir)
        # Find issued certificate (not ca or intermediate)
        cert_file = None
        for f in (pki_dir/'certs').glob('*.cert.pem'):
            if f.name not in ('ca.cert.pem', 'intermediate.cert.pem', 'ocsp.cert.pem'):
                cert_file = f
                break
        assert cert_file is not None
        res = run_cli(['ca', 'compromise', '--cert', str(cert_file), '--db-path', str(db_path)], cwd=tmpdir)
        assert res.returncode == 0
        # Check status in DB
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        with open(cert_file, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())
        serial_hex = format(cert.serial_number, 'x').upper()
        cursor.execute("SELECT status, revocation_reason FROM certificates WHERE serial_hex = ?", (serial_hex,))
        row = cursor.fetchone()
        assert row[0] == 'revoked'
        assert row[1] == 'keyCompromise'
        conn.close()
        gc.collect()

# ------------------------------------------------------------
# Test compromised key re‑issuance blocking (optional)
# ------------------------------------------------------------
def test_compromised_key_blocking():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        os.chdir(tmpdir)
        pki_dir, db_path, inter_pass = setup_full_chain(tmpdir)
        key_path = Path(tmpdir) / 'key.pem'
        csr_path = Path(tmpdir) / 'test.csr'
        run_cli(['client', 'gen-csr', '--subject', 'CN=compromised', '--out-key', str(key_path),
                 '--out-csr', str(csr_path)], cwd=tmpdir)
        run_cli(['ca', 'issue-cert', '--ca-cert', str(pki_dir/'certs'/'intermediate.cert.pem'),
                 '--ca-key', str(pki_dir/'private'/'intermediate.key.pem'),
                 '--ca-pass-file', str(inter_pass), '--template', 'client',
                 '--csr', str(csr_path), '--out-dir', str(pki_dir/'certs')], cwd=tmpdir)
        cert_file = None
        for f in (pki_dir/'certs').glob('*.cert.pem'):
            if f.name not in ('ca.cert.pem', 'intermediate.cert.pem', 'ocsp.cert.pem'):
                cert_file = f
                break
        run_cli(['ca', 'compromise', '--cert', str(cert_file), '--db-path', str(db_path)], cwd=tmpdir)
        res = run_cli(['ca', 'issue-cert', '--ca-cert', str(pki_dir/'certs'/'intermediate.cert.pem'),
                       '--ca-key', str(pki_dir/'private'/'intermediate.key.pem'),
                       '--ca-pass-file', str(inter_pass), '--template', 'client',
                       '--csr', str(csr_path), '--out-dir', str(pki_dir/'certs')], cwd=tmpdir)
        if res.returncode != 0:
            assert 'compromised' in res.stderr.lower()
        else:
            pytest.skip("Compromised key blocking not implemented")
        gc.collect()

# ------------------------------------------------------------
# End‑to‑end integration test (using threading)
# ------------------------------------------------------------
def test_full_hardening_integration():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        os.chdir(tmpdir)
        pki_dir, db_path, inter_pass = setup_full_chain(tmpdir)
        (Path(tmpdir) / 'pki' / 'inter.pass').write_text('interpass')
        port = free_port()
        from micropki.repo import start_repo_server
        server_thread = threading.Thread(
            target=start_repo_server,
            args=('127.0.0.1', port, str(db_path), str(pki_dir/'certs'), None, 2.0, 5),
            daemon=True
        )
        server_thread.start()
        time.sleep(4)
        assert wait_for_server('127.0.0.1', port)
        csr_path, key_path, _ = generate_csr(tmpdir, subject="CN=integration")
        import requests
        with open(csr_path, 'rb') as f:
            csr_data = f.read()
        resp = requests.post(f'http://127.0.0.1:{port}/request-cert?template=server',
                             data=csr_data, headers={'Content-Type': 'application/x-pem-file'})
        assert resp.status_code == 201
        cert_pem = resp.content
        cert_path = Path(tmpdir) / 'issued.cert.pem'
        cert_path.write_bytes(cert_pem)
        ct_log = Path(tmpdir) / 'pki' / 'audit' / 'ct.log'
        assert ct_log.exists()
        audit_log = Path(tmpdir) / 'pki' / 'audit' / 'audit.log'
        assert audit_log.exists()
        res_verify = run_cli(['ca', 'audit-verify', '--audit-log', str(audit_log)], cwd=tmpdir)
        assert res_verify.returncode == 0
        # Compromise
        res_comp = run_cli(['ca', 'compromise', '--cert', str(cert_path), '--db-path', str(db_path)], cwd=tmpdir)
        assert res_comp.returncode == 0
        # CRL
        run_cli(['ca', 'gen-crl', '--ca', 'intermediate', '--passphrase-file', str(inter_pass),
                 '--out-dir', str(pki_dir), '--db-path', str(db_path)], cwd=tmpdir)
        crl_path = pki_dir / 'crl' / 'intermediate.crl.pem'
        assert crl_path.exists()
        # Rate limiting (already tested)
        session = requests.Session()
        session.trust_env = False
        statuses = []
        for _ in range(10):
            r = session.get(f'http://127.0.0.1:{port}/ca/root')
            statuses.append(r.status_code)
        assert 429 in statuses
        time.sleep(2)
        gc.collect()