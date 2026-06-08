import pytest
import tempfile
import time
import subprocess
import sys
from pathlib import Path

def run_cli(args, cwd=None):
    """Helper to run micropki CLI commands."""
    cmd = [sys.executable, '-m', 'micropki.cli'] + args
    return subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)

@pytest.mark.slow
def test_issue_1000_certificates():
    """Performance test: issue 1000 certificates and measure time."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pki_dir = Path(tmpdir) / "pki"
        (pki_dir / "certs").mkdir(parents=True)
        (pki_dir / "private").mkdir()
        root_pass = Path(tmpdir) / "root.pass"
        root_pass.write_text("rootpass")
        inter_pass = Path(tmpdir) / "inter.pass"
        inter_pass.write_text("interpass")
        db_path = pki_dir / "micropki.db"

        # Initialize DB, Root CA, Intermediate CA
        run_cli(["db", "init", "--db-path", str(db_path)], cwd=tmpdir)
        run_cli(["ca", "init", "--subject", "/CN=Perf Root", "--passphrase-file", str(root_pass),
                 "--out-dir", str(pki_dir), "--db-path", str(db_path), "--force"], cwd=tmpdir)
        run_cli(["ca", "issue-intermediate", "--root-cert", str(pki_dir/"certs"/"ca.cert.pem"),
                 "--root-key", str(pki_dir/"private"/"ca.key.pem"), "--root-pass-file", str(root_pass),
                 "--subject", "CN=Perf Inter", "--passphrase-file", str(inter_pass),
                 "--out-dir", str(pki_dir), "--db-path", str(db_path)], cwd=tmpdir)

        start = time.time()
        for i in range(1000):
            res = run_cli(["ca", "issue-cert",
                           "--ca-cert", str(pki_dir/"certs"/"intermediate.cert.pem"),
                           "--ca-key", str(pki_dir/"private"/"intermediate.key.pem"),
                           "--ca-pass-file", str(inter_pass),
                           "--template", "client",
                           "--subject", f"/CN=user{i}",
                           "--out-dir", str(pki_dir/"certs"),
                           "--db-path", str(db_path)], cwd=tmpdir)
            assert res.returncode == 0, f"Failed at {i}: {res.stderr}"
        elapsed = time.time() - start
        certs_per_sec = 1000 / elapsed if elapsed > 0 else 0
        print(f"Issued 1000 certificates in {elapsed:.2f} seconds ({certs_per_sec:.2f} certs/sec)")
        # No assertion on elapsed time – only measure and report