import pytest
import tempfile
import subprocess
import sys
from pathlib import Path
from cryptography import x509

def run_cli(args):
    cmd = [sys.executable, '-m', 'micropki.cli'] + args
    return subprocess.run(cmd, capture_output=True, text=True)

def setup_root_ca(tmpdir):
    out_dir = Path(tmpdir) / 'pki'
    pass_file = Path(tmpdir) / 'root.pass'
    pass_file.write_text('rootpass')
    args = ['ca', 'init', '--subject', '/CN=Test Root', '--passphrase-file', str(pass_file),
            '--out-dir', str(out_dir), '--force']
    res = run_cli(args)
    assert res.returncode == 0
    return out_dir, pass_file

def find_leaf_cert(certs_dir, exclude_names=('ca.cert.pem', 'intermediate.cert.pem')):
    """Возвращает путь к первому сертификату, не входящему в exclude_names."""
    for f in certs_dir.glob('*.cert.pem'):
        if f.name not in exclude_names:
            return f
    return None

def test_chain_validation():
    with tempfile.TemporaryDirectory() as tmpdir:
        root_dir, root_pass = setup_root_ca(tmpdir)
        inter_pass_file = Path(tmpdir) / 'inter.pass'
        inter_pass_file.write_text('interpass')
        # Create Intermediate CA
        args = ['ca', 'issue-intermediate',
                '--root-cert', str(root_dir / 'certs' / 'ca.cert.pem'),
                '--root-key', str(root_dir / 'private' / 'ca.key.pem'),
                '--root-pass-file', str(root_pass),
                '--subject', 'CN=Intermediate CA',
                '--key-type', 'rsa',
                '--passphrase-file', str(inter_pass_file),
                '--out-dir', str(root_dir),
                '--validity-days', '365']
        res = run_cli(args)
        assert res.returncode == 0, res.stderr
        # Create leaf cert
        leaf_args = ['ca', 'issue-cert',
                     '--ca-cert', str(root_dir / 'certs' / 'intermediate.cert.pem'),
                     '--ca-key', str(root_dir / 'private' / 'intermediate.key.pem'),
                     '--ca-pass-file', str(inter_pass_file),
                     '--template', 'server',
                     '--subject', 'CN=leaf.example.com',
                     '--san', 'dns:leaf.example.com',
                     '--out-dir', str(root_dir / 'certs')]
        res = run_cli(leaf_args)
        assert res.returncode == 0, res.stderr
        # Find the leaf certificate
        leaf_cert_path = find_leaf_cert(root_dir / 'certs')
        assert leaf_cert_path is not None, "No leaf certificate found"
        inter_cert = root_dir / 'certs' / 'intermediate.cert.pem'
        root_cert = root_dir / 'certs' / 'ca.cert.pem'
        # Verify chain with OpenSSL (if available)
        try:
            cmd = ['openssl', 'verify', '-CAfile', str(root_cert), '-untrusted', str(inter_cert), str(leaf_cert_path)]
            result = subprocess.run(cmd, capture_output=True)
            assert result.returncode == 0, result.stderr.decode()
        except FileNotFoundError:
            pytest.skip("OpenSSL not found in PATH")

def test_extension_correctness():
    with tempfile.TemporaryDirectory() as tmpdir:
        root_dir, root_pass = setup_root_ca(tmpdir)
        inter_pass_file = Path(tmpdir) / 'inter.pass'
        inter_pass_file.write_text('interpass')
        subprocess.run([sys.executable, '-m', 'micropki.cli', 'ca', 'issue-intermediate',
                        '--root-cert', str(root_dir / 'certs' / 'ca.cert.pem'),
                        '--root-key', str(root_dir / 'private' / 'ca.key.pem'),
                        '--root-pass-file', str(root_pass),
                        '--subject', 'CN=Intermediate',
                        '--passphrase-file', str(inter_pass_file),
                        '--out-dir', str(root_dir)], check=True)
        # Server cert
        args = ['ca', 'issue-cert',
                '--ca-cert', str(root_dir / 'certs' / 'intermediate.cert.pem'),
                '--ca-key', str(root_dir / 'private' / 'intermediate.key.pem'),
                '--ca-pass-file', str(inter_pass_file),
                '--template', 'server',
                '--subject', 'CN=test.com',
                '--san', 'dns:test.com',
                '--out-dir', str(root_dir / 'certs')]
        res = run_cli(args)
        assert res.returncode == 0, res.stderr
        # Find the leaf certificate (skip intermediate)
        cert_path = find_leaf_cert(root_dir / 'certs')
        assert cert_path is not None, "No leaf certificate found"
        with open(cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())
        # Check Basic Constraints CA=False
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is False, "Leaf certificate must have CA=False"
        assert bc.critical is True
        # Check Key Usage
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku.value.digital_signature is True
        assert ku.value.key_encipherment is True
        assert ku.critical is True
        # Check EKU
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert x509.ExtendedKeyUsageOID.SERVER_AUTH in eku.value
        # Check SAN
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        assert any(isinstance(name, x509.DNSName) and name.value == 'test.com' for name in san.value)

def test_negative_server_without_san():
    with tempfile.TemporaryDirectory() as tmpdir:
        root_dir, root_pass = setup_root_ca(tmpdir)
        inter_pass_file = Path(tmpdir) / 'inter.pass'
        inter_pass_file.write_text('interpass')
        subprocess.run([sys.executable, '-m', 'micropki.cli', 'ca', 'issue-intermediate',
                        '--root-cert', str(root_dir / 'certs' / 'ca.cert.pem'),
                        '--root-key', str(root_dir / 'private' / 'ca.key.pem'),
                        '--root-pass-file', str(root_pass),
                        '--subject', 'CN=Intermediate',
                        '--passphrase-file', str(inter_pass_file),
                        '--out-dir', str(root_dir)], check=True)
        args = ['ca', 'issue-cert',
                '--ca-cert', str(root_dir / 'certs' / 'intermediate.cert.pem'),
                '--ca-key', str(root_dir / 'private' / 'intermediate.key.pem'),
                '--ca-pass-file', str(inter_pass_file),
                '--template', 'server',
                '--subject', 'CN=test.com',
                '--out-dir', str(root_dir / 'certs')]
        res = run_cli(args)
        assert res.returncode != 0
        assert 'requires at least one --san' in res.stderr or 'Error' in res.stderr

def test_negative_wrong_passphrase():
    with tempfile.TemporaryDirectory() as tmpdir:
        root_dir, root_pass = setup_root_ca(tmpdir)
        inter_pass_file = Path(tmpdir) / 'inter.pass'
        inter_pass_file.write_text('interpass')
        subprocess.run([sys.executable, '-m', 'micropki.cli', 'ca', 'issue-intermediate',
                        '--root-cert', str(root_dir / 'certs' / 'ca.cert.pem'),
                        '--root-key', str(root_dir / 'private' / 'ca.key.pem'),
                        '--root-pass-file', str(root_pass),
                        '--subject', 'CN=Intermediate',
                        '--passphrase-file', str(inter_pass_file),
                        '--out-dir', str(root_dir)], check=True)
        wrong_pass_file = Path(tmpdir) / 'wrong.pass'
        wrong_pass_file.write_text('wrong')
        args = ['ca', 'issue-cert',
                '--ca-cert', str(root_dir / 'certs' / 'intermediate.cert.pem'),
                '--ca-key', str(root_dir / 'private' / 'intermediate.key.pem'),
                '--ca-pass-file', str(wrong_pass_file),
                '--template', 'client',
                '--subject', 'CN=client',
                '--out-dir', str(root_dir / 'certs')]
        res = run_cli(args)
        assert res.returncode != 0
        # Ожидается ошибка расшифровки
        assert 'password' in res.stderr.lower() or 'decrypt' in res.stderr.lower()

def test_parse_san_string():
    from micropki.crypto_utils import parse_san_string
    from cryptography.x509 import DNSName, RFC822Name, IPAddress
    san = parse_san_string('dns:example.com')
    assert isinstance(san, DNSName) and san.value == 'example.com'
    san = parse_san_string('email:test@example.com')
    assert isinstance(san, RFC822Name) and san.value == 'test@example.com'
    import ipaddress
    san = parse_san_string('ip:192.168.1.1')
    assert isinstance(san, IPAddress) and san.value == ipaddress.ip_address('192.168.1.1')

def test_apply_template_server():
    from micropki.templates import apply_template
    from cryptography import x509
    builder = x509.CertificateBuilder()
    builder, required = apply_template(builder, 'server', None)
    assert required is True
    # We don't check extensions here, just that it doesn't crash