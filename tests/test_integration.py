import os
import tempfile
import subprocess
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography import x509


def run_cli(args):
    # args — список аргументов без указания модуля, например ['ca', 'init', ...]
    cmd = ['python', '-m', 'micropki.cli'] + args
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result


def test_ca_init_success():
    with tempfile.TemporaryDirectory() as tmpdir:
        out_dir = Path(tmpdir) / 'pki'
        pass_file = Path(tmpdir) / 'pass.txt'
        pass_file.write_text('mysecret')
        args = [
            'ca', 'init',
            '--subject', '/CN=Test Root CA',
            '--key-type', 'rsa',
            '--key-size', '4096',
            '--passphrase-file', str(pass_file),
            '--out-dir', str(out_dir),
            '--validity-days', '365',
            '--force'
        ]
        result = run_cli(args)
        assert result.returncode == 0, result.stderr
        assert (out_dir / 'private' / 'ca.key.pem').exists()
        assert (out_dir / 'certs' / 'ca.cert.pem').exists()
        assert (out_dir / 'policy.txt').exists()

        key_data = (out_dir / 'private' / 'ca.key.pem').read_bytes()
        private_key = serialization.load_pem_private_key(key_data, password=b'mysecret')
        assert private_key is not None

        cert_data = (out_dir / 'certs' / 'ca.cert.pem').read_bytes()
        cert = x509.load_pem_x509_certificate(cert_data)
        assert cert.public_key().public_numbers() == private_key.public_key().public_numbers()


def test_negative_missing_subject():
    with tempfile.TemporaryDirectory() as tmpdir:
        pass_file = Path(tmpdir) / 'pass.txt'
        pass_file.write_text('secret')
        args = [
            'ca', 'init',
            '--key-type', 'rsa',
            '--passphrase-file', str(pass_file),
            '--out-dir', str(Path(tmpdir) / 'pki')
        ]
        result = run_cli(args)
        assert result.returncode != 0
        assert '--subject' in result.stderr or 'required' in result.stderr


def test_negative_wrong_key_size():
    with tempfile.TemporaryDirectory() as tmpdir:
        pass_file = Path(tmpdir) / 'pass.txt'
        pass_file.write_text('secret')
        args = [
            'ca', 'init',
            '--subject', '/CN=Test',
            '--key-type', 'rsa',
            '--key-size', '2048',
            '--passphrase-file', str(pass_file),
            '--out-dir', str(Path(tmpdir) / 'pki')
        ]
        result = run_cli(args)
        assert result.returncode != 0
        assert '4096' in result.stderr