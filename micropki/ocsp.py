import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID
from .crypto_utils import parse_dn_string, parse_san_string, generate_rsa_key, generate_ecc_key
from .crypto_utils import load_certificate, load_encrypted_private_key
from .logger import setup_logging

def issue_ocsp_cert(args):
    logger = setup_logging(args.log_file)
    logger.info("Issuing OCSP responder certificate")

    ca_cert = load_certificate(args.ca_cert)
    with open(args.ca_pass_file, 'rb') as f:
        ca_pass = f.read().strip()
    ca_key = load_encrypted_private_key(args.ca_key, ca_pass)

    if args.key_type == 'rsa':
        ocsp_key = generate_rsa_key(args.key_size)
    else:
        ocsp_key = generate_ecc_key(args.key_size)

    subject = parse_dn_string(args.subject)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.serial_number(int.from_bytes(os.urandom(19), 'big'))
    now = datetime.now(timezone.utc)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + timedelta(days=args.validity_days))
    builder = builder.public_key(ocsp_key.public_key())

    builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    builder = builder.add_extension(
        x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                      data_encipherment=False, key_agreement=False, key_cert_sign=False,
                      crl_sign=False, encipher_only=False, decipher_only=False),
        critical=True
    )
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]),
        critical=False
    )
    ski = x509.SubjectKeyIdentifier.from_public_key(ocsp_key.public_key())
    builder = builder.add_extension(ski, critical=False)
    aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
        ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    )
    builder = builder.add_extension(aki, critical=False)

    if args.san:
        san_list = [parse_san_string(s) for s in args.san]
        builder = builder.add_extension(x509.SubjectAlternativeName(san_list), critical=False)

    if args.key_type == 'rsa':
        sig_hash = hashes.SHA256()
    else:
        sig_hash = hashes.SHA384()

    ocsp_cert = builder.sign(private_key=ca_key, algorithm=sig_hash)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cert_path = out_dir / 'ocsp.cert.pem'
    key_path = out_dir / 'ocsp.key.pem'
    with open(cert_path, 'wb') as f:
        f.write(ocsp_cert.public_bytes(serialization.Encoding.PEM))
    unencrypted_key = ocsp_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(key_path, 'wb') as f:
        f.write(unencrypted_key)
    os.chmod(key_path, 0o600)  # on Windows might fail, but fine
    logger.warning(f"OCSP private key stored UNENCRYPTED at {key_path}")

    logger.info(f"OCSP responder certificate saved to {cert_path}")
    logger.info("OCSP certificate issuance completed")