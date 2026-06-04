import os
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization

def create_self_signed_cert(private_key, subject_dn, validity_days, key_type):
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject_dn)
    builder = builder.issuer_name(subject_dn)
    # Serial number: 20 random bytes
    serial = int.from_bytes(os.urandom(19), 'big')
    builder = builder.serial_number(serial)
    now = datetime.now(timezone.utc)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + timedelta(days=validity_days))
    builder = builder.public_key(private_key.public_key())

    # Basic Constraints: CA=True, critical
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    )
    # Key Usage: keyCertSign, cRLSign, digitalSignature (optional but recommended)
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )
    # SKI
    ski = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
    builder = builder.add_extension(ski, critical=False)
    # AKI = SKI for self-signed
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski),
        critical=False
    )

    if key_type == 'rsa':
        sig_hash = hashes.SHA256()
    else:  # ecc
        sig_hash = hashes.SHA384()

    cert = builder.sign(private_key=private_key, algorithm=sig_hash)
    return cert

def cert_to_pem(cert):
    return cert.public_bytes(encoding=serialization.Encoding.PEM)