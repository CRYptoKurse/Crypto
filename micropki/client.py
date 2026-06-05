import os
import sys
import re
import json
import requests
from pathlib import Path
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID
from .crypto_utils import parse_dn_string, parse_san_string, verify_signature
from .logger import setup_logging
from .revocation_check import check_revocation_status
from .validation import validate_certificate_path

def gen_csr(args):
    logger = setup_logging(args.log_file)
    logger.info("Generating CSR")

    if args.key_type == 'rsa':
        if args.key_size not in (2048, 4096):
            logger.error("RSA key size must be 2048 or 4096")
            sys.exit(1)
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=args.key_size)
    elif args.key_type == 'ecc':
        if args.key_size == 256:
            curve = ec.SECP256R1()
        elif args.key_size == 384:
            curve = ec.SECP384R1()
        else:
            logger.error("ECC key size must be 256 or 384")
            sys.exit(1)
        private_key = ec.generate_private_key(curve)
    else:
        logger.error(f"Unsupported key type: {args.key_type}")
        sys.exit(1)

    key_path = Path(args.out_key)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(key_path, 'wb') as f:
        f.write(key_pem)
    try:
        os.chmod(key_path, 0o600)
    except Exception:
        logger.warning("Could not set permissions on private key (non-UNIX)")
    logger.warning(f"Private key stored UNENCRYPTED at {key_path}")

    subject = parse_dn_string(args.subject)

    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(subject)

    if args.san:
        san_list = [parse_san_string(s) for s in args.san]
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False
        )

    csr = builder.sign(private_key, hashes.SHA256())

    csr_path = Path(args.out_csr)
    csr_path.parent.mkdir(parents=True, exist_ok=True)
    with open(csr_path, 'wb') as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    logger.info(f"CSR saved to {csr_path}")
    logger.info("CSR generation completed")

def request_cert(args):
    logger = setup_logging(args.log_file)
    logger.info("Requesting certificate from CA")

    csr_path = Path(args.csr)
    if not csr_path.exists():
        logger.error(f"CSR file not found: {csr_path}")
        sys.exit(1)

    with open(csr_path, 'rb') as f:
        csr_data = f.read()
    try:
        csr = x509.load_pem_x509_csr(csr_data)
    except Exception as e:
        logger.error(f"Invalid CSR: {e}")
        sys.exit(1)

    url = f"{args.ca_url.rstrip('/')}/request-cert"
    params = {'template': args.template}
    headers = {'Content-Type': 'application/x-pem-file'}
    if args.api_key:
        headers['X-API-Key'] = args.api_key

    session = requests.Session()
    session.trust_env = False
    try:
        resp = session.post(url, params=params, data=csr_data, headers=headers, timeout=30)
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to request certificate: {e}")
        if hasattr(e, 'response') and e.response is not None:
            logger.error(f"Response: {e.response.text}")
        sys.exit(1)

    cert_path = Path(args.out_cert)
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    with open(cert_path, 'wb') as f:
        f.write(resp.content)
    logger.info(f"Certificate saved to {cert_path}")
    logger.info("Certificate request completed")

def validate_cert(args):
    logger = setup_logging(args.log_file)
    logger.info("Starting certificate validation")

    with open(args.cert, 'rb') as f:
        leaf = x509.load_pem_x509_certificate(f.read())

    untrusted = []
    if args.untrusted:
        for u in args.untrusted:
            with open(u, 'rb') as f:
                untrusted.append(x509.load_pem_x509_certificate(f.read()))

    trusted = []
    with open(args.trusted, 'rb') as f:
        trust_data = f.read()
    pem_certs = re.findall(b'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', trust_data, re.DOTALL)
    for cert_pem in pem_certs:
        trusted.append(x509.load_pem_x509_certificate(cert_pem))

    check_revocation = (args.mode == 'full')
    crl_sources = args.crl if args.crl else None
    ocsp_url = args.ocsp if args.ocsp else None
    if check_revocation and not crl_sources and not ocsp_url:
        logger.warning("No revocation sources provided; performing chain-only validation")
        check_revocation = False

    validation_time = datetime.now(timezone.utc)
    if getattr(args, 'validation_time', None):
        try:
            validation_time = datetime.fromisoformat(args.validation_time)
            if validation_time.tzinfo is None:
                validation_time = validation_time.replace(tzinfo=timezone.utc)
        except Exception:
            logger.error(f"Invalid validation time format: {args.validation_time}")
            sys.exit(1)

    result = validate_certificate_path(
        leaf, untrusted, trusted,
        validation_time=validation_time,
        check_revocation=check_revocation,
        crl_sources=crl_sources,
        ocsp_url=ocsp_url,
        logger=logger
    )

    if result.get('valid'):
        print("Validation PASSED")
    else:
        print("Validation FAILED")
        print(f"Reason: {result.get('error', 'Unknown error')}")
    for step in result.get('steps', []):
        print(f"  {step}")
    sys.exit(0 if result.get('valid') else 1)

def check_status(args):
    logger = setup_logging(args.log_file)
    logger.info("Checking revocation status")

    with open(args.cert, 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read())
    with open(args.ca_cert, 'rb') as f:
        issuer = x509.load_pem_x509_certificate(f.read())

    ocsp_url = getattr(args, 'ocsp_url', None)
    crl_sources = getattr(args, 'crl', None)

    status, details = check_revocation_status(
        cert, issuer,
        ocsp_url=ocsp_url,
        crl_sources=crl_sources,
        logger=logger
    )

    print(f"Revocation status: {status.upper()}")
    if details:
        print(f"Details: {details}")
    sys.exit(0 if status == 'good' else 1)