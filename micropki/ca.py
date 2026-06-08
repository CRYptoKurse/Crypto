import os
import sys
import re
from pathlib import Path
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509 import load_pem_x509_csr
from .crypto_utils import (generate_rsa_key, generate_ecc_key, encrypt_private_key,
                           parse_dn_string, load_encrypted_private_key, load_certificate,
                           parse_san_string, verify_signature)
from .certificates import cert_to_pem
from .csr import create_csr
from .templates import apply_template
from .logger import setup_logging
from .database import init_db, insert_certificate, get_certificate_by_serial, is_key_compromised
from .policy import check_key_size, check_validity, check_san_list, check_signature_algorithm, enforce_pathlen
from .audit import AuditLogger
from .transparency import CTLog

def init_ca(args):
    logger = setup_logging(args.log_file)
    audit = AuditLogger("./pki/audit/audit.log")
    audit.log("AUDIT", "ca_init", "started", f"Initializing Root CA: {args.subject}", {"subject": args.subject})
    logger.info("CA initialization started")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    private_dir = out_dir / 'private'
    certs_dir = out_dir / 'certs'
    key_path = private_dir / 'ca.key.pem'
    cert_path = certs_dir / 'ca.cert.pem'
    policy_path = out_dir / 'policy.txt'

    if (key_path.exists() or cert_path.exists()) and not args.force:
        logger.error("Output files already exist. Use --force to overwrite.")
        audit.log("AUDIT", "ca_init", "failure", "Output files already exist", {"subject": args.subject})
        sys.exit(1)

    with open(args.passphrase_file, 'rb') as f:
        passphrase = f.read().strip()
        if not passphrase:
            logger.error("Passphrase is empty")
            audit.log("AUDIT", "ca_init", "failure", "Empty passphrase", {})
            sys.exit(1)

    logger.info(f"Generating {args.key_type} key (size {args.key_size})")
    if args.key_type == 'rsa':
        private_key = generate_rsa_key(args.key_size)
    else:
        private_key = generate_ecc_key(args.key_size)
    logger.info("Key generation completed")

    # Policy checks for Root CA
    ok, err = check_key_size(private_key.public_key(), 'root')
    if not ok:
        logger.error(err)
        audit.log("AUDIT", "ca_init", "failure", f"Policy violation: {err}", {})
        sys.exit(1)
    ok, err = check_validity(args.validity_days, 'root')
    if not ok:
        logger.error(err)
        audit.log("AUDIT", "ca_init", "failure", f"Policy violation: {err}", {})
        sys.exit(1)

    subject = parse_dn_string(args.subject)

    logger.info("Creating self-signed certificate")
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(subject)
    serial = int.from_bytes(os.urandom(19), 'big')
    builder = builder.serial_number(serial)
    now = datetime.now(timezone.utc)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + timedelta(days=args.validity_days))
    builder = builder.public_key(private_key.public_key())

    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    builder = builder.add_extension(
        x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                      data_encipherment=False, key_agreement=False, key_cert_sign=True,
                      crl_sign=True, encipher_only=False, decipher_only=False),
        critical=True
    )
    ski = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
    builder = builder.add_extension(ski, critical=False)
    builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski), critical=False)

    if args.key_type == 'rsa':
        sig_hash = hashes.SHA256()
    else:
        sig_hash = hashes.SHA384()
    cert = builder.sign(private_key=private_key, algorithm=sig_hash)
    logger.info("Certificate signing completed")

    private_dir.mkdir(mode=0o700, exist_ok=True)
    encrypted_key = encrypt_private_key(private_key, passphrase)
    with open(key_path, 'wb') as f:
        f.write(encrypted_key)
    try:
        os.chmod(key_path, 0o600)
    except:
        logger.warning("Could not set file permissions on key (non-UNIX)")
    logger.info(f"Saved encrypted private key to {key_path}")

    certs_dir.mkdir(exist_ok=True)
    with open(cert_path, 'wb') as f:
        f.write(cert_to_pem(cert))
    logger.info(f"Saved certificate to {cert_path}")

    policy_content = f"""Certificate Policy Document
CA Name: {args.subject}
Serial Number: {hex(cert.serial_number)}
Validity: {cert.not_valid_before_utc} to {cert.not_valid_after_utc}
Key Algorithm: {args.key_type.upper()}-{args.key_size}
Purpose: Root CA for MicroPKI demonstration
Policy Version: 1.0
Creation Date: {cert.not_valid_before_utc}
"""
    with open(policy_path, 'w', encoding='utf-8') as f:
        f.write(policy_content)
    logger.info(f"Generated policy file at {policy_path}")

    audit.log(
        level="AUDIT",
        operation="ca_init",
        status="success",
        message=f"Root CA initialized: {args.subject}",
        metadata={"subject": args.subject, "serial": hex(cert.serial_number)}
    )

    logger.info("CA initialization completed successfully")

def issue_intermediate(args):
    logger = setup_logging(args.log_file)
    audit = AuditLogger("./pki/audit/audit.log")
    audit.log("AUDIT", "issue_intermediate", "started", f"Issuing Intermediate CA: {args.subject}", {"subject": args.subject})
    logger.info("Intermediate CA issuance started")

    out_dir = Path(args.out_dir)
    private_dir = out_dir / 'private'
    certs_dir = out_dir / 'certs'
    csrs_dir = out_dir / 'csrs'
    private_dir.mkdir(mode=0o700, exist_ok=True)
    certs_dir.mkdir(exist_ok=True)
    csrs_dir.mkdir(exist_ok=True)

    root_cert = load_certificate(args.root_cert)
    with open(args.root_pass_file, 'rb') as f:
        root_pass = f.read().strip()
    root_key = load_encrypted_private_key(args.root_key, root_pass)

    if args.key_type == 'rsa':
        inter_key = generate_rsa_key(args.key_size)
    else:
        inter_key = generate_ecc_key(args.key_size)
    logger.info(f"Intermediate CA key generated ({args.key_type}-{args.key_size})")

    # Policy checks for Intermediate CA
    ok, err = check_key_size(inter_key.public_key(), 'intermediate')
    if not ok:
        logger.error(err)
        audit.log("AUDIT", "issue_intermediate", "failure", f"Policy violation: {err}", {})
        sys.exit(1)
    ok, err = check_validity(args.validity_days, 'intermediate')
    if not ok:
        logger.error(err)
        audit.log("AUDIT", "issue_intermediate", "failure", f"Policy violation: {err}", {})
        sys.exit(1)
    ok, err = enforce_pathlen(args.pathlen, True, 'intermediate')
    if not ok:
        logger.error(err)
        audit.log("AUDIT", "issue_intermediate", "failure", f"Policy violation: {err}", {})
        sys.exit(1)

    subject = parse_dn_string(args.subject)
    csr = create_csr(inter_key, subject, use_ca=True, pathlen=args.pathlen)
    csr_path = csrs_dir / 'intermediate.csr.pem'
    with open(csr_path, 'wb') as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    logger.info(f"CSR saved to {csr_path}")

    db_path = getattr(args, 'db_path', './pki/micropki.db')
    if not Path(db_path).exists():
        serial_hex, serial_int = None, None
    else:
        from .serial import generate_unique_serial
        serial_hex, serial_int = generate_unique_serial(db_path)
        logger.info(f"Generated unique serial: {serial_hex}")

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(csr.subject)
    builder = builder.issuer_name(root_cert.subject)
    if serial_int is None:
        serial_int = int.from_bytes(os.urandom(19), 'big')
    builder = builder.serial_number(serial_int)
    now = datetime.now(timezone.utc)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + timedelta(days=args.validity_days))
    builder = builder.public_key(inter_key.public_key())

    bc = x509.BasicConstraints(ca=True, path_length=args.pathlen)
    builder = builder.add_extension(bc, critical=True)
    ku = x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                       data_encipherment=False, key_agreement=False, key_cert_sign=True,
                       crl_sign=True, encipher_only=False, decipher_only=False)
    builder = builder.add_extension(ku, critical=True)
    ski = x509.SubjectKeyIdentifier.from_public_key(inter_key.public_key())
    builder = builder.add_extension(ski, critical=False)
    root_ski = root_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(root_ski)
    builder = builder.add_extension(aki, critical=False)

    if args.key_type == 'rsa':
        sig_hash = hashes.SHA256()
    else:
        sig_hash = hashes.SHA384()
    inter_cert = builder.sign(private_key=root_key, algorithm=sig_hash)

    if serial_hex is not None:
        try:
            cert_data = {
                'serial_hex': serial_hex,
                'subject': args.subject,
                'issuer': root_cert.subject.rfc4514_string(),
                'not_before': inter_cert.not_valid_before_utc.isoformat(),
                'not_after': inter_cert.not_valid_after_utc.isoformat(),
                'cert_pem': inter_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
                'status': 'valid'
            }
            insert_certificate(db_path, cert_data)
            logger.info(f"Certificate inserted into database (serial {serial_hex})")
        except Exception as e:
            logger.error(f"Database insertion failed: {e}")
            sys.exit(1)

    inter_cert_path = certs_dir / 'intermediate.cert.pem'
    with open(inter_cert_path, 'wb') as f:
        f.write(inter_cert.public_bytes(serialization.Encoding.PEM))
    logger.info(f"Intermediate CA certificate saved to {inter_cert_path}")

    with open(args.passphrase_file, 'rb') as f:
        inter_pass = f.read().strip()
    encrypted_key = encrypt_private_key(inter_key, inter_pass)
    inter_key_path = private_dir / 'intermediate.key.pem'
    with open(inter_key_path, 'wb') as f:
        f.write(encrypted_key)
    try:
        os.chmod(inter_key_path, 0o600)
    except:
        logger.warning("Could not set permissions on intermediate key")
    logger.info(f"Encrypted Intermediate CA key saved to {inter_key_path}")

    policy_path = out_dir / 'policy.txt'
    with open(policy_path, 'a', encoding='utf-8') as f:
        f.write("\n\n=== Intermediate CA ===\n")
        f.write(f"Subject: {args.subject}\n")
        f.write(f"Serial Number: {hex(inter_cert.serial_number)}\n")
        f.write(f"Validity: {inter_cert.not_valid_before_utc} to {inter_cert.not_valid_after_utc}\n")
        f.write(f"Key Algorithm: {args.key_type.upper()}-{args.key_size}\n")
        f.write(f"Path Length Constraint: {args.pathlen}\n")
        f.write(f"Issuer: {root_cert.subject.rfc4514_string()}\n")
    logger.info(f"Policy file updated at {policy_path}")

    audit.log(
        level="AUDIT",
        operation="issue_intermediate",
        status="success",
        message=f"Issued intermediate CA: {args.subject}",
        metadata={"subject": args.subject, "serial": hex(inter_cert.serial_number)}
    )

    logger.info("Intermediate CA issuance completed successfully")

def issue_cert(args):
    logger = setup_logging(args.log_file)
    audit = AuditLogger("./pki/audit/audit.log")
    audit.log("AUDIT", "issue_certificate", "started", f"Issuing {args.template} certificate", {"template": args.template})
    logger.info(f"End-entity certificate issuance started (template: {args.template})")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ca_cert = load_certificate(args.ca_cert)
    with open(args.ca_pass_file, 'rb') as f:
        ca_pass = f.read().strip()
    ca_key = load_encrypted_private_key(args.ca_key, ca_pass)

    csr_mode = False
    if hasattr(args, 'csr') and args.csr:
        with open(args.csr, 'rb') as f:
            csr = load_pem_x509_csr(f.read())
        csr_public_key = csr.public_key()
        try:
            verify_signature(csr_public_key, csr.signature, csr.tbs_certrequest_bytes, csr.signature_hash_algorithm)
        except Exception as e:
            logger.error(f"CSR signature invalid: {e}")
            audit.log("AUDIT", "issue_certificate", "failure", f"CSR signature invalid: {e}", {})
            sys.exit(1)
        ee_public_key = csr_public_key
        subject = csr.subject
        san_list = []
        try:
            san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san_list = list(san_ext.value)
        except x509.extensions.ExtensionNotFound:
            san_list = []
        if args.template == 'server' and not san_list:
            cn = None
            for attr in csr.subject:
                if attr.oid == NameOID.COMMON_NAME:
                    cn = attr.value
                    break
            if cn:
                san_list = [x509.DNSName(cn)]
                logger.warning(f"No SAN found in CSR; using CN={cn} as fallback SAN")
        csr_mode = True
        logger.info("Using external CSR")
    else:
        logger.info("Generating end-entity key pair (RSA 2048)")
        ee_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ee_public_key = ee_key.public_key()
        subject = parse_dn_string(args.subject)
        san_list = [parse_san_string(s) for s in args.san] if args.san else []
        csr_mode = False

    # Проверка скомпрометированного ключа
    if is_key_compromised(args.db_path, ee_public_key):
        logger.error("Public key is compromised, issuance rejected")
        audit.log("AUDIT", "issue_certificate", "failure", "Compromised key reuse blocked", {})
        sys.exit(1)

    # Policy checks for end-entity
    ok, err = check_key_size(ee_public_key, 'end_entity')
    if not ok:
        logger.error(err)
        audit.log("AUDIT", "issue_certificate", "failure", f"Policy violation: {err}", {"template": args.template})
        sys.exit(1)
    ok, err = check_validity(args.validity_days, 'end_entity')
    if not ok:
        logger.error(err)
        audit.log("AUDIT", "issue_certificate", "failure", f"Policy violation: {err}", {"template": args.template})
        sys.exit(1)
    if san_list:
        ok, err = check_san_list(san_list, args.template)
        if not ok:
            logger.error(err)
            audit.log("AUDIT", "issue_certificate", "failure", f"Policy violation: {err}", {"template": args.template})
            sys.exit(1)
    if csr_mode:
        ok, err = check_signature_algorithm(csr.signature_hash_algorithm)
        if not ok:
            logger.error(err)
            audit.log("AUDIT", "issue_certificate", "failure", f"Policy violation: {err}", {"template": args.template})
            sys.exit(1)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(ca_cert.subject)
    serial_int = int.from_bytes(os.urandom(19), 'big')
    builder = builder.serial_number(serial_int)
    now = datetime.now(timezone.utc)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + timedelta(days=args.validity_days))
    builder = builder.public_key(ee_public_key)

    builder, san_required = apply_template(builder, args.template, san_list if san_list else None)
    if args.template == 'server' and san_required and not san_list:
        logger.error("Server certificate requires at least one SAN (dns or ip)")
        audit.log("AUDIT", "issue_certificate", "failure", "Server certificate missing SAN", {"template": args.template})
        sys.exit(1)

    if isinstance(ca_key, rsa.RSAPrivateKey):
        sig_hash = hashes.SHA256()
    else:
        sig_hash = hashes.SHA384()
    cert = builder.sign(private_key=ca_key, algorithm=sig_hash)

    db_path = args.db_path
    serial_hex = format(serial_int, 'x').upper()
    if Path(db_path).exists():
        try:
            cert_data = {
                'serial_hex': serial_hex,
                'subject': subject.rfc4514_string(),
                'issuer': ca_cert.subject.rfc4514_string(),
                'not_before': cert.not_valid_before_utc.isoformat(),
                'not_after': cert.not_valid_after_utc.isoformat(),
                'cert_pem': cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
                'status': 'valid'
            }
            insert_certificate(db_path, cert_data)
            logger.info(f"Certificate inserted into database (serial {serial_hex})")
        except Exception as e:
            logger.error(f"Database insertion failed: {e}")
            sys.exit(1)

    cn = None
    for attr in subject:
        if attr.oid == NameOID.COMMON_NAME:
            cn = attr.value
            break
    if not cn and san_list:
        if isinstance(san_list[0], x509.DNSName):
            cn = san_list[0].value
    if not cn:
        cn = "cert"
    base_name = re.sub(r'[^a-zA-Z0-9.-]', '_', cn)
    cert_path = out_dir / f"{base_name}.cert.pem"
    key_path = out_dir / f"{base_name}.key.pem"

    with open(cert_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    logger.info(f"Certificate saved to {cert_path}")

    if not csr_mode:
        unencrypted_key = ee_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(key_path, 'wb') as f:
            f.write(unencrypted_key)
        try:
            os.chmod(key_path, 0o600)
        except Exception:
            logger.warning("Could not set permissions")
        logger.warning(f"End-entity private key stored UNENCRYPTED at {key_path}")
    else:
        logger.info("Certificate issued from CSR; no private key stored")

    logger.info(f"Issued {args.template} certificate: Subject={subject.rfc4514_string()}, Serial={serial_hex}")
    logger.info("End-entity certificate issuance completed")

    audit.log(
        level="AUDIT",
        operation="issue_certificate",
        status="success",
        message=f"Issued {args.template} certificate for {subject.rfc4514_string()}",
        metadata={"serial": serial_hex, "subject": subject.rfc4514_string(), "template": args.template}
    )

    ct = CTLog()
    ct.append(serial_hex, subject.rfc4514_string(), cert.public_bytes(serialization.Encoding.PEM),
              issuer=ca_cert.subject.rfc4514_string())