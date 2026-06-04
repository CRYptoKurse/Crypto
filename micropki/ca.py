import os
import sys
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from .crypto_utils import (generate_rsa_key, generate_ecc_key, encrypt_private_key,
                           parse_dn_string, load_encrypted_private_key, load_certificate,
                           parse_san_string)
from .certificates import create_self_signed_cert, cert_to_pem
from .csr import create_csr, csr_to_pem
from .templates import apply_template
from .logger import setup_logging

def init_ca(args):
    # Setup logging
    logger = setup_logging(args.log_file)
    logger.info("CA initialization started")

    # Validate out-dir
    out_dir = Path(args.out_dir)
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        logger.error(f"Cannot create output directory: {e}")
        sys.exit(1)

    # Check for existing files
    private_dir = out_dir / 'private'
    certs_dir = out_dir / 'certs'
    key_path = private_dir / 'ca.key.pem'
    cert_path = certs_dir / 'ca.cert.pem'
    policy_path = out_dir / 'policy.txt'

    if (key_path.exists() or cert_path.exists()) and not args.force:
        logger.error(f"Output files already exist. Use --force to overwrite.")
        sys.exit(1)

    # Read passphrase
    try:
        with open(args.passphrase_file, 'rb') as f:
            passphrase = f.read().strip()
            if not passphrase:
                raise ValueError("Passphrase is empty")
    except Exception as e:
        logger.error(f"Failed to read passphrase file: {e}")
        sys.exit(1)

    # Generate key
    logger.info(f"Generating {args.key_type} key (size {args.key_size})")
    try:
        if args.key_type == 'rsa':
            private_key = generate_rsa_key(args.key_size)
        else:
            private_key = generate_ecc_key(args.key_size)
    except Exception as e:
        logger.error(f"Key generation failed: {e}")
        sys.exit(1)
    logger.info("Key generation completed")

    # Parse subject DN
    try:
        subject = parse_dn_string(args.subject)
    except Exception as e:
        logger.error(f"Invalid subject DN: {e}")
        sys.exit(1)

    # Create self-signed cert
    logger.info("Creating self-signed certificate")
    try:
        cert = create_self_signed_cert(private_key, subject, args.validity_days, args.key_type)
    except Exception as e:
        logger.error(f"Certificate creation failed: {e}")
        sys.exit(1)
    logger.info("Certificate signing completed")

    # Write encrypted private key
    private_dir.mkdir(mode=0o700, exist_ok=True)
    encrypted_key = encrypt_private_key(private_key, passphrase)
    with open(key_path, 'wb') as f:
        f.write(encrypted_key)
    # Set permissions (best effort)
    try:
        os.chmod(key_path, 0o600)
    except Exception:
        logger.warning("Could not set file permissions on key (non-UNIX system)")
    logger.info(f"Saved encrypted private key to {key_path}")

    # Write certificate
    certs_dir.mkdir(exist_ok=True)
    with open(cert_path, 'wb') as f:
        f.write(cert_to_pem(cert))
    logger.info(f"Saved certificate to {cert_path}")

    # Write policy.txt
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

    logger.info("CA initialization completed successfully")

def issue_intermediate(args):
    logger = setup_logging(args.log_file)
    logger.info("Intermediate CA issuance started")

    # Проверка выходной директории
    out_dir = Path(args.out_dir)
    private_dir = out_dir / 'private'
    certs_dir = out_dir / 'certs'
    private_dir.mkdir(mode=0o700, exist_ok=True)
    certs_dir.mkdir(exist_ok=True)

    # Загрузка корневого сертификата и ключа
    root_cert = load_certificate(args.root_cert)
    with open(args.root_pass_file, 'rb') as f:
        root_pass = f.read().strip()
    root_key = load_encrypted_private_key(args.root_key, root_pass)

    # Генерация ключа Intermediate CA
    logger.info(f"Generating Intermediate CA key ({args.key_type}, size {args.key_size})")
    if args.key_type == 'rsa':
        inter_key = generate_rsa_key(args.key_size)
    else:
        inter_key = generate_ecc_key(args.key_size)
    logger.info("Intermediate CA key generated")

    # Парсинг subject
    subject = parse_dn_string(args.subject)

    # Создание CSR
    logger.info("Creating Intermediate CA CSR")
    csr = create_csr(inter_key, subject, use_ca=True, pathlen=args.pathlen)
    csr_path = out_dir / 'csrs' / 'intermediate.csr.pem'
    csr_path.parent.mkdir(exist_ok=True)
    with open(csr_path, 'wb') as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    logger.info(f"CSR saved to {csr_path}")

    # Подпись CSR корневым CA
    logger.info("Signing Intermediate CA CSR with Root CA")
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(csr.subject)
    builder = builder.issuer_name(root_cert.subject)
    serial = int.from_bytes(os.urandom(19), 'big')
    builder = builder.serial_number(serial)
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + timedelta(days=args.validity_days))
    builder = builder.public_key(inter_key.public_key())

    # Расширения для Intermediate CA
    # Basic Constraints: CA=True, pathlen = args.pathlen
    bc = x509.BasicConstraints(ca=True, path_length=args.pathlen)
    builder = builder.add_extension(bc, critical=True)
    # Key Usage: keyCertSign, cRLSign
    ku = x509.KeyUsage(digital_signature=False, content_commitment=False,
                       key_encipherment=False, data_encipherment=False,
                       key_agreement=False, key_cert_sign=True,
                       crl_sign=True, encipher_only=False, decipher_only=False)
    builder = builder.add_extension(ku, critical=True)
    # SKI из публичного ключа Intermediate
    ski = x509.SubjectKeyIdentifier.from_public_key(inter_key.public_key())
    builder = builder.add_extension(ski, critical=False)
    # AKI из SKI корневого
    aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
        root_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    )
    builder = builder.add_extension(aki, critical=False)

    # Выбор хэша в зависимости от типа ключа
    if args.key_type == 'rsa':
        sig_hash = hashes.SHA256()
    else:
        sig_hash = hashes.SHA384()
    inter_cert = builder.sign(private_key=root_key, algorithm=sig_hash)

    # Сохранение сертификата Intermediate
    inter_cert_path = certs_dir / 'intermediate.cert.pem'
    with open(inter_cert_path, 'wb') as f:
        f.write(inter_cert.public_bytes(serialization.Encoding.PEM))
    logger.info(f"Intermediate CA certificate saved to {inter_cert_path}")

    # Шифрование и сохранение ключа Intermediate
    with open(args.passphrase_file, 'rb') as f:
        inter_pass = f.read().strip()
    encrypted_key = encrypt_private_key(inter_key, inter_pass)
    inter_key_path = private_dir / 'intermediate.key.pem'
    with open(inter_key_path, 'wb') as f:
        f.write(encrypted_key)
    try:
        os.chmod(inter_key_path, 0o600)
    except Exception:
        logger.warning("Could not set permissions on intermediate key (non-UNIX)")
    logger.info(f"Encrypted Intermediate CA key saved to {inter_key_path}")

    # Обновление policy.txt
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

    logger.info("Intermediate CA issuance completed successfully")

def issue_cert(args):
    logger = setup_logging(args.log_file)
    logger.info(f"End-entity certificate issuance started (template: {args.template})")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Загрузка CA (Intermediate) сертификата и ключа
    ca_cert = load_certificate(args.ca_cert)
    with open(args.ca_pass_file, 'rb') as f:
        ca_pass = f.read().strip()
    ca_key = load_encrypted_private_key(args.ca_key, ca_pass)

    # Генерация ключа для end-entity (если не предоставлен CSR – опционально)
    # Для простоты всегда генерируем новый RSA-2048 ключ (минимальные требования)
    logger.info("Generating end-entity key pair (RSA 2048)")
    ee_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Парсинг subject
    subject = parse_dn_string(args.subject)

    # Парсинг SAN
    san_list = []
    if args.san:
        for san in args.san:
            san_list.append(parse_san_string(san))

    # Создание сертификата
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(ca_cert.subject)
    serial = int.from_bytes(os.urandom(19), 'big')
    builder = builder.serial_number(serial)
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + timedelta(days=args.validity_days))
    builder = builder.public_key(ee_key.public_key())

    # Применение шаблона
    builder, san_required = apply_template(builder, args.template, san_list if san_list else None)

    # Валидация SAN для server
    if args.template == 'server' and san_required and not san_list:
        logger.error("Server certificate requires at least one SAN (dns or ip)")
        sys.exit(1)

    # Подпись
    # Определяем алгоритм хэша по типу ключа CA (RSA -> SHA256, ECC -> SHA384)
    if isinstance(ca_key, rsa.RSAPrivateKey):
        sig_hash = hashes.SHA256()
    else:
        sig_hash = hashes.SHA384()
    cert = builder.sign(private_key=ca_key, algorithm=sig_hash)

    # Формирование имени файла (по CN или первый SAN)
    cn = None
    for attr in subject:
        if attr.oid == x509.NameOID.COMMON_NAME:
            cn = attr.value
            break
    if not cn and san_list and isinstance(san_list[0], x509.DNSName):
        cn = san_list[0].value
    else:
        cn = "cert"
    base_name = cn.replace(' ', '_').replace('*', 'wildcard')
    cert_path = out_dir / f"{base_name}.cert.pem"
    key_path = out_dir / f"{base_name}.key.pem"

    # Сохранение сертификата
    with open(cert_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    logger.info(f"Certificate saved to {cert_path}")

    # Сохранение незашифрованного ключа
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
        logger.warning("Could not set permissions on end-entity key (non-UNIX)")
    logger.warning(f"End-entity private key stored UNENCRYPTED at {key_path}")

    # Логирование
    logger.info(f"Issued {args.template} certificate: Subject={args.subject}, Serial={hex(cert.serial_number)}, SANs={args.san if args.san else 'none'}")

    # Обновление policy.txt (опционально, можно добавить запись о выданном сертификате)
    # Но по требованию POL-2 только Intermediate CA, не обязательно для каждого листа.

    logger.info("End-entity certificate issuance completed")