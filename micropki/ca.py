import os
import sys
from pathlib import Path
from .crypto_utils import generate_rsa_key, generate_ecc_key, encrypt_private_key, parse_dn_string, compute_ski
from .certificates import create_self_signed_cert, cert_to_pem
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