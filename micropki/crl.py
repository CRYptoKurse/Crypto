import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from .database import get_revoked_certificates, get_crl_number, update_crl_number
from .crypto_utils import load_encrypted_private_key, load_certificate
from .logger import setup_logging
from .audit import AuditLogger

def generate_crl(args):
    logger = setup_logging(args.log_file)
    audit = AuditLogger("./pki/audit/audit.log")
    audit.log("AUDIT", "gen_crl", "started", f"Generating CRL for {args.ca}", {"ca": args.ca})

    out_dir = Path(args.out_dir)
    crl_dir = out_dir / 'crl'
    crl_dir.mkdir(parents=True, exist_ok=True)

    if args.ca == 'root':
        cert_path = out_dir / 'certs' / 'ca.cert.pem'
        key_path = out_dir / 'private' / 'ca.key.pem'
        crl_path = args.out_file if args.out_file else crl_dir / 'root.crl.pem'
        issuer_subject = 'root'
    elif args.ca == 'intermediate':
        cert_path = out_dir / 'certs' / 'intermediate.cert.pem'
        key_path = out_dir / 'private' / 'intermediate.key.pem'
        crl_path = args.out_file if args.out_file else crl_dir / 'intermediate.crl.pem'
        issuer_subject = 'intermediate'
    else:
        logger.error(f"Unknown CA: {args.ca}")
        sys.exit(1)

    if not cert_path.exists() or not key_path.exists():
        logger.error(f"CA certificate or key not found for {args.ca}")
        audit.log("AUDIT", "gen_crl", "failure", f"CA files missing for {args.ca}", {"ca": args.ca})
        sys.exit(1)

    ca_cert = load_certificate(str(cert_path))
    with open(args.passphrase_file, 'rb') as f:
        passphrase = f.read().strip()
    ca_key = load_encrypted_private_key(str(key_path), passphrase)

    db_path = args.db_path
    revoked_list = get_revoked_certificates(db_path)

    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.subject)
    now = datetime.now(timezone.utc)
    builder = builder.last_update(now)
    builder = builder.next_update(now + timedelta(days=args.next_update))

    ca_subject_str = ca_cert.subject.rfc4514_string()
    crl_number = get_crl_number(db_path, ca_subject_str)
    builder = builder.add_extension(x509.CRLNumber(crl_number), critical=False)

    aki = ca_cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    builder = builder.add_extension(aki, critical=False)

    for serial_hex, rev_date in revoked_list:
        if rev_date is None:
            continue
        serial_int = int(serial_hex, 16)
        rev_cert = x509.RevokedCertificateBuilder().serial_number(serial_int).revocation_date(rev_date)
        builder = builder.add_revoked_certificate(rev_cert.build())

    if isinstance(ca_key, rsa.RSAPrivateKey):
        sig_hash = hashes.SHA256()
    else:
        sig_hash = hashes.SHA384()
    crl = builder.sign(private_key=ca_key, algorithm=sig_hash)

    with open(crl_path, 'wb') as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))
    logger.info(f"CRL saved to {crl_path} (number {crl_number})")
    update_crl_number(db_path, ca_subject_str, crl_number + 1, now, now + timedelta(days=args.next_update), str(crl_path))
    logger.info("CRL generation completed")
    audit.log("AUDIT", "gen_crl", "success", f"CRL generated for {args.ca}", {"ca": args.ca, "path": str(crl_path)})