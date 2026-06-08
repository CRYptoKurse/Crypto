import sys
from datetime import datetime, timezone
from .logger import setup_logging
from .database import update_certificate_status, get_certificate_status, get_certificate_by_serial
from .audit import AuditLogger

REASON_CODES = {
    'unspecified': 0,
    'keyCompromise': 1,
    'cACompromise': 2,
    'affiliationChanged': 3,
    'superseded': 4,
    'cessationOfOperation': 5,
    'certificateHold': 6,
    'removeFromCRL': 8,
    'privilegeWithdrawn': 9,
    'aACompromise': 10,
}

def revoke_certificate(db_path, serial_hex, reason, force=False, log_file=None, audit_log_path="./pki/audit/audit.log"):
    logger = setup_logging(log_file)
    audit = AuditLogger(audit_log_path)
    serial_hex = serial_hex.upper()
    cert_pem = get_certificate_by_serial(db_path, serial_hex)
    if cert_pem is None:
        logger.error(f"Certificate with serial {serial_hex} not found")
        audit.log("AUDIT", "revoke", "failure", f"Certificate {serial_hex} not found", {"serial": serial_hex})
        sys.exit(1)

    status = get_certificate_status(db_path, serial_hex)
    if status == 'revoked':
        logger.warning(f"Certificate {serial_hex} is already revoked")
        audit.log("AUDIT", "revoke", "failure", f"Certificate {serial_hex} already revoked", {"serial": serial_hex})
        return

    audit.log("AUDIT", "revoke", "started", f"Revoking certificate {serial_hex}", {"serial": serial_hex, "reason": reason})
    update_certificate_status(db_path, serial_hex, 'revoked', reason, datetime.now(timezone.utc))
    logger.info(f"Revoked certificate {serial_hex} with reason: {reason}")
    audit.log("AUDIT", "revoke", "success", f"Revoked certificate {serial_hex}", {"serial": serial_hex, "reason": reason})