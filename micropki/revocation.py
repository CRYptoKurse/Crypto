import sys
from datetime import datetime, timezone
from .logger import setup_logging
from .database import update_certificate_status, get_certificate_status, get_certificate_by_serial

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

def revoke_certificate(db_path, serial_hex, reason, force=False, log_file=None):
    logger = setup_logging(log_file)
    serial_hex = serial_hex.upper()
    cert_pem = get_certificate_by_serial(db_path, serial_hex)
    if cert_pem is None:
        logger.error(f"Certificate with serial {serial_hex} not found")
        sys.exit(1)

    status = get_certificate_status(db_path, serial_hex)
    if status == 'revoked':
        logger.warning(f"Certificate {serial_hex} is already revoked")
        return

    update_certificate_status(db_path, serial_hex, 'revoked', reason, datetime.now(timezone.utc))
    logger.info(f"Revoked certificate {serial_hex} with reason: {reason}")