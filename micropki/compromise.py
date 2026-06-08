from datetime import datetime, timezone
from .database import update_certificate_status, get_certificate_by_serial
from .audit import AuditLogger

def compromise_certificate(db_path: str, serial_hex: str, reason: str, audit_logger: AuditLogger,
                           emergency_crl_callback=None):
    cert_pem = get_certificate_by_serial(db_path, serial_hex)
    if not cert_pem:
        raise ValueError(f"Certificate {serial_hex} not found")
    rev_date = datetime.now(timezone.utc)
    update_certificate_status(db_path, serial_hex, 'revoked', reason, rev_date)

    audit_logger.log(
        level="AUDIT",
        operation="compromise",
        status="success",
        message=f"Certificate {serial_hex} compromised, reason {reason}",
        metadata={"serial": serial_hex, "reason": reason}
    )

    if emergency_crl_callback:
        emergency_crl_callback()