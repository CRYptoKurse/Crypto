import time
from datetime import datetime, timezone, timedelta
from flask import Flask, request, abort, Response
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.ocsp import (
    OCSPResponseBuilder,
    OCSPResponseStatus,
    OCSPResponderEncoding,
    OCSPCertStatus,
    load_der_ocsp_request,
)
from cryptography.x509.oid import ExtensionOID
from .database import get_certificate_status, get_certificate_revocation_info, get_certificate_by_serial
from .logger import setup_logging
from .audit import AuditLogger

app = Flask(__name__)

def start_ocsp_server(host, port, db_path, responder_cert_path, responder_key_path, ca_cert_path, cache_ttl, log_file,
                      rate_limit=0, rate_burst=10):
    logger = setup_logging(log_file)
    audit = AuditLogger("./pki/audit/audit.log")
    audit.log("AUDIT", "ocsp_start", "started", f"Starting OCSP responder on {host}:{port}", {"host": host, "port": port})
    logger.info("Starting OCSP responder")

    with open(responder_cert_path, 'rb') as f:
        responder_cert = x509.load_pem_x509_certificate(f.read())
    with open(responder_key_path, 'rb') as f:
        responder_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(ca_cert_path, 'rb') as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    if rate_limit > 0:
        from .ratelimit import rate_limit_middleware
        rate_limit_middleware(app, rate_limit, rate_burst)

    @app.route('/ocsp', methods=['POST'])
    def ocsp_endpoint():
        if request.content_type != 'application/ocsp-request':
            abort(400)
        req_data = request.get_data()
        try:
            ocsp_req = load_der_ocsp_request(req_data)
        except Exception:
            logger.exception("Failed to parse OCSP request")
            return Response(
                OCSPResponseBuilder.build_unsuccessful(OCSPResponseStatus.MALFORMED_REQUEST).public_bytes(serialization.Encoding.DER),
                content_type='application/ocsp-response'
            )

        serial_hex = format(ocsp_req.serial_number, 'x').upper()
        cert_pem = get_certificate_by_serial(db_path, serial_hex)
        if not cert_pem:
            logger.warning(f"Certificate not found for serial {serial_hex}")
            return Response(
                OCSPResponseBuilder.build_unsuccessful(OCSPResponseStatus.UNAUTHORIZED).public_bytes(serialization.Encoding.DER),
                content_type='application/ocsp-response'
            )

        cert_obj = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
        status = get_certificate_status(db_path, serial_hex)

        if status == 'valid':
            cert_status = OCSPCertStatus.GOOD
            rev_time = None
            rev_reason = None
        elif status == 'revoked':
            cert_status = OCSPCertStatus.REVOKED
            rev_date_str, rev_reason = get_certificate_revocation_info(db_path, serial_hex)
            rev_time = datetime.fromisoformat(rev_date_str) if rev_date_str else None
        else:
            cert_status = OCSPCertStatus.UNKNOWN
            rev_time = None
            rev_reason = None

        builder = OCSPResponseBuilder()
        builder = builder.responder_id(OCSPResponderEncoding.NAME, responder_cert)

        now = datetime.now(timezone.utc)
        next_update = now + timedelta(days=1)

        builder = builder.add_response(
            cert=cert_obj,
            issuer=ca_cert,
            algorithm=hashes.SHA256(),
            cert_status=cert_status,
            this_update=now,
            next_update=next_update,
            revocation_time=rev_time,
            revocation_reason=rev_reason
        )

        nonce_extension = None
        try:
            for ext in ocsp_req.extensions:
                if ext.oid == ExtensionOID.OCSP_NONCE:
                    nonce_extension = ext
                    break
        except Exception as e:
            logger.error(f"Error extracting nonce: {e}")

        if nonce_extension is not None:
            builder = builder.add_extension(nonce_extension, critical=False)
            logger.debug("Nonce added to response")
        else:
            logger.debug("No nonce found in request")

        response = builder.sign(private_key=responder_key, algorithm=hashes.SHA256())

        return Response(
            response.public_bytes(serialization.Encoding.DER),
            content_type='application/ocsp-response'
        )

    audit.log("AUDIT", "ocsp_start", "success", f"OCSP responder listening on {host}:{port}", {"host": host, "port": port})
    app.run(host=host, port=port, threaded=True, use_reloader=False)