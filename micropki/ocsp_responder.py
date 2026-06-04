import sys
import time
from pathlib import Path
from datetime import datetime, timezone
from flask import Flask, request, abort, Response
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.ocsp import (
    OCSPResponseBuilder,
    OCSPResponseStatus,
    load_der_ocsp_request,
)
from cryptography.x509.oid import ExtensionOID
from .database import get_certificate_status, get_certificate_revocation_info
from .logger import setup_logging

app = Flask(__name__)

def compute_issuer_hashes(ca_cert):
    """Compute SHA-1 hash of issuer DN and issuer public key for OCSP CertID."""
    # issuerNameHash = SHA-1(DER of subject DN)
    from cryptography.hazmat.primitives import hashes
    name_hash = hashes.Hash(hashes.SHA1())
    name_hash.update(ca_cert.subject.public_bytes())
    issuer_name_hash = name_hash.finalize()
    # issuerKeyHash = SHA-1(SubjectPublicKeyInfo of issuer)
    key_hash = hashes.Hash(hashes.SHA1())
    key_hash.update(ca_cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    issuer_key_hash = key_hash.finalize()
    return issuer_name_hash, issuer_key_hash

def start_ocsp_server(host, port, db_path, responder_cert_path, responder_key_path, ca_cert_path, cache_ttl, log_file):
    logger = setup_logging(log_file)
    logger.info("Starting OCSP responder")

    with open(responder_cert_path, 'rb') as f:
        responder_cert = x509.load_pem_x509_certificate(f.read())
    with open(responder_key_path, 'rb') as f:
        responder_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(ca_cert_path, 'rb') as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    issuer_name_hash, issuer_key_hash = compute_issuer_hashes(ca_cert)

    app.config['DB_PATH'] = db_path
    app.config['RESPONDER_CERT'] = responder_cert
    app.config['RESPONDER_KEY'] = responder_key
    app.config['ISSUER_NAME_HASH'] = issuer_name_hash
    app.config['ISSUER_KEY_HASH'] = issuer_key_hash
    app.config['CA_CERT'] = ca_cert
    app.config['LOGGER'] = logger

    @app.route('/ocsp', methods=['POST'])
    def ocsp_endpoint():
        start_time = time.time()
        if request.content_type != 'application/ocsp-request':
            abort(400, description="Invalid Content-Type")
        req_data = request.get_data()
        try:
            ocsp_req = load_der_ocsp_request(req_data)
        except Exception:
            logger.exception("Failed to parse OCSP request")
            return Response(
                OCSPResponseBuilder.build_unsuccessful(OCSPResponseStatus.MALFORMED_REQUEST).public_bytes(serialization.Encoding.DER),
                content_type='application/ocsp-response'
            )

        # Extract nonce if present
        nonce = None
        for ext in ocsp_req.extensions:
            if ext.oid == ExtensionOID.OCSP_NONCE:
                nonce = ext.value
                break

        builder = OCSPResponseBuilder()
        builder = builder.responder_id(OCSPResponseBuilder.RESPONDER_ID_HASH, responder_cert)

        for req in ocsp_req.requests:
            if req.issuer_name_hash != issuer_name_hash or req.issuer_key_hash != issuer_key_hash:
                cert_status = 'unknown'
                rev_time = None
                rev_reason = None
            else:
                serial_hex = format(req.serial_number, 'x').upper()
                status = get_certificate_status(db_path, serial_hex)
                if status == 'valid':
                    cert_status = 'good'
                    rev_time = None
                    rev_reason = None
                elif status == 'revoked':
                    cert_status = 'revoked'
                    rev_date_str, rev_reason = get_certificate_revocation_info(db_path, serial_hex)
                    rev_time = datetime.fromisoformat(rev_date_str) if rev_date_str else None
                else:
                    cert_status = 'unknown'
                    rev_time = None
                    rev_reason = None
            builder = builder.add_response(cert=req, status=cert_status,
                                           revocation_time=rev_time,
                                           revocation_reason=rev_reason)

        if nonce:
            builder = builder.add_extension(nonce, critical=False)

        # Build and sign the response
        production_time = datetime.now(timezone.utc)
        response = builder.build(
            private_key=responder_key,
            algorithm=responder_cert.signature_hash_algorithm,
            production_time=production_time
        )
        response_der = response.public_bytes(serialization.Encoding.DER)

        elapsed = (time.time() - start_time) * 1000
        logger.info(f"OCSP request from {request.remote_addr} processed in {elapsed:.2f}ms")
        return Response(response_der, content_type='application/ocsp-response')

    app.run(host=host, port=port, threaded=True)