import sys
from datetime import datetime, timezone
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from .crypto_utils import verify_signature
from .revocation_check import check_revocation_status

def build_chain(leaf, untrusted, trusted):
    chain = [leaf]
    current = leaf
    max_depth = 10
    for _ in range(max_depth):
        issuer_found = None
        for cert in untrusted:
            if cert.subject == current.issuer:
                issuer_found = cert
                break
        if issuer_found:
            chain.append(issuer_found)
            current = issuer_found
            continue
        for cert in trusted:
            if cert.subject == current.issuer:
                chain.append(cert)
                return chain
        break
    return None

def validate_certificate_path(leaf, untrusted, trusted, validation_time=None,
                              check_revocation=False, crl_sources=None, ocsp_url=None,
                              logger=None):
    steps = []
    if validation_time is None:
        validation_time = datetime.now(timezone.utc)

    chain = build_chain(leaf, untrusted, trusted)
    if not chain:
        steps.append("Chain building failed: no path to trusted root")
        return {'valid': False, 'error': 'Chain building failed', 'steps': steps}

    steps.append(f"Chain built: {len(chain)} certificates")

    for i in range(len(chain) - 1):
        cert = chain[i]
        issuer = chain[i+1]
        # Проверка подписи
        try:
            verify_signature(issuer.public_key(), cert.signature, cert.tbs_certificate_bytes, cert.signature_hash_algorithm)
            steps.append(f"Certificate {i+1}: signature valid")
        except Exception as e:
            steps.append(f"Certificate {i+1}: signature invalid - {e}")
            return {'valid': False, 'error': f'Invalid signature at depth {i}', 'steps': steps}

        # Валидность периода
        if not (cert.not_valid_before_utc <= validation_time <= cert.not_valid_after_utc):
            steps.append(f"Certificate {i+1}: validity period expired or not yet valid")
            return {'valid': False, 'error': 'Certificate expired', 'steps': steps}
        steps.append(f"Certificate {i+1}: validity period OK")

        # Basic Constraints
        try:
            bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
            if i == 0:
                if bc.value.ca:
                    steps.append(f"Leaf certificate has CA=TRUE")
                    return {'valid': False, 'error': 'Leaf certificate has CA=TRUE', 'steps': steps}
            else:
                if not bc.value.ca:
                    steps.append(f"Intermediate certificate {i+1} has CA=FALSE")
                    return {'valid': False, 'error': 'Intermediate CA missing CA=TRUE', 'steps': steps}
                if bc.value.path_length is not None:
                    remaining = len(chain) - i - 2
                    if remaining > bc.value.path_length:
                        steps.append(f"Certificate {i+1}: pathLenConstraint exceeded")
                        return {'valid': False, 'error': 'Path length constraint violated', 'steps': steps}
            steps.append(f"Certificate {i+1}: BasicConstraints OK")
        except x509.extensions.ExtensionNotFound:
            if i > 0:
                steps.append(f"Certificate {i+1}: BasicConstraints missing for CA")
                return {'valid': False, 'error': 'BasicConstraints missing for CA', 'steps': steps}

        # Key Usage для CA
        try:
            ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
            if i > 0 and not ku.value.key_cert_sign:
                steps.append(f"✗ Certificate {i+1}: keyCertSign not set")
                return {'valid': False, 'error': 'CA certificate missing keyCertSign', 'steps': steps}
            steps.append(f"Certificate {i+1}: KeyUsage OK")
        except x509.extensions.ExtensionNotFound:
            pass

    # Проверка отзыва (если требуется)
    if check_revocation:
        steps.append("Checking revocation status...")
        issuer = chain[1] if len(chain) > 1 else trusted[0]
        try:
            status, details = check_revocation_status(leaf, issuer, ocsp_url=ocsp_url, crl_sources=crl_sources, logger=logger)
            if status != 'good':
                steps.append(f"Revocation check failed: {status} - {details}")
                return {'valid': False, 'error': f'Certificate revoked: {details}', 'steps': steps}
            steps.append("Revocation check passed (good)")
        except Exception as e:
            steps.append(f"Revocation check error: {e}")
            return {'valid': False, 'error': f'Revocation check error: {e}', 'steps': steps}

    steps.append("Certificate path validation successful")
    return {'valid': True, 'steps': steps}