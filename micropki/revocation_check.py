import os
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.ocsp import OCSPRequestBuilder, load_der_ocsp_response, OCSPCertStatus, OCSPResponseStatus
from cryptography.x509.oid import ExtensionOID
import requests
from .crypto_utils import verify_signature

def extract_ocsp_url(cert):
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
        for desc in aia.value:
            if desc.access_method == x509.AuthorityInformationAccessOID.OCSP:
                return desc.access_location.value
    except x509.extensions.ExtensionNotFound:
        pass
    return None

def extract_crl_urls(cert):
    urls = []
    try:
        cdp = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
        for point in cdp.value:
            for name in point.full_name:
                if isinstance(name, x509.UniformResourceIdentifier):
                    urls.append(name.value)
    except x509.extensions.ExtensionNotFound:
        pass
    return urls

def fetch_crl(url, logger=None):
    try:
        if url.startswith('http://') or url.startswith('https://'):
            session = requests.Session()
            session.trust_env = False
            resp = session.get(url, timeout=10)
            resp.raise_for_status()
            crl_data = resp.content
        else:
            with open(url, 'rb') as f:
                crl_data = f.read()
        try:
            crl = x509.load_pem_x509_crl(crl_data)
        except:
            crl = x509.load_der_x509_crl(crl_data)
        return crl
    except Exception as e:
        if logger:
            logger.error(f"Failed to fetch CRL from {url}: {e}")
        return None

def check_crl(cert, issuer, crl_sources, logger=None):
    serial_hex = format(cert.serial_number, 'x').upper()
    for source in crl_sources:
        crl = fetch_crl(source, logger)
        if crl is None:
            continue
        # Проверка подписи CRL
        try:
            verify_signature(issuer.public_key(), crl.signature, crl.tbs_certlist_bytes, crl.signature_hash_algorithm)
        except Exception as e:
            if logger:
                logger.warning(f"CRL signature verification failed for {source}: {e}")
            continue
        now = datetime.now(timezone.utc)
        # Some cryptography versions provide timezone-aware next_update (next_update_utc),
        # others return a naive datetime. Normalize to timezone-aware UTC for comparison.
        next_update = None
        if hasattr(crl, 'next_update_utc') and getattr(crl, 'next_update_utc') is not None:
            next_update = crl.next_update_utc
        else:
            try:
                nu = crl.next_update
                if nu is not None and nu.tzinfo is None:
                    nu = nu.replace(tzinfo=timezone.utc)
                next_update = nu
            except Exception:
                next_update = None
        if next_update and next_update < now:
            if logger:
                logger.warning(f"CRL expired (nextUpdate {next_update})")
        for revoked in crl:
            if format(revoked.serial_number, 'x').upper() == serial_hex:
                reason = None
                try:
                    for ext in revoked.extensions:
                        if ext.oid == ExtensionOID.CRL_REASON:
                            reason = ext.value
                            break
                except:
                    pass
                return ('revoked', f'revoked at {revoked.revocation_date}, reason: {reason}')
    return ('good', 'Serial not found in CRL')

def check_ocsp(cert, issuer, ocsp_url, logger=None):
    if not ocsp_url:
        return ('unknown', 'No OCSP URL provided')
    builder = OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer, hashes.SHA1())
    request = builder.build()
    request_der = request.public_bytes(serialization.Encoding.DER)
    try:
        session = requests.Session()
        session.trust_env = False
        resp = session.post(ocsp_url, data=request_der,
                            headers={'Content-Type': 'application/ocsp-request'},
                            timeout=10)
        resp.raise_for_status()
        ocsp_response = load_der_ocsp_response(resp.content)
        if ocsp_response.response_status != OCSPResponseStatus.SUCCESSFUL:
            return ('unknown', f'OCSP response status {ocsp_response.response_status}')
        # Проверяем certificate_status
        try:
            status = ocsp_response.certificate_status
        except ValueError:
            # Может быть несколько сертификатов? Берём первый
            status = ocsp_response.certificate_status
        if status == OCSPCertStatus.GOOD:
            return ('good', None)
        elif status == OCSPCertStatus.REVOKED:
            rev_time = ocsp_response.revocation_time_utc
            return ('revoked', f'revoked at {rev_time}')
        else:
            return ('unknown', 'OCSP response unknown')
    except Exception as e:
        if logger:
            logger.error(f"OCSP request failed: {e}")
        return ('unknown', str(e))
def check_revocation_status(cert, issuer, ocsp_url=None, crl_sources=None, logger=None):
    # OCSP first
    if ocsp_url is None:
        ocsp_url = extract_ocsp_url(cert)
    if ocsp_url:
        if logger:
            logger.info(f"Attempting OCSP check at {ocsp_url}")
        status, details = check_ocsp(cert, issuer, ocsp_url, logger)
        if status in ('good', 'revoked'):
            if logger:
                logger.info(f"OCSP result: {status}")
            return (status, details)
        if logger:
            logger.warning(f"OCSP failed ({details}), falling back to CRL")

    # Fallback to CRL
    if crl_sources is None:
        crl_sources = extract_crl_urls(cert)
    if crl_sources:
        if logger:
            logger.info(f"Attempting CRL check from {crl_sources}")
        status, details = check_crl(cert, issuer, crl_sources, logger)
        if status != 'unknown':
            if logger:
                logger.info(f"CRL result: {status}")
            return (status, details)

    if logger:
        logger.error("Both OCSP and CRL checks failed")
    return ('unknown', 'Unable to determine revocation status')