from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from typing import List, Tuple

MAX_VALIDITY = {
    'root': 3650,
    'intermediate': 1825,
    'end_entity': 365
}
MIN_RSA_KEY_SIZE = {
    'root': 4096,
    'intermediate': 3072,
    'end_entity': 2048
}
MIN_ECC_KEY_SIZE = {
    'root': 384,
    'intermediate': 384,
    'end_entity': 256
}
ALLOWED_SAN_TYPES = {
    'server': {'dns', 'ip'},
    'client': {'dns', 'email', 'uri'},
    'code_signing': {'dns', 'uri'}
}
REJECT_WILDCARD = True   # запрещаем wildcard

def check_key_size(public_key, cert_type: str) -> Tuple[bool, str]:
    if isinstance(public_key, rsa.RSAPublicKey):
        size = public_key.key_size
        min_size = MIN_RSA_KEY_SIZE.get(cert_type, MIN_RSA_KEY_SIZE['end_entity'])
        if size < min_size:
            return False, f"RSA key size {size} < {min_size} for {cert_type}"
        return True, ""
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        if public_key.curve.name == 'secp256r1':
            size = 256
        elif public_key.curve.name == 'secp384r1':
            size = 384
        else:
            return False, f"Unsupported ECC curve {public_key.curve.name}"
        min_size = MIN_ECC_KEY_SIZE.get(cert_type, MIN_ECC_KEY_SIZE['end_entity'])
        if size < min_size:
            return False, f"ECC key size {size} < {min_size} for {cert_type}"
        return True, ""
    return False, f"Unsupported key type {type(public_key)}"

def check_validity(days: int, cert_type: str) -> Tuple[bool, str]:
    max_days = MAX_VALIDITY.get(cert_type, MAX_VALIDITY['end_entity'])
    if days > max_days:
        return False, f"Validity {days} days exceeds maximum {max_days} for {cert_type}"
    return True, ""

def check_san_list(san_list: List[x509.GeneralName], template: str) -> Tuple[bool, str]:
    allowed = ALLOWED_SAN_TYPES.get(template, set())
    for san in san_list:
        if isinstance(san, x509.DNSName):
            if 'dns' not in allowed:
                return False, f"DNS name not allowed for template {template}"
            if REJECT_WILDCARD and san.value.startswith('*.'):
                return False, f"Wildcard DNS {san.value} not allowed"
        elif isinstance(san, x509.IPAddress):
            if 'ip' not in allowed:
                return False, f"IP address not allowed for template {template}"
        elif isinstance(san, x509.RFC822Name):
            if 'email' not in allowed:
                return False, f"Email not allowed for template {template}"
        elif isinstance(san, x509.UniformResourceIdentifier):
            if 'uri' not in allowed:
                return False, f"URI not allowed for template {template}"
        else:
            return False, f"Unsupported SAN type {type(san)}"
    return True, ""

def check_signature_algorithm(signature_algorithm) -> Tuple[bool, str]:
    """Проверяет, что алгоритм подписи не SHA-1"""
    alg_str = ""
    if hasattr(signature_algorithm, 'name'):
        alg_str = signature_algorithm.name.lower()
    elif hasattr(signature_algorithm, 'dotted_string'):
        alg_str = signature_algorithm.dotted_string
    else:
        alg_str = str(signature_algorithm).lower()

    if 'sha1' in alg_str:
        return False, f"Signature algorithm {alg_str} uses SHA-1, rejected"
    return True, ""

def enforce_pathlen(pathlen: int, is_ca: bool, cert_type: str) -> Tuple[bool, str]:
    if not is_ca:
        return True, ""
    if cert_type == 'intermediate' and pathlen != 0:
        return False, "Intermediate CA must have path length 0 (cannot issue sub-CAs)"
    return True, ""