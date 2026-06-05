import os
import re
import ipaddress
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography import x509
from cryptography.x509.oid import NameOID

# ---------- Key generation ----------
def generate_rsa_key(key_size=4096):
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)

def generate_ecc_key(curve_size=384):
    if curve_size == 256:
        curve = ec.SECP256R1()
    elif curve_size == 384:
        curve = ec.SECP384R1()
    else:
        raise ValueError("ECC key size must be 256 or 384")
    return ec.generate_private_key(curve)

# ---------- Key encryption ----------
def encrypt_private_key(private_key, passphrase):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
    )

# ---------- Load keys/certificates ----------
def load_encrypted_private_key(key_path, passphrase):
    with open(key_path, 'rb') as f:
        key_data = f.read()
    return serialization.load_pem_private_key(key_data, password=passphrase)

def load_certificate(cert_path):
    with open(cert_path, 'rb') as f:
        return x509.load_pem_x509_certificate(f.read())

# ---------- DN parsing ----------
def parse_dn_string(dn_str):
    attrs = []
    dn_str = dn_str.strip()
    if dn_str.startswith('/'):
        parts = dn_str[1:].split('/')
        for part in parts:
            if '=' not in part:
                continue
            k, v = part.split('=', 1)
            attrs.append((k.upper(), v))
    else:
        for part in dn_str.split(','):
            if '=' not in part:
                continue
            k, v = part.split('=', 1)
            attrs.append((k.upper().strip(), v.strip()))
    oid_map = {
        'CN': NameOID.COMMON_NAME,
        'O': NameOID.ORGANIZATION_NAME,
        'OU': NameOID.ORGANIZATIONAL_UNIT_NAME,
        'C': NameOID.COUNTRY_NAME,
        'ST': NameOID.STATE_OR_PROVINCE_NAME,
        'L': NameOID.LOCALITY_NAME,
        'EMAIL': NameOID.EMAIL_ADDRESS,
    }
    name_attrs = []
    for k, v in attrs:
        if k in oid_map:
            name_attrs.append(x509.NameAttribute(oid_map[k], v))
    return x509.Name(name_attrs)

# ---------- SAN parsing ----------
def parse_san_string(san_str):
    if ':' not in san_str:
        raise ValueError(f"Invalid SAN format: {san_str}")
    typ, val = san_str.split(':', 1)
    typ = typ.lower()
    if typ == 'dns':
        return x509.DNSName(val)
    elif typ == 'ip':
        return x509.IPAddress(ipaddress.ip_address(val))
    elif typ == 'email':
        return x509.RFC822Name(val)
    elif typ == 'uri':
        return x509.UniformResourceIdentifier(val)
    else:
        raise ValueError(f"Unsupported SAN type: {typ}")

# ---------- Universal signature verification ----------
def verify_signature(public_key, signature, data, algorithm=None):
    if algorithm is None:
        algorithm = hashes.SHA256()
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(signature, data, PKCS1v15(), algorithm)
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature, data, ec.ECDSA(algorithm))
    else:
        raise TypeError(f"Unsupported key type: {type(public_key)}")


# ---------- Subject Key Identifier helper ----------
def compute_ski(public_key):
    """Compute and return an x509.SubjectKeyIdentifier for a public key.

    Returns the SubjectKeyIdentifier object, or None on error.
    """
    try:
        return x509.SubjectKeyIdentifier.from_public_key(public_key)
    except Exception:
        return None