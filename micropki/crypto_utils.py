import os
import re
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
from cryptography import x509
from cryptography.x509.oid import NameOID

def generate_rsa_key(key_size=4096):
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)

def generate_ecc_key(curve_size=384):
    if curve_size != 384:
        raise ValueError("ECC key size must be 384 (P-384)")
    from cryptography.hazmat.primitives.asymmetric import ec
    # Совместимость с разными версиями cryptography
    try:
        # Попытка прямого использования (современные версии)
        return ec.generate_private_key(ec.SECP384R1)
    except TypeError:
        # Если не сработало, используем старый синтаксис
        return ec.generate_private_key(ec.SECP384R1())
def encrypt_private_key(private_key, passphrase):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=BestAvailableEncryption(passphrase)
    )

def parse_dn_string(dn_str):
    """Parse DN in slash or comma format -> list of (oid, value)"""
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
        # comma format: CN=...,O=...
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
    }
    name_attrs = []
    for k, v in attrs:
        if k in oid_map:
            name_attrs.append(x509.NameAttribute(oid_map[k], v))
    return x509.Name(name_attrs)

def compute_ski(public_key):
    return x509.SubjectKeyIdentifier.from_public_key(public_key)