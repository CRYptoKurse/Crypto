import pytest
from micropki.crypto_utils import generate_rsa_key, generate_ecc_key, parse_dn_string, compute_ski
from cryptography.hazmat.primitives.asymmetric import rsa, ec

def test_rsa_generation():
    key = generate_rsa_key(4096)
    assert isinstance(key, rsa.RSAPrivateKey)
    assert key.key_size == 4096

def test_ecc_generation():
    key = generate_ecc_key(384)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    # curve name check
    assert key.curve.name == 'secp384r1'

def test_parse_dn_slash():
    dn = parse_dn_string("/CN=Test CA/O=Org/C=US")
    # we can simply check it creates a Name with attributes
    assert len(dn) >= 3

def test_parse_dn_comma():
    dn = parse_dn_string("CN=Test CA,O=Org,C=US")
    assert len(dn) >= 3