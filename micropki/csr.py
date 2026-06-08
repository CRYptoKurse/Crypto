from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec

def create_csr(private_key, subject_dn, use_ca=False, pathlen=None):
    """Создаёт PKCS#10 CSR с опциональным расширением BasicConstraints (CA)"""
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(subject_dn)
    if use_ca:
        # Basic Constraints для CA (некритичное в CSR, по RFC разрешено)
        bc = x509.BasicConstraints(ca=True, path_length=pathlen)
        builder = builder.add_extension(bc, critical=False)
    csr = builder.sign(private_key, hashes.SHA256())
    return csr

def csr_to_pem(csr):
    return csr.public_bytes(serialization.Encoding.PEM)