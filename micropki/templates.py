from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.hazmat.primitives import hashes

def apply_template(cert_builder, template, san_list=None):
    """
    Применяет шаблон server/client/code_signing к CertificateBuilder.
    Возвращает обновлённый builder и список требований к SAN.
    """
    if template == 'server':
        # Key Usage
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(digital_signature=True, key_encipherment=True,
                          content_commitment=False, data_encipherment=False,
                          key_agreement=False, key_cert_sign=False,
                          crl_sign=False, encipher_only=False, decipher_only=False),
            critical=True
        )
        # Extended Key Usage
        cert_builder = cert_builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False
        )
        # Basic Constraints CA=False
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        san_required = True  # хотя бы один DNS или IP
    elif template == 'client':
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(digital_signature=True, key_agreement=False,
                          content_commitment=False, data_encipherment=False,
                          key_encipherment=False, key_cert_sign=False,
                          crl_sign=False, encipher_only=False, decipher_only=False),
            critical=True
        )
        cert_builder = cert_builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False
        )
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        san_required = False  # не обязателен, но рекомендуется
    elif template == 'code_signing':
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(digital_signature=True,
                          content_commitment=False, data_encipherment=False,
                          key_encipherment=False, key_agreement=False,
                          key_cert_sign=False, crl_sign=False,
                          encipher_only=False, decipher_only=False),
            critical=True
        )
        cert_builder = cert_builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
            critical=False
        )
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        san_required = False
    else:
        raise ValueError(f"Unknown template: {template}")

    # Добавляем SAN, если есть
    if san_list:
        cert_builder = cert_builder.add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False
        )
    return cert_builder, san_required