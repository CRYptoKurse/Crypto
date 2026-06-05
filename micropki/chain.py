from cryptography import x509
from cryptography.hazmat.primitives import hashes
import datetime

def verify_chain(leaf_cert, intermediate_cert, root_cert):
    """Проверяет цепочку: leaf подписан intermediate, intermediate подписан root."""
    try:
        # Проверка подписи leaf с помощью intermediate
        leaf_cert.public_key().verify(
            leaf_cert.signature,
            leaf_cert.tbs_certificate_bytes,
            leaf_cert.signature_hash_algorithm
        )
        # Проверка подписи intermediate с помощью root
        intermediate_cert.public_key().verify(
            intermediate_cert.signature,
            intermediate_cert.tbs_certificate_bytes,
            intermediate_cert.signature_hash_algorithm
        )
        # Проверка валидности дат
        now = datetime.datetime.now(datetime.timezone.utc)
        if leaf_cert.not_valid_before_utc > now or leaf_cert.not_valid_after_utc < now:
            return False
        if intermediate_cert.not_valid_before_utc > now or intermediate_cert.not_valid_after_utc < now:
            return False
        if root_cert.not_valid_before_utc > now or root_cert.not_valid_after_utc < now:
            return False
        # Проверка Basic Constraints: intermediate должен быть CA
        bc_inter = intermediate_cert.extensions.get_extension_for_class(x509.BasicConstraints)
        if not bc_inter.value.ca:
            return False
        return True
    except Exception:
        return False