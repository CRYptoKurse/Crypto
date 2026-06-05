from cryptography.x509.ocsp import load_der_ocsp_request
import subprocess
import tempfile

with tempfile.TemporaryDirectory() as tmpdir:
    # Создаём тестовый сертификат
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                    '-keyout', f'{tmpdir}/key.pem', '-out', f'{tmpdir}/cert.pem',
                    '-days', '1', '-subj', '/CN=test'], capture_output=True)
    # Генерируем OCSP-запрос
    subprocess.run(['openssl', 'ocsp', '-issuer', f'{tmpdir}/cert.pem',
                    '-cert', f'{tmpdir}/cert.pem', '-reqout', f'{tmpdir}/req.der'],
                   capture_output=True)
    with open(f'{tmpdir}/req.der', 'rb') as f:
        data = f.read()
    ocsp_req = load_der_ocsp_request(data)
    print("Тип:", type(ocsp_req))
    print("Атрибуты:", [a for a in dir(ocsp_req) if not a.startswith('_')])
    if hasattr(ocsp_req, 'single_requests'):
        print("single_requests:", ocsp_req.single_requests)
    if hasattr(ocsp_req, 'serial_number'):
        print("serial_number:", ocsp_req.serial_number)