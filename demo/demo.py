#!/usr/bin/env python3
"""
MicroPKI Demo Script (Sprint 8) – полная автоматическая демонстрация с выводом на русском языке.
"""

import os
import sys
import time
import subprocess
import shutil
import socket
import threading
import requests
import sqlite3
from pathlib import Path

DEMO_DIR = Path("./demo_run")
PKI_DIR = DEMO_DIR / "pki"
ROOT_PASS_FILE = DEMO_DIR / "root.pass"
INTER_PASS_FILE = DEMO_DIR / "inter.pass"
DB_PATH = PKI_DIR / "micropki.db"
REPO_HOST = "127.0.0.1"
REPO_PORT = 8080
OCSP_HOST = "127.0.0.1"
OCSP_PORT = 8081

def run_cmd(cmd, check=True):
    """Запуск команды с выводом в консоль."""
    print(f"[ЗАПУСК] {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"ОШИБКА: {result.stderr}")
        sys.exit(1)
    return result

def wait_for_server(host, port, timeout=15):
    """Ожидание запуска сервера на указанном порту."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((host, port))
                return True
        except:
            time.sleep(0.5)
    return False

def demo_print(step, status="OK"):
    """Вывод статуса шага демонстрации на русском."""
    if status == "OK":
        print(f"\n>>> {step} ... УСПЕШНО")
    else:
        print(f"\n>>> {step} ... ОШИБКА ({status})")

def get_cert_status(db_path, serial_hex):
    """Получение статуса сертификата из БД."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT status FROM certificates WHERE serial_hex = ?", (serial_hex,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None

def main():
    print("=== Демонстрация MicroPKI (Sprint 8) ===\n")

    # Очистка предыдущего запуска
    if DEMO_DIR.exists():
        shutil.rmtree(DEMO_DIR)
    DEMO_DIR.mkdir(parents=True)
    (PKI_DIR / "certs").mkdir(parents=True)
    (PKI_DIR / "private").mkdir(parents=True)
    (PKI_DIR / "crl").mkdir(parents=True)

    # Создание файлов с паролями
    ROOT_PASS_FILE.write_text("rootpass")
    INTER_PASS_FILE.write_text("interpass")
    demo_print("Созданы файлы паролей")

    # 1. Инициализация базы данных
    run_cmd(["python", "-m", "micropki.cli", "db", "init", "--db-path", str(DB_PATH)])
    demo_print("Инициализация базы данных")

    # 2. Корневой УЦ
    run_cmd(["python", "-m", "micropki.cli", "ca", "init",
             "--subject", "/CN=Demo Root CA",
             "--passphrase-file", str(ROOT_PASS_FILE),
             "--out-dir", str(PKI_DIR),
             "--db-path", str(DB_PATH), "--force"])
    demo_print("Создание корневого центра сертификации (Root CA)")

    # 3. Промежуточный УЦ
    run_cmd(["python", "-m", "micropki.cli", "ca", "issue-intermediate",
             "--root-cert", str(PKI_DIR/"certs"/"ca.cert.pem"),
             "--root-key", str(PKI_DIR/"private"/"ca.key.pem"),
             "--root-pass-file", str(ROOT_PASS_FILE),
             "--subject", "CN=Demo Inter CA",
             "--passphrase-file", str(INTER_PASS_FILE),
             "--out-dir", str(PKI_DIR),
             "--db-path", str(DB_PATH)])
    demo_print("Создание промежуточного центра сертификации (Intermediate CA)")

    # 4. Серверный сертификат (для TLS)
    run_cmd(["python", "-m", "micropki.cli", "ca", "issue-cert",
             "--ca-cert", str(PKI_DIR/"certs"/"intermediate.cert.pem"),
             "--ca-key", str(PKI_DIR/"private"/"intermediate.key.pem"),
             "--ca-pass-file", str(INTER_PASS_FILE),
             "--template", "server",
             "--subject", "/CN=localhost",
             "--san", "dns:localhost",
             "--san", "ip:127.0.0.1",
             "--out-dir", str(PKI_DIR/"certs"),
             "--db-path", str(DB_PATH)])
    demo_print("Выпуск серверного сертификата (localhost с SAN)")

    # 5. Клиентский сертификат
    run_cmd(["python", "-m", "micropki.cli", "ca", "issue-cert",
             "--ca-cert", str(PKI_DIR/"certs"/"intermediate.cert.pem"),
             "--ca-key", str(PKI_DIR/"private"/"intermediate.key.pem"),
             "--ca-pass-file", str(INTER_PASS_FILE),
             "--template", "client",
             "--subject", "/CN=Demo Client",
             "--out-dir", str(PKI_DIR/"certs"),
             "--db-path", str(DB_PATH)])
    demo_print("Выпуск клиентского сертификата")

    # 6. Сертификат для OCSP-респондера
    run_cmd(["python", "-m", "micropki.cli", "ca", "issue-ocsp-cert",
             "--ca-cert", str(PKI_DIR/"certs"/"intermediate.cert.pem"),
             "--ca-key", str(PKI_DIR/"private"/"intermediate.key.pem"),
             "--ca-pass-file", str(INTER_PASS_FILE),
             "--subject", "/CN=OCSP Responder",
             "--out-dir", str(PKI_DIR/"certs")])
    demo_print("Выпуск сертификата OCSP-респондера")

    # 7. Запуск репозитория (фоновый поток)
    repo_thread = threading.Thread(
        target=lambda: run_cmd(["python", "-m", "micropki.cli", "repo", "serve",
                                "--host", REPO_HOST, "--port", str(REPO_PORT),
                                "--db-path", str(DB_PATH),
                                "--cert-dir", str(PKI_DIR/"certs"),
                                "--rate-limit", "2", "--rate-burst", "4"],
                               check=False),
        daemon=True
    )
    repo_thread.start()
    time.sleep(3)
    if not wait_for_server(REPO_HOST, REPO_PORT):
        demo_print("Запуск сервера репозитория", "FAIL")
        sys.exit(1)
    demo_print("Запуск сервера репозитория")

    # 8. Запуск OCSP-респондера (фоновый поток)
    ocsp_thread = threading.Thread(
        target=lambda: run_cmd(["python", "-m", "micropki.cli", "ocsp", "serve",
                                "--host", OCSP_HOST, "--port", str(OCSP_PORT),
                                "--db-path", str(DB_PATH),
                                "--responder-cert", str(PKI_DIR/"certs"/"ocsp.cert.pem"),
                                "--responder-key", str(PKI_DIR/"certs"/"ocsp.key.pem"),
                                "--ca-cert", str(PKI_DIR/"certs"/"intermediate.cert.pem"),
                                "--cache-ttl", "60"],
                               check=False),
        daemon=True
    )
    ocsp_thread.start()
    time.sleep(3)
    if not wait_for_server(OCSP_HOST, OCSP_PORT):
        demo_print("Запуск OCSP-респондера", "FAIL")
        sys.exit(1)
    demo_print("Запуск OCSP-респондера")

    # 9. TLS сервер (Python HTTPS с цепочкой сертификатов)
    server_cert = PKI_DIR/"certs"/"localhost.cert.pem"
    server_key = PKI_DIR/"certs"/"localhost.key.pem"
    inter_cert = PKI_DIR/"certs"/"intermediate.cert.pem"
    chain_file = DEMO_DIR / "chain.pem"
    chain_file.write_bytes(server_cert.read_bytes() + inter_cert.read_bytes())
    demo_print("Создание файла цепочки сертификатов (сервер + промежуточный)")

    def run_https_server():
        import ssl
        import http.server
        import socketserver
        handler = http.server.SimpleHTTPRequestHandler
        httpd = socketserver.TCPServer(("", 8443), handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(chain_file), keyfile=str(server_key))
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        httpd.serve_forever()

    tls_thread = threading.Thread(target=run_https_server, daemon=True)
    tls_thread.start()
    time.sleep(3)
    if not wait_for_server("127.0.0.1", 8443):
        demo_print("Запуск HTTPS-сервера", "FAIL")
    else:
        demo_print("Запуск HTTPS-сервера на порту 8443")
        s_client = subprocess.run(
            ["openssl", "s_client", "-connect", "127.0.0.1:8443",
             "-CAfile", str(PKI_DIR/"certs"/"ca.cert.pem"), "-verify_return_error"],
            input="", capture_output=True, text=True, timeout=5
        )
        if s_client.returncode == 0:
            demo_print("Проверка TLS-соединения с доверием к корневому сертификату")
        else:
            demo_print("Проверка TLS-соединения", f"FAIL (код {s_client.returncode})")

    # 10. Подпись кода (Code signing)
    run_cmd(["python", "-m", "micropki.cli", "ca", "issue-cert",
             "--ca-cert", str(PKI_DIR/"certs"/"intermediate.cert.pem"),
             "--ca-key", str(PKI_DIR/"private"/"intermediate.key.pem"),
             "--ca-pass-file", str(INTER_PASS_FILE),
             "--template", "code_signing",
             "--subject", "/CN=Code Signing Demo",
             "--out-dir", str(PKI_DIR/"certs"),
             "--db-path", str(DB_PATH)])
    demo_print("Выпуск сертификата для подписи кода")

    code_cert = PKI_DIR/"certs"/"Code_Signing_Demo.cert.pem"
    code_key = PKI_DIR/"certs"/"Code_Signing_Demo.key.pem"
    test_file = DEMO_DIR / "test.txt"
    test_file.write_text("Hello MicroPKI!")
    sig_file = DEMO_DIR / "test.txt.sig"
    demo_print("Создан тестовый файл test.txt")

    subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(code_key),
                    "-out", str(sig_file), str(test_file)], check=True)
    demo_print("Файл подписан (openssl dgst -sign)")

    pubkey = subprocess.run(["openssl", "x509", "-in", str(code_cert),
                             "-pubkey", "-noout"], capture_output=True, text=True, check=True).stdout
    pubkey_file = DEMO_DIR / "pubkey.pem"
    pubkey_file.write_text(pubkey)

    result = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(pubkey_file),
                             "-signature", str(sig_file), str(test_file)], capture_output=True, text=True)
    if "Verified OK" in result.stdout:
        demo_print("Проверка подписи (оригинальный файл)")
    else:
        demo_print("Проверка подписи", "FAIL (не удалось верифицировать)")

    # Проверка с изменённым файлом (должна быть ошибка)
    test_file.write_text("Tampered content")
    result_tampered = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(pubkey_file),
                                      "-signature", str(sig_file), str(test_file)], capture_output=True, text=True)
    if "Verification Failure" in result_tampered.stderr or result_tampered.returncode != 0:
        demo_print("Проверка подписи после модификации файла (ожидаемая ошибка)")
    else:
        demo_print("Проверка подписи после модификации", "FAIL (ошибка не обнаружена)")
    test_file.write_text("Hello MicroPKI!")  # восстановление

    # 11. Отзыв сертификата и проверка CRL
    cert_file = server_cert
    serial_out = subprocess.run(["openssl", "x509", "-in", str(cert_file), "-serial", "-noout"],
                                capture_output=True, text=True).stdout.strip()
    serial = serial_out.split('=')[1] if '=' in serial_out else serial_out
    run_cmd(["python", "-m", "micropki.cli", "ca", "revoke", serial,
             "--reason", "keyCompromise", "--db-path", str(DB_PATH)])
    demo_print(f"Отзыв серверного сертификата (серийный номер {serial})")

    run_cmd(["python", "-m", "micropki.cli", "ca", "gen-crl",
             "--ca", "intermediate", "--passphrase-file", str(INTER_PASS_FILE),
             "--out-dir", str(PKI_DIR), "--db-path", str(DB_PATH)])
    demo_print("Генерация CRL (списка отозванных сертификатов)")

    # Проверка статуса в БД
    status = get_cert_status(str(DB_PATH), serial)
    if status == "revoked":
        demo_print("Статус сертификата в базе данных: отозван")
    else:
        demo_print("Статус сертификата в базе данных", f"FAIL (статус {status})")

    # Проверка CRL через openssl
    crl_file = PKI_DIR / "crl" / "intermediate.crl.pem"
    crl_text = subprocess.run(["openssl", "crl", "-in", str(crl_file), "-text", "-noout"],
                              capture_output=True, text=True)
    serial_clean = serial.lstrip('0').lower()
    if serial_clean in crl_text.stdout.lower():
        demo_print("Проверка: серийный номер присутствует в CRL")
    else:
        demo_print("Проверка CRL", f"FAIL (серийный номер {serial} не найден в CRL)")

    # 12. Проверка целостности аудит-лога
    verify_audit = run_cmd(["python", "-m", "micropki.cli", "ca", "audit-verify",
                            "--audit-log", str(PKI_DIR/"audit"/"audit.log")], check=False)
    if verify_audit.returncode == 0:
        demo_print("Проверка целостности аудит-лога (хеш-цепочка)")
    else:
        demo_print("Проверка целостности аудит-лога", "FAIL")

    # 13. Политика безопасности: отклонение слабого ключа (1024 бита)
    weak_csr = DEMO_DIR / "weak.csr"
    subprocess.run(["openssl", "req", "-new", "-newkey", "rsa:1024", "-nodes",
                    "-keyout", str(DEMO_DIR/"weak.key"), "-out", str(weak_csr),
                    "-subj", "/CN=weak"], check=True)
    demo_print("Создан CSR с использованием слабого ключа RSA-1024")

    res = run_cmd(["python", "-m", "micropki.cli", "ca", "issue-cert",
                   "--ca-cert", str(PKI_DIR/"certs"/"intermediate.cert.pem"),
                   "--ca-key", str(PKI_DIR/"private"/"intermediate.key.pem"),
                   "--ca-pass-file", str(INTER_PASS_FILE),
                   "--template", "client", "--csr", str(weak_csr),
                   "--out-dir", str(PKI_DIR/"certs")], check=False)
    if res.returncode != 0:
        demo_print("Политика безопасности: запрос с ключом 1024 бита отклонён")
    else:
        demo_print("Политика безопасности", "FAIL (слабый ключ был принят)")

    demo_print("ДЕМОНСТРАЦИЯ УСПЕШНО ЗАВЕРШЕНА")

if __name__ == "__main__":
    main()