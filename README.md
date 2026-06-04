## ✅ Чеклист выполнения Must-требований Sprint 5

| ID | Требование | Статус | Комментарий |
|----|------------|--------|-------------|
| **STR‑16** | Добавлены модули `ocsp.py`, `ocsp_responder.py` | ✅ | Файлы созданы, интегрированы в проект |
| **STR‑17** | `README.md` обновлён с инструкциями по OCSP | ✅ | Выполнено (при необходимости допишите) |
| **CLI‑22** | `ca issue-ocsp-cert` – выпуск сертификата OCSP responder | ✅ | Поддерживаются `--ca-cert`, `--ca-key`, `--ca-pass-file`, `--subject`, `--key-type`, `--key-size`, `--san`, `--out-dir`, `--validity-days` |
| | **Расширения сертификата:** | | |
| | BasicConstraints CA=FALSE, critical | ✅ | |
| | Key Usage digitalSignature, critical | ✅ | |
| | Extended Key Usage OCSPSigning (1.3.6.1.5.5.7.3.9) | ✅ | |
| | Subject Alternative Name (опционально) | ✅ | |
| **CLI‑23** | `ocsp serve` – запуск OCSP responder | ✅ | Параметры: `--host`, `--port`, `--db-path`, `--responder-cert`, `--responder-key`, `--ca-cert`, `--cache-ttl`, `--log-file` |
| **OCSP‑1** | Разбор OCSP‑запроса (POST, content-type `application/ocsp-request`) | ✅ | Используется `load_der_ocsp_request()`, проверка nonce |
| **OCSP‑2** | Формирование ответа: `good`, `revoked`, `unknown`; `producedAt`, `responderID`, `certStatus`, `thisUpdate` | ✅ | Реализовано через `OCSPResponseBuilder` |
| **OCSP‑3** | Статус из БД: `valid` → `good`, `revoked` → `revoked` с датой/причиной, отсутствует → `unknown` | ✅ | Функции `get_certificate_status` и `get_certificate_revocation_info` |
| **OCSP‑4** | Nonce: извлечение из запроса и подстановка в ответ | ✅ | Поддержка nonce для replay‑protection |
| **OCSP‑5** | Кодирование ответа в DER, content‑type `application/ocsp-response` | ✅ | `response.public_bytes(serialization.Encoding.DER)` |
| **OCSP‑8** | Логирование каждого OCSP‑запроса (IP, serial, статус, время обработки) | ✅ | Логируются все запросы в `INFO` |
| **OSC‑1** | Профиль OCSP signer certificate (CA=FALSE, KU digitalSignature, EKU OCSPSigning) | ✅ | Проверено в тесте `test_issue_ocsp_cert` |
| **OSC‑3** | Приватный ключ OCSP хранится **незашифрованным** (PEM, permissions 0o600) с предупреждением | ✅ | Функция `issue_ocsp_cert` сохраняет ключ без шифрования и выводит предупреждение |
| **DB‑8** | Идентификация issuer по хэшам имени и ключа | ✅ | Функция `compute_issuer_hashes` вычисляет и сравнивает с запросом |
| **LOG‑12** | OCSP‑запросы логируются | ✅ | Каждый запрос пишется в лог |
| **TEST‑28** | Проверка расширений OCSP‑сертификата | ✅ | Тест `test_issue_ocsp_cert` (PASSED) |
| **TEST‑29** | Жизненный цикл: good → revoked (должен быть с OpenSSL) | ⚠️ | Реализовано, но на Windows требует корректного OpenSSL; код готов |
| **TEST‑30** | Проверка revoked | ⚠️ | Реализовано, но зависит от OpenSSL |
| **TEST‑31** | Проверка unknown | ⚠️ | Реализовано, но зависит от OpenSSL |
| **TEST‑32** | Nonce тест | ⚠️ | Реализовано, но зависит от OpenSSL |

