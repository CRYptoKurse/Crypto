

### Общие сведения

MicroPKI — это PKI-система на Python с использованием `cryptography`. Реализованы: иерархия CA, выпуск сертификатов по шаблонам, CRL, OCSP, клиентские утилиты, аудит с цепочкой целостности, политики безопасности, чёрный список ключей, прозрачность.

---

## Установка и запуск

```bash
pip install -e .
```

Все команды вызываются через `python -m micropki.cli <команда>` или после установки через `micropki`.

---

## CLI команды 

### База данных

- `db init --db-path <path>` — создаёт схему SQLite (таблицы `certificates`, `crl_metadata`, `compromised_keys`).

### Управление CA

- `ca init` — создаёт самоподписанный Root CA.  
  Параметры: `--subject`, `--key-type {rsa,ecc}`, `--key-size`, `--passphrase-file`, `--out-dir`, `--validity-days`, `--force`, `--db-path`.
- `ca issue-intermediate` — создаёт Intermediate CA (CSR → подпись корнем).  
  Добавляет `--root-cert`, `--root-key`, `--root-pass-file`, `--pathlen`.
- `ca issue-cert` — выпускает сертификат конечного устройства.  
  Поддерживает `--csr` для внешних запросов. Шаблоны: `server`, `client`, `code_signing`.  
  Остальные параметры: `--ca-cert`, `--ca-key`, `--ca-pass-file`, `--subject`, `--san`, `--out-dir`, `--validity-days`, `--db-path`.
- `ca revoke <serial>` — отзыв сертификата.  
  `--reason` (10 вариантов), `--db-path`.
- `ca gen-crl` — генерация CRL для root или intermediate.  
  `--ca {root,intermediate}`, `--passphrase-file`, `--out-dir`, `--next-update`, `--db-path`.
- `ca list-certs` — вывод списка сертификатов.  
  `--status {valid,revoked,expired}`, `--format {table,json,csv}`, `--db-path`.
- `ca show-cert <serial>` — вывод PEM сертификата.
- `ca issue-ocsp-cert` — выпуск сертификата для OCSP-респондера.  
  Параметры: `--ca-cert`, `--ca-key`, `--ca-pass-file`, `--subject`, `--key-type`, `--key-size`, `--out-dir`.

### Клиентские команды

- `client gen-csr` — генерация пары ключей (незашифрованной) и CSR.  
  `--subject`, `--key-type`, `--key-size`, `--san`, `--out-key`, `--out-csr`.
- `client request-cert` — отправка CSR на `/request-cert` репозитория.  
  `--csr`, `--template`, `--ca-url`, `--api-key` (опционально), `--out-cert`.
- `client validate` — полная валидация цепочки (построение, подписи, сроки, BasicConstraints, KeyUsage, pathLen, опционально отзыв).  
  `--cert`, `--untrusted`, `--trusted`, `--crl`, `--ocsp`, `--mode {chain,full}`, `--validation-time`.
- `client check-status` — проверка статуса отзыва (OCSP → CRL fallback).  
  `--cert`, `--ca-cert`, `--crl`, `--ocsp-url`.

### Репозиторий и OCSP серверы

- `repo serve` — HTTP сервер для распространения сертификатов и CRL, а также приёма CSR.  
  Параметры: `--host`, `--port`, `--db-path`, `--cert-dir`, `--rate-limit`, `--rate-burst`, `--log-file`.  
  Эндпоинты:  
  - `GET /certificate/<serial>`  
  - `GET /ca/root` и `/ca/intermediate`  
  - `GET /crl?ca=...`  
  - `POST /request-cert?template=...` (тело – PEM CSR)
- `ocsp serve` — OCSP-респондер.  
  Параметры: `--host`, `--port`, `--db-path`, `--responder-cert`, `--responder-key`, `--ca-cert`, `--cache-ttl`, `--rate-limit`, `--rate-burst`.

### Аудит и прозрачность

- `ca audit-query` — извлечение записей аудит-лога. Фильтры: `--from`, `--to`, `--level`, `--operation`, `--serial`, `--format`.
- `ca audit-verify` — проверка целостности аудит-лога (хеш-цепочка).  
  Параметры: `--audit-log`, `--chain-file`.
- `ca compromise --cert <файл> --reason <reason>` — пометить публичный ключ как скомпрометированный (вносится в чёрный список).  
  При последующих выпусках ключ будет отклонён.

---

## Основные модули и их назначение

| Модуль | Назначение |
|--------|------------|
| `cli.py` | Разбор аргументов, диспетчеризация команд |
| `ca.py` | Создание Root/Intermediate CA, выпуск сертификатов (с поддержкой CSR) |
| `client.py` | Генерация CSR, запрос сертификата, валидация, проверка статуса |
| `validation.py` | Построение цепочки, проверка подписей, сроков, расширений |
| `revocation_check.py` | Проверка статуса через OCSP (AIA) и CRL (CDP) с fallback |
| `crl.py` | Генерация CRLv2 |
| `ocsp.py`, `ocsp_responder.py` | Выпуск OCSP-сертификата и OCSP-респондер |
| `database.py` | SQLite: таблицы certificates, crl_metadata, compromised_keys |
| `policy.py` | Политики: размеры ключей, сроки, разрешённые SAN, запрет wildcard/SHA-1 |
| `audit.py` | Аудит-логгер с хеш-цепочкой (NDJSON) |
| `transparency.py` | Журнал прозрачности (CT log) |
| `ratelimit.py` | Token bucket для HTTP серверов |
| `crypto_utils.py` | Генерация ключей, шифрование, парсинг DN/SAN, универсальная проверка подписи |
| `templates.py` | Применение шаблонов server/client/code_signing |
| `serial.py` | Уникальные серийные номера (timestamp + CSPRNG) |

---

## Примеры использования (коротко)

```bash
# Инициализация PKI
micropki db init
micropki ca init --subject "/CN=Root CA" --passphrase-file root.pass
micropki ca issue-intermediate --root-cert pki/certs/ca.cert.pem --root-key pki/private/ca.key.pem --root-pass-file root.pass --subject "CN=Inter CA" --passphrase-file inter.pass

# Выпуск серверного сертификата
micropki ca issue-cert --ca-cert pki/certs/intermediate.cert.pem --ca-key pki/private/intermediate.key.pem --ca-pass-file inter.pass --template server --subject "/CN=example.com" --san dns:example.com

# Отзыв и CRL
micropki ca revoke <serial> --reason keyCompromise
micropki ca gen-crl --ca intermediate --passphrase-file inter.pass

# Проверка цепочки с отзывом
micropki client validate --cert server.cert.pem --untrusted intermediate.cert.pem --trusted ca.cert.pem --crl intermediate.crl.pem --mode full

# Запуск репозитория
micropki repo serve --host 0.0.0.0 --port 8080 --rate-limit 10

# Запрос сертификата через API (генерация CSR)
micropki client gen-csr --subject "CN=app" --out-csr app.csr
micropki client request-cert --csr app.csr --template server --ca-url http://localhost:8080 --out-cert app.cert
```

---

## Логирование и аудит

- Обычное логирование (INFO/ERROR) пишется в stderr или в файл `--log-file`.
- Аудит-лог: `./pki/audit/audit.log` (NDJSON с хеш-цепочкой). Целостность проверяется через `ca audit-verify`.
- Журнал прозрачности: `./pki/audit/ct.log` (JSON-строки с информацией о каждом выпущенном сертификате).

---

## Зависимости

- Python ≥3.8
- `cryptography` ≥3.0
- `Flask` ≥2.0
- `requests` ≥2.25
- `pytest` (для тестов)


