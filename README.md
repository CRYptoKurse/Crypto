Спринт 6 (Валидация, клиент, CRL, OCSP fallback)
ID	Требование	Статус	Примечание
STR‑19	Модули validation.py, revocation_check.py, client.py	✅	Присутствуют

CLI‑25	client gen-csr	✅	Работает
CLI‑26	client request-cert	✅	Работает
CLI‑27	client validate	✅	Работает, выводит шаги
CLI‑28	client check-status	✅	Работает
CLI‑29	ca issue-cert --csr	✅	Работает
CLI‑30	Репозиторий endpoint /request-cert	✅	Работает
VAL‑1	Построение цепочки	✅	Работает
VAL‑2	Проверки подписи, срока, BasicConstraints, KeyUsage, pathLen	✅	Работает
VAL‑5	Структурированный результат	✅	Выводится
REV‑1	CRL проверка	✅	Работает

REV‑3	Логика приоритета OCSP → fallback CRL	✅	Работает
REV‑4	Извлечение OCSP URL из AIA	✅	Есть функция
REPO‑15	Endpoint /request-cert	✅	Работает
CA‑1	Поддержка CSR в issue-cert	✅	Работает
LOG‑16	Логирование API-запросов	✅	Есть
TEST‑38	Генерация CSR	✅	Проходит
TEST‑39	Запрос сертификата	✅	Проходит
TEST‑40	Валидация валидной цепочки	✅	Проходит
TEST‑41	Проверка expired (--validation-time)	❓	Не тестировалось
TEST‑43	CRL revoked	✅	Проходит (ручная проверка)

TEST‑46	Построение цепочки с недостающим intermediate	✅	Проходит
🧾 Все команды для запуска и проверки (одной строкой)
Подготовка окружения (один раз)
bash
python -m micropki.cli db init --db-path ./pki/micropki.db
echo rootsecret > root.pass && python -m micropki.cli ca init --subject "/CN=Test Root CA" --passphrase-file root.pass --out-dir ./pki --db-path ./pki/micropki.db --force
echo intersecret > inter.pass && copy inter.pass pki\
python -m micropki.cli ca issue-intermediate --root-cert ./pki/certs/ca.cert.pem --root-key ./pki/private/ca.key.pem --root-pass-file root.pass --subject "CN=Intermediate CA" --passphrase-file inter.pass --out-dir ./pki --db-path ./pki/micropki.db
Генерация CSR и сертификата
bash
python -m micropki.cli client gen-csr --subject "CN=myapp.example.com" --key-type rsa --key-size 2048 --san dns:myapp.example.com --san dns:api.example.com --out-key myapp.key.pem --out-csr myapp.csr.pem
Запуск репозитория (терминал 1)
bash
python -m micropki.cli repo serve --host 127.0.0.1 --port 8080 --db-path ./pki/micropki.db --cert-dir ./pki/certs
Получение сертификата (терминал 2)
bash
python -m micropki.cli client request-cert --csr myapp.csr.pem --template server --ca-url http://127.0.0.1:8080 --out-cert myapp.cert.pem
Выпуск OCSP-сертификата
bash
python -m micropki.cli ca issue-ocsp-cert --ca-cert ./pki/certs/intermediate.cert.pem --ca-key ./pki/private/intermediate.key.pem --ca-pass-file inter.pass --subject "CN=OCSP Responder" --key-type rsa --key-size 2048 --out-dir ./pki/certs
Запуск OCSP-responder (терминал 3)
bash
python -m micropki.cli ocsp serve --host 127.0.0.1 --port 8081 --db-path ./pki/micropki.db --responder-cert ./pki/certs/ocsp.cert.pem --responder-key ./pki/certs/ocsp.key.pem --ca-cert ./pki/certs/intermediate.cert.pem
Генерация CRL
bash
python -m micropki.cli ca gen-crl --ca intermediate --passphrase-file inter.pass --out-dir ./pki --db-path ./pki/micropki.db
Валидация цепочки (с OCSP и CRL)
bash
python -m micropki.cli client validate --cert myapp.cert.pem --untrusted ./pki/certs/intermediate.cert.pem --trusted ./pki/certs/ca.cert.pem --crl http://127.0.0.1:8080/crl?ca=intermediate --ocsp http://127.0.0.1:8081/ocsp --mode full
Проверка статуса (check-status)
bash
python -m micropki.cli client check-status --cert myapp.cert.pem --ca-cert ./pki/certs/intermediate.cert.pem --crl http://127.0.0.1:8080/crl?ca=intermediate --ocsp-url http://127.0.0.1:8081/ocsp
Отзыв сертификата и повторная проверка
bash
SERIAL=$(openssl x509 -in myapp.cert.pem -noout -serial | cut -d= -f2)
python -m micropki.cli ca revoke $SERIAL --reason keyCompromise --db-path ./pki/micropki.db
python -m micropki.cli ca gen-crl --ca intermediate --passphrase-file inter.pass --out-dir ./pki --db-path ./pki/micropki.db
python -m micropki.cli client validate --cert myapp.cert.pem --untrusted ./pki/certs/intermediate.cert.pem --trusted ./pki/certs/ca.cert.pem --crl http://127.0.0.1:8080/crl?ca=intermediate --ocsp http://127.0.0.1:8081/ocsp --mode full
