
### 📋 Чеклист выполнения Must-требований Sprint 4

| ID | Требование | Статус |
|----|------------|--------|
| STR‑13 | Новые модули `crl.py`, `revocation.py` | ✅ |
| STR‑14 | README обновлён (revoke, gen-crl, CRL endpoints) | ✅ |
| STR‑15 | Директория `crl/` создаётся | ✅ |
| CLI‑18 | `ca revoke <serial> --reason --force` | ✅ |
| CLI‑19 | `ca gen-crl --ca root/intermediate --next-update --out-file` | ✅ |
| CLI‑21 | Старые команды не изменены | ✅ |
| CRL‑1 | CRL v2 с полями issuer, thisUpdate, nextUpdate, список serial | ✅ |
| CRL‑3 | При revoke обновляется БД (status, revocation_reason, revocation_date) | ✅ |
| CRL‑4 | CRL подписывается ключом CA, сохраняется в PEM | ✅ |
| CRL‑5 | CRL сохраняется в `crl/<ca>.crl.pem` | ✅ |
| CRL‑7 | Все 10 причин отзыва поддерживаются | ✅ |
| REPO‑9 | `GET /crl?ca=root|intermediate` возвращает CRL с MIME `application/pkix-crl` | ✅ |
| REPO‑12 | Логирование CRL запросов | ✅ |
| DB‑5 | Поля `status`, `revocation_reason`, `revocation_date` используются | ✅ |
| LOG‑9 | Логирование успешного/неудачного отзыва | ✅ |
| LOG‑10 | Логирование генерации CRL | ✅ |
| TEST‑21 | Полный жизненный цикл: выпуск → отзыв → CRL → проверка | ✅ |
| TEST‑22 | Проверка CRL через OpenSSL | ✅ |
| TEST‑26 | CRL distribution через HTTP | ✅ |

