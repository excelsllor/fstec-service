# Секреты и автозапуск

## Где что лежит

- `/home/raport/fstec-service/services/.env.public` — несекретная конфигурация (порты, флаги, модели).
- `/etc/fstec/secrets.cred` — секреты, зашифрованные `systemd-creds` ключом хоста (0600 root).
- `/run/fstec/compose.env` — расшифрованный env в tmpfs, 0640 root:raport; создаётся при старте.
- `.env` — симлинк на `/run/fstec/compose.env`; plaintext `.env` на диске больше нет.

В зашифрованный файл входят: `FSTEC_SECRET_KEY`, `POSTGRES_PASSWORD`, `REDIS_PASSWORD`,
`GLPI_PASSWORD`, `GLPI_CLIENT_SECRET`, `KAFKA_SASL_PASSWORD`, `KAFKA_INTER_BROKER_PASSWORD`.

## Автозапуск

`fstec-compose.service` включён в `multi-user.target`:

```bash
sudo systemctl start fstec-compose.service
sudo systemctl status fstec-compose.service
```

Скрипт `/usr/local/sbin/fstec-up.sh` расшифровывает секреты, собирает `/run/fstec/compose.env`
и запускает `docker compose -f docker-compose.yml -f docker-compose.t4.yml` (Kafka/Postgres/Redis,
затем приложение и TLS-прокси, затем nginx).

## Изменить секрет

```bash
sudo systemd-creds decrypt --name=fstec-secrets /etc/fstec/secrets.cred /tmp/fstec-secrets.env
sudoedit /tmp/fstec-secrets.env
sudo systemd-creds encrypt --name=fstec-secrets --with-key=host /tmp/fstec-secrets.env /etc/fstec/secrets.cred
sudo shred -u /tmp/fstec-secrets.env
sudo /usr/local/sbin/fstec-up.sh --prepare-only
sudo systemctl restart fstec-compose.service
```

Перед изменением пароля БД/Redis/Kafka проверьте, что новый пароль уже применён в соответствующем
сервисе, иначе контейнеры не подключатся.

## Ограничения

- TPM на сервере отсутствует, поэтому используется host-key (`/var/lib/systemd/credential.secret`).
  Это защищает от случайного копирования `.cred`/`.env`, но не от полного образа диска с root-ключом.
  Для защиты от кражи диска нужен TPM/шифрование диска.
- Секреты видны в переменных окружения процессов и в `docker inspect`; это неизбежно для текущей схемы.
- `bootstrap_password.txt` удалён из volume; пароль добавлен в `secrets.cred` как `FSTEC_BOOTSTRAP_PASSWORD`
  (приложение его не читает, только восстановление входа root-пользователем).
