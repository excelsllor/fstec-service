# Приложение 8: Формат JSON-схем для обмена с внешними API

ТЗ: п. 8 «Приложения (формируются на этапе проектирования)», п. 2.4 «Security Posture Analyzer».

Документ определяет JSON-контракты обмена:
1. **NVD API v2** (запрос уязвимости по CVE).
2. **BDU ФСТЭК** (bdu.fstec.ru).
3. **CMDB Заказчика** (внутренняя БД инвентаризации, через API по ТЗ 4.3).
4. Внутренний нормализованный формат уязвимости (единый для сервисов).

---

## 1. NVD API v2

### 1.1 Запрос
```
GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-1234
Хедер (рекомендуется для повышения квоты): X-Api-Key: <ключ>   (ТЗ не требует, но RBAC)
```

### 1.2 Ответ (маппинг используемых полей)
```jsonc
{
  "resultsPerPage": 1,
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2026-1234",
        "sourceIdentifier": "cve@mitre.org",
        "published": "2026-01-15T09:00:00.000Z",
        "lastModified": "2026-02-01T10:00:00.000Z",
        "descriptions": [
          {"lang": "en", "value": "Heap overflow in OpenSSL <=1.1.1k"}
        ],
        "metrics": {
          "cvssMetricV31": [
            {
              "source": "nvd@nist.gov",
              "type": "Primary",
              "cvssData": {
                "version": "3.1",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "baseScore": 9.8,
                "baseSeverity": "CRITICAL"
              }
            }
          ]
        },
        "weaknesses": [
          {"description": [{"value": "CWE-122"}]}
        ],
        "configurations": [
          {
            "nodes": [
              {
                "cpeMatch": [
                  {
                    "vulnerable": true,
                    "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
                    "versionEndIncluding": "1.1.1k"
                  }
                ]
              }
            ]
          }
        ]
      }
    }
  ]
}
```

### 1.3 Нормализация (внутренний формат уязвимости)
Результат приводится к единой схеме (раздел 4) с полями:
`cve_id, cvss_score, cvss_version, cvss_vector, severity, cpe[], affected_range, fixed_version, patch_url, references`.

---

## 2. BDU ФСТЭК (bdu.fstec.ru)

### 2.1 Запрос (из мозга критического кейса приёмки 7.1)
```
GET https://bdu.fstec.ru/vul?unid=BDU:2026-XXXX
или POST на поисковый эндпоинт с параметром BDU-ID
```
Фактический публичный API bdu.fstec.ru ограничен; при недоступности структурированного
API используется HTML-страница описания уязвимости с последующим парсингом в нормализованную схему.

### 2.2 Ответ (нормализуемый контент)
```jsonc
{
  "bdu_id": "BDU:2026-XXXX",
  "title": "Уязвимость ...",
  "description": "Описание уязвимости (рус.)",
  "published": "2026-05-20",
  "severity": "Высокий",
  "cvss": {
    "base_score": 8.8,
    "vector": "CVSS:3.1/...",
    "severity_ru": "Высокий"
  },
  "cve_id": "CVE-2026-1234",
  "cpe": ["cpe:2.3:a:openssl:openssl:1.1.1k:..."],
  "affected_products": ["OpenSSL 1.1.1k"],
  "references": [
    {"source": "vendor", "url": "https://www.openssl.org/news/security.html"},
    {"source": "cve", "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-1234"}
  ]
}
```

### 2.3 Нормализация
Маппинг BDU → внутренняя схема (раздел 4). Источник фиксируется в `source: "bdu"`.

---

## 3. CMDB Заказчика (внутренняя БД инвентаризации)

Подключение — **только через API** (ТЗ 4.3). Мок-реализация для dev — `cmdb-mock` (отдаёт статические примеры).

### 3.1 Конфигурация коннектора (env/конфиг)
```
CMDB_ENDPOINT   = https://<cmdb-host>/api/inventory/software
CMDB_AUTH_TYPE  = bearer | basic | none
CMDB_TOKEN      = <masked>
CMDB_TIMEOUT_S  = 5
```

### 3.2 Запрос (SQL/REST возвращает перечень установленного ПО и версий)
```
GET {CMDB_ENDPOINT}?query=software&filter=version  (пагинация постранично)
```

### 3.3 Ответ
```jsonc
{
  "items": [
    {
      "host": "srv-mail.example.local",
      "product": "OpenSSL",
      "vendor": "OpenSSL Project",
      "version": "1.1.1k",
      "cpe": "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*:*",
      "os": "RED OS 8",
      "last_seen": "2026-09-01"
    },
    {
      "host": "srv-web.example.local",
      "product": "TrueConf Server",
      "vendor": "TrueConf",
      "version": "7.0",
      "cpe": null,
      "os": "RED OS 7",
      "last_seen": "2026-09-01"
    }
  ],
  "page": 1,
  "total": 2
}
```

### 3.4 Требование к CMDB (для внедрения, ТЗ 8 / КП)
- Проекция инвентаризации с точными версиями ПО (или совместимый API).
- Поля: host, product, vendor, version, cpe (опц.), os, last_seen.
- Данные соответствуют «перечню установленного ПО и его точных версий» (ТЗ 2.4).
- Доступ только по API (ТЗ 4.3), TLS 1.3.

---

## 4. Внутренний нормализованный формат уязвимости (общий)

Используется в Kafka-событии `security.assessed` и в reporting-сервисе.

```jsonc
{
  "source": "nvd",                    // "nvd" | "bdu" | "manual"
  "cve_id": "CVE-2026-1234",
  "bdu_id": "BDU:2026-XXXX",
  "title": "Heap overflow in OpenSSL",
  "description": "Полное описание",
  "severity": "critical",             // critical|high|medium|low|unknown
  "cvss": {
    "score": 9.8,
    "version": "3.1",
    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  },
  "cpe_products": [
    {
      "cpe": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
      "name": "OpenSSL",
      "vendor": "OpenSSL Project"
    }
  ],
  "affected_range": {"version_end_including": "1.1.1k", "note": null},
  "fixed_version": "1.1.2",
  "patch_url": "https://www.openssl.org/news/security.html",
  "references": [{"source": "vendor", "url": "..."}],
  "cmdb": {
    "match": true,
    "installed": {"product": "OpenSSL", "version": "1.1.1k", "host": "srv-mail.example.local"},
    "needs_update": true
  },
  "recommendation": "Обновить OpenSSL с 1.1.1k до 1.1.2"
}
```

---

## 5. Примечания
- Все внешние вызовы — TLS 1.3 (ТЗ 4.3), ретраи до 3 с экспоненциальной задержкой (1с,2с,4с), тайм-аут ≤15с суммарно (ТЗ KPI 1.4: проверка уязвимости ≤15с).
- Ответы NVD/BDU кэшируются в Redis (TTL ≥ 24ч) для ускорения повторных проверок.
- При полной недоступности внешних API: уведомление оператора + перевод в ручной режим (ТЗ 4.2).