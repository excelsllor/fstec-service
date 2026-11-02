import os
import secrets
import warnings
from pathlib import Path

# Профиль развёртывания: dev | prod. В prod небезопасные дефолты запрещены (fail-fast).
FSTEC_ENV = os.environ.get("FSTEC_ENV", "dev").strip().lower()
IS_PROD = FSTEC_ENV in ("prod", "production")

_BASE = Path(__file__).resolve().parent.parent
_DATA = Path(os.environ.get("FSTEC_DATA_DIR", _BASE / "data"))

DATA_DIR = _DATA
UPLOAD_DIR = Path(os.environ.get("FSTEC_UPLOAD_DIR", DATA_DIR / "uploads"))
REPORT_DIR = Path(os.environ.get("FSTEC_REPORT_DIR", DATA_DIR / "reports"))
RAW_DIR = Path(os.environ.get("FSTEC_RAW_DIR", DATA_DIR / "raw"))
DB_PATH = DATA_DIR / "fstec_services.db"

for d in (UPLOAD_DIR, REPORT_DIR, RAW_DIR, DATA_DIR):
    d.mkdir(parents=True, exist_ok=True)

DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{DB_PATH}")

# Событийная шина: memory (тесты/один процесс) | sqlite (локальный мульти-процесс) | kafka (prod)
EVENT_BUS = os.environ.get("FSTEC_EVENT_BUS", "memory").lower()
BUS_POLL_S = float(os.environ.get("FSTEC_BUS_POLL_S", "0.25"))
# Сколько сообщений топика шины обрабатывается одновременно (этап 4). 1 = прежнее
# строго последовательное поведение; >1 включает перекрытие обработки (например,
# ожидание vLLM не блокирует разбор следующего письма). Порядок внутри одного
# сообщения (несколько подписчиков) сохраняется, курсор SQLite двигается только
# после завершения всей пачки.
BUS_CONCURRENCY = max(1, int(os.environ.get("FSTEC_BUS_CONCURRENCY", "1")))
# Размер пачки, читаемой за один опрос шины.
BUS_BATCH = max(1, int(os.environ.get("FSTEC_BUS_BATCH", "100")))

KAFKA_BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
# Число партиций топика: максимальная параллельность консьюмера на топик.
KAFKA_TOPIC_PARTITIONS = max(1, int(os.environ.get("FSTEC_KAFKA_PARTITIONS", "1")))
KAFKA_REPLICATION_FACTOR = max(1, int(os.environ.get("FSTEC_KAFKA_REPLICATION", "1")))
KAFKA_CONSUMER_GROUP = os.environ.get("FSTEC_KAFKA_GROUP", "fstec")
KAFKA_SECURITY_PROTOCOL = os.environ.get("KAFKA_SECURITY_PROTOCOL", "PLAINTEXT").upper()
KAFKA_SASL_MECHANISM = os.environ.get("KAFKA_SASL_MECHANISM", "PLAIN").upper()
KAFKA_SASL_USERNAME = os.environ.get("KAFKA_SASL_USERNAME", "")
KAFKA_SASL_PASSWORD = os.environ.get("KAFKA_SASL_PASSWORD", "")
KAFKA_SSL_CA_FILE = os.environ.get("KAFKA_SSL_CA_FILE", "")

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

# Auth
# Секрет подписи JWT. Известные дефолты запрещены: в prod требуется уникальный
# секрет >= 32 символов (иначе RuntimeError), в dev — генерируется эфемерный.
_INSECURE_SECRETS = {"dev-insecure-change-me", "change-me", "changeme", "secret", "fstec"}


def _resolve_secret_key() -> str:
    value = os.environ.get("FSTEC_SECRET_KEY", "").strip()
    if value and value not in _INSECURE_SECRETS:
        if IS_PROD and len(value) < 32:
            raise RuntimeError(
                "FSTEC_SECRET_KEY слишком короткий для prod (нужно >= 32 символов). "
                "Сгенерируйте: python -c \"import secrets; print(secrets.token_urlsafe(48))\"")
        if len(value) < 32:
            warnings.warn(
                "FSTEC_SECRET_KEY короче 32 символов — не используйте это значение в prod.",
                RuntimeWarning, stacklevel=2)
        return value
    if IS_PROD:
        raise RuntimeError(
            "FSTEC_SECRET_KEY не задан или равен известному дефолту. "
            "Задайте уникальный секрет: python -c \"import secrets; print(secrets.token_urlsafe(48))\"")
    warnings.warn(
        "FSTEC_SECRET_KEY не задан — сгенерирован эфемерный dev-секрет "
        "(токены не переживут перезапуск). На боевом сервере задайте FSTEC_SECRET_KEY.",
        RuntimeWarning, stacklevel=2)
    return secrets.token_urlsafe(48)


SECRET_KEY = _resolve_secret_key()
ALGORITHM = "HS256"
JWT_AUDIENCE = "fstec-service"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("FSTEC_TOKEN_MINUTES", "120"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.environ.get("FSTEC_REFRESH_DAYS", "30"))

# CORS: список разрешённых origin через запятую. В prod по умолчанию пусто
# (UI и API отдаются с одного origin через nginx); в dev — локальный Vite.
_default_cors = "" if IS_PROD else "http://localhost:5173,http://127.0.0.1:5173"
CORS_ORIGINS = [o.strip() for o in os.environ.get("FSTEC_CORS_ORIGINS", _default_cors).split(",") if o.strip()]

# Отключать /api/docs и /api/openapi.json (в prod обязательно).
DISABLE_DOCS = os.environ.get("FSTEC_DISABLE_DOCS", "1" if IS_PROD else "0").lower() in ("1", "true", "yes")

BOOTSTRAP_USERNAME = "admin"
BOOTSTRAP_FULL_NAME = "Администратор"
MIN_PASSWORD_LENGTH = 6
# Пароль bootstrap-администратора: если задан, используется он и не пишется в лог/файл.
BOOTSTRAP_PASSWORD = os.environ.get("FSTEC_BOOTSTRAP_PASSWORD", "").strip()

# Загрузка (ТЗ 2.1)
ALLOWED_EXTENSIONS = {".pdf", ".doc", ".docx", ".odt", ".xlsx", ".rtf", ".txt"}
MAX_FILE_SIZE = 20 * 1024 * 1024          # ТЗ 2.1: 20 МБ
MAX_FILES_PER_BATCH = 10                  # ТЗ 2.1: до 10 файлов

# OCR (ТЗ 2.2)
OCR_ENABLED = os.environ.get("FSTEC_OCR_ENABLED", "true").lower() in ("1", "true", "yes")
OCR_LANG = os.environ.get("FSTEC_OCR_LANG", "rus+eng")
OCR_MIN_TEXT = int(os.environ.get("FSTEC_OCR_MIN_TEXT", "20"))
# Провайдер: auto (paddle → tesseract) | paddle | tesseract
OCR_ENGINE = os.environ.get("FSTEC_OCR_ENGINE", "tesseract").lower()
# Устройство распознавания: gpu (CUDA) | cpu (в dev и <=4 ГБ видеопамяти)
OCR_DEVICE = os.environ.get("FSTEC_OCR_DEVICE", "cpu").lower()
OCR_GPU_IDS = [int(x) for x in os.environ.get("FSTEC_OCR_GPU_IDS", "0").split(",") if x.strip().isdigit()]

# LLM (ТЗ 2.3)
LLM_PROVIDER = os.environ.get("FSTEC_LLM_PROVIDER", "heuristic")  # heuristic | vllm
VLLM_BASE_URL = os.environ.get("VLLM_BASE_URL", "http://localhost:8000/v1")
VLLM_MODEL = os.environ.get("VLLM_MODEL", "Qwen3.5-9B")
VLLM_CA_FILE = os.environ.get("VLLM_CA_FILE", "")
LLM_TIMEOUT_S = float(os.environ.get("FSTEC_LLM_TIMEOUT_S", "10"))
VLLM_MAX_TOKENS = int(os.environ.get("FSTEC_VLLM_MAX_TOKENS", "900"))
PLAN_MAX_TOKENS = max(800, int(os.environ.get("FSTEC_PLAN_MAX_TOKENS", "4000")))
VLLM_TEMPERATURE = float(os.environ.get("FSTEC_VLLM_TEMPERATURE", "0.1"))
VLLM_TOP_P = float(os.environ.get("FSTEC_VLLM_TOP_P", "0.9"))
# Прогрев/keepalive vLLM: первый запрос после старта не должен быть холодным.
LLM_WARMUP_ENABLED = os.environ.get("FSTEC_LLM_WARMUP_ENABLED", "1").lower() in ("1", "true", "yes")
LLM_WARMUP_INTERVAL_S = max(30.0, float(os.environ.get("FSTEC_LLM_WARMUP_INTERVAL_S", "300")))
LLM_WARMUP_TIMEOUT_S = max(5.0, float(os.environ.get("FSTEC_LLM_WARMUP_TIMEOUT_S", "60")))
# Штрафы за повторы (борьба с зацикливанием Qwen3 при низкой temperature).
VLLM_REPETITION_PENALTY = float(os.environ.get("FSTEC_VLLM_REPETITION_PENALTY", "1.08"))
VLLM_FREQUENCY_PENALTY = float(os.environ.get("FSTEC_VLLM_FREQUENCY_PENALTY", "0.3"))
# LLM-классификация типа письма (3 класса: hacker|vulnerability|other; compromise -> hacker).
VLLM_CLASSIFY_MAX_CHARS = int(os.environ.get("FSTEC_VLLM_CLASSIFY_MAX_CHARS", "6000"))
# LLM-извлечение IoC (гибрид с regex): вкл/выкл, лимит текста и бюджет генерации.
VLLM_EXTRACT_IO = os.environ.get("FSTEC_LLM_EXTRACT", "1").lower() in ("1", "true", "yes")
VLLM_EXTRACT_MAX_CHARS = int(os.environ.get("FSTEC_LLM_EXTRACT_MAX_CHARS", "12000"))
VLLM_EXTRACT_MAX_TOKENS = int(os.environ.get("FSTEC_LLM_EXTRACT_MAX_TOKENS", "2000"))
# Режим «размышлений» Qwen3: enable_thinking в chat_template_kwargs (reasoning_content отдельно).
# Thinking потребляет много токенов — при включении бюджеты ответа поднимаются
# до VLLM_THINK_MAX_TOKENS, а контекст для analyze ужимается (бюджет = ctx - completion).
LLM_ENABLE_THINKING = os.environ.get("FSTEC_LLM_ENABLE_THINKING", "0").lower() in ("1", "true", "yes")
# Объединённый analyze+extract одним вызовом LLM. По умолчанию ВЫКЛ: замеры
# (e_bench) показали, что на крупных письмах (9-148) merged уходит в runaway-
# генерацию с обрывом схемы и ретраем (~320 с против ~17 с у двух отдельных
# вызовов). Два раздельных вызова (analyze + extract_iocs) быстрее ~6x.
LLM_MERGED_ANALYZE = os.environ.get("FSTEC_LLM_MERGED_ANALYZE", "0").lower() in ("1", "true", "yes")
LLM_MERGED_VULN = os.environ.get("FSTEC_LLM_MERGED_VULN", "0").lower() in ("1", "true", "yes")
# Включать извлечение IoC в merged-ответ LLM. Выкл -> IoC берутся только
# детерминированным regex-проходом (быстро, меньше gen-токенов -> ниже латентность).
# Внешний сервис-классификатор IoC (EuroBERT token-classification). Если задан,
# извлечение IoC уходит из 8B на него (быстро, CPU) -> LLM_MERGED_IOCS выкл.
IOC_CLASSIFIER_URL = os.environ.get(
    "FSTEC_IOC_CLASSIFIER_URL", "http://host.docker.internal:8002/extract").strip()
LLM_MERGED_IOCS = os.environ.get("FSTEC_LLM_MERGED_IOCS", "1").lower() in ("1", "true", "yes")
BERT_PRIMARY_IOCS = os.environ.get("FSTEC_BERT_PRIMARY_IOCS", "0").lower() in ("1", "true", "yes")
DEDUPE_PROMPT_LINES = os.environ.get("FSTEC_DEDUPE_PROMPT_LINES", "0").lower() in ("1", "true", "yes")
# Полностью отключить guided_json (промптовый JSON). Нужно для экспериментов со
# спекулятивным декодированием: guided+spec несовместимы на vLLM 0.8.5.
LLM_DISABLE_GUIDED = os.environ.get("FSTEC_LLM_DISABLE_GUIDED", "0").lower() in ("1", "true", "yes")
LLM_GUIDED_FALLBACK = os.environ.get("FSTEC_LLM_GUIDED_FALLBACK", "0").lower() in ("1", "true", "yes")
VLLM_THINK_MAX_TOKENS = int(os.environ.get("FSTEC_VLLM_THINK_MAX_TOKENS", "5000"))
# Лимит токенов на «размышления» (thinking_budget у Qwen3): предупреждает бесконечный reasoning
# и гарантирует переход к финальному JSON. Без лимита модель сжигает весь бюджет на reasoning
# и возвращает пустой content (в интерфейсе llama-server context_length учитывается отдельно).
VLLM_THINK_BUDGET = int(os.environ.get("FSTEC_VLLM_THINK_BUDGET", "2000"))
# Этап 4: сколько запросов к vLLM держим одновременно и какого размера пул соединений.
# Раньше вызов был синхронным urllib и блокировал event loop на всё время генерации,
# поэтому воркер обрабатывал строго одно письмо. Значения по умолчанию совпадают с
# измеренным рабочим режимом vLLM на T4 (concurrency 10-12); поднимать выше VRAM не позволяет.
LLM_CONCURRENCY_CAP = max(1, int(os.environ.get("FSTEC_LLM_CONCURRENCY_CAP", "12")))
LLM_MAX_CONCURRENCY = min(LLM_CONCURRENCY_CAP, max(1, int(os.environ.get("FSTEC_LLM_CONCURRENCY", "8"))))
LLM_POOL_MAX_CONNECTIONS = max(1, int(os.environ.get("FSTEC_LLM_POOL_MAX", "16")))
LLM_POOL_KEEPALIVE = max(1, int(os.environ.get("FSTEC_LLM_POOL_KEEPALIVE", "8")))
# Контекст llama-server -c 16384: на ЛЕВЫЙ промпт (после _fit_context) остаётся
# 16384 - VLLM_MAX_TOKENS = 15484 токенов — достаточно для писем целиком (макс ~12665).
CHUNK_MAX_TOKENS = int(os.environ.get("FSTEC_CHUNK_MAX_TOKENS", "15400"))
SUMMARY_MAX_CHARS = 500

# RuBERT-классификация (быстрый предиктор категорий, GPU под vLLM)
# deepvk/USER2-base — RuModernBERT (8192 токенов контекста) как замена ruBERT (512).
# RUBERT_MAX_TOKENS=2048 — измеренный оптимум: полный 8192 разбавляет mean-pooling
# длинными блок-списками и в 6 раз медленнее (11/12 на обоих, 2.0с против 12.7с/письмо).
RUBERT_MODEL = os.environ.get("FSTEC_RUBERT_MODEL", "deepvk/USER2-base")
RUBERT_DEVICE = os.environ.get("FSTEC_RUBERT_DEVICE", "cpu").lower()
RUBERT_CONFIDENCE = float(os.environ.get("FSTEC_RUBERT_CONFIDENCE", "0.35"))
RUBERT_MAX_TOKENS = int(os.environ.get("FSTEC_RUBERT_MAX_TOKENS", "2048"))
RUBERT_AUTHORITATIVE = os.environ.get("FSTEC_RUBERT_AUTHORITATIVE", "0").lower() in ("1", "true", "yes")
ANALYSIS_CACHE_ENABLED = os.environ.get("FSTEC_ANALYSIS_CACHE", "0").lower() in ("1", "true", "yes")
ANALYSIS_CACHE_TTL_S = int(os.environ.get("FSTEC_ANALYSIS_CACHE_TTL_S", "86400"))
LLM_NO_SUMMARY = os.environ.get("FSTEC_LLM_NO_SUMMARY", "0").lower() in ("1", "true", "yes")
LLM_SKIP_ANALYZE = os.environ.get("FSTEC_LLM_SKIP_ANALYZE", "0").lower() in ("1", "true", "yes")
LLM_PROMPT_DIGEST = os.environ.get("FSTEC_LLM_PROMPT_DIGEST", "0").lower() in ("1", "true", "yes")
LLM_PROMPT_DIGEST_CHARS = int(os.environ.get("FSTEC_LLM_PROMPT_DIGEST_CHARS", "6000"))
# Вариант A: массивы IoC собирает детерминированный extractor/BERT, а 8B
# возвращает только classification/summary/entities. Это убирает из completion
# длинный список IoC, который модель иначе копирует из письма.
LLM_LOCAL_IOC_ARRAYS = os.environ.get("FSTEC_LLM_LOCAL_IOC_ARRAYS", "0").lower() in ("1", "true", "yes")

# Security (ТЗ 2.4)
SECURITY_MODE = os.environ.get("FSTEC_SECURITY_MODE", "live")  # mock (оффлайн/dev) | live (внешние БД)
SECURITY_RETRY_MAX = int(os.environ.get("FSTEC_SECURITY_RETRY_MAX", "3"))
# Этап 4: параллельные запросы во внешние БД по уязвимостям одного письма и размер
# пула соединений httpx. Раньше каждая уязвимость обогащалась строго последовательно.
SECURITY_LOOKUP_CONCURRENCY = max(1, int(os.environ.get("FSTEC_SECURITY_CONCURRENCY", "8")))
SECURITY_POOL_MAX_CONNECTIONS = max(1, int(os.environ.get("FSTEC_SECURITY_POOL_MAX", "16")))
# Пул соединений SQLAlchemy: при параллельной обработке писем дефолтных 5 соединений
# не хватает, запросы начинают упираться в таймаут очереди пула.
DB_POOL_SIZE = max(1, int(os.environ.get("FSTEC_DB_POOL_SIZE", "10")))
DB_MAX_OVERFLOW = max(0, int(os.environ.get("FSTEC_DB_MAX_OVERFLOW", "20")))
SECURITY_CACHE_TTL_S = int(os.environ.get("FSTEC_SECURITY_CACHE_TTL_S", str(24 * 60 * 60)))
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
NVD_API_BASE = os.environ.get("NVD_API_BASE", "https://services.nvd.nist.gov")
BDU_API_BASE = os.environ.get("BDU_API_BASE", "https://bdu.fstec.ru")
# Включать fallback с verify=False при сбое TLS у BDU (только для dev/тест-стендов; в проде оставить 0)
BDU_TLS_INSECURE_FALLBACK = os.environ.get("FSTEC_BDU_INSECURE_FALLBACK", "0") == "1"
# bdu.fstec.ru отдаёт 403 на запросы с User-Agent клиента httpx ("python-httpx/..."),
# поэтому нужен браузерный UA. Без него enrichment BDU не работает вовсе.
BDU_USER_AGENT = os.environ.get(
    "FSTEC_BDU_USER_AGENT",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36",
)
# CMDB Заказчика (Приложение 8): провайдер mock (dev, тот же протокол) | rest
CMDB_PROVIDER = os.environ.get("CMDB_PROVIDER", "mock")
CMDB_ENDPOINT = os.environ.get("CMDB_ENDPOINT", "http://localhost:9000/api/inventory/software")
CMDB_AUTH_TYPE = os.environ.get("CMDB_AUTH_TYPE", "none")  # none | bearer | basic
# Токен CMDB: основной env — CMDB_AUTH_TOKEN (как в docker-compose/.env.example),
# CMDB_TOKEN оставлен для обратной совместимости.
CMDB_TOKEN = os.environ.get("CMDB_AUTH_TOKEN", os.environ.get("CMDB_TOKEN", ""))
CMDB_TIMEOUT_S = float(os.environ.get("CMDB_TIMEOUT_S", "5"))

# GLPI как CMDB Заказчика (CMDB_PROVIDER=glpi): инвентарь ПО Software/SoftwareVersion.
# v1 — legacy REST apirest.php (Basic или user_token), v2 — HL API api.php (OAuth2 password grant).
GLPI_URL = os.environ.get("GLPI_URL", "").rstrip("/")
GLPI_API = os.environ.get("GLPI_API", "v1").strip().lower()          # v1 | v2
GLPI_AUTH = os.environ.get("GLPI_AUTH", "basic").strip().lower()    # v1: basic | user_token
GLPI_USERNAME = os.environ.get("GLPI_USERNAME", "")
GLPI_PASSWORD = os.environ.get("GLPI_PASSWORD", "")
GLPI_USER_TOKEN = os.environ.get("GLPI_USER_TOKEN", "")
GLPI_CLIENT_ID = os.environ.get("GLPI_CLIENT_ID", "")
GLPI_CLIENT_SECRET = os.environ.get("GLPI_CLIENT_SECRET", "")
GLPI_SCOPE = os.environ.get("GLPI_SCOPE", "api")
GLPI_APP_TOKEN = os.environ.get("GLPI_APP_TOKEN", "")
GLPI_TIMEOUT_S = float(os.environ.get("GLPI_TIMEOUT_S", "8"))
GLPI_MAX_SOFTWARE = max(1, int(os.environ.get("GLPI_MAX_SOFTWARE", "5")))
GLPI_MAX_VERSIONS = max(1, int(os.environ.get("GLPI_MAX_VERSIONS", "25")))
GLPI_INVENTORY_CACHE_TTL_S = max(0.0, float(os.environ.get("GLPI_INVENTORY_CACHE_TTL_S", "300")))
GLPI_INVENTORY_CACHE_MAX = max(1, int(os.environ.get("GLPI_INVENTORY_CACHE_MAX", "512")))
PARSE_CACHE_TTL_S = max(0.0, float(os.environ.get("FSTEC_PARSE_CACHE_TTL_S", "300")))
PARSE_CACHE_MAX = max(1, int(os.environ.get("FSTEC_PARSE_CACHE_MAX", "128")))
GLPI_DB_HOST = os.environ.get("GLPI_DB_HOST", "").strip()
GLPI_DB_PORT = int(os.environ.get("GLPI_DB_PORT", "3306"))
GLPI_DB_NAME = os.environ.get("GLPI_DB_NAME", "").strip()
GLPI_DB_USER = os.environ.get("GLPI_DB_USER", "").strip()
GLPI_DB_PASSWORD = os.environ.get("GLPI_DB_PASSWORD", "")
GLPI_DB_CHARSET = os.environ.get("GLPI_DB_CHARSET", "utf8mb4").strip() or "utf8mb4"
GLPI_DB_PREFIX = os.environ.get("GLPI_DB_PREFIX", "glpi_").strip() or "glpi_"

# Порт gateway
GATEWAY_PORT = int(os.environ.get("FSTEC_GATEWAY_PORT", "8666"))

# Отчётность (ТЗ 2.5)
ORG_NAME = os.environ.get("FSTEC_ORG_NAME", "Правительства Липецкой области")