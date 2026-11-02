import json
import logging
from pathlib import Path
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker, declarative_base
from shared.config import (DATABASE_URL, DATA_DIR, DB_MAX_OVERFLOW, DB_POOL_SIZE)

logger = logging.getLogger(__name__)

_is_sqlite = DATABASE_URL.startswith("sqlite")

_kwargs = {"connect_args": {"check_same_thread": False, "timeout": 30}} if _is_sqlite else {}
# Этап 4: обработчики держат сессию в том числе во время ожидания vLLM, поэтому
# соединений нужно не меньше, чем максимальная конкурентность воркера. Иначе
# запросы встают в очередь пула и падают по таймауту. Для файловой SQLite
# SQLAlchemy 2.0 уже использует QueuePool.
_kwargs["pool_size"] = DB_POOL_SIZE
_kwargs["max_overflow"] = DB_MAX_OVERFLOW
engine = create_engine(DATABASE_URL, **_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


if _is_sqlite:
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db(create_all: bool = True):
    from shared import models  # noqa: F401  (регистрация ORM-схемы в Base.metadata)
    if _is_sqlite:
        _migrate_sqlite()
    else:
        _migrate_postgres()
    if create_all:
        Base.metadata.create_all(bind=engine)
    if _is_sqlite:
        _enable_foreign_keys()
    _seed_defaults()


def _migrate_postgres():
    """Лёгкие миграции PostgreSQL (create_all не меняет существующие колонки)."""
    try:
        with engine.connect() as conn:
            row = conn.execute(text(
                "SELECT data_type FROM information_schema.columns "
                "WHERE table_name='vulnerabilities' AND column_name='affected_range'"
            )).fetchone()
            if row and row[0] not in ("text", "character varying"):
                conn.execute(text("ALTER TABLE vulnerabilities ALTER COLUMN affected_range TYPE TEXT"))
                conn.commit()
                logger.info("PostgreSQL migration: vulnerabilities.affected_range -> TEXT")
            elif row and row[0] == "character varying":
                conn.execute(text("ALTER TABLE vulnerabilities ALTER COLUMN affected_range TYPE TEXT"))
                conn.commit()
                logger.info("PostgreSQL migration: vulnerabilities.affected_range widened to TEXT")
            for col, typ in (("cmdb_error", "TEXT"), ("cvss_version", "VARCHAR(20)")):
                exists = conn.execute(text(
                    "SELECT 1 FROM information_schema.columns WHERE table_name='vulnerabilities' "
                    "AND column_name=:c"), {"c": col}).fetchone()
                if not exists:
                    conn.execute(text(f"ALTER TABLE vulnerabilities ADD COLUMN {col} {typ}"))
                    conn.commit()
                    logger.info("PostgreSQL migration: vulnerabilities.%s added", col)
    except Exception as e:
        logger.error("PostgreSQL migration failed: %s", e)


def _migrate_sqlite():
    """Лёгкие миграции существующих БД SQLite (create_all не меняет таблицы)."""
    _run_id_tables = [
        "documents", "attachments", "threats", "vulnerabilities", "iocs",
        "entities", "summaries", "sla_events", "reports",
        "generated_responses", "measure_candidates",
    ]
    try:
        with engine.connect() as conn:
            cols = {r[1] for r in conn.execute(text("PRAGMA table_info(generated_responses)"))}
            if cols and "plan_json" not in cols:
                conn.execute(text("ALTER TABLE generated_responses ADD COLUMN plan_json TEXT DEFAULT ''"))
            for t in _run_id_tables:
                tcols = {r[1] for r in conn.execute(text(f"PRAGMA table_info({t})"))}
                if tcols and "run_id" not in tcols:
                    conn.execute(text(f"ALTER TABLE {t} ADD COLUMN run_id INTEGER"))
            vcols = {r[1] for r in conn.execute(text("PRAGMA table_info(vulnerabilities)"))}
            if vcols and "cvss_version" not in vcols:
                conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN cvss_version VARCHAR(20) DEFAULT ''"))
            if vcols and "cmdb_error" not in vcols:
                conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN cmdb_error TEXT DEFAULT ''"))
            conn.commit()
    except Exception as e:
        logger.error("SQLite migration failed: %s", e)


def _enable_foreign_keys():
    try:
        with engine.connect() as conn:
            conn.execute(text("PRAGMA foreign_keys=ON"))
    except Exception as e:
        logger.error("PRAGMA foreign_keys failed: %s", e)


def _seed_defaults():
    """Базовые справочники: типы угроз и шаблоны действий (по данным монолита)."""
    from shared.models import ThreatType, MeasureTemplate, VulnActionTemplate
    db = SessionLocal()
    try:
        if db.query(ThreatType).count() == 0:
            for name, key, desc in [
                ("Фишинговая рассылка", "phishing", "Фишинговые рассылки электронных писем"),
                ("Целевая компьютерная атака", "malware_attack", "Атаки с применением вредоносного ПО"),
                ("Эксплуатация уязвимости", "vulnerability", "Эксплуатация уязвимостей ПО (BDU/CVE)"),
                ("Компрометация веб-сайта", "compromise", "Компрометация веб-сайта разработчика ПО"),
                ("Атака ClickFix", "clickfix", "Атаки с использованием метода ClickFix"),
            ]:
                db.add(ThreatType(name=name, key=key, description=desc))
            db.commit()

        if db.query(MeasureTemplate).count() == 0:
            types = {t.key: t.id for t in db.query(ThreatType).all()}
            for text in [
                "на уровне сетевых средств защиты информации обеспечено ограничение обращений к указанным адресам;",
                "произведена настройка правил системы мониторинга событий информационной безопасности согласно рекомендациям.",
            ]:
                for key in ("phishing", "malware_attack", "compromise", "clickfix", "vulnerability"):
                    db.add(MeasureTemplate(name=f"Базовая мера ({key})", threat_type_id=types[key],
                                           content=text, is_default=True))
            db.commit()

        if db.query(VulnActionTemplate).count() == 0:
            for name, action, content, is_default in [
                ("Обновление ПО", "update", "Ведутся работы по обновлению программного обеспечения «{software}» до неуязвимой версии.", True),
                ("Компенсирующие меры", "compensate", "Применены компенсирующие меры для программного обеспечения «{software}».", False),
                ("ПО не используется", "skip", "Программное обеспечение «{software}» не используется.", False),
            ]:
                db.add(VulnActionTemplate(name=name, action_type=action, content=content, is_default=is_default))
            db.commit()
    except Exception as e:
        logger.error("Seed defaults failed: %s", e)
        db.rollback()
    finally:
        db.close()
    _seed_reply_resources()


def _seed_reply_resources():
    """Шаблоны ответа, intro-фрагменты и библиотека мер (из data/generator/*.json)."""
    from shared.models import Measure, IntroFragment, ReplyTemplate
    base = Path(__file__).resolve().parent.parent / "data" / "generator"

    def _load(name: str) -> list[dict]:
        f = base / name
        if not f.exists():
            logger.warning("Resource file not found: %s", f)
            return []
        try:
            return json.loads(f.read_text(encoding="utf-8"))
        except Exception as e:
            logger.error("Bad resource json %s: %s", f, e)
            return []

    db = SessionLocal()
    try:
        if db.query(ReplyTemplate).count() == 0:
            for t in _load("reply_templates.json"):
                if not t.get("skeleton"):
                    continue
                db.add(ReplyTemplate(key=t["key"], letter_type=t.get("letter_type", ""),
                                     skeleton=t["skeleton"], is_default=True))
        if db.query(IntroFragment).count() == 0:
            for fr in _load("intro_fragments.json"):
                db.add(IntroFragment(key=fr["key"], label=fr.get("label", ""),
                                     template=fr["template"], applies_to=fr.get("applies_to", ""),
                                     is_default=True))
        measures_seed = _load("measures_library.json")
        if db.query(Measure).count() == 0:
            for m in measures_seed:
                db.add(Measure(text=m["text"], threat_type=m.get("threat_type", ""),
                               tags=m.get("tags", ""), addr_inflection=bool(m.get("addr_inflection", False)),
                               source=m.get("source", "seed")))
        else:
            # Пересинхронизация эталонных мер из JSON (порядок/теги), не трогая меры admin/llm
            etalon = (db.query(Measure).filter(Measure.source.in_(("etalon", "seed")))
                      .order_by(Measure.id).all())
            seed_sig = [(m["text"], m.get("tags", ""), bool(m.get("addr_inflection", False)))
                        for m in measures_seed]
            db_sig = [(m.text, m.tags or "", bool(m.addr_inflection)) for m in etalon]
            if measures_seed and db_sig != seed_sig:
                for m in etalon:
                    db.delete(m)
                db.flush()
                for m in measures_seed:
                    db.add(Measure(text=m["text"], threat_type=m.get("threat_type", ""),
                                   tags=m.get("tags", ""),
                                   addr_inflection=bool(m.get("addr_inflection", False)),
                                   source=m.get("source", "etalon")))
        db.commit()
    except Exception as e:
        logger.error("Seed reply resources failed: %s", e)
        db.rollback()
    finally:
        db.close()