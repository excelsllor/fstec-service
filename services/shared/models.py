"""ORM-модели микросервисного хранилища (PostgreSQL в проде, SQLite в dev).

Соответствие таблиц модели данных: docs/phase1_design.md §3.
"""
from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, ForeignKey, Boolean, Float, JSON,
)
from sqlalchemy.orm import relationship, backref
from shared.db import Base


def _utcnow():
    return datetime.now(timezone.utc)


class Run(Base):
    """Сквозной прогон (модель LLM + дата) для сравнения моде в одной БД."""
    __tablename__ = "runs"

    id = Column(Integer, primary_key=True, index=True)
    model = Column(String(50), default="", index=True)   # 14b | 9b | ...
    label = Column(String(100), default="")
    note = Column(Text, default="")
    created_at = Column(DateTime, default=_utcnow)

    documents = relationship("Document", back_populates="run")


class Document(Base):
    __tablename__ = "documents"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=True, index=True)
    letter_number = Column(String(50), default="")
    letter_date = Column(String(20), default="")
    letter_type = Column(String(30), default="other")
    status = Column(String(30), default="uploaded")
    subject = Column(String(500), default="")
    original_text = Column(Text, default="")
    all_text = Column(Text, default="")
    parse_errors = Column(Text, default="")

    content_hash = Column(String(64), default="", index=True)
    source_filename = Column(String(500), default="")
    file_path = Column(String(1000), default="")
    size = Column(Integer, default=0)
    mime = Column(String(100), default="")
    ocr_used = Column(Boolean, default=False)
    processing_stage = Column(String(30), default="uploaded")
    sla = Column(String(20), default="normal")       # normal | critical
    routing = Column(String(20), default="default")  # default | infosec

    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)

    run = relationship("Run", back_populates="documents")

    attachments = relationship("Attachment", back_populates="document", cascade="all, delete-orphan")
    threats = relationship("Threat", back_populates="document", cascade="all, delete-orphan")
    iocs = relationship("IoC", back_populates="document", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="document", cascade="all, delete-orphan")
    responses = relationship("GeneratedResponse", back_populates="document", cascade="all, delete-orphan")
    summaries = relationship("Summary", back_populates="document", cascade="all, delete-orphan")


class Attachment(Base):
    __tablename__ = "attachments"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=True, index=True)
    document_id = Column(Integer, ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True)
    filename = Column(String(500), nullable=False)
    file_path = Column(String(1000), nullable=False)
    file_type = Column(String(20), default="")
    parsed_text = Column(Text, default="")
    parse_status = Column(String(20), default="pending")
    parse_errors = Column(Text, default="")
    is_main = Column(Boolean, default=False)
    created_at = Column(DateTime, default=_utcnow)

    document = relationship("Document", back_populates="attachments")


class DocumentTable(Base):
    __tablename__ = "document_tables"

    id = Column(Integer, primary_key=True, index=True)
    document_id = Column(Integer, ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True)
    table_index = Column(Integer, default=0)
    rows_json = Column(Text, default="[]")
    created_at = Column(DateTime, default=_utcnow)


class Threat(Base):
    __tablename__ = "threats"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=True, index=True)
    document_id = Column(Integer, ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True)
    number = Column(Integer, default=0)
    group_name = Column(String(200), default="")
    threat_type = Column(String(50), default="")
    theme = Column(String(500), default="")
    archive_name = Column(String(300), default="")
    exe_name = Column(String(300), default="")
    malware_type = Column(String(200), default="")
    description = Column(Text, default="")
    measures = Column(Text, default="")

    document = relationship("Document", back_populates="threats")


class IoC(Base):
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=True, index=True)
    document_id = Column(Integer, ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True)
    ioc_type = Column(String(30), nullable=False, index=True)
    value = Column(String(500), nullable=False)
    context = Column(Text, default="")
    llm_validated = Column(Boolean, default=False)
    source = Column(String(10), default="regex")

    document = relationship("Document", back_populates="iocs")


class Entity(Base):
    __tablename__ = "entities"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=True, index=True)
    document_id = Column(Integer, ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True)
    entity_type = Column(String(30), nullable=False)   # organization | deadline | contact
    value = Column(String(500), nullable=False)
    context = Column(Text, default="")

    document = relationship("Document")


class Summary(Base):
    __tablename__ = "summaries"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=True, index=True)
    document_id = Column(Integer, ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True)
    summary = Column(String(500), default="")
    confidence = Column(Float, default=0.0)

    document = relationship("Document", back_populates="summaries")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=True, index=True)
    document_id = Column(Integer, ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True)
    bdu_id = Column(String(50), default="", index=True)
    cve_id = Column(String(50), default="", index=True)
    description = Column(Text, default="")
    software = Column(String(500), default="")
    severity = Column(String(30), default="unknown")
    cvss_score = Column(Float, nullable=True)
    cvss_version = Column(String(20), default="")
    cpe = Column(String(500), default="")
    affected_range = Column(Text, default="")
    fixed_version = Column(String(100), default="")
    patch_url = Column(String(1000), default="")
    cmdb_match = Column(Boolean, default=False)
    cmdb_error = Column(Text, default="")
    current_version = Column(String(100), default="")
    target_version = Column(String(100), default="")
    source = Column(String(20), default="manual")  # nvd | bdu | manual (Фаза 3)
    recommendation = Column(Text, default="")
    is_applicable = Column(Boolean, nullable=True)
    applicability_notes = Column(Text, default="")
    action_type = Column(String(30), default="")
    action_details = Column(Text, default="")
    response_point = Column(Text, default="")

    document = relationship("Document", back_populates="vulnerabilities")


class SLABase(Base):
    __tablename__ = "sla_events"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=True, index=True)
    document_id = Column(Integer, ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True)
    sla = Column(String(20), default="normal")
    routing = Column(String(20), default="default")
    reason = Column(Text, default="")
    created_at = Column(DateTime, default=_utcnow)

    document = relationship("Document")


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=True, index=True)
    document_id = Column(Integer, ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True)
    report_type = Column(String(50), default="indicator_card")
    filename = Column(String(500), nullable=False)
    file_path = Column(String(1000), nullable=False)
    generated_at = Column(DateTime, default=_utcnow)

    document = relationship("Document")


class GeneratedResponse(Base):
    __tablename__ = "generated_responses"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=True, index=True)
    document_id = Column(Integer, ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True)
    content = Column(Text, default="")
    edited_content = Column(Text, default="")
    plan_json = Column(Text, default="")       # структура блоков ответа с аннотациями мер (source/candidate_id)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)

    document = relationship("Document", back_populates="responses")


class Measure(Base):
    """Библиотека стандартных мер (отдельный справочник для LLM-подбора проекта ответа)."""
    __tablename__ = "measures"

    id = Column(Integer, primary_key=True, index=True)
    text = Column(Text, nullable=False)
    threat_type = Column(String(50), default="")       # phishing | malware_attack | compromise | clickfix | vulnerability | hacker
    tags = Column(String(300), default="")             # csv-теги применимости
    addr_inflection = Column(Boolean, default=False)   # мера склоняется по числу адресов (адресам/адресу)
    source = Column(String(50), default="manual")      # etalon | seed | admin | llm
    created_at = Column(DateTime, default=_utcnow)


class MeasureCandidate(Base):
    """Меры, предложенные LLM; статус — очередь на рассмотрение администратором."""
    __tablename__ = "measure_candidates"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=True, index=True)
    document_id = Column(Integer, ForeignKey("documents.id", ondelete="CASCADE"), nullable=True, index=True)
    threat_id = Column(Integer, ForeignKey("threats.id", ondelete="CASCADE"), nullable=True)
    text = Column(Text, nullable=False)
    note = Column(Text, default="")
    status = Column(String(20), default="pending")     # pending | approved | rejected
    reviewed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=_utcnow)


class ReplyTemplate(Base):
    """Шаблоны проекта ответа по типу письма (шапка/intro/outro/блок)."""
    __tablename__ = "reply_templates"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(50), nullable=False, unique=True)   # hacker | compromise | vulnerability | other
    letter_type = Column(String(50), default="")
    skeleton = Column(JSON, nullable=False)                 # {header, intro, outro, block_template, ...}
    is_default = Column(Boolean, default=False)
    created_at = Column(DateTime, default=_utcnow)


class IntroFragment(Base):
    """Ранние фразы блока ответа («связанных с …»): LLM выбирает фрагмент по данным угрозы."""
    __tablename__ = "intro_fragments"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), nullable=False, unique=True)
    label = Column(String(300), default="")
    template = Column(Text, nullable=False)                 # «деятельностью хакерской группировки {{group}}, …»
    applies_to = Column(String(300), default="")            # csv: phishing | malware_attack | compromise | clickfix | vulnerability | hacker
    is_default = Column(Boolean, default=False)
    created_at = Column(DateTime, default=_utcnow)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="user")
    full_name = Column(String(200), default="")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=_utcnow)


class BootstrapSecret(Base):
    __tablename__ = "bootstrap_secrets"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), nullable=False, index=True)
    secret = Column(Text, nullable=False)
    used = Column(Boolean, default=False)
    created_at = Column(DateTime, default=_utcnow)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True, index=True)
    username = Column(String(100), default="", index=True)
    action = Column(String(50), nullable=False, index=True)
    object_type = Column(String(50), default="")
    object_id = Column(Integer, nullable=True)
    filename = Column(String(500), default="")
    document_id = Column(Integer, nullable=True, index=True)
    ip_address = Column(String(45), default="")
    created_at = Column(DateTime, default=_utcnow)


class ThreatType(Base):
    __tablename__ = "threat_types"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False, unique=True)
    key = Column(String(50), nullable=False, unique=True)
    description = Column(Text, default="")
    created_at = Column(DateTime, default=_utcnow)


class MeasureTemplate(Base):
    __tablename__ = "measure_templates"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    threat_type_id = Column(Integer, ForeignKey("threat_types.id"), nullable=True)
    content = Column(Text, default="")
    is_default = Column(Boolean, default=False)
    created_at = Column(DateTime, default=_utcnow)


class VulnActionTemplate(Base):
    __tablename__ = "vuln_action_templates"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    action_type = Column(String(50), default="update")
    content = Column(Text, default="")
    is_default = Column(Boolean, default=False)
    created_at = Column(DateTime, default=_utcnow)