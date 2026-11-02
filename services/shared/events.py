"""Pydantic-схемы событий Kafka (печатные контракты, см. phase1_design.md §1.2)."""
from datetime import datetime, timezone
from pydantic import BaseModel, Field


def _now() -> datetime:
    return datetime.now(timezone.utc)


class AttachmentMeta(BaseModel):
    filename: str
    path: str
    size: int = 0


class DocumentsUploaded(BaseModel):
    event: str = "documents.uploaded"
    document_id: int
    user_id: int | None = None
    main_file: AttachmentMeta
    attachments: list[AttachmentMeta] = Field(default_factory=list)
    uploaded_at: datetime = Field(default_factory=_now)


class DocumentParsed(BaseModel):
    event: str = "document.parsed"
    document_id: int
    text: str = ""
    all_text: str = ""
    ocr_used: bool = False
    parse_errors: list[str] = Field(default_factory=list)
    attachments: list[dict] = Field(default_factory=list)
    parsed_at: datetime = Field(default_factory=_now)


class EntityItem(BaseModel):
    type: str        # organization | deadline | contact
    value: str
    context: str = ""


class SoftwareItem(BaseModel):
    name: str
    version: str = ""


class AnalysisIocs(BaseModel):
    ip_addresses: list[str] = Field(default_factory=list)      # IPv4 (+порт)
    ipv4_cidr: list[str] = Field(default_factory=list)
    ipv6: list[str] = Field(default_factory=list)              # IPv6 (+CIDR)
    domains: list[str] = Field(default_factory=list)
    hashes: list[str] = Field(default_factory=list)            # md5/sha1/sha256/...
    urls: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    cve: list[str] = Field(default_factory=list)
    bdu: list[str] = Field(default_factory=list)
    software: list[SoftwareItem] = Field(default_factory=list)


class DocumentAnalyzed(BaseModel):
    event: str = "document.analyzed"
    document_id: int
    classification: str = "other"
    letter_number: str = ""
    letter_date: str = ""
    summary: str = ""
    entities: list[EntityItem] = Field(default_factory=list)
    iocs: AnalysisIocs = Field(default_factory=AnalysisIocs)
    threats: list[dict] = Field(default_factory=list)
    vulns_raw: list[dict] = Field(default_factory=list)
    sla: str = "normal"                # вычислено в llm-service (категорирование, ТЗ 2.4)
    routing: str = "default"
    llm_used: bool = False
    analyzed_at: datetime = Field(default_factory=_now)


class VulnerabilityAssessed(BaseModel):
    cve_id: str = ""
    bdu_id: str = ""
    description: str = ""
    software: str = ""
    severity: str = "unknown"
    cvss_score: float | None = None
    cvss_version: str = ""
    cpe: str = ""
    affected_range: str = ""
    fixed_version: str = ""
    patch_url: str = ""
    cmdb_match: bool = False
    cmdb_error: str = ""
    current_version: str = ""
    target_version: str = ""
    recommendation: str = ""
    source: str = "manual"
    is_applicable: bool | None = None
    action_type: str = ""
    applicability_notes: str = ""         # nvd | bdu | manual (Фаза 3, phase1_json_schemas.md §4)


class SecurityAssessed(BaseModel):
    event: str = "security.assessed"
    document_id: int
    vulnerabilities: list[VulnerabilityAssessed] = Field(default_factory=list)
    sla: str = "normal"                # normal | critical
    routing: str = "default"           # default | infosec
    external_errors: list[str] = Field(default_factory=list)   # недоступность NVD/BDU/CMDB (ТЗ 4.2)
    assessed_at: datetime = Field(default_factory=_now)


class ReportReady(BaseModel):
    event: str = "report.ready"
    document_id: int
    report_type: str = "indicator_card"   # indicator_card | reply
    filename: str = ""
    file_path: str = ""
    generated_at: datetime = Field(default_factory=_now)


class ReplyGenerated(BaseModel):
    event: str = "reply.generated"
    document_id: int
    filename: str = ""
    file_path: str = ""
    text: str = ""
    generated_at: datetime = Field(default_factory=_now)


class AuditEvent(BaseModel):
    event: str = "audit.events"
    user_id: int | None = None
    username: str = ""
    action: str = ""
    object_type: str = ""
    object_id: int | None = None
    filename: str = ""
    document_id: int | None = None
    ip_address: str = ""
    created_at: datetime = Field(default_factory=_now)


EVENT_MODELS = {
    "documents.uploaded": DocumentsUploaded,
    "document.parsed": DocumentParsed,
    "document.analyzed": DocumentAnalyzed,
    "security.assessed": SecurityAssessed,
    "report.ready": ReportReady,
    "reply.generated": ReplyGenerated,
    "audit.events": AuditEvent,
}


def parse_event(topic: str, raw: dict):
    model = EVENT_MODELS.get(topic)
    if model is None:
        return raw
    return model.model_validate(raw)