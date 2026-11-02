from dataclasses import dataclass, field


@dataclass
class ParseResult:
    text: str = ""
    tables: list[list[list[str]]] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    page_texts: list[str] = field(default_factory=list)