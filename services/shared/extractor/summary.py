"""Саммари документа (ТЗ 2.3.3, ≤500 символов). Хевристика для dev/MVP;
в проде — LLM (Qwen3-14B) с этим же ограничением длины."""
import re


def summarize_heuristic(text: str, max_chars: int = 500) -> str:
    if not text:
        return ""
    cleaned = re.sub(r"\s+", " ", text).strip()
    if not cleaned:
        return ""
    first_sentence = re.split(r"(?<=[.!?])\s+", cleaned)[0]
    summary = re.sub(r"\s+", " ", first_sentence).strip().strip(".,;:")
    if len(summary) > max_chars:
        summary = summary[: max_chars - 1].rstrip() + "…"
    return summary or cleaned[:max_chars]