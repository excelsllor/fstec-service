import io
import pdfplumber
from shared.parsers.base import ParseResult


def parse_pdf(content: bytes) -> ParseResult:
    result = ParseResult()
    try:
        text_parts = []
        tables = []
        with pdfplumber.open(io.BytesIO(content)) as pdf:
            result.metadata["pages"] = len(pdf.pages)
            for i, page in enumerate(pdf.pages):
                try:
                    page_text = page.extract_text() or ""
                except Exception as e:
                    result.errors.append(f"Страница {i+1}: {e}")
                    page_text = ""
                text_parts.append(page_text)
                try:
                    page_tables = page.extract_tables()
                    for t in page_tables:
                        cleaned = []
                        for row in t:
                            cleaned_row = [(cell or "").strip() for cell in row]
                            cleaned.append(cleaned_row)
                        if cleaned:
                            tables.append(cleaned)
                except Exception:
                    pass
        result.text = "\n".join(text_parts)
        result.page_texts = text_parts
        result.tables = tables
    except Exception as e:
        result.errors.append(f"PDF: {e}")
    return result