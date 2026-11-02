import chardet
from shared.parsers.base import ParseResult


def parse_text(content: bytes) -> ParseResult:
    detected = chardet.detect(content)
    encoding = detected.get("encoding", "utf-8") or "utf-8"
    try:
        text = content.decode(encoding)
    except (UnicodeDecodeError, LookupError):
        try:
            text = content.decode("utf-8", errors="replace")
        except Exception:
            text = content.decode("latin-1", errors="replace")
    return ParseResult(text=text)


def parse_rtf(content: bytes) -> ParseResult:
    try:
        from striprtf.striprtf import rtf_to_text
        plain = rtf_to_text(content.decode("utf-8", errors="replace"))
        return ParseResult(text=plain)
    except Exception:
        return parse_text(content)


def parse_html(content: bytes) -> ParseResult:
    detected = chardet.detect(content)
    encoding = detected.get("encoding", "utf-8") or "utf-8"
    try:
        raw = content.decode(encoding)
    except (UnicodeDecodeError, LookupError):
        raw = content.decode("utf-8", errors="replace")
    try:
        from html.parser import HTMLParser

        class TextExtractor(HTMLParser):
            def __init__(self):
                super().__init__()
                self.result = []
                self._skip = False

            def handle_starttag(self, tag, attrs):
                if tag in ("script", "style"):
                    self._skip = True

            def handle_endtag(self, tag):
                if tag in ("script", "style"):
                    self._skip = False
                if tag in ("p", "br", "div", "tr", "li", "h1", "h2", "h3", "h4"):
                    self.result.append("\n")

            def handle_data(self, data):
                if not self._skip:
                    self.result.append(data)

        extractor = TextExtractor()
        extractor.feed(raw)
        return ParseResult(text="".join(extractor.result))
    except Exception:
        return ParseResult(text=raw)