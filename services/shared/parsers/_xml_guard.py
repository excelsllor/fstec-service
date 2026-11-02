"""Защита от XXE/DTD и ZIP-бомб при разборе ZIP-XML (docx/xlsx/odt).

lxml (python-docx) и openpyxl по умолчанию могут резолвить внутренние/внешние
сущности DTD; OOXML-части не должны содержать DOCTYPE/ENTITY вообще.
Любая часть архива с запрещёнными маркерами → кортеж отклонён, содержимое не разбирается.

Дополнительно ограничивается распакованный размер (защита от zip-bomb): размеры
берутся из заголовков ZIP до распаковки, поэтому многогигабайтная часть не
загружается в память.
"""
import io
import zipfile

_XXE_MARKERS = (b"<!DOCTYPE", b"<!ENTITY", b"<!ELEMENT", b"<!ATTLIST", b"<!NOTATION")

_MAX_PART = 2 * 1024 * 1024            # 2 МБ на одну XML-часть
_MAX_TOTAL = 64 * 1024 * 1024          # 64 МБ суммарно распакованного
_MAX_ENTRIES = 2048                    # максимум файлов в архиве


def guard_zip_xml(content: bytes, *, what: str, errors: list[str],
                  max_part: int = _MAX_PART, max_total: int = _MAX_TOTAL,
                  max_entries: int = _MAX_ENTRIES) -> bool:
    """Проверяет zip-архив на XXE/DTD и превышение лимитов распаковки.

    True — безопасно (можно парсить). False — в errors добавлено описание, архив отклонён.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            infos = zf.infolist()
            if len(infos) > max_entries:
                errors.append(f"{what}: слишком много файлов в архиве ({len(infos)})")
                return False
            total = sum(i.file_size for i in infos)
            if total > max_total:
                errors.append(f"{what}: распакованный размер архива превышает лимит")
                return False
            for info in infos:
                name = info.filename
                low = name.lower()
                if not (low.endswith((".xml", ".rels")) or ".xml" in low):
                    continue
                if info.file_size > max_part:
                    errors.append(f"{what}: XML-часть {name!r} превышает лимит")
                    return False
                data = zf.read(name)
                if any(marker in data for marker in _XXE_MARKERS):
                    errors.append(f"{what}: отклонён XML-файл с DTD/ENTITY ({name!r})")
                    return False
    except zipfile.BadZipFile:
        errors.append(f"{what}: повреждён ZIP-архив")
        return False
    except Exception as e:  # noqa: BLE001
        errors.append(f"{what}: ошибка проверки архива: {e}")
        return False
    return True
