"""RuBERT-классификация категорий документов (hacker|compromise|vulnerability|other).

Быстрый детерминированный предиктор по [CLS]-эмбеддингам + косинусная близость к
фразам-сеедам категорий. GPU под vLLM, поэтому по умолчанию работает на CPU.
Веса грузятся лениво (singleton); без модели/зависимостей возвращает None — тогда
используется heuristic-fallback. Дообучение (LoRA) — Фаза 3.
"""
import logging

from shared.config import RUBERT_CONFIDENCE, RUBERT_DEVICE, RUBERT_MAX_TOKENS, RUBERT_MODEL

logger = logging.getLogger(__name__)

CATEGORY_SEEDS: dict[str, list[str]] = {
    "hacker": [
        "хакерской группировкой осуществляется рассылка фишинговых писем",
        "архив с наименованием",
        "исполняемый файл с наименованием",
        "вредоносное программное обеспечение",
        "фишинговая рассылка",
    ],
    "compromise": [
        "компрометация веб-сайта разработчика",
        "скомпрометирован",
        "неавторизованный доступ",
    ],
    "vulnerability": [
        "эксплуатация уязвимости",
        "уровень опасности по cvss",
        "bdu:",
        "cve-",
        "уязвимость",
    ],
    "other": [
        "служебная записка",
        "информационное письмо",
        "общие организационные вопросы",
    ],
}


class RuBERTClassifier:
    def __init__(self, model_name: str = RUBERT_MODEL, device: str = RUBERT_DEVICE,
                 confidence: float = RUBERT_CONFIDENCE):
        self.model_name = model_name
        self.device = device
        self.confidence = confidence
        self._model = None
        self._tokenizer = None
        self._centroids: list[tuple[str, "torch.Tensor"]] = []

    def is_available(self) -> bool:
        try:
            import torch
            from transformers import AutoModel, AutoTokenizer
            return True
        except Exception:
            return False

    def _load(self):
        if self._model is not None:
            return True
        try:
            import torch
            from transformers import AutoModel, AutoTokenizer
            self._tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self._model = AutoModel.from_pretrained(self.model_name)
            self._model.eval()
            device = "cuda" if self.device == "gpu" and torch.cuda.is_available() else "cpu"
            if device == "cuda":
                self._model = self._model.to(device)
            self._centroids = self._build_centroids(device)
            return True
        except Exception as e:
            logger.warning("RuBERT загрузка не удалась (%s), fallback: %s", self.model_name, e)
            return False

    def _build_centroids(self, device: str) -> list[tuple[str, "torch.Tensor"]]:
        import torch
        centroids = []
        for label, phrases in CATEGORY_SEEDS.items():
            enc = self._tokenizer(phrases, return_tensors="pt", padding=True,
                                  truncation=True, max_length=128)
            enc = {k: v.to(device) for k, v in enc.items()}
            with torch.no_grad():
                out = self._model(**enc)
            vecs = out.last_hidden_state.mean(dim=1)
            centroids.append((label, vecs.mean(dim=0)))
        return centroids

    def classify(self, text: str) -> tuple[str | None, float]:
        if not self._load():
            return None, 0.0
        emb = self._embed(text)
        return self._classify_vectors(emb)

    def _embed(self, text: str) -> "torch.Tensor":
        import torch
        # Полный текст, обрезка по контексту модели (RuModernBERT/USER2 — 8192 токенов,
        # ruBERT-512 через FSTEC_RUBERT_MAX_TOKENS). Раньше резали text[:512] символов (~170
        # токенов) — энкодер не видел ни один классификационный сигнал письма.
        enc = self._tokenizer(text, return_tensors="pt", truncation=True,
                              max_length=RUBERT_MAX_TOKENS, padding=False)
        device = "cuda" if self.device == "gpu" and torch.cuda.is_available() else "cpu"
        enc = {k: v.to(device) for k, v in enc.items()}
        with torch.no_grad():
            return self._model(**enc).last_hidden_state.mean(dim=1).squeeze(0)

    def _classify_vectors(self, emb: "torch.Tensor") -> tuple[str | None, float]:
        import torch
        best_label, best_score = None, -1.0
        for label, centroid in self._centroids:
            sim = torch.nn.functional.cosine_similarity(emb, centroid, dim=0).item()
            if sim > best_score:
                best_score, best_label = sim, label
        if best_score < self.confidence:
            return None, best_score
        return best_label, best_score


_classifier: RuBERTClassifier | None = None


def get_rubert() -> RuBERTClassifier | None:
    global _classifier
    if _classifier is None:
        c = RuBERTClassifier()
        if c._load():
            _classifier = c
    return _classifier


def rubert_available() -> bool:
    return get_rubert() is not None