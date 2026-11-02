#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Оценка качества на реальном корпусе (Step 3).

Запускает анализ каждого корпуса тем же пайплайном, что llm-service
(shared.extractor.* + llm_service.provider), сравнивает с золотом из
corpus_index.json и считает метрики:
  - классификация: accuracy + confusion matrix (правило/heuristic vs vllm)
  - IoC (ip/domain): precision / recall / F1 (set-based)
  - саммари: длина <= 500 для llm-режима

Режимы:
  heuristic — быстрый baseline без GPU (для CI)
  vllm      — прогон через локальный OpenAI-совместимый сервер (llama.cpp /
              vLLM), задаётся FSTEC_LLM_PROVIDER=vllm + VLLM_BASE_URL.

Использование:
  export FSTEC_LLM_PROVIDER=vllm VLLM_BASE_URL=http://127.0.0.1:8000/v1
  python tools/quality_eval.py --corpus data/quality/corpus_index.json
"""
import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from shared.config import RUBERT_MODEL
from shared.extractor.ioc_extractor import extract_iocs
from llm_service.analyze import analyze
from llm_service.provider import get_provider


# --- метрики ---
def set_f1(pred: set, gold: set, cover: bool = False):
    if not gold:
        return {"precision": 1.0 if not pred else 0.0,
                "recall": 1.0 if not pred else 0.0,
                "f1": 1.0 if not pred else 0.0,
                "tp": 0, "fp": len(pred), "fn": 0}
    if cover:
        pred = list(pred)
        gold = list(gold)
        tp, fp, fn = 0, 0, 0
        used = set()
        for p in pred:
            hit = None
            for gi, g in enumerate(gold):
                if gi in used:
                    continue
                if p == g or p.endswith("." + g) or g.endswith("." + p):
                    hit = gi
                    break
            if hit is not None:
                tp += 1
                used.add(hit)
            else:
                fp += 1
        fn = len(gold) - len(used)
    else:
        tp = len(pred & gold)
        fp = len(pred - gold)
        fn = len(gold - pred)
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f1, 4),
            "tp": tp, "fp": fp, "fn": fn}


def norm_ip(i):
    return i.split(":")[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=str(ROOT / "data" / "quality" / "corpus_index.json"))
    ap.add_argument("--out", default=str(ROOT / "data" / "quality" / "quality_report.json"))
    ap.add_argument("--no-rubert", action="store_true",
                    help="Отключить RuBERT (показывает чистый regex/heuristic baseline).")
    ap.add_argument("--encoder-only", action="store_true",
                    help="Замерить СТАНД-АЛОНЕ точность энкодера (без regex/LLM): classify(полный текст).")
    ap.add_argument("--encoder-model", default=None,
                    help="Модель энкодера для --encoder-only (по умолчанию FSTEC_RUBERT_MODEL).")
    args = ap.parse_args()

    corpus = json.loads(Path(args.corpus).read_text(encoding="utf-8"))
    if args.encoder_only:
        _run_encoder_only(args, corpus)
        return

    if args.no_rubert:
        import llm_service.analyze as an
        an.rubert_available = lambda: False
    provider = get_provider()
    mode = provider.kind.value
    print(f"=== Quality eval | provider={mode} | cases={len(corpus)} ===")

    rows = []
    cls_preds, cls_gold = [], []
    ioc_totals = {"ip": {"tp": 0, "fp": 0, "fn": 0},
                  "domain": {"tp": 0, "fp": 0, "fn": 0},
                  "domain_full": {"tp": 0, "fp": 0, "fn": 0}}
    summary_ok = 0
    summary_total = 0

    for name, case in corpus.items():
        text = case["full"] if case.get("full") else case["main"]

        event, _ = analyze(provider, text)
        pred_cls = event.classification
        gold_cls = case["gold"]["classification"]

        # IoC через общий экстрактор = то же, что persist_analysis в БД
        iocs = extract_iocs(text)
        pred_ips = {norm_ip(i) for i in event.iocs.ip_addresses}
        pred_doms = set(event.iocs.domains)

        # 1) «узкое» золото = блок-список из приложений; 2) «полное» = + списки тела письма
        gold_att = case["gold"]
        gf = case.get("gold_full") or {
            "ips": gold_att.get("ips") or [], "domains": gold_att.get("domains") or []}
        gold_ips = set(gold_att.get("ips") or [])
        gold_doms = set(gold_att.get("domains") or [])
        gold_full_ips = set(gf["ips"])
        gold_full_doms = set(gf["domains"])

        ip_eval = set_f1(pred_ips, gold_ips)
        dom_eval = set_f1(pred_doms, gold_doms, cover=True)
        dom_full_eval = set_f1(pred_doms, gold_full_doms, cover=True)
        for k in ("tp", "fp", "fn"):
            ioc_totals["ip"][k] += ip_eval[k]
            ioc_totals["domain"][k] += dom_eval[k]
        for k in ("tp", "fp", "fn"):
            ioc_totals["domain_full"][k] += dom_full_eval[k]

        if mode == "vllm":
            summary_total += 1
            if len(event.summary) <= 500:
                summary_ok += 1

        cls_preds.append(pred_cls)
        cls_gold.append(gold_cls)
        match = pred_cls == gold_cls
        rows.append({
            "id": name, "gold_class": gold_cls, "pred_class": pred_cls,
            "class_ok": match,
            "ip": ip_eval,
            "domain": dom_eval, "domain_full": dom_full_eval,
            "n_pred_ip": len(pred_ips), "n_gold_ip": len(gold_ips),
            "n_pred_dom": len(pred_doms), "n_gold_dom": len(gold_doms),
            "n_gold_dom_full": len(gold_full_doms),
            "summary_len": len(event.summary),
        })
        print(f"  {name:6} class gold={gold_cls:12} pred={pred_cls:12} "
              f"{'OK' if match else 'MISS'} | ip P/R/F1={ip_eval['precision']}/{ip_eval['recall']}/{ip_eval['f1']} "
              f"({len(pred_ips)}/{len(gold_ips)}) | dom P/R/F1={dom_eval['precision']}/{dom_eval['recall']}/{dom_eval['f1']} "
              f"[full {dom_full_eval['precision']}/{dom_full_eval['recall']}/{dom_full_eval['f1']}] "
              f"({len(pred_doms)}/{len(gold_doms)})")

    acc = sum(1 for p, g in zip(cls_preds, cls_gold) if p == g) / len(cls_gold)
    ip_tot = set_f1_sets(ioc_totals["ip"])
    dom_tot = set_f1_sets(ioc_totals["domain"])
    dom_full_tot = set_f1_sets(ioc_totals["domain_full"])

    report = {
        "provider": mode,
        "cases": len(corpus),
        "classification_accuracy": round(acc, 4),
        "confusion": _confusion(cls_gold, cls_preds),
        "ioc": {"ip": ip_tot, "domain": dom_tot, "domain_full": dom_full_tot},
    }
    if mode == "vllm":
        report["summary_le500"] = {"ok": summary_ok, "total": summary_total}
    report["rows"] = rows

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\n=== Accuracy={acc:.3f} | IP F1={ip_tot['f1']:.3f} | DOM F1={dom_tot['f1']:.3f} "
          f"| DOM_full P/R/F1={dom_full_tot['precision']}/{dom_full_tot['recall']}/{dom_full_tot['f1']} ===")
    print(f"Report: {out}")


def set_f1_sets(agg):
    tp, fp, fn = agg["tp"], agg["fp"], agg["fn"]
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f1, 4), **agg}


def _confusion(gold, pred):
    classes = sorted(set(gold) | set(pred))
    m = {g: {p: 0 for p in classes} for g in classes}
    for g, p in zip(gold, pred):
        m[g][p] += 1
    return m


def _run_encoder_only(args, corpus):
    """Stand-alone точность энкодера: classify(полный текст) без regex/LLM + замер времени."""
    from llm_service.rubert import RuBERTClassifier
    model = args.encoder_model or RUBERT_MODEL
    print(f"=== Encoder-only eval | model={model} | cases={len(corpus)} ===")
    enc = RuBERTClassifier(model_name=model)
    if not enc._load():
        print("  encoder unavailable — проверьте сеть/веса")
        return

    rows, preds, golds, times = [], [], [], []
    total_tok = 0
    wall0 = time.perf_counter()
    for name, case in corpus.items():
        text = case["full"] if case.get("full") else case["main"]
        gold = case["gold"]["classification"]
        ts = time.perf_counter()
        lbl, conf = enc.classify(text)
        dt = time.perf_counter() - ts
        pred = lbl if lbl else "other"
        nt = len(enc._tokenizer.encode(text))
        total_tok += nt
        rows.append({"id": name, "gold": gold, "pred": pred,
                     "conf": round(conf, 4), "sec": round(dt, 2), "tokens": nt})
        preds.append(pred)
        golds.append(gold)
        times.append(dt)
        mark = "OK" if pred == gold else "MISS"
        print(f"  {name:6} gold={gold:10} pred={pred:10} conf={conf:.3f} tok={nt:6} {dt:6.2f}s {mark}")

    acc = sum(1 for p, g in zip(preds, golds) if p == g) / len(golds)
    wall = time.perf_counter() - wall0
    mean_t = sum(times) / len(times)
    report = {
        "provider": "encoder",
        "encoder_model": model,
        "cases": len(corpus),
        "classification_accuracy": round(acc, 4),
        "confusion": _confusion(golds, preds),
        "mean_sec_per_letter": round(mean_t, 2),
        "total_sec": round(wall, 1),
        "mean_tokens_per_letter": total_tok // len(golds),
        "rows": rows,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\n=== Encoder acc={acc:.3f} | mean={mean_t:.2f}s/letter | total={wall:.1f}s | "
          f"mean_tok={total_tok // len(golds)} ===")
    print(f"Report: {out}")


if __name__ == "__main__":
    main()