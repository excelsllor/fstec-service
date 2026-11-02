#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Сверка идеи «модель-классификатор» : regex-baseline vs локальная Qwen (llama.cpp).

Сравнивает на корпусе реальных писем ФСТЭК:
  1) тип письма (3 класса: hacker / vulnerability / other; compromise -> hacker)
  2) извлечённые IoC: ips, domains, hashes, emails
     - regex  : shared.extractor.ioc_extractor (как в блок-списках прод)
     - LLM    : экстрактивное извлечение через /v1/chat/completions;
                любое значение НЕ входящее в текст дословно -> отбрасывается
                (анти-галлюцинация) и считается violation.
  gold берётся из data/quality/corpus_index.json (ips/domains/classification).

Использование:
  python tools/eval_llm_vs_regex.py
  python tools/eval_llm_vs_regex.py --base-url http://127.0.0.1:8080/v1 --model qwen3.5-9b
  python tools/eval_llm_vs_regex.py --type-only-only  (прогнать типы по 22 письмам, без IoC)
"""
import argparse
import ipaddress
import json
import re
import sys
import time
from pathlib import Path

import urllib.request

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from shared.extractor.ioc_extractor import extract_iocs
from shared.extractor.letter_analyzer import _detect_type
from shared.extractor.patterns import HASH_MD5, HASH_SHA1, HASH_SHA256, HASH_SHA384, HASH_SHA512, EMAIL_PATTERN

HASH_RE = re.compile(
    r"^(?:" + "|".join(p.pattern for p in (HASH_MD5, HASH_SHA1, HASH_SHA256, HASH_SHA384, HASH_SHA512)) + r")$",
    re.IGNORECASE)

ALIAS3 = {"hacker": "hacker", "compromise": "hacker", "vulnerability": "vulnerability", "other": "other"}
CLOSED = {"hacker", "vulnerability", "other"}


def to3(t):
    return ALIAS3.get(t, "other" if t not in ALIAS3 else t)


def norm_ip(i):
    s = i.split(":")[0]
    try:
        ipaddress.ip_address(s)
        return s
    except ValueError:
        return None


def _mentions(text, value):
    """Дословное присутствие значения в тексте (с допусками обфускации)."""
    v = value.strip().lower()
    if not v:
        return False
    t = text.lower()
    if v in t:
        return True
    # текст с обфускацией [.]/(.)/[:] — значения типа 104[.]238[.]… и hxxps[:]//host[.]tld
    d = (t.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
         .replace("[//]", "//").replace("[/]", "/"))
    if v in d:
        return True
    # значения, разбитые в PDF пробелами/переносами строк (IP, хеши, домены)
    t_ws = re.sub(r"\s+", "", t)
    v_ws = re.sub(r"\s+", "", v)
    if len(v_ws) >= 8 and v_ws in t_ws:
        return True
    return False


def clean_domain(d):
    d = d.strip().strip(".").lower()
    d = re.sub(r"^[a-z]+://", "", d)
    d = re.sub(r"^hxxps?\[\:\]//", "", d)
    d = re.sub(r"^hxxps?[.:]//", "", d)
    d = re.sub(r"^\[/\]//", "", d)
    d = re.sub(r"^\[\:\]//", "", d)
    d = d.split("/")[0].split(":")[0].split("?")[0].strip(".")
    return d


def llm_classify_only(head, base_url, model, max_tokens=40):
    """Быстрый этап: только тип письма на голове текста (3 класса)."""
    call = {
        "model": model,
        "messages": [
            {"role": "system", "content": (
                "Ты — классификатор официальных писем ФСТЭК России. "
                "Определи тип письма: только один из: hacker, vulnerability, other. "
                "hacker — угрозы хакерских группировок, фишинг, вредоносное ПО, "
                "компрометация/фишинговые ресурсы. "
                "vulnerability — сведения о конкретных уязвимостях (BDU, CVE) и меры по их устранению. "
                "other — прочее. "
                "Верни ТОЛЬКО JSON: {\"classification\": \"hacker\"|\"vulnerability\"|\"other\"}. "
                "Без пояснений и markdown."
            )},
            {"role": "user", "content": head},
        ],
        "temperature": 0.1,
        "top_p": 0.9,
        "max_tokens": max_tokens,
        "include_reasoning": False,
        "chat_template_kwargs": {"enable_thinking": False},
        "stream": False,
    }
    req = urllib.request.Request(base_url.rstrip("/") + "/chat/completions",
                                 data=json.dumps(call).encode("utf-8"),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=300) as r:
        data = json.loads(r.read().decode("utf-8"))
    return data["choices"][0]["message"].get("content", "") or ""


def llm_extract_annotated(body, base_url, model, max_tokens=1800):
    call = {
        "model": model,
        "messages": [
            {"role": "system", "content": (
                "Ты — модуль извлечения данных из официальных писем ФСТЭК России. "
                "1) Определи тип письма: только один из: hacker, vulnerability, other. "
                "hacker — угрозы хакерских группировок, фишинг, " 
                "вредоносное ПО, компрометация/фишинговые ресурсы. "
                "vulnerability — сведения о конкретных уязвимостях (BDU, CVE) и меры по их устранению. "
                "other — прочее. "
                "2) Извлеки IoC: ips (IPv4/IPv6), domains (домены и хосты), hashes (md5/sha1/sha256/sha384/sha512 32-128 hex), "
                "emails (E-mail из письма). "
                "ВЫДЕЛЯЙ ТОЛЬКО значения, которые ДОСЛОВНО ПРИСУТСТВУЮТ в тексте письма. Не перефразируй, "
                "не реконструируй домены из URL, не добавляй ничего от себя. "
                "Один пустой JSON, без пояснений и без обёрток в markdown: "
                '{"classification": "...", "iocs": {"ips": [], "domains": [], "hashes": [], "emails": []}}'
            )},
            {"role": "user", "content": body},
        ],
        "temperature": 0.1,
        "top_p": 0.9,
        "max_tokens": max_tokens,
        "include_reasoning": False,
        "chat_template_kwargs": {"enable_thinking": False},
        "stream": False,
    }
    req = urllib.request.Request(base_url.rstrip("/") + "/chat/completions",
                                 data=json.dumps(call).encode("utf-8"),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=600) as r:
        data = json.loads(r.read().decode("utf-8"))
    raw = data["choices"][0]["message"].get("content", "") or ""
    return raw


def parse_llm_json(raw):
    m = re.search(r"\{.*\}", raw, re.S)
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    cls = to3(str(obj.get("classification", "")).strip().lower())
    iocs = obj.get("iocs") or {}
    res = {"ips": [], "domains": [], "hashes": [], "emails": []}
    for k in res:
        v = iocs.get(k) or []
        res[k] = [str(x) for x in v if isinstance(x, (str, int))]
    return {"classification": cls, "iocs": res}


def set_f1(pred, gold, cover=False):
    if not gold:
        return {"p": 1.0 if not pred else 0.0, "r": 1.0 if not pred else 0.0,
                "f1": 1.0 if not pred else 0.0, "tp": 0, "fp": len(pred), "fn": 0}
    if cover:
        pred, gold = list(pred), list(gold)
        used, tp, fp = set(), 0, 0
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
    return {"p": round(p, 4), "r": round(r, 4), "f1": round(f1, 4), "tp": tp, "fp": fp, "fn": fn}


def agg(totals):
    tp, fp, fn = totals
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return {"p": round(p, 4), "r": round(r, 4), "f1": round(f1, 4), "tp": tp, "fp": fp, "fn": fn}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=str(ROOT / "data" / "quality" / "corpus_index.json"))
    ap.add_argument("--root", default=str(ROOT.parent.parent))
    ap.add_argument("--out", default=str(ROOT / "data" / "quality" / "eval_llm_vs_regex.json"))
    ap.add_argument("--base-url", default="http://127.0.0.1:8080/v1")
    ap.add_argument("--model", default="qwen3.5-9b")
    ap.add_argument("--type-only", action="store_true",
                    help="Только типы (все 22 письма из letter_types_gold), без IoC.")
    ap.add_argument("--no-llm", action="store_true", help="Только regex-baseline.")
    ap.add_argument("--ids", default=None,
                    help="Подмножество id письма через запятую (для прогресса по пачкам).")
    ap.add_argument("--tag", default="", help="Суффикс файла отчёта (eval_..._<tag>.json).")
    ap.add_argument("--stage", choices=["type", "ioc", "both"], default="both",
                    help="type — только классификация на голове текста (быстро); "
                         "ioc — извлечение адресов/хешей на полном тексте.")
    ap.add_argument("--head", type=int, default=6000,
                    help="Первые N символов для --stage type.")
    ap.add_argument("--max-tokens", type=int, default=0,
                    help="Ограничение генерации LLM. 0 = авто (type: 40, ioc: 6000).")
    ap.add_argument("--text-cap", type=int, default=12000,
                    help="Макс. длина текста для --stage ioc (символов).")
    args = ap.parse_args()

    corpus = json.loads(Path(args.corpus).read_text(encoding="utf-8"))

    # золото типов для всех писем
    gold_file = ROOT / "data" / "quality" / "letter_types_gold.json"
    gold_types = json.loads(gold_file.read_text(encoding="utf-8")) if gold_file.exists() else {}

    rows = []
    acc_re, acc_llm = 0, 0
    io = {"ip": {"re": [0, 0, 0], "llm": [0, 0, 0]},
          "domain": {"re": [0, 0, 0], "llm": [0, 0, 0]},
          "domain_full": {"re": [0, 0, 0], "llm": [0, 0, 0]}}
    n_llm, n_viol = 0, 0
    total_re_hash, total_llm_hash, hash_agree = 0, 0, 0

    from shared.parsers import parse_file

    def resolve(name):
        for cand in (ROOT / "corpus" / "real" / f"{name}.pdf",
                     Path(args.root) / f"{name}.pdf"):
            if cand.exists():
                return cand
        return None

    # набор писем: 12 из corpus + (по желанию) все 22 из letter_types_gold
    ids = list(corpus.keys())
    if args.type_only:
        ids = list(gold_types.keys())
    else:
        for lid in gold_types:
            if lid not in ids:
                ids.append(lid)

    if args.ids:
        keep = {x.strip() for x in args.ids.split(",")}
        ids = [i for i in ids if i in keep]

    out_file = Path(args.out)
    if args.tag:
        out_file = out_file.with_name(out_file.stem + "_" + args.tag + out_file.suffix)

    cases = []
    for name in ids:
        p = resolve(name)
        if p is None:
            print(f"  {name}: НЕТ файла PDF")
            continue
        text = (parse_file(str(p)).text or "").strip()
        if not text:
            print(f"  {name}: пустой текст")
            continue
        gold = corpus.get(name, {}).get("gold") or {}
        gold.setdefault("classification", gold_types.get(name, "other"))
        cases.append((name, gold, text[:18000]))

    print(f"=== LLM vs REGEX | model={args.model} | llm={'on' if not args.no_llm else 'off'} | cases={len(cases)} ===")
    for name, gold, full in cases:
        # --- regex baseline ---
        re_cls = to3(_detect_type(full))
        ri = extract_iocs(full)
        re_ips = {x for x in (norm_ip(i) for i in ri.ips) if x}
        re_doms = {clean_domain(d) for d in ri.domains}
        re_hashes = set(ri.hashes)
        re_emails = set(ri.emails)

        # --- gold ---
        g_cls = to3(gold["classification"])
        g_ips = set(gold.get("ips") or [])
        g_doms = set(gold.get("domains") or [])
        gf = corpus.get(name, {}).get("gold_full") or {}
        gf_ips = set(gf.get("ips") or g_ips)
        gf_doms = set(gf.get("domains") or g_doms)

        row = {"id": name, "gold_class": g_cls, "re_class": re_cls, "llm_class": "n/a",
               "n_ips": {"re": len(re_ips), "llm": None, "gold": len(g_ips)},
               "n_doms": {"re": len(re_doms), "llm": None, "gold": len(g_doms)},
               "n_hashes": {"re": len(re_hashes), "llm": None, "gold": 0},
               "n_viol": 0, "llm_raw": "",
               "gold_iocs": {"ips": sorted(g_ips), "domains": sorted(g_doms)},
               "gold_full_iocs": {"domains": sorted(gf_doms)},
               "re_iocs": {"ips": sorted(re_ips), "domains": sorted(re_doms), "hashes": sorted(re_hashes)},
               "llm_iocs": {"ips": [], "domains": [], "hashes": [], "emails": []}}

        acc_re += int(re_cls == g_cls)
        # IoC-метрики считаем только там, где есть золото адресов (12 писем корпуса)
        has_ioc_gold = bool(gold.get("ips") or gold.get("domains"))

        # --- LLM ---
        if not args.no_llm:
            m_tok = args.max_tokens or (40 if args.stage == "type" else 6000)
            p_text = (full[:args.head] if args.stage == "type" else full[:args.text_cap])
            t0 = time.perf_counter()
            try:
                if args.stage == "type":
                    raw = llm_classify_only(p_text, args.base_url, args.model)
                else:
                    raw = llm_extract_annotated(p_text, args.base_url, args.model, max_tokens=m_tok)
            except Exception as ex:
                print(f"  {name}: LLM error {ex!r}")
                raw = ""
            dt = time.perf_counter() - t0
            row["llm_raw"] = raw[:200]
            n_llm += 1
            llm = parse_llm_json(raw)
            llm_cls, viol = "other", 0
            llm_ips, llm_doms, llm_hashes, llm_emails = set(), set(), set(), set()
            if llm:
                llm_cls = llm["classification"]
                for i in llm["iocs"]["ips"]:
                    ip = norm_ip(i)
                    if ip and _mentions(p_text, i):
                        llm_ips.add(ip)
                    else:
                        viol += 1
                for d in llm["iocs"]["domains"]:
                    dd = clean_domain(d)
                    if dd and len(dd) >= 4 and _mentions(p_text, dd):
                        llm_doms.add(dd)
                    else:
                        viol += 1
                for h in llm["iocs"]["hashes"]:
                    hh = h.strip().lower()
                    if HASH_RE.match(hh) and _mentions(p_text, hh):
                        llm_hashes.add(hh)
                    else:
                        viol += 1
                for e in llm["iocs"]["emails"]:
                    ee = e.strip().lower()
                    if EMAIL_PATTERN.match(ee) and _mentions(p_text, ee):
                        llm_emails.add(ee)
                    else:
                        viol += 1
            if llm_cls not in CLOSED:
                llm_cls = "other"
            print(f"  [{name}] {dt:6.1f}s cl_gold={g_cls} re={re_cls} llm={llm_cls} "
                  f"{'OK' if llm_cls == g_cls else 'MISS'} | "
                  f"ip re={len(re_ips)}/llm={len(llm_ips)}/{len(g_ips)} "
                  f"dom re={len(re_doms)}/llm={len(llm_doms)}/{len(g_doms)} "
                  f"hash re={len(re_hashes)}/llm={len(llm_hashes)} viol={viol}")
            row["llm_class"] = llm_cls
            row["n_viol"] = viol
            row["n_ips"]["llm"] = len(llm_ips)
            row["n_doms"]["llm"] = len(llm_doms)
            row["n_hashes"]["llm"] = len(llm_hashes)
            row["llm_iocs"] = {"ips": sorted(llm_ips), "domains": sorted(llm_doms),
                               "hashes": sorted(llm_hashes), "emails": sorted(llm_emails)}
            n_viol += viol
            acc_llm += int(llm_cls == g_cls)

            for kind, pred, gold_s, gold2 in (("ip", llm_ips, g_ips, gf_ips),
                                               ("domain", llm_doms, g_doms, gf_doms)):
                if not has_ioc_gold:
                    continue
                e = set_f1(pred, gold_s)
                e2 = set_f1(pred, gold2, cover=True)
                io[kind]["llm"][0] += e["tp"]; io[kind]["llm"][1] += e["fp"]; io[kind]["llm"][2] += e["fn"]
                if kind == "domain":
                    io[kind + "_full"]["llm"][0] += e2["tp"]; io[kind + "_full"]["llm"][1] += e2["fp"]; io[kind + "_full"]["llm"][2] += e2["fn"]
            if args.stage != "type":
                total_llm_hash += len(llm_hashes)
                hash_agree += len(llm_hashes & re_hashes)

        for kind, pred, gold_s, gold2 in (("ip", re_ips, g_ips, gf_ips),
                                         ("domain", re_doms, g_doms, gf_doms)):
            if not has_ioc_gold or args.stage == "type":
                continue
            e = set_f1(pred, gold_s)
            e2 = set_f1(pred, gold2, cover=True)
            io[kind]["re"][0] += e["tp"]; io[kind]["re"][1] += e["fp"]; io[kind]["re"][2] += e["fn"]
            if kind == "domain":
                io[kind + "_full"]["re"][0] += e2["tp"]; io[kind + "_full"]["re"][1] += e2["fp"]; io[kind + "_full"]["re"][2] += e2["fn"]
        if args.stage != "type":
            total_re_hash += len(re_hashes)

        rows.append(row)

    # гибрид: объединение regex ∪ LLM (после анти-галлюцинации LLM)
    u_tot = {"ip": [0, 0, 0], "domain": [0, 0, 0]}
    for r in rows:
        if r["llm_class"] == "n/a":
            continue
        if not (r["gold_iocs"]["ips"] or r["gold_iocs"]["domains"]):
            continue
        for kind, key in (("ip", "ips"), ("domain", "domains")):
            u = set(r["re_iocs"][key]) | set(r["llm_iocs"].get(key, []))
            e = set_f1(u, set(r["gold_iocs"][key]))
            u_tot[kind][0] += e["tp"]; u_tot[kind][1] += e["fp"]; u_tot[kind][2] += e["fn"]

    n = sum(1 for r in rows if r["llm_class"] != "n/a")
    print(f"cases={len(rows)}  (llm={n})")
    print(f"CLASS regex acc={acc_re/len(rows):.3f}  llm acc={acc_llm/n if n else float('nan'):.3f}")
    for kind in ("ip", "domain"):
        for src in ("re", "llm"):
            m = agg(io[kind][src])
            print(f"  IoC {kind:7} {src:3} P/R/F1={m['p']}/{m['r']}/{m['f1']}  (tp/fp/fn={m['tp']}/{m['fp']}/{m['fn']})")
        mu = agg(u_tot[kind])
        print(f"  IoC {kind:7} union P/R/F1={mu['p']}/{mu['r']}/{mu['f1']}  (tp/fp/fn={mu['tp']}/{mu['fp']}/{mu['fn']})")
    print(f"  domain_full(cover): re={agg(io['domain_full']['re'])} llm={agg(io['domain_full']['llm'])}")
    print(f"  hashes: regex_total={total_re_hash} llm_total={total_llm_hash} overlap={hash_agree}")
    print(f"  llm violations (выдумано): {n_viol}")

    out = {
        "model": args.model, "base_url": args.base_url,
        "classification": {"regex_acc": round(acc_re / len(rows), 4),
                           "llm_acc": round(acc_llm / n, 4) if n else None},
        "ioc": {"ip": {"regex": agg(io["ip"]["re"]), "llm": agg(io["ip"]["llm"]), "union": agg(u_tot["ip"])},
                "domain": {"regex": agg(io["domain"]["re"]), "llm": agg(io["domain"]["llm"]), "union": agg(u_tot["domain"])}},
        "ioc_full": {"domain": {"regex": agg(io["domain_full"]["re"]), "llm": agg(io["domain_full"]["llm"])}},
        "hashes": {"regex_total": total_re_hash, "llm_total": total_llm_hash, "overlap": hash_agree},
        "llm_violations": n_viol,
        "rows": rows,
    }
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"Report: {out_file}")


if __name__ == "__main__":
    main()
