import json, pathlib

d = json.loads(pathlib.Path("data/quality/check_e2e.json").read_text("utf-8"))
rows = d["rows"]

latest = {}
for r in rows:
    latest[r["id"]] = r

old = {
    "9-70": 0.544, "9-77": 0.8, "9-78": 0.853, "9-81": 0.796, "9-85": 0.774,
    "9-89": 0.887, "9-93": 0.86, "9-99": 0.846, "9-104": 0.847, "9-107": 0.95,
    "9-113": 0.884, "9-118": 0.939,
    "9-114": 0.156, "9-119": 0.125, "9-121": 0.168, "9-126": 0.132,
    "9-132": 0.163, "9-137": 0.138, "9-145": 0.092, "9-148": 0.12,
    "9-152": 0.153, "9-157": 0.143,
}

order = ["9-70", "9-77",
         "9-78", "9-81", "9-85", "9-89", "9-93", "9-99", "9-104", "9-107", "9-113", "9-118",
         "9-114", "9-119", "9-121", "9-126", "9-132", "9-137", "9-145", "9-148", "9-152", "9-157"]

header = f"{'ID':<8} {'TYPE':<14} {'OLD':>6} {'NEW':>6} {'DELTA':>7} {'KW':>6}"
print(header)
print("-" * len(header))
for cid in order:
    r = latest.get(cid)
    if not r:
        continue
    o = old.get(cid, 0)
    n = r.get("ratio", 0)
    delta = n - o
    kw = r.get("keyword_match", "")
    lt = r.get("letter_type", "?")
    print(f"{cid:<8} {lt:<14} {o:>6.3f} {n:>6.3f} {delta:>+7.3f} {kw:>6}")

vh = [r for r in latest.values() if r.get("letter_type") == "vulnerability"]
ha = [r for r in latest.values() if r.get("letter_type") == "hacker"]
co = [r for r in latest.values() if r.get("letter_type") == "compromise"]
print()
print(f"AVG vulnerability: {sum(r.get('ratio', 0) for r in vh)/len(vh):.3f} (was 0.139)")
print(f"AVG hacker:        {sum(r.get('ratio', 0) for r in ha)/len(ha):.3f} (was 0.835)")
print(f"AVG compromise:    {sum(r.get('ratio', 0) for r in co)/len(co):.3f} (was 0.800)")
print(f"Total:             {(sum(r.get('ratio',0) for r in latest.values()))/len(latest):.3f}")
