"""Offline evaluation of archived LLM decisions on a shared scanner pool."""

import json
import random
from collections import defaultdict
from pathlib import Path
from statistics import mean

FAMILIES = {
    89: {943, 564},
    79: {80, 83, 116},
    78: {77, 88},
    22: {23, 36, 73},
    798: {259, 321, 522},
    327: {326, 328, 916},
    502: {915},
    330: {338},
    95: {94, 77},
}


def cwe(value):
    digits = "".join(c for c in str(value) if c.isdigit())
    return int(digits) if digits else None


def key(f):
    return f["file"], f["line_start"], cwe(f["cwe"])


def evaluate(findings, seeds):
    # One seed can close one finding; repeated tool rules at one location collapse.
    unique = {key(f): f for f in findings}
    candidates = []
    for fk, f in unique.items():
        for seed in seeds:
            distance = abs(f["line_start"] - seed["line"])
            if f["file"] == seed["file"] and distance <= 3:
                exact = cwe(f["cwe"]) == seed["cwe"]
                family = cwe(f["cwe"]) in FAMILIES.get(seed["cwe"], set())
                if exact or family:
                    candidates.append((not exact, distance, seed["id"], fk))
    matched, used = set(), set()
    for _, _, sid, fk in sorted(candidates):
        if sid not in matched and fk not in used:
            matched.add(sid)
            used.add(fk)
    tp, fp, fn = len(matched), len(unique) - len(used), len(seeds) - len(matched)
    p = tp / (tp + fp) if tp + fp else None
    r = tp / (tp + fn) if tp + fn else None
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": p,
        "recall": r,
        "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
        "matched_seed_ids": sorted(matched),
        "findings": len(unique),
    }


def keep_single(record):
    return record["verdict"] != "false_positive"


def keep_consensus(finding, votes):
    # High/Critical always go to a human. Missing votes retain the finding.
    return (
        (finding.get("severity") or "").lower() in {"high", "critical"}
        or len(votes) != 3
        or any(v != "false_positive" for v in votes)
    )


def paired_intervals(baseline, model, seeds, iterations=1000):
    files = sorted({s["file"] for s in seeds} | {f["file"] for f in baseline})
    rng = random.Random(42)  # noqa: S311 - reproducible statistical resampling
    values = {k: [] for k in ("precision", "recall", "f1")}
    for _ in range(iterations):
        sampled = rng.choices(files, k=len(files))

        def clone(rows, is_seed=False, sampled=sampled):
            result = []
            for i, file in enumerate(sampled):
                for row in rows:
                    if row["file"] == file:
                        new = {**row, "file": f"{i}/{file}"}
                        if is_seed:
                            new["id"] = f"{i}/{row['id']}"
                        result.append(new)
            return result

        a = evaluate(clone(baseline), clone(seeds, True))
        b = evaluate(clone(model), clone(seeds, True))
        for k in values:
            if a[k] is not None and b[k] is not None:
                values[k].append(b[k] - a[k])
    return {
        k: {
            "delta_ci95": [
                sorted(v)[int(0.025 * len(v))],
                sorted(v)[min(len(v) - 1, int(0.975 * len(v)))],
            ],
            "valid_samples": len(v),
        }
        for k, v in values.items()
        if v
    }


def run():
    data = json.loads(Path("data/hw3/experiment.json").read_text())
    seeds, runs = data["seeds"], data["runs"]
    pools = [{r["finding"]["id"] for r in run["records"]} for run in runs]
    if not all(pool == pools[0] for pool in pools):
        raise ValueError("Runs must contain the same finding IDs")
    for run in runs:
        if len(run["records"]) != len(pools[0]):
            raise ValueError("Duplicate finding ID")
    first = {r["finding"]["id"]: r["finding"] for r in runs[0]["records"]}
    votes = defaultdict(list)
    for run in runs:
        for row in run["records"]:
            if row["finding"] != first[row["finding"]["id"]]:
                raise ValueError("Finding changed between runs")
            votes[row["finding"]["id"]].append(row["verdict"])
    baseline = evaluate(list(first.values()), seeds)
    single = [
        evaluate([r["finding"] for r in run["records"] if keep_single(r)], seeds) for run in runs
    ]
    kept = [f for fid, f in first.items() if keep_consensus(f, votes[fid])]
    consensus = evaluate(kept, seeds)
    by_cwe = {}
    for code in sorted(
        {s["cwe"] for s in seeds} | {cwe(f["cwe"]) for f in first.values()} - {None}
    ):
        group = [s for s in seeds if s["cwe"] == code]
        # Family matching is intentionally disabled in these per-CWE slices.
        by_cwe[str(code)] = {
            "baseline": evaluate([f for f in first.values() if cwe(f["cwe"]) == code], group),
            "consensus": evaluate([f for f in kept if cwe(f["cwe"]) == code], group),
        }
    report = {
        "scope": {
            "language": "python",
            "seeds": len(seeds),
            "scanner_records": len(first),
            "model": runs[0]["model"],
            "evaluation": "archived decisions; no API calls",
        },
        "baseline": baseline,
        "single_pass_runs": single,
        "single_pass_mean": {k: mean(r[k] for r in single) for k in ("precision", "recall", "f1")},
        "consensus": consensus,
        "by_cwe": by_cwe,
        "lost_seed_ids": sorted(
            set(baseline["matched_seed_ids"]) - set(consensus["matched_seed_ids"])
        ),
    }
    report["paired_file_bootstrap"] = paired_intervals(list(first.values()), kept, seeds)
    calls = data["calls"]
    report["archived_call_usage"] = {
        "calls": len(calls),
        "input_tokens": sum(c["usage"]["input"] for c in calls),
        "output_tokens": sum(c["usage"]["output"] for c in calls),
        "latency_seconds": [c["latency_sec"] for c in calls],
        "note": "batch-call timings, not per-finding or total scanner time",
    }
    Path("reports/hw3_metrics.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k not in {"by_cwe"}}, indent=2))


if __name__ == "__main__":
    run()
