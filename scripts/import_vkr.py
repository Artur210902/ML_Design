"""Export allowlisted experiment fields; never copy credentials or source snippets."""

import argparse
import hashlib
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    target = Path("data/hw3")
    target.mkdir(parents=True, exist_ok=True)
    manifest = {}

    def read(relative):
        raw = (args.root / relative).read_bytes()
        manifest[relative] = hashlib.sha256(raw).hexdigest()
        return json.loads(raw)

    ledger = read("benchmark/seeding/ground_truth_multi.json")
    seeds = [
        {k: r[k] for k in ("id", "file", "line", "cwe")}
        for r in ledger["seeds"]
        if r["lang"] == "python"
    ]
    runs = []
    for n in range(1, 4):
        raw = read(f"docs/evidence/config-common-python/2-tools-plus-llm-r{n}.json")
        records = []
        for row in raw["decisions"]:
            f, d = row["finding"], row["decision"]
            records.append(
                {
                    "finding": {
                        k: f.get(k)
                        for k in (
                            "id",
                            "source",
                            "rule_id",
                            "file",
                            "line_start",
                            "line_end",
                            "cwe",
                            "severity",
                            "tool_version",
                        )
                    },
                    "verdict": d.get("verdict", "uncertain"),
                }
            )
        runs.append({"run": n, "model": raw["model"], "records": records})
    journal_path = "docs/evidence/config-common-python/llm-calls.jsonl"
    raw_journal = (args.root / journal_path).read_bytes()
    manifest[journal_path] = hashlib.sha256(raw_journal).hexdigest()
    calls = []
    for line in raw_journal.decode().splitlines():
        row = json.loads(line)
        if row.get("config") == "2-tools-plus-llm":
            calls.append(
                {
                    k: row.get(k)
                    for k in ("ts", "model", "usage", "latency_sec", "attempts", "finish_reason")
                }
            )
    payload = {"schema": 1, "seeds": seeds, "runs": runs, "calls": calls}
    (target / "experiment.json").write_text(json.dumps(payload, indent=2) + "\n")
    (target / "provenance.json").write_text(
        json.dumps(
            {
                "source": "VKR-ANTEI",
                "files_sha256": manifest,
                "export": "allowlisted fields; no source code, explanations, credentials or API endpoints",
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
