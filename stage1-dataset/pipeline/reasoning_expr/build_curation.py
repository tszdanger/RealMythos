#!/usr/bin/env python3
"""Build a CVE-level curated dataset from prioritized data sources.

The first source that contributes a CVE wins. Later, lower-priority sources are
recorded in the registry but their records are not selected for generation.
"""

import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from data_source import (
    CVEfixesSource,
    DiverseVulSource,
    MegaVulSource,
    PrimeVulSource,
    ReposVulSource,
)


SOURCE_CLASSES = {
    "primevul": PrimeVulSource,
    "megavul": MegaVulSource,
    "reposvul": ReposVulSource,
    "cvefixes": CVEfixesSource,
    "diversevul": DiverseVulSource,
}


def normalize_code(code: str) -> str:
    return re.sub(r"\s+", "", code or "")


def short_hash(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:16]


def function_hash(pair) -> str:
    return short_hash(normalize_code(pair.vuln_func))


def pair_hash(pair) -> str:
    return short_hash(normalize_code(pair.vuln_func) + "\0" + normalize_code(pair.benign_func))


def record_id(source_name: str, pair) -> str:
    return f"{source_name}:pair{pair.pair_idx}:{pair.cve}:{function_hash(pair)}"


def load_source(source_name: str, source_path: str):
    source_cls = SOURCE_CLASSES.get(source_name)
    if not source_cls:
        raise ValueError(f"Unsupported source '{source_name}'. Available: {sorted(SOURCE_CLASSES)}")
    source = source_cls()
    records = source.load(source_path)
    pairs = source.normalize(records)
    return source, pairs


def selected_record(source_name: str, priority: int, pair) -> dict:
    return {
        "source": source_name,
        "priority": priority,
        "record_id": record_id(source_name, pair),
        "source_pair_idx": pair.pair_idx,
        "cve": pair.cve,
        "cwe": pair.cwe,
        "cve_desc": pair.cve_desc,
        "project": pair.project,
        "function_hash": function_hash(pair),
        "pair_hash": pair_hash(pair),
        "vuln_func": pair.vuln_func,
        "fixed_func": pair.benign_func,
        "raw": pair.raw,
    }


def registry_record(cve: str, selected: dict, seen_sources: dict) -> dict:
    skipped = {}
    for source_name, entries in seen_sources.items():
        skipped[source_name] = [
            {
                "record_id": e["record_id"],
                "source_pair_idx": e["source_pair_idx"],
                "project": e["project"],
                "function_hash": e["function_hash"],
                "pair_hash": e["pair_hash"],
            }
            for e in entries
            if e["record_id"] != selected["record_id"]
        ]

    return {
        "cve": cve,
        "selected_source": selected["source"],
        "selected_record_id": selected["record_id"],
        "selected_priority": selected["priority"],
        "selected_project": selected["project"],
        "selected_function_hash": selected["function_hash"],
        "selected_pair_hash": selected["pair_hash"],
        "seen_sources": sorted(seen_sources),
        "seen_counts": {k: len(v) for k, v in sorted(seen_sources.items())},
        "skipped_records": skipped,
        "decision": "selected_from_highest_priority_source",
    }


def write_jsonl(path: Path, rows: list[dict]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def parse_source_args(values: list[str]) -> list[tuple[str, int, str]]:
    sources = []
    for value in values:
        parts = value.split(":", 2)
        if len(parts) != 3:
            raise ValueError(
                "--source-spec must be formatted as name:priority:path, "
                f"got: {value}"
            )
        name, priority_text, path = parts
        sources.append((name.strip(), int(priority_text), path.strip()))
    return sorted(sources, key=lambda item: item[1], reverse=True)


def load_sources_from_config(path: str) -> list[tuple[str, int, str]]:
    try:
        import yaml
    except ImportError as exc:
        raise ImportError("pyyaml is required for curation config files") from exc

    with open(path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}

    sources = []
    for item in config.get("sources", []):
        sources.append((
            str(item["name"]),
            int(item["priority"]),
            str(item["path"]),
        ))
    if not sources:
        raise ValueError(f"No sources found in curation config: {path}")
    return sorted(sources, key=lambda item: item[1], reverse=True)


def build_curation(sources: list[tuple[str, int, str]], output_dir: Path):
    selected_by_cve = {}
    seen_by_cve = defaultdict(lambda: defaultdict(list))
    source_stats = []

    for source_name, priority, source_path in sources:
        print(f"[source] {source_name} priority={priority} path={source_path}")
        _, pairs = load_source(source_name, source_path)
        selected = skipped_existing = skipped_duplicate_same_source = 0
        seen_in_source = set()

        for pair in pairs:
            cve = (pair.cve or "").strip()
            if not cve or cve == "N/A":
                continue

            rec = selected_record(source_name, priority, pair)
            seen_by_cve[cve][source_name].append(rec)

            if cve in selected_by_cve:
                if selected_by_cve[cve]["source"] == source_name:
                    skipped_duplicate_same_source += 1
                else:
                    skipped_existing += 1
                continue
            if cve in seen_in_source:
                skipped_duplicate_same_source += 1
                continue

            selected_by_cve[cve] = rec
            seen_in_source.add(cve)
            selected += 1

        source_stats.append({
            "source": source_name,
            "priority": priority,
            "path": source_path,
            "normalized_pairs": len(pairs),
            "selected_new_cves": selected,
            "skipped_existing_cves": skipped_existing,
            "skipped_duplicate_same_source": skipped_duplicate_same_source,
        })
        print(
            f"  normalized={len(pairs)} selected={selected} "
            f"skipped_existing={skipped_existing}"
        )

    # Preserve source-priority and source-local order for selected_records.jsonl.
    # This makes --max-pairs sample the highest-priority source first.
    selected_rows = list(selected_by_cve.values())
    registry_rows = [
        registry_record(cve, selected_by_cve[cve], seen_by_cve[cve])
        for cve in sorted(selected_by_cve)
    ]

    selected_path = output_dir / "selected_records.jsonl"
    registry_path = output_dir / "cve_registry.jsonl"
    summary_path = output_dir / "summary.json"
    config_path = output_dir / "source_priority.json"

    write_jsonl(selected_path, selected_rows)
    write_jsonl(registry_path, registry_rows)

    selected_source_counts = Counter(row["source"] for row in selected_rows)
    real_cve_rows = [
        row for row in selected_rows
        if re.match(r"^CVE-\d{4}-\d{4,7}$", str(row.get("cve") or ""), re.IGNORECASE)
    ]
    summary = {
        "total_selected_cves": len(real_cve_rows),
        "total_selected_records": len(selected_rows),
        "real_cve_records": len(real_cve_rows),
        "synthetic_id_records": len(selected_rows) - len(real_cve_rows),
        "selected_source_counts": dict(sorted(selected_source_counts.items())),
        "source_stats": source_stats,
        "outputs": {
            "selected_records": str(selected_path),
            "cve_registry": str(registry_path),
        },
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    config_path.write_text(
        json.dumps(
            {
                "sources": [
                    {"name": n, "priority": p, "path": path}
                    for n, p, path in sources
                ]
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    print("\nCuration summary")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config",
        default="data/curation/source_priority.yaml",
        help="YAML source priority config. Ignored when --source-spec is set.",
    )
    parser.add_argument(
        "--source-spec",
        action="append",
        default=None,
        help="Source spec formatted as name:priority:path. Can be repeated.",
    )
    parser.add_argument(
        "--output-dir",
        default="data/curation/primevul_megavul_reposvul_cvefixes",
        help="Directory for cve_registry.jsonl and selected_records.jsonl",
    )
    args = parser.parse_args()

    if args.source_spec:
        sources = parse_source_args(args.source_spec)
    elif args.config and Path(args.config).exists():
        sources = load_sources_from_config(args.config)
    else:
        sources = parse_source_args([
            "primevul:100:data/primevul_train_paired.jsonl",
            "megavul:80:data/megavul",
            "reposvul:70:data/ReposVul",
            "cvefixes:60:data/cvefixes",
        ])
    build_curation(sources, Path(args.output_dir))


if __name__ == "__main__":
    main()
