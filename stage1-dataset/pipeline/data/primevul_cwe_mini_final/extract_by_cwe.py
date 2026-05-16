#!/usr/bin/env python3
"""Build a CWE-balanced mini subset from PrimeVul JSONL split files."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Select 1-N PrimeVul cases for each CWE bucket."
    )
    parser.add_argument(
        "--input",
        nargs="+",
        default=["data/primevul_train_paired.jsonl"],
        help=(
            "One or more PrimeVul JSONL files. For the full original release, "
            "pass train, valid, and test JSONL files together."
        ),
    )
    parser.add_argument(
        "--output-dir",
        default="data/primevul_cwe_mini",
        help="Directory where the mini dataset and summary are written.",
    )
    parser.add_argument(
        "--mode",
        choices=("single", "paired-adjacent"),
        default="single",
        help=(
            "single: sample individual records. paired-adjacent: sample "
            "adjacent vulnerable/fixed pairs from *_paired.jsonl files."
        ),
    )
    parser.add_argument(
        "--target",
        choices=("1", "0", "any"),
        default="1",
        help="Target label to sample in single mode.",
    )
    parser.add_argument(
        "--cases-per-cwe",
        type=int,
        default=2,
        help="Maximum number of cases to keep per CWE.",
    )
    parser.add_argument(
        "--strategy",
        choices=("shortest", "first"),
        default="shortest",
        help="Selection strategy inside each CWE bucket.",
    )
    return parser.parse_args()


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if line:
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Invalid JSON at {path}:{line_no}: {exc}") from exc
                record["_source_file"] = str(path)
                record["_source_line"] = line_no
                records.append(record)
    return records


def normalize_cwes(value: Any) -> list[str]:
    if value is None:
        return ["<missing>"]
    if isinstance(value, list):
        raw_values = value
    elif isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return ["<missing>"]
        if stripped.startswith("[") and stripped.endswith("]"):
            try:
                parsed = json.loads(stripped)
                raw_values = parsed if isinstance(parsed, list) else [parsed]
            except json.JSONDecodeError:
                raw_values = [stripped]
        elif "," in stripped:
            raw_values = stripped.split(",")
        else:
            raw_values = [stripped]
    else:
        raw_values = [value]

    cwes = [str(cwe).strip() for cwe in raw_values if str(cwe).strip()]
    return cwes or ["<missing>"]


def public_record(record: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in record.items() if not k.startswith("_")}


def cwe_sort_key(cwe: str) -> tuple[int, int | str]:
    prefix = "CWE-"
    if cwe.startswith(prefix):
        suffix = cwe[len(prefix) :]
        if suffix.isdigit():
            return (0, int(suffix))
    return (1, cwe)


def target_matches(record: dict[str, Any], target: str) -> bool:
    if target == "any":
        return True
    return str(record.get("target")) == target


def is_valid_pair(vuln: dict[str, Any], fixed: dict[str, Any]) -> bool:
    return (
        vuln.get("target") == 1
        and fixed.get("target") == 0
        and vuln.get("cve") == fixed.get("cve")
        and vuln.get("commit_id") == fixed.get("commit_id")
        and normalize_cwes(vuln.get("cwe")) == normalize_cwes(fixed.get("cwe"))
    )


def case_sort_key(case: dict[str, Any], strategy: str) -> tuple[Any, ...]:
    if strategy == "shortest":
        if "record" in case:
            func_len = len(case["record"].get("func") or "")
            return (func_len, case["source_order"])
        vuln_len = len(case["vuln"].get("func") or "")
        fixed_len = len(case["fixed"].get("func") or "")
        return (vuln_len + fixed_len, vuln_len, case["source_order"])
    return (case["source_order"],)


def build_single_cases(
    inputs: list[Path], target: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    cases: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    total_records = 0
    source_order = 0

    for input_path in inputs:
        records = load_jsonl(input_path)
        total_records += len(records)
        for record in records:
            if not target_matches(record, target):
                continue
            cwes = normalize_cwes(record.get("cwe"))
            if cwes == ["<missing>"]:
                skipped.append(
                    {
                        "source_file": record["_source_file"],
                        "source_line": record["_source_line"],
                        "idx": record.get("idx"),
                        "reason": "missing_cwe",
                    }
                )
                continue
            cases.append(
                {
                    "source_order": source_order,
                    "source_file": record["_source_file"],
                    "source_line": record["_source_line"],
                    "record": public_record(record),
                    "cwes": cwes,
                }
            )
            source_order += 1

    return cases, skipped, total_records


def build_paired_cases(
    inputs: list[Path],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    cases: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    total_records = 0
    source_order = 0

    for input_path in inputs:
        records = load_jsonl(input_path)
        total_records += len(records)
        for record_offset in range(0, len(records), 2):
            if record_offset + 1 >= len(records):
                skipped.append(
                    {
                        "source_file": str(input_path),
                        "source_pair_index": record_offset // 2,
                        "reason": "missing_fixed_record",
                        "vuln_idx": records[record_offset].get("idx"),
                    }
                )
                continue

            vuln = records[record_offset]
            fixed = records[record_offset + 1]
            source_pair_index = record_offset // 2

            if is_valid_pair(vuln, fixed):
                cases.append(
                    {
                        "source_order": source_order,
                        "source_file": str(input_path),
                        "source_pair_index": source_pair_index,
                        "vuln_source_line": vuln["_source_line"],
                        "fixed_source_line": fixed["_source_line"],
                        "vuln": public_record(vuln),
                        "fixed": public_record(fixed),
                        "cwes": normalize_cwes(vuln.get("cwe")),
                    }
                )
                source_order += 1
                continue

            skipped.append(
                {
                    "source_file": str(input_path),
                    "source_pair_index": source_pair_index,
                    "reason": "pair_metadata_mismatch",
                    "vuln_idx": vuln.get("idx"),
                    "fixed_idx": fixed.get("idx"),
                    "vuln_target": vuln.get("target"),
                    "fixed_target": fixed.get("target"),
                    "vuln_cwe": vuln.get("cwe"),
                    "fixed_cwe": fixed.get("cwe"),
                    "vuln_cve": vuln.get("cve"),
                    "fixed_cve": fixed.get("cve"),
                    "vuln_commit_id": vuln.get("commit_id"),
                    "fixed_commit_id": fixed.get("commit_id"),
                }
            )

    return cases, skipped, total_records


def select_by_cwe(
    cases: list[dict[str, Any]],
    cases_per_cwe: int,
    strategy: str,
) -> list[dict[str, Any]]:
    by_cwe: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for case in cases:
        for cwe in case["cwes"]:
            by_cwe[cwe].append(case)

    selected: list[dict[str, Any]] = []
    for cwe in sorted(by_cwe, key=cwe_sort_key):
        bucket = sorted(by_cwe[cwe], key=lambda case: case_sort_key(case, strategy))
        for rank, case in enumerate(bucket[:cases_per_cwe], start=1):
            row = {k: v for k, v in case.items() if k != "cwes"}
            row["selection_cwe"] = cwe
            row["selection_rank"] = rank
            row["case_cwes"] = case["cwes"]
            selected.append(row)
    return selected


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def make_record_rows(selected_cases: list[dict[str, Any]], mode: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for case in selected_cases:
        if mode == "single":
            record = dict(case["record"])
            record["selection_cwe"] = case["selection_cwe"]
            record["selection_rank"] = case["selection_rank"]
            record["case_cwes"] = case["case_cwes"]
            record["source_file"] = case["source_file"]
            record["source_line"] = case["source_line"]
            rows.append(record)
            continue

        for role in ("vuln", "fixed"):
            record = dict(case[role])
            record["selection_cwe"] = case["selection_cwe"]
            record["selection_rank"] = case["selection_rank"]
            record["case_cwes"] = case["case_cwes"]
            record["source_file"] = case["source_file"]
            record["source_pair_index"] = case["source_pair_index"]
            record["source_line"] = case[f"{role}_source_line"]
            rows.append(record)
    return rows


def make_command(args: argparse.Namespace) -> str:
    return (
        "python3 data/primevul_cwe_mini_final/extract_by_cwe.py "
        f"--input {' '.join(args.input)} "
        f"--output-dir {args.output_dir} "
        f"--mode {args.mode} "
        f"--target {args.target} "
        f"--cases-per-cwe {args.cases_per_cwe} "
        f"--strategy {args.strategy}"
    )


def make_summary(
    inputs: list[Path],
    total_records: int,
    valid_cases: list[dict[str, Any]],
    skipped: list[dict[str, Any]],
    selected_cases: list[dict[str, Any]],
    selected_records: list[dict[str, Any]],
    args: argparse.Namespace,
    output_files: dict[str, Path],
) -> dict[str, Any]:
    valid_cwe_counts: Counter[str] = Counter()
    for case in valid_cases:
        for cwe in case["cwes"]:
            valid_cwe_counts[cwe] += 1

    selected_cwe_counts: Counter[str] = Counter(
        case["selection_cwe"] for case in selected_cases
    )
    selected_rows = [
        {
            "cwe": cwe,
            "available_valid_cases": valid_cwe_counts[cwe],
            "selected_cases": selected_cwe_counts[cwe],
        }
        for cwe in sorted(selected_cwe_counts, key=cwe_sort_key)
    ]

    return {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "command": make_command(args),
        "input_paths": [str(path) for path in inputs],
        "mode": args.mode,
        "target": args.target if args.mode == "single" else None,
        "strategy": args.strategy,
        "cases_per_cwe": args.cases_per_cwe,
        "input_records": total_records,
        "valid_cases": len(valid_cases),
        "skipped_cases": len(skipped),
        "valid_cwe_count": len(valid_cwe_counts),
        "selected_cwe_count": len(selected_cwe_counts),
        "selected_cases": len(selected_cases),
        "selected_records": len(selected_records),
        "selected_cwe_distribution": selected_rows,
        "output_files": {name: str(path) for name, path in output_files.items()},
    }


def write_markdown_summary(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# PrimeVul CWE Mini Dataset",
        "",
        "## Reproducibility",
        "",
        f"- Command: `{summary['command']}`",
        f"- Inputs: `{', '.join(summary['input_paths'])}`",
        f"- Mode: `{summary['mode']}`",
        f"- Target: `{summary['target']}`",
        f"- Strategy: `{summary['strategy']}`",
        f"- Max cases per CWE: `{summary['cases_per_cwe']}`",
        "",
        "## Counts",
        "",
        f"- Input records: {summary['input_records']}",
        f"- Valid cases: {summary['valid_cases']}",
        f"- Skipped cases: {summary['skipped_cases']}",
        f"- Covered CWE buckets: {summary['selected_cwe_count']}",
        f"- Selected cases: {summary['selected_cases']}",
        f"- Selected records: {summary['selected_records']}",
        "",
        "## Output Files",
        "",
    ]
    for name, file_path in summary["output_files"].items():
        lines.append(f"- `{name}`: `{file_path}`")

    lines.extend(
        [
            "",
            "## CWE Distribution",
            "",
            "| CWE | Available valid cases | Selected cases |",
            "|---|---:|---:|",
        ]
    )
    for row in summary["selected_cwe_distribution"]:
        lines.append(
            f"| {row['cwe']} | {row['available_valid_cases']} | "
            f"{row['selected_cases']} |"
        )

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    args = parse_args()
    if args.cases_per_cwe < 1:
        raise ValueError("--cases-per-cwe must be at least 1")

    inputs = [Path(input_path) for input_path in args.input]
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.mode == "single":
        valid_cases, skipped, total_records = build_single_cases(inputs, args.target)
    else:
        valid_cases, skipped, total_records = build_paired_cases(inputs)

    selected_cases = select_by_cwe(valid_cases, args.cases_per_cwe, args.strategy)
    selected_records = make_record_rows(selected_cases, args.mode)

    output_files = {
        "selected_cases_jsonl": output_dir / "primevul_cwe_mini_cases.jsonl",
        "primevul_records_jsonl": output_dir / "primevul_cwe_mini_records.jsonl",
        "summary_json": output_dir / "summary.json",
        "summary_md": output_dir / "SUMMARY.md",
        "skipped_cases_jsonl": output_dir / "skipped_cases.jsonl",
    }

    write_jsonl(output_files["selected_cases_jsonl"], selected_cases)
    write_jsonl(output_files["primevul_records_jsonl"], selected_records)
    write_jsonl(output_files["skipped_cases_jsonl"], skipped)

    summary = make_summary(
        inputs=inputs,
        total_records=total_records,
        valid_cases=valid_cases,
        skipped=skipped,
        selected_cases=selected_cases,
        selected_records=selected_records,
        args=args,
        output_files=output_files,
    )
    output_files["summary_json"].write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    write_markdown_summary(output_files["summary_md"], summary)

    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
