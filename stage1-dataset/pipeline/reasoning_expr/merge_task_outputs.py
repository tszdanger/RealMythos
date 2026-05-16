#!/usr/bin/env python3
"""Merge completed concurrent task outputs into one dataset directory."""

import argparse
import hashlib
import json
from collections import Counter, OrderedDict
from pathlib import Path
import time


STAGE_FILES = [
    "case_results.jsonl",
    "context_aug_results.jsonl",
    "context_rejects.jsonl",
    "distill_results.jsonl",
    "poc_eval_results.jsonl",
    "reasoning_rewrite_results.jsonl",
    "training_data.jsonl",
    "failures.jsonl",
    "qwen_baseline_results.jsonl",
    "qwen_poc_eval_results.jsonl",
]


def timestamp():
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path):
    if not path.exists():
        return []
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Malformed JSONL in {path}:{line_no}: {exc}") from exc
    return rows


def write_jsonl(path: Path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def row_key(row: dict):
    for key in ("record_id", "id"):
        value = row.get(key)
        if value:
            return str(value)
    cve = row.get("cve") or "unknown"
    pair_idx = row.get("pair_idx")
    return f"{cve}:pair{pair_idx}"


def ordered_unique(rows):
    latest = OrderedDict()
    duplicates = 0
    for row in rows:
        key = row_key(row)
        if key in latest:
            duplicates += 1
        latest[key] = row
    return list(latest.values()), duplicates


def task_ids_from_summary(tasks_dir: Path):
    summary = load_json(tasks_dir / "shards_summary.json")
    tasks = summary.get("tasks") or []
    if tasks:
        return [item["task_id"] for item in tasks if item.get("task_id")], summary
    task_ids = sorted(p.name for p in tasks_dir.glob("task_*") if p.is_dir())
    return task_ids, summary


def verify_task_manifest(task_dir: Path, manifest: dict, errors: list):
    input_path = task_dir / "input.jsonl"
    if not input_path.exists():
        errors.append(f"missing task input: {input_path}")
        return

    expected_hash = manifest.get("input_sha256")
    if expected_hash:
        actual_hash = sha256_file(input_path)
        if actual_hash != expected_hash:
            errors.append(
                f"input hash mismatch for {task_dir.name}: "
                f"expected={expected_hash} actual={actual_hash}"
            )

    expected_count = manifest.get("record_count")
    if expected_count is not None:
        actual_count = sum(1 for line in input_path.read_text(encoding="utf-8").splitlines() if line.strip())
        if actual_count != expected_count:
            errors.append(
                f"input record_count mismatch for {task_dir.name}: "
                f"expected={expected_count} actual={actual_count}"
            )


def merge_task_outputs(tasks_dir: Path, outputs_root: Path, output_dir: Path,
                       strict=False, require_training=False):
    task_ids, shards_summary = task_ids_from_summary(tasks_dir)
    if not task_ids:
        raise ValueError(f"No task ids found under {tasks_dir}")

    output_dir.mkdir(parents=True, exist_ok=True)
    merged_by_stage = {name: [] for name in STAGE_FILES}
    task_summaries = []
    errors = []
    aggregate_status = Counter()
    aggregate_sources = Counter()

    for task_id in task_ids:
        task_dir = tasks_dir / task_id
        run_dir = outputs_root / task_id
        manifest = load_json(task_dir / "manifest.json")
        monitor = load_json(run_dir / "monitor.json")

        if not task_dir.exists():
            errors.append(f"missing task dir: {task_dir}")
        else:
            verify_task_manifest(task_dir, manifest, errors)

        if not run_dir.exists():
            errors.append(f"missing output dir: {run_dir}")
            task_summaries.append({
                "task_id": task_id,
                "status": "missing_output",
                "expected_records": manifest.get("record_count"),
            })
            continue

        status = monitor.get("status", "missing_monitor")
        if strict and status != "done":
            errors.append(f"{task_id} monitor status is {status}, expected done")

        stage_counts = {}
        for filename in STAGE_FILES:
            rows = load_jsonl(run_dir / filename)
            merged_by_stage[filename].extend(rows)
            stage_counts[filename] = len(rows)

        case_rows = load_jsonl(run_dir / "case_results.jsonl")
        failure_rows = load_jsonl(run_dir / "failures.jsonl")
        unique_case_rows, case_duplicates = ordered_unique(case_rows)
        for row in unique_case_rows:
            aggregate_status[row.get("status", "unknown")] += 1
            if row.get("source_name"):
                aggregate_sources[row.get("source_name")] += 1

        expected_count = manifest.get("record_count")
        if strict and expected_count is not None and len(unique_case_rows) != expected_count:
            errors.append(
                f"{task_id} has {len(unique_case_rows)} unique case result(s), "
                f"expected {expected_count}"
            )
        if strict and monitor.get("failed", 0):
            errors.append(f"{task_id} monitor reports failed={monitor.get('failed')}")
        if strict and failure_rows:
            errors.append(f"{task_id} has {len(failure_rows)} failure row(s)")
        if require_training and not stage_counts.get("training_data.jsonl"):
            errors.append(f"{task_id} has no training_data.jsonl rows")

        task_summaries.append({
            "task_id": task_id,
            "status": status,
            "expected_records": manifest.get("record_count"),
            "unique_case_results": len(unique_case_rows),
            "duplicate_case_results": case_duplicates,
            "monitor": {
                "total": monitor.get("total"),
                "completed": monitor.get("completed"),
                "context_rejected": monitor.get("context_rejected"),
                "failed": monitor.get("failed"),
                "skipped_success": monitor.get("skipped_success"),
                "skipped_failed": monitor.get("skipped_failed"),
            },
            "stage_counts": stage_counts,
            "output_dir": str(run_dir),
        })

    output_counts = {}
    duplicate_counts = {}
    for filename, rows in merged_by_stage.items():
        unique_rows, duplicates = ordered_unique(rows)
        write_jsonl(output_dir / filename, unique_rows)
        output_counts[filename] = len(unique_rows)
        duplicate_counts[filename] = duplicates

    summary = {
        "created_at": timestamp(),
        "tasks_dir": str(tasks_dir),
        "outputs_root": str(outputs_root),
        "output_dir": str(output_dir),
        "task_count": len(task_ids),
        "source_dataset": shards_summary.get("input"),
        "source_dataset_sha256": shards_summary.get("input_sha256"),
        "expected_records": shards_summary.get("total_records"),
        "aggregate_case_status": dict(sorted(aggregate_status.items())),
        "aggregate_sources": dict(sorted(aggregate_sources.items())),
        "output_counts": output_counts,
        "duplicate_rows_removed": duplicate_counts,
        "strict": strict,
        "require_training": require_training,
        "ok": not errors,
        "errors": errors,
        "tasks": task_summaries,
    }
    (output_dir / "merge_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    if errors and strict:
        raise ValueError(json.dumps(summary, ensure_ascii=False, indent=2))
    return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tasks-dir", required=True, help="Directory containing task_* manifests")
    parser.add_argument("--outputs-root", required=True, help="Directory containing task_* output folders")
    parser.add_argument("--output-dir", required=True, help="Merged output directory")
    parser.add_argument("--strict", action="store_true", help="Fail if any task is incomplete or has failures")
    parser.add_argument("--require-training", action="store_true", help="Fail if any task has no training_data rows")
    args = parser.parse_args()

    summary = merge_task_outputs(
        Path(args.tasks_dir),
        Path(args.outputs_root),
        Path(args.output_dir),
        strict=args.strict,
        require_training=args.require_training,
    )
    printable = {k: v for k, v in summary.items() if k != "tasks"}
    print(json.dumps(printable, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
