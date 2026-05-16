#!/usr/bin/env python3
"""Split a curated JSONL dataset into small task packages.

Each task package is a directory containing input.jsonl and manifest.json. The
pipeline runner can process one task package independently with its own API key,
rate limiter, output directory, and retry policy.
"""

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
import time


def timestamp():
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_jsonl(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            record.setdefault("_input_line", line_no)
            yield record


def write_jsonl(path: Path, rows):
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def build_shards(input_path: Path, output_dir: Path, shard_size: int,
                 max_records=None, overwrite=False):
    source_sha256 = sha256_file(input_path)
    all_records = list(load_jsonl(input_path))
    records = all_records
    if max_records is not None:
        records = records[:max_records]

    output_dir.mkdir(parents=True, exist_ok=True)
    shards = []

    for shard_idx, start in enumerate(range(0, len(records), shard_size)):
        shard_records = records[start:start + shard_size]
        task_dir = output_dir / f"task_{shard_idx:06d}"
        input_file = task_dir / "input.jsonl"
        manifest_file = task_dir / "manifest.json"

        if task_dir.exists() and not overwrite:
            raise FileExistsError(
                f"Task directory already exists: {task_dir}. "
                "Use --overwrite to replace shard files."
            )
        task_dir.mkdir(parents=True, exist_ok=True)

        write_jsonl(input_file, shard_records)
        input_sha256 = sha256_file(input_file)

        source_counts = Counter(r.get("source", "unknown") for r in shard_records)
        cves = [r.get("cve") for r in shard_records if r.get("cve")]
        manifest = {
            "task_id": task_dir.name,
            "input_file": str(input_file),
            "source_dataset": str(input_path),
            "source_dataset_sha256": source_sha256,
            "shard_index": shard_idx,
            "shard_size": shard_size,
            "record_count": len(shard_records),
            "input_sha256": input_sha256,
            "start_offset": start,
            "end_offset_exclusive": start + len(shard_records),
            "source_counts": dict(sorted(source_counts.items())),
            "first_cve": cves[0] if cves else None,
            "last_cve": cves[-1] if cves else None,
            "created_at": timestamp(),
        }
        manifest_file.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        shards.append(manifest)

    summary = {
        "input": str(input_path),
        "input_sha256": source_sha256,
        "output_dir": str(output_dir),
        "source_dataset_record_count": len(all_records),
        "total_records": len(records),
        "shard_size": shard_size,
        "task_count": len(shards),
        "created_at": timestamp(),
        "tasks": [
            {
                "task_id": item["task_id"],
                "input_file": item["input_file"],
                "input_sha256": item["input_sha256"],
                "record_count": item["record_count"],
                "start_offset": item["start_offset"],
                "end_offset_exclusive": item["end_offset_exclusive"],
                "source_counts": item["source_counts"],
                "first_cve": item["first_cve"],
                "last_cve": item["last_cve"],
            }
            for item in shards
        ],
    }
    (output_dir / "shards_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return summary


def count_jsonl_rows(path: Path) -> int:
    rows = 0
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows += 1
    return rows


def resolve_input_file(task_dir: Path, manifest: dict) -> Path:
    input_file = Path(manifest.get("input_file") or "")
    if input_file.exists():
        return input_file
    return task_dir / "input.jsonl"


def verify_shards(output_dir: Path) -> dict:
    summary_path = output_dir / "shards_summary.json"
    if not summary_path.exists():
        raise FileNotFoundError(f"Missing shards summary: {summary_path}")

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    errors = []
    checked_tasks = 0
    checked_records = 0

    source_path = Path(summary.get("input") or "")
    expected_source_hash = summary.get("input_sha256")
    if source_path.exists() and expected_source_hash:
        actual_source_hash = sha256_file(source_path)
        if actual_source_hash != expected_source_hash:
            errors.append({
                "file": str(source_path),
                "field": "input_sha256",
                "expected": expected_source_hash,
                "actual": actual_source_hash,
            })

    task_ids = [item.get("task_id") for item in summary.get("tasks", []) if item.get("task_id")]
    if not task_ids:
        task_ids = sorted(p.name for p in output_dir.glob("task_*") if p.is_dir())

    for task_id in task_ids:
        task_dir = output_dir / task_id
        manifest_path = task_dir / "manifest.json"
        if not manifest_path.exists():
            errors.append({"file": str(manifest_path), "error": "missing_manifest"})
            continue
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        input_file = resolve_input_file(task_dir, manifest)
        if not input_file.exists():
            errors.append({"file": str(input_file), "error": "missing_input"})
            continue

        actual_hash = sha256_file(input_file)
        expected_hash = manifest.get("input_sha256")
        if expected_hash and actual_hash != expected_hash:
            errors.append({
                "file": str(input_file),
                "field": "input_sha256",
                "expected": expected_hash,
                "actual": actual_hash,
            })

        actual_rows = count_jsonl_rows(input_file)
        expected_rows = manifest.get("record_count")
        if expected_rows is not None and actual_rows != expected_rows:
            errors.append({
                "file": str(input_file),
                "field": "record_count",
                "expected": expected_rows,
                "actual": actual_rows,
            })

        checked_tasks += 1
        checked_records += actual_rows

    expected_total = summary.get("total_records")
    if expected_total is not None and checked_records != expected_total:
        errors.append({
            "file": str(summary_path),
            "field": "total_records",
            "expected": expected_total,
            "actual": checked_records,
        })

    result = {
        "output_dir": str(output_dir),
        "summary": str(summary_path),
        "checked_tasks": checked_tasks,
        "checked_records": checked_records,
        "ok": not errors,
        "errors": errors,
    }
    if errors:
        raise ValueError(json.dumps(result, ensure_ascii=False, indent=2))
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default=None, help="Input selected_records.jsonl")
    parser.add_argument("--output-dir", required=True, help="Directory for task_* shards")
    parser.add_argument("--shard-size", type=int, default=100, help="Records per task package")
    parser.add_argument("--max-records", type=int, default=None, help="Optional cap for pilot sharding")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing task shard files")
    parser.add_argument("--verify-only", action="store_true", help="Verify existing shard manifests and hashes")
    args = parser.parse_args()

    if args.verify_only:
        result = verify_shards(Path(args.output_dir))
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    if not args.input:
        raise ValueError("--input is required unless --verify-only is set")
    if args.shard_size <= 0:
        raise ValueError("--shard-size must be positive")

    summary = build_shards(
        Path(args.input),
        Path(args.output_dir),
        args.shard_size,
        max_records=args.max_records,
        overwrite=args.overwrite,
    )
    printable = {k: v for k, v in summary.items() if k != "tasks"}
    print(json.dumps(printable, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
