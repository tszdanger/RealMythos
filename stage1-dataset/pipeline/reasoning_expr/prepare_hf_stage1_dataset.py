#!/usr/bin/env python3
"""Prepare the public Hugging Face Stage 1 SFT dataset.

This script converts the internal training_data.jsonl into the public schema
planned for RealMythos/RealMythosReasoning.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


DEFAULT_INPUT = Path("results_20260514/01_direct_use/training_data.jsonl")
DEFAULT_OUTPUT = Path("results_20260514/02_huggingface_release/sft_train.jsonl")
DEFAULT_SUMMARY = Path("results_20260514/02_huggingface_release/sft_train_summary.json")

PUBLIC_FIELDS = [
    "cve",
    "cwe",
    "project",
    "label",
    "self_contained",
    "augmented_context",
    "question",
    "reasoning",
    "response",
    "reasoning_source",
    "poc_eval",
    "review_flag",
]

CHINESE_QUESTION_INTRO = (
    "\u5206\u6790\u4ee5\u4e0b C/C++ \u4ee3\u7801\uff0c"
    "\u5224\u65ad\u662f\u5426\u5b58\u5728\u5b89\u5168\u6f0f\u6d1e\u3002\n"
    "\u5982\u679c\u5b58\u5728\uff0c\u8bf7\u5206\u6790\u6f0f\u6d1e\u6839\u56e0\u3001"
    "\u89e6\u53d1\u6761\u4ef6\u3001\u653b\u51fb\u8005\u53ef\u63a7\u8f93\u5165\u3001"
    "\u6570\u636e\u6d41\u8def\u5f84\u3001\u5f71\u54cd\uff0c"
    "\u5e76\u6784\u9020\u4e00\u4e2a\u53ef\u89e6\u53d1 PoC\u3002"
)

ENGLISH_QUESTION_INTRO = (
    "Analyze the following C/C++ code and determine whether it contains a security vulnerability.\n"
    "If a vulnerability exists, explain the root cause, trigger conditions, attacker-controlled inputs, "
    "data-flow path, potential impact, and construct a PoC that can trigger it."
)

CHINESE_CONTEXT_HEADER = "\u3010\u8865\u5145\u4e0a\u4e0b\u6587\u3011"
CHINESE_CODE_HEADER = "\u3010\u5f85\u5206\u6790\u4ee3\u7801\u3011"
POC_REQUIREMENTS_HEADER_RE = re.compile(
    r"\n*\u3010PoC\s*\u9488\u5bf9\u6027\u8981\u6c42\u3011.*\Z",
    re.DOTALL,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Filter internal training_data.jsonl into the public Stage 1 HF dataset."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT,
        help=f"Input internal JSONL file. Default: {DEFAULT_INPUT}",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Output public JSONL file. Default: {DEFAULT_OUTPUT}",
    )
    parser.add_argument(
        "--summary",
        type=Path,
        default=DEFAULT_SUMMARY,
        help=f"Output summary JSON file. Default: {DEFAULT_SUMMARY}",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite output files if they already exist.",
    )
    return parser.parse_args()


def compact_poc_eval(value: Any) -> dict[str, Any] | None:
    """Keep only public PoC evaluation fields."""
    if value is None:
        return None
    if not isinstance(value, dict):
        raise TypeError(f"poc_eval must be an object, got {type(value).__name__}")
    return {
        "analysis": value.get("analysis"),
        "scores": value.get("scores"),
        "total_score": value.get("total_score"),
    }


def clean_question(question: str) -> tuple[str, dict[str, bool]]:
    """Remove internal prompt-routing instructions and normalize public headers."""
    stats = {
        "removed_poc_requirements": False,
        "translated_intro": False,
        "translated_context_header": False,
        "translated_code_header": False,
    }

    if POC_REQUIREMENTS_HEADER_RE.search(question):
        question = POC_REQUIREMENTS_HEADER_RE.sub("", question).rstrip()
        stats["removed_poc_requirements"] = True

    if question.startswith(CHINESE_QUESTION_INTRO):
        question = ENGLISH_QUESTION_INTRO + question[len(CHINESE_QUESTION_INTRO) :]
        stats["translated_intro"] = True

    if CHINESE_CONTEXT_HEADER in question:
        question = question.replace(CHINESE_CONTEXT_HEADER, "### Additional Context")
        stats["translated_context_header"] = True

    if CHINESE_CODE_HEADER in question:
        question = question.replace(CHINESE_CODE_HEADER, "### Code Under Analysis")
        stats["translated_code_header"] = True

    return question.strip(), stats


def convert_record(record: dict[str, Any], line_no: int) -> dict[str, Any]:
    required = [
        "cve",
        "cwe",
        "project",
        "label",
        "self_contained",
        "augmented_context",
        "question",
        "v4_reasoning",
        "v4_response",
        "reasoning_source",
        "poc_eval",
    ]
    missing = [name for name in required if name not in record]
    if missing:
        raise KeyError(f"line {line_no}: missing required fields: {', '.join(missing)}")

    question, _ = clean_question(record["question"])

    return {
        "cve": record["cve"],
        "cwe": record["cwe"],
        "project": record["project"],
        "label": record["label"],
        "self_contained": record["self_contained"],
        "augmented_context": record["augmented_context"],
        "question": question,
        "reasoning": record["v4_reasoning"],
        "response": record["v4_response"],
        "reasoning_source": record["reasoning_source"],
        "poc_eval": compact_poc_eval(record["poc_eval"]),
        "review_flag": record.get("review_flag"),
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    args = parse_args()

    if not args.input.exists():
        raise FileNotFoundError(f"input file does not exist: {args.input}")
    for path in (args.output, args.summary):
        if path.exists() and not args.overwrite:
            raise FileExistsError(f"{path} already exists; pass --overwrite to replace it")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.summary.parent.mkdir(parents=True, exist_ok=True)

    records = 0
    review_flag_count = 0
    cve_set: set[str] = set()
    cwe_counter: Counter[str] = Counter()
    score_counter: Counter[str] = Counter()
    field_counter: Counter[str] = Counter()
    question_cleaning_counter: Counter[str] = Counter()

    with args.input.open("r", encoding="utf-8") as fin, args.output.open(
        "w", encoding="utf-8", newline="\n"
    ) as fout:
        for line_no, line in enumerate(fin, start=1):
            if not line.strip():
                continue
            record = json.loads(line)
            _, cleaning_stats = clean_question(record["question"])
            public_record = convert_record(record, line_no)
            fout.write(json.dumps(public_record, ensure_ascii=False, separators=(",", ":")))
            fout.write("\n")

            records += 1
            cve_set.add(public_record["cve"])
            for cwe in public_record.get("cwe") or []:
                cwe_counter[str(cwe)] += 1
            if public_record.get("review_flag") is not None:
                review_flag_count += 1
            poc_eval = public_record.get("poc_eval") or {}
            score_counter[str(poc_eval.get("total_score"))] += 1
            field_counter.update(public_record.keys())
            for key, changed in cleaning_stats.items():
                if changed:
                    question_cleaning_counter[key] += 1

    summary = {
        "input": str(args.input),
        "output": str(args.output),
        "records": records,
        "unique_cves": len(cve_set),
        "public_fields": PUBLIC_FIELDS,
        "field_presence": dict(field_counter),
        "question_cleaning": dict(question_cleaning_counter),
        "review_flag_count": review_flag_count,
        "top_cwe": cwe_counter.most_common(30),
        "poc_total_score_histogram": dict(sorted(score_counter.items(), key=lambda item: item[0])),
        "output_size_bytes": args.output.stat().st_size,
        "output_sha256": sha256_file(args.output),
    }
    args.summary.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    print(f"wrote {records} records to {args.output}")
    print(f"summary: {args.summary}")
    print(f"sha256: {summary['output_sha256']}")


if __name__ == "__main__":
    main()
