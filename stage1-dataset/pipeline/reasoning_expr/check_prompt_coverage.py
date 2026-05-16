"""Check PromptRouter static CWE coverage against a mini-dataset summary.

Usage:
  python reasoning_expr/check_prompt_coverage.py \
    --summary data/primevul_cwe_mini_final/summary.json \
    --classes reasoning_expr/prompt_templates/poc_classes.yaml
"""

import argparse
import json
from pathlib import Path


def normalize_cwe(cwe):
    cwe = str(cwe).strip().upper()
    if cwe.isdigit():
        return f"CWE-{cwe}"
    if cwe.startswith("CWE") and not cwe.startswith("CWE-"):
        suffix = cwe[3:].lstrip("-_ ")
        if suffix:
            return f"CWE-{suffix}"
    return cwe


def load_summary_cwes(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return [
        normalize_cwe(item["cwe"])
        for item in data.get("selected_cwe_distribution", [])
    ]


def load_class_map(path):
    try:
        import yaml
    except ImportError as exc:
        raise SystemExit("pyyaml is required: pip install pyyaml") from exc

    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    cwe_to_class = {}
    duplicates = []
    for class_id, class_data in data.get("classes", {}).items():
        for raw_cwe in class_data.get("cwe_codes", []):
            cwe = normalize_cwe(raw_cwe)
            if cwe in cwe_to_class:
                duplicates.append((cwe, cwe_to_class[cwe], class_id))
            cwe_to_class[cwe] = class_id
    return data, cwe_to_class, duplicates


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--summary",
        default="data/primevul_cwe_mini_final/summary.json",
        help="Path to mini-dataset summary.json",
    )
    parser.add_argument(
        "--classes",
        default="reasoning_expr/prompt_templates/poc_classes.yaml",
        help="Path to PromptRouter class YAML",
    )
    args = parser.parse_args()

    summary_cwes = load_summary_cwes(args.summary)
    config, cwe_to_class, duplicates = load_class_map(args.classes)
    summary_set = set(summary_cwes)
    mapped_set = set(cwe_to_class)

    missing = sorted(summary_set - mapped_set)
    extra = sorted(mapped_set - summary_set)

    print(f"Summary CWE count: {len(summary_set)}")
    print(f"Prompt classes: {len(config.get('classes', {}))}")
    print(f"Mapped CWE count: {len(mapped_set)}")
    print(f"Covered summary CWE: {len(summary_set & mapped_set)}/{len(summary_set)}")
    print(f"Missing summary CWE: {len(missing)}")
    print(f"Extra mapped CWE: {len(extra)}")
    print(f"Duplicate mappings: {len(duplicates)}")

    if missing:
        print("\nMissing:")
        for cwe in missing:
            print(f"  - {cwe}")

    if duplicates:
        print("\nDuplicates:")
        for cwe, first, second in duplicates:
            print(f"  - {cwe}: {first}, {second}")

    print("\nClass distribution for summary CWEs:")
    by_class = {}
    for cwe in summary_cwes:
        by_class.setdefault(cwe_to_class.get(cwe, "<missing>"), []).append(cwe)
    for class_id in sorted(by_class):
        values = sorted(set(by_class[class_id]))
        print(f"  {class_id}: {len(values)}")
        print(f"    {', '.join(values)}")

    if missing or duplicates:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
