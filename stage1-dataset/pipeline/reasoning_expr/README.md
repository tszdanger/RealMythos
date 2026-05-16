# Security Reasoning Data Pipeline

This directory contains the main pipeline used to construct the RealMythos Stage 1 security reasoning dataset.

The pipeline starts from curated vulnerable/fixed code records, augments code context when needed, routes examples to vulnerability-aware prompts, generates teacher reasoning, evaluates PoC quality signals, rewrites reasoning into a patch-unaware format, and exports the final public Hugging Face dataset schema.

## Main Pipeline Files

| File | Purpose |
| --- | --- |
| `data_source.py` | Source adapters and canonical record normalization. |
| `build_curation.py` | Cross-source CVE-level curation and deduplication. |
| `build_task_shards.py` | Task shard generation for larger batch runs. |
| `run_task_concurrent.py` | Concurrent task execution helper. |
| `merge_task_outputs.py` | Merge shard outputs back into release-ready pipeline outputs. |
| `context_augmentation.py` | Context sufficiency checks and context augmentation helpers. |
| `prompts.py` | English prompt templates used by the reasoning pipeline. |
| `prompt_router.py` | CWE/pattern-aware prompt routing. |
| `prompt_templates/poc_classes.yaml` | PoC prompt class definitions. |
| `poc_eval.py` | Main PoC quality evaluator used in the Stage 1 pipeline. |
| `run_reasoning.py` | End-to-end orchestration for context, reasoning, evaluation, rewrite, and SFT formatting. |
| `prepare_hf_stage1_dataset.py` | Public schema filtering and Stage 1 Hugging Face export preparation. |
| `translate_reasoning_en.py` | Resumable English reasoning translation/cleanup utility for public release. |

## Pipeline Stages

1. Context augmentation and verification.
2. Teacher reasoning and PoC generation.
3. PoC quality evaluation.
4. Patch-unaware reasoning rewrite.
5. SFT/public dataset formatting.
6. Optional baseline model evaluation.
7. Optional baseline PoC evaluation.

## Release Notes

Large datasets, intermediate JSONL files, logs, local artifacts, and exploratory reports are intentionally not tracked in Git. Public data artifacts should be released through Hugging Face with dataset cards, checksums, and versioned summaries.

This directory is intended to keep only the scripts needed to reproduce or audit the Stage 1 data collection and release pipeline.
