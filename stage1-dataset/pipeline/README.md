# RealMythos Stage 1 Security Reasoning Pipeline

This repository contains the reproducibility code used to build the RealMythos Stage 1 security reasoning dataset. The pipeline constructs supervised fine-tuning records from real-world vulnerable/fixed code examples, adds missing code context when needed, generates teacher reasoning and PoC responses, evaluates PoC quality, rewrites reasoning into a patch-unaware form, and exports a public Hugging Face dataset schema.

RealMythos is developed as an open, reproducible effort toward transparent cybersecurity reasoning systems. This repository focuses on Stage 1 data construction and release preparation.

## Repository Layout

```text
stage1-pipeline/
|-- data/
|   |-- curation/source_priority.yaml
|   `-- primevul_cwe_mini_final/extract_by_cwe.py
|-- reasoning_expr/
|   |-- run_reasoning.py              # End-to-end Step 1-7 pipeline
|   |-- run_task_concurrent.py        # Concurrent execution for one task shard
|   |-- build_curation.py             # Cross-source CVE-level curation
|   |-- build_task_shards.py          # Shard curated inputs into task packages
|   |-- merge_task_outputs.py         # Merge task outputs after a full run
|   |-- prepare_hf_stage1_dataset.py  # Public dataset schema filtering
|   |-- translate_reasoning_en.py     # Resumable English reasoning cleanup
|   |-- prompt_router.py
|   |-- prompt_templates/poc_classes.yaml
|   |-- prompts.py
|   |-- context_augmentation.py
|   |-- poc_eval.py
|   `-- README.md
|-- test/
|   |-- callllm.py
|   `-- test_deepseek.py
`-- .env.example
```

Large datasets, generated JSONL files, task shards, logs, local experiments, and release artifacts are intentionally not tracked in Git.

## Artifact Policy

The public Stage 1 dataset should live on Hugging Face with its dataset card, schema description, license, limitations, and release notes.

The full-run reproducibility inputs are different from the public dataset. They include curated intermediate records and task shards used to reproduce the data-generation run:

- `selected_records.jsonl`
- `tasks_50/`
- `shards_summary.json`
- per-task `manifest.json`
- checksum files for downloaded artifact bundles

These artifacts should not be committed to Git and do not need to be published as a Hugging Face dataset. For the initial release, we recommend distributing them as a separate reproducibility artifact bundle through Google Drive, institutional storage, or another file-hosting service with stable access control.

Current Stage 1 reproducibility artifact bundle:

- [Google Drive: `primevul_megavul_reposvul_cvefixes`](https://drive.google.com/file/d/1k_0P5ESSS3LjXkOTJlNfQckdaw1cLrmt/view?usp=sharing)

This bundle is intended for reproducing the full data-generation run. It is not the public training dataset and should not be treated as the Hugging Face release artifact.

Recommended bundle format:

```text
realmythos_stage1_repro_artifacts_YYYYMMDD.tar.gz
realmythos_stage1_repro_artifacts_YYYYMMDD.tar.gz.sha256
```

The archive should unpack into:

```text
data/curation/primevul_megavul_reposvul_cvefixes/
|-- selected_records.jsonl
|-- cve_registry.jsonl
|-- summary.json
`-- tasks_50/
    |-- shards_summary.json
    |-- task_000000/
    |   |-- manifest.json
    |   `-- input.jsonl
    `-- ...
```

For the May 2026 Stage 1 run, the expected shard configuration is `tasks_50`, with approximately 50 cases per task shard.

## Environment

Install dependencies from the repository root:

```bash
pip install openai python-dotenv pyyaml pyarrow
cp .env.example .env
```

For Stage 1 data generation, configure a DeepSeek-compatible API key:

```bash
export OPENAI_API_KEY="your_deepseek_api_key"
```

`OPENROUTER_API_KEY` is only needed for optional Step 6/7 baseline evaluation.

## Pipeline Stages

| Step | Stage | Main output |
| ---: | --- | --- |
| 1 | Context augmentation and verification | `context_aug_results.jsonl`, `context_rejects.jsonl` |
| 2 | Teacher reasoning and PoC generation | `distill_results.jsonl` |
| 3 | PoC quality evaluation | `poc_eval_results.jsonl` |
| 4 | Patch-unaware reasoning rewrite | `reasoning_rewrite_results.jsonl` |
| 5 | SFT data formatting | `training_data.jsonl` |
| 6 | Optional baseline model evaluation | `qwen_baseline_results.jsonl` |
| 7 | Optional baseline PoC evaluation | `qwen_poc_eval_results.jsonl` |

Stage 1 release data is produced from Steps 1-5. Steps 6-7 are optional baseline analyses and are not required to create the public dataset.

## Quick Local Run

Use a small compatible JSONL input when testing the pipeline locally:

```bash
python3 reasoning_expr/run_reasoning.py \
  --mode pipeline \
  --source curated \
  --steps 1 2 3 4 5 \
  --data-path data/curation/primevul_megavul_reposvul_cvefixes/selected_records.jsonl \
  --output-dir output_curated \
  --max-pairs 10
```

For more detailed script-level usage, see [reasoning_expr/README.md](reasoning_expr/README.md).

## Full-Scale Reproduction

Full-scale execution should be treated as a reproducibility run, not as a casual quick-start path. The recommended workflow is:

1. Obtain the reproducibility artifact bundle.
2. Verify the bundle checksum.
3. Verify every task shard manifest.
4. Run task shards with isolated output directories.
5. Merge completed task outputs.
6. Export the public dataset schema.

### 1. Download and Verify Artifacts

Download the current Stage 1 reproducibility bundle from:

- [Google Drive: `primevul_megavul_reposvul_cvefixes`](https://drive.google.com/file/d/1k_0P5ESSS3LjXkOTJlNfQckdaw1cLrmt/view?usp=sharing)

After extraction, the curated artifact directory should be available at:

```text
data/curation/primevul_megavul_reposvul_cvefixes/
```

If the downloaded archive is accompanied by a `.sha256` file, verify the archive checksum before extraction:

```bash
sha256sum -c realmythos_stage1_repro_artifacts_YYYYMMDD.tar.gz.sha256
tar -xzf realmythos_stage1_repro_artifacts_YYYYMMDD.tar.gz
```

If a separate archive checksum is not available, still verify the internal task manifests before running the pipeline:

```bash
python3 reasoning_expr/build_task_shards.py \
  --output-dir data/curation/primevul_megavul_reposvul_cvefixes/tasks_50 \
  --verify-only
```

For the May 2026 Stage 1 run, a successful verification should report approximately:

```text
checked_tasks: 200
checked_records: 9964
ok: true
```

If checksum or manifest verification fails, do not run the pipeline on those artifacts. Download or regenerate the artifacts again.

### 2. Regenerate Task Shards If Needed

If `selected_records.jsonl` is available but `tasks_50/` is not, regenerate task packages:

```bash
python3 reasoning_expr/build_task_shards.py \
  --input data/curation/primevul_megavul_reposvul_cvefixes/selected_records.jsonl \
  --output-dir data/curation/primevul_megavul_reposvul_cvefixes/tasks_50 \
  --shard-size 50 \
  --overwrite
```

The sharding script writes SHA-256 hashes for the full input and for every task package. `run_task_concurrent.py` verifies the local `manifest.json` before processing a shard.

### 3. Run One Task Shard

Each shard should use its own output directory:

```bash
OPENAI_API_KEY=your_key_a python3 reasoning_expr/run_task_concurrent.py \
  --input data/curation/primevul_megavul_reposvul_cvefixes/tasks_50/task_000000/input.jsonl \
  --output-dir output_tasks_50/task_000000 \
  --source curated \
  --steps 1 2 3 4 5 \
  --model deepseek-v4-pro \
  --concurrency 5 \
  --rpm 20
```

For multiple API keys, run one process per key and one output directory per task shard. Keep keys outside Git and avoid committing shell scripts that contain credentials.

### 4. Monitor and Resume

Each task output directory contains:

```text
case_events.jsonl       # Case start/finish/failure event log
case_results.jsonl      # Completed or context-rejected case results
failures.jsonl          # Failed cases with traceback
monitor.json            # Progress counters and run status
case_logs/*.log         # Per-case stdout/stderr logs
checkpoints/*.json      # Per-case Step 1-4 checkpoint files
training_data.jsonl     # Step 5 task-level SFT output
```

Inspect progress with:

```bash
cat output_tasks_50/task_000000/monitor.json
tail -f output_tasks_50/task_000000/case_events.jsonl
tail -f output_tasks_50/task_000000/failures.jsonl
```

To retry failed cases while preserving completed work:

```bash
OPENAI_API_KEY=your_key_a python3 reasoning_expr/run_task_concurrent.py \
  --input data/curation/primevul_megavul_reposvul_cvefixes/tasks_50/task_000000/input.jsonl \
  --output-dir output_tasks_50/task_000000 \
  --source curated \
  --steps 1 2 3 4 5 \
  --model deepseek-v4-pro \
  --concurrency 5 \
  --rpm 20 \
  --retry-failed
```

### 5. Merge Task Outputs

After all task shards finish, merge outputs in manifest order:

```bash
python3 reasoning_expr/merge_task_outputs.py \
  --tasks-dir data/curation/primevul_megavul_reposvul_cvefixes/tasks_50 \
  --outputs-root output_tasks_50 \
  --output-dir output_merged/full_run \
  --strict
```

The merged directory contains:

```text
output_merged/full_run/case_results.jsonl
output_merged/full_run/context_aug_results.jsonl
output_merged/full_run/context_rejects.jsonl
output_merged/full_run/distill_results.jsonl
output_merged/full_run/poc_eval_results.jsonl
output_merged/full_run/reasoning_rewrite_results.jsonl
output_merged/full_run/training_data.jsonl
output_merged/full_run/failures.jsonl
output_merged/full_run/merge_summary.json
```

Use `--strict` for release-grade merges. Remove it only for partial inspection of incomplete runs.

## Public Dataset Export

Convert internal `training_data.jsonl` into the public Stage 1 schema:

```bash
python3 reasoning_expr/prepare_hf_stage1_dataset.py \
  --input output_merged/full_run/training_data.jsonl \
  --output hf_release/stage1/sft_train.jsonl \
  --summary hf_release/stage1/sft_train_summary.json \
  --overwrite
```

If English reasoning cleanup is required:

```bash
python3 reasoning_expr/translate_reasoning_en.py \
  --input hf_release/stage1/sft_train.jsonl \
  --output hf_release/stage1/sft_train_en.jsonl \
  --public-schema \
  --concurrency 30 \
  --rpm 120
```

The public Hugging Face dataset should include the final exported JSONL, a dataset card, schema documentation, license information, limitations, and release notes. It should not include raw intermediate curation artifacts unless they are intentionally approved for public redistribution.

## Data Sources

The curation configuration is defined in [data/curation/source_priority.yaml](data/curation/source_priority.yaml). The current Stage 1 curation order is:

1. PrimeVul
2. MegaVul
3. ReposVul
4. CVEfixes

Input datasets must be prepared locally according to their respective licenses and access terms. This repository provides adapters and curation code, but it does not redistribute the upstream datasets.

## Notes For Contributors

- Do not commit API keys, `.env`, task outputs, generated JSONL files, or downloaded source datasets.
- Keep public-facing prompts and documentation in English for release consistency.
- Keep reproducibility artifacts versioned with dates, checksums, and a short manifest.
- Treat `selected_records.jsonl` and `tasks_50/` as reproducibility inputs, not as the public dataset itself.
