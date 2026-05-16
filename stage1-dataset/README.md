# Stage 1 Dataset

Stage 1 is the first RealMythos release artifact. It focuses on a high-quality security reasoning dataset derived from real-world vulnerability data.

**Status:** Completed; Hugging Face release prepared

The Hugging Face dataset repository has been prepared:

[RealMythos/RealMythosReasoning](https://huggingface.co/datasets/RealMythos/RealMythosReasoning)

The companion technical report is hosted as a latest-draft PDF on Google Drive:

[Stage 1 Technical Report Draft](https://drive.google.com/drive/folders/15QTlPNgEjfR-rOYg1zI0YCjT5VL9EfUi?usp=sharing)

The full public dataset is distributed through Hugging Face. This directory contains the public Stage 1 overview and the reproducibility pipeline code; dataset-card content, release notes, downloadable data artifacts, and report drafts should live outside Git with stable links.

## Research Lineage

The data-collection idea behind this release builds on two earlier lines of our work: **Reef: A Framework for Collecting Real-World Vulnerabilities and Fixes** for real-world vulnerability/fix collection, and **API-guided Dataset Synthesis to Finetune Large Code Models** for structured code-data synthesis. RealMythos adapts these ideas to reasoning-data construction, PoC-aware evaluation, and staged open release infrastructure.

The RealMythos technical report will also be made available as an arXiv preprint; the arXiv link will be added once available.

## Planned Contents

- Dataset schema
- Example records
- Dataset card
- [Technical report latest draft](https://drive.google.com/drive/folders/15QTlPNgEjfR-rOYg1zI0YCjT5VL9EfUi?usp=sharing)
- Data quality report
- Release manifest and checksums
- Responsible-use notes
- Reproducibility pipeline code under [`pipeline/`](pipeline/)

## Release Goals

- Make the dataset understandable without private context
- Document how records were collected, filtered, and evaluated
- Provide clear intended-use and out-of-scope-use guidance
- Link the dataset to exact release versions and checksums
- Prepare the foundation for Stage 2 model training and evaluation claims

## Public Distribution Plan

| Location | Purpose |
|---|---|
| Hugging Face dataset repository | Full dataset files and dataset card |
| GitHub repository | Documentation, schema, release notes, checksums, examples, and reproducibility pipeline code |
| Google Drive report draft | [Latest technical report PDF](https://drive.google.com/drive/folders/15QTlPNgEjfR-rOYg1zI0YCjT5VL9EfUi?usp=sharing) during pre-arXiv iteration |
| GitHub Releases | Versioned release notes and small metadata artifacts |
| Google Drive artifact bundle | Full-run reproducibility inputs such as `selected_records.jsonl` and `tasks_50/` |

## Reproducibility Code

The Stage 1 data-generation and export pipeline is included under [`pipeline/`](pipeline/). It is provided here as a standalone release snapshot.

The pipeline directory contains the scripts used for curation, task sharding, concurrent data generation, PoC evaluation, reasoning cleanup, and Hugging Face export preparation. Large inputs and generated outputs are intentionally excluded from Git.

Full-run reproducibility inputs are distributed separately:

[Google Drive: `primevul_megavul_reposvul_cvefixes`](https://drive.google.com/file/d/1k_0P5ESSS3LjXkOTJlNfQckdaw1cLrmt/view?usp=sharing)

These artifacts are used to reproduce the data-generation run. They are not the public Hugging Face training dataset.

## Included Materials

- [Stage 1 Technical Report latest draft](https://drive.google.com/drive/folders/15QTlPNgEjfR-rOYg1zI0YCjT5VL9EfUi?usp=sharing)
- [Pipeline README](pipeline/README.md)
