# RealMythos

Languages: [English](README.md) | [简体中文](README.zh-CN.md) | [한국어](README.ko.md) | [Deutsch (Schweiz)](README.de-CH.md)

[![Stage 1](https://img.shields.io/badge/Stage%201-Dataset%20Complete-2ea44f)](https://huggingface.co/datasets/RealMythos/RealMythosReasoning)
[![Hugging Face](https://img.shields.io/badge/Hugging%20Face-RealMythosReasoning-ffcc4d)](https://huggingface.co/datasets/RealMythos/RealMythosReasoning)
[![Technical Report](https://img.shields.io/badge/Technical%20Report-Google%20Drive%20Draft-b31b1b)](https://drive.google.com/drive/folders/15QTlPNgEjfR-rOYg1zI0YCjT5VL9EfUi?usp=sharing)
[![Roadmap](https://img.shields.io/badge/Roadmap-4%20Stages-0969da)](ROADMAP.md)
[![Responsible Use](https://img.shields.io/badge/Responsible%20Use-Documented-6e7781)](docs/responsible-use.md)

RealMythos is a staged open initiative for the **public reconstruction of Claude Mythos as an open cybersecurity reasoning stack**. It starts from **real-world vulnerability data** and moves through high-quality reasoning data, trained open models, reproducible vulnerability environments, and multi-agent trace collection infrastructure toward executable, inspectable, and community-verifiable security reasoning systems.

Our goal is to make advanced security reasoning **fairer, more inspectable, and more broadly usable**. We do not agree with the idea that powerful cybersecurity reasoning tools should remain concentrated behind closed access gates controlled by a single company or a small set of private actors (**including Anthropic**, whose Claude Mythos remains closed to the public). The benefits of enabling researchers, defenders, educators, and builders to use, inspect, reproduce, and improve these tools openly are far greater than the benefits of keeping them proprietary and opaque.

> RealMythos treats Claude Mythos as a capability stack to be reconstructed in public, not as a single closed checkpoint: data, models, reproducible environments, and trace collection infrastructure should be released in layers that the community can inspect, reproduce, and improve.

## Release Snapshot

| Item | Current state |
|---|---|
| Primary artifact | [RealMythos/RealMythosReasoning](https://huggingface.co/datasets/RealMythos/RealMythosReasoning) |
| GitHub repository | [tszdanger/RealMythos](https://github.com/tszdanger/RealMythos) |
| Technical report | [Latest draft on Google Drive](https://drive.google.com/drive/folders/15QTlPNgEjfR-rOYg1zI0YCjT5VL9EfUi?usp=sharing) |
| Stage 1 scope | 6,159 CVE-linked C/C++ security reasoning records |
| Release focus | SFT-ready reasoning data, PoC-aware responses, quality signals, and responsible-use documentation |
| Reproducibility code | [`stage1-dataset/pipeline/`](stage1-dataset/pipeline/) |
| Roadmap | Four-stage path from data to models, reproducible environments, and scaffold-based traces |

## Why RealMythos

We view Claude Mythos not as a single model checkpoint, but as a complete security reasoning architecture:

```text
real vulnerability data
        |
        v
reasoning dataset
        |
        v
open security reasoning model
        |
        v
reproducible software environments
        |
        v
multi-agent trace collection and validation
```

RealMythos is our effort to reconstruct this stack in the open, with **versioned artifacts, responsible release practices, and reproducible research infrastructure**. The project is deliberately staged so that every layer can be inspected and improved by the community: data first, then models, then executable environments, and finally richer multi-agent trace collection.

We want RealMythos to make Claude Mythos-level security reasoning more transparent and fair. Instead of asking the community to trust a closed system, RealMythos is designed around **public artifacts, documented methods, reproducible evaluation, and open collaboration**.

## Research Lineage

The data-collection philosophy behind RealMythos is influenced by two earlier lines of our work. **Reef** provides the real-world vulnerability and fix collection foundation, while **API-guided dataset synthesis** informs the way we think about structured code-data generation for training large code models. RealMythos extends these ideas toward security reasoning data, model training, reproducible environments, and multi-agent trace infrastructure.

| Reference | Status |
|---|---|
| Reef: A Framework for Collecting Real-World Vulnerabilities and Fixes | Published at ASE 2023 |
| API-guided Dataset Synthesis to Finetune Large Code Models | Published at OOPSLA 2025 |
| RealMythos technical report | arXiv preprint to be added |

<details>
<summary>BibTeX for related prior work</summary>

```bibtex
@inproceedings{wang2023reef,
  title={Reef: A framework for collecting real-world vulnerabilities and fixes},
  author={Wang, Chaozheng and Li, Zongjie and Pena, Yun and Gao, Shuzheng and Chen, Sirong and Wang, Shuai and Gao, Cuiyun and Lyu, Michael R},
  booktitle={2023 38th IEEE/ACM International Conference on Automated Software Engineering (ASE)},
  pages={1952--1962},
  year={2023},
  organization={IEEE}
}

@article{li2025api,
  title={Api-guided dataset synthesis to finetune large code models},
  author={Li, Zongjie and Wu, Daoyuan and Wang, Shuai and Su, Zhendong},
  journal={Proceedings of the ACM on Programming Languages},
  volume={9},
  number={OOPSLA1},
  pages={786--815},
  year={2025},
  publisher={ACM New York, NY, USA}
}
```

</details>

## Current Status

Legend: ![Done](https://img.shields.io/badge/%E2%9C%93-Done-2ea44f?style=flat-square) completed / - not yet complete

| Stage | Focus | Design Complete | Development Complete | Internal Review Complete | Released |
|---|---|:---:|:---:|:---:|:---:|
| Stage 1 | Security reasoning dataset | ![Done](https://img.shields.io/badge/%E2%9C%93-Done-2ea44f?style=flat-square) | ![Done](https://img.shields.io/badge/%E2%9C%93-Done-2ea44f?style=flat-square) | ![Done](https://img.shields.io/badge/%E2%9C%93-Done-2ea44f?style=flat-square) | ![Done](https://img.shields.io/badge/%E2%9C%93-Done-2ea44f?style=flat-square) |
| Stage 2 | Open security reasoning model | ![Done](https://img.shields.io/badge/%E2%9C%93-Done-2ea44f?style=flat-square) | ![Done](https://img.shields.io/badge/%E2%9C%93-Done-2ea44f?style=flat-square) | ![Done](https://img.shields.io/badge/%E2%9C%93-Done-2ea44f?style=flat-square) | - |
| Stage 3 | Reproducible software environments | ![Done](https://img.shields.io/badge/%E2%9C%93-Done-2ea44f?style=flat-square) | - | - | - |
| Stage 4 | Scaffold-based trace collection | - | - | - | - |

## Stage 1 Dataset

The **Stage 1 dataset** is hosted on Hugging Face:

[RealMythos/RealMythosReasoning](https://huggingface.co/datasets/RealMythos/RealMythosReasoning)

The companion technical report is hosted as a latest-draft PDF on Google Drive. A stable arXiv preprint will be added once available.

[Stage 1 Technical Report Draft](https://drive.google.com/drive/folders/15QTlPNgEjfR-rOYg1zI0YCjT5VL9EfUi?usp=sharing)

The Stage 1 release is designed as the public foundation for the rest of the RealMythos stack. It includes:

- SFT-ready reasoning data
- Case-level metadata and quality signals
- Dataset schema and example records
- A technical report describing data collection and responsible disclosure practices
- Dataset card and responsible-use notes
- Versioned manifests and checksums

What makes this release different:

| Design axis | RealMythos Stage 1 choice |
|---|---|
| Grounding | Records are derived from real CVE-linked vulnerability cases rather than generic security Q&A. |
| Reasoning target | Prompts ask for root cause, trigger conditions, attacker-controlled inputs, data-flow path, impact, and PoC-oriented reasoning. |
| Leakage control | Reasoning is prepared in a patch-unaware form to reduce direct reliance on fixed-code leakage. |
| Quality signal | PoC-oriented evaluation metadata is retained as structured release data. |
| Release philosophy | The dataset, pipeline notes, roadmap, and responsible-use policy are published together. |

Compared with common baseline datasets:

Legend: :white_check_mark: supported / :x: not included / :heavy_minus_sign: not applicable

| Dataset | Size | Teacher | CoT | Real CVE code | PoC | Patch-unaware | Quality gate |
|---|---:|---|:---:|:---:|:---:|:---:|:---:|
| [Primus](https://huggingface.co/datasets/trendmicro-ailab/Primus-Reasoning) | 4,864 | o1 / R1 | :white_check_mark: | :x: | :x: | :x: | :x: |
| [CyberSec-Merged](https://huggingface.co/datasets/Mohannadcse/cybersec-reasoning-merged) | 23,146 | mixed | :white_check_mark: | :x: | :x: | :x: | :x: |
| [AquilaX](https://huggingface.co/datasets/AquilaX-AI/security_assistant_data) | 18,282 | template | :white_check_mark: | :x: | :x: | :x: | :x: |
| [SecCoT-CN](https://huggingface.co/datasets/cfrylhy/SecCoT-CN) | 31,921 | GPT-4.1 / Qwen3 | :white_check_mark: | :x: | :x: | :x: | :x: |
| [SecKnowledge](https://arxiv.org/abs/2510.14113) | 153K / 403K | expert + LLM | :white_check_mark: | :x: | :x: | :x: | :x: |
| [OpenCodeReasoning](https://huggingface.co/datasets/nvidia/OpenCodeReasoning) | 736,712 | R1 | :white_check_mark: | :x: | :x: | :x: | :white_check_mark: |
| [RealMythos](https://huggingface.co/datasets/RealMythos/RealMythosReasoning) | 6,159 | DeepSeek-V4-Pro | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |

The full dataset is hosted through **Hugging Face**. This GitHub repository hosts documentation, schemas, release notes, reports, and reproducibility-oriented project materials.

## Quick Links

| Resource | Purpose |
|---|---|
| [Roadmap](ROADMAP.md) | Project stages, deliverables, and release principles |
| [Stage 1 Technical Report Draft](https://drive.google.com/drive/folders/15QTlPNgEjfR-rOYg1zI0YCjT5VL9EfUi?usp=sharing) | Latest draft hosted outside Git |
| [Stage 1 Dataset Notes](stage1-dataset/README.md) | Dataset release plan and distribution notes |
| [Stage 1 Pipeline](stage1-dataset/pipeline/README.md) | Reproducibility code and execution guidance |
| [Responsible Use](docs/responsible-use.md) | Intended-use and out-of-scope-use boundaries |
| [Release Policy](docs/release-policy.md) | Versioning, artifact, and publication policy |
| [Authors and Maintainers](AUTHORS.md) | Participants and independent-project notice |

## Repository Layout

```text
.
|-- .github/
|-- .gitignore
|-- README.md
|-- README.zh-CN.md
|-- README.ko.md
|-- README.de-CH.md
|-- ROADMAP.md
|-- CONTRIBUTING.md
|-- SECURITY.md
|-- AUTHORS.md
|-- LICENSES.md
|-- stage1-dataset/
|   |-- README.md
|   `-- pipeline/
|       |-- .env.example
|       |-- .gitignore
|       |-- README.md
|       |-- data/
|       |-- reasoning_expr/
|       `-- test/
|-- stage2-model/
|   `-- README.md
|-- stage3-repro-env/
|   `-- README.md
|-- stage4-trace-scaffold/
|   `-- README.md
`-- docs/
    |-- _config.yml
    |-- _layouts/
    |-- assets/
    |-- index.md
    |-- roadmap.md
    |-- stage1-dataset.md
    |-- responsible-use.md
    |-- release-policy.md
    |-- repository-organization.md
    `-- authors.md
```

This repository intentionally does not place large dataset files or model checkpoints in Git. Public data artifacts should be published through Hugging Face or release archives with explicit versioning and checksums.

## Project Participants

> RealMythos is an **independent open project**. It is not affiliated with Anthropic, Claude, or any existing Mythos-branded project. In this project, "public reconstruction" means building an open alternative from public data, documented methods, and reproducible infrastructure; it does not mean copying proprietary systems, weights, prompts, APIs, or unpublished Anthropic materials.
>
> The project is developed by its authors in their personal capacity and personal time. Institutional affiliations are listed only to identify contributors; they do not imply legal affiliation, sponsorship, endorsement, review, approval, or responsibility by the authors' employers, universities, laboratories, funding bodies, or other institutions.

| Participant | Affiliation | Primary role |
|---|---|---|
| Zongjie Li | HKUST | Project lead |
| Liwen Wang | HKUST | Dataset construction |
| Chaozheng Wang | CUHK | Model training and evaluation |
| Zimo Ji | HKUST | Reproducibility infrastructure |

All participants contributed to improving the data-collection framework during iterative development, including substantial manual inspection, review, and release-readiness checking across the pipeline.

## Responsible Use

RealMythos is intended for security research, defensive evaluation, model alignment, and reproducible academic study. It is not intended for unauthorized exploitation, offensive scanning, or automated vulnerability weaponization.

For safety-sensitive reports, please follow [SECURITY.md](SECURITY.md).
