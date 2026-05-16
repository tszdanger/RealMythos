---
layout: default
title: Home
---

# RealMythos

Open, reproducible security reasoning from real-world vulnerabilities.

[Stage 1 Dataset](https://huggingface.co/datasets/RealMythos/RealMythosReasoning) |
[Report Draft](https://drive.google.com/drive/folders/15QTlPNgEjfR-rOYg1zI0YCjT5VL9EfUi?usp=sharing) |
[Roadmap](roadmap.md) |
[Responsible Use](responsible-use.md) |
[Authors](authors.md)

RealMythos is a staged open initiative for the public reconstruction of Claude Mythos as a transparent cybersecurity reasoning stack: reasoning data, trained open models, reproducible software environments, and multi-agent trace collection infrastructure.

The goal is to make advanced security reasoning fairer, more inspectable, and more broadly usable. We do not agree with the idea that powerful cybersecurity reasoning tools should remain concentrated behind closed access gates controlled by a single company or a small set of private actors. The benefits of enabling researchers, defenders, educators, and builders to use, inspect, reproduce, and improve these tools openly are far greater than the benefits of keeping them proprietary and opaque.

RealMythos is an independent open project. It is not affiliated with Anthropic, Claude, or any existing Mythos-branded project. In this project, public reconstruction means building an open alternative from public data, documented methods, and reproducible infrastructure, not copying proprietary systems, weights, prompts, APIs, or unpublished Anthropic materials. Through staged open releases and community collaboration, the project aims to implement Claude Mythos-level cybersecurity reasoning capabilities in a fully open, reproducible, and auditable way.

## Research Lineage

RealMythos builds on ideas from two earlier lines of work: Reef, our ASE 2023 work on collecting real-world vulnerabilities and fixes, and API-guided dataset synthesis, our OOPSLA 2025 work on structured code-data synthesis for finetuning large code models. RealMythos extends these directions toward reasoning datasets, open models, reproducible environments, and multi-agent trace infrastructure. A RealMythos arXiv technical report will be added once available.

## Current Focus

Stage 1 is complete. The dataset release is hosted on Hugging Face, with companion documentation and pipeline code in this repository.

[RealMythos/RealMythosReasoning](https://huggingface.co/datasets/RealMythos/RealMythosReasoning)

The Stage 1 technical report documents the data-collection process, quality-control decisions, and responsible-release considerations. The [latest draft](https://drive.google.com/drive/folders/15QTlPNgEjfR-rOYg1zI0YCjT5VL9EfUi?usp=sharing) is hosted through Google Drive, and a stable arXiv preprint will be added once available.

## Project Map

| Stage | Focus | Status |
|---|---|---|
| Stage 1 | Security reasoning dataset | Completed; release prepared |
| Stage 2 | Open security reasoning model | Completed internally; packaging in progress |
| Stage 3 | Reproducible software environments | Planned |
| Stage 4 | Scaffold-based trace collection | Design phase |

## Documentation

- [Roadmap](roadmap.md)
- [Stage 1 Dataset](stage1-dataset.md)
- [Stage 1 Technical Report latest draft](https://drive.google.com/drive/folders/15QTlPNgEjfR-rOYg1zI0YCjT5VL9EfUi?usp=sharing)
- [Responsible Use](responsible-use.md)
- [Release Policy](release-policy.md)
- [Repository Organization](repository-organization.md)
- [Authors and Maintainers](authors.md)

## Web Status

This directory is ready to serve as a lightweight GitHub Pages source. It is currently documentation-only: no custom theme, no generated site framework, and no separate domain are required for the Stage 1 release.
