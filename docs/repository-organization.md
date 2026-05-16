---
layout: default
title: Repository Organization
---

# Repository Organization

The initial public release will use one GitHub repository as the main entry point, with Hugging Face used for large dataset distribution.

The Stage 1 dataset repository is:

[RealMythos/RealMythosReasoning](https://huggingface.co/datasets/RealMythos/RealMythosReasoning)

The companion GitHub repository and report are:

- [tszdanger/RealMythos](https://github.com/tszdanger/RealMythos)
- [Stage 1 Technical Report latest draft](https://drive.google.com/drive/folders/15QTlPNgEjfR-rOYg1zI0YCjT5VL9EfUi?usp=sharing)

## Recommended Structure

```text
.
|-- README.md
|-- ROADMAP.md
|-- stage1-dataset/
|   `-- pipeline/
|-- stage2-model/
|-- stage3-repro-env/
|-- stage4-trace-scaffold/
`-- docs/
```

## Rationale

Using one repository at the beginning keeps the project easy to discover and review. Stage-specific directories preserve boundaries between dataset documentation, model release materials, reproducibility environments, and trace scaffold planning.

As the project grows, mature stages can be split into separate repositories under a RealMythos GitHub organization.

## Suggested Future Organization

```text
RealMythos/
|-- realmythos
|-- realmythos-data
|-- realmythos-model
|-- realmythos-env
`-- realmythos-trace
```
