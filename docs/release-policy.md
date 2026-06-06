---
layout: default
title: Release Policy
---

# Release Policy

RealMythos releases should be versioned, documented, and reproducible where possible.

## Required Release Materials

Each public release should include:

- Version tag
- Changelog
- Artifact checksums
- Dataset or model card
- Known limitations
- Responsible-use statement
- Author and contact information
- Links to exact code and data versions

## Artifact Locations

| Artifact | Preferred Location |
|---|---|
| Large datasets | Hugging Face dataset repository |
| Model checkpoints | Hugging Face model repository or approved release storage |
| Documentation | GitHub repository |
| Technical report drafts | [Google Drive](https://drive.google.com/drive/folders/15QTlPNgEjfR-rOYg1zI0YCjT5VL9EfUi?usp=sharing) or institutional storage until arXiv release |
| Stable technical reports | arXiv, Zenodo, or GitHub Releases after version freeze |
| Small metadata artifacts | GitHub repository or GitHub Releases |

## Current Public Artifacts

| Artifact | Location | Notes |
|---|---|---|
| Stage 1 dataset | [RealMythos/RealMythosReasoning](https://huggingface.co/datasets/RealMythos/RealMythosReasoning) | CVE-grounded C/C++ security reasoning dataset |
| Stage 2 model | [RealMythos/pocwriter-v1](https://huggingface.co/RealMythos/pocwriter-v1) | Full-parameter SFT of Qwen3.5-9B trained on the Stage 1 dataset |
| Technical report draft | [Google Drive latest draft](https://drive.google.com/drive/folders/15QTlPNgEjfR-rOYg1zI0YCjT5VL9EfUi?usp=sharing) | Draft location before a stable arXiv or archival release |

## Mutation Policy

Released artifacts should not be silently overwritten. If a public artifact changes, publish a new version or clearly document the correction.

Model checkpoints should be treated as immutable public artifacts. New training runs, safety revisions, or evaluation-backed improvements should be published as new model versions rather than replacing `pocwriter-v1` without notice.
