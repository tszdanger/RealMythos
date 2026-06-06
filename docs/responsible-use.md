---
layout: default
title: Responsible Use
---

# Responsible Use

RealMythos is intended for security research, defensive evaluation, model alignment, and reproducible academic study.

## Intended Uses

- Security reasoning research
- Defensive model evaluation
- Supervised fine-tuning for vulnerability understanding
- Academic reproducibility studies
- Quality analysis of model reasoning traces
- Authorized vulnerability analysis and controlled PoC validation on systems the user owns or is explicitly authorized to test

## Out-of-Scope Uses

- Unauthorized exploitation
- Offensive scanning against real-world systems
- Automated vulnerability weaponization
- Deployment as an unsupervised exploit generation service
- Using released models or generated PoCs against third-party systems without explicit written authorization

## Release Posture

Security-sensitive artifacts should be released with clear documentation, versioning, and safety boundaries. Public artifacts should avoid silent mutation; changes should be captured through version tags, release notes, and manifests.

The Stage 2 model, [RealMythos/pocwriter-v1](https://huggingface.co/RealMythos/pocwriter-v1), is released for authorized security research and controlled validation only. Users are responsible for verifying outputs manually and complying with applicable laws, engagement scopes, disclosure policies, and upstream license terms.
