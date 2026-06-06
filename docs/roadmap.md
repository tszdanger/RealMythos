---
layout: default
title: Roadmap
---

# Roadmap

RealMythos treats Claude Mythos-level cybersecurity capability as a full architecture rather than a single model, and aims to reconstruct that capability stack in public through staged open releases. The project is organized into four stages.

## Stage 1: Security Reasoning Dataset

**Status:** Completed; Hugging Face release published

**Dataset:** [RealMythos/RealMythosReasoning](https://huggingface.co/datasets/RealMythos/RealMythosReasoning)

Stage 1 provides the foundational security reasoning dataset derived from real-world vulnerability data.

## Stage 2: Open Security Reasoning Model

**Status:** Public model released

**Model:** [RealMythos/pocwriter-v1](https://huggingface.co/RealMythos/pocwriter-v1)

Stage 2 releases an open model trained using the Stage 1 dataset. The first public checkpoint, `pocwriter-v1`, is a full-parameter SFT of Qwen3.5-9B for authorized security reasoning, C/C++ vulnerability analysis, and controlled PoC drafting.

Internal performance claims should be finalized only with exact evaluation configuration, baseline definitions, and public reproducibility artifacts.

## Stage 3: Reproducible Software Environments

**Status:** Design complete; initial framework and limited examples planned
**Target:** Initial examples in June 2026

Stage 3 builds reproducible vulnerability environments for academic institutions and open-source communities. The design scope is complete, and the first public package will focus on an example framework, limited reproducible cases, and reproduction-status metadata. The goal is to move from the current estimated reproducibility rate of approximately 18% toward 35%.

## Stage 4: Scaffold-Based Trace Collection

**Status:** Design phase  
**Target:** After the Stage 3 initial release

Stage 4 explores multiple scaffolds for collecting richer security reasoning traces, including static-analysis-assisted, dynamic execution, environment-grounded, and multi-reviewer workflows.

## Full Roadmap

The full project roadmap is maintained in the repository root as `ROADMAP.md`.
