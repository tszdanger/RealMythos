---
layout: default
title: Stage 2 Model
---

# Stage 2 Model

The first public RealMythos model release is:

[RealMythos/pocwriter-v1](https://huggingface.co/RealMythos/pocwriter-v1)

`pocwriter-v1` is a full-parameter supervised fine-tune of [Qwen/Qwen3.5-9B](https://huggingface.co/Qwen/Qwen3.5-9B), trained on the Stage 1 [RealMythos/RealMythosReasoning](https://huggingface.co/datasets/RealMythos/RealMythosReasoning) dataset.

## Release Metadata

| Item | Current value |
|---|---|
| Model repository | [RealMythos/pocwriter-v1](https://huggingface.co/RealMythos/pocwriter-v1) |
| Base model | [Qwen/Qwen3.5-9B](https://huggingface.co/Qwen/Qwen3.5-9B) |
| Training data | [RealMythos/RealMythosReasoning](https://huggingface.co/datasets/RealMythos/RealMythosReasoning) |
| Method | Full-parameter supervised fine-tuning |
| Framework | LLaMA-Factory with DeepSpeed ZeRO |
| Checkpoint | Stage-1 SFT checkpoint 748 |
| License | Apache-2.0 |

## Intended Use

- Authorized security research
- C/C++ vulnerability reasoning and source-code analysis
- PoC drafting for controlled validation on systems the user owns or is explicitly authorized to test
- Triage notes, reproduction guidance, and write-up assistance
- Defensive model evaluation and academic study

## Limitations

`pocwriter-v1` is an early public checkpoint. Its outputs may be unstable, incomplete, or incorrect, and generated PoCs must be manually verified. The training distribution is concentrated on English C/C++ CVE-linked vulnerability reasoning, especially memory-safety cases. Public performance claims should be tied to exact evaluation settings, baselines, and released evaluation artifacts.

## Responsible Use

Do not use the model against systems you do not own or lack explicit written authorization to test. Generated PoCs are intended for validation in controlled, authorized environments only. The broader project policy is maintained in [Responsible Use](responsible-use.md).

## Related Materials

- [Stage 1 Dataset](stage1-dataset.md)
- [Stage 2 local README](https://github.com/tszdanger/RealMythos/tree/main/stage2-model)
- [Release Policy](release-policy.md)
- [Hugging Face model card](https://huggingface.co/RealMythos/pocwriter-v1)
