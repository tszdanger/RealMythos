# RealMythos

语言: [English](README.md) | [简体中文](README.zh-CN.md) | [한국어](README.ko.md) | [Deutsch (Schweiz)](README.de-CH.md)

[![Stage 1](https://img.shields.io/badge/Stage%201-Dataset%20Complete-2ea44f)](https://huggingface.co/datasets/RealMythos/RealMythosReasoning)
[![Hugging Face](https://img.shields.io/badge/Hugging%20Face-RealMythosReasoning-ffcc4d)](https://huggingface.co/datasets/RealMythos/RealMythosReasoning)
[![Technical Report](https://img.shields.io/badge/Technical%20Report-Google%20Drive%20Draft-b31b1b)](https://drive.google.com/drive/folders/15QTlPNgEjfR-rOYg1zI0YCjT5VL9EfUi?usp=sharing)
[![Roadmap](https://img.shields.io/badge/Roadmap-4%20Stages-0969da)](ROADMAP.md)
[![Responsible Use](https://img.shields.io/badge/Responsible%20Use-Documented-6e7781)](docs/responsible-use.md)

RealMythos 是一个分阶段推进的开放项目，目标是以公开数据、开放方法和可复现基础设施，公开重建 Claude Mythos 级别的网络安全推理能力栈。项目从真实世界漏洞数据出发，逐步发布高质量推理数据、开放模型、可复现漏洞环境，以及多 scaffold 的 trace 收集基础设施。

我们的目标是让高级安全推理能力更加公平、透明、可检查、可复现。我们不认同强大的网络安全推理工具应长期集中在少数闭源访问门槛之后，尤其是 **Anthropic** 的 Claude Mythos 目前并未向公众开放。RealMythos 希望通过公开协作，让研究者、防御者、教育者和开源社区能够检查、复现、改进这类系统。

> RealMythos 将 Claude Mythos 视为一个完整能力栈，而不是单一模型 checkpoint。数据、模型、可复现环境和 trace 收集基础设施都应以可检查、可复现、可迭代的方式分层发布。

## 发布概览

| 项目 | 当前状态 |
|---|---|
| 主要数据集 | [RealMythos/RealMythosReasoning](https://huggingface.co/datasets/RealMythos/RealMythosReasoning) |
| GitHub 仓库 | [tszdanger/RealMythos](https://github.com/tszdanger/RealMythos) |
| 技术报告 | [Google Drive 最新草稿](https://drive.google.com/drive/folders/15QTlPNgEjfR-rOYg1zI0YCjT5VL9EfUi?usp=sharing) |
| Stage 1 范围 | 6,159 条 CVE 关联的 C/C++ 安全推理记录 |
| 发布重点 | SFT 数据、PoC-aware 响应、质量信号和 responsible-use 文档 |
| 可复现代码 | [`stage1-dataset/pipeline/`](stage1-dataset/pipeline/) |
| Roadmap | 从数据到模型、可复现环境和 scaffold trace 的四阶段计划 |

## 当前进展

| Stage | 重点 | 设计完成 | 开发完成 | 内部检查完成 | 已发布 |
|---|---|:---:|:---:|:---:|:---:|
| Stage 1 | 安全推理数据集 | yes | yes | yes | yes |
| Stage 2 | 开放安全推理模型 | yes | yes | yes | no |
| Stage 3 | 可复现软件环境 | yes | no | no | no |
| Stage 4 | Scaffold trace 收集 | no | no | no | no |

## Stage 1 数据集

Stage 1 数据集已托管在 Hugging Face:

[RealMythos/RealMythosReasoning](https://huggingface.co/datasets/RealMythos/RealMythosReasoning)

Stage 1 旨在作为 RealMythos 后续模型训练、可复现环境和 trace 收集工作的公开基础。该数据集包含真实 CVE 关联漏洞样例、代码分析问题、推理 trace、PoC-oriented 响应，以及结构化质量评估信息。

主要特点：

- 来自真实 CVE 关联漏洞案例，而不是通用安全问答。
- 面向根因、触发条件、攻击者可控输入、数据流路径、影响和 PoC 推理。
- 使用 patch-unaware 形式降低对修复代码泄露的依赖。
- 保留 PoC-oriented 质量评估元数据。
- 数据集、pipeline、roadmap 和 responsible-use policy 一起发布。

## 研究来源

RealMythos 的数据收集思路受到我们此前两条工作的影响：ASE 2023 的 **Reef: A Framework for Collecting Real-World Vulnerabilities and Fixes**，以及 OOPSLA 2025 的 **API-guided Dataset Synthesis to Finetune Large Code Models**。RealMythos 将这些思路扩展到安全推理数据、模型训练、可复现环境和多 agent trace 基础设施。

## 关键链接

| 资源 | 用途 |
|---|---|
| [Roadmap](ROADMAP.md) | 项目阶段、交付物和发布原则 |
| [Stage 1 技术报告草稿](https://drive.google.com/drive/folders/15QTlPNgEjfR-rOYg1zI0YCjT5VL9EfUi?usp=sharing) | Git 外部托管的最新报告草稿 |
| [Stage 1 数据集说明](stage1-dataset/README.md) | 数据发布计划和分发说明 |
| [Stage 1 Pipeline](stage1-dataset/pipeline/README.md) | 可复现代码和运行说明 |
| [Responsible Use](docs/responsible-use.md) | 适用范围和不适用范围 |
| [Authors and Maintainers](AUTHORS.md) | 参与者和独立项目声明 |

## 独立性声明

RealMythos 是独立开放项目，与 Anthropic、Claude 或任何已有 Mythos 品牌项目没有从属关系。本文中的“公开重建”指使用公开数据、文档化方法和可复现基础设施构建开放替代方案，并不意味着复制任何私有系统、权重、提示词、API 或未公开材料。

项目由作者在个人研究时间中推进。机构信息仅用于标识贡献者身份，不代表其所属机构的法律关联、赞助、背书、审核、批准或责任。

## Responsible Use

RealMythos 面向安全研究、防御评估、模型对齐和可复现学术研究。它不应用于未授权攻击、自动化漏洞武器化或针对真实系统的攻击性扫描。
