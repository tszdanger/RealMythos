# RealMythos

언어: [English](README.md) | [简体中文](README.zh-CN.md) | [한국어](README.ko.md) | [Deutsch (Schweiz)](README.de-CH.md)

[![Stage 1](https://img.shields.io/badge/Stage%201-Dataset%20Complete-2ea44f)](https://huggingface.co/datasets/RealMythos/RealMythosReasoning)
[![Hugging Face](https://img.shields.io/badge/Hugging%20Face-RealMythosReasoning-ffcc4d)](https://huggingface.co/datasets/RealMythos/RealMythosReasoning)
[![Technical Report](https://img.shields.io/badge/Technical%20Report-Google%20Drive%20Draft-b31b1b)](https://drive.google.com/drive/folders/15QTlPNgEjfR-rOYg1zI0YCjT5VL9EfUi?usp=sharing)
[![Roadmap](https://img.shields.io/badge/Roadmap-4%20Stages-0969da)](ROADMAP.md)
[![Responsible Use](https://img.shields.io/badge/Responsible%20Use-Documented-6e7781)](docs/responsible-use.md)

RealMythos는 공개 데이터, 문서화된 방법, 재현 가능한 인프라를 바탕으로 Claude Mythos 수준의 사이버보안 추론 능력 스택을 공개적으로 재구성하기 위한 단계적 오픈 프로젝트입니다. 이 프로젝트는 실제 취약점 데이터에서 시작해 고품질 추론 데이터, 공개 모델, 재현 가능한 취약점 실행 환경, 그리고 여러 scaffold 기반 trace 수집 인프라로 확장됩니다.

우리의 목표는 고급 보안 추론 능력을 더 공정하고, 더 투명하며, 더 널리 사용할 수 있게 만드는 것입니다. 강력한 사이버보안 추론 도구가 소수의 폐쇄적 접근 장벽 뒤에 집중돼 있어야 한다는 생각에는 동의하지 않습니다. 특히 **Anthropic**의 Claude Mythos는 현재 대중에게 공개돼 있지 않습니다. RealMythos는 연구자, 방어자, 교육자, 오픈소스 커뮤니티가 이러한 시스템을 검토하고, 재현하고, 개선할 수 있도록 공개 협력을 지향합니다.

> RealMythos는 Claude Mythos를 단일 모델 checkpoint가 아니라 하나의 능력 스택으로 봅니다. 데이터, 모델, 재현 가능한 환경, trace 수집 인프라는 커뮤니티가 검토하고 재현하며 개선할 수 있도록 단계적으로 공개돼야 합니다.

## 릴리스 개요

| 항목 | 현재 상태 |
|---|---|
| 주요 아티팩트 | [RealMythos/RealMythosReasoning](https://huggingface.co/datasets/RealMythos/RealMythosReasoning) |
| GitHub 저장소 | [tszdanger/RealMythos](https://github.com/tszdanger/RealMythos) |
| 기술 보고서 | [Google Drive 최신 초안](https://drive.google.com/drive/folders/15QTlPNgEjfR-rOYg1zI0YCjT5VL9EfUi?usp=sharing) |
| Stage 1 범위 | CVE와 연결된 C/C++ 보안 추론 레코드 6,159개 |
| 릴리스 초점 | SFT용 데이터, PoC-aware 응답, 품질 신호, responsible-use 문서 |
| 재현 코드 | [`stage1-dataset/pipeline/`](stage1-dataset/pipeline/) |
| Roadmap | 데이터, 모델, 재현 환경, scaffold trace로 이어지는 네 단계 계획 |

## 현재 진행 상황

| Stage | 초점 | 설계 완료 | 개발 완료 | 내부 검토 완료 | 공개됨 |
|---|---|:---:|:---:|:---:|:---:|
| Stage 1 | 보안 추론 데이터셋 | yes | yes | yes | yes |
| Stage 2 | 공개 보안 추론 모델 | yes | yes | yes | no |
| Stage 3 | 재현 가능한 소프트웨어 환경 | yes | no | no | no |
| Stage 4 | Scaffold 기반 trace 수집 | no | no | no | no |

## Stage 1 데이터셋

Stage 1 데이터셋은 Hugging Face에서 제공됩니다.

[RealMythos/RealMythosReasoning](https://huggingface.co/datasets/RealMythos/RealMythosReasoning)

Stage 1은 이후 모델 학습, 재현 가능한 환경 구축, trace 수집을 위한 공개 기반입니다. 각 레코드는 실제 CVE 연결 취약점 사례를 중심으로 구성되며, 코드 분석 질문, 추론 trace, PoC-oriented 응답, 구조화된 품질 평가 정보를 포함합니다.

주요 특징:

- 일반 보안 Q&A가 아니라 실제 CVE 연결 취약점 사례에 기반합니다.
- 원인, 트리거 조건, 공격자 제어 입력, 데이터 흐름, 영향, PoC 추론을 다룹니다.
- 수정 코드에 직접 의존하는 leakage를 줄이기 위해 patch-unaware 형태로 정리했습니다.
- PoC-oriented 품질 평가 메타데이터를 포함합니다.
- 데이터셋, pipeline, roadmap, responsible-use policy를 함께 공개합니다.

## 연구적 배경

RealMythos의 데이터 수집 철학은 두 가지 선행 연구에서 영향을 받았습니다. 하나는 ASE 2023의 **Reef: A Framework for Collecting Real-World Vulnerabilities and Fixes**이고, 다른 하나는 OOPSLA 2025의 **API-guided Dataset Synthesis to Finetune Large Code Models**입니다. RealMythos는 이 아이디어를 보안 추론 데이터, 모델 학습, 재현 가능한 환경, multi-agent trace 인프라로 확장합니다.

## 주요 링크

| 리소스 | 용도 |
|---|---|
| [Roadmap](ROADMAP.md) | 프로젝트 단계, 산출물, 릴리스 원칙 |
| [Stage 1 기술 보고서 초안](https://drive.google.com/drive/folders/15QTlPNgEjfR-rOYg1zI0YCjT5VL9EfUi?usp=sharing) | Git 외부에 보관되는 최신 보고서 초안 |
| [Stage 1 데이터셋 노트](stage1-dataset/README.md) | 데이터 릴리스 계획과 배포 설명 |
| [Stage 1 Pipeline](stage1-dataset/pipeline/README.md) | 재현 코드와 실행 가이드 |
| [Responsible Use](docs/responsible-use.md) | 의도한 사용 범위와 제외되는 사용 범위 |
| [Authors and Maintainers](AUTHORS.md) | 참여자와 독립 프로젝트 고지 |

## 독립성 고지

RealMythos는 독립적인 오픈 프로젝트이며 Anthropic, Claude 또는 기존 Mythos 브랜드 프로젝트와 제휴돼 있지 않습니다. 여기서 “public reconstruction”은 공개 데이터, 문서화된 방법, 재현 가능한 인프라로 공개 대안을 구축한다는 뜻이며, 사유 시스템, 가중치, 프롬프트, API 또는 미공개 Anthropic 자료를 복제한다는 뜻이 아닙니다.

이 프로젝트는 참여자들이 개인 연구 시간에 개발합니다. 기관명은 기여자를 식별하기 위한 정보일 뿐이며, 소속 기관의 법적 제휴, 후원, 보증, 검토, 승인 또는 책임을 의미하지 않습니다.

## Responsible Use

RealMythos는 보안 연구, 방어적 평가, 모델 정렬, 재현 가능한 학술 연구를 위한 프로젝트입니다. 승인되지 않은 공격, 자동화된 취약점 무기화, 실제 시스템에 대한 공격적 스캔에는 사용해서는 안 됩니다.
