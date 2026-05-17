# RealMythos

Sprachen: [English](README.md) | [简体中文](README.zh-CN.md) | [한국어](README.ko.md) | [Deutsch (Schweiz)](README.de-CH.md)

[![Stage 1](https://img.shields.io/badge/Stage%201-Dataset%20Complete-2ea44f)](https://huggingface.co/datasets/RealMythos/RealMythosReasoning)
[![Hugging Face](https://img.shields.io/badge/Hugging%20Face-RealMythosReasoning-ffcc4d)](https://huggingface.co/datasets/RealMythos/RealMythosReasoning)
[![Technical Report](https://img.shields.io/badge/Technical%20Report-Google%20Drive%20Draft-b31b1b)](https://drive.google.com/drive/folders/15QTlPNgEjfR-rOYg1zI0YCjT5VL9EfUi?usp=sharing)
[![Roadmap](https://img.shields.io/badge/Roadmap-4%20Stages-0969da)](ROADMAP.md)
[![Responsible Use](https://img.shields.io/badge/Responsible%20Use-Documented-6e7781)](docs/responsible-use.md)

RealMythos ist eine gestufte Open-Source-Initiative zur öffentlichen Rekonstruktion von Claude Mythos als offenem Cybersicherheits-Reasoning-Stack. Das Projekt beginnt mit realen Schwachstellendaten und entwickelt daraus hochwertige Reasoning-Daten, offene Modelle, reproduzierbare Schwachstellenumgebungen und eine Infrastruktur zur Sammlung von Multi-Scaffold-Traces.

Unser Ziel ist es, fortgeschrittenes Security Reasoning fairer, transparenter und breiter nutzbar zu machen. Wir teilen nicht die Ansicht, dass leistungsfähige Cybersicherheits-Reasoning-Werkzeuge hinter geschlossenen Zugangsschranken einer einzelnen Firma oder einer kleinen Gruppe privater Akteure konzentriert bleiben sollten. Dazu gehört ausdrücklich **Anthropic**, dessen Claude Mythos der Öffentlichkeit nicht offen zugänglich ist. RealMythos soll Forschenden, Verteidigern, Lehrenden und der Open-Source-Community ermöglichen, solche Systeme zu prüfen, zu reproduzieren und zu verbessern.

> RealMythos versteht Claude Mythos als einen Capability Stack, der öffentlich rekonstruiert werden kann, nicht als einzelnes geschlossenes Checkpoint-Modell. Daten, Modelle, reproduzierbare Umgebungen und Trace-Infrastruktur sollen in Schichten veröffentlicht werden, die die Community prüfen, reproduzieren und weiterentwickeln kann.

## Release-Überblick

| Element | Aktueller Stand |
|---|---|
| Primäres Artefakt | [RealMythos/RealMythosReasoning](https://huggingface.co/datasets/RealMythos/RealMythosReasoning) |
| GitHub-Repository | [tszdanger/RealMythos](https://github.com/tszdanger/RealMythos) |
| Technischer Bericht | [Aktueller Entwurf auf Google Drive](https://drive.google.com/drive/folders/15QTlPNgEjfR-rOYg1zI0YCjT5VL9EfUi?usp=sharing) |
| Umfang von Stage 1 | 6'159 CVE-verknüpfte C/C++ Security-Reasoning-Datensätze |
| Release-Fokus | SFT-fähige Reasoning-Daten, PoC-aware Antworten, Qualitätssignale und Responsible-Use-Dokumentation |
| Reproduzierbarkeitscode | [`stage1-dataset/pipeline/`](stage1-dataset/pipeline/) |
| Roadmap | Vierstufiger Weg von Daten zu Modellen, reproduzierbaren Umgebungen und Scaffold-basierten Traces |

## Aktueller Stand

| Stage | Fokus | Design fertig | Entwicklung fertig | Interne Prüfung fertig | Veröffentlicht |
|---|---|:---:|:---:|:---:|:---:|
| Stage 1 | Security-Reasoning-Datensatz | yes | yes | yes | yes |
| Stage 2 | Offenes Security-Reasoning-Modell | yes | yes | yes | no |
| Stage 3 | Reproduzierbare Softwareumgebungen | yes | no | no | no |
| Stage 4 | Scaffold-basierte Trace-Sammlung | no | no | no | no |

## Stage 1 Datensatz

Der Stage-1-Datensatz ist auf Hugging Face verfügbar:

[RealMythos/RealMythosReasoning](https://huggingface.co/datasets/RealMythos/RealMythosReasoning)

Stage 1 bildet die öffentliche Grundlage für die weiteren RealMythos-Schichten: Modelltraining, reproduzierbare Umgebungen und Trace-Sammlung. Jeder Datensatz basiert auf einem realen CVE-verknüpften Schwachstellenfall und enthält eine Code-Analysefrage, einen Reasoning Trace, eine PoC-orientierte Antwort und strukturierte Qualitätsmetadaten.

Wichtige Eigenschaften:

- Die Daten beruhen auf realen CVE-verknüpften Schwachstellenfällen, nicht auf generischen Security-Q&A-Beispielen.
- Die Prompts behandeln Root Cause, Trigger-Bedingungen, vom Angreifer kontrollierte Eingaben, Datenfluss, Auswirkung und PoC-orientiertes Reasoning.
- Das Reasoning wird patch-unaware aufbereitet, um direkte Leakage aus Fixed-Code-Informationen zu reduzieren.
- PoC-orientierte Evaluationsmetadaten bleiben als Qualitätssignal erhalten.
- Datensatz, Pipeline, Roadmap und Responsible-Use-Policy werden gemeinsam veröffentlicht.

## Forschungslinie

Die Datenerhebung von RealMythos baut auf zwei früheren Arbeiten auf: **Reef: A Framework for Collecting Real-World Vulnerabilities and Fixes** (ASE 2023) und **API-guided Dataset Synthesis to Finetune Large Code Models** (OOPSLA 2025). RealMythos erweitert diese Ideen in Richtung Security-Reasoning-Daten, Modelltraining, reproduzierbare Umgebungen und Multi-Agent-Trace-Infrastruktur.

## Wichtige Links

| Ressource | Zweck |
|---|---|
| [Roadmap](ROADMAP.md) | Projektphasen, Deliverables und Release-Prinzipien |
| [Stage 1 Technical Report Draft](https://drive.google.com/drive/folders/15QTlPNgEjfR-rOYg1zI0YCjT5VL9EfUi?usp=sharing) | Aktueller Berichtsentwurf ausserhalb von Git |
| [Stage 1 Dataset Notes](stage1-dataset/README.md) | Hinweise zu Datenrelease und Distribution |
| [Stage 1 Pipeline](stage1-dataset/pipeline/README.md) | Reproduzierbarkeitscode und Ausführungsanleitung |
| [Responsible Use](docs/responsible-use.md) | Vorgesehene Nutzung und ausgeschlossene Nutzung |
| [Authors and Maintainers](AUTHORS.md) | Beteiligte und Hinweis zur Unabhängigkeit des Projekts |

## Unabhängigkeit

RealMythos ist ein unabhängiges offenes Projekt. Es ist nicht mit Anthropic, Claude oder einem bestehenden Mythos-Projekt verbunden. “Public reconstruction” bedeutet hier, eine offene Alternative aus öffentlichen Daten, dokumentierten Methoden und reproduzierbarer Infrastruktur zu bauen. Es bedeutet nicht, proprietäre Systeme, Gewichte, Prompts, APIs oder unveröffentlichte Anthropic-Materialien zu kopieren.

Das Projekt wird von den Beteiligten in persönlicher Forschungskapazität entwickelt. Institutionelle Zugehörigkeiten dienen nur zur Identifikation der Beitragenden und bedeuten keine rechtliche Verbindung, Förderung, Billigung, Prüfung, Genehmigung oder Verantwortung durch die jeweiligen Institutionen.

## Responsible Use

RealMythos ist für Security Research, defensive Evaluation, Model Alignment und reproduzierbare akademische Forschung gedacht. Es ist nicht für unautorisierte Angriffe, automatisierte Weaponization von Schwachstellen oder offensive Scans gegen reale Systeme bestimmt.
