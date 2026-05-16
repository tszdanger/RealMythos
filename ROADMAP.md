# RealMythos Roadmap

RealMythos is an open initiative for reproducible security reasoning and the public reconstruction of Claude Mythos as an open cybersecurity research stack. We treat Claude Mythos-level capability as a full architecture rather than a single model: data, model training, reproducible environments, and multi-agent trace collection all need to mature together.

The project starts with high-quality reasoning data, expands into open model training, then builds executable reproduction environments, and finally provides scaffold-based trace collection infrastructure for the broader research community.

This roadmap describes current priorities and expected release directions. It is not a binding commitment to specific dates or features. Public releases are subject to quality review, reproducibility checks, and responsible disclosure considerations.

## Vision

RealMythos aims to make advanced security reasoning research more open, inspectable, and reproducible.

The project builds on ideas from two earlier lines of our work: **Reef: A Framework for Collecting Real-World Vulnerabilities and Fixes** for real-world vulnerability/fix collection, and **API-guided Dataset Synthesis to Finetune Large Code Models** for structured code-data synthesis. RealMythos extends these directions into reasoning data, trained models, reproducible execution environments, and scaffold-based trace collection. A RealMythos arXiv technical report will be added once available.

The long-term goal is to provide:

- High-quality vulnerability reasoning data with transparent provenance and quality controls
- Open models trained and evaluated on security reasoning traces
- Reproducible software environments for validating vulnerability reasoning and PoC behavior
- Scaffold-based trace collection frameworks for future data generation
- Responsible release practices for security-sensitive artifacts

## Roadmap Principles

1. Quality before scale
   We prioritize verifiable, well-documented data over simply increasing sample count.

2. Reproducibility before leaderboard claims
   Performance improvements should be supported by transparent evaluation scripts, baselines, and release artifacts.

3. Responsible release by default
   Security-sensitive data, PoC traces, and execution environments require careful documentation and disclosure boundaries.

4. Versioned releases only
   Public artifacts should be released with version tags, schemas, manifests, checksums, and changelogs.

5. Community-verifiable infrastructure
   The project should enable external researchers to inspect, reproduce, and extend the work.

## Stage 1: Security Reasoning Dataset

**Status:** Completed; Hugging Face release prepared
**Target release:** May 2026  
**Primary location:** [RealMythos/RealMythosReasoning](https://huggingface.co/datasets/RealMythos/RealMythosReasoning), with GitHub documentation and release metadata

Stage 1 focuses on releasing a high-quality security reasoning dataset derived from real-world vulnerability data.

### Goals

- Provide curated vulnerability reasoning samples derived from real-world vulnerability data
- Include reasoning traces suitable for supervised fine-tuning
- Preserve case-level metadata needed for inspection and quality analysis
- Document data collection, filtering, evaluation, and responsible release practices
- Establish the first public foundation for the RealMythos project

### Release Deliverables

- Public dataset release on Hugging Face
- Dataset schema and example records
- Dataset card / data statement
- [Technical report latest draft](https://drive.google.com/drive/folders/15QTlPNgEjfR-rOYg1zI0YCjT5VL9EfUi?usp=sharing) on Google Drive
- Data source composition statistics
- Quality score distribution
- Known limitations and intended-use statement
- Author, contact, and license information
- Release manifest and checksums

### Success Criteria

- Users can understand what the dataset contains and how it was produced
- Users can load and inspect the dataset without relying on private scripts
- Data quality criteria and rejection criteria are documented
- Safety boundaries are explicitly stated
- The dataset is citable and versioned

## Stage 2: Open Security Reasoning Model

**Status:** Completed internally; public packaging in progress  
**Target release:** Late May 2026

Stage 2 releases an open model trained using the Stage 1 reasoning data. Internal experiments show an average performance improvement of more than 25% over the selected baseline setup. The public release will document the exact evaluation setting before making final performance claims.

### Goals

- Demonstrate that the Stage 1 reasoning data improves open-source security reasoning models
- Provide a reproducible model training and evaluation setup
- Release model artifacts or adapters when appropriate
- Establish baseline results for future community comparison

### Planned Deliverables

- RealMythos model checkpoint or adapter
- Training configuration
- Evaluation scripts
- Baseline comparison report
- Model card
- Inference examples
- Safety and limitation notes
- Reproducibility instructions

### Evaluation Focus

- Vulnerability reasoning quality
- PoC construction quality
- Patch-unaware reasoning behavior
- Generalization to held-out vulnerabilities
- Comparison against base open-source models

### Success Criteria

- The reported performance improvement is supported by public evaluation artifacts
- Users can reproduce the evaluation setup
- Model behavior, limitations, and intended use are documented
- The model release is linked to the exact dataset version used for training

## Stage 3: Reproducible Software Environments

**Status:** Design complete; initial framework and limited examples planned
**Target initial release:** June 2026

Stage 3 focuses on helping academic institutions and open-source communities reproduce vulnerability reasoning results in realistic software environments. The design scope is complete; the first public package will focus on an example framework, a limited set of reproducible cases, and clear reproduction-status metadata.

The current estimated reproducibility rate is approximately 18%. The Stage 3 goal is to move toward 35% through standardized environment construction, dependency capture, and validation workflows.

### Goals

- Build reproducible software environments for selected vulnerability cases
- Provide a reference framework for reconstructing vulnerable and fixed software states
- Support controlled validation of reasoning traces and PoC behavior
- Reduce the gap between textual reasoning datasets and executable security research

### Planned Deliverables

- Initial reproducibility framework
- Limited set of reproducible example cases
- Environment specification format
- Build and validation scripts
- Reproducibility report
- Failure taxonomy for non-reproducible cases
- Documentation for academic and community contributors

### Example Components

- Containerized vulnerable software environments
- Dependency and compiler version records
- Build scripts
- Test harnesses
- PoC execution guards
- Validation logs
- Reproduction status metadata

### Success Criteria

- Initial example cases can be reproduced by external users
- Reproducibility status is tracked per case
- The framework explains why certain cases fail to reproduce
- The measured reproducibility rate improves from 18% toward 35%
- The framework can be extended by external contributors

## Stage 4: Scaffold-Based Trace Collection

**Status:** Design phase  
**Target:** After the Stage 3 initial release

Stage 4 aims to build multiple scaffold-based frameworks for collecting richer security reasoning traces.

Instead of relying on a single prompt or execution setup, RealMythos will explore different scaffolds for collecting traces across diverse reasoning workflows, model behaviors, and software environments.

### Goals

- Collect reasoning traces from multiple scaffold designs
- Compare how scaffold structure affects reasoning quality and reproducibility
- Support future dataset expansion with more diverse trace sources
- Enable community-contributed trace collection under a consistent governance process

### Planned Directions

- Static-analysis-assisted scaffold
- Dynamic execution scaffold
- Patch-diff-aware internal scaffold with patch-unaware public output
- Multi-reviewer trace validation scaffold
- Human-in-the-loop validation scaffold
- Environment-grounded PoC scaffold
- Failure-analysis scaffold for rejected or non-reproducible cases

### Planned Deliverables

- Scaffold interface specification
- Trace schema
- Collection runner design
- Quality evaluation protocol
- Safety review process
- Example scaffold implementations
- Contribution guidelines for new scaffolds

### Success Criteria

- Multiple scaffold types can produce comparable trace records
- Trace quality can be evaluated consistently
- Unsafe or low-quality traces can be filtered before release
- Community contributors can add new scaffold implementations without changing the core data format

## Community Participation

We welcome contributions in the following areas:

- Dataset inspection and quality review
- CWE and vulnerability-class coverage analysis
- Reproducibility case construction
- Benchmark and evaluation scripts
- Documentation improvements
- Model evaluation on external benchmarks
- Responsible disclosure and safety review
- New scaffold design proposals

Larger changes should start with a design issue or proposal. Security-sensitive reports should follow the project security policy rather than being disclosed through public issues.

## Non-Goals

RealMythos does not aim to provide tools for unauthorized exploitation, automated vulnerability weaponization, or offensive scanning against real-world systems.

The project is intended for security research, model evaluation, defensive education, and reproducible academic study.

## Release Policy

Each public release should include:

- Version tag
- Changelog
- Artifact checksums
- Dataset or model card
- Known limitations
- Responsible-use statement
- Author and contact information
- Links to exact code and data versions

## Disclaimer

This roadmap reflects current priorities as of May 2026. Dates, scope, and artifacts may change based on quality results, safety review, infrastructure constraints, and community feedback.
