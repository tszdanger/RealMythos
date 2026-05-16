"""Prompt templates for Cyber-LeetCode style vulnerability reasoning experiments."""

SYSTEM_PROMPT = """You are a senior security researcher. You excel at analyzing C/C++ code for security vulnerabilities and can precisely deduce the conditions required to trigger them."""

# Step 1: Distillation prompt with vulnerable code and fix comparison.
REASONING_REWRITE_SYSTEM_PROMPT = """You are a conservative security-reasoning editor.
Your job is NOT to summarize or simplify the reasoning. Your job is to preserve
the original technical reasoning trace, including meta-reasoning and PoC design
logic, while rewriting only the parts that reveal patch/CVE-only information."""


PROMPT_REASONING_REWRITE_CODE_ONLY = """Rewrite the original reasoning so it reads
like a reasoning trace produced by a model that only saw the training question
below.

[Training question visible to the student model]
{question}

[Original teacher reasoning]
{reasoning}

[Primary objective]
Preserve the original reasoning trace as much as possible. Keep the structure,
order, technical details, intermediate hypotheses, uncertainty, and conclusion.
Do not shorten the reasoning unless a phrase is purely patch/CVE metadata.

[What must be preserved]
1. Meta-reasoning is valuable. Keep the model's thought process about how it
   identifies the bug, narrows the trigger condition, chooses a PoC strategy,
   and validates expected behavior.
2. Preserve code-level reasoning: function names, variables, branches, checks,
   control flow, data flow, state assumptions, attacker-controlled fields,
   boundary conditions, and expected failure mode.
3. Preserve PoC construction logic. Keep details such as using a C harness,
   mocking/stubbing project functions, forcing a return value, constructing a
   payload, setting fields, invoking a vulnerable function, and checking the
   crash/error/observable effect, as long as these details are consistent with
   the visible question and original reasoning.
4. Preserve useful engineering judgments even if they are not literally copied
   from the code, for example choosing a local harness to simulate an external
   dependency. Rewrite them as PoC design choices grounded in the visible code.

[What should be edited]
Only edit sentence-level leakage that would not be visible to the student model:
1. Explicit CVE numbers, CWE numbers, dataset labels, evaluator comments, commit
   information, diff/patch wording, and direct mentions of patched/fixed/benign
   code versions.
2. Comparisons like "the patch added/removed/changed X" should be rewritten as
   vulnerable-code observations, for example "the current code lacks X" or "this
   path proceeds without checking X", if that fact is visible from the question.
3. If a clause depends only on the patch/CVE metadata and cannot be grounded in
   the question, delete that clause only. Do not delete the whole paragraph when
   the rest contains useful technical reasoning.

[Do not do]
1. Do not summarize, compress, or turn detailed reasoning into a high-level
   skeleton.
2. Do not remove PoC design details merely because they are implementation
   choices. Keep them when they follow from the original reasoning and visible
   vulnerable code.
3. Do not add new vulnerability facts, new APIs, new effects, or new exploit
   paths that were not present in the original reasoning.
4. Do not change the final vulnerability conclusion or PoC strategy unless the
   original text relied solely on forbidden metadata.

[Output]
Return only the rewritten reasoning in this exact tag:

<reasoning>
...
</reasoning>
"""


PROMPT_PATCH_DIFF = """[Context]
The following vulnerable code and its fix patch were extracted from the {project} project.

CVE ID: {cve}
Description: {cve_desc}
CWE Type: {cwe}

[Vulnerable Code]
```c
{vuln_func}
```

[Fixed Code]
```c
{patched_func}
```

[Task]
Analyze the root cause of this vulnerability by comparing the vulnerable code with its fix, and construct a PoC that triggers it.

[Important Requirement]
In your reasoning process (reasoning_content), you must NOT mention, quote, or describe any content from the fixed code ("Fixed Code" section).
Do not write statements like "by observing the patch, I found it ...", "the fixed code added ... after ...", or "the patch removed ...".
The fixed code is for your private reference only to understand how the vulnerability was remediated. Your reasoning must be based entirely on analyzing the vulnerable code itself.

[Answer Format]
First provide a vulnerability analysis (root cause, trigger conditions, impact), then at the end provide a complete, independently executable PoC code.

[PoC Writing Strict Rules]
1. Do NOT output only raw payload data or byte streams (e.g., b"A"*1000)!
2. For network protocol vulnerabilities, write a standalone Python 3 script with socket communication, complete packet assembly, and sending.
3. For local API vulnerabilities, write a C reproduction program (Harness) with a main function, struct definitions, memory allocation, and vulnerable function invocation.
4. All code must be placed inside a single <poc>...</poc> tag. No explanatory natural language is allowed inside the tag!
5. The PoC should be able to reproduce the vulnerability (trigger crash/overflow/exception) or print the constructed Payload to stdout.
6. Comments, variable names, temp file names, and print strings in the PoC must use neutral case/test naming. Verification output should use neutral descriptions like "expected signal" or "test completed". Do NOT include vulnerable/fixed kernel/version, CVE numbers, patch/diff/commit, or fix-related metadata."""

# Step 2: Code-only training prompt for restructured training data.
PROMPT_TRAINING = """Analyze the following C code and determine whether a security vulnerability exists. If so, analyze the root cause and construct a PoC that triggers it.

```c
{func}
```

[PoC Writing Strict Rules]
1. Do NOT output only raw payload data or byte streams (e.g., b"A"*1000)!
2. For network protocol vulnerabilities, write a standalone Python 3 script with socket communication, complete packet assembly, and sending.
3. For local API vulnerabilities, write a C reproduction program (Harness) with a main function, struct definitions, memory allocation, and vulnerable function invocation.
4. All code must be placed inside a single <poc>...</poc> tag. No explanatory natural language is allowed inside the tag!
5. The PoC should be able to reproduce the vulnerability (trigger crash/overflow/exception) or print the constructed Payload to stdout.
6. Comments, variable names, temp file names, and print strings in the PoC must use neutral case/test naming. Verification output should use neutral descriptions like "expected signal" or "test completed". Do NOT include vulnerable/fixed kernel/version, CVE numbers, patch/diff/commit, or fix-related metadata."""
