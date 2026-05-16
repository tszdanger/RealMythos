"""Context classification and augmentation prompts."""

JUDGE_PROMPT = """You are a security research assistant. Determine whether the following C code snippet is **self-contained**.

[Vulnerability Info]
CVE: {cve}
Description: {cve_desc}
CWE: {cwe}

[Code Snippet]
```c
{func}
```

[Criteria]
- **SELF_CONTAINED**: The vulnerability logic is fully contained within the code. Input parameter meanings are clear, and data flow can be traced within the function.
- **NOT_SELF_CONTAINED**: External struct definitions, global variables, or call-chain information are needed to understand the vulnerability.

Please output:
1. Inside a <judgment> tag, output SELF_CONTAINED or NOT_SELF_CONTAINED.
2. Inside a <reason> tag, briefly explain (within 50 words).
3. If NOT_SELF_CONTAINED, inside a <missing> tag list the required context."""


GENERATOR_PROMPT = """Add the necessary context to the following code to make it self-contained.

[Vulnerability Info]
CVE: {cve} | Description: {cve_desc}

[Missing Context]
{missing_context}

[Code Snippet]
```c
{func}
```

Please generate complete C code inside a <context> tag, including #include, struct definitions, macro definitions, the function itself, and a harness example showing how to call it.

[Important Constraints]
- You may only add code symbol definitions (struct/typedef/macro/function signatures). Do NOT explain the vulnerability mechanism or assume attack paths.
- The added code is only for showing external dependencies and must NOT contain any logic or comments about "how to exploit this vulnerability"."""


VERIFIER_PROMPT = """Verify whether the following context is sufficient to independently analyze this vulnerability.

[Vulnerability Info]
CVE: {cve} | Description: {cve_desc}

[Augmented Context]
```c
{augmented_context}
```

Please output:
1. Inside a <verdict> tag, output SUFFICIENT or INSUFFICIENT.
2. Inside a <reason> tag, explain your reasoning.
3. If INSUFFICIENT, inside a <feedback> tag explain what is still missing."""
