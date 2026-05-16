#!/usr/bin/env python3
"""
PrimeVul Reasoning Experiment - Full Pipeline

Step 1: Context Classification & Augmentation
  - Judge: LLM decides if function is self-contained
  - If NOT self-contained:
      Generator: LLM generates missing context (structs, caller, preconditions)
      Verifier: Another LLM call verifies context sufficiency

Step 2: Teacher Reasoning Distillation
  - Patch-diff prompt with vuln code + patched code + augmented context (if any)
  - Extract native reasoning + PoC code block (markdown ````python)

Step 3: PoC Quality Evaluation
  - Evaluate generated PoC on 6 dimensions (Relevance, Exploitability, Completeness, Precision, Safety, Correctness)
  - Total score: 6-30 (sum of all dimensions)

Step 4: Patch-unaware Reasoning Rewrite
  - Rewrite teacher reasoning using only the SFT question visible to the student
  - Preserve the original reasoning flow while removing patch/CVE/diff leakage

Step 5: SFT Data Formatting
  - Reorganize into input/output format for SFT training
  - Filter: requires PoC extraction PASS, validate_poc() check, and optional min_poc_score
  - Training data includes poc_eval field for quality tracking

Step 6: Qwen Baseline Evaluation
  - Query Qwen 3.5-9b (OpenRouter) with the same questions from Step 5
  - Compare pre-fine-tuning baseline against DeepSeek-v4-pro distilled data

Step 7: Qwen Baseline PoC Evaluation
  - Evaluate Qwen's generated PoCs using the same 6-dimension scoring
  - Early comparison of Qwen vs DeepSeek PoC quality

Usage:
  # Run full pipeline on 3 pilot cases
  python run_reasoning.py --mode pipeline --steps 1 2 3 4 5 --max-pairs 3

  # Run individual steps
  python run_reasoning.py --mode pipeline --steps 1 --max-pairs 3    # context aug only
  python run_reasoning.py --mode pipeline --steps 1 2 --max-pairs 3  # aug + distill
  python run_reasoning.py --mode pipeline --steps 1 2 3 --max-pairs 3  # aug + distill + poc eval
  python run_reasoning.py --mode pipeline --steps 4 5 --max-pairs 3  # rewrite existing distill + SFT format

  # Run Qwen baseline evaluation (requires Step 5 output)
  python run_reasoning.py --mode pipeline --steps 6 7 --max-pairs 3
"""

import argparse
import json
import os
import re
import sys
import time
from openai import OpenAI
try:
    from dotenv import load_dotenv
except ModuleNotFoundError:
    def load_dotenv(path):
        if not path or not os.path.exists(path):
            return False
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                if line.startswith("export "):
                    line = line[len("export "):]
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
        return True

# Load .env from project root
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env'))

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from prompts import (
    SYSTEM_PROMPT,
    PROMPT_PATCH_DIFF,
    PROMPT_TRAINING,
    REASONING_REWRITE_SYSTEM_PROMPT,
    PROMPT_REASONING_REWRITE_CODE_ONLY,
)
from context_augmentation import JUDGE_PROMPT, GENERATOR_PROMPT, VERIFIER_PROMPT
from poc_eval import POC_EVAL_PROMPT
from data_source import (
    CanonicalPair,
    CVEfixesSource,
    CrossVulSource,
    CuratedSource,
    DiverseVulSource,
    MegaVulSource,
    PrimeVulSource,
    ReposVulSource,
)
from prompt_router import PromptRouter, VulnClassConfig


VALID_PIPELINE_STEPS = {1, 2, 3, 4, 5, 6, 7}
DEEPSEEK_RATE_LIMITER = None


def set_deepseek_rate_limiter(limiter):
    """Install a process-wide limiter used by call_deepseek().

    The regular serial pipeline leaves this unset. Concurrent task runners can
    set it to a thread-safe object exposing acquire().
    """
    global DEEPSEEK_RATE_LIMITER
    DEEPSEEK_RATE_LIMITER = limiter


# -------------------------------------------------------
# Progress Tracker
# -------------------------------------------------------

class ProgressTracker:
    """Simple text progress bar with ETA."""

    def __init__(self, total: int, desc: str = "Progress"):
        self.total = total
        self.current = 0
        self.desc = desc
        self.start_time = time.time()
        self._print()

    def _print(self):
        pct = self.current / max(self.total, 1)
        bar_len = 30
        filled = int(bar_len * pct)
        bar = '#' * filled + '-' * (bar_len - filled)
        elapsed = time.time() - self.start_time
        if self.current > 0:
            eta = elapsed / self.current * (self.total - self.current)
        else:
            eta = 0
        eta_min = eta / 60
        print(f"\r[{bar}] {self.current}/{self.total} | "
              f"{pct*100:.1f}% | ETA: {eta_min:.1f} min", end='', flush=True)

    def update(self, n: int = 1):
        self.current += n
        self._print()

    def finish(self):
        self.current = self.total
        self._print()
        elapsed = time.time() - self.start_time
        print(f"\r[{ '#' * 30 }] {self.total}/{self.total} | "
              f"100.0% | Done in {elapsed/60:.1f} min", flush=True)


# -------------------------------------------------------
# API Clients & Calls
# -------------------------------------------------------

def get_client():
    import httpx
    return OpenAI(
        api_key=os.environ.get('OPENAI_API_KEY') or os.environ.get('DEEPSEEK_API_KEY'),
        base_url="https://api.deepseek.com",
        timeout=httpx.Timeout(connect=30.0, read=180.0, write=30.0, pool=30.0),
    )


def get_qwen_client():
    import httpx
    api_key = os.environ.get('OPENROUTER_API_KEY')
    if not api_key:
        return None
    return OpenAI(
        api_key=api_key,
        base_url="https://openrouter.ai/api/v1",
        timeout=httpx.Timeout(connect=30.0, read=180.0, write=30.0, pool=30.0),
    )


def call_qwen(client, messages, model="qwen/qwen3.5-9b", max_retries=5):
    """Call Qwen 3.5-9b via OpenRouter with reasoning enabled.
    Returns (reasoning_text, response_content)."""
    for attempt in range(max_retries + 1):
        try:
            response = client.chat.completions.create(
                model=model, messages=messages, stream=False,
                extra_body={"reasoning": {"enabled": True}},
            )
            time.sleep(3)
            msg = response.choices[0].message
            reasoning = getattr(msg, 'reasoning', None) or ""
            if not reasoning:
                rd = getattr(msg, 'reasoning_details', None)
                if rd and isinstance(rd, list):
                    reasoning = "\n".join(
                        d.get("text", "") for d in rd if isinstance(d, dict)
                    )
            content = msg.content or ""
            return reasoning, content
        except Exception as e:
            if attempt < max_retries:
                wait = 5 * (attempt + 1)
                print(f"\n    [warning] Qwen API error (attempt {attempt+1}/{max_retries+1}): {e}")
                print(f"    Retrying in {wait}s ...")
                time.sleep(wait)
            else:
                print(f"\n    [error] Qwen API error after {max_retries} retries: {e}")
                return "", f"ERROR: {e}"


def call_deepseek(client, messages, model="deepseek-v4-pro", max_retries=5,
                  max_tokens=384 * 1024,
                  request_timeout=120.0,
                  reasoning_effort="high", thinking_type="enabled",
                  empty_response_retries=1):
    """Call DeepSeek API, return (reasoning_content, response_content)."""
    empty_response_count = 0
    for attempt in range(max_retries + 1):
        try:
            if DEEPSEEK_RATE_LIMITER is not None:
                DEEPSEEK_RATE_LIMITER.acquire()

            request = {
                "model": model,
                "messages": messages,
                "stream": False,
            }
            if thinking_type:
                request["extra_body"] = {"thinking": {"type": thinking_type}}
            if reasoning_effort and thinking_type != "disabled":
                request["reasoning_effort"] = reasoning_effort
            if max_tokens is not None:
                request["max_tokens"] = max_tokens

            response = client.with_options(timeout=request_timeout).chat.completions.create(
                **request
            )
            time.sleep(3)
            msg = response.choices[0].message
            reasoning = getattr(msg, 'reasoning_content', None) or ""
            content = msg.content or ""
            if not content.strip() and empty_response_count < empty_response_retries:
                empty_response_count += 1
                finish_reason = getattr(response.choices[0], "finish_reason", "unknown")
                usage = getattr(response, "usage", None)
                print(
                    f"\n    [warning] DeepSeek returned empty final response "
                    f"(finish_reason={finish_reason}, usage={usage}); "
                    f"retrying once with the same settings and max_tokens={max_tokens} ..."
                )
                time.sleep(5)
                continue
            return reasoning, content
        except Exception as e:
            if attempt < max_retries:
                wait = 5 * (attempt + 1)
                print(f"\n    [warning] DeepSeek API error (attempt {attempt+1}/{max_retries+1}): {e}")
                print(f"    Retrying in {wait}s ...")
                time.sleep(wait)
            else:
                print(f"\n    [error] DeepSeek API error after {max_retries} retries: {e}")
                return "", f"ERROR: {e}"



def load_samples(data_path):
    with open(data_path, 'r') as f:
        return [json.loads(l) for l in f]


def pair_vuln_benign(all_samples):
    vuln = [r for r in all_samples if r['target'] == 1]
    benign = [r for r in all_samples if r['target'] == 0]
    return [(vuln[i], benign[i], i) for i in range(len(vuln))]


def extract_tag(content, tag):
    m = re.search(rf'<{tag}>(.*?)</{tag}>', content, re.DOTALL)
    return m.group(1).strip() if m else None


def extract_code_block(content):
    """Extract PoC code from response content.
    Tries ```python / ```python3 first, then ```c, then generic ```.
    When multiple blocks exist, picks the most complete one (has includes/main or is longest)."""
    # Try fenced Python code blocks first
    m = re.search(r'```python3?\s*\n(.*?)\n```', content, re.DOTALL)
    if m:
        return m.group(1).strip()
    # Try fenced C code blocks and pick the best one if multiple exist.
    c_blocks = re.findall(r'```c\s*\n(.*?)\n```', content, re.DOTALL)
    if c_blocks:
        # Prefer blocks that look like complete programs (have #include and main)
        for block in c_blocks:
            block_stripped = block.strip()
            if '#include' in block_stripped and 'main(' in block_stripped:
                return block_stripped
        # Otherwise return the longest block
        return max(c_blocks, key=len).strip()
    # Try generic fenced blocks
    for m in re.finditer(r'```\s*\n(.*?)\n```', content, re.DOTALL):
        block = m.group(1).strip()
        if len(block) < 30:
            continue
        # Check for code-like patterns (Python or C)
        if any(kw in block for kw in ['import ', 'def ', 'class ', 'struct ',
                                        'int ', 'void ', 'main(', '#include',
                                        'socket', 'sys.', 'b\'', 'b"',
                                        'malloc', 'memcpy', 'printf']):
            return block
    # Fallback: return full content if non-empty
    return content.strip() if content.strip() else None


def strip_outer_code_fence(text):
    """Remove one surrounding markdown code fence if the whole text is fenced."""
    if not text:
        return text
    m = re.match(r'^\s*```[a-zA-Z0-9_+-]*\s*\n(.*?)\n```\s*$', text, re.DOTALL)
    return m.group(1).strip() if m else text.strip()


def validate_poc(poc_text, min_len=50):
    """Quick heuristic check: is this actually a PoC script.

    The router can request Python, C/C++, PHP, HTML/JS, or shell PoCs depending
    on the vulnerability class. This check intentionally stays heuristic; it is
    a formatting guard, not a semantic exploit validator.
    Returns True if poc_text looks like executable code."""
    if not poc_text or len(poc_text) < min_len:
        return False
    poc_text = strip_outer_code_fence(poc_text)
    head = poc_text.lstrip()[:200]
    if head.startswith(("##", "###", "# ", "**Analysis")):
        return False
    # Must contain at least some code-specific patterns
    code_patterns = [
        # Python
        'import ', 'def ', 'class ', 'print(', 'sys.stdout',
        'struct.', 'socket', 'b\'', 'b"', '#!/usr',
        'subprocess', 'os.', 'open(', 'base64',
        # C
        'int main', 'void main', '#include', 'malloc',
        'memcpy', 'printf(', 'fprintf(', 'struct ',
        # PHP
        '<?php', 'echo ', '$argv', '$_GET', '$_POST', '->',
        # HTML / JavaScript
        '<!doctype html', '<html', '<script', 'document.',
        'addEventListener', 'fetch(', 'XMLHttpRequest', 'new Worker',
        # Shell
        '#!/bin/sh', '#!/usr/bin/env bash', 'set -e', 'curl ',
    ]
    lowered = poc_text.lower()
    return any(p in poc_text for p in code_patterns) or any(
        p in lowered for p in ['<!doctype html', '<html', '<script']
    )


def extract_tags(content):
    """Extract PoC from <poc> tags first, with code-block fallback for old outputs."""
    code = extract_tag(content, "poc")
    if code is None:
        # Keep the old code-block extractor for results generated before <poc> output.
        code = extract_code_block(content)
    else:
        code = strip_outer_code_fence(code)
    return {
        "has_poc_tag": code is not None,
        "poc": code,
    }


class CVEDedup:
    """Lazy CVE deduplication during pipeline execution.

    Tracks seen CVEs. When a CVE is encountered a second time,
    calls LLM to judge whether it's the same vulnerability as the
    first processed pair. If same, skip it. If different, process it.
    """

    def __init__(self, llm_client):
        self.seen = {}  # cve -> CanonicalPair
        self.llm_client = llm_client

    def should_skip(self, pair) -> bool:
        if self.llm_client is None:
            return False

        if pair.cve not in self.seen:
            self.seen[pair.cve] = pair
            return False

        prev = self.seen[pair.cve]
        same = self._compare(prev, pair)
        if same:
            print(f"  [CVE dedup] Skipping duplicate {pair.cve} (same as pair_idx={prev.pair_idx})")
            return True
        # Different vulnerability: update stored pair.
        print(f"  [CVE dedup] {pair.cve} pair_idx={pair.pair_idx} is a different vuln, processing")
        self.seen[pair.cve] = pair
        return False

    def _compare(self, a, b) -> bool:
        prompt = f"""Given the same CVE ({a.cve}), two different code pairs were found.
Judge whether they represent the **same underlying vulnerability** (same code path, same root cause).

[Pair A] (pair_idx={a.pair_idx})
Vulnerable function:
```c
{a.vuln_func[:500]}
```
Patched function:
```c
{a.benign_func[:500]}
```

[Pair B] (pair_idx={b.pair_idx})
Vulnerable function:
```c
{b.vuln_func[:500]}
```
Patched function:
```c
{b.benign_func[:500]}
```

Return ONLY <same_vulnerability>YES</same_vulnerability> or <same_vulnerability>NO</same_vulnerability>."""
        try:
            resp = self.llm_client.chat.completions.create(
                model="qwen/qwen3.5-9b",
                messages=[
                    {"role": "system", "content": "You are a security researcher."},
                    {"role": "user", "content": prompt},
                ],
                stream=False,
            )
            content = resp.choices[0].message.content or ""
            return "YES" in content.upper().replace("<SAME_VULNERABILITY>", "").replace("</SAME_VULNERABILITY>", "").strip()[:3]
        except Exception:
            # On error, conservatively skip to avoid duplicates
            return True


# -------------------------------------------------------
# STEP 1: Context Classification & Augmentation
# -------------------------------------------------------

def _pair_to_dict(pair):
    """Convert CanonicalPair to dict for functions that expect dict access."""
    if hasattr(pair, 'vuln_func'):
        return {
            'func': pair.vuln_func,
            'cve': pair.cve,
            'cwe': pair.cwe,
            'cve_desc': pair.cve_desc,
            'project': pair.project,
            'pair_idx': pair.pair_idx,
            'raw': pair.raw,
        }
    return pair


def step1_classify(client, vuln_rec, model):
    prompt = JUDGE_PROMPT.format(
        cve=vuln_rec.get("cve", "N/A"),
        cve_desc=vuln_rec.get("cve_desc", "N/A"),
        cwe=", ".join(vuln_rec.get("cwe", [])),
        func=vuln_rec["func"],
    )
    messages = [
        {"role": "system", "content": "You are a security research assistant."},
        {"role": "user", "content": prompt},
    ]
    _, content = call_deepseek(client, messages, model)
    return content


def step1_generate(client, vuln_rec, missing, model):
    prompt = GENERATOR_PROMPT.format(
        cve=vuln_rec.get("cve", "N/A"),
        cve_desc=vuln_rec.get("cve_desc", "N/A"),
        missing_context=missing,
        func=vuln_rec["func"],
    )
    messages = [
        {"role": "system", "content": "You are a security research assistant."},
        {"role": "user", "content": prompt},
    ]
    _, content = call_deepseek(client, messages, model)
    return content


def step1_verify(client, vuln_rec, augmented, model):
    prompt = VERIFIER_PROMPT.format(
        cve=vuln_rec.get("cve", "N/A"),
        cve_desc=vuln_rec.get("cve_desc", "N/A"),
        augmented_context=augmented,
    )
    messages = [
        {"role": "system", "content": "You are a security research assistant."},
        {"role": "user", "content": prompt},
    ]
    _, content = call_deepseek(client, messages, model)
    return content


def run_context_augmentation(client, vuln_rec, model, max_verify_rounds=2):
    """Run the full Step 1 pipeline for one sample."""
    print(f"  [Step 1a] Judging self-containment...")
    judge_result = step1_classify(client, vuln_rec, model)

    judgment = extract_tag(judge_result, "judgment")
    reason = extract_tag(judge_result, "reason")
    missing = extract_tag(judge_result, "missing")

    print(f"    Judgment: {judgment}")
    print(f"    Reason: {reason}")

    if judgment != "NOT_SELF_CONTAINED" or not missing:
        return {
            "self_contained": True,
            "judge_raw": judge_result,
            "augmented_context": None,
        }

    print(f"    Missing: {missing[:200]}...")
    print(f"  [Step 1b] Generating context...")
    gen_result = step1_generate(client, vuln_rec, missing, model)
    augmented = extract_tag(gen_result, "context")

    if not augmented:
        return {
            "self_contained": False,
            "judge_raw": judge_result,
            "augmented_context": gen_result,
        }

    print(f"    Generated context ({len(augmented)} chars)")

    # Verification rounds
    for rnd in range(max_verify_rounds):
        print(f"  [Step 1c] Verifying (round {rnd+1})...")
        verify_result = step1_verify(client, vuln_rec, augmented, model)

        verdict = extract_tag(verify_result, "verdict")
        verify_reason = extract_tag(verify_result, "reason")
        feedback = extract_tag(verify_result, "feedback")

        print(f"    Verdict: {verdict} | Reason: {verify_reason}")

        if verdict == "SUFFICIENT":
            break

        if feedback and rnd < max_verify_rounds - 1:
            print(f"    Feedback: {feedback[:200]}...")
            # Regenerate with feedback
            print(f"    [Step 1b] Regenerating with feedback...")
            gen_result = step1_generate(client, vuln_rec, missing + "\n\nVerifier feedback: " + feedback, model)
            augmented = extract_tag(gen_result, "context")
            if augmented:
                print(f"    Regenerated ({len(augmented)} chars)")
        else:
            break

    return {
        "self_contained": False,
        "judge_raw": judge_result,
        "gen_raw": gen_result,
        "verify_raw": verify_result,
        "augmented_context": augmented,
        "verdict": verdict,
    }


# -------------------------------------------------------
# STEP 2: Teacher Reasoning Distillation
# -------------------------------------------------------

def context_reject_reason(context_aug):
    """Return a rejection reason if Step 1 context is not fit for distillation."""
    if not context_aug:
        return None
    if context_aug.get("self_contained", True):
        return None
    if not context_aug.get("augmented_context"):
        return "missing_augmented_context"
    if context_aug.get("verdict") != "SUFFICIENT":
        return f"verifier_{context_aug.get('verdict') or 'missing'}"
    return None


def strip_outer_code_fence(text):
    """Remove one outer markdown code fence so callers can wrap it cleanly."""
    if not text:
        return text
    stripped = str(text).strip()
    match = re.fullmatch(r"```[A-Za-z0-9_+.-]*\s*\n(.*?)\n```", stripped, re.DOTALL)
    if match:
        return match.group(1).strip()
    return stripped


def run_distillation(client, vuln_rec, benign_rec, augmented_context, model,
                     router=None, vuln_class=None):
    """Run Step 2: teacher reasoning distillation with patch diff."""
    # Handle both CanonicalPair and dict
    if hasattr(vuln_rec, 'vuln_func'):
        vuln_dict = _pair_to_dict(vuln_rec)
        vuln_dict['func'] = vuln_rec.vuln_func
        benign_dict = _pair_to_dict(benign_rec)
        benign_dict['func'] = benign_rec.benign_func
    else:
        vuln_dict = vuln_rec
        benign_dict = benign_rec

    # Build prompt
    if router and vuln_class:
        # Class-specific prompt routing
        full_prompt = router.compose_prompt(
            vuln_class=vuln_class,
            project=vuln_dict.get("project", "unknown"),
            cve=vuln_dict.get("cve", "N/A"),
            cve_desc=vuln_dict.get("cve_desc", "N/A"),
            cwe=vuln_dict.get("cwe", []),
            vuln_func=vuln_dict["func"],
            patched_func=benign_dict["func"],
            augmented_context=augmented_context,
        )
    elif augmented_context:
        # Backward-compatible: old monolithic prompt with augmented context
        full_prompt = f"""[Context]
The following vulnerable code and its fix patch were extracted from the {vuln_dict.get("project", "unknown")} project.

CVE ID: {vuln_dict.get("cve", "N/A")}
Description: {vuln_dict.get("cve_desc", "N/A")}
CWE Type: {", ".join(vuln_dict.get("cwe", []))}

[Augmented Context] (For reference only; helps understand external code dependencies)
```c
{augmented_context}
```

[Vulnerable Code]
```c
{vuln_dict["func"]}
```

[Fixed Code]
```c
{benign_dict["func"]}
```

[Task]
Analyze the root cause of this vulnerability by comparing the vulnerable code with its fix, and construct a PoC that triggers it.

[Trigger Path]
In your analysis, briefly explain the data flow path:
1. Which function/code line contains the vulnerability?
2. Who calls this function? Through what entry point does user input arrive here?
3. Which input fields can the attacker control?

[Important Requirement]
In your reasoning process (reasoning_content), you must NOT mention, quote, or describe any content from the fixed code ("Fixed Code" section).
Do not write statements like "by observing the patch, I found it ...", "the fixed code added ... after ...", or "the patch removed ...".
The fixed code is for your private reference only to understand how the vulnerability was remediated. Your reasoning must be based entirely on analyzing the vulnerable code itself.

[Answer Format]
First provide a vulnerability analysis (root cause, trigger conditions, impact), then at the end provide complete, independently executable PoC code.

[PoC Writing Strict Rules]
1. Do NOT output only raw payload data or byte streams (e.g., b"A"*1000)!
2. For network protocol vulnerabilities, write a standalone Python 3 script with socket communication, complete packet assembly, and sending.
3. For local API vulnerabilities, write a C reproduction program (Harness) with a main function, struct definitions, memory allocation, and vulnerable function invocation.
4. All code must be placed inside a single ```python or ```c code block. No explanatory natural language is allowed inside the code block!
5. The PoC should reproduce the vulnerability (trigger crash/overflow/exception) or print the constructed Payload to stdout."""
    else:
        full_prompt = PROMPT_PATCH_DIFF.format(
            project=vuln_dict.get("project", "unknown"),
            cve=vuln_dict.get("cve", "N/A"),
            cve_desc=vuln_dict.get("cve_desc", "N/A"),
            cwe=", ".join(vuln_dict.get("cwe", [])),
            vuln_func=vuln_dict["func"],
            patched_func=benign_dict["func"],
        )

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": full_prompt},
    ]
    reasoning, content = call_deepseek(client, messages, model)
    return full_prompt, reasoning, content


# -------------------------------------------------------
# STEP 4: Patch-unaware Reasoning Rewrite
# -------------------------------------------------------

PATCH_UNAWARE_LEAK_PATTERNS = [
    ("patch", re.compile(r"\bpatch(?:ed|es|ing)?\b", re.IGNORECASE)),
    ("diff", re.compile(r"\bdiff\b", re.IGNORECASE)),
    ("commit", re.compile(r"\bcommit\b", re.IGNORECASE)),
    ("patched version", re.compile(r"\bpatched\s+version\b", re.IGNORECASE)),
    ("benign version", re.compile(r"\bbenign\s+version\b", re.IGNORECASE)),
    ("cve id", re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)),
    ("cwe id", re.compile(r"\bCWE-\d+\b", re.IGNORECASE)),
]


def find_reasoning_leak_terms(text):
    """Return patch/CVE metadata terms that should not appear in SFT reasoning."""
    if not text:
        return []
    found = []
    for name, pattern in PATCH_UNAWARE_LEAK_PATTERNS:
        if hasattr(pattern, "search"):
            if pattern.search(text):
                found.append(name)
        elif pattern in text:
            found.append(name)
    return sorted(set(found))


def build_training_question(record, router):
    """Build the code-only SFT question used by both rewrite and Step 5."""
    ca = record.get("context_aug", {}) or {}
    augmented_context = strip_outer_code_fence(ca.get("augmented_context"))

    vuln_class = router.classify(
        record.get("cwe", []),
        record.get("cve_desc", ""),
        record.get("vuln_func", ""),
        record.get("cve", ""),
    )
    class_instructions = router.format_class_instructions(vuln_class)

    parts = [
        "Analyze the following C/C++ code and determine whether a security vulnerability exists.",
        "If a vulnerability exists, analyze the root cause, trigger conditions, attacker-controlled input, data-flow path, impact, and construct a triggering PoC.",
        "",
    ]
    if augmented_context:
        parts.extend([
            "[Additional Context]",
            "```c",
            augmented_context,
            "```",
            "",
        ])
    parts.extend([
        "[Code Under Analysis]",
        "```c",
        record["vuln_func"],
        "```",
        "",
        class_instructions,
    ])
    return "\n".join(parts), vuln_class


def rewrite_reasoning_code_only(client, original_reasoning, question, model,
                                max_retries=1):
    """Rewrite teacher reasoning so it only uses information visible in question."""
    if not original_reasoning or not original_reasoning.strip():
        return {
            "reasoning": "",
            "raw_response": "",
            "patch_leak_terms": [],
            "attempts": 0,
        }

    feedback = ""
    last_content = ""
    for attempt in range(max_retries + 1):
        prompt = PROMPT_REASONING_REWRITE_CODE_ONLY.format(
            question=question,
            reasoning=original_reasoning,
        )
        if feedback:
            prompt += feedback

        messages = [
            {"role": "system", "content": REASONING_REWRITE_SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]
        _, content = call_deepseek(client, messages, model)
        last_content = content
        rewritten = extract_tag(content, "reasoning") or content.strip()
        rewritten = rewritten.strip()
        leak_terms = find_reasoning_leak_terms(rewritten)
        if not leak_terms or attempt == max_retries:
            return {
                "reasoning": rewritten,
                "raw_response": last_content,
                "patch_leak_terms": leak_terms,
                "attempts": attempt + 1,
            }

        feedback = (
            "\n\n[Retry requirement]\n"
            "The previous rewrite still contained forbidden metadata terms: "
            f"{', '.join(leak_terms)}. Rewrite again and remove those terms "
            "without changing the reasoning flow."
        )

    return {
        "reasoning": "",
        "raw_response": last_content,
        "patch_leak_terms": ["rewrite_failed"],
        "attempts": max_retries + 1,
    }


def run_reasoning_rewrite(client, input_path, output_path, model, source=None):
    """Step 4: rewrite distillation reasoning into patch-unaware reasoning."""
    if not os.path.exists(input_path):
        print(f"Error: Step 4 requires Step 2 output ({input_path})")
        sys.exit(1)

    results = load_samples(input_path)
    yaml_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "prompt_templates", "poc_classes.yaml"
    )
    router = PromptRouter(yaml_path)

    done = set()
    if os.path.exists(output_path):
        for r in load_samples(output_path):
            pair_idx = r.get("pair_idx")
            if pair_idx is not None:
                done.add(pair_idx)

    print(f"Step 4: rewriting reasoning for {len(results)} samples...")
    if done:
        print(f"  Resuming: skipping {len(done)} already-rewritten samples")

    rewritten_count = 0
    leak_count = 0
    skipped = 0
    for r in results:
        pair_idx = r.get("pair_idx")
        if pair_idx in done:
            skipped += 1
            continue
        reject_reason = context_reject_reason(r.get("context_aug"))
        if reject_reason:
            print(f"  Skipping pair_idx={pair_idx}: context rejected ({reject_reason})")
            skipped += 1
            continue

        original_reasoning = r.get("reasoning", "")
        if not original_reasoning:
            print(f"  Skipping pair_idx={pair_idx}: missing original reasoning")
            skipped += 1
            continue

        question, vuln_class = build_training_question(r, router)
        print(f"  [Step 4] pair_idx={pair_idx} class={vuln_class.class_id}")
        rewrite = rewrite_reasoning_code_only(
            client, original_reasoning, question, model
        )
        if rewrite.get("patch_leak_terms"):
            leak_count += 1
            print(f"    Warning: remaining leak terms: {rewrite['patch_leak_terms']}")
        else:
            print(f"    rewritten_len={len(rewrite.get('reasoning', ''))}")

        out = dict(r)
        out.update({
            "rewrite_prompt_type": "rewrite_reasoning_code_only",
            "rewritten_reasoning": rewrite.get("reasoning", ""),
            "reasoning_rewrite": rewrite,
        })
        with open(output_path, 'a') as f:
            f.write(json.dumps(out, ensure_ascii=False) + "\n")
        rewritten_count += 1

    print(f"Step 4 done: rewritten={rewritten_count}, "
          f"remaining_leak_warnings={leak_count}, skipped={skipped}")
    print(f"Saved to {output_path}")


# -------------------------------------------------------
# STEP 3: PoC Quality Evaluation
# -------------------------------------------------------
def _parse_eval_scores(content):
    """Parse per-dimension scores and total from eval response."""
    scores = {}
    for dim in ["Relevance", "Exploitability", "Completeness", "Precision", "Safety", "Correctness"]:
        m = re.search(rf'{dim}:\s*(\d+)/5', content)
        if m:
            scores[dim] = int(m.group(1))
    m = re.search(r'<total_score>\s*(\d+)\s*</total_score>', content)
    total = int(m.group(1)) if m else sum(scores.values())
    return scores, total


def run_poc_eval(client, vuln_rec, poc_text, eval_model="deepseek-v4-pro"):
    """Evaluate PoC quality on 6 dimensions. Returns per-dimension scores and total."""
    prompt = POC_EVAL_PROMPT.format(
        cve=vuln_rec.get("cve", "N/A"),
        cve_desc=vuln_rec.get("cve_desc", "N/A"),
        cwe=", ".join(vuln_rec.get("cwe", [])),
        vuln_func=vuln_rec["func"],
        poc=poc_text,
    )
    messages = [
        {"role": "system", "content": "You are a security researcher evaluating PoC quality."},
        {"role": "user", "content": prompt},
    ]
    _, content = call_deepseek(client, messages, eval_model)

    scores, total = _parse_eval_scores(content)
    analysis = extract_tag(content, "analysis")

    return {
        "analysis": analysis,
        "scores": scores,
        "total_score": total,  # 6-30
        "raw_response": content,
    }


def run_qwen_poc_eval(client, qwen_record, distill_records, eval_model="deepseek-v4-pro"):
    """Evaluate a Qwen baseline PoC using the same 6-dimension eval.
    Looks up vuln_func from distill records by pair_idx."""
    pair_idx = qwen_record.get("pair_idx")
    # Find matching distill record for vuln_func
    vuln_func = None
    for d in distill_records:
        if d.get("pair_idx") == pair_idx:
            vuln_func = d.get("vuln_func")
            break

    if not vuln_func:
        return {"error": f"could not find vuln_func for pair_idx={pair_idx}"}

    poc_text = qwen_record.get("extracted", {}).get("poc", "")
    if not poc_text:
        return {"error": "no PoC extracted"}

    prompt = POC_EVAL_PROMPT.format(
        cve=qwen_record.get("cve", "N/A"),
        cve_desc=qwen_record.get("cve_desc", ""),
        cwe=", ".join(qwen_record.get("cwe", [])),
        vuln_func=vuln_func,
        poc=poc_text,
    )
    messages = [
        {"role": "system", "content": "You are a security researcher evaluating PoC quality."},
        {"role": "user", "content": prompt},
    ]
    _, content = call_deepseek(client, messages, eval_model)

    scores, total = _parse_eval_scores(content)
    analysis = extract_tag(content, "analysis")

    return {
        "analysis": analysis,
        "scores": scores,
        "total_score": total,
        "raw_response": content,
    }


# -------------------------------------------------------
# STEP 5: SFT Data Formatting
# -------------------------------------------------------

def run_reformatter(input_path, output_path, poc_eval_path=None, min_poc_score=None,
                    source=None, reasoning_rewrite_path=None,
                    require_rewritten_reasoning=False):
    if source is None:
        from data_source import PrimeVulSource
        source = PrimeVulSource()
    results = load_samples(input_path)
    # Load poc_eval from separate file if provided
    poc_eval_map = {}
    if poc_eval_path and os.path.exists(poc_eval_path):
        for r in load_samples(poc_eval_path):
            pair_idx = r.get("pair_idx")
            if r.get("poc_eval") and pair_idx is not None:
                poc_eval_map[pair_idx] = r["poc_eval"]

    reasoning_rewrite_map = {}
    if reasoning_rewrite_path and os.path.exists(reasoning_rewrite_path):
        for r in load_samples(reasoning_rewrite_path):
            pair_idx = r.get("pair_idx")
            rewritten = (
                r.get("rewritten_reasoning")
                or r.get("reasoning_rewrite", {}).get("reasoning")
            )
            if pair_idx is not None and rewritten:
                reasoning_rewrite_map[pair_idx] = {
                    "reasoning": rewritten,
                    "patch_leak_terms": (
                        r.get("reasoning_rewrite", {}).get("patch_leak_terms")
                        or find_reasoning_leak_terms(rewritten)
                    ),
                }

    # Initialize prompt router for class-specific training questions
    yaml_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "prompt_templates", "poc_classes.yaml"
    )
    router = PromptRouter(yaml_path)  # no LLM client needed; CWE mapping is deterministic

    training_data = []
    for r in results:
        reject_reason = context_reject_reason(r.get("context_aug"))
        if reject_reason:
            print(f"  Skipping pair_idx={r.get('pair_idx')}: context rejected ({reject_reason})")
            continue

        if not r.get("extracted", {}).get("has_poc_tag") or r.get("refused"):
            continue

        poc = r.get("extracted", {}).get("poc", "")
        if not validate_poc(poc):
            print(f"  Skipping pair_idx={r.get('pair_idx')}: PoC failed validation (not executable Python)")
            continue

        pair_idx = r.get("pair_idx")
        pe = poc_eval_map.get(pair_idx)
        if pe and min_poc_score is not None:
            if pe.get("total_score", 0) < min_poc_score:
                print(f"  Skipping pair_idx={pair_idx}: PoC score {pe.get('total_score')} < {min_poc_score}")
                continue

        ca = r.get("context_aug", {})
        augmented_context = strip_outer_code_fence(ca.get("augmented_context")) if ca else None
        self_contained = ca.get("self_contained", True) if ca else True

        # Prefer patch-unaware rewritten reasoning for SFT.
        rewrite_entry = reasoning_rewrite_map.get(pair_idx)
        review_flag = None
        if rewrite_entry:
            leak_terms = rewrite_entry.get("patch_leak_terms") or []
            if leak_terms:
                # Keep the sample but flag it for potential manual review.
                # V4-pro's rewrite is generally trustworthy; hard-coded leak
                # terms may be false positives.
                review_flag = f"possible_leak_terms: {leak_terms}"
                print(f"  [needs review] pair_idx={pair_idx}: leak terms {leak_terms}")
            reasoning = rewrite_entry.get("reasoning", "")
            reasoning_source = "rewrite_reasoning_code_only"
        elif require_rewritten_reasoning:
            print(f"  Skipping pair_idx={pair_idx}: missing rewritten reasoning")
            continue
        else:
            reasoning = r.get("reasoning", "")
            reasoning_source = "original_reasoning"
        if not reasoning:
            continue  # skip if no reasoning captured

        question, vuln_class = build_training_question(r, router)

        sample = {
            "pair_idx": pair_idx,
            "id": f"{source.source_name.lower()}_pair{pair_idx}_{r.get('cve', 'unknown')}",
            "cve": r.get("cve", ""),
            "cwe": r.get("cwe", []),
            "project": r.get("project", ""),
            "source": source.source_name,
            "label": "vulnerable",
            "self_contained": self_contained,
            "augmented_context": augmented_context,
            "question": question,
            "v4_reasoning": reasoning,
            "v4_response": poc,
            "reasoning_source": reasoning_source,
            "poc_eval": pe,
            "models": {
                "v4": {
                    "reasoning": reasoning,
                    "response": poc,
                },
            },
        }
        if review_flag:
            sample["review_flag"] = review_flag
        training_data.append(sample)

    with open(output_path, 'w') as f:
        for s in training_data:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")

    flagged = [s for s in training_data if s.get("review_flag")]
    print(f"Converted {len(training_data)} samples to training format.")
    if flagged:
        print(f"  [warning] {len(flagged)} samples flagged for potential review:")
        for s in flagged:
            print(f"    pair_idx={s['pair_idx']} {s['cve']}: {s['review_flag']}")
    print(f"Saved to {output_path}")


# -------------------------------------------------------
# STEP 6: Qwen Baseline Evaluation
# -------------------------------------------------------

def run_qwen_baseline(training_data_path, output_path, max_pairs=None):
    """Query Qwen 3.5-9b with the same questions from training data.
    This serves as a pre-fine-tuning baseline for comparison."""

    client = get_qwen_client()
    samples = load_samples(training_data_path)
    if max_pairs:
        samples = samples[:max_pairs]

    print(f"Step 6: Qwen 3.5-9b baseline evaluation on {len(samples)} samples...")
    print(f"  Model: qwen/qwen3.5-9b (OpenRouter)")
    print(f"  Input: {training_data_path}")

    for s in samples:
        print(f"\n  --- {s.get('id', 'unknown')} ---")
        question = s.get("question", "")
        if not question:
            print("    Skipping: no question field")
            continue

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": question},
        ]
        reasoning, content = call_qwen(client, messages)
        tags = extract_tags(content)
        refused = any(kw in content.lower() for kw in ["i cannot", "i can't", "i won't", "i am unable"])

        result = {
            "pair_idx": s.get("pair_idx"),
            "id": s.get("id", ""),
            "cve": s.get("cve", ""),
            "cwe": s.get("cwe", []),
            "project": s.get("project", ""),
            "model": "qwen/qwen3.5-9b",
            "question": question,
            "reasoning": reasoning,
            "response": content,
            "extracted": tags,
            "refused": refused,
            # Include DeepSeek data for comparison
            "v4_reasoning": s.get("v4_reasoning", ""),
            "v4_response": s.get("v4_response", ""),
        }
        with open(output_path, 'a') as f:
            f.write(json.dumps(result, ensure_ascii=False) + "\n")

        print(f"    reasoning_len={len(reasoning)} | "
              f"poc={'PASS' if tags['has_poc_tag'] else 'FAIL'} | "
              f"refused={'YES' if refused else 'NO'}")

    # Print summary
    if os.path.exists(output_path):
        all_results = load_samples(output_path)
    else:
        all_results = []
    total = len(all_results)
    if total == 0:
        print(f"\n{'='*60}")
        print(f"Qwen Baseline Summary: No samples processed (empty training data)")
        print(f"{'='*60}")
        return
    poc_pass = sum(1 for r in all_results if r.get("extracted", {}).get("has_poc_tag"))
    refused = sum(1 for r in all_results if r.get("refused"))
    avg_reasoning = sum(len(r.get("reasoning", "")) for r in all_results) / max(total, 1)

    print(f"\n{'='*60}")
    print(f"Qwen Baseline Summary:")
    print(f"  Total: {total} | PoC PASS: {poc_pass}/{total} | Refused: {refused}/{total}")
    print(f"  Avg reasoning length: {avg_reasoning:.0f} chars")
    print(f"  Results saved to: {output_path}")
    print(f"{'='*60}")


def run_qwen_poc_evaluation(client, qwen_path, distill_path, output_path, eval_model):
    """Step 7: Evaluate Qwen baseline PoCs using the same 6-dimension scoring."""
    qwen_results = load_samples(qwen_path)
    distill_records = load_samples(distill_path)

    print(f"Step 7: Qwen baseline PoC evaluation on {len(qwen_results)} samples...")
    print(f"  Evaluator: {eval_model}")

    for r in qwen_results:
        print(f"  --- {r.get('id', 'unknown')} ---")
        poc_text = r.get("extracted", {}).get("poc", "")
        if not poc_text:
            print("    Skipping: no PoC extracted")
            continue

        eval_result = run_qwen_poc_eval(client, r, distill_records, eval_model)
        r["poc_eval"] = eval_result
        with open(output_path, 'a') as f:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

        total = eval_result.get("total_score", 0)
        scores = eval_result.get("scores", {})
        print(f"    Total: {total}/30 | Scores: {scores}")

    # Print summary
    if os.path.exists(output_path):
        all_eval = load_samples(output_path)
    else:
        all_eval = []
    total = len(all_eval)
    if total == 0:
        print(f"\n{'='*60}")
        print(f"Qwen PoC Eval Summary: No samples evaluated")
        print(f"{'='*60}")
        return

    avg_total = sum(r.get("poc_eval", {}).get("total_score", 0) for r in all_eval) / total
    print(f"\n{'='*60}")
    print(f"Qwen PoC Evaluation Summary:")
    print(f"  Total evaluated: {total}")
    print(f"  Avg total score: {avg_total:.1f}/30")

    # Per-dimension averages
    dims = ["Relevance", "Exploitability", "Completeness", "Precision", "Safety", "Correctness"]
    for d in dims:
        vals = [r.get("poc_eval", {}).get("scores", {}).get(d, 0) for r in all_eval]
        avg = sum(vals) / max(len(vals), 1)
        print(f"  Avg {d}: {avg:.1f}/5")
    print(f"{'='*60}")


def run_pipeline(data_path, output_dir, model, steps, max_pairs=None, source=None, start_pair=0):
    """Run the full reasoning pipeline.

    Args:
        source: DataSource instance. If None, defaults to PrimeVulSource().
    """
    if source is None:
        source = PrimeVulSource()

    client = get_client()

    # Initialize prompt router for class-specific PoC prompts
    yaml_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "prompt_templates", "poc_classes.yaml"
    )
    router = PromptRouter(yaml_path, llm_client=get_qwen_client())

    all_samples = source.load(data_path)
    pairs = source.normalize(all_samples)

    # Lazy CVE dedup runs inline during the loop with zero startup delay.
    dedup = CVEDedup(get_qwen_client())

    if start_pair:
        pairs = pairs[start_pair:]
    if max_pairs:
        pairs = pairs[:max_pairs]

    os.makedirs(output_dir, exist_ok=True)
    context_file = os.path.join(output_dir, "context_aug_results.jsonl")
    context_reject_file = os.path.join(output_dir, "context_rejects.jsonl")
    distill_file = os.path.join(output_dir, "distill_results.jsonl")
    poc_eval_file = os.path.join(output_dir, "poc_eval_results.jsonl")
    rewrite_file = os.path.join(output_dir, "reasoning_rewrite_results.jsonl")
    training_file = os.path.join(output_dir, "training_data.jsonl")

    # Resume: skip already-processed pairs
    skip_idxs = set()
    if 1 in steps and os.path.exists(context_file):
        with open(context_file) as f:
            for line in f:
                skip_idxs.add(json.loads(line).get("pair_idx"))
        if os.path.exists(context_reject_file):
            with open(context_reject_file) as f:
                for line in f:
                    skip_idxs.add(json.loads(line).get("pair_idx"))
    elif 2 in steps and os.path.exists(distill_file):
        with open(distill_file) as f:
            for line in f:
                skip_idxs.add(json.loads(line).get("pair_idx"))
    if 4 in steps and os.path.exists(rewrite_file):
        rewritten = set()
        for r in load_samples(rewrite_file):
            pair_idx = r.get("pair_idx")
            if pair_idx is not None:
                rewritten.add(pair_idx)
        skip_idxs.update(rewritten)
        if rewritten:
            print(f"  Step 4 resume: skipping {len(rewritten)} already-rewritten pairs")
    if skip_idxs:
        print(f"  Resuming: skipping {len(skip_idxs)} already-processed pairs")

    # Load existing Step 2 distillation results when running Step 3/4 without Step 2.
    distill_records = {}
    if (3 in steps or 4 in steps) and 2 not in steps and os.path.exists(distill_file):
        for r in load_samples(distill_file):
            pair_idx = r.get("pair_idx")
            if pair_idx is not None:
                distill_records[pair_idx] = r

    total = len(pairs)
    per_case_steps = any(step in steps for step in (1, 2, 3, 4))
    progress = ProgressTracker(total, "Pipeline") if per_case_steps else None
    processed = 0
    skipped = 0
    context_rejected = 0

    for pair in pairs:
        if not per_case_steps:
            break
        progress.update(1)
        # Lazy CVE dedup: skip if this CVE was already processed with same vuln
        if dedup.should_skip(pair):
            skipped += 1
            continue

        pair_idx = pair.pair_idx
        if pair_idx in skip_idxs:
            skipped += 1
            continue

        case_start = time.time()
        print(f"\n\n--- Case {processed+1}/{total - skipped} | "
              f"Pair idx={pair_idx} | CVE: {pair.cve} | {pair.cwe} | {pair.project} ---")

        # Build vuln/benign dicts for Step 1 and Step 2
        vuln_dict = _pair_to_dict(pair)
        vuln_dict['func'] = pair.vuln_func
        benign_dict = {'func': pair.benign_func}

        if (3 in steps or 4 in steps) and 2 not in steps:
            result = dict(distill_records.get(pair_idx, {}))
            if not result:
                print(f"  Skipping pair_idx={pair_idx}: no Step 2 distillation result")
                skipped += 1
                continue
            aug_result = result.get("context_aug") or {
                "self_contained": True,
                "augmented_context": None,
            }
        else:
            result = {
                "pair_idx": pair_idx,
                "cve": pair.cve,
                "cwe": pair.cwe,
                "project": pair.project,
                "vuln_func": pair.vuln_func,
                "patched_func": pair.benign_func,
            }

        # Step 1: Context Augmentation
        if 1 in steps:
            aug_start = time.time()
            aug_result = run_context_augmentation(client, vuln_dict, model)
            aug_time = time.time() - aug_start
            result["context_aug"] = aug_result
            with open(context_file, 'a') as f:
                f.write(json.dumps(result, ensure_ascii=False) + "\n")

            reject_reason = context_reject_reason(aug_result)
            if reject_reason:
                result["context_rejected"] = True
                result["context_reject_reason"] = reject_reason
                with open(context_reject_file, 'a') as f:
                    f.write(json.dumps(result, ensure_ascii=False) + "\n")
                context_rejected += 1
                print(f"  [Step 1] Context rejected ({reject_reason}); skipping downstream steps.")
                continue
        else:
            aug_result = result.get("context_aug") or {
                "self_contained": True,
                "augmented_context": None,
            }
            aug_time = 0

        # Step 2: Teacher Reasoning Distillation
        if 2 in steps:
            distill_start = time.time()
            # Classify vulnerability type for prompt routing
            vuln_class = router.classify(pair.cwe, pair.cve_desc, pair.vuln_func, pair.cve)
            prompt, reasoning, content = run_distillation(
                client, vuln_dict, benign_dict, aug_result.get("augmented_context"), model,
                router=router, vuln_class=vuln_class,
            )
            tags = extract_tags(content)
            refused = any(kw in content.lower() for kw in ["i cannot", "i can't", "i won't", "i am unable"])
            prompt_family = "patch_diff" if pair.benign_func.strip() else "vulnerable_only"

            result.update({
                "prompt_type": f"{prompt_family}:{vuln_class.class_id}", "model": model,
                "prompt": prompt,
                "reasoning": reasoning,
                "response": content,
                "extracted": tags, "refused": refused,
            })
            with open(distill_file, 'a') as f:
                f.write(json.dumps(result, ensure_ascii=False) + "\n")
            distill_time = time.time() - distill_start

            print(f"  reasoning_len={len(reasoning)} | "
                  f"poc={'PASS' if tags['has_poc_tag'] else 'FAIL'} | "
                  f"refused={'YES' if refused else 'NO'}")
        else:
            distill_time = 0

        # Step 3: PoC Quality Evaluation
        eval_time = 0
        if 3 in steps:
            poc_text = result.get("extracted", {}).get("poc", "")
            if poc_text:
                eval_start = time.time()
                print(f"  [Step 3] Evaluating PoC quality...")
                eval_result = run_poc_eval(client, vuln_dict, poc_text, model)
                result["poc_eval"] = eval_result
                with open(poc_eval_file, 'a') as f:
                    f.write(json.dumps(result, ensure_ascii=False) + "\n")
                eval_time = time.time() - eval_start
                print(f"    Total: {eval_result['total_score']}/30 | Scores: {eval_result['scores']}")

        # Step 4: Patch-unaware Reasoning Rewrite (per-case inline)
        rewrite_time = 0
        if 4 in steps:
            original_reasoning = result.get("reasoning", "")
            context_ok = not context_reject_reason(result.get("context_aug"))
            if context_ok and original_reasoning and original_reasoning.strip():
                rewrite_start = time.time()
                question, vuln_class = build_training_question(result, router)
                print(f"  [Step 4] class={vuln_class.class_id}")
                rewrite = rewrite_reasoning_code_only(
                    client, original_reasoning, question, model
                )
                rewrite_time = time.time() - rewrite_start
                if rewrite.get("patch_leak_terms"):
                    print(f"    Warning: remaining leak terms: {rewrite['patch_leak_terms']}")
                else:
                    print(f"    rewritten_len={len(rewrite.get('reasoning', ''))}")
                result.update({
                    "rewrite_prompt_type": "rewrite_reasoning_code_only",
                    "rewritten_reasoning": rewrite.get("reasoning", ""),
                    "reasoning_rewrite": rewrite,
                })
                with open(rewrite_file, 'a') as f:
                    f.write(json.dumps(result, ensure_ascii=False) + "\n")

        case_time = time.time() - case_start
        print(f"  [time] Case took {case_time/60:.1f} min "
              f"(Step1:{aug_time/60:.1f}m Step2:{distill_time/60:.1f}m "
              f"Step3:{eval_time/60:.1f}m Step4:{rewrite_time/60:.1f}m)")
        processed += 1

    if progress:
        progress.finish()
    else:
        print("No per-case generation steps requested; using existing outputs.")
    print(f"\n  Processed: {processed} | Skipped (dedup/resume): {skipped}/{total} | "
          f"Context rejected: {context_rejected}")

    # Step 5: Format final SFT data (runs on all completed distill results)
    if 5 in steps:
        print(f"\n{'='*60}")
        print("Step 5: Formatting SFT training data...")
        poc_eval_path = poc_eval_file if os.path.exists(poc_eval_file) else None
        reasoning_rewrite_path = rewrite_file if os.path.exists(rewrite_file) else None
        run_reformatter(
            distill_file,
            training_file,
            poc_eval_path=poc_eval_path,
            source=source,
            reasoning_rewrite_path=reasoning_rewrite_path,
            require_rewritten_reasoning=4 in steps,
        )

    # Step 6: Qwen Baseline (requires Step 5 output)
    if 6 in steps:
        if 5 not in steps and not os.path.exists(training_file):
            print("Error: Step 6 requires Step 5 output (training_data.jsonl)")
            sys.exit(1)
        print(f"\n{'='*60}")
        qwen_file = os.path.join(output_dir, "qwen_baseline_results.jsonl")
        run_qwen_baseline(training_file, qwen_file, max_pairs)

    # Step 7: Qwen Baseline PoC Evaluation (requires Step 2 and Step 6 output)
    if 7 in steps:
        qwen_file = os.path.join(output_dir, "qwen_baseline_results.jsonl")
        if not os.path.exists(qwen_file):
            print("Error: Step 7 requires Step 6 output (qwen_baseline_results.jsonl)")
            sys.exit(1)
        print(f"\n{'='*60}")
        qwen_poc_eval_file = os.path.join(output_dir, "qwen_poc_eval_results.jsonl")
        run_qwen_poc_evaluation(client, qwen_file, distill_file, qwen_poc_eval_file, model)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', type=str, default="pipeline",
                        choices=["pipeline", "reformatter"],
                        help='Run mode')
    parser.add_argument('--steps', type=int, nargs='+', default=[1, 2],
                        help='Steps to run: 1=context aug, 2=distill, 3=poc eval, 4=rewrite reasoning, 5=format SFT, 6=qwen baseline, 7=qwen poc eval')
    parser.add_argument('--data-path', type=str,
                        default="data/primevul_train_paired.jsonl",
                        help='Path to data file (JSONL)')
    parser.add_argument('--source', type=str, default="primevul",
                        choices=["primevul", "megavul", "reposvul", "cvefixes", "crossvul", "diversevul", "curated"],
                        help='Data source type (determines load/normalize logic)')
    parser.add_argument('--model', type=str, default="deepseek-v4-pro",
                        help='Model name')
    parser.add_argument('--output-dir', type=str, default="output",
                        help='Output directory')
    parser.add_argument('--max-pairs', type=int, default=None,
                        help='Max pairs to process')
    parser.add_argument('--start-pair', type=int, default=0,
                        help='Pair index offset to start from after source normalization')
    parser.add_argument('--input', type=str, help='Input file for reformatter')
    parser.add_argument('--output', type=str, help='Output file for reformatter')
    parser.add_argument('--poc-eval-path', type=str, help='PoC evaluation file for reformatter')
    parser.add_argument('--min-poc-score', type=int, default=None,
                        help='Minimum PoC quality score (6-30) to include in training data')
    parser.add_argument('--reasoning-rewrite-path', type=str,
                        help='Patch-unaware reasoning rewrite file for reformatter')
    parser.add_argument('--require-rewritten-reasoning', action='store_true',
                        help='Skip samples without patch-unaware rewritten reasoning')

    args = parser.parse_args()

    invalid_steps = sorted(set(args.steps) - VALID_PIPELINE_STEPS)
    if invalid_steps:
        print(f"Error: invalid --steps {invalid_steps}. Valid steps: {sorted(VALID_PIPELINE_STEPS)}")
        sys.exit(1)

    # Instantiate data source based on --source
    source_map = {
        "primevul": PrimeVulSource,
        "megavul": MegaVulSource,
        "reposvul": ReposVulSource,
        "cvefixes": CVEfixesSource,
        "crossvul": CrossVulSource,
        "diversevul": DiverseVulSource,
        "curated": CuratedSource,
    }
    source_cls = source_map.get(args.source)
    if source_cls is None:
        print(f"Error: unknown data source '{args.source}'. Available: {list(source_map.keys())}")
        sys.exit(1)
    source = source_cls()

    if args.mode == "pipeline":
        run_pipeline(args.data_path, args.output_dir, args.model,
                     args.steps, args.max_pairs, source=source,
                     start_pair=args.start_pair)
    elif args.mode == "reformatter":
        if not args.input or not args.output:
            print("Error: --input and --output required")
            sys.exit(1)
        run_reformatter(args.input, args.output,
                        poc_eval_path=args.poc_eval_path,
                        min_poc_score=args.min_poc_score,
                        source=source,
                        reasoning_rewrite_path=args.reasoning_rewrite_path,
                        require_rewritten_reasoning=args.require_rewritten_reasoning)


if __name__ == "__main__":
    main()
