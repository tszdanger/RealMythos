"""Vulnerability class-based PoC prompt router.

Routes vulnerability samples to class-specific PoC prompt instructions
based on CWE code mapping, with LLM fallback for unmapped classes.
"""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class VulnClassConfig:
    """Configuration for one vulnerability class's PoC prompt instructions."""
    class_id: str
    display_name: str
    cwe_codes: list[str]
    analysis_focus: str
    poc_format: str
    required_components: list[str]
    is_dynamic: bool = False


class PromptRouter:
    """Routes vulnerability samples to class-specific PoC prompts.

    Classification strategy:
    1. Deterministic CWE code lookup (fast path)
    2. LLM-based classification for unmapped CWEs (with disk cache)
    """

    def __init__(self, yaml_path: str, llm_client=None):
        yaml_file = Path(yaml_path)
        if not yaml_file.exists():
            raise FileNotFoundError(f"Prompt template not found: {yaml_path}")

        self._config = self._load_yaml(yaml_file)
        self._cwe_to_class: dict[str, VulnClassConfig] = self._build_cwe_index()
        self._llm_client = llm_client
        self._llm_cache: dict[str, VulnClassConfig] = {}
        self._llm_cache_path = yaml_file.parent / "llm_classification_cache.json"
        self._load_llm_cache()

    def _load_yaml(self, path: Path) -> dict:
        try:
            import yaml
        except ImportError:
            raise ImportError("pyyaml is required: pip install pyyaml")
        with open(path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)

    def _build_cwe_index(self) -> dict[str, VulnClassConfig]:
        """Build a CWE-code to VulnClassConfig mapping from YAML."""
        index: dict[str, VulnClassConfig] = {}
        for class_id, cls_data in self._config['classes'].items():
            cwe_codes = [self._normalize_cwe(cwe) for cwe in cls_data['cwe_codes']]
            config = VulnClassConfig(
                class_id=class_id,
                display_name=cls_data['display_name'],
                cwe_codes=cwe_codes,
                analysis_focus=cls_data['analysis_focus'],
                poc_format=cls_data['poc_format'],
                required_components=cls_data['required_components'],
            )
            for cwe in cwe_codes:
                if cwe in index:
                    prev = index[cwe].class_id
                    raise ValueError(
                        f"CWE {cwe} is mapped to multiple prompt classes: "
                        f"{prev}, {class_id}"
                    )
                index[cwe] = config
        return index

    @staticmethod
    def _normalize_cwe(cwe: str) -> str:
        """Normalize CWE tokens so summary files and YAML match reliably."""
        cwe = str(cwe).strip().upper()
        if cwe.isdigit():
            return f"CWE-{cwe}"
        if cwe.startswith("CWE") and not cwe.startswith("CWE-"):
            suffix = cwe[3:].lstrip("-_ ")
            if suffix:
                return f"CWE-{suffix}"
        return cwe

    def _load_llm_cache(self):
        """Load previously cached LLM classification results."""
        if self._llm_cache_path.exists():
            with open(self._llm_cache_path, 'r', encoding='utf-8') as f:
                raw = json.load(f)
            for cache_key, data in raw.items():
                self._llm_cache[cache_key] = VulnClassConfig(
                    class_id=data['class_id'],
                    display_name=data['display_name'],
                    cwe_codes=data['cwe_codes'],
                    analysis_focus=data['analysis_focus'],
                    poc_format=data['poc_format'],
                    required_components=data['required_components'],
                    is_dynamic=True,
                )

    def _save_llm_cache(self):
        """Persist LLM classification cache to disk."""
        raw = {}
        for key, cfg in self._llm_cache.items():
            raw[key] = {
                'class_id': cfg.class_id,
                'display_name': cfg.display_name,
                'cwe_codes': cfg.cwe_codes,
                'analysis_focus': cfg.analysis_focus,
                'poc_format': cfg.poc_format,
                'required_components': cfg.required_components,
            }
        with open(self._llm_cache_path, 'w', encoding='utf-8') as f:
            json.dump(raw, f, ensure_ascii=False, indent=2)

    def classify(
        self,
        cwe_list: list[str],
        cve_desc: str = "",
        vuln_func: str = "",
        cve: str = "",
    ) -> VulnClassConfig:
        """Classify a vulnerability into a class.

        Priority:
        1. Match any CWE in cwe_list against the static mapping
        2. If no match, use LLM fallback (cached)
        3. If LLM fails, fall back to input_validation

        Args:
            cwe_list: List of CWE codes (e.g., ["CWE-119", "CWE-200"])
            cve_desc: CVE description text
            vuln_func: Vulnerable function source code
            cve: CVE identifier

        Returns:
            VulnClassConfig for the matched class.
        """
        # Fast path: deterministic CWE lookup
        normalized_cwes = [self._normalize_cwe(cwe) for cwe in cwe_list]

        for cwe in normalized_cwes:
            if cwe in self._cwe_to_class:
                return self._cwe_to_class[cwe]

        # Check LLM cache
        cache_key = cve_desc[:200] if cve_desc else vuln_func[:200]
        if cache_key in self._llm_cache:
            return self._llm_cache[cache_key]

        # Slow path: LLM-based classification
        if self._llm_client is not None:
            config = self._classify_via_llm(cve, cve_desc, normalized_cwes, vuln_func)
            if config:
                self._llm_cache[cache_key] = config
                self._save_llm_cache()
                return config

        # Ultimate fallback
        print(f"  [PromptRouter] No match for CWE {normalized_cwes}, falling back to input_validation")
        iv_cwe = self._config['classes'].get('input_validation', {}).get('cwe_codes', [])
        if iv_cwe and iv_cwe[0] in self._cwe_to_class:
            return self._cwe_to_class[iv_cwe[0]]
        return self._get_first_class()

    def _classify_via_llm(
        self, cve: str, cve_desc: str, cwe_list: list[str], vuln_func: str
    ) -> Optional[VulnClassConfig]:
        """Call LLM to classify an unmapped vulnerability."""
        fallback_tpl = self._config.get('classification_fallback', {})
        prompt = fallback_tpl.get('user_prompt_template', '').format(
            cve=cve,
            cve_desc=cve_desc,
            cwe=", ".join(cwe_list),
            vuln_func=vuln_func,
        )
        messages = [
            {"role": "system", "content": fallback_tpl.get('system_prompt', '')},
            {"role": "user", "content": prompt},
        ]
        try:
            response = self._llm_client.chat.completions.create(
                model="qwen/qwen3.5-9b",
                messages=messages,
                stream=False,
            )
            content = response.choices[0].message.content or ""
            # Strip markdown code block fences if present
            content = content.strip()
            if content.startswith("```"):
                content = content.split("\n", 1)[-1]
                if content.endswith("```"):
                    content = content[:-3]
                content = content.strip()
            data = json.loads(content)
            return VulnClassConfig(
                class_id=f"dynamic_{cve.replace('CVE-', '')}" if cve else "dynamic_unknown",
                display_name="Dynamic Classification",
                cwe_codes=cwe_list,
                analysis_focus=data.get('analysis_focus', 'Analyze the root cause of the vulnerability'),
                poc_format=data.get('poc_format', 'Construct independently executable PoC code'),
                required_components=data.get('required_components', ['Complete executable code']),
                is_dynamic=True,
            )
        except Exception as e:
            print(f"  [PromptRouter] LLM classification failed: {e}, using fallback")
            return None

    def _get_first_class(self) -> VulnClassConfig:
        """Return first class config as ultimate fallback."""
        first_id = next(iter(self._config['classes']))
        first_data = self._config['classes'][first_id]
        return VulnClassConfig(
            class_id=first_id,
            display_name=first_data['display_name'],
            cwe_codes=first_data['cwe_codes'],
            analysis_focus=first_data['analysis_focus'],
            poc_format=first_data['poc_format'],
            required_components=first_data['required_components'],
        )

    def format_class_instructions(self, vuln_class: VulnClassConfig) -> str:
        """Format the class-specific instruction block for injection into the prompt."""
        components_str = "\n".join(
            f"   - {c}" for c in vuln_class.required_components
        )
        return f"""[PoC Class-Specific Requirements] (Vulnerability Class: {vuln_class.display_name})
Analysis Focus: {vuln_class.analysis_focus}

PoC Format Requirements: {vuln_class.poc_format}

PoC must include the following components:
{components_str}

Do NOT output only raw payload data or byte streams (e.g., b"A"*N)! The PoC must be a complete, executable program."""

    def compose_prompt(
        self,
        vuln_class: VulnClassConfig,
        project: str,
        cve: str,
        cve_desc: str,
        cwe: list[str],
        vuln_func: str,
        patched_func: str,
        augmented_context: Optional[str] = None,
    ) -> str:
        """Compose the full distillation prompt.

        Structure:
        [Context]            -- CVE info, project
        [Augmented Context]  -- optional supplement from Step 0
        [Code Blocks]        -- vulnerable code + patched code
        [Class Instructions] -- class-specific analysis_focus + poc_format + required_components
        [Task]               -- analyze root cause + build PoC
        [Anti-leakage]       -- must not reference patch in reasoning
        [Output Format]      -- analysis first, then PoC in code block
        """
        class_instructions = self.format_class_instructions(vuln_class)

        aug_section = ""
        if augmented_context:
            aug_section = f"""
[Augmented Context] (for reference only; helps understand external code dependencies)
```c
{augmented_context}
```
"""

        if not (patched_func or "").strip():
            return f"""[Context]
The following vulnerable function was extracted from the {project} project. This data source does not provide reliable fixed code, so you must analyze based on the vulnerable code, augmented context, and vulnerability background only.

CVE ID: {cve}
Description: {cve_desc}
CWE Type: {", ".join(cwe)}

{aug_section}[Vulnerable Code]
```c
{vuln_func}
```

[Task]
Analyze the root cause of this vulnerability based solely on the vulnerable code itself, and construct a PoC that triggers it. Do not assume a patch is visible, and do not fabricate fix code.

[Trigger Path]
In your analysis, briefly explain the data flow path:
1. Which function/code line contains the vulnerability?
2. Who calls this function? Through what entry point does user input arrive here?
3. Which input fields can the attacker control?

{class_instructions}
[Important Requirement]
Reasoning must be based on the vulnerable code and augmented context only. CVE numbers, commit messages, or dataset labels are for background context only; do not restate these in your reasoning or claim "the patch added/removed/changed logic".

[Answer Format]
You must strictly use the following two XML-style tags and output nothing outside them:
<analysis>
Explain the root cause, trigger conditions, attacker-controlled inputs, data flow path, impact, and expected PoC behavior in English. Do NOT mention the fix patch or fixed version.
</analysis>

<poc>
Place complete, independently executable PoC source code here. Only source code itself; no markdown code fences, no explanatory natural language.
</poc>

[PoC Writing Strict Rules]
1. Do NOT output only raw payload data or byte streams (e.g., b"A"*1000)!
2. For network protocol vulnerabilities, write a standalone Python 3 script with socket communication, complete packet assembly, and sending.
3. For local API vulnerabilities, write a C reproduction program (Harness) with a main function, struct definitions, memory allocation, and vulnerable function invocation.
4. All PoC code must be placed inside the <poc> tag. Do NOT use ```python, ```c, or any markdown code fences.
5. The PoC should reproduce the vulnerability (trigger crash/overflow/exception) or print the constructed payload to stdout."""

        prompt = f"""[Context]
The following vulnerable code and its fix patch were extracted from the {project} project.

CVE ID: {cve}
Description: {cve_desc}
CWE Type: {", ".join(cwe)}

{aug_section}[Vulnerable Code]
```c
{vuln_func}
```

[Fixed Code]
```c
{patched_func}
```

[Task]
Analyze the root cause of this vulnerability by comparing the vulnerable code with its fix, and construct a PoC that triggers it.

[Trigger Path]
In your analysis, briefly explain the data flow path:
1. Which function/code line contains the vulnerability?
2. Who calls this function? Through what entry point does user input arrive here?
3. Which input fields can the attacker control?

{class_instructions}
[Important Requirement]
In your reasoning process (reasoning_content), you must NOT mention, quote, or describe any content from the fixed code ("Fixed Code" section).
Do not write statements like "by observing the patch, I found it ...", "the fixed code added ... after ...", or "the patch removed ...".
The fixed code is for your private reference only to understand how the vulnerability was remediated. Your reasoning must be based entirely on analyzing the vulnerable code itself.
The final vulnerability analysis must also NOT describe patch details; only explain the root cause, trigger conditions, impact, and PoC trigger method of the vulnerable code itself.

[Answer Format]
You must strictly use the following two XML-style tags and output nothing outside them:

<analysis>
Explain the root cause, trigger conditions, attacker-controlled inputs, data flow path, impact, and expected PoC behavior in English. Do NOT mention the fix patch or fixed version.
</analysis>

<poc>
Place complete, independently executable PoC source code here. Only source code itself; no markdown code fences, no explanatory natural language.
</poc>

[PoC Writing Strict Rules]
1. Do NOT output only raw payload data or byte streams (e.g., b"A"*1000)!
2. For network protocol vulnerabilities, write a standalone Python 3 script with socket communication, complete packet assembly, and sending.
3. For local API vulnerabilities, write a C reproduction program (Harness) with a main function, struct definitions, memory allocation, and vulnerable function invocation.
4. All PoC code must be placed inside the <poc> tag. Do NOT use ```python, ```c, or any markdown code fences.
5. The PoC should reproduce the vulnerability (trigger crash/overflow/exception) or print the constructed payload to stdout.
6. Comments, variable names, temp file names, and print strings in the PoC must use neutral case/test naming. Verification output should use neutral descriptions like "expected signal" or "test completed". Do NOT include vulnerable/fixed kernel/version, CVE numbers, patch/diff/commit, or fix-related metadata."""
        return prompt
