#!/usr/bin/env python3
"""Concurrent runner for one curated task package.

This runner keeps changes to the main serial pipeline small. It reuses the same
Step 1-4 functions from run_reasoning.py, runs cases concurrently, records one
complete case result per line, and materializes the usual stage JSONL files from
case_results.jsonl.
"""

import argparse
import hashlib
import json
import os
import re
import sys
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from data_source import (
    CVEfixesSource,
    CrossVulSource,
    CuratedSource,
    DiverseVulSource,
    MegaVulSource,
    PrimeVulSource,
    ReposVulSource,
)
from prompt_router import PromptRouter
from run_reasoning import (
    build_training_question,
    context_reject_reason,
    extract_tags,
    get_client,
    run_context_augmentation,
    run_distillation,
    run_poc_eval,
    run_qwen_baseline,
    run_qwen_poc_evaluation,
    run_reformatter,
    rewrite_reasoning_code_only,
    set_deepseek_rate_limiter,
)


SOURCE_CLASSES = {
    "curated": CuratedSource,
    "cvefixes": CVEfixesSource,
    "diversevul": DiverseVulSource,
    "primevul": PrimeVulSource,
    "megavul": MegaVulSource,
    "reposvul": ReposVulSource,
    "crossvul": CrossVulSource,
}

_STREAM_PROXY_LOCK = threading.Lock()
_STDOUT_PROXY = None
_STDERR_PROXY = None


class ThreadLocalStream:
    """Route writes from worker threads to per-thread log files."""

    def __init__(self, default_stream):
        self.default_stream = default_stream
        self.local = threading.local()
        self.lock = threading.Lock()

    def set_stream(self, stream):
        self.local.stream = stream

    def clear_stream(self):
        if hasattr(self.local, "stream"):
            del self.local.stream

    def _stream(self):
        return getattr(self.local, "stream", None) or self.default_stream

    def write(self, data):
        stream = self._stream()
        with self.lock:
            stream.write(data)
            stream.flush()

    def flush(self):
        self._stream().flush()

    def isatty(self):
        return self.default_stream.isatty()

    @property
    def encoding(self):
        return getattr(self.default_stream, "encoding", "utf-8")

    def __getattr__(self, name):
        return getattr(self.default_stream, name)


def install_thread_log_routing():
    """Install stdout/stderr proxies once and return them."""

    global _STDOUT_PROXY, _STDERR_PROXY
    with _STREAM_PROXY_LOCK:
        if _STDOUT_PROXY is None:
            _STDOUT_PROXY = ThreadLocalStream(sys.stdout)
            sys.stdout = _STDOUT_PROXY
        if _STDERR_PROXY is None:
            _STDERR_PROXY = ThreadLocalStream(sys.stderr)
            sys.stderr = _STDERR_PROXY
    return _STDOUT_PROXY, _STDERR_PROXY


class TokenBucketRateLimiter:
    """Simple thread-safe token bucket for requests per minute."""

    def __init__(self, rpm: int):
        if rpm <= 0:
            raise ValueError("rpm must be positive")
        self.capacity = float(rpm)
        self.tokens = float(rpm)
        self.refill_rate = float(rpm) / 60.0
        self.updated_at = time.monotonic()
        self.lock = threading.Lock()

    def acquire(self):
        while True:
            with self.lock:
                now = time.monotonic()
                elapsed = now - self.updated_at
                self.updated_at = now
                self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                wait = (1.0 - self.tokens) / self.refill_rate
            time.sleep(min(max(wait, 0.05), 5.0))


class JsonlStore:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, row: dict):
        with self.lock:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
                f.flush()


class Monitor:
    def __init__(self, path: Path, total: int, concurrency: int, rpm: int, steps: list[int]):
        self.path = path
        self.lock = threading.Lock()
        self.state = {
            "status": "running",
            "started_at": timestamp(),
            "updated_at": timestamp(),
            "total": total,
            "pending": total,
            "running": 0,
            "completed": 0,
            "context_rejected": 0,
            "failed": 0,
            "skipped_success": 0,
            "skipped_failed": 0,
            "concurrency": concurrency,
            "rpm": rpm,
            "steps": steps,
        }
        self.write()

    def update(self, **delta):
        with self.lock:
            for key, value in delta.items():
                self.state[key] = self.state.get(key, 0) + value
            self.state["updated_at"] = timestamp()
            self.write_locked()

    def set_status(self, status: str):
        with self.lock:
            self.state["status"] = status
            self.state["updated_at"] = timestamp()
            self.write_locked()

    def write(self):
        with self.lock:
            self.write_locked()

    def write_locked(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.state, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.path)


def timestamp():
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def safe_filename(value: str) -> str:
    text = str(value or "unknown")
    text = re.sub(r"[^A-Za-z0-9_.-]+", "_", text).strip("._")
    return (text or "unknown")[:180]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def count_jsonl_rows(path: Path) -> int:
    rows = 0
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows += 1
    return rows


def verify_task_input(input_path: Path):
    manifest_path = input_path.parent / "manifest.json"
    if not manifest_path.exists():
        print(f"Input hash check skipped: no manifest.json next to {input_path}")
        return

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected_hash = manifest.get("input_sha256")
    if expected_hash:
        actual_hash = sha256_file(input_path)
        if actual_hash != expected_hash:
            raise ValueError(
                "Task input hash mismatch: "
                f"{input_path} expected={expected_hash} actual={actual_hash}"
            )

    expected_rows = manifest.get("record_count")
    if expected_rows is not None:
        actual_rows = count_jsonl_rows(input_path)
        if actual_rows != expected_rows:
            raise ValueError(
                "Task input record count mismatch: "
                f"{input_path} expected={expected_rows} actual={actual_rows}"
            )

    print(f"Input manifest verified: {manifest_path}")


def load_jsonl(path: Path, *, skip_bad_lines: bool = True):
    if not path.exists():
        return []
    rows = []
    bad_lines = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                if not skip_bad_lines:
                    raise
                bad_lines.append({
                    "source_file": str(path),
                    "line_no": line_no,
                    "error": str(exc),
                    "line_prefix": line[:240],
                    "time": timestamp(),
                })
    if bad_lines:
        bad_path = path.with_name(path.name + ".bad_lines.jsonl")
        with bad_path.open("a", encoding="utf-8") as f:
            for row in bad_lines:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
        print(
            f"Warning: skipped {len(bad_lines)} malformed JSONL line(s) in {path}; "
            f"details appended to {bad_path}",
            file=sys.stderr,
        )
    return rows


def write_jsonl_atomic(path: Path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    tmp.replace(path)


def record_id_for_pair(pair, source_name: str) -> str:
    if pair.raw and pair.raw.get("record_id"):
        return pair.raw["record_id"]
    return f"{source_name.lower()}:pair{pair.pair_idx}:{pair.cve}"


def pair_to_vuln_dict(pair) -> dict:
    return {
        "func": pair.vuln_func,
        "cve": pair.cve,
        "cwe": pair.cwe,
        "cve_desc": pair.cve_desc,
        "project": pair.project,
        "pair_idx": pair.pair_idx,
        "raw": pair.raw,
    }


def is_error_response(text: str) -> bool:
    return isinstance(text, str) and text.strip().startswith("ERROR:")


def load_pairs(input_path: Path, source_name: str):
    source_cls = SOURCE_CLASSES[source_name]
    source = source_cls()
    records = source.load(str(input_path))
    pairs = source.normalize(records)
    return source, pairs


def load_resume_sets(output_dir: Path):
    successes = set()
    context_rejected = set()
    for row in load_jsonl(output_dir / "case_results.jsonl"):
        record_id = row.get("record_id")
        if not record_id:
            continue
        status = row.get("status")
        if status == "success":
            successes.add(record_id)
        elif status == "context_rejected":
            context_rejected.add(record_id)

    failures = set()
    for row in load_jsonl(output_dir / "failures.jsonl"):
        record_id = row.get("record_id")
        if record_id:
            failures.add(record_id)
    return successes | context_rejected, failures


def base_result_for_pair(pair, record_id, source_name):
    return {
        "record_id": record_id,
        "source_name": source_name,
        "pair_idx": pair.pair_idx,
        "cve": pair.cve,
        "cwe": pair.cwe,
        "cve_desc": pair.cve_desc,
        "project": pair.project,
        "vuln_func": pair.vuln_func,
        "patched_func": pair.benign_func,
        "raw": pair.raw,
    }


def load_checkpoint(path: Path | None):
    if not path or not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"Warning: ignoring malformed checkpoint {path}: {exc}", file=sys.stderr)
        return None


def save_checkpoint(path: Path | None, result: dict, completed_steps: set[int]):
    if not path:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "record_id": result.get("record_id"),
        "status": result.get("status", "in_progress"),
        "completed_steps": sorted(completed_steps),
        "updated_at": timestamp(),
        "result": result,
    }
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def process_pair(pair, record_id, source_name, model, steps, router, checkpoint_path=None):
    vuln_dict = pair_to_vuln_dict(pair)
    benign_dict = {"func": pair.benign_func}
    requested_steps = {step for step in steps if step in {1, 2, 3, 4}}

    result = base_result_for_pair(pair, record_id, source_name)
    completed_steps = set()
    checkpoint = load_checkpoint(checkpoint_path)
    if checkpoint and checkpoint.get("record_id") == record_id:
        result.update(checkpoint.get("result") or {})
        completed_steps = {
            int(step)
            for step in checkpoint.get("completed_steps", [])
            if str(step).isdigit()
        }
        terminal_status = result.get("status")
        if terminal_status == "context_rejected" and 1 in completed_steps:
            result["resumed_from_checkpoint"] = True
            return result
        if terminal_status == "success" and requested_steps.issubset(completed_steps):
            result["resumed_from_checkpoint"] = True
            return result
        if terminal_status == "success":
            result.pop("status", None)
            result.pop("completed_at", None)
        if 1 in completed_steps:
            reject_reason = context_reject_reason(
                result.get("context_aug") or {"self_contained": True}
            )
            if reject_reason:
                result.update({
                    "status": "context_rejected",
                    "context_rejected": True,
                    "context_reject_reason": reject_reason,
                    "completed_at": timestamp(),
                    "resumed_from_checkpoint": True,
                })
                save_checkpoint(checkpoint_path, result, completed_steps)
                return result
        if requested_steps and requested_steps.issubset(completed_steps):
            result.update({
                "status": "success",
                "completed_at": timestamp(),
                "resumed_from_checkpoint": True,
            })
            save_checkpoint(checkpoint_path, result, completed_steps)
            return result

    client = get_client()

    aug_result = result.get("context_aug") or {
        "self_contained": True,
        "augmented_context": None,
    }

    if 1 in steps and 1 not in completed_steps:
        aug_result = run_context_augmentation(client, vuln_dict, model)
        result["context_aug"] = aug_result
        completed_steps.add(1)
        reject_reason = context_reject_reason(aug_result)
        if reject_reason:
            result.update({
                "status": "context_rejected",
                "context_rejected": True,
                "context_reject_reason": reject_reason,
                "completed_at": timestamp(),
            })
            save_checkpoint(checkpoint_path, result, completed_steps)
            return result
        save_checkpoint(checkpoint_path, result, completed_steps)
    elif 1 in completed_steps:
        reject_reason = context_reject_reason(aug_result)
        if reject_reason:
            result.update({
                "status": "context_rejected",
                "context_rejected": True,
                "context_reject_reason": reject_reason,
                "completed_at": timestamp(),
            })
            save_checkpoint(checkpoint_path, result, completed_steps)
            return result

    if 2 in steps and 2 not in completed_steps:
        vuln_class = router.classify(pair.cwe, pair.cve_desc, pair.vuln_func, pair.cve)
        print(f"[Step 2] distill start class={vuln_class.class_id}")
        prompt, reasoning, content = run_distillation(
            client,
            vuln_dict,
            benign_dict,
            aug_result.get("augmented_context"),
            model,
            router=router,
            vuln_class=vuln_class,
        )
        if is_error_response(content):
            raise RuntimeError(content)
        tags = extract_tags(content)
        refused = any(
            kw in content.lower()
            for kw in ["i cannot", "i can't", "i won't", "i am unable"]
        )
        print(
            "[Step 2] distill done "
            f"reasoning_chars={len(reasoning or '')} "
            f"response_chars={len(content or '')} "
            f"has_poc={tags.get('has_poc_tag')} refused={refused}"
        )
        prompt_family = "patch_diff" if pair.benign_func.strip() else "vulnerable_only"
        result.update({
            "prompt_type": f"{prompt_family}:{vuln_class.class_id}",
            "model": model,
            "prompt": prompt,
            "reasoning": reasoning,
            "response": content,
            "extracted": tags,
            "refused": refused,
        })
        completed_steps.add(2)
        save_checkpoint(checkpoint_path, result, completed_steps)

    if 3 in steps and 3 not in completed_steps:
        poc_text = result.get("extracted", {}).get("poc", "")
        if poc_text:
            print(f"[Step 3] poc eval start poc_chars={len(poc_text)}")
            eval_result = run_poc_eval(client, vuln_dict, poc_text, model)
            raw_response = eval_result.get("raw_response", "")
            if is_error_response(raw_response):
                raise RuntimeError(raw_response)
            result["poc_eval"] = eval_result
            print(f"[Step 3] poc eval done total_score={eval_result.get('total_score')}")
        else:
            result["poc_eval_skipped_reason"] = "no_poc"
            print("[Step 3] poc eval skipped reason=no_poc")
        completed_steps.add(3)
        save_checkpoint(checkpoint_path, result, completed_steps)

    if 4 in steps and 4 not in completed_steps:
        original_reasoning = result.get("reasoning", "")
        if original_reasoning and original_reasoning.strip():
            print(f"[Step 4] rewrite start reasoning_chars={len(original_reasoning)}")
            question, vuln_class = build_training_question(result, router)
            rewrite = rewrite_reasoning_code_only(
                client,
                original_reasoning,
                question,
                model,
            )
            if is_error_response(rewrite.get("raw_response", "")):
                raise RuntimeError(rewrite["raw_response"])
            result.update({
                "rewrite_prompt_type": "rewrite_reasoning_code_only",
                "rewritten_reasoning": rewrite.get("reasoning", ""),
                "reasoning_rewrite": rewrite,
            })
            print(
                "[Step 4] rewrite done "
                f"reasoning_chars={len(rewrite.get('reasoning', '') or '')} "
                f"leak_terms={len(rewrite.get('patch_leak_terms') or [])}"
            )
        else:
            result["reasoning_rewrite_skipped_reason"] = "no_reasoning"
            print("[Step 4] rewrite skipped reason=no_reasoning")
        completed_steps.add(4)
        save_checkpoint(checkpoint_path, result, completed_steps)

    result.update({
        "status": "success",
        "completed_at": timestamp(),
    })
    save_checkpoint(checkpoint_path, result, completed_steps)
    return result


def materialize_stage_files(output_dir: Path):
    rows = load_jsonl(output_dir / "case_results.jsonl")
    latest = {}
    for row in rows:
        record_id = row.get("record_id")
        if record_id:
            latest[record_id] = row
    records = list(latest.values())

    files = {
        "context_aug_results.jsonl": [
            r for r in records if r.get("context_aug")
        ],
        "context_rejects.jsonl": [
            r for r in records if r.get("status") == "context_rejected"
        ],
        "distill_results.jsonl": [
            r for r in records if r.get("status") == "success" and r.get("response")
        ],
        "poc_eval_results.jsonl": [
            r for r in records if r.get("status") == "success" and r.get("poc_eval")
        ],
        "reasoning_rewrite_results.jsonl": [
            r for r in records if r.get("status") == "success" and r.get("reasoning_rewrite")
        ],
    }

    for filename, file_rows in files.items():
        write_jsonl_atomic(output_dir / filename, file_rows)


def run_step5(output_dir: Path, source):
    distill_file = output_dir / "distill_results.jsonl"
    if not distill_file.exists():
        print("Step 5 skipped: no distill_results.jsonl")
        return
    poc_eval_file = output_dir / "poc_eval_results.jsonl"
    rewrite_file = output_dir / "reasoning_rewrite_results.jsonl"
    training_file = output_dir / "training_data.jsonl"
    run_reformatter(
        str(distill_file),
        str(training_file),
        poc_eval_path=str(poc_eval_file) if poc_eval_file.exists() else None,
        source=source,
        reasoning_rewrite_path=str(rewrite_file) if rewrite_file.exists() else None,
        require_rewritten_reasoning=rewrite_file.exists(),
    )


def run_step6(output_dir: Path, max_cases=None):
    training_file = output_dir / "training_data.jsonl"
    if not training_file.exists():
        raise FileNotFoundError("Step 6 requires Step 5 output: training_data.jsonl")
    qwen_file = output_dir / "qwen_baseline_results.jsonl"
    run_qwen_baseline(str(training_file), str(qwen_file), max_cases)


def run_step7(output_dir: Path, eval_model: str):
    qwen_file = output_dir / "qwen_baseline_results.jsonl"
    distill_file = output_dir / "distill_results.jsonl"
    if not qwen_file.exists():
        raise FileNotFoundError("Step 7 requires Step 6 output: qwen_baseline_results.jsonl")
    if not distill_file.exists():
        raise FileNotFoundError("Step 7 requires Step 2 output: distill_results.jsonl")
    qwen_poc_eval_file = output_dir / "qwen_poc_eval_results.jsonl"
    run_qwen_poc_evaluation(
        get_client(),
        str(qwen_file),
        str(distill_file),
        str(qwen_poc_eval_file),
        eval_model,
    )


def validate_steps(steps):
    valid = {1, 2, 3, 4, 5, 6, 7}
    invalid = sorted(set(steps) - valid)
    if invalid:
        raise ValueError(f"Invalid concurrent task steps {invalid}; valid steps are {sorted(valid)}")
    if (3 in steps or 4 in steps) and 2 not in steps:
        raise ValueError("Concurrent Step 3/4 currently require Step 2 in the same run")
    if 7 in steps and 6 not in steps:
        raise ValueError("Concurrent Step 7 currently requires Step 6 in the same run")


def run_concurrent_task(args):
    validate_steps(args.steps)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    input_path = Path(args.input)
    verify_task_input(input_path)
    source, pairs = load_pairs(input_path, args.source)
    if args.max_cases is not None:
        pairs = pairs[:args.max_cases]

    per_case_steps = any(step in args.steps for step in (1, 2, 3, 4))
    completed_ids, failed_ids = load_resume_sets(output_dir)
    pending = []
    skipped_success = skipped_failed = 0
    if per_case_steps:
        for pair in pairs:
            record_id = record_id_for_pair(pair, source.source_name)
            if record_id in completed_ids:
                skipped_success += 1
                continue
            if record_id in failed_ids and not args.retry_failed:
                skipped_failed += 1
                continue
            pending.append((pair, record_id))

    event_store = JsonlStore(output_dir / "case_events.jsonl")
    result_store = JsonlStore(output_dir / "case_results.jsonl")
    failure_store = JsonlStore(output_dir / "failures.jsonl")
    monitor = Monitor(output_dir / "monitor.json", len(pending), args.concurrency, args.rpm, args.steps)
    if skipped_success:
        monitor.update(skipped_success=skipped_success)
    if skipped_failed:
        monitor.update(skipped_failed=skipped_failed)

    limiter = TokenBucketRateLimiter(args.rpm)
    set_deepseek_rate_limiter(limiter)
    stdout_proxy, stderr_proxy = install_thread_log_routing()

    yaml_path = Path(__file__).resolve().parent / "prompt_templates" / "poc_classes.yaml"
    router = PromptRouter(str(yaml_path))

    def worker(pair, record_id):
        log_path = output_dir / "case_logs" / f"{safe_filename(record_id)}.log"
        checkpoint_path = output_dir / "checkpoints" / f"{safe_filename(record_id)}.json"
        event_store.append({
            "event": "case_started",
            "record_id": record_id,
            "pair_idx": pair.pair_idx,
            "cve": pair.cve,
            "log_path": str(log_path),
            "checkpoint_path": str(checkpoint_path),
            "time": timestamp(),
        })
        monitor.update(pending=-1, running=1)
        started = time.time()
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with log_path.open("a", encoding="utf-8") as log_file:
                log_file.write(f"\n--- case_started {timestamp()} {record_id} ---\n")
                stdout_proxy.set_stream(log_file)
                stderr_proxy.set_stream(log_file)
                try:
                    result = process_pair(
                        pair,
                        record_id,
                        source.source_name,
                        args.model,
                        args.steps,
                        router,
                        checkpoint_path=checkpoint_path,
                    )
                finally:
                    stdout_proxy.clear_stream()
                    stderr_proxy.clear_stream()
            result["duration_seconds"] = round(time.time() - started, 3)
            result["case_log_path"] = str(log_path)
            result["checkpoint_path"] = str(checkpoint_path)
            result_store.append(result)
            if result.get("status") == "context_rejected":
                monitor.update(running=-1, context_rejected=1)
            else:
                monitor.update(running=-1, completed=1)
            event_store.append({
                "event": "case_finished",
                "record_id": record_id,
                "status": result.get("status"),
                "duration_seconds": result["duration_seconds"],
                "log_path": str(log_path),
                "checkpoint_path": str(checkpoint_path),
                "time": timestamp(),
            })
            return result
        except Exception as exc:
            failure = {
                "record_id": record_id,
                "pair_idx": pair.pair_idx,
                "cve": pair.cve,
                "cwe": pair.cwe,
                "project": pair.project,
                "error": str(exc),
                "traceback": traceback.format_exc(),
                "log_path": str(log_path),
                "checkpoint_path": str(checkpoint_path),
                "time": timestamp(),
            }
            failure_store.append(failure)
            monitor.update(running=-1, failed=1)
            event_store.append({
                "event": "case_failed",
                "record_id": record_id,
                "error": str(exc),
                "log_path": str(log_path),
                "checkpoint_path": str(checkpoint_path),
                "time": timestamp(),
            })
            return failure

    print(
        f"Running task: input={args.input} pending={len(pending)} "
        f"skipped_success={skipped_success} skipped_failed={skipped_failed} "
        f"concurrency={args.concurrency} rpm={args.rpm}"
    )

    if pending and per_case_steps:
        with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
            futures = [
                executor.submit(worker, pair, record_id)
                for pair, record_id in pending
            ]
            for future in as_completed(futures):
                future.result()

    materialize_stage_files(output_dir)
    if 5 in args.steps:
        run_step5(output_dir, source)
    if 6 in args.steps:
        run_step6(output_dir, args.max_cases)
    if 7 in args.steps:
        run_step7(output_dir, args.model)

    monitor.set_status("done")
    print(f"Done. Outputs saved to {output_dir}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Task input JSONL")
    parser.add_argument("--output-dir", required=True, help="Task output directory")
    parser.add_argument("--source", default="curated", choices=sorted(SOURCE_CLASSES))
    parser.add_argument("--steps", type=int, nargs="+", default=[1, 2, 3, 4, 5])
    parser.add_argument("--model", default="deepseek-v4-pro")
    parser.add_argument("--concurrency", type=int, default=5)
    parser.add_argument("--rpm", type=int, default=20, help="DeepSeek requests per minute for this process")
    parser.add_argument("--max-cases", type=int, default=None, help="Optional pilot cap")
    parser.add_argument("--retry-failed", action="store_true", help="Retry record_ids present in failures.jsonl")
    args = parser.parse_args()

    if args.concurrency <= 0:
        raise ValueError("--concurrency must be positive")
    run_concurrent_task(args)


if __name__ == "__main__":
    main()
