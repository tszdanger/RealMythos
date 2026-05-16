"""Translate reasoning fields in the public SFT dataset to English.

The script is designed for long resumable runs:

- loads existing partial output/state as a checkpoint
- translates only records whose reasoning still contains Chinese
- runs each API translation in an isolated subprocess with a hard timeout
- writes a JSONL state file after every successful record
- rebuilds the final output in input order

Usage:
    python reasoning_expr/translate_reasoning_en.py \
      --input results_20260514/02_huggingface_release/sft_train.jsonl \
      --output results_20260514/02_huggingface_release/sft_train_en.jsonl \
      --concurrency 6 --rpm 120
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from openai import OpenAI


TRANSLATE_PROMPT = """Translate the following reasoning text from Chinese to professional English.

Rules:
- Preserve code structure, syntax, variable names, function names, and technical terms
- Translate ONLY the Chinese prose/explanation parts
- Translate every Chinese sentence, label, heading, note, and analysis phrase outside source code
- Translate Chinese comments inside code blocks, but do not change executable code, identifiers, literals, or formatting
- Do not leave Chinese prompt markers such as \u3010\u5f85\u5206\u6790\u4ee3\u7801\u3011, \u3010\u8865\u5145\u4e0a\u4e0b\u6587\u3011, or \u6ce8\u610f in the prose
- Replace references such as \u5f85\u5206\u6790\u4ee3\u7801 with "code under analysis"
- If XML-style tags such as <reasoning> appear, keep the tags but translate the text inside them
- The final answer should contain no Chinese characters unless they are part of an unavoidable original string literal
- Use precise cybersecurity and software engineering terminology
- Maintain the original structure, bullet points, and formatting
- Do not change executable code semantics
- Output ONLY the translated text, no preamble or explanation

Text to translate:
{text}
"""

CN_RE = re.compile(r"[\u4e00-\u9fff]")


def configure_stdio() -> None:
    """Use UTF-8 for redirected logs/stdout on Windows when available."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            reconfigure(encoding="utf-8", errors="replace")


def load_env_file(path: Path) -> None:
    """Load simple KEY=VALUE lines from .env without overriding existing env vars."""
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            if key.startswith("export "):
                key = key[len("export ") :].strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


def load_default_env_files() -> None:
    here = Path(__file__).resolve()
    candidates = [
        Path.cwd() / ".env",
        here.parent.parent / ".env",
        here.parent / ".env",
    ]
    seen: set[Path] = set()
    for path in candidates:
        resolved = path.resolve()
        if resolved not in seen:
            seen.add(resolved)
            load_env_file(resolved)


class TokenBucketRateLimiter:
    """Thread-safe token bucket rate limiter."""

    def __init__(self, rpm: int):
        self.capacity = float(rpm)
        self.tokens = float(rpm)
        self.refill_rate = float(rpm) / 60.0
        self.updated_at = time.monotonic()
        self.lock = threading.Lock()

    def acquire(self) -> None:
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


def has_chinese(text: str) -> bool:
    return bool(text and CN_RE.search(text))


def replace_surrogates(text: str) -> str:
    """Replace isolated surrogate code points that cannot be sent as UTF-8."""
    return text.encode("utf-8", "replace").decode("utf-8")


def clean_json_value(value: Any) -> Any:
    if isinstance(value, str):
        return replace_surrogates(value)
    if isinstance(value, list):
        return [clean_json_value(item) for item in value]
    if isinstance(value, dict):
        return {key: clean_json_value(item) for key, item in value.items()}
    return value


def make_client() -> OpenAI:
    load_default_env_files()
    api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("DEEPSEEK_API_KEY")
    if not api_key:
        raise EnvironmentError("Set OPENAI_API_KEY or DEEPSEEK_API_KEY")
    return OpenAI(api_key=api_key, base_url="https://api.deepseek.com")


def split_text(text: str, max_chars: int) -> list[str]:
    """Split long reasoning into paragraph-ish chunks for safer API calls."""
    if len(text) <= max_chars:
        return [text]

    chunks: list[str] = []
    current: list[str] = []
    current_len = 0

    for part in re.split(r"(\n\n+)", text):
        if not part:
            continue
        if current and current_len + len(part) > max_chars:
            chunks.append("".join(current))
            current = []
            current_len = 0
        if len(part) > max_chars:
            if current:
                chunks.append("".join(current))
                current = []
                current_len = 0
            for i in range(0, len(part), max_chars):
                chunks.append(part[i : i + max_chars])
            continue
        current.append(part)
        current_len += len(part)

    if current:
        chunks.append("".join(current))
    return chunks


def translate_chunk(client: OpenAI, chunk: str, request_timeout: float, max_retries: int) -> str:
    chunk = replace_surrogates(chunk)
    if not has_chinese(chunk):
        return chunk

    prompt = replace_surrogates(TRANSLATE_PROMPT.format(text=chunk))
    last_err: Exception | None = None
    for attempt in range(max_retries):
        try:
            resp = client.chat.completions.create(
                model="deepseek-chat",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0,
                max_tokens=8192,
                timeout=request_timeout,
            )
            return (resp.choices[0].message.content or "").strip()
        except Exception as exc:  # noqa: BLE001 - we want resumable batch behavior
            last_err = exc
            if attempt < max_retries - 1:
                time.sleep(min(2**attempt, 20))
    raise RuntimeError(str(last_err))


def translate_text(
    reasoning: str,
    *,
    chunk_chars: int,
    request_timeout: float,
    max_retries: int,
) -> str:
    reasoning = replace_surrogates(reasoning)
    if not has_chinese(reasoning):
        return reasoning

    client = make_client()
    chunks = split_text(reasoning, chunk_chars)
    translated: list[str] = []
    for chunk in chunks:
        translated.append(
            translate_chunk(
                client,
                chunk,
                request_timeout=request_timeout,
                max_retries=max_retries,
            )
        )
    return "\n\n".join(translated)


def worker_main() -> None:
    """Subprocess worker: read JSON payload from stdin and emit JSON to stdout."""
    configure_stdio()
    try:
        raw_payload = sys.stdin.buffer.read().decode("utf-8", "replace")
        payload = json.loads(raw_payload)
        text = translate_text(
            payload["reasoning"],
            chunk_chars=int(payload["chunk_chars"]),
            request_timeout=float(payload["request_timeout"]),
            max_retries=int(payload["max_retries"]),
        )
        encoded = base64.b64encode(text.encode("utf-8", "replace")).decode("ascii")
        sys.stdout.write(json.dumps({"ok": True, "reasoning_en_b64": encoded}, ensure_ascii=True))
    except Exception as exc:  # noqa: BLE001
        sys.stdout.write(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=True))
        sys.exit(1)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Translate reasoning to English")
    parser.add_argument("--input", help="Input SFT JSONL")
    parser.add_argument("--output", help="Output JSONL with reasoning_en")
    parser.add_argument("--state-file", default=None, help="Checkpoint JSONL file")
    parser.add_argument("--summary", default=None, help="Summary JSON output")
    parser.add_argument("--concurrency", type=int, default=6)
    parser.add_argument("--rpm", type=int, default=120)
    parser.add_argument("--max-lines", type=int, default=None, help="Limit to first N input lines")
    parser.add_argument("--start-line", type=int, default=None, help="Start index, 0-based inclusive")
    parser.add_argument("--end-line", type=int, default=None, help="End index, 0-based exclusive")
    parser.add_argument("--chunk-chars", type=int, default=8000)
    parser.add_argument("--request-timeout", type=float, default=120.0)
    parser.add_argument("--record-timeout", type=float, default=900.0)
    parser.add_argument("--max-retries", type=int, default=3)
    parser.add_argument("--flush-every", type=int, default=25)
    parser.add_argument("--stop-after", type=int, default=None, help="Stop after N successful new records")
    parser.add_argument(
        "--public-schema",
        action="store_true",
        help="Write cleaned English reasoning into the public reasoning field and omit reasoning_en",
    )
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    return parser.parse_args()


def record_key(record: dict[str, Any], idx: int) -> str:
    return f"{idx}:{record.get('cve', '')}"


def load_input(path: Path, max_lines: int | None, start_line: int | None, end_line: int | None) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            if not line.strip():
                continue
            if max_lines is not None and idx >= max_lines:
                break
            if start_line is not None and idx < start_line:
                continue
            if end_line is not None and idx >= end_line:
                break
            record = json.loads(line)
            record["_input_idx"] = idx
            records.append(record)
    return records


def load_completed_from_jsonl(path: Path, input_by_cve: dict[str, int]) -> dict[str, str]:
    completed: dict[str, str] = {}
    if not path.exists():
        return completed
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"WARNING: ignoring invalid JSON in {path} line {line_no}: {exc}")
                continue
            if record.get("translate_error") or record.get("reasoning_en") is None:
                continue
            idx = record.get("_input_idx", record.get("pair_idx"))
            if idx is None:
                idx = input_by_cve.get(record.get("cve"))
            if idx is None:
                continue
            key = f"{idx}:{record.get('cve', '')}"
            completed[key] = record["reasoning_en"]
    return completed


def load_completed_state(path: Path) -> dict[str, str]:
    completed: dict[str, str] = {}
    if not path.exists():
        return completed
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"WARNING: ignoring invalid JSON in {path} line {line_no}: {exc}")
                continue
            if item.get("ok") and item.get("reasoning_en") is not None:
                completed[item["key"]] = item["reasoning_en"]
    return completed


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def rebuild_output(output: Path, records: list[dict[str, Any]], completed: dict[str, str], public_schema: bool = False) -> int:
    written = 0
    with output.open("w", encoding="utf-8", newline="\n") as f:
        for record in sorted(records, key=lambda item: item["_input_idx"]):
            key = record_key(record, record["_input_idx"])
            if key not in completed:
                continue
            public_record = {k: clean_json_value(v) for k, v in record.items() if k != "_input_idx"}
            if public_schema:
                public_record["reasoning"] = completed[key]
                public_record.pop("reasoning_en", None)
            else:
                public_record["reasoning_en"] = completed[key]
            f.write(json.dumps(public_record, ensure_ascii=False, separators=(",", ":")))
            f.write("\n")
            written += 1
    return written


def append_state(state_file: Path, item: dict[str, Any], lock: threading.Lock) -> None:
    with lock:
        with state_file.open("a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(item, ensure_ascii=False, separators=(",", ":")))
            f.write("\n")
            f.flush()


def parse_worker_payload(stdout: bytes) -> dict[str, Any]:
    text = stdout.decode("utf-8", "replace").strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end > start:
            return json.loads(text[start : end + 1])
        raise RuntimeError(f"invalid worker JSON: {text[:500]!r}")


def run_worker(record: dict[str, Any], args: argparse.Namespace, limiter: TokenBucketRateLimiter) -> tuple[str, str]:
    idx = record["_input_idx"]
    key = record_key(record, idx)
    reasoning = replace_surrogates(record.get("reasoning") or "")
    if not has_chinese(reasoning):
        return key, reasoning

    limiter.acquire()
    payload = {
        "reasoning": reasoning,
        "chunk_chars": args.chunk_chars,
        "request_timeout": args.request_timeout,
        "max_retries": args.max_retries,
    }
    payload_bytes = json.dumps(payload, ensure_ascii=True).encode("utf-8", "replace")
    proc = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), "--worker"],
        input=payload_bytes,
        capture_output=True,
        timeout=args.record_timeout,
        check=False,
    )
    if proc.returncode != 0:
        stdout = proc.stdout.decode("utf-8", "replace").strip()
        stderr = proc.stderr.decode("utf-8", "replace").strip()
        error = stdout or stderr or f"worker exited with {proc.returncode}"
        try:
            parsed = json.loads(error)
            error = parsed.get("error") or error
        except json.JSONDecodeError:
            pass
        raise RuntimeError(error[:2000])
    result = parse_worker_payload(proc.stdout)
    if not result.get("ok"):
        raise RuntimeError(str(result.get("error")))
    if "reasoning_en_b64" in result:
        reasoning_en = base64.b64decode(result["reasoning_en_b64"]).decode("utf-8", "replace")
    else:
        reasoning_en = str(result.get("reasoning_en", ""))
    return key, reasoning_en


def main() -> None:
    configure_stdio()
    args = parse_args()
    if args.worker:
        worker_main()
        return

    if not args.input or not args.output:
        raise SystemExit("--input and --output are required")

    load_default_env_files()
    if not (os.environ.get("OPENAI_API_KEY") or os.environ.get("DEEPSEEK_API_KEY")):
        raise SystemExit("Set OPENAI_API_KEY or DEEPSEEK_API_KEY, or place one in .env")

    input_path = Path(args.input)
    output_path = Path(args.output)
    state_file = Path(args.state_file) if args.state_file else output_path.with_suffix(output_path.suffix + ".state.jsonl")
    summary_path = Path(args.summary) if args.summary else output_path.with_suffix(output_path.suffix + ".summary.json")

    records = load_input(input_path, args.max_lines, args.start_line, args.end_line)
    input_by_cve = {record.get("cve"): record["_input_idx"] for record in records}

    completed = load_completed_from_jsonl(output_path, input_by_cve)
    completed.update(load_completed_state(state_file))

    # Pre-complete records that do not need translation.
    for record in records:
        key = record_key(record, record["_input_idx"])
        if key not in completed and not has_chinese(record.get("reasoning") or ""):
            completed[key] = record.get("reasoning") or ""

    todo = [record for record in records if record_key(record, record["_input_idx"]) not in completed]
    print(
        f"Loaded {len(records)} input records; checkpoint has {len(completed)} complete; "
        f"to translate: {len(todo)}"
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    state_file.parent.mkdir(parents=True, exist_ok=True)

    if args.stop_after is not None and len(todo) > args.stop_after:
        todo = todo[: args.stop_after]
        print(f"Limited this run to the first {len(todo)} pending records via --stop-after")

    if not todo:
        written = rebuild_output(output_path, records, completed)
        print(f"Nothing to translate. Rebuilt {written} records at {output_path}")
    else:
        limiter = TokenBucketRateLimiter(args.rpm)
        state_lock = threading.Lock()
        counters = Counter()
        start = time.monotonic()

        def handle_record(record: dict[str, Any]) -> tuple[str, str | None, str | None]:
            key = record_key(record, record["_input_idx"])
            try:
                done_key, reasoning_en = run_worker(record, args, limiter)
                append_state(
                    state_file,
                    {
                        "ok": True,
                        "key": done_key,
                        "idx": record["_input_idx"],
                        "cve": record.get("cve"),
                        "reasoning_en": reasoning_en,
                    },
                    state_lock,
                )
                return done_key, reasoning_en, None
            except Exception as exc:  # noqa: BLE001
                append_state(
                    state_file,
                    {
                        "ok": False,
                        "key": key,
                        "idx": record["_input_idx"],
                        "cve": record.get("cve"),
                        "error": str(exc),
                    },
                    state_lock,
                )
                return key, None, str(exc)

        print(
            f"Starting translation with concurrency={args.concurrency}, rpm={args.rpm}, "
            f"chunk_chars={args.chunk_chars}, record_timeout={args.record_timeout}s"
        )
        with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
            futures = {executor.submit(handle_record, record): record for record in todo}
            for future in as_completed(futures):
                record = futures[future]
                done_key, reasoning_en, error = future.result()
                if error:
                    counters["errors"] += 1
                    print(f"ERROR idx={record['_input_idx']} cve={record.get('cve')}: {error[:300]}")
                else:
                    counters["completed"] += 1
                    if reasoning_en is not None:
                        completed[done_key] = reasoning_en

                new_done = counters["completed"]
                if new_done and (new_done % args.flush_every == 0):
                    written = rebuild_output(output_path, records, completed, args.public_schema)
                    elapsed = time.monotonic() - start
                    rate = counters["completed"] / elapsed if elapsed else 0
                    print(
                        f"progress new={counters['completed']} errors={counters['errors']} "
                        f"written={written}/{len(records)} rate={rate:.2f}/s"
                    )

                if args.stop_after and counters["completed"] >= args.stop_after:
                    print(f"stop-after reached ({args.stop_after}); waiting for in-flight tasks to finish")
                    break

        completed.update(load_completed_state(state_file))
        written = rebuild_output(output_path, records, completed, args.public_schema)
        print(f"Rebuilt {written} records at {output_path}")

    completed_count = len(completed)
    output_sha = sha256_file(output_path) if output_path.exists() else None
    summary = {
        "input": str(input_path),
        "output": str(output_path),
        "state_file": str(state_file),
        "records_in_scope": len(records),
        "completed": completed_count,
        "remaining": max(0, len(records) - completed_count),
        "output_size_bytes": output_path.stat().st_size if output_path.exists() else 0,
        "output_sha256": output_sha,
        "public_schema": args.public_schema,
    }
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
