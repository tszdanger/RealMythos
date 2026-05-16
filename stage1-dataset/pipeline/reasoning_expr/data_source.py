"""Data source abstraction layer.

All data sources are normalized into CanonicalPair, the pipeline-internal format.
Adding a new data source only requires implementing a new DataSource subclass.
"""

from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path
import ast
import hashlib
import json
import re


@dataclass
class CanonicalPair:
    """Pipeline-internal data format. All data sources normalize to this."""
    vuln_func: str
    benign_func: str
    cve: str
    cwe: list = field(default_factory=list)
    cve_desc: str = ""
    project: str = "unknown"
    pair_idx: int = 0
    raw: Optional[dict] = None


class DataSource:
    """Data source protocol. Each new data source implements load() and normalize()."""

    def load(self, path: str) -> list:
        """Load raw records from the given path."""
        raise NotImplementedError

    def normalize(self, records: list) -> list[CanonicalPair]:
        """Normalize raw records into CanonicalPair list."""
        raise NotImplementedError

    @property
    def source_name(self) -> str:
        """Data source identifier (e.g., 'PrimeVul', 'Devign')."""
        raise NotImplementedError


class PrimeVulSource(DataSource):
    """Adapter for PrimeVul JSONL format.

    Expected schema per record:
        target: int (1=vuln, 0=benign)
        func: str (C function code)
        cve: str
        cwe: list[str]
        cve_desc: str
        project: str
        idx: int
    """

    def load(self, path: str) -> list[dict]:
        import json
        records = []
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records

    def normalize(self, records: list) -> list[CanonicalPair]:
        vuln = [r for r in records if r.get('target') == 1]
        benign = [r for r in records if r.get('target') == 0]
        pairs = []
        for i in range(len(vuln)):
            v, b = vuln[i], benign[i]
            pairs.append(CanonicalPair(
                vuln_func=v.get('func', ''),
                benign_func=b.get('func', ''),
                cve=v.get('cve', 'N/A'),
                cwe=v.get('cwe', []),
                cve_desc=v.get('cve_desc', ''),
                project=v.get('project', 'unknown'),
                pair_idx=i,
                raw={'vuln': v, 'benign': b},
            ))
        return pairs

    @property
    def source_name(self) -> str:
        return 'PrimeVul'


class MegaVulSource(DataSource):
    """Adapter for the hitoshura25/megavul parquet format.

    Expected schema per row:
        cve_id: str
        cve_description: str
        cwe_id: str
        repo_url: str
        file_paths: str
        language: str
        diff_stats: str
        vulnerable_code: str
        fixed_code: str

    Only rows with both vulnerable_code and fixed_code are converted into
    CanonicalPair. The current pipeline is C/C++ oriented, so Java or other
    future languages are intentionally filtered out here.
    """

    COLUMNS = [
        "cve_id",
        "hash",
        "repo_url",
        "cve_description",
        "cwe_id",
        "cwe_name",
        "cwe_description",
        "commit_message",
        "file_paths",
        "language",
        "diff_stats",
        "vulnerable_code",
        "fixed_code",
        "security_keywords",
    ]
    SUPPORTED_LANGUAGES = {"C", "C++"}

    def load(self, path: str) -> list[dict]:
        """Load usable MegaVul records from a parquet file or directory."""
        try:
            import pyarrow.parquet as pq
        except ImportError as exc:
            raise ImportError(
                "pyarrow is required for MegaVul parquet files: pip install pyarrow"
            ) from exc

        parquet_files = self._find_parquet_files(path)
        records = []
        global_row_idx = 0

        for parquet_path in parquet_files:
            parquet_file = pq.ParquetFile(parquet_path)
            available = set(parquet_file.schema.names)
            columns = [c for c in self.COLUMNS if c in available]

            for batch in parquet_file.iter_batches(columns=columns, batch_size=4096):
                for row in batch.to_pylist():
                    row["_source_file"] = str(parquet_path)
                    row["_row_idx"] = global_row_idx
                    global_row_idx += 1
                    if self._is_usable_record(row):
                        records.append(row)

        return records

    def normalize(self, records: list) -> list[CanonicalPair]:
        pairs = []
        for i, r in enumerate(records):
            raw = {
                k: v for k, v in r.items()
                if k not in {"vulnerable_code", "fixed_code"}
            }
            pairs.append(CanonicalPair(
                vuln_func=(r.get("vulnerable_code") or "").strip(),
                benign_func=(r.get("fixed_code") or "").strip(),
                cve=(r.get("cve_id") or "N/A").strip(),
                cwe=self._parse_cwe(r.get("cwe_id")),
                cve_desc=(r.get("cve_description") or "").strip(),
                project=self._project_from_url(r.get("repo_url") or ""),
                pair_idx=i,
                raw=raw,
            ))
        return pairs

    @property
    def source_name(self) -> str:
        return 'MegaVul'

    def _find_parquet_files(self, path: str) -> list[Path]:
        root = Path(path)
        if root.is_file():
            if root.suffix != ".parquet":
                raise ValueError(f"MegaVulSource expects parquet input, got: {path}")
            return [root]
        if not root.exists():
            raise FileNotFoundError(f"MegaVul path not found: {path}")

        files = sorted(root.rglob("*.parquet"))
        if not files:
            raise FileNotFoundError(f"No parquet files found under: {path}")
        return files

    def _is_usable_record(self, row: dict) -> bool:
        language = (row.get("language") or "").strip()
        if language not in self.SUPPORTED_LANGUAGES:
            return False

        vuln = (row.get("vulnerable_code") or "").strip()
        fixed = (row.get("fixed_code") or "").strip()
        if not vuln or not fixed:
            return False
        if vuln == fixed:
            return False
        if not (row.get("cve_id") or "").strip():
            return False
        return True

    def _parse_cwe(self, cwe_value) -> list[str]:
        if not cwe_value:
            return []
        if isinstance(cwe_value, list):
            values = cwe_value
        else:
            text = str(cwe_value).strip()
            values = None
            if text.startswith("["):
                try:
                    parsed = ast.literal_eval(text)
                    if isinstance(parsed, list):
                        values = parsed
                except (SyntaxError, ValueError):
                    values = None
            if values is None:
                values = re.split(r"[,;/|]", text)

        normalized = []
        for item in values:
            cwe = str(item).strip().strip("'\"")
            if cwe:
                normalized.append(cwe)
        return normalized

    def _project_from_url(self, url: str) -> str:
        match = re.search(r"github\.com/([^/]+/[^/]+)", url)
        if match:
            return match.group(1)
        return url or "unknown"


class CVEfixesSource(DataSource):
    """Adapter for the hitoshura25/cvefixes parquet format.

    The HuggingFace export is commit/file-level and contains multiple
    languages. The current generation pipeline is still C/C++ oriented, so this
    adapter conservatively keeps only C/C++ rows with non-empty vulnerable and
    fixed code snippets.
    """

    COLUMNS = [
        "cve_id",
        "hash",
        "repo_url",
        "cve_description",
        "cvss2_base_score",
        "cvss3_base_score",
        "published_date",
        "severity",
        "cwe_id",
        "cwe_name",
        "cwe_description",
        "commit_message",
        "commit_date",
        "version_tag",
        "repo_total_files",
        "repo_total_commits",
        "file_paths",
        "language",
        "diff_stats",
        "vulnerable_code",
        "fixed_code",
        "security_keywords",
    ]
    SUPPORTED_LANGUAGES = {"C", "C++"}

    def load(self, path: str) -> list[dict]:
        """Load usable CVEfixes records from a parquet file or directory."""
        try:
            import pyarrow.parquet as pq
        except ImportError as exc:
            raise ImportError(
                "pyarrow is required for CVEfixes parquet files: pip install pyarrow"
            ) from exc

        parquet_files = self._find_parquet_files(path)
        records = []
        global_row_idx = 0

        for parquet_path in parquet_files:
            parquet_file = pq.ParquetFile(parquet_path)
            available = set(parquet_file.schema_arrow.names)
            columns = [c for c in self.COLUMNS if c in available]

            for batch in parquet_file.iter_batches(columns=columns, batch_size=4096):
                for row in batch.to_pylist():
                    row["_source_file"] = str(parquet_path)
                    row["_row_idx"] = global_row_idx
                    global_row_idx += 1
                    if self._is_usable_record(row):
                        records.append(row)

        return records

    def normalize(self, records: list) -> list[CanonicalPair]:
        pairs = []
        for i, r in enumerate(records):
            raw = {
                k: v for k, v in r.items()
                if k not in {"vulnerable_code", "fixed_code"}
            }
            pairs.append(CanonicalPair(
                vuln_func=(r.get("vulnerable_code") or "").strip(),
                benign_func=(r.get("fixed_code") or "").strip(),
                cve=(r.get("cve_id") or "N/A").strip(),
                cwe=self._parse_cwe(r.get("cwe_id")),
                cve_desc=self._clean_description(r.get("cve_description")),
                project=self._project_from_url(r.get("repo_url") or ""),
                pair_idx=i,
                raw=raw,
            ))
        return pairs

    @property
    def source_name(self) -> str:
        return 'CVEfixes'

    def _find_parquet_files(self, path: str) -> list[Path]:
        root = Path(path)
        if root.is_file():
            if root.suffix != ".parquet":
                raise ValueError(f"CVEfixesSource expects parquet input, got: {path}")
            return [root]
        if not root.exists():
            raise FileNotFoundError(f"CVEfixes path not found: {path}")

        files = sorted(root.rglob("*.parquet"))
        if not files:
            raise FileNotFoundError(f"No parquet files found under: {path}")
        return files

    def _is_usable_record(self, row: dict) -> bool:
        language = (row.get("language") or "").strip()
        if language not in self.SUPPORTED_LANGUAGES:
            return False

        vuln = (row.get("vulnerable_code") or "").strip()
        fixed = (row.get("fixed_code") or "").strip()
        if not vuln or not fixed:
            return False
        if vuln == fixed:
            return False
        if not (row.get("cve_id") or "").strip():
            return False
        return True

    def _parse_cwe(self, cwe_value) -> list[str]:
        if not cwe_value:
            return []
        if isinstance(cwe_value, list):
            values = cwe_value
        else:
            text = str(cwe_value).strip()
            values = None
            if text.startswith("["):
                try:
                    parsed = ast.literal_eval(text)
                    if isinstance(parsed, list):
                        values = parsed
                except (SyntaxError, ValueError):
                    values = None
            if values is None:
                values = re.split(r"[,;/|]", text)

        normalized = []
        for item in values:
            cwe = str(item).strip().strip("'\"")
            if cwe:
                normalized.append(cwe)
        return normalized

    def _clean_description(self, value) -> str:
        if not value:
            return ""
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict) and item.get("lang") == "en":
                    return str(item.get("value") or "").strip()
            return str(value[0]).strip() if value else ""
        if isinstance(value, dict):
            return str(value.get("value") or value).strip()

        text = str(value).strip()
        if text.startswith("[") or text.startswith("{"):
            try:
                return self._clean_description(ast.literal_eval(text))
            except (SyntaxError, ValueError):
                return text
        return text

    def _project_from_url(self, url: str) -> str:
        match = re.search(r"github\.com/([^/]+/[^/]+)", url)
        if match:
            return match.group(1)
        return url or "unknown"


class DiverseVulSource(DataSource):
    """Adapter for wagner-group/diversevul JSONL format.

    DiverseVul is a function-level vulnerability detection dataset. It does not
    provide patched/fixed code. To keep curation CVE-level and avoid ambiguous
    multi-CVE commit messages, this adapter conservatively keeps only target=1
    vulnerable functions whose commit message contains exactly one CVE id.
    """

    CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

    def load(self, path: str) -> list[dict]:
        root = Path(path)
        if root.is_dir():
            files = sorted(root.glob("*.json"))
        elif root.is_file():
            files = [root]
        else:
            raise FileNotFoundError(f"DiverseVul path not found: {path}")

        records = []
        global_row_idx = 0
        for file_path in files:
            with file_path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    row = json.loads(line)
                    row["_source_file"] = str(file_path)
                    row["_row_idx"] = global_row_idx
                    global_row_idx += 1
                    if self._is_usable_record(row):
                        records.append(row)
        return records

    def normalize(self, records: list) -> list[CanonicalPair]:
        pairs = []
        for i, r in enumerate(records):
            message = r.get("message") or ""
            cve = self._extract_single_cve(message)
            raw = {k: v for k, v in r.items() if k != "func"}
            raw["has_fixed_func"] = False
            pairs.append(CanonicalPair(
                vuln_func=(r.get("func") or "").strip(),
                benign_func="",
                cve=cve or "N/A",
                cwe=self._parse_cwe(r.get("cwe")),
                cve_desc=message.strip(),
                project=r.get("project") or "unknown",
                pair_idx=i,
                raw=raw,
            ))
        return pairs

    @property
    def source_name(self) -> str:
        return 'DiverseVul'

    def _is_usable_record(self, row: dict) -> bool:
        if row.get("target") != 1:
            return False
        if not (row.get("func") or "").strip():
            return False
        return self._extract_single_cve(row.get("message") or "") is not None

    def _extract_single_cve(self, text: str) -> Optional[str]:
        cves = sorted({m.upper() for m in self.CVE_RE.findall(text or "")})
        if len(cves) != 1:
            return None
        return cves[0]

    def _parse_cwe(self, cwe_value) -> list[str]:
        if not cwe_value:
            return []
        if isinstance(cwe_value, list):
            values = cwe_value
        else:
            values = re.split(r"[,;/|]", str(cwe_value))
        return [str(item).strip() for item in values if str(item).strip()]


class ReposVulSource(DataSource):
    """Adapter for Eshe0922/ReposVul JSONL format.

    ReposVul contains repository/file/function/line-level information. For this
    pipeline we use only the function-level before/after lists:
    details[*].function_before and details[*].function_after.

    The after-side function target labels are not set in the current C/C++ dump,
    so this adapter pairs each target=1 before function with a uniquely matched
    changed after function by function name. Records marked outdated are skipped
    to keep the curation conservative.
    """

    SUPPORTED_LANGUAGES = {"C", "C++"}
    C_LIKE_EXTENSIONS = {
        "c", "c++", "cc", "cpp", "cxx", "h", "hh", "hpp", "hxx",
    }
    KEYWORDS = {
        "if", "for", "while", "switch", "return", "sizeof",
    }

    def load(self, path: str) -> list[dict]:
        root = Path(path)
        if root.is_dir():
            files = sorted(root.rglob("*.jsonl"))
        elif root.is_file():
            if root.suffix != ".jsonl":
                raise ValueError(f"ReposVulSource expects JSONL input, got: {path}")
            files = [root]
        else:
            raise FileNotFoundError(f"ReposVul path not found: {path}")
        if not files:
            raise FileNotFoundError(f"No JSONL files found under: {path}")

        records = []
        seen_pairs = set()
        global_row_idx = 0

        for file_path in files:
            with file_path.open("r", encoding="utf-8") as f:
                for line_no, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    row = json.loads(line)
                    if not self._is_usable_record(row):
                        global_row_idx += 1
                        continue

                    for detail_idx, detail in enumerate(row.get("details") or []):
                        if not isinstance(detail, dict):
                            continue
                        if not self._is_c_like_detail(detail):
                            continue

                        after_by_name = self._after_functions_by_name(
                            detail.get("function_after") or []
                        )
                        for before_idx, before in enumerate(detail.get("function_before") or []):
                            if not isinstance(before, dict) or before.get("target") != 1:
                                continue
                            before_code = (before.get("function") or "").strip()
                            before_name = self._function_name(before_code)
                            if not before_code or not before_name:
                                continue

                            after_code = self._unique_changed_after(
                                before_code,
                                after_by_name.get(before_name, []),
                            )
                            if not after_code:
                                continue

                            pair_key = (
                                row.get("cve_id"),
                                self._normalize_code(before_code),
                                self._normalize_code(after_code),
                            )
                            if pair_key in seen_pairs:
                                continue
                            seen_pairs.add(pair_key)

                            records.append({
                                "cve_id": (row.get("cve_id") or "").strip(),
                                "cwe_id": row.get("cwe_id") or [],
                                "cve_description": (row.get("cve_description") or "").strip(),
                                "project": row.get("project") or "unknown",
                                "commit_id": row.get("commit_id"),
                                "commit_message": row.get("commit_message"),
                                "commit_date": row.get("commit_date"),
                                "publish_date": row.get("publish_date"),
                                "cvss": row.get("cvss"),
                                "cve_language": row.get("cve_language"),
                                "url": row.get("url"),
                                "html_url": row.get("html_url"),
                                "outdated": row.get("outdated"),
                                "file_path": detail.get("file_path"),
                                "file_language": detail.get("file_language"),
                                "file_name": detail.get("file_name"),
                                "detail_target": detail.get("target"),
                                "function_name": before_name,
                                "function_before_idx": before_idx,
                                "detail_idx": detail_idx,
                                "vulnerable_code": before_code,
                                "fixed_code": after_code,
                                "_source_file": str(file_path),
                                "_row_idx": global_row_idx,
                                "_line_no": line_no,
                            })
                    global_row_idx += 1

        return records

    def normalize(self, records: list) -> list[CanonicalPair]:
        pairs = []
        for i, r in enumerate(records):
            raw = {
                k: v for k, v in r.items()
                if k not in {"vulnerable_code", "fixed_code"}
            }
            raw["pairing_strategy"] = "before_target_1_unique_after_name_match"
            raw["has_fixed_func"] = True
            raw["skip_outdated"] = True
            pairs.append(CanonicalPair(
                vuln_func=(r.get("vulnerable_code") or "").strip(),
                benign_func=(r.get("fixed_code") or "").strip(),
                cve=(r.get("cve_id") or "N/A").strip(),
                cwe=self._parse_cwe(r.get("cwe_id")),
                cve_desc=(r.get("cve_description") or "").strip(),
                project=r.get("project") or "unknown",
                pair_idx=i,
                raw=raw,
            ))
        return pairs

    @property
    def source_name(self) -> str:
        return 'ReposVul'

    def _is_usable_record(self, row: dict) -> bool:
        if row.get("outdated"):
            return False
        if (row.get("cve_language") or "").strip() not in self.SUPPORTED_LANGUAGES:
            return False
        if not (row.get("cve_id") or "").strip():
            return False
        if not row.get("details"):
            return False
        return True

    def _is_c_like_detail(self, detail: dict) -> bool:
        language = str(detail.get("file_language") or "").strip().lower()
        if not language:
            return True
        return language in self.C_LIKE_EXTENSIONS

    def _after_functions_by_name(self, functions: list) -> dict[str, list[str]]:
        by_name = {}
        for item in functions:
            if not isinstance(item, dict):
                continue
            code = (item.get("function") or "").strip()
            name = self._function_name(code)
            if not code or not name:
                continue
            by_name.setdefault(name, []).append(code)
        return by_name

    def _unique_changed_after(self, before_code: str, candidates: list[str]) -> Optional[str]:
        before_norm = self._normalize_code(before_code)
        changed = [
            code for code in candidates
            if code.strip() and self._normalize_code(code) != before_norm
        ]
        if len(changed) != 1:
            return None
        return changed[0].strip()

    def _function_name(self, code: str) -> Optional[str]:
        if not code:
            return None
        header = code.split("{", 1)[0]
        matches = re.findall(r"([A-Za-z_~][A-Za-z0-9_:~<>]*)\s*\(", header)
        for name in reversed(matches):
            short_name = name.split("::")[-1]
            if short_name not in self.KEYWORDS:
                return short_name
        return None

    def _normalize_code(self, code: str) -> str:
        return re.sub(r"\s+", "", code or "")

    def _parse_cwe(self, cwe_value) -> list[str]:
        if not cwe_value:
            return []
        if isinstance(cwe_value, list):
            values = cwe_value
        else:
            values = re.split(r"[,;/|]", str(cwe_value))
        return [str(item).strip() for item in values if str(item).strip()]


class CrossVulSource(DataSource):
    """Adapter for hitoshura25/crossvul parquet format.

    CrossVul is a multi-language before/after file-pair repair dataset. It does
    not expose CVE ids in the HuggingFace export, so this adapter creates a
    synthetic vulnerability id from the file_pair_id prefix:
    CROSSVUL-{group_id}. The source is therefore suitable only as a low-priority
    auxiliary dataset, not as a CVE-grounded source.

    To keep prompt sizes manageable for PoC generation, only C/C++ records with
    both before/after code under MAX_CODE_CHARS are retained.
    """

    COLUMNS = [
        "cwe_id",
        "cwe_description",
        "language",
        "vulnerable_code",
        "fixed_code",
        "file_pair_id",
        "source",
        "language_dir",
    ]
    SUPPORTED_LANGUAGES = {"c", "cpp", "c++"}
    MAX_CODE_CHARS = 10_000

    def load(self, path: str) -> list[dict]:
        try:
            import pyarrow.parquet as pq
        except ImportError as exc:
            raise ImportError(
                "pyarrow is required for CrossVul parquet files: pip install pyarrow"
            ) from exc

        parquet_files = self._find_parquet_files(path)
        records = []
        seen_pair_hashes = set()
        global_row_idx = 0

        for parquet_path in parquet_files:
            parquet_file = pq.ParquetFile(parquet_path)
            available = set(parquet_file.schema_arrow.names)
            columns = [c for c in self.COLUMNS if c in available]

            for batch in parquet_file.iter_batches(columns=columns, batch_size=2048):
                for row in batch.to_pylist():
                    row["_source_file"] = str(parquet_path)
                    row["_row_idx"] = global_row_idx
                    global_row_idx += 1
                    if not self._is_usable_record(row):
                        continue

                    pair_key = self._pair_hash(
                        row.get("vulnerable_code") or "",
                        row.get("fixed_code") or "",
                    )
                    if pair_key in seen_pair_hashes:
                        continue
                    seen_pair_hashes.add(pair_key)
                    records.append(row)

        return records

    def normalize(self, records: list) -> list[CanonicalPair]:
        pairs = []
        for i, r in enumerate(records):
            file_pair_id = str(r.get("file_pair_id") or "").strip()
            group_id = file_pair_id.split("_", 1)[0] if file_pair_id else str(i)
            raw = {
                k: v for k, v in r.items()
                if k not in {"vulnerable_code", "fixed_code"}
            }
            raw["synthetic_vuln_id"] = f"CROSSVUL-{group_id}"
            raw["real_cve_available"] = False
            raw["max_code_chars"] = self.MAX_CODE_CHARS
            pairs.append(CanonicalPair(
                vuln_func=(r.get("vulnerable_code") or "").strip(),
                benign_func=(r.get("fixed_code") or "").strip(),
                cve=f"CROSSVUL-{group_id}",
                cwe=self._parse_cwe(r.get("cwe_id")),
                cve_desc=(r.get("cwe_description") or "").strip(),
                project=f"crossvul/{(r.get('language_dir') or r.get('language') or 'unknown')}",
                pair_idx=i,
                raw=raw,
            ))
        return pairs

    @property
    def source_name(self) -> str:
        return 'CrossVul'

    def _find_parquet_files(self, path: str) -> list[Path]:
        root = Path(path)
        if root.is_file():
            if root.suffix != ".parquet":
                raise ValueError(f"CrossVulSource expects parquet input, got: {path}")
            return [root]
        if not root.exists():
            raise FileNotFoundError(f"CrossVul path not found: {path}")

        files = sorted(root.rglob("*.parquet"))
        if not files:
            raise FileNotFoundError(f"No parquet files found under: {path}")
        return files

    def _is_usable_record(self, row: dict) -> bool:
        language = str(row.get("language") or "").strip().lower()
        language_dir = str(row.get("language_dir") or "").strip().lower()
        if language not in self.SUPPORTED_LANGUAGES and language_dir not in self.SUPPORTED_LANGUAGES:
            return False

        vuln = (row.get("vulnerable_code") or "").strip()
        fixed = (row.get("fixed_code") or "").strip()
        if not vuln or not fixed or vuln == fixed:
            return False
        if len(vuln) > self.MAX_CODE_CHARS or len(fixed) > self.MAX_CODE_CHARS:
            return False
        if not (row.get("cwe_id") or "").strip():
            return False
        if not (row.get("file_pair_id") or "").strip():
            return False
        return True

    def _parse_cwe(self, cwe_value) -> list[str]:
        if not cwe_value:
            return []
        if isinstance(cwe_value, list):
            values = cwe_value
        else:
            values = re.split(r"[,;/|]", str(cwe_value))
        return [str(item).strip() for item in values if str(item).strip()]

    def _pair_hash(self, vulnerable_code: str, fixed_code: str) -> str:
        norm_v = re.sub(r"\s+", "", vulnerable_code or "")
        norm_f = re.sub(r"\s+", "", fixed_code or "")
        return hashlib.sha1((norm_v + "\0" + norm_f).encode("utf-8")).hexdigest()


class CuratedSource(DataSource):
    """Adapter for curation output produced by build_curation.py.

    Expected schema per JSONL record:
        source: str
        record_id: str
        cve: str
        cwe: list[str]
        cve_desc: str
        project: str
        vuln_func: str
        fixed_func: str
    """

    def load(self, path: str) -> list[dict]:
        import json
        records = []
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records

    def normalize(self, records: list) -> list[CanonicalPair]:
        pairs = []
        for i, r in enumerate(records):
            pairs.append(CanonicalPair(
                vuln_func=(r.get("vuln_func") or "").strip(),
                benign_func=(r.get("fixed_func") or r.get("benign_func") or "").strip(),
                cve=(r.get("cve") or "N/A").strip(),
                cwe=r.get("cwe") or [],
                cve_desc=(r.get("cve_desc") or "").strip(),
                project=r.get("project") or "unknown",
                pair_idx=i,
                raw={k: v for k, v in r.items() if k not in {"vuln_func", "fixed_func"}},
            ))
        return pairs

    @property
    def source_name(self) -> str:
        return 'Curated'
