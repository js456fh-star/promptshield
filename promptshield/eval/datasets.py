"""Dataset loaders for benchmarking.

Built-in public dataset:
  deepset  -> https://huggingface.co/datasets/deepset/prompt-injections
              (EN/DE, label 1 = injection, splits: train / test)

Also loads any local .jsonl / .csv / .parquet file with a text column and a
0/1 label column, so you can plug in other public sets.
"""
from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass
from pathlib import Path

CACHE = Path.home() / ".cache" / "promptshield"
BUNDLED = Path(__file__).resolve().parents[2] / "data" / "sample.jsonl"

HF_DATASETS = {
    "deepset": {"repo": "deepset/prompt-injections", "text": "text", "label": "label"},
}


@dataclass
class Example:
    text: str
    label: int  # 1 = attack, 0 = benign


def load(name_or_path: str, split: str = "test") -> list[Example]:
    if name_or_path == "sample":
        return load_file(BUNDLED)
    if name_or_path in HF_DATASETS:
        return load_hf(name_or_path, split)
    return load_file(Path(name_or_path))


def load_hf(name: str, split: str) -> list[Example]:
    spec = HF_DATASETS[name]
    cache = CACHE / f"{name}-{split}.jsonl"
    if not cache.exists():
        import httpx
        api = f"https://huggingface.co/api/datasets/{spec['repo']}/parquet/default/{split}"
        with httpx.Client(timeout=60, follow_redirects=True) as c:
            urls = c.get(api).raise_for_status().json()
            rows: list[Example] = []
            for url in urls:
                rows += _parquet_rows(c.get(url).raise_for_status().content, spec["text"], spec["label"])
        cache.parent.mkdir(parents=True, exist_ok=True)
        with cache.open("w") as f:
            for r in rows:
                f.write(json.dumps({"text": r.text, "label": r.label}) + "\n")
    return load_file(cache)


def _parquet_rows(raw: bytes, text_col: str, label_col: str) -> list[Example]:
    import pyarrow.parquet as pq
    t = pq.read_table(io.BytesIO(raw)).to_pydict()
    return [Example(str(x), int(y)) for x, y in zip(t[text_col], t[label_col])]


def load_file(path: Path, text_col: str = "text", label_col: str = "label") -> list[Example]:
    suffix = path.suffix.lower()
    if suffix == ".jsonl":
        rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    elif suffix == ".csv":
        rows = list(csv.DictReader(path.open(newline="")))
    elif suffix == ".parquet":
        return _parquet_rows(path.read_bytes(), text_col, label_col)
    else:
        raise ValueError(f"Unsupported dataset format: {path}")
    return [Example(str(r[text_col]), int(r[label_col])) for r in rows]
