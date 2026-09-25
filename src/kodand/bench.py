"""Ground-truth benchmark harness (Track A #8).

Runs the template scan against a labeled corpus and reports precision / recall /
F1 per AST category and overall. Corpus layout:

  <corpus>/manifest.yaml            # optional; else inferred from folders
  <corpus>/malicious/<name>/SKILL.md
  <corpus>/benign/<name>/SKILL.md

manifest.yaml (optional) maps sample folder -> expected categories:
  samples:
    malicious/aws-steal: [AST03, AST05]
    benign/safe-doc: []

If no manifest, every sample under malicious/ is expected to yield >=1 finding
(any category) and every sample under benign/ is expected to yield 0 findings.
"""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

import yaml

from kodand.webui.scan_service import run_template_scan

# Only findings whose composite confidence score is at least this are counted as
# "detected" for accuracy scoring. This is where the v3 Context Engine + scoring
# pays off: mitigation/example/warning lines score below the threshold and no
# longer count as false positives.
SCORE_THRESHOLD = 45


def _categories_over_threshold(out_dir: Path, score_threshold: int) -> set:
    aj = out_dir / "analysis.json"
    if not aj.exists():
        return set()
    try:
        data = json.loads(aj.read_text())
    except Exception:
        return set()
    return {f["category"] for f in data.get("findings", [])
            if f.get("confidence_score", 0) >= score_threshold}


def _expected(corpus: Path):
    man = corpus / "manifest.yaml"
    if man.exists():
        data = yaml.safe_load(man.read_text()) or {}
        return {k: set(v or []) for k, v in (data.get("samples") or {}).items()}, True
    exp = {}
    for sub, label in (("malicious", None), ("benign", set())):
        base = corpus / sub
        if base.is_dir():
            for d in base.iterdir():
                if d.is_dir():
                    exp[f"{sub}/{d.name}"] = None if sub == "malicious" else set()
    return exp, False


def run_bench(corpus_path: str, score_threshold: int = SCORE_THRESHOLD) -> dict:
    corpus = Path(corpus_path).expanduser().resolve()
    expected, has_manifest = _expected(corpus)
    per_cat = {}   # cat -> {tp,fp,fn}
    any_tp = any_fn = 0
    tmp = Path(tempfile.mkdtemp(prefix="kodand-bench-"))
    try:
        for sample, exp_cats in expected.items():
            sample_dir = corpus / sample
            sample_out = tmp / sample.replace("/", "_")
            run_template_scan(str(sample_dir), use_custom=False, custom_dir=None,
                              out_dir=sample_out, formats=("json",))
            got = _categories_over_threshold(sample_out, score_threshold)
            if exp_cats is None:
                # presence-only expectation
                if got:
                    any_tp += 1
                else:
                    any_fn += 1
                continue
            if not exp_cats and not got:
                continue  # true negative
            for c in got | exp_cats:
                d = per_cat.setdefault(c, {"tp": 0, "fp": 0, "fn": 0})
                if c in got and c in exp_cats:
                    d["tp"] += 1
                elif c in got and c not in exp_cats:
                    d["fp"] += 1
                elif c not in got and c in exp_cats:
                    d["fn"] += 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    def prf(tp, fp, fn):
        p = tp / (tp + fp) if (tp + fp) else 1.0
        r = tp / (tp + fn) if (tp + fn) else 1.0
        f = 2 * p * r / (p + r) if (p + r) else 0.0
        return round(p, 3), round(r, 3), round(f, 3)

    cat_rows = {}
    TP = FP = FN = 0
    for c, d in sorted(per_cat.items()):
        TP += d["tp"]; FP += d["fp"]; FN += d["fn"]
        cat_rows[c] = {**d, "precision": prf(d["tp"], d["fp"], d["fn"])[0],
                       "recall": prf(d["tp"], d["fp"], d["fn"])[1],
                       "f1": prf(d["tp"], d["fp"], d["fn"])[2]}
    op, orr, of1 = prf(TP, FP, FN)
    return {"has_manifest": has_manifest, "samples": len(expected), "score_threshold": score_threshold,
            "per_category": cat_rows,
            "overall": {"tp": TP, "fp": FP, "fn": FN, "precision": op, "recall": orr, "f1": of1},
            "presence_only": {"tp": any_tp, "fn": any_fn}}
