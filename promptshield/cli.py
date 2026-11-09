"""Command line: serve | scan | train | eval"""
from __future__ import annotations

import argparse
import json
import sys


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="promptshield", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="Run the firewall proxy")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)

    sc = sub.add_parser("scan", help="Scan a single text (or stdin with '-')")
    sc.add_argument("text")
    sc.add_argument("--output", action="store_true", help="Scan as model output (DLP) instead of input")
    sc.add_argument("--model", help="Path to a trained classifier")

    t = sub.add_parser("train", help="Train the ML classifier on a dataset's train split")
    t.add_argument("--dataset", default="deepset")
    t.add_argument("--out", default="models/classifier.joblib")

    e = sub.add_parser("eval", help="Benchmark against a labelled dataset")
    e.add_argument("--dataset", default="deepset", help="'deepset', 'sample', or a path to .jsonl/.csv/.parquet")
    e.add_argument("--split", default="test")
    e.add_argument("--model", help="Path to a trained classifier (adds 'classifier' and 'hybrid' rows)")
    e.add_argument("--threshold", type=float, default=0.5)
    e.add_argument("--json", help="Write metrics to this JSON file")
    e.add_argument("--show-errors", type=int, default=0, help="Print N misses and false alarms")

    a = ap.parse_args(argv)

    if a.cmd == "serve":
        import logging
        import uvicorn
        from .proxy import create_app
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
        uvicorn.run(create_app(), host=a.host, port=a.port)
        return 0

    from .engine import Firewall

    if a.cmd == "scan":
        text = sys.stdin.read() if a.text == "-" else a.text
        clf = _load_clf(a.model)
        fw = Firewall(classifier=clf)
        v = fw.scan_output(text) if a.output else fw.scan_input(text)
        print(json.dumps(v.to_dict(), indent=2))
        return 1 if v.blocked else 0

    from .eval.datasets import load

    if a.cmd == "train":
        from .detectors.classifier import ClassifierDetector
        data = load(a.dataset, "train")
        clf = ClassifierDetector.train([d.text for d in data], [d.label for d in data])
        clf.save(a.out)
        print(f"Trained on {len(data)} examples -> {a.out}")
        return 0

    if a.cmd == "eval":
        from .eval.evaluate import evaluate, markdown
        data = load(a.dataset, a.split)
        reports = [evaluate(Firewall(threshold=a.threshold), data, "heuristics")]
        if a.model:
            clf = _load_clf(a.model)
            reports.append(evaluate(Firewall(threshold=a.threshold, classifier=clf, use_heuristics=False), data, "classifier"))
            reports.append(evaluate(Firewall(threshold=a.threshold, classifier=clf), data, "hybrid"))
        print(markdown(reports, f"{a.dataset}:{a.split}" if a.dataset == "deepset" else a.dataset))
        if a.show_errors:
            best = reports[-1]
            print(f"### Misses ({best.name})")
            for t in best.misses[:a.show_errors]:
                print(" -", t[:140].replace("\n", " "))
            print(f"### False alarms ({best.name})")
            for t in best.false_alarms[:a.show_errors]:
                print(" -", t[:140].replace("\n", " "))
        if a.json:
            with open(a.json, "w") as f:
                json.dump([r.to_dict() for r in reports], f, indent=2)
        return 0
    return 1


def _load_clf(path):
    if not path:
        return None
    from .detectors.classifier import ClassifierDetector
    return ClassifierDetector.load(path)


if __name__ == "__main__":
    raise SystemExit(main())
