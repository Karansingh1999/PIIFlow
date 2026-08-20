from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main(argv: list[str] | None = None) -> int:
    from benchmarks.evaluator.loader import ManifestError, load_manifest
    from benchmarks.evaluator.reporting import write_markdown_report
    from benchmarks.evaluator.runner import evaluate

    parser = argparse.ArgumentParser(description="Run PIIFlow-Bench.")
    parser.add_argument("--manifest", type=Path, default=Path(__file__).with_name("manifest.yaml"))
    parser.add_argument("--partition", choices=["all", "in_scope", "challenge"], default="all")
    parser.add_argument(
        "--system",
        choices=["all", "piiflow", "piiflow_legacy", "lexical", "direct"],
        default="all",
    )
    parser.add_argument(
        "--output-directory",
        type=Path,
        default=Path(__file__).with_name("results"),
    )
    parser.add_argument("--fail-on-invalid-manifest", action="store_true")
    parser.add_argument(
        "--limit", type=int, default=None, help="Evaluate a deterministic prefix subset."
    )
    args = parser.parse_args(argv)

    try:
        manifest = load_manifest(args.manifest)
    except ManifestError as exc:
        print(f"Invalid manifest: {exc}", file=sys.stderr)
        return 2 if args.fail_on_invalid_manifest else 0

    metrics = evaluate(
        manifest_path=args.manifest,
        manifest=manifest,
        partition=args.partition,
        system=args.system,
        output_directory=args.output_directory,
        limit=args.limit,
    )
    write_markdown_report(metrics, args.output_directory)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
