"""
One-command CAPA-over-TTD wrapper.

Runs the native ttdcapa-extract.exe to turn a .run trace into a neutral TTD report
JSON, then invokes capa with `-f ttd` against that report and a rules directory.

    python ttd-capa.py <trace.run> <rules-dir> [--sample sample.exe]
                       [--extractor path\\to\\ttdcapa-extract.exe]
                       [--keep-json] [-- capa args...]

Anything after a bare `--` (or any unrecognized flags) is forwarded to capa, e.g.:

    python ttd-capa.py trace.run ./rules -- -vv
"""
import os
import sys
import shutil
import argparse
import tempfile
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent


def find_extractor(explicit: str | None) -> Path:
    if explicit:
        p = Path(explicit)
        if not p.is_file():
            sys.exit(f"extractor not found: {p}")
        return p

    # search common build output locations relative to this script
    candidates = [
        HERE / "ttdcapa-extract.exe",
        HERE / "ttd" / "x64" / "Release" / "ttdcapa-extract.exe",
        HERE / "ttd" / "x64" / "Debug" / "ttdcapa-extract.exe",
        HERE / "ttd" / "ttdcapa-extract.exe",
    ]
    for c in candidates:
        if c.is_file():
            return c

    found = shutil.which("ttdcapa-extract")
    if found:
        return Path(found)

    sys.exit(
        "could not locate ttdcapa-extract.exe; build the ttd/ project or pass "
        "--extractor <path>"
    )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Run CAPA capability detection over a TTD .run trace.",
        epilog="Arguments after `--` are passed through to capa.",
    )
    parser.add_argument("trace", help="path to the TTD .run trace file")
    parser.add_argument("rules", help="path to a directory of capa rules")
    parser.add_argument("--sample", help="optional on-disk sample for accurate hashes")
    parser.add_argument("--extractor", help="path to ttdcapa-extract.exe")
    parser.add_argument("--max-calls", type=int, help="cap recorded API calls (for huge traces)")
    parser.add_argument("--with-stack-args", action="store_true", help="also capture stack args 5+")
    parser.add_argument("--keep-json", action="store_true", help="keep the intermediate TTD report")
    parser.add_argument("--python", default=sys.executable, help="python interpreter to run capa")
    args, capa_extra = parser.parse_known_args(argv)
    # argparse leaves a leading "--" in capa_extra if present; drop it
    if capa_extra and capa_extra[0] == "--":
        capa_extra = capa_extra[1:]

    trace = Path(args.trace)
    if not trace.is_file():
        sys.exit(f"trace not found: {trace}")
    rules = Path(args.rules)
    if not rules.exists():
        sys.exit(f"rules path not found: {rules}")

    extractor = find_extractor(args.extractor)

    fd, json_path = tempfile.mkstemp(suffix=".ttd.json")
    os.close(fd)
    json_path = Path(json_path)

    try:
        extract_cmd = [str(extractor), str(trace), "-o", str(json_path)]
        if args.sample:
            extract_cmd += ["--sample", args.sample]
        if args.max_calls:
            extract_cmd += ["--max-calls", str(args.max_calls)]
        if args.with_stack_args:
            extract_cmd += ["--with-stack-args"]

        print(f"[ttd-capa] extracting: {' '.join(extract_cmd)}", file=sys.stderr)
        rc = subprocess.call(extract_cmd)
        if rc != 0:
            sys.exit(f"ttdcapa-extract failed (exit {rc})")
        if json_path.stat().st_size == 0:
            sys.exit("ttdcapa-extract produced an empty report")

        capa_cmd = [
            args.python,
            "-m",
            "capa.main",
            "-f",
            "ttd",
            "-r",
            str(rules),
            *capa_extra,
            str(json_path),
        ]
        print(f"[ttd-capa] running capa: {' '.join(capa_cmd)}", file=sys.stderr)
        return subprocess.call(capa_cmd)
    finally:
        if args.keep_json:
            print(f"[ttd-capa] kept TTD report: {json_path}", file=sys.stderr)
        else:
            json_path.unlink(missing_ok=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
