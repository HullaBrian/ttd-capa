"""
Print a chronological "timeline" of what the TTD extractor uncovered, ordered by
TTD trace position so you can step through it in WinDbg.

Two modes:

  * capability timeline (default, needs a rules dir) -- runs capa's matcher over the
    report and lists every capability that fired at call / span-of-calls scope, in
    trace order, each tagged with its TTD position (Sequence:Steps) and thread id:

        python ttd-timeline.py report.ttd.json -r capa-9.4.0/rules

  * call timeline (--calls, no rules needed) -- lists every resolved API call the
    extractor recorded, in trace order, with its TTD position, tid, args and retval:

        python ttd-timeline.py report.ttd.json --calls

The TTD position is exactly what WinDbg shows: paste "Sequence:Steps" into the
time-travel position box, or use `!tt <Sequence>:<Steps>`, to jump to the event.

Requires the capa fork to be installed in the active virtual environment.
"""
import sys
import json
import argparse
from pathlib import Path
from typing import Optional

HERE = Path(__file__).resolve().parent

from capa.features.address import ProcessAddress, ThreadAddress, DynamicCallAddress  # noqa: E402
from capa.features.extractors.ttd.models import TtdCall  # noqa: E402
from capa.features.extractors.ttd.extractor import TtdExtractor  # noqa: E402


# a position past anything real, so calls without a TTD position sort last
_NO_POS_KEY = (1 << 64, 1 << 64)


def position_key(call: TtdCall) -> tuple[int, int]:
    """Sort key from the navigable TTD position 'Sequence:Steps' (hex).

    Falls back to the synthetic `seq` counter for reports produced before the
    extractor learned to emit positions.
    """
    if call.position and ":" in call.position:
        seq, _, steps = call.position.partition(":")
        try:
            return (int(seq, 16), int(steps, 16))
        except ValueError:
            pass
    return (call.seq, 0)


def position_label(call: TtdCall) -> str:
    return call.position if call.position else f"seq={call.seq}"


def fmt_arg(a) -> str:
    """Integers as hex (pointers/handles read naturally); strings quoted."""
    if isinstance(a, bool):
        return repr(a)
    if isinstance(a, int):
        # show negatives as their 64-bit two's-complement form, e.g. -2 -> 0xfffffffffffffffe
        return f"0x{a & 0xFFFFFFFFFFFFFFFF:x}" if a < 0 else f"0x{a:x}"
    return repr(a)


def format_call(call: TtdCall) -> str:
    api = f"{call.module}.{call.api}" if call.module else call.api
    args = ", ".join(fmt_arg(a) for a in call.args)
    ret = "" if call.ret is None else f" -> 0x{call.ret & 0xFFFFFFFFFFFFFFFF:x}"
    return f"{api}({args}){ret}"


def resolve_call(extractor: TtdExtractor, addr: DynamicCallAddress) -> Optional[TtdCall]:
    """Map a call/span match address back to the TtdCall the extractor indexed."""
    try:
        return extractor.sorted_calls[addr.thread.process][addr.thread][addr.id]
    except (KeyError, IndexError):
        return None


def iter_all_calls(extractor: TtdExtractor):
    """Yield (ProcessAddress, ThreadAddress, TtdCall) for every recorded call."""
    for proc_addr, threads in extractor.sorted_calls.items():
        for thread_addr, calls in threads.items():
            for call in calls:
                yield proc_addr, thread_addr, call


def render_call_timeline(extractor: TtdExtractor, limit: Optional[int]) -> int:
    events = [
        (position_key(call), proc.pid, thread.tid, call)
        for proc, thread, call in iter_all_calls(extractor)
    ]
    events.sort(key=lambda e: e[0])
    if limit:
        events = events[:limit]

    posw = max((len(position_label(c)) for _, _, _, c in events), default=8)
    print(f"{'TTD POS':<{posw}}  {'PID':>6}  {'TID':>6}  CALL")
    print("-" * (posw + 2 + 6 + 2 + 6 + 2 + 4))
    for _, pid, tid, call in events:
        print(f"{position_label(call):<{posw}}  {pid:>6}  {tid:>6}  {format_call(call)}")
    sys.stdout.flush()
    print(f"\n{len(events)} calls.", file=sys.stderr)
    return 0


def render_capability_timeline(extractor: TtdExtractor, rules_path: Path, limit: Optional[int]) -> int:
    import capa.rules
    import capa.rules.cache  # noqa: F401  (registers capa.rules.cache used by get_rules)
    from capa.capabilities.common import find_capabilities

    print(f"[ttd-timeline] loading rules from {rules_path} ...", file=sys.stderr)
    ruleset = capa.rules.get_rules([rules_path])

    print("[ttd-timeline] matching ...", file=sys.stderr)
    capabilities = find_capabilities(ruleset, extractor, disable_progress=True)

    timeline = []  # (poskey, pos_label, tid, namespace, rule, call_name)
    unpositioned: dict[str, str] = {}  # rule -> namespace, for process/thread/file scope

    for rule_name, results in capabilities.matches.items():
        rule = ruleset[rule_name]
        if rule.is_subscope_rule():
            # synthetic helper rules, not user-facing capabilities
            continue
        namespace = rule.meta.get("namespace", "") or ""
        if namespace.startswith("internal/") or rule.meta.get("lib"):
            # capa uses these internally; they aren't user-facing capabilities
            continue

        for addr, _ in results:
            if isinstance(addr, DynamicCallAddress):
                call = resolve_call(extractor, addr)
                if call is None:
                    continue
                timeline.append(
                    (
                        position_key(call),
                        position_label(call),
                        addr.thread.tid,
                        namespace,
                        rule_name,
                        format_call(call),
                    )
                )
            else:
                # process / thread / file scope: no single navigable position
                unpositioned[rule_name] = namespace

    timeline.sort(key=lambda e: e[0])
    if limit:
        timeline = timeline[:limit]

    if timeline:
        posw = max(len("TTD POS"), max(len(e[1]) for e in timeline))
        rulew = min(38, max(len(e[4]) for e in timeline))
        nsw = min(34, max(len(e[3]) for e in timeline))
        header = f"{'TTD POS':<{posw}}  {'TID':>6}  {'CAPABILITY':<{rulew}}  {'NAMESPACE':<{nsw}}  TRIGGERING CALL"
        print(header)
        print("-" * len(header))
        for _, pos, tid, namespace, rule_name, call_name in timeline:
            print(f"{pos:<{posw}}  {tid:>6}  {rule_name:<{rulew}}  {namespace:<{nsw}}  {call_name}")

    if unpositioned:
        print("\n# capabilities matched at process/thread/file scope (no single TTD position):")
        for rule_name, namespace in sorted(unpositioned.items()):
            print(f"  {rule_name}  [{namespace}]")

    sys.stdout.flush()
    print(
        f"\n{len(timeline)} positioned capability matches; "
        f"{len(unpositioned)} scope-level capabilities.",
        file=sys.stderr,
    )
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Print a TTD-position-ordered timeline of capabilities (or raw API calls) "
        "uncovered in a TTD report.",
    )
    parser.add_argument("report", help="path to a TTD report (.ttd.json) from ttdcapa-extract")
    parser.add_argument("-r", "--rules", help="capa rules directory (enables the capability timeline)")
    parser.add_argument(
        "--calls",
        action="store_true",
        help="list every recorded API call instead of capa capabilities (no rules needed)",
    )
    parser.add_argument("--limit", type=int, help="show only the first N timeline rows")
    args = parser.parse_args(argv)

    report_path = Path(args.report)
    if not report_path.is_file():
        sys.exit(f"report not found: {report_path}")

    report = json.loads(report_path.read_text(encoding="utf-8"))
    extractor = TtdExtractor.from_report(report)

    if args.calls or not args.rules:
        if not args.calls and not args.rules:
            print(
                "[ttd-timeline] no --rules given; showing the API-call timeline. "
                "pass -r <rules-dir> for a capability timeline.",
                file=sys.stderr,
            )
        return render_call_timeline(extractor, args.limit)

    rules_path = Path(args.rules)
    if not rules_path.exists():
        sys.exit(f"rules path not found: {rules_path}")
    return render_capability_timeline(extractor, rules_path, args.limit)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
