# ttd-capa — CAPA capability detection over Time Travel Debugging traces

Run [Mandiant CAPA](https://github.com/mandiant/capa) capability detection against a
**Time Travel Debugging (TTD) `.run` trace**. TTD records a complete dynamic execution
of a process, which maps cleanly onto CAPA's *dynamic* analysis model (the same model
used for CAPE / DRAKVUF / VMRay sandbox reports).

CAPA has no native TTD support, and TTD's Replay API
(`Microsoft.TimeTravelDebugging.Apis`) is **C++ only**. This project bridges the two:

```
 sample.run  ──►  ttdcapa-extract.exe  ──►  trace.ttd.json  ──►  capa -f ttd  ──►  capabilities
 (TTD trace)      (native C++ sweep)        (neutral report)      (Python backend)   ATT&CK / MBC
```

1. A native **C++ extractor** (`ttdcapa-extract.exe`) replays the trace, resolves every
   call to an exported `module.api`, captures arguments and return values, and emits a
   self-contained **neutral "TTD report" JSON**.
2. A **CAPA dynamic backend** (`-f ttd`, `capa/features/extractors/ttd/`) ingests that
   JSON and feeds CAPA's matcher, mirroring the DRAKVUF extractor.

The split exists because the Replay API is callback-heavy and hot-path; a batch JSON
dump is the right seam between native replay and Python matching.

---

## Repository layout

```
ttd-capa/
├── README.md                         # this file
├── ttd-capa.py                       # one-command wrapper (extract + capa)
├── ttd-timeline.py                   # trace-ordered timeline of capabilities / calls
├── tests/
│   ├── test_ttd_extractor.py         # parity check: dump features per scope
│   └── sample.ttd.json               # tiny schema fixture
├── ttd/                              # native C++ extractor (MSBuild / Visual Studio)
│   ├── ttdcapa-extract.sln
│   ├── ttdcapa-extract.vcxproj
│   ├── packages.config               # Microsoft.TimeTravelDebugging.Apis 0.9.5
│   └── src/
│       ├── main.cpp                  # CLI, trace open/index, export map, call sweep, JSON emit
│       ├── guest_pe.{h,cpp}          # PE parsing from guest memory (exports/imports/sections/strings)
│       ├── hashes.{h,cpp}            # MD5/SHA1/SHA256 of the on-disk sample (CNG/bcrypt)
│       ├── json_writer.{h,cpp}       # minimal streaming JSON writer
│       └── records.h                 # POD records shared across the extractor
├── build/                            # deploy dir: ttdcapa-extract.exe + TTD runtime DLLs
└── capa-9.4.0/                       # bundled CAPA, extended with the TTD backend
    └── capa/features/extractors/ttd/ # the new dynamic backend (see below)
```

### CAPA-side additions

A new dynamic backend package mirrors `capa/features/extractors/drakvuf/`:

| File | Role |
|------|------|
| `ttd/models.py`    | Pydantic `TtdReport` schema for the JSON report |
| `ttd/extractor.py` | `TtdExtractor(DynamicFeatureExtractor)`, indexes calls, implements the 10 abstract methods |
| `ttd/global_.py`   | emits `OS(windows)`, `Arch(amd64)`, `Format(pe)` |
| `ttd/file.py`      | `Import` / `Export` / `Section` / `String` at file scope |
| `ttd/process.py`   | environment strings as `String` at process scope |
| `ttd/thread.py`    | thread enumeration (no thread features) |
| `ttd/call.py`      | reversed args → `Number`/`String`; `API` name variants via `generate_symbols` |
| `ttd/helpers.py`   | call indexing helper |

The format/backend was wired into the bundled CAPA tree (`FORMAT_TTD` / `BACKEND_TTD`)
across `capa/features/common.py`, `capa/helpers.py`, `capa/loader.py`, and
`capa/main.py`. No changes to the matching engine, rule loading, or renderers were
needed — those are scope-agnostic.

---

## Prerequisites

- **Windows x64** (the extractor links the TTD Replay runtime).
- **Visual Studio 2022/2026** (or Build Tools) with the C++ workload and **C++20**.
- **Python 3.10+** for CAPA.
- A **TTD `.run` trace** (plus its `.idx`; the extractor builds the `.idx` on first run
  if missing). Record one with WinDbg Preview's Time-travel debugging or `tttracer.exe`.
- **x64 traces only** in this version.

---

## Build the C++ extractor

Open `ttd/ttdcapa-extract.sln` in Visual Studio, select **x64 / Release**, and build.
The `Microsoft.TimeTravelDebugging.Apis` NuGet package is restored automatically from
`packages.config`, and a post-build step copies the TTD runtime DLLs next to the exe.

The resulting `ttdcapa-extract.exe` plus `TTDReplay.dll` / `TTDReplayCPU.dll` must live
in the same folder at run time (the wrapper looks in `build/` and `ttd/x64/Release/`).

---

## Install the CAPA Python side

```powershell
cd capa-9.4.0
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

Capability **rules** are a separate repo. Clone the tag matching this CAPA version:

```powershell
git clone --branch v9.4.0 https://github.com/mandiant/capa-rules capa-9.4.0/rules
```

---

## Usage

### One command (wrapper)

```powershell
python ttd-capa.py <trace.run> <rules-dir> [--sample sample.exe] [-- <capa args>]
```

The wrapper runs the extractor to a temp report, then invokes `capa -f ttd`. Anything
after a bare `--` is forwarded to CAPA:

```powershell
python ttd-capa.py build\beacon.run capa-9.4.0\rules --sample beacon.exe -- -vv
```

Useful flags: `--extractor <path>` (locate the exe), `--max-calls N` (cap huge traces),
`--with-stack-args` (also capture stack args 5+), `--keep-json` (keep the report).

### Two steps (manual)

```powershell
# 1) extract a neutral report from the trace
build\ttdcapa-extract.exe build\beacon.run --sample beacon.exe -o build\beacon.ttd.json

# 2) run capa against the report
python -m capa.main -f ttd -r capa-9.4.0\rules build\beacon.ttd.json
```

`-f ttd` is optional — CAPA auto-detects the format from a `.ttd.json` report. Add `-vv`
to inspect the full feature tree per scope.

### Extractor CLI

```
ttdcapa-extract <trace.run> [--sample <sample.exe>] [-o <out.json>]
                [--max-calls N] [--with-stack-args]
```

`--sample` supplies the on-disk binary for accurate MD5/SHA hashes (the trace itself
doesn't carry them). Without `-o`, the report is written to stdout; progress goes to
stderr.

### Timeline — navigate matches in WinDbg (`ttd-timeline.py`)

`-v`/`-vv` group matches by rule; when you instead want to walk the trace *in execution
order* and jump to each event in WinDbg, use the timeline script. It reads a TTD report
and prints rows ordered by **TTD position** (`Sequence:Steps`, exactly what WinDbg
shows). Two modes:

```powershell
# capability timeline: every capability that fired at call / span scope, in trace order,
# each tagged with its TTD position, thread id, namespace, and the triggering call
python ttd-timeline.py build\beacon.ttd.json -r capa-9.4.0\rules

# call timeline: every recorded API call in trace order (no rules needed)
python ttd-timeline.py build\beacon.ttd.json --calls
```

```
TTD POS      TID  CAPABILITY                           NAMESPACE                 TRIGGERING CALL
2A1F:3C4       4  link function at runtime on Windows  linking/runtime-linking   kernel32.GetProcAddress(0x7ffa6a180000, 'CreateThread', ...) -> 0x7ffa6a163100
```

To jump there in WinDbg, paste the `TTD POS` into the time-travel position box (or run
`!tt 2A1F:3C4`). Integer arguments and return values are shown in hex. `--limit N` caps
the rows. Capabilities that only match at process/thread/file scope have no single
navigable position and are listed separately at the end.

> Positions are populated by the extractor's `position` field. Reports produced before
> that field existed fall back to the synthetic `seq` counter (shown as `seq=N`); re-run
> the extractor to get real navigable positions.

Run it with the capa venv's interpreter (e.g. `capa-9.4.0\.venv\Scripts\python.exe`) so
capa's dependencies are importable; the script adds the bundled `capa-9.4.0` tree to
`sys.path` itself, so it works from any directory.

---

## The TTD report JSON

The contract between the extractor and the CAPA backend — one self-describing file:

```jsonc
{
  "version": 1,
  "trace":  { "path": "beacon.run", "arch": "x64", "os": "windows" },
  "sample": { "md5": "...", "sha1": "...", "sha256": "...", "name": "beacon.exe" },
  "file": {
    "imports":  [ { "dll": "kernel32.dll", "name": "CreateFileA", "va": 140001234 } ],
    "exports":  [ { "name": "Start", "va": 140005678 } ],
    "sections": [ { "name": ".text", "va": 140001000 } ],
    "strings":  [ "strings recovered from the main module image" ]
  },
  "processes": [{
    "pid": 7036, "ppid": 0, "name": "beacon.exe",
    "environ": [ "PATH=..." ],
    "threads": [ 100, 101 ],
    "calls": [{
      "tid": 100,
      "seq": 12345,                  // monotonic order, consistent with the timeline
      "position": "1A:4F",           // navigable TTD position "Sequence:Steps" (hex)
      "module": "kernel32",          // resolved owning module (no extension)
      "api": "CreateFileA",          // resolved export name
      "args": [ "C:\\path", 1073741824 ],  // strings + ints, natural call order
      "ret": 224                     // RAX, or null if no matching RET was seen
    }]
  }]
}
```

- `module` + `api` are split; the Python side runs `generate_symbols` to produce all
  match variants (`kernel32.CreateFileA`, `CreateFileA`, `CreateFile`, …).
- `args` are emitted in natural call order; `call.py` reverses them to match the
  disassembly convention (as CAPE/DRAKVUF do).
- `position` is the TTD "Sequence:Steps" (hex) of the CALL, as WinDbg shows it. CAPA
  appends it to each rendered call (` @TTD 1A:4F`), so in `-vv`/`-j` output every match
  carries the exact timeline location plus its `{pid,tid,call}` header — paste the
  position into WinDbg's time-travel box (or `!tt 1A:4F`) to jump straight to the call.
- Everything the matcher needs is in this file — no `.run` access from Python.

---

## How it works

### Extractor (`ttd/src/main.cpp`)

1. **Open & index** — `MakeReplayEngine()` → `Initialize(trace.run)`; build the `.idx`
   if it isn't already loaded (slow first run only).
2. **Architecture gate** — `GetSystemInfo().System.ProcessorArchitecture` carries the
   standard Windows `PROCESSOR_ARCHITECTURE_*` value; only `AMD64` (9) is accepted.
3. **Export map** — `GetModuleList()` for each module's base; parse its PE export
   directory **from guest memory** to build an `address → (module, api)` map. Forwarders
   and ordinal-only exports are handled; ASLR bases come from the trace.
4. **Main-module file features** — parse the main image's imports/sections and recover
   strings (packed samples legitimately show empty imports until unpacked at runtime).
5. **Call sweep** — a single forward `ReplayForward()` with a `SetCallReturnCallback`.
   On each CALL whose target is a known export entry, record `module.api`, thread id,
   `seq`, and arguments from `RCX/RDX/R8/R9` (+ optional stack slots). Pointer args are
   dereferenced and, if they point to a readable ASCII/UTF-16 string, captured as a
   `String`; otherwise the integer is kept as a `Number`. On the matching RET, `RAX` is
   recorded as the return value.
6. **Emit** the neutral JSON report.

> **Why `SetReplayFlags(ReplayAllSegmentsWithoutFiltering | ReplaySegmentsSequentially)`
> is required:** by default, bulk `ReplayForward` *filters segments* — instructions
> still execute, but detailed callbacks (call/return) only fire for segments a
> watchpoint "claims." With only a call/return callback registered, nothing claims a
> segment and the callback never fires. `ReplayAllSegmentsWithoutFiltering` forces full
> replay of every segment; `ReplaySegmentsSequentially` keeps it single-threaded so the
> callback's mutation of shared state is race-free.

### CAPA backend (`capa/features/extractors/ttd/`)

`TtdExtractor.from_report(json)` validates the report with the `TtdReport` Pydantic
model, pre-computes global features, and indexes calls per
`ProcessAddress → ThreadAddress → [call]`. CAPA then drives the standard dynamic
interface (`global → file → process → thread → call`) and matches rules unchanged.

---

## Limitations

- **x64 traces only.** x86 (stack-based args) and ARM64 are deferred.
- **Argument capture is heuristic** — register args + RAX, with pointer→string
  dereferencing. CAPA matches argument *values*, not names/types, so this is sufficient,
  but expect occasional over-capture (e.g. per-character string fragments from APIs that
  walk a buffer one char at a time). Harmless for matching.
- **Only exported APIs are recorded** — intra-module calls are intentionally skipped to
  keep volume sane (mirrors CAPE/apimon behavior).
- **One process per trace** — TTD records a single process; child processes get their
  own traces.

---

## Verifying the backend in isolation

`tests/test_ttd_extractor.py` loads a report through `TtdExtractor` and dumps every
feature per scope — handy to confirm a call yields the expected `API`/`Number`/`String`
features:

```powershell
python tests\test_ttd_extractor.py [report.ttd.json]
```

With no argument it uses the bundled `tests/sample.ttd.json` fixture.
