> [!WARNING]
> ttd-capa is still early in development. You may encounter unexpected issues and rough edges. If you hit a bug or have a suggestion, please open an issue or PR.

# ttd-capa

ttd-capa is a [CAPA](https://github.com/mandiant/capa)-compatible capability extractor for Time Travel Debugging (TTD) traces. TTD records the complete execution of a process, and ttd-capa mines that recording for the capabilities a binary actually exercised at runtime.

![](assets/ttd-capa-comparison.png)

A static CAPA scan only sees what is visible without running the sample. Against a packed binary, that is often little more than the packer itself (UPX in the screenshot above). ttd-capa scans the full trace instead, so capabilities that only appear once the sample unpacks and executes become visible (right side of the screenshot). This makes it useful for triaging packed or obfuscated malware, where the interesting behavior is hidden until runtime.

# How It Works

ttd-capa is not a standalone tool. It runs alongside CAPA, producing a report that CAPA then matches against its existing rules.

![](assets/ttd-capa-diagram.png)

The workflow is:

1. Record a TTD trace of the sample.
2. Run ttd-capa on the trace to generate a CAPA-compatible JSON report.
3. Run CAPA on the report to extract capabilities using the standard rule set.

To build the report, ttd-capa walks the module load events in the trace, extracts each module's exported functions, then sweeps the entire trace watching for calls into those exports. Every matching call is logged with its module, function name, arguments, and return value.

Arguments are decoded using Microsoft's own Win32 API metadata, which gives ttd-capa each function's real parameter count and types. Because a TTD trace can be read at any point in time, `[Out]` parameters are re-read at the call's return, so values a function writes back to the caller (buffers, output handles, byte counts) are captured filled in. String arguments are resolved automatically, which tends to surface quick wins during analysis. Calls with no available metadata fall back to a register-based heuristic.

Because TTD records timestamps, ttd-capa can also reconstruct the order and timing of capabilities across execution, not just the set of capabilities present.

# Prerequisites

- Windows
- Microsoft C++ Build Tools, v143 (VS2022) or newer
- TTD DLLs (`TTDReplay.dll` and `TTDReplayCPU.dll`), which ship with WinDbg
- Python 3.10+ (for CAPA)

# Building

Clone with submodules, since the `win32json` submodule supplies the API metadata:

```powershell
git clone --recursive <repo-url>
# or, in an existing clone:
git submodule update --init
```

Then build the extractor:

1. Open `ttd/ttdcapa-extract.sln` in Visual Studio.
2. Install the required NuGet packages (`Microsoft.TimeTravelDebugging.Apis` and `nlohmann.json`).
3. Set the configuration to `x64` / `Release`.
4. Build the solution (`Build > Build Solution`).

The extractor also needs Microsoft's `TTDReplay.dll` and `TTDReplayCPU.dll` at runtime. These ship with WinDbg, not with this project. Locate them with:

```powershell
Join-Path (Get-AppxPackage Microsoft.WinDbg).InstallLocation 'amd64\ttd'
```

Then either pass `--ttd-dlls <that path>` when running, or copy both DLLs next to `ttdcapa-extract.exe`. See [docs/ttdcapa-extract.md](docs/ttdcapa-extract.md) for the full option reference.

# Installing a TTD-compatible CAPA (temporary)

A PR to upstream CAPA is in progress, so native TTD support should land there eventually. Until then, use the fork.

Clone and install [HullaBrian/capa](https://github.com/HullaBrian/capa):

```powershell
git clone https://github.com/HullaBrian/capa
cd capa
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

Capability rules live in a separate repo. Download the rules release matching the fork (9.4.0): [capa-rules v9.4.0](https://github.com/mandiant/capa-rules/archive/refs/tags/v9.4.0.zip).

# Usage

## Python wrapper (recommended)

`ttd-capa.py` combines feature extraction and rule matching into a single step:

```powershell
python ttd-capa.py <trace.run> <rules-dir> [--sample sample.exe] [-- <capa args>]
```

It runs the extractor to a temporary report and then invokes `capa -f ttd`. Anything after a bare `--` is passed straight through to CAPA:

```powershell
python ttd-capa.py <trace.run> <rules-dir> --sample sample.exe -- -vv
```

Useful flags:

- `--extractor <path>` - path to the ttd-capa extractor executable
- `--max-calls N` - cap the number of calls processed on very large traces
- `--max-buffer N` - bytes to keep from any one captured buffer (default 65536)
- `--keep-json` - keep the generated JSON report after the run

See [docs/ttdcapa-extract.md](docs/ttdcapa-extract.md) for the complete list.

## Manual

To run the two steps yourself:

```powershell
# 1) generate the report from the trace
<ttdcapa-extract.exe> <trace.run> --sample <optional sample file> -o <output.json>

# 2) run capa against the report
python -m capa.main -f ttd -r <rules-dir> <output.json>
```

## Timeline

`ttd-timeline.py` uses the TTD timestamps in a report to show capabilities (or all observed API calls) in execution order:

```powershell
# executed capabilities only
python ttd-timeline.py <report.json> -r <rules-dir>

# all observed API calls
python ttd-timeline.py <report.json> --calls
```

Example output for a UPX-packed Cobalt Strike beacon:

```
TTD POS       TID  CAPABILITY                              NAMESPACE                           TRIGGERING CALL
--------------------------------------------------------------------------------------------------------------
8F6:1EF2        4  link function at runtime on Windows     linking/runtime-linking             kernel32.GetProcAddress(hModule=0x7ffc23060000, lpProcName='InternetConnectA') -> 0x7ffc23129740
8F9:153A        4  link function at runtime on Windows     linking/runtime-linking             kernel32.GetProcAddress(hModule=0x7ffc23060000, lpProcName='InternetOpenA') -> 0x7ffc2312ab30
...
3E3E:F52        4  create HTTP request                     communication/http/client           wininet.InternetOpenA(lpszAgent='Mozilla/4.0 (compatible; MSIE 5.0; Windows NT; DigExt; DTS Agent', dwAccessType=0x0, lpszProxy=0x0, lpszProxyBypass=0x0, dwFlags=0x0) -> 0xcc0004
3E3E:25B7       4  connect to HTTP server                  communication/http/client           wininet.InternetConnectA(hInternet=0xcc0004, lpszServerName='192.168.81.129', nServerPort=0x50, lpszUserName=0x0, lpszPassword=0x0, dwService=0x3, dwFlags=0x0, dwContext=0xb684c4) -> 0xcc0008
...
```

# Supported

- x64 and x86 traces, including WoW64 (bitness is decided per call from the owning module's PE header)
- Functions directly exported by loaded modules
- Exact argument decoding for APIs covered by the public Win32 SDK metadata

# Not Supported

- Dynamically allocated code. Any code which is present during the recording only is not scanned by ttd-capa...for now... (coming soon)
- ARM64 traces
- COM interface methods (the call target is a vtable slot, not a named export, and the metadata has no vtable indices)
- Variadic functions (`printf`-style): only their fixed parameters are decoded
- Structure fields: struct parameters are recorded as pointers and not expanded
- Exact argument decoding for `ntdll` internals, undocumented APIs, and CRT helpers, which fall back to the register heuristic and may be wrong

A few caveats worth knowing:

- Some string and buffer arguments come back empty even when the data is in the trace. This is a property of the memory-read interface used during the sweep, not evidence that the argument was null; the raw pointer value is still recorded. Recovering these values is possible but expensive, so it is not done yet.
- On x86, some signatures are undecodable because a pointer-sized parameter (`SIZE_T`, `WPARAM`, `LPARAM`, etc.) is ambiguous against the x64 width stored in the index. Affected calls fall back to the heuristic; `--dump-sig` marks them `[no x86 layout]`.
