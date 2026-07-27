> [!WARNING]  
> ttd-capa is still very early-on in development. As such, you may encounter unexpected issues and/or spaghetti code in this project. In no way is this professionally written software. If you have an issue or a suggestion, feel free to open an issue or PR

# Overview

ttd-capa is a [CAPA](https://github.com/mandiant/capa) compatible capability extractor built for Time Travel Debugging (TTD) traces.
TTD records the complete execution of a process, and exposes a vast amount of information which can be used for analysis purposes.

![](assets/ttd-capa-comparison.png)

With this tool, reverse engineers can get signifcantly more information from a binary with just a TTD trace, a tool, and a dream. 
Take a packed CobaltStrike beacon as an example (see above screenshot). With just a static CAPA scan, only a few things might be observed (left side of screenshot).
You may even see the type of packer being used (i.e. UPX). However, not much can be determined about the actual capabilities 
of the packed executable code. This is where ttd-capa shines. Once a TTD trace is recorded, ttd-capa can scan the entire trace and identify 
capabilities only revealed during runtime (right side of screenshot).

![](assets/ttd-capa-diagram.png)
ttd-capa is not a standalone tool. Rather, it is meant to be run in unison with the CAPA tool so as to extract information useful for CAPA rule matching.
The general capability extraction process looks like:
1. Record a TTD trace of a given sample
2. Run ttd-capa on the trace, which generates a CAPA-compatible JSON report
3. Run CAPA on the report, which uses existing CAPA rules to extract capability information

# How it Works
ttd-capa uses the official Microsoft TTD C++ SDK to interact with TTD, and [nlohmann/json](https://github.com/nlohmann/json) for working with JSON.

ttd-capa will first gather a list of module load events and navigate to each. Once there, it will extract the exported functions directly from the TTD trace 
and store their associated virtual address, function name, and module name. Next, ttd-capa registeres a call callback with the TTD engine, and iterates over 
the entire trace. Every time a call occurs, ttd-capa checks if the call target is one stored in the module export map. If it is, then it will log the call along 
with the associate module, function name, parameters, and return value. Additionally, ttd-capa automatically attempts to resolve function parameters as strings, 
which has the potential to significantly increase quick wins during malware analysis.

## Metadata-driven parameter decoding
Knowing an API's name is not the same as knowing its signature. Without one, all an extractor can do is grab the four
x64 argument registers and guess at each value - so `CloseHandle(hObject)` gets recorded with four arguments, three of
which are whatever the caller happened to leave in RDX/R8/R9, and any integer that happens to point at printable bytes
gets mistaken for a string.

ttd-capa fixes that with Microsoft's own Win32 API metadata, vendored as the [win32json](https://github.com/marlersoft/win32json)
submodule. `tools/build-win32-index.py` flattens those ~300 JSON files into a compact binary index
(`ttd/data/win32-index.bin`, ~2.7 MB) keyed by export name, which the extractor memory-maps at startup. For every call
whose export is in the index, ttd-capa now knows:

- **the real parameter count**, so exactly that many arguments are captured - including the ones past RCX/RDX/R8/R9
  (`CreateProcessW` has ten) and none of the register residue that used to masquerade as arguments
- **each parameter's type**, so `PSTR` is decoded as ANSI and `PWSTR` as UTF-16 rather than by trial, and values typed
  as `HANDLE`, enums, or plain integers are never dereferenced at all
- **direction** - `[Out]` parameters are re-read at the call's *return* position, so `lpNumberOfBytesRead` and friends
  are rendered filled in. This is something a live debugger can't easily do, and it's where a time-travel trace earns
  its keep
- **buffer lengths**, from `MemorySize(BytesParamIndex)` and array count parameters, so `InternetReadFile`'s `lpBuffer`
  can be captured at its true length once the callee has written it
- **enum and flag tables**, so `dwCreationDisposition=3` renders as `CREATE_ALWAYS`

The decoded view lands in a new `params` array on each call in the report. The `args` array capa matches against keeps
its original shape - it just has the correct arity now, plus any strings recovered from `[Out]` parameters. Symbolic
flag names are deliberately *not* pushed into `args`, since existing rules match flags numerically.

Coverage is the public Windows SDK, which is what the metadata documents: roughly the top 15% of calls in a typical
trace by volume, but the great majority of the *interesting* ones. Calls with no signature - `ntdll` internals, CRT
helpers like `memset` - fall back to the original four-register heuristic unchanged.

To regenerate the index (only needed after bumping the `win32json` submodule):

```powershell
python tools\build-win32-index.py
```

# Prerequisites
- Windows
- v145 for Microsoft C++ Build Tools
- TTD DLLs (`TTDReplay.dll` and `TTDReplayCPU.dll`)
- Python 3.10+ (for CAPA)

# Building ttd-capa
Clone with submodules (`git clone --recursive`, or `git submodule update --init` in an existing clone) - the
`win32json` submodule supplies the API metadata.

1. Open `ttd/ttdcapa-extract.sln` in Visual Studio
2. Ensure that the required nuget packages (`Microsoft.TimeTravelDebugging.Apis` and `nlohmann.json`) are installed
3. Set the build mode to `x64` and `Release`
4. Navigate to `Build > Build Solution` in order to begin the build

The build copies `ttd/data/win32-index.bin` next to the executable. If it's missing, run
`python tools\build-win32-index.py` to generate it; without it the extractor still runs, but falls back to heuristic
argument capture for every call.

After the build, ttd-capa cannot run properly without Microsoft's `TTDReplay.dll` and `TTDReplayCPU.dll` being in the same directory as `ttdcapa-extract.exe`. 
To get those DLLs, ensure you have WinDbg instealled already. Then, run the following PowerShell command to find the DLL location on your system:

```powershell
Join-Path (Get-AppxPackage Microsoft.WinDbg).InstallLocation 'amd64\ttd'
```

Then, copy `TTDReplay.dll` and `TTDReplayCPU.dll` into the same directory as `ttdcapa-extract.exe`.

# (Temporary) Installing TTD compatible CAPA
I'm opening a PR to the main CAPA repository, so hopefully CAPA will eventually have native support 
for TTD traces. In the meantime, you can install a custom fork of CAPA. To start, clone [https://github.com/HullaBrian/capa](https://github.com/HullaBrian/capa)

Once you have cloned the repository, create a Python virtual environment, and install CAPA:
```powershell
cd capa
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

Capability rules are a separate repo maintained by the CAPA team. Clone the rules release matching 
the version of the (temporary) fork (should be 9.4.0): [https://github.com/mandiant/capa-rules/archive/refs/tags/v9.4.0.zip](https://github.com/mandiant/capa-rules/archive/refs/tags/v9.4.0.zip)

# Usage
## Python Wrapper Script
Included in this repository is `ttd-capa.py`, which is a wrapper script that abstracts some of the "plumbing" away and makes 
extracting the features and performing rule matching a single step.

```powershell
python ttd-capa.py <trace.run> <rules-dir> [--sample sample.exe] [-- <capa args>]
```

The wrapper runs the extractor to a temp report (deleted after use), then invokes `capa -f ttd`. Anything
after a bare `--` is forwarded to CAPA:

```powershell
python ttd-capa.py <trace.run> <rules-dir> --sample sample.exe -- -vv
```

Useful flags:
- `--extractor <path>` - specify a path to the ttd-capa extractor executable
- `--max-calls N` - cap huge traces to certain number of calls
- `--with-stack-args` - for calls with *no* Win32 metadata, also grab four stack slots past the register arguments.
  Calls we have a signature for always capture their true arity, stack parameters included, so this only affects the
  heuristic fallback path
- `--win32-index <path>` - use a specific `win32-index.bin` instead of the one next to the extractor
- `--no-metadata` - disable metadata-driven decoding and use the original four-register heuristic everywhere
- `--max-buffer N` - bytes to keep from any one captured buffer (default 65536). Buffers cut short
  at this limit carry a `bytes_total` field giving their real length. The default is deliberately
  generous: buffer parameters are well under 1% of the calls in a typical trace, so they are never
  the dominant cost in a report, whereas a buffer truncated below the interesting part is lost
- `--keep-json` - keep the generated JSON report after the Python script runs

## Manual
To manually extract capability features without the Python wrapper script:

```powershell
# 1) generate report from the trace
<PATH TO TTDCAPA-EXTRACT.EXE> <PATH TO TTD TRACE> --sample <OPTIONAL SAMPLE FILE> -o <OUTPUT JSON PATH>

# 2) run capa against the report
python -m capa.main -f ttd -r <CAPA RULES DIRECTORY> <OUTPUT JSON PATH>
```

# Timeline Generation
ttd-capa exposes TTD timestamps, which means that not only can we get the capabilities
over the entire execution of the sample, but also the order and time when they were leveraged.

See the following example generated by `ttd-timeline.py` on a JSON report for a UPX-packed CobaltStrike beacon. Within the timeline 
is a clearly defined order of the executed capabilities, along with the associated function parameters. This can provide quick wins 
during initial triage efforts.
```
TTD POS       TID  CAPABILITY                              NAMESPACE                           TRIGGERING CALL
--------------------------------------------------------------------------------------------------------------
...
38DF:F52        4  create HTTP request                     communication/http/client           wininet.InternetOpenA('Mozilla/4.0 (compatible; MSIE 5.0; Windows NT; DigExt; DTS Agent', 0x0, 0x0, 0x0, 0x0, 0x19b5040, 0xcdbc90, '/jquery-3.3.1.min.js') -> 0xcc0004
38E5:6DA        4  connect to HTTP server                  communication/http/client           wininet.InternetConnectA(0xcc0004, '192.168.81.129', 0x50, 0x0, 0x0, 0x3, 0x0, 0x11584c4) -> 0xcc0008
...
```

`ttd-timeline.py` allows you to either display execution capabilities or all observed API calls within the trace in the final timeline view.

To see only the executed capabilities in the trace:
```powershell
python ttd-timeline.py <JSON REPORT PATH> -r <CAPA RULES PATH>
```

To see all observed API calls during the trace:
```powershell
python ttd-timeline.py <JSON REPORT PATH> --calls
```

# Limitations
- x64 and x86 traces are supported, including WoW64; ARM64 is not. Bitness is decided per call
  from the PE header of the module owning the call target rather than once per trace -- a WoW64
  process runs both widths at once, and `SystemInfo.ProcessorArchitecture` describes the machine
  that did the recording, not the process that was recorded
- On x86, a parameter whose stack footprint cannot be derived from the index makes the whole
  signature undecodable, and the call falls back to the heuristic capture. This affects any API
  taking a pointer-sized scalar (`SIZE_T`, `WPARAM`, `LPARAM` and the other typedefs over
  `UIntPtr`): the index records the x64 width of 8, and an 8 is ambiguous between a genuine
  64-bit type, which pushes 8 bytes on x86 too, and a pointer-sized one, which pushes 4.
  Guessing would silently shift every later parameter. Roughly a fifth of commonly-seen APIs are
  affected, `VirtualAlloc` and `HeapAlloc` among them; `--dump-sig` marks them `[no x86 layout]`.
  Fixing it means having `build-win32-index.py` emit the x86 footprint alongside the x64 one --
  there is a spare pad byte in the parameter record for exactly that
- Aggregates passed by value are declined on x86 for the same reason: the x64 ABI passes them by
  hidden pointer, so the index records a pointer where x86 pushes the whole struct
- Only the functions directly exported by loaded modules are logged in the JSON report
- Argument decoding is exact only for APIs covered by the Win32 metadata (public SDK surface). `ntdll` internals,
  undocumented APIs, and CRT helpers fall back to the four-register heuristic, so their arguments may still be wrong
- COM interface methods are not resolved; the metadata has no vtable indices, and the call target is a vtable slot
  rather than a named export
- Variadic functions (`printf`-style) have no statically knowable argument count, so only their fixed parameters are
  decoded
- Structure parameters are recorded as pointers; fields are not expanded

# Verifying the backend in isolation
`tests/test_ttd_extractor.py` loads a report and dumps every feature per scope - helpful to confirm expected `API`/`Number`/`String` features:

```powershell
python tests\test_ttd_extractor.py [report.ttd.json]
```

With no argument it uses the bundled `tests/sample.ttd.json` fixture.
