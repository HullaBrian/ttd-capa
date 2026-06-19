> [!WARNING]  
> ttd-capa is still very early-on in development. As such, you may encounter unexpected issues and/or spaghetti code in this project. In no way is this professionally written software.

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

# Prerequisites
- Windows
- v145 for Microsoft C++ Build Tools
- TTD DLLs (`TTDReplay.dll` and `TTDReplayCPU.dll`)
- Python 3.10+ (for CAPA)

# Building ttd-capa
1. Open `ttd/ttdcapa-extract.sln` in Visual Studio
2. Ensure that the required nuget packages (`Microsoft.TimeTravelDebugging.Apis` and `nlohmann.json`) are installed
3. Set the build mode to `x64` and `Release`
4. Navigate to `Build > Build Solution` in order to begin the build

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
- `--with-stack-args` - captures parameters for function calls that are on the stack (capture more than 5+ parameters for function calls)
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
TTD grants malware analysts the unique opportunity to not only identify statically present capabilities, but those capabilities 
only revealed during execution. Thankfully, ttd-capa exposes TTD timestamps, which means that not only can we get the capabilities
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
- Only x64 traces are supported at the moment (no x86 or ARM)
- Argument captures are heuristic, so errors may occur
- Only the functions directly exported by loaded modules are logged in the JSON report

# Verifying the backend in isolation
`tests/test_ttd_extractor.py` loads a report and dumps every feature per scope - helpful to confirm expected `API`/`Number`/`String` features:

```powershell
python tests\test_ttd_extractor.py [report.ttd.json]
```

With no argument it uses the bundled `tests/sample.ttd.json` fixture.
