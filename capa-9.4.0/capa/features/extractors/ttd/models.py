# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Pydantic models for the neutral "TTD report" JSON emitted by ttdcapa-extract.exe.

This is the contract between the native TTD trace sweeper (C++) and capa's TTD
dynamic backend. Everything capa needs to match rules comes from this document;
the .run trace itself is never touched from Python.

Schema (version 1)::

    {
      "version": 1,
      "trace":   { "path": "sample.run", "arch": "x64", "os": "windows" },
      "sample":  { "md5": "...", "sha1": "...", "sha256": "...", "name": "sample.exe" },
      "file": {
        "imports":  [ { "dll": "kernel32.dll", "name": "CreateFileA", "va": 140001234 } ],
        "exports":  [ { "name": "Start", "va": 140005678 } ],
        "sections": [ { "name": ".text", "va": 140001000 } ],
        "strings":  [ "recovered from the main module image" ]
      },
      "processes": [
        {
          "pid": 1234, "ppid": 500, "name": "sample.exe",
          "environ": [ "PATH=..." ],
          "threads": [ 100, 101 ],
          "calls": [
            { "tid": 100, "seq": 12345, "position": "1A:4F",
              "module": "kernel32", "api": "CreateFileA",
              "args": [ "C:\\\\path", 1073741824 ], "ret": 224 }
          ]
        }
      ]
    }
"""
from typing import Union, Optional

from pydantic import BaseModel, ConfigDict


class ConciseModel(BaseModel):
    # ignore unknown keys so the schema can evolve without breaking older capa builds
    model_config = ConfigDict(extra="ignore")


class TtdImport(ConciseModel):
    dll: str
    name: str
    va: int = 0


class TtdExport(ConciseModel):
    name: str
    va: int = 0


class TtdSection(ConciseModel):
    name: str
    va: int = 0


class TtdFile(ConciseModel):
    imports: list[TtdImport] = []
    exports: list[TtdExport] = []
    sections: list[TtdSection] = []
    strings: list[str] = []


class TtdSample(ConciseModel):
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    name: str = ""


class TtdTrace(ConciseModel):
    path: str = ""
    arch: str = "x64"
    os: str = "windows"


class TtdCall(ConciseModel):
    tid: int
    # ordering key within a thread, derived from the TTD Position (Sequence:Steps).
    seq: int = 0
    # navigable TTD position "Sequence:Steps" (hex) of the call, for WinDbg time-travel.
    position: str = ""
    # owning module of the resolved export, e.g. "kernel32" or "kernel32.dll" (may be empty).
    module: str = ""
    # resolved export name, e.g. "CreateFileA".
    api: str
    # call arguments in natural (left-to-right) order; ints -> Number, strings -> String.
    args: list[Union[int, str]] = []
    # return value (RAX), if captured.
    ret: Optional[int] = None


class TtdProcess(ConciseModel):
    pid: int
    ppid: int = 0
    name: str = ""
    environ: list[str] = []
    threads: list[int] = []
    calls: list[TtdCall] = []


class TtdReport(ConciseModel):
    version: int
    trace: TtdTrace = TtdTrace()
    sample: TtdSample = TtdSample()
    file: TtdFile = TtdFile()
    processes: list[TtdProcess] = []
