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


import logging
from typing import Iterator

from capa.features.file import Export, Import, Section
from capa.features.common import String, Feature
from capa.features.address import NO_ADDRESS, Address, ThreadAddress, ProcessAddress, AbsoluteVirtualAddress
from capa.features.extractors.helpers import generate_symbols
from capa.features.extractors.ttd.models import TtdCall, TtdReport
from capa.features.extractors.base_extractor import ProcessHandle

logger = logging.getLogger(__name__)


def get_processes(
    report: TtdReport, calls: dict[ProcessAddress, dict[ThreadAddress, list[TtdCall]]]
) -> Iterator[ProcessHandle]:
    """
    Enumerate the processes recorded in the trace.
    """
    for process in report.processes:
        proc_addr = ProcessAddress(pid=process.pid, ppid=process.ppid)
        yield ProcessHandle(address=proc_addr, inner=process)


def extract_import_names(report: TtdReport) -> Iterator[tuple[Feature, Address]]:
    """
    Extract imported function names from the main module's import table.
    """
    for imp in report.file.imports:
        if not imp.name:
            continue
        for name in generate_symbols(imp.dll, imp.name, include_dll=True):
            yield Import(name), AbsoluteVirtualAddress(imp.va)


def extract_export_names(report: TtdReport) -> Iterator[tuple[Feature, Address]]:
    for exp in report.file.exports:
        if not exp.name:
            continue
        yield Export(exp.name), AbsoluteVirtualAddress(exp.va)


def extract_section_names(report: TtdReport) -> Iterator[tuple[Feature, Address]]:
    for section in report.file.sections:
        yield Section(section.name), AbsoluteVirtualAddress(section.va)


def extract_file_strings(report: TtdReport) -> Iterator[tuple[Feature, Address]]:
    for string in report.file.strings:
        yield String(string), NO_ADDRESS


def extract_features(report: TtdReport) -> Iterator[tuple[Feature, Address]]:
    for handler in FILE_HANDLERS:
        for feature, addr in handler(report):
            yield feature, addr


FILE_HANDLERS = (
    extract_import_names,
    extract_export_names,
    extract_section_names,
    extract_file_strings,
)
