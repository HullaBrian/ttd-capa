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

from capa.features.common import (
    OS,
    OS_LINUX,
    ARCH_I386,
    FORMAT_PE,
    ARCH_AMD64,
    OS_WINDOWS,
    Arch,
    Format,
    Feature,
)
from capa.features.address import NO_ADDRESS, Address
from capa.features.extractors.ttd.models import TtdReport

logger = logging.getLogger(__name__)


def extract_format(report: TtdReport) -> Iterator[tuple[Feature, Address]]:
    # TTD records native Windows processes; the recorded sample is a PE.
    yield Format(FORMAT_PE), NO_ADDRESS


def extract_os(report: TtdReport) -> Iterator[tuple[Feature, Address]]:
    os = report.trace.os.lower()
    if os == OS_LINUX:
        yield OS(OS_LINUX), NO_ADDRESS
    else:
        # TTD is a Windows facility; default to Windows.
        yield OS(OS_WINDOWS), NO_ADDRESS


def extract_arch(report: TtdReport) -> Iterator[tuple[Feature, Address]]:
    arch = report.trace.arch.lower()
    if arch in ("x86", "i386", "32"):
        yield Arch(ARCH_I386), NO_ADDRESS
    else:
        # x64 / amd64 is the v1 target.
        yield Arch(ARCH_AMD64), NO_ADDRESS


def extract_features(report: TtdReport) -> Iterator[tuple[Feature, Address]]:
    for global_handler in GLOBAL_HANDLER:
        for feature, addr in global_handler(report):
            yield feature, addr


GLOBAL_HANDLER = (
    extract_format,
    extract_os,
    extract_arch,
)
