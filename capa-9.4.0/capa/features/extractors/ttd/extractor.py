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
from typing import Union, Iterator

import capa.features.extractors.ttd.call
import capa.features.extractors.ttd.file
import capa.features.extractors.ttd.thread
import capa.features.extractors.ttd.global_
import capa.features.extractors.ttd.process
from capa.features.common import Feature
from capa.features.address import NO_ADDRESS, Address, ThreadAddress, ProcessAddress, AbsoluteVirtualAddress, _NoAddress
from capa.features.extractors.ttd.models import TtdCall, TtdReport
from capa.features.extractors.ttd.helpers import index_calls
from capa.features.extractors.base_extractor import (
    CallHandle,
    SampleHashes,
    ThreadHandle,
    ProcessHandle,
    DynamicFeatureExtractor,
)

logger = logging.getLogger(__name__)

CURRENT_VERSION = 1


class TtdExtractor(DynamicFeatureExtractor):
    def __init__(self, report: TtdReport):
        super().__init__(
            hashes=SampleHashes(
                md5=report.sample.md5,
                sha1=report.sample.sha1,
                sha256=report.sample.sha256,
            )
        )

        self.report: TtdReport = report

        # organize calls per process/thread, sorted by trace position, so that each
        # call is addressable by index (DynamicCallAddress requires a call index).
        self.sorted_calls: dict[ProcessAddress, dict[ThreadAddress, list[TtdCall]]] = index_calls(report)

        # pre-compute these because we'll yield them at *every* scope.
        self.global_features = list(capa.features.extractors.ttd.global_.extract_features(self.report))

    def get_base_address(self) -> Union[AbsoluteVirtualAddress, _NoAddress, None]:
        # the trace records a live process; there is no single static base address.
        return NO_ADDRESS

    def extract_global_features(self) -> Iterator[tuple[Feature, Address]]:
        yield from self.global_features

    def extract_file_features(self) -> Iterator[tuple[Feature, Address]]:
        yield from capa.features.extractors.ttd.file.extract_features(self.report)

    def get_processes(self) -> Iterator[ProcessHandle]:
        yield from capa.features.extractors.ttd.file.get_processes(self.report, self.sorted_calls)

    def extract_process_features(self, ph: ProcessHandle) -> Iterator[tuple[Feature, Address]]:
        yield from capa.features.extractors.ttd.process.extract_features(ph)

    def get_process_name(self, ph: ProcessHandle) -> str:
        return ph.inner.name

    def get_threads(self, ph: ProcessHandle) -> Iterator[ThreadHandle]:
        yield from capa.features.extractors.ttd.process.get_threads(self.sorted_calls, ph)

    def extract_thread_features(self, ph: ProcessHandle, th: ThreadHandle) -> Iterator[tuple[Feature, Address]]:
        yield from []

    def get_calls(self, ph: ProcessHandle, th: ThreadHandle) -> Iterator[CallHandle]:
        yield from capa.features.extractors.ttd.thread.get_calls(self.sorted_calls, ph, th)

    def get_call_name(self, ph: ProcessHandle, th: ThreadHandle, ch: CallHandle) -> str:
        call: TtdCall = ch.inner
        api = f"{call.module}.{call.api}" if call.module else call.api
        arguments = ", ".join(repr(arg) for arg in call.args)
        ret = "" if call.ret is None else f" -> 0x{call.ret:x}"
        # surface the navigable TTD position so the analyst can jump to the call in
        # WinDbg (paste "Sequence:Steps" into the position box or use `!tt Seq:Steps`).
        pos = f" @TTD {call.position}" if call.position else ""
        return f"{api}({arguments}){ret}{pos}"

    def extract_call_features(
        self, ph: ProcessHandle, th: ThreadHandle, ch: CallHandle
    ) -> Iterator[tuple[Feature, Address]]:
        yield from capa.features.extractors.ttd.call.extract_features(ph, th, ch)

    @classmethod
    def from_report(cls, report: dict) -> "TtdExtractor":
        tr = TtdReport.model_validate(report)

        if tr.version != CURRENT_VERSION:
            logger.warning(
                "TTD report version '%s' does not match supported version '%s'; results may be incomplete",
                tr.version,
                CURRENT_VERSION,
            )

        return cls(report=tr)
