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


from capa.features.address import ThreadAddress, ProcessAddress
from capa.features.extractors.ttd.models import TtdCall, TtdReport


def index_calls(report: TtdReport) -> dict[ProcessAddress, dict[ThreadAddress, list[TtdCall]]]:
    """
    Organize calls into processes and threads, sorted by trace position (seq) so
    that each call is addressable by index (DynamicCallAddress requires a call index).

    Threads that executed no recorded API calls are still represented (with an
    empty list) so that they appear in the process/thread layout.
    """
    result: dict[ProcessAddress, dict[ThreadAddress, list[TtdCall]]] = {}

    for process in report.processes:
        proc_addr = ProcessAddress(pid=process.pid, ppid=process.ppid)
        threads = result.setdefault(proc_addr, {})

        # seed every declared thread so threads with no calls are still visible
        for tid in process.threads:
            threads.setdefault(ThreadAddress(process=proc_addr, tid=tid), [])

        for call in process.calls:
            thread_addr = ThreadAddress(process=proc_addr, tid=call.tid)
            threads.setdefault(thread_addr, []).append(call)

    for threads in result.values():
        for calls in threads.values():
            calls.sort(key=lambda call: call.seq)

    return result
