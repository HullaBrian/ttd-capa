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

from capa.features.insn import API, Number
from capa.features.common import String, Feature
from capa.features.address import Address
from capa.features.extractors.helpers import generate_symbols
from capa.features.extractors.ttd.models import TtdCall
from capa.features.extractors.base_extractor import CallHandle, ThreadHandle, ProcessHandle

logger = logging.getLogger(__name__)


def extract_call_features(ph: ProcessHandle, th: ThreadHandle, ch: CallHandle) -> Iterator[tuple[Feature, Address]]:
    """
    Extract the given call's features (API name and arguments) as API, Number, and
    String features.

    yields:
      Feature, address; where Feature is either API, Number, or String.
    """
    call: TtdCall = ch.inner

    # list similar to disassembly: arguments right-to-left, call
    for arg in reversed(call.args):
        # note: bool is a subclass of int; the extractor never emits booleans, but
        # guard anyway so a stray JSON `true` doesn't become Number(1).
        if isinstance(arg, bool):
            continue
        elif isinstance(arg, int):
            yield Number(arg), ch.address
        elif isinstance(arg, str):
            yield String(arg), ch.address

    # over-generate API name variants (module.api, api, and A/W-trimmed forms) so
    # rules match regardless of whether they reference the DLL or the bare name.
    # only include the DLL prefix when we actually resolved a module, otherwise
    # generate_symbols would emit junk ".CreateFileA" variants.
    for name in generate_symbols(call.module, call.api, include_dll=bool(call.module)):
        yield API(name), ch.address


def extract_features(ph: ProcessHandle, th: ThreadHandle, ch: CallHandle) -> Iterator[tuple[Feature, Address]]:
    for handler in CALL_HANDLERS:
        for feature, addr in handler(ph, th, ch):
            yield feature, addr


CALL_HANDLERS = (extract_call_features,)
