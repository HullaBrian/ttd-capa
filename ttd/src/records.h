// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

// Plain-old-data records shared between the PE parser, the call sweep, and the
// JSON emitter. These mirror the fields of the neutral "TTD report" schema in
// capa/features/extractors/ttd/models.py.
#pragma once

#include <cstdint>
#include <string>
#include <variant>
#include <vector>

namespace ttdcapa {

struct ImportRecord {
    std::string dll;
    std::string name;
    uint64_t va = 0;
};

struct ExportRecord {
    std::string name;
    uint64_t va = 0;
};

struct SectionRecord {
    std::string name;
    uint64_t va = 0;
};

// One call argument: either an integer (Number) or a dereferenced string (String).
using ArgValue = std::variant<int64_t, std::string>;

struct CallRecord {
    uint64_t tid = 0;   // TTD UniqueThreadId
    uint64_t seq = 0;   // monotonic record order (consistent with timeline order)
    std::string module; // resolved owning module, e.g. "kernel32" (no extension)
    std::string api;    // resolved export name, e.g. "CreateFileA"
    std::vector<ArgValue> args;
    bool has_ret = false;
    uint64_t ret = 0;
};

struct ProcessRecord {
    uint64_t pid = 0;
    uint64_t ppid = 0;
    std::string name;
    // note: not named "environ" — that is a macro in MSVC's UCRT <stdlib.h>,
    // which would mangle any `record.environ` member access.
    std::vector<std::string> env_strings;
    std::vector<uint64_t> threads;  // TTD UniqueThreadIds
    std::vector<CallRecord> calls;
};

// A loaded module's address range plus the export name for each exported address,
// used to resolve a CALL target to module.api.
struct ModuleExports {
    std::string name;  // module name without extension, e.g. "kernel32"
    uint64_t base = 0;
    uint64_t size = 0;
    // exported function VA -> export name
    std::vector<std::pair<uint64_t, std::string>> exports;
};

}  // namespace ttdcapa
