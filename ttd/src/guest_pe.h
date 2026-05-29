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

// Parse PE structures (exports, imports, sections, strings) directly out of a
// guest process image, reading bytes through a caller-supplied reader. The reader
// is backed by TTD's QueryMemoryBuffer so we see the image exactly as it was
// mapped in the recorded process (ASLR-relocated, IAT-resolved).
#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "records.h"

namespace ttdcapa {

// Read `size` bytes of guest virtual memory at `addr` into `dst`.
// Returns the number of bytes actually available/read (may be < size).
using GuestReader = std::function<size_t(uint64_t addr, void* dst, size_t size)>;

// Parse the export directory of the PE image mapped at `base`. Appends one entry
// per named export (forwarders are skipped). Returns false if `base` is not a
// readable PE32+ image at this position.
bool parse_exports(const GuestReader& read, uint64_t base, const std::string& module_name,
                   std::vector<std::pair<uint64_t, std::string>>& out);

// Parse the import directory of the PE image mapped at `base`.
bool parse_imports(const GuestReader& read, uint64_t base, std::vector<ImportRecord>& out);

// Parse the section table of the PE image mapped at `base`.
bool parse_sections(const GuestReader& read, uint64_t base, std::vector<SectionRecord>& out);

// Recover ASCII and UTF-16LE strings (length >= min_len) from the image's mapped
// sections. Caps output at `max_strings` to keep the report bounded.
bool recover_strings(const GuestReader& read, uint64_t base, std::vector<std::string>& out,
                     size_t min_len = 5, size_t max_strings = 2000);

// Strip a path/extension from a module name: "C:\\...\\kernel32.dll" -> "kernel32".
std::string module_basename(const std::wstring& full);

}  // namespace ttdcapa
