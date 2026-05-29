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

#include "guest_pe.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace ttdcapa {
namespace {

// Read a trivially-copyable value at a guest address. Returns false if the full
// object could not be read.
template <typename T>
bool read_obj(const GuestReader& read, uint64_t addr, T& out) {
    return read(addr, &out, sizeof(T)) == sizeof(T);
}

// Read a NUL-terminated ASCII string at a guest address (bounded).
std::string read_cstr(const GuestReader& read, uint64_t addr, size_t max_len = 512) {
    std::string s;
    s.reserve(64);
    char chunk[64];
    while (s.size() < max_len) {
        size_t want = sizeof(chunk);
        size_t got = read(addr + s.size(), chunk, want);
        if (got == 0) {
            break;
        }
        for (size_t i = 0; i < got; ++i) {
            if (chunk[i] == '\0') {
                return s;
            }
            s.push_back(chunk[i]);
        }
        if (got < want) {
            break;
        }
    }
    return s;
}

// Locate the NT headers for the image at `base`. Returns the file-relative offset
// of the NT headers (e_lfanew) and validates the PE/PE32+ signatures.
bool read_nt_headers(const GuestReader& read, uint64_t base, IMAGE_NT_HEADERS64& nt) {
    IMAGE_DOS_HEADER dos{};
    if (!read_obj(read, base, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }
    if (!read_obj(read, base + static_cast<uint32_t>(dos.e_lfanew), nt)) {
        return false;
    }
    if (nt.Signature != IMAGE_NT_SIGNATURE ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return false;
    }
    return true;
}

bool is_printable_ascii(unsigned char c) {
    return c == '\t' || (c >= 0x20 && c <= 0x7e);
}

}  // namespace

std::string module_basename(const std::wstring& full) {
    size_t slash = full.find_last_of(L"\\/");
    std::wstring name = (slash == std::wstring::npos) ? full : full.substr(slash + 1);
    size_t dot = name.find_last_of(L'.');
    if (dot != std::wstring::npos) {
        name = name.substr(0, dot);
    }
    // narrow ASCII-only module name
    std::string out;
    out.reserve(name.size());
    for (wchar_t wc : name) {
        out.push_back(static_cast<char>(wc & 0x7f));
    }
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

bool parse_exports(const GuestReader& read, uint64_t base, const std::string& /*module_name*/,
                   std::vector<std::pair<uint64_t, std::string>>& out) {
    IMAGE_NT_HEADERS64 nt{};
    if (!read_nt_headers(read, base, nt)) {
        return false;
    }

    const IMAGE_DATA_DIRECTORY& dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir.VirtualAddress == 0 || dir.Size == 0) {
        return true;  // valid PE, just no exports
    }

    IMAGE_EXPORT_DIRECTORY exp{};
    if (!read_obj(read, base + dir.VirtualAddress, exp)) {
        return false;
    }

    const uint32_t dir_begin = dir.VirtualAddress;
    const uint32_t dir_end = dir.VirtualAddress + dir.Size;

    // Walk the name table; each name maps (via the ordinal table) to a function RVA.
    for (uint32_t i = 0; i < exp.NumberOfNames; ++i) {
        uint32_t name_rva = 0;
        if (!read_obj(read, base + exp.AddressOfNames + i * sizeof(uint32_t), name_rva)) {
            break;
        }
        uint16_t ordinal = 0;
        if (!read_obj(read, base + exp.AddressOfNameOrdinals + i * sizeof(uint16_t), ordinal)) {
            break;
        }
        if (ordinal >= exp.NumberOfFunctions) {
            continue;
        }
        uint32_t func_rva = 0;
        if (!read_obj(read, base + exp.AddressOfFunctions + ordinal * sizeof(uint32_t), func_rva)) {
            continue;
        }
        if (func_rva == 0) {
            continue;
        }
        // A function RVA pointing back into the export directory is a forwarder
        // ("OTHERDLL.Func") rather than real code; calls land on the forwarded
        // target, so these never match a CALL site. Skip them.
        if (func_rva >= dir_begin && func_rva < dir_end) {
            continue;
        }
        std::string name = read_cstr(read, base + name_rva);
        if (name.empty()) {
            continue;
        }
        out.emplace_back(base + func_rva, std::move(name));
    }
    return true;
}

bool parse_imports(const GuestReader& read, uint64_t base, std::vector<ImportRecord>& out) {
    IMAGE_NT_HEADERS64 nt{};
    if (!read_nt_headers(read, base, nt)) {
        return false;
    }

    const IMAGE_DATA_DIRECTORY& dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir.VirtualAddress == 0 || dir.Size == 0) {
        return true;
    }

    for (uint32_t idx = 0;; ++idx) {
        IMAGE_IMPORT_DESCRIPTOR desc{};
        if (!read_obj(read, base + dir.VirtualAddress + idx * sizeof(IMAGE_IMPORT_DESCRIPTOR),
                      desc)) {
            break;
        }
        if (desc.Name == 0 && desc.FirstThunk == 0) {
            break;  // null terminator
        }
        std::string dll = read_cstr(read, base + desc.Name, 128);

        // OriginalFirstThunk (the import name table) survives binding; fall back to
        // FirstThunk if it is absent.
        uint32_t int_rva = desc.OriginalFirstThunk ? desc.OriginalFirstThunk : desc.FirstThunk;
        uint32_t iat_rva = desc.FirstThunk;
        if (int_rva == 0) {
            continue;
        }

        for (uint32_t t = 0;; ++t) {
            uint64_t thunk = 0;
            if (!read_obj(read, base + int_rva + t * sizeof(uint64_t), thunk) || thunk == 0) {
                break;
            }
            uint64_t slot_va = base + iat_rva + t * sizeof(uint64_t);
            if (thunk & IMAGE_ORDINAL_FLAG64) {
                // import by ordinal: no name to match against; record a synthetic name
                ImportRecord rec;
                rec.dll = dll;
                rec.name = "#" + std::to_string(static_cast<uint16_t>(thunk & 0xffff));
                rec.va = slot_va;
                out.push_back(std::move(rec));
            } else {
                // import by name: thunk -> IMAGE_IMPORT_BY_NAME { WORD Hint; CHAR Name[]; }
                std::string name = read_cstr(read, base + (thunk & 0x7fffffff) + sizeof(uint16_t));
                if (!name.empty()) {
                    ImportRecord rec;
                    rec.dll = dll;
                    rec.name = std::move(name);
                    rec.va = slot_va;
                    out.push_back(std::move(rec));
                }
            }
        }
    }
    return true;
}

bool parse_sections(const GuestReader& read, uint64_t base, std::vector<SectionRecord>& out) {
    IMAGE_NT_HEADERS64 nt{};
    if (!read_nt_headers(read, base, nt)) {
        return false;
    }

    IMAGE_DOS_HEADER dos{};
    if (!read_obj(read, base, dos)) {
        return false;
    }
    // section headers follow the optional header
    uint64_t sect_va = base + dos.e_lfanew + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
                       nt.FileHeader.SizeOfOptionalHeader;

    for (uint16_t i = 0; i < nt.FileHeader.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER sh{};
        if (!read_obj(read, sect_va + i * sizeof(IMAGE_SECTION_HEADER), sh)) {
            break;
        }
        char name[IMAGE_SIZEOF_SHORT_NAME + 1] = {0};
        std::memcpy(name, sh.Name, IMAGE_SIZEOF_SHORT_NAME);
        SectionRecord rec;
        rec.name = name;
        rec.va = base + sh.VirtualAddress;
        out.push_back(std::move(rec));
    }
    return true;
}

bool recover_strings(const GuestReader& read, uint64_t base, std::vector<std::string>& out,
                     size_t min_len, size_t max_strings) {
    IMAGE_NT_HEADERS64 nt{};
    if (!read_nt_headers(read, base, nt)) {
        return false;
    }
    IMAGE_DOS_HEADER dos{};
    if (!read_obj(read, base, dos)) {
        return false;
    }
    uint64_t sect_va = base + dos.e_lfanew + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
                       nt.FileHeader.SizeOfOptionalHeader;

    for (uint16_t i = 0; i < nt.FileHeader.NumberOfSections && out.size() < max_strings; ++i) {
        IMAGE_SECTION_HEADER sh{};
        if (!read_obj(read, sect_va + i * sizeof(IMAGE_SECTION_HEADER), sh)) {
            break;
        }
        // executable code sections are mostly noise for string recovery; skip them
        if (sh.Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            continue;
        }
        uint32_t vsize = sh.Misc.VirtualSize ? sh.Misc.VirtualSize : sh.SizeOfRawData;
        if (vsize == 0 || vsize > 64 * 1024 * 1024) {
            continue;
        }

        std::vector<uint8_t> buf(vsize);
        size_t got = read(base + sh.VirtualAddress, buf.data(), buf.size());
        if (got == 0) {
            continue;
        }
        buf.resize(got);

        // ASCII runs
        std::string cur;
        for (size_t p = 0; p < buf.size() && out.size() < max_strings; ++p) {
            if (is_printable_ascii(buf[p])) {
                cur.push_back(static_cast<char>(buf[p]));
            } else {
                if (cur.size() >= min_len) {
                    out.push_back(cur);
                }
                cur.clear();
            }
        }
        if (cur.size() >= min_len && out.size() < max_strings) {
            out.push_back(cur);
        }

        // UTF-16LE runs (printable ASCII char followed by 0x00)
        cur.clear();
        for (size_t p = 0; p + 1 < buf.size() && out.size() < max_strings; p += 2) {
            if (buf[p + 1] == 0 && is_printable_ascii(buf[p])) {
                cur.push_back(static_cast<char>(buf[p]));
            } else {
                if (cur.size() >= min_len) {
                    out.push_back(cur);
                }
                cur.clear();
            }
        }
        if (cur.size() >= min_len && out.size() < max_strings) {
            out.push_back(cur);
        }
    }
    return true;
}

}  // namespace ttdcapa
