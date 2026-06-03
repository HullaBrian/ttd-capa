#include "ttd_pe_utils.hpp"
#include "ttdutils.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <TTD/IdnaBasicTypes.h>
#include <TTD/IReplayEngineStl.h>

namespace ttdcapa {
namespace {

// Read a NUL-terminated ASCII string at a guest address (bounded).
std::string readCSTR(TTD::Replay::UniqueCursor* cursor, TTD::GuestAddress addr, size_t maxLength = 512) {
    std::string s;
    s.reserve(64);
    char chunk[64];
    while (s.size() < maxLength) {
        size_t want = sizeof(chunk);
        size_t got = readMemory(cursor, addr + s.size(), chunk, want);
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
bool readNTHeaders(TTD::Replay::UniqueCursor* cursor, TTD::GuestAddress moduleBaseAddress, IMAGE_NT_HEADERS64& nt) {
    IMAGE_DOS_HEADER dos{};
    if (!readMemory(cursor, moduleBaseAddress, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }
    if (!readMemory(cursor, moduleBaseAddress + static_cast<uint32_t>(dos.e_lfanew), &nt, sizeof(nt))) {
        return false;
    }
    if (nt.Signature != IMAGE_NT_SIGNATURE ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return false;
    }
    return true;
}

bool isPrintableASCII(unsigned char c) {
    return c == '\t' || (c >= 0x20 && c <= 0x7e);
}

}  // namespace

std::string getModuleBaseName(const std::wstring& full) {
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

bool getModuleExports(TTD::Replay::UniqueCursor* cursor, TTD::GuestAddress moduleBaseAddress, std::vector<std::pair<uint64_t, std::string>>& out) {
    IMAGE_NT_HEADERS64 nt{};
    if (!readNTHeaders(cursor, moduleBaseAddress, nt)) {
        return false;
    }

    const IMAGE_DATA_DIRECTORY& dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir.VirtualAddress == 0 || dir.Size == 0) {
        return true;  // valid PE, just no exports
    }

    IMAGE_EXPORT_DIRECTORY exp{};
    if (!readMemory(cursor, moduleBaseAddress + dir.VirtualAddress, &exp, sizeof(exp))) {
        return false;
    }

    const uint32_t dir_begin = dir.VirtualAddress;
    const uint32_t dir_end = dir.VirtualAddress + dir.Size;

    // Walk the name table; each name maps (via the ordinal table) to a function RVA.
    for (uint32_t i = 0; i < exp.NumberOfNames; ++i) {
        uint32_t name_rva = 0;
        if (!readMemory(cursor, moduleBaseAddress + exp.AddressOfNames + i * sizeof(uint32_t), &name_rva, sizeof(name_rva))) {
            break;
        }

        uint16_t ordinal = 0;
        if (!readMemory(cursor, moduleBaseAddress + exp.AddressOfNameOrdinals + i * sizeof(uint16_t), &ordinal, sizeof(ordinal))) {
            break;
        }

        if (ordinal >= exp.NumberOfFunctions) {
            continue;
        }

        uint32_t func_rva = 0;
        if (!readMemory(cursor, moduleBaseAddress + exp.AddressOfFunctions + ordinal * sizeof(uint32_t), &func_rva, sizeof(func_rva))) {
            continue;
        }

        if (func_rva == 0) {
            continue;
        }

        // Skip forwarded exports
        if (func_rva >= dir_begin && func_rva < dir_end) {
            continue;
        }

        std::string name = readCSTR(cursor, moduleBaseAddress + name_rva);

        // Skip empty export names (possibly due to error in parsing name)
        if (name.empty()) {
            continue;
        }

        out.emplace_back((uint64_t)(moduleBaseAddress + func_rva), std::move(name));
    }
    return true;
}

bool getModuleImports(TTD::Replay::UniqueCursor* cursor, TTD::GuestAddress moduleBaseAddress, std::vector<ImportRecord>& out) {
    IMAGE_NT_HEADERS64 nt{};

    if (!readNTHeaders(cursor, moduleBaseAddress, nt)) {
        return false;
    }

    const IMAGE_DATA_DIRECTORY& dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir.VirtualAddress == 0 || dir.Size == 0) {
        return true;
    }

    for (uint32_t idx = 0;; ++idx) {
        IMAGE_IMPORT_DESCRIPTOR desc{};

        if (!readMemory(cursor, moduleBaseAddress + dir.VirtualAddress + idx * sizeof(IMAGE_IMPORT_DESCRIPTOR), &desc, sizeof(desc))) {
            break;
        }

        if (desc.Name == 0 && desc.FirstThunk == 0) {
            break;  // null terminator
        }

        std::string dll = readCSTR(cursor, moduleBaseAddress + desc.Name, 128);

        // OriginalFirstThunk (the import name table) survives binding; fall back to
        // FirstThunk if it is absent.
        uint32_t int_rva = desc.OriginalFirstThunk ? desc.OriginalFirstThunk : desc.FirstThunk;
        uint32_t iat_rva = desc.FirstThunk;
        if (int_rva == 0) {
            continue;
        }

        for (uint32_t t = 0;; ++t) {
            uint64_t thunk = 0;
            if (!readMemory(cursor, moduleBaseAddress + int_rva + t * sizeof(uint64_t), &thunk, sizeof(thunk)) || thunk == 0) {
                break;
            }

            TTD::GuestAddress slot_va = moduleBaseAddress + iat_rva + t * sizeof(uint64_t);

            if (thunk & IMAGE_ORDINAL_FLAG64) {
                // import by ordinal: no name to match against; record a synthetic name
                ImportRecord rec;
                rec.dll = dll;
                rec.name = "#" + std::to_string(static_cast<uint16_t>(thunk & 0xffff));
                rec.va = slot_va;
                out.push_back(std::move(rec));
            } else {
                // import by name: thunk -> IMAGE_IMPORT_BY_NAME { WORD Hint; CHAR Name[]; }
                std::string name = readCSTR(cursor, moduleBaseAddress + (thunk & 0x7fffffff) + sizeof(uint16_t));
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

bool getModuleSections(TTD::Replay::UniqueCursor* cursor, TTD::GuestAddress moduleBaseAddress, std::vector<SectionRecord>& out) {
    IMAGE_NT_HEADERS64 nt{};

    if (!readNTHeaders(cursor, moduleBaseAddress, nt)) {
        return false;
    }

    IMAGE_DOS_HEADER dos{};
    if (!readMemory(cursor, moduleBaseAddress, &dos, sizeof(dos))) {
        return false;
    }
    // section headers follow the optional header
    TTD::GuestAddress sect_va = moduleBaseAddress + dos.e_lfanew + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + nt.FileHeader.SizeOfOptionalHeader;

    for (uint16_t i = 0; i < nt.FileHeader.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER sh{};

        if (!readMemory(cursor, sect_va + i * sizeof(IMAGE_SECTION_HEADER), &sh, sizeof(sh))) {
            break;
        }

        char name[IMAGE_SIZEOF_SHORT_NAME + 1] = {0};
        std::memcpy(name, sh.Name, IMAGE_SIZEOF_SHORT_NAME);
        SectionRecord rec;
        rec.name = name;
        rec.va = moduleBaseAddress + sh.VirtualAddress;
        out.push_back(std::move(rec));
    }
    return true;
}

bool getModuleStrings(TTD::Replay::UniqueCursor* cursor, TTD::GuestAddress moduleBaseAddress, std::vector<std::string>& out, size_t minLength, size_t maxStrings) {
    IMAGE_NT_HEADERS64 nt{};

    if (!readNTHeaders(cursor, moduleBaseAddress, nt)) {
        return false;
    }

    IMAGE_DOS_HEADER dos{};
    if (!readMemory(cursor, moduleBaseAddress, &dos, sizeof(dos))) {
        return false;
    }

    TTD::GuestAddress sect_va = moduleBaseAddress + dos.e_lfanew + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + nt.FileHeader.SizeOfOptionalHeader;

    for (uint16_t i = 0; i < nt.FileHeader.NumberOfSections && out.size() < maxStrings; ++i) {
        IMAGE_SECTION_HEADER sh{};
        if (!readMemory(cursor, sect_va + i * sizeof(IMAGE_SECTION_HEADER), &sh, sizeof(sh))) {
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
        size_t got = readMemory(cursor, moduleBaseAddress + sh.VirtualAddress, buf.data(), buf.size());
        if (got == 0) {
            continue;
        }

        buf.resize(got);

        // ASCII runs
        std::string cur;
        for (size_t p = 0; p < buf.size() && out.size() < maxStrings; ++p) {
            if (isPrintableASCII(buf[p])) {
                cur.push_back(static_cast<char>(buf[p]));
            } else {
                if (cur.size() >= minLength) {
                    out.push_back(cur);
                }
                cur.clear();
            }
        }

        if (cur.size() >= minLength && out.size() < maxStrings) {
            out.push_back(cur);
        }

        // UTF-16LE runs (printable ASCII char followed by 0x00)
        cur.clear();
        for (size_t p = 0; p + 1 < buf.size() && out.size() < maxStrings; p += 2) {
            if (buf[p + 1] == 0 && isPrintableASCII(buf[p])) {
                cur.push_back(static_cast<char>(buf[p]));
            } else {
                if (cur.size() >= minLength) {
                    out.push_back(cur);
                }
                cur.clear();
            }
        }

        if (cur.size() >= minLength && out.size() < maxStrings) {
            out.push_back(cur);
        }
    }
    return true;
}

}  // namespace ttdcapa
