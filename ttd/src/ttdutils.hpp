#ifndef TTDUITLS_HPP
#define TTDUITLS_HPP

#include <windows.h>
#include <iostream>
#include <cstdint>
#include <optional>
#include <unordered_map>
#include <string>
#include <variant>
#include <vector>

#include <TTD/IReplayEngine.h>
#include <TTD/IReplayEngineStl.h>
#include <TTD/ErrorReporting.h>

#include "win32meta.hpp"

class ConsoleErrorReporting : public TTD::ErrorReporting {
public:
    void __fastcall VPrintError(char const* fmt, va_list args) override {
        char buf[2048];
        vsnprintf(buf, sizeof(buf), fmt, args);
        std::cerr << "[-][TTD SDK] " << buf << "\n";
    }
};

namespace ttdcapa {
    struct ImportRecord {
        std::string dll;
        std::string name;
        TTD::GuestAddress va;
    };

    struct ExportRecord {
        std::string name;
        TTD::GuestAddress va;
    };

    struct SectionRecord {
        std::string name;
        TTD::GuestAddress va;
    };

    // One call argument: either an integer or a dereferenced string
    using ArgValue = std::variant<int64_t, std::string>;

    // One parameter decoded with the help of the Win32 metadata index. `name` and
    // `type` point into the index blob, which outlives every record, so they cost
    // nothing to copy. Enum values keep their index rather than their decoded flag
    // names so millions of in-memory calls stay cheap; names are resolved once at
    // report-write time.
    struct DecodedArg {
        const char* name = nullptr;
        const char* type = nullptr;
        win32meta::ArgKind kind = win32meta::ArgKind::Unknown;
        uint32_t enum_index = 0xFFFFFFFFu;
        uint64_t raw = 0;             // the register/stack value as captured
        uint64_t deref = 0;           // pointee, for PtrToInt and friends
        double fval = 0.0;            // for Float/Double params (read from XMM)
        std::string str;              // decoded string contents
        std::vector<uint8_t> bytes;   // bounded buffer preview
        uint64_t bytes_total = 0;     // the buffer's real length, when `bytes` is only a prefix
        bool bytes_capped = false;    // --max-buffer cut the capture short
        bool has_str = false;
        bool has_deref = false;
        bool has_fval = false;
        bool is_out = false;
        bool from_return = false;     // contents were read at the return position
    };

    // A dereference deferred until the call returns, so [Out] parameters can be
    // rendered filled in -- something only a time-travel trace makes easy.
    struct PendingOut {
        uint16_t param_index = 0;
        win32meta::ArgKind kind = win32meta::ArgKind::Unknown;
        uint64_t ptr = 0;
        uint16_t pointee_size = 0;
        win32meta::AuxKind aux_kind = win32meta::AuxKind::None;
        int32_t aux_value = 0;
        uint64_t in_cap = 0;  // caller-supplied upper bound on length, 0 if unknown
    };

    struct CallRecord {
        uint64_t tid = 0;            // TTD Thread ID
        uint64_t seq = 0;            // monotonic record order (consistent with timeline order)
        std::string position;        // TTD navigable position "Sequence:Steps" (hex), for WinDbg
        std::wstring module;         // resolved owning module, e.g. "kernel32" (no extension)
        std::string api;             // resolved export name, e.g. "CreateFileA"
        std::vector<ArgValue> args;      // flat view consumed by capa (ints and strings)
        std::vector<DecodedArg> params;  // rich view; only meaningful when `metadata` is set
        bool metadata = false;           // args came from a real signature, not the heuristic
        bool has_ret = false;
        uint64_t ret = 0;
        // Where the callee will return to, i.e. the instruction after the CALL. Identifies
        // the call site, which is what tells you who in the sample made the call. The
        // replay engine hands this to the callback already, so recording it is free.
        uint64_t return_address = 0;
    };

    struct ProcessRecord {
        uint64_t pid = 0;
        uint64_t ppid = 0;
        std::string name;
        std::vector<std::string> env_strings;
        std::vector<uint64_t> threads;         // TTD UniqueThreadIds
        std::vector<CallRecord> calls;
    };

    // A loaded module's address range plus the export name for each exported address,
    // used to resolve a CALL target to module.api.
    struct ModuleExports {
        std::string name;                                       // module name without extension, something like "kernel32"
        TTD::GuestAddress base;
        uint64_t size = 0;
        std::vector<std::pair<uint64_t, std::string>> exports;  // exported function VA -> export name
    };

    // One resolved call target: which module it belongs to, its export name, and the
    // bitness of that module. The bitness is per module rather than per trace because
    // a WoW64 process runs 32-bit and 64-bit code side by side, and it decides which
    // calling convention the call's arguments follow.
    struct ResolvedExport {
        std::wstring module;
        std::string api;
        bool is64 = true;
    };

    // Navigates all module load events, and returns a map of all function VAs along with their associated module and function name
    std::unordered_map<uint64_t, ResolvedExport> resolveTraceModuleExports(TTD::Replay::UniqueReplayEngine& engine, TTD::Replay::UniqueCursor& cursor);

    // TTD memory read utility function
    size_t readMemory(TTD::Replay::UniqueCursor* cursor, TTD::GuestAddress addr, void* dest, unsigned __int64 size);

    // UTF-16 -> UTF-8, for the wide strings TTD and the PE headers hand back
    std::string convertWstringToString(const std::wstring& ws);

    // Initializes the TTD engine based off a given trace file (.run) path
    bool initializeTTDEngine(TTD::Replay::UniqueReplayEngine& engine, std::wstring trace_file_path);

    // Attempts to interpret the memory at a certain address as a string. If not a string, will return null
    std::optional<std::string> tryReadString(TTD::Replay::IThreadView const* thread, uint64_t addr);

    // Read a NUL-terminated string the metadata told us is really there. Unlike
    // tryReadString these do not guess: no minimum length, and the wide reader
    // converts real UTF-16 (not just its ASCII subset) to UTF-8. Returns nullopt
    // only when the memory is unreadable or the bytes aren't a plausible string.
    std::optional<std::string> readAnsiString(TTD::Replay::IThreadView const* thread, uint64_t addr, size_t maxChars = 512);
    std::optional<std::string> readWideString(TTD::Replay::IThreadView const* thread, uint64_t addr, size_t maxChars = 512);

    // Attempts to capture an argument as a string. If it doesn't look like a valid string, this function will return the same argument value
    ArgValue captureCallArg(TTD::Replay::IThreadView const* thread, uint64_t value);
}

#endif