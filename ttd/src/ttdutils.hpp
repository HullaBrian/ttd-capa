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

    struct CallRecord {
        uint64_t tid = 0;            // TTD Thread ID
        uint64_t seq = 0;            // monotonic record order (consistent with timeline order)
        std::string position;        // TTD navigable position "Sequence:Steps" (hex), for WinDbg
        std::wstring module;         // resolved owning module, e.g. "kernel32" (no extension)
        std::string api;             // resolved export name, e.g. "CreateFileA"
        std::vector<ArgValue> args;
        bool has_ret = false;
        uint64_t ret = 0;
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

    // Navigates all module load events, and returns a map of all function VAs along with their associated module and function name
    std::unordered_map<uint64_t, std::pair<std::wstring, std::string>> resolveTraceModuleExports(TTD::Replay::UniqueReplayEngine& engine, TTD::Replay::UniqueCursor& cursor);

    // TTD memory read utility function
    size_t readMemory(TTD::Replay::UniqueCursor* cursor, TTD::GuestAddress addr, void* dest, unsigned __int64 size);

    // Initializes the TTD engine based off a given trace file (.run) path
    bool initializeTTDEngine(TTD::Replay::UniqueReplayEngine& engine, std::wstring trace_file_path);

    // Attempts to interpret the memory at a certain address as a string. If not a string, will return null
    std::optional<std::string> tryReadString(TTD::Replay::IThreadView const* thread, uint64_t addr);

    // Attempts to capture an argument as a string. If it doesn't look like a valid string, this function will return the same argument value
    ArgValue captureCallArg(TTD::Replay::IThreadView const* thread, uint64_t value);
}

#endif