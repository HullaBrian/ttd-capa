#include "ttdutils.hpp"
#include "utils.hpp"
#include "ttd_pe_utils.hpp"

#include <cstdint>
#include <iostream>
#include <format>
#include <string>
#include <optional>
#include <winerror.h>
#include <unordered_map>
#include <map>
#include <ranges>

#include <TTD/IReplayEngineStl.h>
#include <TTD/IReplayEngineRegisters.h>
#include <TTD/ErrorReporting.h>

extern ttdcapa::Report g_report;

namespace ttdcapa {
    std::unordered_map<uint64_t, std::pair<std::wstring, std::string>> resolveTraceModuleExports(TTD::Replay::UniqueReplayEngine& engine, TTD::Replay::UniqueCursor& cursor) {
        std::unordered_map<uint64_t, std::pair<std::wstring, std::string>> resolvedTraceModuleExports;  // function VA -> (module, api)

        size_t count = engine->GetModuleLoadedEventCount();
        TTD::Replay::ModuleLoadedEvent const* moduleLoadEvents = engine->GetModuleLoadedEventList();
        cursor->SetPosition(engine->GetFirstPosition());

        for (size_t i = 0; i < count; i++) {
            TTD::Replay::ModuleLoadedEvent const& moduleLoadEvent = moduleLoadEvents[i];

            // std::wcout << std::format(L"[+] Found module: {}\n", moduleLoadEvent.pModule->pName);
            cursor->SetPosition(moduleLoadEvent.Position);

            // walk module exports
            std::wstring moduleName(moduleLoadEvent.pModule->pName, moduleLoadEvent.pModule->NameLength);
            std::string moduleBaseName = getModuleBaseName(moduleName);
            std::wstring moduleNameStripped(moduleBaseName.begin(), moduleBaseName.end());

            std::vector<std::pair<uint64_t, std::string>> moduleExports;
            if (getModuleExports(&cursor, moduleLoadEvent.pModule->Address, moduleExports)) {
                for (auto& moduleExport : moduleExports) {
                    resolvedTraceModuleExports.emplace(moduleExport.first, std::make_pair(moduleNameStripped, std::move(moduleExport.second)));
                }
            }
        }

        return resolvedTraceModuleExports;
    }

    size_t readMemory(TTD::Replay::UniqueCursor* cursor, TTD::GuestAddress addr, void* dest, unsigned __int64 size) {
        TTD::Replay::MemoryBuffer memoryBuffer = cursor->get()->QueryMemoryBuffer(addr, TTD::BufferView{ dest, size });
        return memoryBuffer.Memory.Size;
    }

    bool initializeTTDEngine(TTD::Replay::UniqueReplayEngine& engine, std::wstring traceFilePath) {
        ConsoleErrorReporting reporter;
        engine->RegisterDebugModeAndLogging(TTD::Replay::DebugModeType::None, &reporter);

        if (!engine->Initialize(traceFilePath.c_str())) {
            std::wcerr << L"[-] Failed to open trace: " << traceFilePath.c_str() << std::endl;
            return false;
        }

        if (engine->GetIndexStatus() != TTD::Replay::IndexStatus::IndexFileLoaded) {
            std::cerr << "[+] Building index (first run may be slow)...\n";
            auto progress = [](void const*, TTD::Replay::IndexBuildProgressType const* d) noexcept -> void {
                if (d->KeyframeCount > 0) {
                    std::cerr << "\r" << (d->KeyframesProcessed * 100 / d->KeyframeCount) << "%   ";
                }
            };
            engine->BuildIndex(progress, nullptr, TTD::Replay::IndexBuildFlags::None);
            std::cerr << "\n";
        }

        std::cerr << "[+] Initialized TTD engine\n";
        return true;
    }

    // Try to interpret the bytes at `addr` as a NUL-terminated ASCII or UTF-16LE
    // string. Returns the decoded ASCII text if it looks like a real string.
    std::optional<std::string> tryReadString(TTD::Replay::IThreadView const* thread, uint64_t addr) {
        if (addr < 0x10000) {
            return std::nullopt;  // null / low addresses are never string pointers
        }
        constexpr size_t kMax = 512;
        char buf[kMax];
        auto result = thread->QueryMemoryBuffer(TTD::GuestAddress{ addr }, TTD::BufferView{ buf, kMax });
        size_t avail = result.Memory.Size;
        if (avail < 2) {
            return std::nullopt;
        }

        // ASCII: printable run terminated by NUL.
        {
            std::string s;
            for (size_t i = 0; i < avail; ++i) {
                unsigned char c = static_cast<unsigned char>(buf[i]);
                if (c == 0) {
                    break;
                }
                if (c == '\t' || (c >= 0x20 && c <= 0x7e)) {
                    s.push_back(static_cast<char>(c));
                }
                else {
                    s.clear();
                    break;
                }
            }
            if (s.size() >= 4) {
                return s;
            }
        }

        // UTF-16LE: printable ASCII chars each followed by 0x00, terminated by 0x0000.
        {
            std::string s;
            bool ok = true;
            for (size_t i = 0; i + 1 < avail; i += 2) {
                unsigned char lo = static_cast<unsigned char>(buf[i]);
                unsigned char hi = static_cast<unsigned char>(buf[i + 1]);
                if (lo == 0 && hi == 0) {
                    break;
                }
                if (hi == 0 && (lo == '\t' || (lo >= 0x20 && lo <= 0x7e))) {
                    s.push_back(static_cast<char>(lo));
                }
                else {
                    ok = false;
                    break;
                }
            }
            if (ok && s.size() >= 4) {
                return s;
            }
        }
        return std::nullopt;
    }

    // Capture one candidate argument: a dereferenced string if it points to one,
    // otherwise the raw integer value.
    ttdcapa::ArgValue captureCallArg(TTD::Replay::IThreadView const* thread, uint64_t value) {
        if (auto s = tryReadString(thread, value)) {
            return *s;
        }
        return static_cast<int64_t>(value);
    }
}