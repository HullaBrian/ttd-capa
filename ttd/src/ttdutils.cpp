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

    std::string convertWstringToString(const std::wstring& ws) {
        if (ws.empty()) {
            return {};
        }
        int needed = ::WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()), nullptr, 0, nullptr, nullptr);
        if (needed <= 0) {
            return {};
        }
        std::string out(static_cast<size_t>(needed), '\0');
        ::WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()), out.data(), needed, nullptr, nullptr);
        return out;
    }

    size_t readMemory(TTD::Replay::UniqueCursor* cursor, TTD::GuestAddress addr, void* dest, unsigned __int64 size) {
        TTD::Replay::MemoryBuffer memoryBuffer = cursor->get()->QueryMemoryBuffer(addr, TTD::BufferView{ dest, size });
        return memoryBuffer.Memory.Size;
    }

    bool initializeTTDEngine(TTD::Replay::UniqueReplayEngine& engine, std::wstring traceFilePath) {
        // The engine holds this pointer for its whole lifetime and calls into it
        // whenever it reports an error. A stack local would dangle the moment this
        // function returns, and the first derailment during ReplayForward would then
        // dispatch a virtual call through reclaimed stack memory.
        static ConsoleErrorReporting reporter;
        engine->RegisterDebugModeAndLogging(TTD::Replay::DebugModeType::None, &reporter);

        if (!engine->Initialize(traceFilePath.c_str())) {
            std::wcerr << L"[-] Failed to open trace: " << traceFilePath.c_str() << std::endl;
            return false;
        }

        if (engine->GetIndexStatus() != TTD::Replay::IndexStatus::IndexFileLoaded) {
            std::cerr << "[+] Building index (first run may be slow)...\n";
            engine->BuildIndex(nullptr, nullptr, TTD::Replay::IndexBuildFlags::None);
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

    namespace {
        // Shared by both typed readers: an address below the first 64 KiB is never a
        // valid user-mode string pointer, and treating one as such is how a flags
        // DWORD ends up rendered as text.
        constexpr uint64_t kMinStringAddr = 0x10000;

        bool isPlausibleTextByte(unsigned char c) {
            return c == '\t' || c == '\r' || c == '\n' || (c >= 0x20 && c != 0x7f);
        }

        // The -A entry points take strings in the ANSI code page, so their high
        // bytes are not UTF-8. Emitting them raw would produce a report that the
        // JSON serializer refuses to write, so transcode before anything else sees
        // them. Pure-ASCII input (the overwhelming majority) short-circuits.
        std::string ansiToUtf8(std::string bytes) {
            bool ascii = true;
            for (unsigned char c : bytes) {
                if (c >= 0x80) {
                    ascii = false;
                    break;
                }
            }
            if (ascii) {
                return bytes;
            }

            int wide = ::MultiByteToWideChar(CP_ACP, 0, bytes.data(), static_cast<int>(bytes.size()), nullptr, 0);
            if (wide > 0) {
                std::wstring ws(static_cast<size_t>(wide), L'\0');
                if (::MultiByteToWideChar(CP_ACP, 0, bytes.data(), static_cast<int>(bytes.size()), ws.data(), wide) == wide) {
                    return convertWstringToString(ws);
                }
            }

            // Unconvertible: keep the ASCII skeleton rather than dropping the string.
            for (char& c : bytes) {
                if (static_cast<unsigned char>(c) >= 0x80) {
                    c = '?';
                }
            }
            return bytes;
        }
    }  // namespace

    std::optional<std::string> readAnsiString(TTD::Replay::IThreadView const* thread, uint64_t addr, size_t maxChars) {
        if (addr < kMinStringAddr) {
            return std::nullopt;
        }
        std::vector<char> buf(maxChars + 1);
        auto result = thread->QueryMemoryBuffer(TTD::GuestAddress{ addr }, TTD::BufferView{ buf.data(), maxChars });
        size_t avail = result.Memory.Size;
        if (avail == 0) {
            return std::nullopt;
        }

        std::string s;
        for (size_t i = 0; i < avail; ++i) {
            unsigned char c = static_cast<unsigned char>(buf[i]);
            if (c == 0) {
                return ansiToUtf8(std::move(s));
            }
            if (!isPlausibleTextByte(c)) {
                return std::nullopt;  // control bytes mean this wasn't a string after all
            }
            s.push_back(static_cast<char>(c));
        }
        // Ran out of readable memory before the terminator; keep what we have as
        // long as it looked like text the whole way.
        return s.empty() ? std::nullopt : std::optional<std::string>(ansiToUtf8(std::move(s)));
    }

    std::optional<std::string> readWideString(TTD::Replay::IThreadView const* thread, uint64_t addr, size_t maxChars) {
        if (addr < kMinStringAddr) {
            return std::nullopt;
        }
        std::vector<wchar_t> buf(maxChars + 1);
        auto result = thread->QueryMemoryBuffer(
            TTD::GuestAddress{ addr }, TTD::BufferView{ buf.data(), maxChars * sizeof(wchar_t) });
        size_t availChars = result.Memory.Size / sizeof(wchar_t);
        if (availChars == 0) {
            return std::nullopt;
        }

        size_t len = 0;
        while (len < availChars && buf[len] != L'\0') {
            wchar_t wc = buf[len];
            // Reject C0 controls (other than the usual whitespace) rather than
            // emitting mojibake for a pointer that only looked like a string.
            if (wc < 0x20 && wc != L'\t' && wc != L'\r' && wc != L'\n') {
                return std::nullopt;
            }
            ++len;
        }
        if (len == 0) {
            return std::string{};
        }
        return convertWstringToString(std::wstring(buf.data(), len));
    }

    // Capture one candidate argument: a dereferenced string if it points to one, otherwise the raw integer value.
    ttdcapa::ArgValue captureCallArg(TTD::Replay::IThreadView const* thread, uint64_t value) {
        if (auto s = tryReadString(thread, value)) {
            return *s;
        }
        return static_cast<int64_t>(value);
    }
}