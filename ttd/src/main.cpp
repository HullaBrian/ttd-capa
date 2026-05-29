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

// ttdcapa-extract: sweep a Time Travel Debugging (.run) trace and emit a neutral
// "TTD report" JSON consumed by capa's TTD dynamic backend
// (capa/features/extractors/ttd/). x64 traces only in v1.
//
//   ttdcapa-extract <trace.run> [--sample <sample.exe>] [-o <out.json>]
//                   [--max-calls N] [--with-stack-args]

#include <cassert>
#define DBG_ASSERT(cond) assert(cond)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>  // S_OK, HRESULT

#include <TTD/IReplayEngineStl.h>
#include <TTD/IReplayEngineRegisters.h>
#include <TTD/ErrorReporting.h>

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "guest_pe.h"
#include "hashes.h"
#include "json_writer.h"
#include "records.h"

using namespace TTD;
using namespace TTD::Replay;

namespace {

class ConsoleErrorReporting : public ErrorReporting {
public:
    void __fastcall VPrintError(char const* fmt, va_list args) override {
        char buf[2048];
        vsnprintf(buf, sizeof(buf), fmt, args);
        std::cerr << "[TTD] " << buf << "\n";
    }
};

struct Options {
    std::filesystem::path trace;
    std::filesystem::path sample;  // optional on-disk sample for hashing
    std::filesystem::path output;  // empty => stdout
    uint64_t max_calls = 0;        // 0 => unlimited
    bool with_stack_args = false;
};

bool parse_args(int argc, wchar_t** argv, Options& opt) {
    for (int i = 1; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"--sample" && i + 1 < argc) {
            opt.sample = argv[++i];
        } else if ((a == L"-o" || a == L"--output") && i + 1 < argc) {
            opt.output = argv[++i];
        } else if (a == L"--max-calls" && i + 1 < argc) {
            opt.max_calls = std::wcstoull(argv[++i], nullptr, 10);
        } else if (a == L"--with-stack-args") {
            opt.with_stack_args = true;
        } else if (!a.empty() && a[0] == L'-') {
            std::cerr << "unknown option\n";
            return false;
        } else if (opt.trace.empty()) {
            opt.trace = a;
        } else {
            std::cerr << "unexpected positional argument\n";
            return false;
        }
    }
    return !opt.trace.empty();
}

// Try to interpret the bytes at `addr` as a NUL-terminated ASCII or UTF-16LE
// string. Returns the decoded ASCII text if it looks like a real string.
std::optional<std::string> try_read_string(IThreadView const* thread, uint64_t addr) {
    if (addr < 0x10000) {
        return std::nullopt;  // null / low addresses are never string pointers
    }
    constexpr size_t kMax = 512;
    char buf[kMax];
    auto result = thread->QueryMemoryBuffer(GuestAddress{addr}, BufferView{buf, kMax});
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
            } else {
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
            } else {
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
ttdcapa::ArgValue capture_arg(IThreadView const* thread, uint64_t value) {
    if (auto s = try_read_string(thread, value)) {
        return *s;
    }
    return static_cast<int64_t>(value);
}

void write_report(std::ostream& os, const std::string& arch, const std::string& os_name,
                  const std::filesystem::path& trace_path, const ttdcapa::SampleHashes& hashes,
                  const std::string& sample_name, const std::vector<ttdcapa::ImportRecord>& imports,
                  const std::vector<ttdcapa::ExportRecord>& exports,
                  const std::vector<ttdcapa::SectionRecord>& sections,
                  const std::vector<std::string>& strings,
                  const ttdcapa::ProcessRecord& process) {
    ttdcapa::JsonWriter w(os);
    w.begin_object();
    w.member("version", static_cast<int64_t>(1));

    w.key("trace");
    w.begin_object();
    w.member("path", ttdcapa::JsonWriter::narrow(trace_path.wstring()));
    w.member("arch", arch);
    w.member("os", os_name);
    w.end_object();

    w.key("sample");
    w.begin_object();
    w.member("md5", hashes.md5);
    w.member("sha1", hashes.sha1);
    w.member("sha256", hashes.sha256);
    w.member("name", sample_name);
    w.end_object();

    w.key("file");
    w.begin_object();
    w.key("imports");
    w.begin_array();
    for (const auto& imp : imports) {
        w.begin_object();
        w.member("dll", imp.dll);
        w.member("name", imp.name);
        w.member("va", imp.va);
        w.end_object();
    }
    w.end_array();
    w.key("exports");
    w.begin_array();
    for (const auto& exp : exports) {
        w.begin_object();
        w.member("name", exp.name);
        w.member("va", exp.va);
        w.end_object();
    }
    w.end_array();
    w.key("sections");
    w.begin_array();
    for (const auto& sec : sections) {
        w.begin_object();
        w.member("name", sec.name);
        w.member("va", sec.va);
        w.end_object();
    }
    w.end_array();
    w.key("strings");
    w.begin_array();
    for (const auto& s : strings) {
        w.value(s);
    }
    w.end_array();
    w.end_object();  // file

    w.key("processes");
    w.begin_array();
    {
        w.begin_object();
        w.member("pid", process.pid);
        w.member("ppid", process.ppid);
        w.member("name", process.name);
        w.key("environ");
        w.begin_array();
        for (const auto& e : process.env_strings) {
            w.value(e);
        }
        w.end_array();
        w.key("threads");
        w.begin_array();
        for (uint64_t t : process.threads) {
            w.value(t);
        }
        w.end_array();
        w.key("calls");
        w.begin_array();
        for (const auto& call : process.calls) {
            w.begin_object();
            w.member("tid", call.tid);
            w.member("seq", call.seq);
            w.member("position", call.position);
            w.member("module", call.module);
            w.member("api", call.api);
            w.key("args");
            w.begin_array();
            for (const auto& arg : call.args) {
                if (std::holds_alternative<int64_t>(arg)) {
                    w.value(std::get<int64_t>(arg));
                } else {
                    w.value(std::get<std::string>(arg));
                }
            }
            w.end_array();
            if (call.has_ret) {
                w.member("ret", call.ret);
            } else {
                w.key("ret");
                w.value_null();
            }
            w.end_object();
        }
        w.end_array();
        w.end_object();
    }
    w.end_array();  // processes

    w.end_object();
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    Options opt;
    if (!parse_args(argc, argv, opt)) {
        std::cerr << "Usage: ttdcapa-extract <trace.run> [--sample <sample.exe>] "
                     "[-o <out.json>] [--max-calls N] [--with-stack-args]\n";
        return 1;
    }

    auto [engine, hr] = MakeReplayEngine();
    if (hr != S_OK || !engine) {
        std::cerr << "Failed to create replay engine: 0x" << std::hex << hr << "\n";
        return 1;
    }

    ConsoleErrorReporting reporter;
    engine->RegisterDebugModeAndLogging(DebugModeType::None, &reporter);

    if (!engine->Initialize(opt.trace.wstring().c_str())) {
        std::cerr << "Failed to open trace: " << opt.trace.string() << "\n";
        return 1;
    }

    if (engine->GetIndexStatus() != IndexStatus::IndexFileLoaded) {
        std::cerr << "Building index (first run may be slow)...\n";
        auto progress = [](void const*, IndexBuildProgressType const* d) noexcept -> void {
            if (d->KeyframeCount > 0) {
                std::cerr << "\r" << (d->KeyframesProcessed * 100 / d->KeyframeCount) << "%   ";
            }
        };
        engine->BuildIndex(progress, nullptr, IndexBuildFlags::None);
        std::cerr << "\n";
    }

    // --- architecture gate (x64 only in v1) ---
    SystemInfo const& sys = engine->GetSystemInfo();
    // SystemInfo.System.ProcessorArchitecture holds the standard Windows
    // PROCESSOR_ARCHITECTURE_* value (AMD64 == 9), not the TTD ProcessorArchitecture
    // enum. Gate against the Windows constant from <windows.h>.
    uint16_t pa = static_cast<uint16_t>(sys.System.ProcessorArchitecture);
    if (pa != PROCESSOR_ARCHITECTURE_AMD64) {
        std::cerr << "Only x64 traces are supported in this version (arch="
                  << static_cast<int>(pa) << ").\n";
        return 2;
    }
    const std::string arch = "x64";
    const std::string os_name = "windows";

    // --- module export map (resolve CALL target -> module.api) ---
    UniqueCursor cursor{engine->NewCursor()};
    cursor->SetDefaultMemoryPolicy(QueryMemoryPolicy::GloballyAggressive);

    Position const last = engine->GetLastPosition();

    auto make_reader = [&cursor]() -> ttdcapa::GuestReader {
        return [&cursor](uint64_t addr, void* dst, size_t size) -> size_t {
            auto r = cursor->QueryMemoryBuffer(GuestAddress{addr}, BufferView{dst, size});
            return r.Memory.Size;
        };
    };
    ttdcapa::GuestReader read = make_reader();

    size_t mod_count = engine->GetModuleCount();
    Module const* mods = engine->GetModuleList();

    // exact function-entry VA -> (module, api)
    std::unordered_map<uint64_t, std::pair<std::string, std::string>> api_by_va;

    // Identify the main module (first image whose name ends in ".exe").
    int main_idx = -1;
    for (size_t i = 0; i < mod_count; ++i) {
        std::wstring name = mods[i].pName ? mods[i].pName : L"";
        if (name.size() >= 4) {
            std::wstring ext = name.substr(name.size() - 4);
            for (auto& c : ext) c = static_cast<wchar_t>(towlower(c));
            if (ext == L".exe") {
                main_idx = static_cast<int>(i);
                break;
            }
        }
    }

    // Read each module's exports at the end of the trace, falling back to the
    // start for modules that had already unloaded by then.
    cursor->SetPosition(last);
    std::vector<size_t> failed;
    for (size_t i = 0; i < mod_count; ++i) {
        std::string mname = ttdcapa::module_basename(mods[i].pName ? mods[i].pName : L"");
        std::vector<std::pair<uint64_t, std::string>> exps;
        if (ttdcapa::parse_exports(read, static_cast<uint64_t>(mods[i].Address), mname, exps)) {
            for (auto& e : exps) {
                api_by_va.emplace(e.first, std::make_pair(mname, std::move(e.second)));
            }
        } else {
            failed.push_back(i);
        }
    }
    if (!failed.empty()) {
        cursor->SetPosition(Position::Min);
        for (size_t i : failed) {
            std::string mname = ttdcapa::module_basename(mods[i].pName ? mods[i].pName : L"");
            std::vector<std::pair<uint64_t, std::string>> exps;
            if (ttdcapa::parse_exports(read, static_cast<uint64_t>(mods[i].Address), mname, exps)) {
                for (auto& e : exps) {
                    api_by_va.emplace(e.first, std::make_pair(mname, std::move(e.second)));
                }
            }
        }
        cursor->SetPosition(last);
    }

    std::cerr << "Resolved " << api_by_va.size() << " exported APIs across " << mod_count
              << " modules.\n";

    // --- main-module file features (imports / exports / sections / strings) ---
    std::vector<ttdcapa::ImportRecord> imports;
    std::vector<ttdcapa::ExportRecord> exports;
    std::vector<ttdcapa::SectionRecord> sections;
    std::vector<std::string> strings;
    std::string sample_name;

    if (main_idx >= 0) {
        uint64_t mbase = static_cast<uint64_t>(mods[main_idx].Address);
        std::wstring full = mods[main_idx].pName ? mods[main_idx].pName : L"";
        size_t slash = full.find_last_of(L"\\/");
        sample_name = ttdcapa::JsonWriter::narrow(
            slash == std::wstring::npos ? full : full.substr(slash + 1));

        auto try_parse = [&](Position p) -> bool {
            cursor->SetPosition(p);
            imports.clear();
            sections.clear();
            std::vector<std::pair<uint64_t, std::string>> exps;
            bool ok = ttdcapa::parse_imports(read, mbase, imports);
            ok = ttdcapa::parse_sections(read, mbase, sections) && ok;
            if (ttdcapa::parse_exports(read, mbase, "", exps)) {
                for (auto& e : exps) {
                    exports.push_back({std::move(e.second), e.first});
                }
            }
            return ok && !sections.empty();
        };
        if (!try_parse(last)) {
            try_parse(Position::Min);
        }
        cursor->SetPosition(last);
        ttdcapa::recover_strings(read, mbase, strings);
    }

    // --- call/return sweep ---
    ttdcapa::ProcessRecord process;
    process.pid = static_cast<uint64_t>(sys.ProcessId);
    process.ppid = 0;  // not exposed by the Replay API
    process.name = sample_name;

    size_t thread_count = engine->GetThreadCount();
    ThreadInfo const* thread_list = engine->GetThreadList();
    for (size_t i = 0; i < thread_count; ++i) {
        process.threads.push_back(static_cast<uint64_t>(thread_list[i].UniqueId));
    }

    // per-thread stack of in-flight recorded calls: (expected return addr, call index)
    std::unordered_map<uint64_t, std::vector<std::pair<uint64_t, size_t>>> in_flight;
    uint64_t seq = 0;
    bool limit_hit = false;

    UniqueCursor sweep{engine->NewCursor()};

    auto on_call_return = [&](GuestAddress target, GuestAddress fall_through,
                              IThreadView const* thread) noexcept {
        bool is_call = (static_cast<uint64_t>(fall_through) != 0);
        uint64_t utid = static_cast<uint64_t>(thread->GetThreadInfo().UniqueId);

        if (is_call) {
            auto it = api_by_va.find(static_cast<uint64_t>(target));
            if (it == api_by_va.end()) {
                return;  // not an exported API entry; skip intra-module noise
            }
            if (opt.max_calls != 0 && process.calls.size() >= opt.max_calls) {
                limit_hit = true;
                return;
            }

            ttdcapa::CallRecord rec;
            rec.tid = utid;
            rec.seq = seq++;
            rec.module = it->second.first;
            rec.api = it->second.second;

            // The navigable TTD position of this CALL, as WinDbg shows it:
            // "Sequence:Steps" in hex. Paste it into WinDbg's time-travel position
            // box (or `!tt Sequence:Steps`) to jump straight to this instruction.
            Position pos = thread->GetPosition();
            char posbuf[40];
            std::snprintf(posbuf, sizeof(posbuf), "%llX:%llX",
                          static_cast<unsigned long long>(pos.Sequence),
                          static_cast<unsigned long long>(pos.Steps));
            rec.position = posbuf;

            // GetCrossPlatformContext returns by value; bind to a local before
            // taking its address (the result is a temporary, not an l-value).
            RegisterContext regs = thread->GetCrossPlatformContext();
            auto const* ctx = reinterpret_cast<AMD64_CONTEXT const*>(&regs);
            rec.args.push_back(capture_arg(thread, ctx->Rcx));
            rec.args.push_back(capture_arg(thread, ctx->Rdx));
            rec.args.push_back(capture_arg(thread, ctx->R8));
            rec.args.push_back(capture_arg(thread, ctx->R9));

            if (opt.with_stack_args) {
                // Stack args 5+ live above the shadow space. At the CALL instruction
                // the return address has not been pushed yet, so the first stack arg
                // slot is [RSP + 0x28]. Heuristic; over-capture is acceptable.
                for (int k = 0; k < 4; ++k) {
                    uint64_t slot = ctx->Rsp + 0x28 + static_cast<uint64_t>(k) * 8;
                    uint64_t v = 0;
                    if (thread->QueryMemoryBuffer(GuestAddress{slot}, BufferView{&v, sizeof(v)})
                            .Memory.Size == sizeof(v)) {
                        rec.args.push_back(capture_arg(thread, v));
                    }
                }
            }

            size_t idx = process.calls.size();
            in_flight[utid].push_back({static_cast<uint64_t>(fall_through), idx});
            process.calls.push_back(std::move(rec));
        } else {
            // RET: pair with the most recent recorded call on this thread whose
            // expected return address matches where we are returning to.
            auto it = in_flight.find(utid);
            if (it != in_flight.end() && !it->second.empty()) {
                auto& top = it->second.back();
                if (top.first == static_cast<uint64_t>(target)) {
                    process.calls[top.second].ret = thread->GetBasicReturnValue();
                    process.calls[top.second].has_ret = true;
                    it->second.pop_back();
                }
            }
        }
    };

    sweep->SetCallReturnCallback(on_call_return);
    // By default bulk ReplayForward filters segments: instructions still execute, but
    // detailed callbacks (call/return) only fire for segments "claimed" by a watchpoint.
    // With only a call/return callback registered, nothing claims a segment and the
    // callback never fires. ReplayAllSegmentsWithoutFiltering forces full replay of every
    // segment; ReplaySegmentsSequentially keeps it single-threaded so the callback's
    // mutations of shared state (process.calls, in_flight, seq) are race-free.
    sweep->SetReplayFlags(ReplayFlags::ReplayAllSegmentsWithoutFiltering |
                          ReplayFlags::ReplaySegmentsSequentially);
    sweep->SetPosition(Position::Min);
    std::cerr << "Sweeping calls...\n";
    sweep->ReplayForward();

    if (limit_hit) {
        std::cerr << "Reached --max-calls limit (" << opt.max_calls << ").\n";
    }
    std::cerr << "Recorded " << process.calls.size() << " API calls.\n";

    // --- hashes (of the on-disk sample, if provided) ---
    ttdcapa::SampleHashes hashes;
    if (!opt.sample.empty()) {
        hashes = ttdcapa::hash_file(opt.sample);
        if (sample_name.empty()) {
            sample_name = ttdcapa::JsonWriter::narrow(opt.sample.filename().wstring());
            process.name = sample_name;
        }
    }

    // --- emit JSON ---
    if (opt.output.empty()) {
        write_report(std::cout, arch, os_name, opt.trace, hashes, sample_name, imports, exports,
                     sections, strings, process);
    } else {
        std::ofstream out(opt.output, std::ios::binary | std::ios::trunc);
        if (!out) {
            std::cerr << "Failed to open output file: " << opt.output.string() << "\n";
            return 1;
        }
        write_report(out, arch, os_name, opt.trace, hashes, sample_name, imports, exports, sections,
                     strings, process);
        std::cerr << "Wrote " << opt.output.string() << "\n";
    }

    return 0;
}
