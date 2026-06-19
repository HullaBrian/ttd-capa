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

#include "ttdutils.hpp"
#include "utils.hpp"
#include "ttd_pe_utils.hpp"

using namespace ttdcapa;

Report g_report;

int wmain(int argc, wchar_t** argv) {
    Options opt;
    if (!parse_args(argc, argv, opt)) {
        std::cerr << "Usage: ttdcapa-extract <trace.run> [--sample <sample.exe>] [-o <out.json>] [--max-calls N] [--with-stack-args]\n";
        return 1;
    }
    
    auto [engine, hr] = TTD::Replay::MakeReplayEngine();
    if (hr != S_OK || !engine) {
        std::cerr << "[-] Failed to create replay engine: 0x" << std::hex << hr << "\n";
        return false;
    }

    // Ensure TTD engine is initialized before doing any actual work
    if (!initializeTTDEngine(engine, opt.trace) || engine == NULL) {
        std::wcerr << "[-] Exiting...\n";
    }

    // Begin building report
    g_report.trace_path = opt.trace;
    TTD::SystemInfo const& sys = engine->GetSystemInfo();
    uint16_t pa = static_cast<uint16_t>(sys.System.ProcessorArchitecture);
    if (pa != PROCESSOR_ARCHITECTURE_AMD64) {
        std::cerr << "[-] Only x64 traces are supported in this version (arch=" << static_cast<int>(pa) << ").\n";
        return 2;
    }
    g_report.process.pid = static_cast<uint64_t>(sys.ProcessId);
    
    TTD::Replay::UniqueCursor inspection_cursor{ engine->NewCursor() };

    // Get basic report data like strings, imports, sections, etc
    initializeReport(engine, inspection_cursor, opt.sample);

    // Get list of function VAs used for call sweep
    std::unordered_map<uint64_t, std::pair<std::wstring, std::string>> resolvedTraceModuleExports;
    resolvedTraceModuleExports = resolveTraceModuleExports(engine, inspection_cursor);
    std::cerr << "[+] Resolved all exported module functions across execution\n";

    size_t thread_count = engine->GetThreadCount();
    TTD::Replay::ThreadInfo const* thread_list = engine->GetThreadList();
    for (size_t i = 0; i < thread_count; ++i) {
        g_report.process.threads.push_back(static_cast<uint64_t>(thread_list[i].UniqueId));
    }

    // per-thread stack of in-flight recorded calls: (expected return addr, call index)
    std::unordered_map<uint64_t, std::vector<std::pair<uint64_t, size_t>>> in_flight;
    uint64_t seq = 0;
    bool limit_hit = false;

    TTD::Replay::UniqueCursor sweep{ engine->NewCursor() };

    auto on_call_return = [&](TTD::GuestAddress target, TTD::GuestAddress fall_through,
        TTD::Replay::IThreadView const* thread) noexcept {
            bool is_call = (static_cast<uint64_t>(fall_through) != 0);
            uint64_t utid = static_cast<uint64_t>(thread->GetThreadInfo().UniqueId);

            if (is_call) {
                auto it = resolvedTraceModuleExports.find(static_cast<uint64_t>(target));
                if (it == resolvedTraceModuleExports.end()) {  // skip unresolved API function calls
                    return;
                }
                if (opt.max_calls != 0 && g_report.process.calls.size() >= opt.max_calls) {
                    limit_hit = true;
                    return;
                }

                ttdcapa::CallRecord rec;
                rec.tid = utid;
                rec.seq = seq++;
                rec.module = it->second.first;
                rec.api = it->second.second;

                // Retrieve usable TTD timestamp
                TTD::Replay::Position pos = thread->GetPosition();
                char posbuf[40];
                std::snprintf(
                    posbuf, sizeof(posbuf),
                    "%llX:%llX",
                    static_cast<unsigned long long>(pos.Sequence),
                    static_cast<unsigned long long>(pos.Steps)
                );
                rec.position = posbuf;

                TTD::Replay::RegisterContext regs = thread->GetCrossPlatformContext();
                auto const* ctx = reinterpret_cast<AMD64_CONTEXT const*>(&regs);
                rec.args.push_back(captureCallArg(thread, ctx->Rcx));
                rec.args.push_back(captureCallArg(thread, ctx->Rdx));
                rec.args.push_back(captureCallArg(thread, ctx->R8));
                rec.args.push_back(captureCallArg(thread, ctx->R9));

                if (opt.with_stack_args) {  // Capture arguments on stack based on offsets from RSP
                    for (int k = 0; k < 4; ++k) {
                        uint64_t slot = ctx->Rsp + 0x28 + static_cast<uint64_t>(k) * 8;
                        uint64_t v = 0;
                        if (thread->QueryMemoryBuffer(TTD::GuestAddress{ slot }, TTD::BufferView{ &v, sizeof(v) })
                            .Memory.Size == sizeof(v)) {
                            rec.args.push_back(captureCallArg(thread, v));
                        }
                    }
                }

                size_t idx = g_report.process.calls.size();
                in_flight[utid].push_back({ static_cast<uint64_t>(fall_through), idx });
                g_report.process.calls.push_back(std::move(rec));
            } else {
                // Log most recent function called as returned and capture return value
                auto it = in_flight.find(utid);
                if (it != in_flight.end() && !it->second.empty()) {
                    auto& top = it->second.back();
                    if (top.first == static_cast<uint64_t>(target)) {
                        g_report.process.calls[top.second].ret = thread->GetBasicReturnValue();
                        g_report.process.calls[top.second].has_ret = true;
                        it->second.pop_back();
                    }
                }
            }
        };

    sweep->SetCallReturnCallback(on_call_return);
    sweep->SetReplayFlags(TTD::Replay::ReplayFlags::ReplaySegmentsSequentially);
    sweep->SetPosition(TTD::Replay::Position::Min);
    std::cerr << "[+] Beginning execution sweep...\n";
    sweep->ReplayForward();

    if (limit_hit) {
        std::cerr << "[!] Reached --max-calls limit (" << opt.max_calls << ")\n";
    }
    std::cerr << "[+] Recorded " << g_report.process.calls.size() << " API calls\n";

    writeReport(opt.output);

    std::cerr << "[!] Exiting...\n";
    return 0;
}
