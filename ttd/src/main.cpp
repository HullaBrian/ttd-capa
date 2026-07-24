// ttdcapa-extract: sweep a Time Travel Debugging (.run) trace and emit a neutral
// "TTD report" JSON consumed by capa's TTD dynamic backend
// (capa/features/extractors/ttd/). x64 traces only in v1.
//
//   ttdcapa-extract <trace.run> [--sample <sample.exe>] [-o <out.json>]
//                   [--max-calls N] [--with-stack-args] [--win32-index <path>]
//                   [--no-metadata] [--max-buffer N]
//   ttdcapa-extract --dump-sig <ApiName>
//
// Arguments are decoded against the pre-baked Win32 metadata index whenever the
// resolved export is in it (see win32meta.hpp / abi_x64.hpp); calls we have no
// signature for fall back to the original heuristic capture.

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
#include "win32meta.hpp"
#include "abi_x64.hpp"

using namespace ttdcapa;

Report g_report;

// Print one function's decoded signature and exit. Lets the metadata index and the
// ABI classification be checked without waiting on a trace replay.
static int dumpSignature(const std::string& api) {
    const win32meta::FuncSig* sig = win32meta::index().lookup(api);
    if (sig == nullptr) {
        std::cerr << "[-] '" << api << "' is not in the metadata index\n";
        return 3;
    }
    std::cout << sig->name << "  dll=" << sig->dll
              << "  params=" << static_cast<int>(sig->paramCount)
              << (sig->hiddenRetPtr() ? "  [hidden-return-pointer]" : "")
              << (sig->unsupported() ? "  [unsupported]" : "") << "\n";
    for (uint8_t i = 0; i < sig->paramCount; ++i) {
        const win32meta::ParamSig& p = sig->params[i];
        std::cout << "  slot " << static_cast<int>(p.slot) << "  " << p.name
                  << " : " << p.type << "  (" << win32meta::kindName(p.kind) << ")";
        if (p.isIn()) std::cout << " in";
        if (p.isOut()) std::cout << " out";
        if (p.attrs & win32meta::AttrOptional) std::cout << " optional";
        if (p.auxKind == win32meta::AuxKind::BytesFromParam) std::cout << "  bytes=param[" << p.auxValue << "]";
        if (p.auxKind == win32meta::AuxKind::CountFromParam) std::cout << "  count=param[" << p.auxValue << "]";
        if (p.auxKind == win32meta::AuxKind::CountConst) std::cout << "  count=" << p.auxValue;
        if (p.hasEnum()) std::cout << "  enum=" << win32meta::index().enumName(p.enumIndex);
        std::cout << "\n";
    }
    return 0;
}

int wmain(int argc, wchar_t** argv) {
    Options opt;
    if (!parse_args(argc, argv, opt)) {
        std::cerr << "Usage: ttdcapa-extract <trace.run> [--sample <sample.exe>] [-o <out.json>]\n"
                     "                       [--max-calls N] [--with-stack-args]\n"
                     "                       [--win32-index <path>] [--no-metadata] [--max-buffer N]\n"
                     "       ttdcapa-extract --dump-sig <ApiName>\n";
        return 1;
    }

    DecodeOptions decode_opt;
    decode_opt.max_buffer = opt.max_buffer;
    if (!opt.no_metadata) {
        std::string err;
        if (win32meta::loadIndex(opt.win32_index, err)) {
            std::cerr << "[+] Loaded Win32 metadata for " << win32meta::index().functionCount()
                      << " functions\n";
        } else {
            std::cerr << "[!] " << err << "; falling back to heuristic argument capture\n";
        }
    }

    if (!opt.dump_sig.empty()) {
        return dumpSignature(opt.dump_sig);
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
    std::cerr << "[+] Resolved " << resolvedTraceModuleExports.size()
              << " exported module functions across execution\n";

    size_t thread_count = engine->GetThreadCount();
    TTD::Replay::ThreadInfo const* thread_list = engine->GetThreadList();
    for (size_t i = 0; i < thread_count; ++i) {
        g_report.process.threads.push_back(static_cast<uint64_t>(thread_list[i].UniqueId));
    }

    // per-thread stack of recorded calls we haven't seen return yet, each carrying
    // the [Out] dereferences we deliberately postponed until the callee has run
    struct InFlight {
        uint64_t ret_addr = 0;
        size_t call_index = 0;
        std::vector<PendingOut> pending;
    };
    std::unordered_map<uint64_t, std::vector<InFlight>> in_flight;
    uint64_t seq = 0;
    uint64_t events_seen = 0;
    bool limit_hit = false;

    TTD::Replay::UniqueCursor sweep{ engine->NewCursor() };

    auto on_call_return = [&](TTD::GuestAddress target, TTD::GuestAddress fall_through,
        TTD::Replay::IThreadView const* thread) noexcept {
            bool is_call = (static_cast<uint64_t>(fall_through) != 0);
            uint64_t utid = static_cast<uint64_t>(thread->GetThreadInfo().UniqueId);
            ++events_seen;

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

                std::vector<PendingOut> pending;
                win32meta::FuncSig const* sig = win32meta::index().lookup(rec.api);
                if (sig != nullptr && !sig->unsupported()) {
                    // We know the real arity, so capture exactly that many arguments
                    // -- no stale RDX/R8/R9 residue masquerading as parameters.
                    decodeArgs(*sig, *ctx, thread, decode_opt, rec.params, pending);
                    rec.args = toCapaArgs(rec.params);
                    rec.metadata = true;
                } else {
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
                }

                size_t idx = g_report.process.calls.size();
                in_flight[utid].push_back(InFlight{ static_cast<uint64_t>(fall_through), idx, std::move(pending) });
                g_report.process.calls.push_back(std::move(rec));
            } else {
                // Log most recent function called as returned and capture return value
                auto it = in_flight.find(utid);
                if (it != in_flight.end() && !it->second.empty()) {
                    InFlight& top = it->second.back();
                    if (top.ret_addr == static_cast<uint64_t>(target)) {
                        CallRecord& call = g_report.process.calls[top.call_index];
                        call.ret = thread->GetBasicReturnValue();
                        call.has_ret = true;
                        if (!top.pending.empty()) {
                            // The payoff of a time-travel trace: [Out] parameters can be
                            // rendered filled in, which a live debugger can't easily do.
                            resolvePendingOuts(top.pending, thread, decode_opt, call.params);
                            call.args = toCapaArgs(call.params);
                        }
                        it->second.pop_back();
                    }
                }
            }
        };

    sweep->SetCallReturnCallback(on_call_return);
    // Without ReplayAllSegmentsWithoutFiltering the engine only replays segments it
    // thinks can hit an event, and a call/return callback alone doesn't qualify --
    // the sweep then completes instantly having seen nothing.
    sweep->SetReplayFlags(TTD::Replay::ReplayFlags::ReplaySegmentsSequentially |
                          TTD::Replay::ReplayFlags::ReplayAllSegmentsWithoutFiltering);
    sweep->SetPosition(TTD::Replay::Position::Min);
    std::cerr << "[+] Beginning execution sweep...\n";
    sweep->ReplayForward();

    if (limit_hit) {
        std::cerr << "[!] Reached --max-calls limit (" << opt.max_calls << ")\n";
    }
    std::cerr << "[+] Recorded " << g_report.process.calls.size() << " API calls from "
              << events_seen << " call/return events\n";

    writeReport(opt.output);

    std::cerr << "[!] Exiting...\n";
    return 0;
}
