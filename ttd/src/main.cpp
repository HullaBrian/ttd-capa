// ttdcapa-extract: sweep a Time Travel Debugging (.run) trace and emit a neutral
// "TTD report" JSON consumed by capa's TTD dynamic backend
// (capa/features/extractors/ttd/). x64 and x86 traces, including WoW64.
//
//   ttdcapa-extract <trace.run> [--sample <sample.exe>] [-o <out.json>]
//                   [--max-calls N] [--with-stack-args] [--win32-index <path>]
//                   [--no-metadata] [--max-buffer N]
//   ttdcapa-extract --dump-sig <ApiName>
//
// Arguments are decoded against the pre-baked Win32 metadata index whenever the
// resolved export is in it (see win32meta.hpp / abi.hpp); calls we have no
// signature for fall back to the original heuristic capture.
//
// Bitness is decided per call from the module owning the target, not once for the
// trace: SystemInfo reports the *recording machine's* architecture, which says
// nothing about the guest, and a WoW64 process runs both widths at once.

#include <cassert>
#define DBG_ASSERT(cond) assert(cond)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>  // S_OK, HRESULT

#include <TTD/IReplayEngineStl.h>
#include <TTD/IReplayEngineRegisters.h>
#include <TTD/ErrorReporting.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "ttdutils.hpp"
#include "utils.hpp"
#include "ttd_pe_utils.hpp"
#include "win32meta.hpp"
#include "abi.hpp"
#include "binreport.hpp"

using namespace ttdcapa;

Report g_report;

// The cursor currently replaying, for the stdin watcher thread to interrupt. Only
// non-null while ReplayForward is running; InterruptReplay is documented as safe to
// call from any thread.
static std::atomic<TTD::Replay::ICursor*> g_replayingCursor{ nullptr };

// Print one function's decoded signature and exit. Lets the metadata index and the
// ABI classification be checked without waiting on a trace replay.
static int dumpSignature(const std::string& api) {
    const win32meta::FuncSig* sig = win32meta::index().lookup(api);
    if (sig == nullptr) {
        std::cerr << "[-] '" << api << "' is not in the metadata index\n";
        return 3;
    }
    std::vector<uint16_t> x86Offsets;
    bool x86Ok = x86StackLayout(*sig, x86Offsets);

    std::cout << sig->name << "  dll=" << sig->dll
              << "  params=" << static_cast<int>(sig->paramCount)
              << (sig->hiddenRetPtr() ? "  [hidden-return-pointer]" : "")
              << (sig->unsupported() ? "  [unsupported]" : "")
              << (x86Ok ? "" : "  [no x86 layout]") << "\n";
    for (uint8_t i = 0; i < sig->paramCount; ++i) {
        const win32meta::ParamSig& p = sig->params[i];
        std::cout << "  slot " << static_cast<int>(p.slot);
        if (x86Ok) {
            std::cout << "  x86@esp+" << (4 + x86Offsets[i]);
        }
        std::cout << "  " << p.name
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
    // Deliberately not gated on sys.System.ProcessorArchitecture: that field comes
    // from GetSystemInfo() on the recording machine, so a 32-bit process recorded on
    // an x64 box reports AMD64. The guest's real width comes from each module's PE
    // header while resolving exports, below.
    TTD::SystemInfo const& sys = engine->GetSystemInfo();
    g_report.process.pid = static_cast<uint64_t>(sys.ProcessId);
    
    TTD::Replay::UniqueCursor inspection_cursor{ engine->NewCursor() };

    // Get basic report data like strings, imports, sections, etc
    initializeReport(engine, inspection_cursor, opt.sample);

    // Get list of function VAs used for call sweep
    std::unordered_map<uint64_t, ResolvedExport> resolvedTraceModuleExports;
    resolvedTraceModuleExports = resolveTraceModuleExports(engine, inspection_cursor);
    size_t exports32 = 0;
    for (const auto& entry : resolvedTraceModuleExports) {
        if (!entry.second.is64) {
            ++exports32;
        }
    }
    std::cerr << "[+] Resolved " << resolvedTraceModuleExports.size()
              << " exported module functions across execution ("
              << exports32 << " in 32-bit modules)\n";

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
        GuestArch arch = GuestArch::X64;  // must match the entry pass to re-read correctly
        std::vector<PendingOut> pending;
    };
    std::unordered_map<uint64_t, std::vector<InFlight>> in_flight;
    uint64_t seq = 0;
    uint64_t events_seen = 0;
    bool limit_hit = false;

    TTD::Replay::UniqueCursor sweep{ engine->NewCursor() };

    // Progress is measured against the trace's last sequence number. The call callback
    // is the only place we are given a position, but call/return events are dense
    // enough (tens of millions in a large trace) for that to be smooth.
    const uint64_t final_sequence = static_cast<uint64_t>(engine->GetLastPosition().Sequence);
    uint64_t next_progress_ms = 0;
    double highest_pct = 0.0;

    auto on_call_return = [&](TTD::GuestAddress target, TTD::GuestAddress fall_through,
        TTD::Replay::IThreadView const* thread) noexcept {
            bool is_call = (static_cast<uint64_t>(fall_through) != 0);
            uint64_t utid = static_cast<uint64_t>(thread->GetThreadInfo().UniqueId);
            ++events_seen;

            // Rate-limited to a few lines a second. The event counter is masked first so
            // the common path is an AND rather than a clock read.
            if (opt.report_progress && (events_seen & 0x3FF) == 0) {
                uint64_t now = ::GetTickCount64();
                if (now >= next_progress_ms) {
                    next_progress_ms = now + 200;
                    uint64_t at = static_cast<uint64_t>(thread->GetPosition().Sequence);
                    double pct = final_sequence != 0 ? (100.0 * static_cast<double>(at)
                                                        / static_cast<double>(final_sequence))
                                                     : 0.0;
                    if (pct > 100.0) {
                        pct = 100.0;
                    }
                    // Positions from different threads are not perfectly ordered, so a
                    // sample occasionally reads behind the one before it (about 4% of
                    // them). Clamp here rather than letting a progress bar walk
                    // backwards.
                    if (pct < highest_pct) {
                        pct = highest_pct;
                    } else {
                        highest_pct = pct;
                    }
                    std::fprintf(stderr, "[progress] %.2f %zu\n", pct,
                                 g_report.process.calls.size());
                    std::fflush(stderr);
                }
            }

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
                rec.module = it->second.module;
                rec.api = it->second.api;

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

                // The target module's PE header decided this; in a WoW64 trace the
                // 32-bit and 64-bit halves alternate call by call.
                CallFrame frame;
                frame.arch = it->second.is64 ? GuestArch::X64 : GuestArch::X86;
                frame.thread = thread;
                if (frame.arch == GuestArch::X64) {
                    frame.x64 = ctx;
                } else {
                    frame.x86 = reinterpret_cast<X86_NT5_CONTEXT const*>(&regs);
                }

                std::vector<PendingOut> pending;
                win32meta::FuncSig const* sig = win32meta::index().lookup(rec.api);
                // decodeArgs declines a signature it cannot lay out for this
                // architecture, in which case the heuristic path below is still
                // better than parameters read from the wrong offsets.
                if (sig != nullptr && !sig->unsupported()
                    && decodeArgs(*sig, frame, decode_opt, rec.params, pending)) {
                    // We know the real arity, so capture exactly that many arguments
                    // -- no stale RDX/R8/R9 residue masquerading as parameters.
                    rec.args = toCapaArgs(rec.params);
                    rec.metadata = true;
                } else {
                    rec.params.clear();
                    pending.clear();

                    if (frame.arch == GuestArch::X86) {
                        // Nothing arrives in registers on x86, so the heuristic has to
                        // read the stack even without --with-stack-args. Four words
                        // keeps it comparable to the x64 fallback's four registers.
                        int words = opt.with_stack_args ? 8 : 4;
                        for (int k = 0; k < words; ++k) {
                            uint64_t addr = static_cast<uint64_t>(frame.x86->Esp) + 4 + static_cast<uint64_t>(k) * 4;
                            uint32_t v = 0;
                            if (thread->QueryMemoryBuffer(TTD::GuestAddress{ addr }, TTD::BufferView{ &v, sizeof(v) })
                                .Memory.Size == sizeof(v)) {
                                rec.args.push_back(captureCallArg(thread, v));
                            }
                        }
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
                }

                size_t idx = g_report.process.calls.size();
                in_flight[utid].push_back(
                    InFlight{ static_cast<uint64_t>(fall_through), idx, frame.arch, std::move(pending) });
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
                            // Pointer width has to match the entry pass, so carry the
                            // architecture over rather than re-deriving it here.
                            CallFrame retFrame;
                            retFrame.arch = top.arch;
                            retFrame.thread = thread;
                            resolvePendingOuts(top.pending, retFrame, decode_opt, call.params);
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
    if (opt.report_progress) {
        // The sweep is only part of the wall clock -- serialising a multi-hundred-MB
        // report takes comparable time -- so name the phases rather than let a caller's
        // progress bar sit at 100% looking wedged.
        std::fprintf(stderr, "[phase] sweep\n");
        std::fflush(stderr);
    }

    // A UI driving this as a child process can ask to stop early. Everything recorded
    // so far is already in g_report, so an interrupted sweep still yields a usable
    // report -- only the calls that had not returned yet lose their return values and
    // [Out] parameters.
    g_replayingCursor.store(sweep.get());
    std::thread cancel_watcher;
    if (opt.cancel_on_stdin) {
        cancel_watcher = std::thread([] {
            std::string line;
            while (std::getline(std::cin, line)) {
                if (line.rfind("cancel", 0) == 0) {
                    if (auto* cursor = g_replayingCursor.load()) {
                        cursor->InterruptReplay();
                    }
                    return;
                }
            }
        });
        // Detached because it is parked in a blocking read; the process exits out from
        // under it once the report is written.
        cancel_watcher.detach();
    }

    TTD::Replay::ICursorView::ReplayResult result = sweep->ReplayForward();
    g_replayingCursor.store(nullptr);

    const bool interrupted = result.StopReason == TTD::Replay::EventType::Interrupted;
    if (interrupted) {
        std::cerr << "[!] Sweep cancelled; writing the " << g_report.process.calls.size()
                  << " calls recorded so far\n";
    }

    if (limit_hit) {
        std::cerr << "[!] Reached --max-calls limit (" << opt.max_calls << ")\n";
    }
    std::cerr << "[+] Recorded " << g_report.process.calls.size() << " API calls from "
              << events_seen << " call/return events\n";

    if (opt.report_progress) {
        std::fprintf(stderr, "[phase] write\n");
        std::fflush(stderr);
    }
    if (!opt.binary_output.empty()) {
        std::string err;
        if (binreport::write(opt.binary_output, g_report, err)) {
            std::cerr << "[+] Wrote binary report " << opt.binary_output.string() << "\n";
        } else {
            std::cerr << "[-] " << err << "\n";
        }
    }
    if (!opt.output.empty()) {
        writeReport(opt.output);
    }

    std::cerr << "[!] Exiting...\n";
    return 0;
}
