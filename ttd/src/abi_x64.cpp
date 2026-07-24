#include "abi_x64.hpp"

#include <cstdio>
#include <cstring>

using ttdcapa::win32meta::ArgKind;
using ttdcapa::win32meta::AuxKind;

namespace ttdcapa {
    namespace {

        // A dereference is only worth attempting above the first 64 KiB; the null
        // page and its neighbours are never mapped in user mode.
        constexpr uint64_t kMinDerefAddr = 0x10000;

        // Guards against a mis-typed count parameter turning into a huge read.
        constexpr uint64_t kMaxCountElements = 1u << 20;

        bool readGuest(TTD::Replay::IThreadView const* thread, uint64_t addr, void* dst, size_t size) {
            if (addr < kMinDerefAddr || size == 0) {
                return false;
            }
            auto result = thread->QueryMemoryBuffer(TTD::GuestAddress{ addr }, TTD::BufferView{ dst, size });
            return result.Memory.Size == size;
        }

        // The value in `slot`, honouring the shared integer/SSE slot numbering.
        uint64_t fetchSlot(const AMD64_CONTEXT& ctx, TTD::Replay::IThreadView const* thread,
                           uint8_t slot, bool isFloat, bool& ok) {
            ok = true;
            if (slot < 4) {
                if (isFloat) {
                    const M128BIT* xmm[4] = { &ctx.Xmm0, &ctx.Xmm1, &ctx.Xmm2, &ctx.Xmm3 };
                    return xmm[slot]->Low;
                }
                const uint64_t gpr[4] = { ctx.Rcx, ctx.Rdx, ctx.R8, ctx.R9 };
                return gpr[slot];
            }
            // Above the shadow space the caller reserved for RCX/RDX/R8/R9.
            uint64_t addr = ctx.Rsp + 0x28 + static_cast<uint64_t>(slot - 4) * 8;
            uint64_t v = 0;
            ok = readGuest(thread, addr, &v, sizeof(v));
            return v;
        }

        double floatValue(const win32meta::ParamSig& p, uint64_t bits) {
            if (p.kind == ArgKind::Float) {
                float f = 0.0f;
                uint32_t lo = static_cast<uint32_t>(bits);
                std::memcpy(&f, &lo, sizeof(f));
                return static_cast<double>(f);
            }
            double d = 0.0;
            std::memcpy(&d, &bits, sizeof(d));
            return d;
        }

        // Widen a pointee of `size` bytes to 64 bits.
        uint64_t narrowRead(const uint8_t* raw, uint16_t size) {
            uint64_t v = 0;
            std::memcpy(&v, raw, size > 8 ? 8 : size);
            return v;
        }

        bool derefScalar(TTD::Replay::IThreadView const* thread, uint64_t ptr, uint16_t size, uint64_t& out) {
            uint16_t width = size == 0 ? 8 : (size > 8 ? 8 : size);
            uint8_t buf[8] = {};
            if (!readGuest(thread, ptr, buf, width)) {
                return false;
            }
            out = narrowRead(buf, width);
            return true;
        }

        std::string formatGuid(const uint8_t* b) {
            char buf[40];
            std::snprintf(buf, sizeof(buf),
                          "{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                          static_cast<unsigned long>(narrowRead(b, 4)),
                          static_cast<unsigned>(narrowRead(b + 4, 2)),
                          static_cast<unsigned>(narrowRead(b + 6, 2)),
                          b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
            return buf;
        }

        bool isBufferKind(ArgKind kind) {
            return kind == ArgKind::AnsiBuffer || kind == ArgKind::WideBuffer || kind == ArgKind::ByteBuffer;
        }

        // How many bytes a counted buffer parameter spans, or 0 when we can't tell.
        // `args` supplies the sibling parameter the count lives in -- after a return
        // pass those may themselves have been filled in, which is exactly what makes
        // ReadFile's lpBuffer renderable at its *actual* length.
        uint64_t resolveByteCount(const win32meta::ParamSig& p, const std::vector<DecodedArg>& args) {
            uint64_t count = 0;
            switch (p.auxKind) {
                case AuxKind::CountConst:
                    count = static_cast<uint64_t>(p.auxValue);
                    break;
                case AuxKind::BytesFromParam:
                case AuxKind::CountFromParam: {
                    if (p.auxValue < 0 || static_cast<size_t>(p.auxValue) >= args.size()) {
                        return 0;
                    }
                    const DecodedArg& src = args[static_cast<size_t>(p.auxValue)];
                    count = src.has_deref ? src.deref : src.raw;
                    break;
                }
                case AuxKind::None:
                default:
                    return 0;
            }
            if (count == 0 || count > kMaxCountElements) {
                return 0;
            }
            if (p.auxKind == AuxKind::BytesFromParam) {
                return count;
            }
            uint16_t elem = p.pointeeSize ? p.pointeeSize : 1;
            return count * elem;
        }

        // Length of `buf` up to and including its first `charWidth`-wide NUL. A
        // character buffer's count parameter is the caller's *capacity*, so without
        // this the report would carry a few hundred bytes of unrelated stack memory
        // after every out-string.
        size_t terminatorEnd(const std::vector<uint8_t>& buf, size_t charWidth) {
            for (size_t i = 0; i + charWidth <= buf.size(); i += charWidth) {
                bool nul = true;
                for (size_t k = 0; k < charWidth; ++k) {
                    if (buf[i + k] != 0) {
                        nul = false;
                        break;
                    }
                }
                if (nul) {
                    return i + charWidth;
                }
            }
            return buf.size();
        }

        // Read a counted buffer into `arg`, capped at opt.max_buffer. Character
        // buffers additionally get a textual rendering, since that's what a rule or
        // an analyst actually wants to see.
        void captureBuffer(TTD::Replay::IThreadView const* thread, const DecodeOptions& opt,
                           ArgKind kind, uint64_t ptr, uint64_t byteCount, DecodedArg& arg) {
            if (ptr < kMinDerefAddr || byteCount == 0) {
                return;
            }
            size_t want = static_cast<size_t>(byteCount < opt.max_buffer ? byteCount : opt.max_buffer);
            std::vector<uint8_t> buf(want);
            auto result = thread->QueryMemoryBuffer(TTD::GuestAddress{ ptr }, TTD::BufferView{ buf.data(), want });
            size_t got = result.Memory.Size;
            if (got == 0) {
                return;
            }
            buf.resize(got);

            if (kind == ArgKind::AnsiBuffer) {
                if (auto s = readAnsiString(thread, ptr, got)) {
                    arg.str = std::move(*s);
                    arg.has_str = !arg.str.empty();
                }
                buf.resize(terminatorEnd(buf, 1));
            } else if (kind == ArgKind::WideBuffer) {
                if (auto s = readWideString(thread, ptr, got / sizeof(wchar_t))) {
                    arg.str = std::move(*s);
                    arg.has_str = !arg.str.empty();
                }
                buf.resize(terminatorEnd(buf, 2));
            }
            arg.bytes = std::move(buf);
        }

        // Everything that needs the callee to have run. Shared by the entry pass
        // (for [In] parameters, which are already valid) and the return pass.
        void dereference(TTD::Replay::IThreadView const* thread, const DecodeOptions& opt,
                         ArgKind kind, uint64_t ptr, uint16_t pointeeSize,
                         uint64_t byteCount, DecodedArg& arg) {
            switch (kind) {
                case ArgKind::AnsiString:
                    if (auto s = readAnsiString(thread, ptr, opt.max_string)) {
                        arg.str = std::move(*s);
                        arg.has_str = true;
                    }
                    break;
                case ArgKind::WideString:
                    if (auto s = readWideString(thread, ptr, opt.max_string)) {
                        arg.str = std::move(*s);
                        arg.has_str = true;
                    }
                    break;
                case ArgKind::PtrToInt: {
                    uint64_t v = 0;
                    if (derefScalar(thread, ptr, pointeeSize, v)) {
                        arg.deref = v;
                        arg.has_deref = true;
                    }
                    break;
                }
                case ArgKind::PtrToAnsiString:
                case ArgKind::PtrToWideString: {
                    uint64_t inner = 0;
                    if (!derefScalar(thread, ptr, 8, inner)) {
                        break;
                    }
                    arg.deref = inner;
                    arg.has_deref = true;
                    auto s = (kind == ArgKind::PtrToAnsiString)
                        ? readAnsiString(thread, inner, opt.max_string)
                        : readWideString(thread, inner, opt.max_string);
                    if (s) {
                        arg.str = std::move(*s);
                        arg.has_str = true;
                    }
                    break;
                }
                case ArgKind::Guid: {
                    uint8_t g[16] = {};
                    if (readGuest(thread, ptr, g, sizeof(g))) {
                        arg.str = formatGuid(g);
                        arg.has_str = true;
                    }
                    break;
                }
                case ArgKind::AnsiBuffer:
                case ArgKind::WideBuffer:
                case ArgKind::ByteBuffer:
                    captureBuffer(thread, opt, kind, ptr, byteCount, arg);
                    break;
                default:
                    break;
            }
        }

        // Some parameters are pointers whose pointee the metadata can't pin down:
        // opaque void*, and the raw UInt16*/UIntPtr* that RPC uses for RPC_WSTR.
        // For those the old guess-if-it-looks-like-text heuristic is still the best
        // information available -- and unlike before, we now only apply it to values
        // we know really are parameters and really are pointers.
        bool mayHoldUntypedString(ArgKind kind) {
            return kind == ArgKind::Pointer || kind == ArgKind::Unknown || kind == ArgKind::PtrToInt;
        }

        void tryUntypedString(TTD::Replay::IThreadView const* thread, DecodedArg& arg) {
            if (arg.has_str || !mayHoldUntypedString(arg.kind)) {
                return;
            }
            if (auto s = tryReadString(thread, arg.raw)) {
                arg.str = std::move(*s);
                arg.has_str = true;
                return;
            }
            // A T** out-parameter: the string lives one more hop away.
            if (arg.has_deref) {
                if (auto s = tryReadString(thread, arg.deref)) {
                    arg.str = std::move(*s);
                    arg.has_str = true;
                }
            }
        }

        bool needsDeref(ArgKind kind) {
            switch (kind) {
                case ArgKind::AnsiString:
                case ArgKind::WideString:
                case ArgKind::PtrToInt:
                case ArgKind::PtrToAnsiString:
                case ArgKind::PtrToWideString:
                case ArgKind::Guid:
                case ArgKind::AnsiBuffer:
                case ArgKind::WideBuffer:
                case ArgKind::ByteBuffer:
                    return true;
                default:
                    return false;
            }
        }

    }  // namespace

    void decodeArgs(const win32meta::FuncSig& sig,
                    const AMD64_CONTEXT& ctx,
                    TTD::Replay::IThreadView const* thread,
                    const DecodeOptions& opt,
                    std::vector<DecodedArg>& out,
                    std::vector<PendingOut>& deferred) {
        out.clear();
        out.resize(sig.paramCount);

        // Pass 1: capture every raw slot first. A buffer's length can live in a
        // parameter that comes *after* it (ReadFile's lpBuffer refers forward to
        // nNumberOfBytesToRead), so no dereferencing until all the scalars are in.
        for (uint8_t i = 0; i < sig.paramCount; ++i) {
            const win32meta::ParamSig& p = sig.params[i];
            DecodedArg& arg = out[i];
            arg.name = p.name;
            arg.type = p.type;
            arg.kind = p.kind;
            arg.enum_index = p.enumIndex;
            arg.is_out = p.isOut();

            bool ok = false;
            arg.raw = fetchSlot(ctx, thread, p.slot, p.isFloat(), ok);
            if (!ok) {
                // Stack slot we couldn't read: leave it zero rather than invent one.
                arg.raw = 0;
            }
            if (p.isFloat()) {
                arg.fval = floatValue(p, arg.raw);
                arg.has_fval = true;
            }
        }

        // Pass 2: dereference. Scalars and handles are deliberately untouched --
        // that alone removes most of the bogus String features the old heuristic
        // produced from flag values that happened to look like addresses.
        for (uint8_t i = 0; i < sig.paramCount; ++i) {
            const win32meta::ParamSig& p = sig.params[i];
            DecodedArg& arg = out[i];
            if (!needsDeref(p.kind)) {
                tryUntypedString(thread, arg);
                continue;
            }

            uint64_t byteCount = isBufferKind(p.kind) ? resolveByteCount(p, out) : 0;

            // [In] contents are already valid here. [In,Out] gets read twice: once
            // now for what the caller passed, then again at the return.
            if (p.isIn()) {
                dereference(thread, opt, p.kind, arg.raw, p.pointeeSize, byteCount, arg);
                tryUntypedString(thread, arg);
            }
            if (p.isOut() && arg.raw >= kMinDerefAddr) {
                PendingOut pending;
                pending.param_index = i;
                pending.kind = p.kind;
                pending.ptr = arg.raw;
                pending.pointee_size = p.pointeeSize;
                pending.aux_kind = p.auxKind;
                pending.aux_value = p.auxValue;
                pending.in_cap = byteCount;
                deferred.push_back(pending);
            }
        }
    }

    void resolvePendingOuts(const std::vector<PendingOut>& pending,
                            TTD::Replay::IThreadView const* thread,
                            const DecodeOptions& opt,
                            std::vector<DecodedArg>& args) {
        // Scalars first: a buffer's real length is usually itself an [Out] scalar
        // (ReadFile's lpNumberOfBytesRead), so it has to be resolved before the
        // buffer that depends on it.
        for (const PendingOut& po : pending) {
            if (po.param_index >= args.size() || isBufferKind(po.kind)) {
                continue;
            }
            DecodedArg& arg = args[po.param_index];
            DecodedArg fresh;
            dereference(thread, opt, po.kind, po.ptr, po.pointee_size, 0, fresh);
            if (fresh.has_deref || fresh.has_str) {
                fresh.name = arg.name;
                fresh.type = arg.type;
                fresh.kind = arg.kind;
                fresh.enum_index = arg.enum_index;
                fresh.raw = arg.raw;
                fresh.is_out = true;
                fresh.from_return = true;
                arg = std::move(fresh);
            }
            tryUntypedString(thread, arg);
        }

        for (const PendingOut& po : pending) {
            if (po.param_index >= args.size() || !isBufferKind(po.kind)) {
                continue;
            }
            DecodedArg& arg = args[po.param_index];

            // Prefer the length the callee reported; fall back to what the caller
            // offered, and never exceed it.
            win32meta::ParamSig probe;
            probe.auxKind = po.aux_kind;
            probe.auxValue = po.aux_value;
            probe.pointeeSize = po.pointee_size;
            uint64_t byteCount = resolveByteCount(probe, args);
            if (byteCount == 0) {
                byteCount = po.in_cap;
            } else if (po.in_cap != 0 && byteCount > po.in_cap) {
                byteCount = po.in_cap;
            }
            if (byteCount == 0) {
                continue;
            }

            DecodedArg fresh;
            captureBuffer(thread, opt, po.kind, po.ptr, byteCount, fresh);
            if (!fresh.bytes.empty() || fresh.has_str) {
                arg.bytes = std::move(fresh.bytes);
                arg.str = std::move(fresh.str);
                arg.has_str = fresh.has_str;
                arg.from_return = true;
            }
        }
    }

    std::vector<ArgValue> toCapaArgs(const std::vector<DecodedArg>& args) {
        std::vector<ArgValue> out;
        out.reserve(args.size());
        for (const DecodedArg& a : args) {
            if (a.has_str && !a.str.empty()) {
                out.push_back(a.str);
            } else {
                out.push_back(static_cast<int64_t>(a.raw));
            }
        }
        return out;
    }

}  // namespace ttdcapa
