#include "abi.hpp"

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

        // Every x86 stack argument occupies a whole number of 4-byte words.
        constexpr uint16_t kX86StackAlign = 4;

        // Matches win32meta's MAX_PARAMS; the index never emits more.
        constexpr size_t kMaxParams = 32;

        bool readGuest(TTD::Replay::IThreadView const* thread, uint64_t addr, void* dst, size_t size) {
            if (addr < kMinDerefAddr || size == 0) {
                return false;
            }
            auto result = thread->QueryMemoryBuffer(TTD::GuestAddress{ addr }, TTD::BufferView{ dst, size });
            return result.Memory.Size == size;
        }

        // True for the kinds that are a pointer in the guest, whatever they point at.
        bool isPointerKind(ArgKind kind) {
            switch (kind) {
                case ArgKind::AnsiString:
                case ArgKind::WideString:
                case ArgKind::AnsiBuffer:
                case ArgKind::WideBuffer:
                case ArgKind::ByteBuffer:
                case ArgKind::PtrToInt:
                case ArgKind::StructPtr:
                case ArgKind::FuncPtr:
                case ArgKind::Guid:
                case ArgKind::Pointer:
                case ArgKind::PtrToAnsiString:
                case ArgKind::PtrToWideString:
                case ArgKind::Handle:  // opaque but pointer-sized
                    return true;
                default:
                    return false;
            }
        }

        // An aggregate the x64 ABI passes by hidden pointer but x86 pushes by value.
        // The index cannot tell us its x86 footprint -- it records the x64 size, which
        // is wrong for any struct holding a pointer -- so its presence makes the whole
        // signature unlayoutable on x86. The display type is the discriminator: a real
        // pointer parameter renders as "OVERLAPPED*", a by-value one as "VARIANT".
        bool isByValueAggregate(const win32meta::ParamSig& p) {
            if (p.kind != ArgKind::StructPtr) {
                return false;
            }
            size_t len = p.type != nullptr ? std::strlen(p.type) : 0;
            return len == 0 || p.type[len - 1] != '*';
        }

        // Bytes one parameter occupies on the x86 argument stack, or 0 if unknowable.
        uint16_t x86StackFootprint(const win32meta::ParamSig& p) {
            if (isByValueAggregate(p)) {
                return 0;
            }
            uint16_t size = 4;
            switch (p.kind) {
                case ArgKind::Float:
                    size = 4;
                    break;
                case ArgKind::Double:
                    size = 8;
                    break;
                case ArgKind::Integer:
                case ArgKind::Enum:
                case ArgKind::Bool:
                    // For scalars the index stores the value's own width here -- but
                    // computed for x64, where a pointer-sized scalar (UIntPtr, and the
                    // SIZE_T/WPARAM/LPARAM typedefs over it) is 8 bytes and on x86 is
                    // 4. An 8 here is therefore ambiguous: Int64 really does push 8
                    // bytes on x86, UIntPtr pushes 4, and the index cannot tell us
                    // which. Guessing would silently shift every later parameter, so
                    // decline and let the caller fall back to the heuristic.
                    //
                    // Resolving this properly means having the builder emit the x86
                    // footprint alongside the x64 one; there is a spare pad byte in the
                    // parameter record for it.
                    if (p.pointeeSize == 8) {
                        return 0;
                    }
                    size = (p.pointeeSize >= 1 && p.pointeeSize < 8) ? p.pointeeSize : 4;
                    break;
                default:
                    size = 4;  // pointers, handles, and anything unclassified
                    break;
            }
            return static_cast<uint16_t>((size + kX86StackAlign - 1) / kX86StackAlign * kX86StackAlign);
        }

        // Byte offset of each parameter from the first argument on the x86 stack.
        // Returns false when any parameter's footprint is unknown, in which case every
        // offset after it would be wrong and the signature must not be used.
        bool computeStackOffsets(const win32meta::FuncSig& sig, uint16_t (&offsets)[kMaxParams]) {
            // `slot` is the positional ABI index and is already shifted for a hidden
            // return pointer, which on x86 is simply the first pushed argument. Walk in
            // slot order so a shifted signature still lays out correctly.
            uint16_t running[kMaxParams] = {};
            uint16_t footprint[kMaxParams] = {};
            uint8_t maxSlot = 0;

            for (uint8_t i = 0; i < sig.paramCount && i < kMaxParams; ++i) {
                const win32meta::ParamSig& p = sig.params[i];
                if (p.slot >= kMaxParams) {
                    return false;
                }
                uint16_t bytes = x86StackFootprint(p);
                if (bytes == 0) {
                    return false;
                }
                footprint[p.slot] = bytes;
                maxSlot = p.slot > maxSlot ? p.slot : maxSlot;
            }

            // A hidden return pointer occupies slot 0 without appearing in the
            // parameter list, so fill any gap with a pointer-sized push.
            uint16_t offset = 0;
            for (uint8_t s = 0; s <= maxSlot && s < kMaxParams; ++s) {
                running[s] = offset;
                offset += footprint[s] != 0 ? footprint[s] : kX86StackAlign;
            }

            for (uint8_t i = 0; i < sig.paramCount && i < kMaxParams; ++i) {
                offsets[i] = running[sig.params[i].slot];
            }
            return true;
        }

        // The value of parameter `index`, from wherever its architecture puts it.
        uint64_t fetchArg(const CallFrame& frame, const win32meta::FuncSig& sig, uint8_t index,
                          const uint16_t (&x86Offsets)[kMaxParams], bool& ok) {
            const win32meta::ParamSig& p = sig.params[index];
            ok = true;

            if (frame.arch == GuestArch::X86) {
                // At the callee's first instruction ESP points at the return address,
                // so the arguments begin one word above it.
                uint64_t addr = static_cast<uint64_t>(frame.x86->Esp) + kX86StackAlign + x86Offsets[index];
                uint64_t v = 0;
                size_t width = p.kind == ArgKind::Double ? 8 : 4;
                ok = readGuest(frame.thread, addr, &v, width);
                return v;
            }

            const AMD64_CONTEXT& ctx = *frame.x64;
            if (p.slot < 4) {
                if (p.isFloat()) {
                    const M128BIT* xmm[4] = { &ctx.Xmm0, &ctx.Xmm1, &ctx.Xmm2, &ctx.Xmm3 };
                    return xmm[p.slot]->Low;
                }
                const uint64_t gpr[4] = { ctx.Rcx, ctx.Rdx, ctx.R8, ctx.R9 };
                return gpr[p.slot];
            }
            // Above the shadow space the caller reserved for RCX/RDX/R8/R9.
            uint64_t addr = ctx.Rsp + 0x28 + static_cast<uint64_t>(p.slot - 4) * 8;
            uint64_t v = 0;
            ok = readGuest(frame.thread, addr, &v, sizeof(v));
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

        // `fallbackWidth` is what to read when the metadata did not pin the pointee
        // down -- the guest's pointer width, since an untyped pointee is usually one.
        bool derefScalar(TTD::Replay::IThreadView const* thread, uint64_t ptr, uint16_t size,
                         uint16_t fallbackWidth, uint64_t& out) {
            uint16_t width = size == 0 ? fallbackWidth : (size > 8 ? 8 : size);
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

        // Everything that needs a pointer followed. Shared by the entry pass (for
        // [In] parameters, which are already valid) and the return pass.
        void dereference(TTD::Replay::IThreadView const* thread, const DecodeOptions& opt,
                         ArgKind kind, uint64_t ptr, uint16_t pointeeSize, uint16_t pointerSize,
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
                    if (derefScalar(thread, ptr, pointeeSize, pointerSize, v)) {
                        arg.deref = v;
                        arg.has_deref = true;
                    }
                    break;
                }
                case ArgKind::PtrToAnsiString:
                case ArgKind::PtrToWideString: {
                    // The pointee here is itself a pointer, so its width is the guest's.
                    uint64_t inner = 0;
                    if (!derefScalar(thread, ptr, pointerSize, pointerSize, inner)) {
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

    bool x86StackLayout(const win32meta::FuncSig& sig, std::vector<uint16_t>& offsets) {
        offsets.clear();
        if (sig.paramCount > kMaxParams) {
            return false;
        }
        uint16_t computed[kMaxParams] = {};
        if (!computeStackOffsets(sig, computed)) {
            return false;
        }
        offsets.assign(computed, computed + sig.paramCount);
        return true;
    }

    bool decodeArgs(const win32meta::FuncSig& sig,
                    const CallFrame& frame,
                    const DecodeOptions& opt,
                    std::vector<DecodedArg>& out,
                    std::vector<PendingOut>& deferred) {
        if (sig.paramCount > kMaxParams) {
            return false;
        }
        if ((frame.arch == GuestArch::X64 && frame.x64 == nullptr)
            || (frame.arch == GuestArch::X86 && frame.x86 == nullptr)) {
            return false;
        }

        uint16_t x86Offsets[kMaxParams] = {};
        if (frame.arch == GuestArch::X86 && !computeStackOffsets(sig, x86Offsets)) {
            return false;
        }

        const uint16_t pointerSize = frame.pointerSize();
        TTD::Replay::IThreadView const* thread = frame.thread;

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
            arg.raw = fetchArg(frame, sig, i, x86Offsets, ok);
            if (!ok) {
                // Stack slot we couldn't read: leave it zero rather than invent one.
                arg.raw = 0;
            }
            // A 32-bit guest's pointers and handles are 4 bytes; anything above that
            // in the word we read is not part of the value.
            if (pointerSize == 4 && isPointerKind(p.kind)) {
                arg.raw &= 0xFFFFFFFFull;
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
                dereference(thread, opt, p.kind, arg.raw, p.pointeeSize, pointerSize, byteCount, arg);
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
        return true;
    }

    void resolvePendingOuts(const std::vector<PendingOut>& pending,
                            const CallFrame& frame,
                            const DecodeOptions& opt,
                            std::vector<DecodedArg>& args) {
        const uint16_t pointerSize = frame.pointerSize();
        TTD::Replay::IThreadView const* thread = frame.thread;

        // Scalars first: a buffer's real length is usually itself an [Out] scalar
        // (ReadFile's lpNumberOfBytesRead), so it has to be resolved before the
        // buffer that depends on it.
        for (const PendingOut& po : pending) {
            if (po.param_index >= args.size() || isBufferKind(po.kind)) {
                continue;
            }
            DecodedArg& arg = args[po.param_index];
            DecodedArg fresh;
            dereference(thread, opt, po.kind, po.ptr, po.pointee_size, pointerSize, 0, fresh);
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
