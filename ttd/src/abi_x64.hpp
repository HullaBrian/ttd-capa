#ifndef ABI_X64_HPP
#define ABI_X64_HPP

// The x64 calling-convention decoder.
//
// The Win32 metadata gives us types and semantics; mapping those onto registers
// and stack slots is ours to write (WIN32JSON-TTD-INTEGRATION-NOTES.md section 3).
// That's this file: given a signature and a thread's register state at a CALL,
// produce one DecodedArg per real parameter -- no more, no less.
//
// Microsoft x64 in one paragraph: the first four parameters go in RCX/RDX/R8/R9,
// or XMM0-3 if they're floating point. Crucially the slot index is *shared* between
// the two register files, so a float in position 2 lives in XMM2, not XMM0.
// Parameters five and up sit at [RSP+0x28] onwards, above the 32-byte shadow space
// the caller must reserve. Aggregates that aren't exactly 1/2/4/8 bytes are passed
// by hidden pointer, and a function returning one takes an extra hidden first
// parameter -- the indexer pre-computes both, so `slot` here is always final.

#include <cstdint>
#include <vector>

#include <TTD/IReplayEngineStl.h>
#include <TTD/IReplayEngineRegisters.h>

#include "ttdutils.hpp"
#include "win32meta.hpp"

namespace ttdcapa {

    struct DecodeOptions {
        size_t max_buffer = 256;   // bytes of any one counted buffer to keep
        size_t max_string = 512;   // characters of any one string to keep
    };

    // Decode every parameter of `sig` from the register state at the call.
    // Dereferences that only make sense once the callee has run are appended to
    // `deferred` instead; feed those to resolvePendingOuts at the return.
    void decodeArgs(const win32meta::FuncSig& sig,
                    const AMD64_CONTEXT& ctx,
                    TTD::Replay::IThreadView const* thread,
                    const DecodeOptions& opt,
                    std::vector<DecodedArg>& out,
                    std::vector<PendingOut>& deferred);

    // Re-read the deferred dereferences at the return position and patch them into
    // `args` (which must be the vector decodeArgs filled in for this same call).
    void resolvePendingOuts(const std::vector<PendingOut>& pending,
                            TTD::Replay::IThreadView const* thread,
                            const DecodeOptions& opt,
                            std::vector<DecodedArg>& args);

    // Flatten decoded parameters into the int/string list capa matches rules
    // against. Strings recovered from [Out] parameters are included -- they are
    // genuine new evidence; symbolic enum names are not, so rules that match flags
    // numerically keep working.
    std::vector<ArgValue> toCapaArgs(const std::vector<DecodedArg>& args);

}  // namespace ttdcapa

#endif
