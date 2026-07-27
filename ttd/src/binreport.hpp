#ifndef BINREPORT_HPP
#define BINREPORT_HPP

// A binary report format for consumers that load the whole thing and browse it, as
// opposed to capa, which wants the JSON.
//
// Why: on a 3.4M-call trace the JSON report costs about 50s to serialise and 16.6s to
// load back (8.9s of QJsonDocument parse plus 7.6s building per-call objects), against a
// 30s sweep and 138ms of actual disk I/O. Two thirds of the wall clock was the format.
// Nothing about that is inherent -- it is text formatting, hex encoding, and allocating
// several million small objects.
//
// This layout is designed to be memory-mapped and read in place: fixed-size call records
// indexable by row, a deduplicated string table for the names that repeat (a trace has
// millions of calls but only thousands of distinct module!api pairs), raw bytes instead
// of hex, positions as two integers instead of "45905:15A5", and a per-call lowercased
// search haystack so a filter is a scan over mapped pages rather than something that has
// to be built first. Loading becomes a header validation; nothing is parsed and nothing
// is allocated per call.
//
// All integers are little-endian. All offsets are byte offsets from the start of the
// file, so a mapped view needs no fixups.

#include <cstdint>
#include <filesystem>
#include <string>

#include "ttdutils.hpp"
#include "utils.hpp"  // Report

namespace ttdcapa {

    namespace binreport {

        constexpr char kMagic[8] = { 'T', 'T', 'D', 'B', 'E', 'H', 'V', '1' };
        constexpr uint32_t kVersion = 1;
        constexpr size_t kHeaderSize = 128;
        constexpr size_t kCallRecordSize = 40;

        enum class Arch : uint32_t {
            X64 = 0,
            X86 = 1,
        };

        // Presence bits in a parameter record's `bits` byte.
        enum ParamBits : uint8_t {
            ParamOut = 0x01,
            ParamAtReturn = 0x02,
            ParamHasDeref = 0x04,
            ParamHasStr = 0x08,
            ParamHasBytes = 0x10,
            ParamHasFlags = 0x20,
        };

        // Set in a call record's paramCount field when the call was decoded from a real
        // signature. Needed separately because a decoded call can legitimately have zero
        // parameters.
        constexpr uint16_t kDecodedFlag = 0x8000;

        // File layout:
        //
        //   [0, 128)              header
        //   [callsOff, ...)       callCount * 40-byte records, in sweep order
        //   [paramsOff, ...)      variable-length parameter records, referenced by call
        //   [stringsOff, ...)     NUL-terminated UTF-8, deduplicated
        //   [blobOff, ...)        search haystacks, parameter strings, buffer bytes
        //
        // Header (offset: type name):
        //    0: char[8]  magic
        //    8: u32      version
        //   12: u32      arch
        //   16: u64      callCount
        //   24: u64      paramBytes      (size of the parameter region)
        //   32: u64      pid
        //   40: u64      callsOff
        //   48: u64      paramsOff
        //   56: u64      stringsOff
        //   64: u64      stringsSize
        //   72: u64      blobOff
        //   80: u64      blobSize
        //   88: u64      decodedCount
        //   96: u64      maxSeq
        //  104: u32      tracePathStr    (offset into the string table)
        //  108: u32      sampleNameStr
        //  112: u32      maxPositionChars
        //  116: u32      reserved
        //  120: u64      reserved
        //
        // Call record (offset: type name):
        //    0: u64  ret
        //    8: u32  tid
        //   12: u32  positionSequence
        //   16: u32  positionSteps
        //   20: u32  moduleStr
        //   24: u32  apiStr
        //   28: u32  paramOff        (offset into the parameter region, 0 if none)
        //   32: u32  searchOff       (offset into the blob)
        //   36: u16  paramCount      (low 15 bits; kDecodedFlag set when decoded)
        //   38: u16  searchLen
        //
        // Parameter record, variable length:
        //   u8  kind
        //   u8  bits
        //   u32 nameStr
        //   u32 typeStr
        //   u64 value
        //   u64 deref                 if ParamHasDeref
        //   u32 strOff,  u32 strLen   if ParamHasStr
        //   u32 bytesOff, u32 bytesLen, u64 bytesTotal   if ParamHasBytes
        //   u32 flagsOff, u32 flagsLen                   if ParamHasFlags
        //
        // `seq` is not stored: recorded calls are numbered densely from zero in sweep
        // order, so a record's index is its sequence number.

        // Write `g_report` to `path` in the format above. Returns false with `error` set.
        bool write(const std::filesystem::path& path, const Report& report, std::string& error);

    }  // namespace binreport

}  // namespace ttdcapa

#endif
