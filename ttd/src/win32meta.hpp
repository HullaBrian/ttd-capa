#ifndef WIN32META_HPP
#define WIN32META_HPP

// Loader for the pre-baked Win32 API metadata index (win32-index.bin) produced by
// tools/build-win32-index.py from the win32json submodule.
//
// The index answers one question per recorded call: "given this export name, what
// are its parameters?" -- count, names, types, direction, and how to decode each
// one. That turns the extractor's blind 4-register grab into an exact capture.
//
// Lookup is keyed on the bare function name. Module is carried for display only:
// API sets mean the metadata's "CreateFileW -> KERNEL32.dll" shows up in a trace as
// KERNELBASE.dll!CreateFileW, so matching on module would lose most calls.
// See WIN32JSON-TTD-INTEGRATION-NOTES.md section 4.

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace ttdcapa::win32meta {

    // How to decode one parameter. Values must match the K_* constants in
    // tools/build-win32-index.py.
    enum class ArgKind : uint8_t {
        Unknown = 0,
        Integer,           // plain scalar, never dereferenced
        Bool,
        Handle,            // opaque HANDLE/HKEY/HWND; pointer-sized but not a pointer
        Enum,              // scalar with a symbolic value table (see enumIndex)
        Float,             // 4-byte float, arrives in XMM<slot>
        Double,            // 8-byte float, arrives in XMM<slot>
        AnsiString,        // char*, NUL-terminated
        WideString,        // wchar_t*, NUL-terminated
        AnsiBuffer,        // char[], length from aux
        WideBuffer,        // wchar_t[], length from aux
        ByteBuffer,        // void*/byte[], length from aux
        PtrToInt,          // pointer to a pointeeSize-byte scalar
        StructPtr,         // pointer to a struct/union (not expanded in v1)
        FuncPtr,
        Guid,              // pointer to a 16-byte GUID
        Pointer,           // opaque pointer, contents unknown
        PtrToAnsiString,   // char** -- out-param that receives an allocated string
        PtrToWideString,   // wchar_t**
    };

    // Bitmask of a parameter's direction/nullability attributes.
    enum ParamAttr : uint8_t {
        AttrIn = 0x01,
        AttrOut = 0x02,
        AttrOptional = 0x04,
        AttrConst = 0x08,
        AttrReserved = 0x10,
        AttrNotNulTerminated = 0x20,
        AttrNulNulTerminated = 0x40,
        AttrComOutPtr = 0x80,
    };

    // Where a buffer parameter's length comes from.
    enum class AuxKind : uint8_t {
        None = 0,
        BytesFromParam,   // auxValue is the index of a parameter holding a byte count
        CountFromParam,   // auxValue is the index of a parameter holding an element count
        CountConst,       // auxValue is the element count itself
    };

    enum FuncFlag : uint8_t {
        FlagHiddenRetPtr = 0x01,  // returns a large aggregate; RCX is the hidden return buffer
        FlagUnsupported = 0x02,   // at least one parameter could not be classified
        FlagSetLastError = 0x04,
    };

    struct ParamSig {
        const char* name = "";
        const char* type = "";
        ArgKind kind = ArgKind::Unknown;
        uint8_t attrs = 0;
        uint8_t slot = 0;          // positional ABI slot, already shifted for FlagHiddenRetPtr
        AuxKind auxKind = AuxKind::None;
        int32_t auxValue = 0;
        uint32_t enumIndex = 0xFFFFFFFFu;
        uint16_t pointeeSize = 0;  // bytes per pointee/element, 0 if unknown

        bool isIn() const { return (attrs & AttrIn) != 0; }
        bool isOut() const { return (attrs & AttrOut) != 0; }
        bool isFloat() const { return kind == ArgKind::Float || kind == ArgKind::Double; }
        bool hasEnum() const { return enumIndex != 0xFFFFFFFFu; }
    };

    struct FuncSig {
        const char* name = "";
        const char* dll = "";
        const ParamSig* params = nullptr;
        uint8_t paramCount = 0;
        uint8_t flags = 0;

        bool unsupported() const { return (flags & FlagUnsupported) != 0; }
        bool hiddenRetPtr() const { return (flags & FlagHiddenRetPtr) != 0; }
    };

    // Loaded once at startup and read-only thereafter, so the replay sweep can hit
    // it from the call callback without synchronisation.
    class Index {
    public:
        bool load(const std::filesystem::path& path, std::string& error);
        bool loaded() const { return !funcs_.empty(); }
        size_t functionCount() const { return funcs_.size(); }
        const std::filesystem::path& path() const { return path_; }

        // Bare export name, e.g. "CreateFileW". Returns nullptr when unknown, which
        // is the caller's cue to fall back to the heuristic capture.
        const FuncSig* lookup(std::string_view api) const;

        const char* enumName(uint32_t enumIndex) const;

        // Symbolic names for `value`: an exact match if one exists, otherwise a
        // greedy bit decomposition for flag enums. Empty when nothing matches.
        std::vector<std::string> decodeEnum(uint32_t enumIndex, uint64_t value) const;

    private:
        struct EnumTable {
            const char* name = "";
            uint32_t valueOffset = 0;
            uint32_t valueCount = 0;
            bool isFlags = false;
            uint8_t width = 4;
        };
        struct EnumValue {
            const char* name = "";
            int64_t value = 0;
        };

        std::vector<uint8_t> blob_;
        std::vector<FuncSig> funcs_;
        std::vector<ParamSig> params_;
        std::vector<EnumTable> enums_;
        std::vector<EnumValue> enumValues_;
        std::unordered_map<std::string_view, uint32_t> byName_;
        std::filesystem::path path_;
    };

    // Process-wide instance; empty until loadIndex() succeeds.
    Index& index();

    // Try `explicitPath` if non-empty, else the conventional locations next to the
    // executable and in the source tree. Returns false with `error` set; the caller
    // is expected to warn and continue in heuristic mode.
    bool loadIndex(const std::filesystem::path& explicitPath, std::string& error);

    const char* kindName(ArgKind kind);

}  // namespace ttdcapa::win32meta

#endif
