#include "win32meta.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <algorithm>
#include <cstring>
#include <fstream>

namespace ttdcapa::win32meta {
    namespace {
        constexpr char kMagic[8] = { 'W', '3', '2', 'I', 'D', 'X', '0', '1' };
        constexpr uint32_t kFormatVersion = 1;

        // Record sizes must match the struct.pack formats in tools/build-win32-index.py.
        constexpr size_t kHeaderSize = 32;
        constexpr size_t kFuncRecSize = 16;
        constexpr size_t kParamRecSize = 24;
        constexpr size_t kEnumRecSize = 16;
        constexpr size_t kEnumValRecSize = 16;

        template <typename T>
        T readAt(const uint8_t* p, size_t off) {
            T v{};
            std::memcpy(&v, p + off, sizeof(T));
            return v;
        }

        int popcount64(uint64_t v) {
            int n = 0;
            while (v) {
                v &= v - 1;
                ++n;
            }
            return n;
        }
    }  // namespace

    bool Index::load(const std::filesystem::path& path, std::string& error) {
        std::ifstream f(path, std::ios::binary);
        if (!f) {
            error = "cannot open index";
            return false;
        }
        std::vector<uint8_t> blob((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        if (blob.size() < kHeaderSize || std::memcmp(blob.data(), kMagic, sizeof(kMagic)) != 0) {
            error = "not a win32 index file (bad magic)";
            return false;
        }

        const uint8_t* p = blob.data();
        uint32_t version = readAt<uint32_t>(p, 8);
        if (version != kFormatVersion) {
            error = "index format version " + std::to_string(version) +
                    ", expected " + std::to_string(kFormatVersion) + " (regenerate with tools/build-win32-index.py)";
            return false;
        }

        uint32_t funcCount = readAt<uint32_t>(p, 12);
        uint32_t paramCount = readAt<uint32_t>(p, 16);
        uint32_t enumCount = readAt<uint32_t>(p, 20);
        uint32_t enumValCount = readAt<uint32_t>(p, 24);
        uint32_t strtabSize = readAt<uint32_t>(p, 28);

        size_t funcOff = kHeaderSize;
        size_t paramOff = funcOff + static_cast<size_t>(funcCount) * kFuncRecSize;
        size_t enumOff = paramOff + static_cast<size_t>(paramCount) * kParamRecSize;
        size_t enumValOff = enumOff + static_cast<size_t>(enumCount) * kEnumRecSize;
        size_t strOff = enumValOff + static_cast<size_t>(enumValCount) * kEnumValRecSize;
        if (strOff + strtabSize != blob.size()) {
            error = "index is truncated or corrupt";
            return false;
        }
        // Every string offset is dereferenced without a bounds check below, so the
        // pool must be NUL-terminated for that to be safe.
        if (strtabSize == 0 || blob[blob.size() - 1] != 0) {
            error = "index string pool is not NUL-terminated";
            return false;
        }

        blob_ = std::move(blob);
        p = blob_.data();
        const char* strtab = reinterpret_cast<const char*>(p + strOff);
        auto str = [&](uint32_t off) -> const char* {
            return off < strtabSize ? strtab + off : "";
        };

        params_.resize(paramCount);
        for (uint32_t i = 0; i < paramCount; ++i) {
            size_t o = paramOff + static_cast<size_t>(i) * kParamRecSize;
            ParamSig& ps = params_[i];
            ps.name = str(readAt<uint32_t>(p, o));
            ps.type = str(readAt<uint32_t>(p, o + 4));
            ps.kind = static_cast<ArgKind>(p[o + 8]);
            ps.attrs = p[o + 9];
            ps.slot = p[o + 10];
            ps.auxKind = static_cast<AuxKind>(p[o + 11]);
            ps.auxValue = readAt<int32_t>(p, o + 12);
            ps.enumIndex = readAt<uint32_t>(p, o + 16);
            ps.pointeeSize = readAt<uint16_t>(p, o + 20);
            if (ps.enumIndex != 0xFFFFFFFFu && ps.enumIndex >= enumCount) {
                ps.enumIndex = 0xFFFFFFFFu;
            }
        }

        funcs_.resize(funcCount);
        byName_.reserve(funcCount * 2);
        for (uint32_t i = 0; i < funcCount; ++i) {
            size_t o = funcOff + static_cast<size_t>(i) * kFuncRecSize;
            FuncSig& fs = funcs_[i];
            fs.name = str(readAt<uint32_t>(p, o));
            fs.dll = str(readAt<uint32_t>(p, o + 4));
            uint32_t firstParam = readAt<uint32_t>(p, o + 8);
            fs.paramCount = p[o + 12];
            fs.flags = p[o + 13];
            if (static_cast<size_t>(firstParam) + fs.paramCount > params_.size()) {
                error = "index parameter range out of bounds";
                return false;
            }
            fs.params = fs.paramCount ? &params_[firstParam] : nullptr;
            byName_.emplace(std::string_view(fs.name), i);
        }

        enumValues_.resize(enumValCount);
        for (uint32_t i = 0; i < enumValCount; ++i) {
            size_t o = enumValOff + static_cast<size_t>(i) * kEnumValRecSize;
            enumValues_[i].name = str(readAt<uint32_t>(p, o));
            enumValues_[i].value = readAt<int64_t>(p, o + 8);
        }

        enums_.resize(enumCount);
        for (uint32_t i = 0; i < enumCount; ++i) {
            size_t o = enumOff + static_cast<size_t>(i) * kEnumRecSize;
            EnumTable& et = enums_[i];
            et.name = str(readAt<uint32_t>(p, o));
            et.valueOffset = readAt<uint32_t>(p, o + 4);
            et.valueCount = readAt<uint32_t>(p, o + 8);
            et.isFlags = p[o + 12] != 0;
            et.width = p[o + 13];
            if (static_cast<size_t>(et.valueOffset) + et.valueCount > enumValues_.size()) {
                et.valueOffset = 0;
                et.valueCount = 0;
            }
        }

        path_ = path;
        return true;
    }

    const FuncSig* Index::lookup(std::string_view api) const {
        auto it = byName_.find(api);
        return it == byName_.end() ? nullptr : &funcs_[it->second];
    }

    const char* Index::enumName(uint32_t enumIndex) const {
        return enumIndex < enums_.size() ? enums_[enumIndex].name : "";
    }

    std::vector<std::string> Index::decodeEnum(uint32_t enumIndex, uint64_t value) const {
        std::vector<std::string> out;
        if (enumIndex >= enums_.size()) {
            return out;
        }
        const EnumTable& et = enums_[enumIndex];
        // The captured value is a full 64-bit register; mask to the enum's real width
        // so sign-extension and upper garbage don't defeat the comparisons.
        uint64_t mask = et.width >= 8 ? ~0ull : ((1ull << (et.width * 8)) - 1);
        uint64_t v = value & mask;

        const EnumValue* vals = enumValues_.data() + et.valueOffset;
        for (uint32_t i = 0; i < et.valueCount; ++i) {
            if ((static_cast<uint64_t>(vals[i].value) & mask) == v) {
                out.emplace_back(vals[i].name);
                return out;  // exact match wins, flags or not
            }
        }
        if (!et.isFlags || v == 0) {
            return out;
        }

        // Greedy decomposition: consume the widest matching bit groups first so
        // composites like GENERIC_WRITE beat their individual constituent bits.
        std::vector<uint32_t> order(et.valueCount);
        for (uint32_t i = 0; i < et.valueCount; ++i) {
            order[i] = i;
        }
        std::sort(order.begin(), order.end(), [&](uint32_t a, uint32_t b) {
            return popcount64(static_cast<uint64_t>(vals[a].value) & mask) >
                   popcount64(static_cast<uint64_t>(vals[b].value) & mask);
        });

        uint64_t remaining = v;
        for (uint32_t i : order) {
            uint64_t bits = static_cast<uint64_t>(vals[i].value) & mask;
            if (bits != 0 && (remaining & bits) == bits) {
                out.emplace_back(vals[i].name);
                remaining &= ~bits;
            }
        }
        if (remaining != 0) {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(remaining));
            out.emplace_back(buf);
        }
        return out;
    }

    Index& index() {
        static Index instance;
        return instance;
    }

    namespace {
        std::filesystem::path executableDir() {
            wchar_t buf[MAX_PATH * 4];
            DWORD n = ::GetModuleFileNameW(nullptr, buf, static_cast<DWORD>(std::size(buf)));
            if (n == 0 || n >= std::size(buf)) {
                return {};
            }
            return std::filesystem::path(buf, buf + n).parent_path();
        }
    }  // namespace

    bool loadIndex(const std::filesystem::path& explicitPath, std::string& error) {
        std::vector<std::filesystem::path> candidates;
        if (!explicitPath.empty()) {
            candidates.push_back(explicitPath);
        } else {
            std::filesystem::path dir = executableDir();
            if (!dir.empty()) {
                candidates.push_back(dir / L"win32-index.bin");
                // running straight out of ttd\bin\<plat>\<config>\ during development
                candidates.push_back(dir / L".." / L".." / L".." / L"data" / L"win32-index.bin");
            }
        }

        std::error_code ec;
        for (const auto& c : candidates) {
            if (!std::filesystem::exists(c, ec)) {
                continue;
            }
            if (index().load(c, error)) {
                return true;
            }
            return false;  // found but unusable: surface the real reason
        }
        error = "win32-index.bin not found (run tools/build-win32-index.py, or pass --win32-index)";
        return false;
    }

    const char* kindName(ArgKind kind) {
        switch (kind) {
            case ArgKind::Integer:         return "int";
            case ArgKind::Bool:            return "bool";
            case ArgKind::Handle:          return "handle";
            case ArgKind::Enum:            return "enum";
            case ArgKind::Float:           return "float";
            case ArgKind::Double:          return "double";
            case ArgKind::AnsiString:      return "str";
            case ArgKind::WideString:      return "wstr";
            case ArgKind::AnsiBuffer:      return "strbuf";
            case ArgKind::WideBuffer:      return "wstrbuf";
            case ArgKind::ByteBuffer:      return "buf";
            case ArgKind::PtrToInt:        return "int*";
            case ArgKind::StructPtr:       return "struct*";
            case ArgKind::FuncPtr:         return "fnptr";
            case ArgKind::Guid:            return "guid";
            case ArgKind::Pointer:         return "ptr";
            case ArgKind::PtrToAnsiString: return "str*";
            case ArgKind::PtrToWideString: return "wstr*";
            case ArgKind::Unknown:
            default:                       return "unknown";
        }
    }
}  // namespace ttdcapa::win32meta
