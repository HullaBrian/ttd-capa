#include "binreport.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <unordered_map>
#include <vector>

#include "win32meta.hpp"

namespace ttdcapa::binreport {
    namespace {

        // Append-only growable buffer with little-endian writers. Everything is built in
        // memory and written once: the whole point is to avoid per-record formatting, and
        // a few hundred MB of contiguous bytes is one sequential write.
        class ByteSink {
        public:
            void reserve(size_t bytes) { buf_.reserve(bytes); }
            size_t size() const { return buf_.size(); }
            const uint8_t* data() const { return buf_.data(); }

            void u8(uint8_t v) { buf_.push_back(v); }
            void u16(uint16_t v) { raw(&v, sizeof(v)); }
            void u32(uint32_t v) { raw(&v, sizeof(v)); }
            void u64(uint64_t v) { raw(&v, sizeof(v)); }

            void raw(const void* p, size_t n) {
                const auto* b = static_cast<const uint8_t*>(p);
                buf_.insert(buf_.end(), b, b + n);
            }

            void pad(size_t to) {
                while (buf_.size() < to) {
                    buf_.push_back(0);
                }
            }

        private:
            std::vector<uint8_t> buf_;
        };

        // Deduplicating string table. Module and API names repeat across millions of
        // calls but number only in the thousands, so this is where most of the text goes.
        class StringTable {
        public:
            StringTable() { sink_.u8(0); }  // offset 0 is the empty string

            uint32_t add(const std::string& s) {
                if (s.empty()) {
                    return 0;
                }
                auto it = seen_.find(s);
                if (it != seen_.end()) {
                    return it->second;
                }
                uint32_t off = static_cast<uint32_t>(sink_.size());
                sink_.raw(s.data(), s.size());
                sink_.u8(0);
                seen_.emplace(s, off);
                return off;
            }

            const ByteSink& bytes() const { return sink_; }

        private:
            ByteSink sink_;
            std::unordered_map<std::string, uint32_t> seen_;
        };

        std::string toLower(std::string s) {
            std::transform(s.begin(), s.end(), s.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return s;
        }

        std::string toHexValue(uint64_t v) {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(v));
            return buf;
        }

        // The same text a viewer would search: "module!api" plus each parameter rendered
        // the way it is displayed. Built here so a filter never has to reconstruct it.
        std::string buildHaystack(const CallRecord& call, const std::string& moduleName) {
            std::string out;
            out.reserve(96);
            out += moduleName;
            out += '!';
            out += call.api;

            if (call.metadata) {
                for (const DecodedArg& p : call.params) {
                    out += ' ';
                    if (p.name != nullptr) {
                        out += p.name;
                        out += '=';
                    }
                    if (p.has_str && !p.str.empty()) {
                        out += '"';
                        out += p.str;
                        out += '"';
                    } else if (p.enum_index != 0xFFFFFFFFu) {
                        auto names = win32meta::index().decodeEnum(p.enum_index, p.raw);
                        if (!names.empty()) {
                            for (size_t i = 0; i < names.size(); ++i) {
                                if (i != 0) {
                                    out += '|';
                                }
                                out += names[i];
                            }
                        } else {
                            out += toHexValue(p.raw);
                        }
                    } else {
                        out += toHexValue(p.raw);
                    }
                }
            } else {
                for (const ArgValue& a : call.args) {
                    out += ' ';
                    if (std::holds_alternative<std::string>(a)) {
                        out += '"';
                        out += std::get<std::string>(a);
                        out += '"';
                    } else {
                        out += toHexValue(static_cast<uint64_t>(std::get<int64_t>(a)));
                    }
                }
            }
            return toLower(std::move(out));
        }

        // "Sequence:Steps" is stored as two integers; parse the string form the sweep
        // already produced rather than plumbing the raw Position through.
        void parsePosition(const std::string& text, uint32_t& sequence, uint32_t& steps) {
            sequence = 0;
            steps = 0;
            size_t colon = text.find(':');
            if (colon == std::string::npos) {
                return;
            }
            sequence = static_cast<uint32_t>(std::strtoull(text.c_str(), nullptr, 16));
            steps = static_cast<uint32_t>(std::strtoull(text.c_str() + colon + 1, nullptr, 16));
        }

    }  // namespace

    bool write(const std::filesystem::path& path, const Report& report, std::string& error) {
        StringTable strings;
        ByteSink calls;
        ByteSink params;
        ByteSink blob;

        const size_t callCount = report.process.calls.size();
        calls.reserve(callCount * kCallRecordSize);
        blob.reserve(callCount * 96);
        params.reserve(callCount * 24);

        const uint32_t tracePathStr = strings.add(report.trace_path.string());
        const uint32_t sampleNameStr = strings.add(report.sample_name);

        uint64_t decodedCount = 0;
        uint64_t maxSeq = 0;
        uint32_t maxPositionChars = 0;

        for (const CallRecord& call : report.process.calls) {
            std::string moduleName(call.module.begin(), call.module.end());

            // The haystack and any parameter payloads go in the blob; the call record
            // only ever holds offsets and lengths.
            std::string haystack = buildHaystack(call, moduleName);
            uint32_t searchOff = static_cast<uint32_t>(blob.size());
            blob.raw(haystack.data(), haystack.size());

            uint32_t paramOff = 0;
            uint16_t paramCount = 0;
            if (call.metadata) {
                ++decodedCount;
                paramCount = static_cast<uint16_t>(call.params.size() & 0x7FFF) | kDecodedFlag;
                paramOff = static_cast<uint32_t>(params.size());

                for (const DecodedArg& p : call.params) {
                    uint8_t bits = 0;
                    if (p.is_out) bits |= ParamOut;
                    if (p.from_return) bits |= ParamAtReturn;
                    if (p.has_deref) bits |= ParamHasDeref;
                    if (p.has_str && !p.str.empty()) bits |= ParamHasStr;
                    if (!p.bytes.empty()) bits |= ParamHasBytes;

                    std::string flagText;
                    if (p.enum_index != 0xFFFFFFFFu) {
                        auto names = win32meta::index().decodeEnum(p.enum_index, p.raw);
                        for (size_t i = 0; i < names.size(); ++i) {
                            if (i != 0) {
                                flagText += '|';
                            }
                            flagText += names[i];
                        }
                    }
                    if (!flagText.empty()) bits |= ParamHasFlags;

                    params.u8(static_cast<uint8_t>(p.kind));
                    params.u8(bits);
                    params.u32(strings.add(p.name != nullptr ? p.name : ""));
                    params.u32(strings.add(p.type != nullptr ? p.type : ""));
                    params.u64(p.raw);

                    if (bits & ParamHasDeref) {
                        params.u64(p.deref);
                    }
                    if (bits & ParamHasStr) {
                        params.u32(static_cast<uint32_t>(blob.size()));
                        params.u32(static_cast<uint32_t>(p.str.size()));
                        blob.raw(p.str.data(), p.str.size());
                    }
                    if (bits & ParamHasBytes) {
                        params.u32(static_cast<uint32_t>(blob.size()));
                        params.u32(static_cast<uint32_t>(p.bytes.size()));
                        // Raw, not hex: half the size and nothing to decode on load.
                        params.u64(p.bytes_capped ? p.bytes_total : p.bytes.size());
                        blob.raw(p.bytes.data(), p.bytes.size());
                    }
                    if (bits & ParamHasFlags) {
                        params.u32(static_cast<uint32_t>(blob.size()));
                        params.u32(static_cast<uint32_t>(flagText.size()));
                        blob.raw(flagText.data(), flagText.size());
                    }
                }
            } else {
                // Heuristic capture has no names or types, but the values still need to
                // be displayable. Encode them as nameless parameters so the reader has
                // one representation to handle; the missing kDecodedFlag is what tells it
                // to render them positionally.
                paramCount = static_cast<uint16_t>(call.args.size() & 0x7FFF);
                paramOff = static_cast<uint32_t>(params.size());

                for (const ArgValue& a : call.args) {
                    bool isString = std::holds_alternative<std::string>(a);
                    params.u8(static_cast<uint8_t>(win32meta::ArgKind::Unknown));
                    params.u8(isString ? static_cast<uint8_t>(ParamHasStr) : uint8_t{0});
                    params.u32(0);  // no name
                    params.u32(0);  // no type
                    if (isString) {
                        const std::string& s = std::get<std::string>(a);
                        params.u64(0);
                        params.u32(static_cast<uint32_t>(blob.size()));
                        params.u32(static_cast<uint32_t>(s.size()));
                        blob.raw(s.data(), s.size());
                    } else {
                        params.u64(static_cast<uint64_t>(std::get<int64_t>(a)));
                    }
                }
            }

            uint32_t posSequence = 0;
            uint32_t posSteps = 0;
            parsePosition(call.position, posSequence, posSteps);
            maxPositionChars = std::max(maxPositionChars, static_cast<uint32_t>(call.position.size()));
            maxSeq = std::max(maxSeq, call.seq);

            calls.u64(call.has_ret ? call.ret : 0);
            calls.u32(static_cast<uint32_t>(call.tid));
            calls.u32(posSequence);
            calls.u32(posSteps);
            calls.u32(strings.add(moduleName));
            calls.u32(strings.add(call.api));
            calls.u32(paramOff);
            calls.u32(searchOff);
            calls.u16(paramCount);
            calls.u16(static_cast<uint16_t>(std::min<size_t>(haystack.size(), 0xFFFF)));
        }

        // Assemble: header, then each region in the order the header declares.
        const uint64_t callsOff = kHeaderSize;
        const uint64_t paramsOff = callsOff + calls.size();
        const uint64_t stringsOff = paramsOff + params.size();
        const uint64_t blobOff = stringsOff + strings.bytes().size();

        ByteSink header;
        header.raw(kMagic, sizeof(kMagic));
        header.u32(kVersion);
        header.u32(static_cast<uint32_t>(report.arch == "x86" ? Arch::X86 : Arch::X64));
        header.u64(callCount);
        header.u64(params.size());
        header.u64(report.process.pid);
        header.u64(callsOff);
        header.u64(paramsOff);
        header.u64(stringsOff);
        header.u64(strings.bytes().size());
        header.u64(blobOff);
        header.u64(blob.size());
        header.u64(decodedCount);
        header.u64(maxSeq);
        header.u32(tracePathStr);
        header.u32(sampleNameStr);
        header.u32(maxPositionChars);
        header.pad(kHeaderSize);

        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) {
            error = "cannot open " + path.string();
            return false;
        }
        out.write(reinterpret_cast<const char*>(header.data()), static_cast<std::streamsize>(header.size()));
        out.write(reinterpret_cast<const char*>(calls.data()), static_cast<std::streamsize>(calls.size()));
        out.write(reinterpret_cast<const char*>(params.data()), static_cast<std::streamsize>(params.size()));
        out.write(reinterpret_cast<const char*>(strings.bytes().data()),
                  static_cast<std::streamsize>(strings.bytes().size()));
        out.write(reinterpret_cast<const char*>(blob.data()), static_cast<std::streamsize>(blob.size()));
        if (!out.good()) {
            error = "write failed for " + path.string();
            return false;
        }
        out.close();
        return true;
    }

}  // namespace ttdcapa::binreport
