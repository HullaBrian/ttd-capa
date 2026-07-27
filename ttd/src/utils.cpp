#include "utils.hpp"
#include "ttd_pe_utils.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <fstream>
#include <iostream>
#include <bcrypt.h>

#include <nlohmann/json.hpp>

#pragma comment(lib, "bcrypt.lib")

extern ttdcapa::Report g_report;

namespace ttdcapa {
    namespace {
        std::string to_hex(const std::vector<uint8_t>& bytes) {
            static const char* digits = "0123456789abcdef";
            std::string out;
            out.reserve(bytes.size() * 2);

            for (uint8_t b : bytes) {
                out.push_back(digits[b >> 4]);
                out.push_back(digits[b & 0x0f]);
            }

            return out;
        }

        // Hash an in-memory buffer with a single CNG algorithm.
        std::string hashBuffer(LPCWSTR alg, const std::vector<uint8_t>& data) {
            BCRYPT_ALG_HANDLE hAlg = nullptr;
            if (!BCRYPT_SUCCESS(::BCryptOpenAlgorithmProvider(&hAlg, alg, nullptr, 0))) {
                return {};
            }

            DWORD hash_len = 0, cb = 0;
            ::BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_len), sizeof(hash_len), &cb, 0);

            BCRYPT_HASH_HANDLE hHash = nullptr;
            std::string result;
            if (BCRYPT_SUCCESS(::BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0))) {
                if (BCRYPT_SUCCESS(::BCryptHashData(
                    hHash, const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()), 0))) {
                    std::vector<uint8_t> digest(hash_len);
                    if (BCRYPT_SUCCESS(::BCryptFinishHash(hHash, digest.data(), hash_len, 0))) {
                        result = to_hex(digest);
                    }
                }
                ::BCryptDestroyHash(hHash);
            }
            ::BCryptCloseAlgorithmProvider(hAlg, 0);
            return result;
        }

    }  // namespace

    SampleHashes hashFile(const std::filesystem::path& path) {
        SampleHashes out;

        std::ifstream f(path, std::ios::binary);
        if (!f) {
            return out;
        }
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

        out.md5 = hashBuffer(BCRYPT_MD5_ALGORITHM, data);
        out.sha1 = hashBuffer(BCRYPT_SHA1_ALGORITHM, data);
        out.sha256 = hashBuffer(BCRYPT_SHA256_ALGORITHM, data);
        return out;
    }

    void initializeReport(TTD::Replay::UniqueReplayEngine& engine, TTD::Replay::UniqueCursor& cursor, std::wstring samplePath) {
        g_report.arch = "x64";
        g_report.os_name = "windows";
        g_report.process.ppid = 0;  // not exposed by TTD :(
        
        size_t mod_count = engine->GetModuleCount();
        TTD::Replay::Module const* mods = engine->GetModuleList();

        // exact function-entry VA -> (module, api)
        std::unordered_map<uint64_t, std::pair<std::string, std::string>> api_by_va;

        // Identify the main module (first image whose name ends in ".exe").
        int mainIndex = -1;
        for (size_t i = 0; i < mod_count; ++i) {
            std::wstring name = mods[i].pName ? mods[i].pName : L"";
            if (name.size() >= 4) {
                std::wstring ext = name.substr(name.size() - 4);
                for (auto& c : ext) c = static_cast<wchar_t>(towlower(c));  // Lowercase name
                if (ext == L".exe") {
                    mainIndex = static_cast<int>(i);
                    break;
                }
            }
        }

        if (mainIndex == -1) {
            std::wcerr << L"[-] Unable to resolve main module!\n";
            return;
        }

        TTD::GuestAddress mbase = mods[mainIndex].Address;
        std::wstring full = mods[mainIndex].pName ? mods[mainIndex].pName : L"";
        size_t slash = full.find_last_of(L"\\/");
        g_report.sample_name = convertWstringToString( slash == std::wstring::npos ? full : full.substr(slash + 1));

        auto try_parse = [&](TTD::Replay::Position p) -> bool {
            cursor->SetPosition(p);

            g_report.imports.clear();
            g_report.sections.clear();

            std::vector<std::pair<uint64_t, std::string>> exps;
            bool ok = getModuleImports(&cursor, mbase, g_report.imports);
            ok = ttdcapa::getModuleSections(&cursor, mbase, g_report.sections) && ok;

            // The main image's PE format is what the report calls the trace's
            // architecture. A WoW64 trace also holds 64-bit system modules, but the
            // process it recorded is the 32-bit one.
            bool mainIs64 = true;
            if (getModuleExports(&cursor, mbase, exps, &mainIs64)) {
                g_report.arch = mainIs64 ? "x64" : "x86";
                for (auto& e : exps) {
                    ExportRecord exportRecord;
                    exportRecord.name = e.second;
                    exportRecord.va = (TTD::GuestAddress) e.first;
                    g_report.exports.push_back(exportRecord);
                }
            }

            return ok && !g_report.sections.empty();
        };

        if (!try_parse(engine->GetLastPosition())) {
            try_parse(TTD::Replay::Position::Min);
        }

        cursor->SetPosition(engine->GetLastPosition());
        getModuleStrings(&cursor, mbase, g_report.strings);

        if (!samplePath.empty()) {
            g_report.hashes = hashFile(samplePath);
            if (g_report.sample_name.empty()) {
                g_report.process.name = g_report.sample_name;
            }
        }

        // The thread list is filled in by the caller after this returns; collecting it
        // here too duplicated every entry.
    }

    bool parse_args(int argc, wchar_t** argv, Options& opt) {
        for (int i = 1; i < argc; ++i) {
            std::wstring a = argv[i];
            if (a == L"--sample" && i + 1 < argc) {
                opt.sample = argv[++i];
            }
            else if ((a == L"-o" || a == L"--output") && i + 1 < argc) {
                opt.output = argv[++i];
            }
            else if (a == L"--max-calls" && i + 1 < argc) {
                opt.max_calls = std::wcstoull(argv[++i], nullptr, 10);
            }
            else if (a == L"--with-stack-args") {
                opt.with_stack_args = true;
            }
            else if (a == L"--win32-index" && i + 1 < argc) {
                opt.win32_index = argv[++i];
            }
            else if (a == L"--no-metadata") {
                opt.no_metadata = true;
            }
            else if (a == L"--max-buffer" && i + 1 < argc) {
                opt.max_buffer = static_cast<size_t>(std::wcstoull(argv[++i], nullptr, 10));
            }
            else if (a == L"--dump-sig" && i + 1 < argc) {
                opt.dump_sig = convertWstringToString(argv[++i]);
            }
            else if (!a.empty() && a[0] == L'-') {
                std::cerr << "unknown option\n";
                return false;
            }
            else if (opt.trace.empty()) {
                opt.trace = a;
            }
            else {
                std::cerr << "unexpected positional argument\n";
                return false;
            }
        }
        // --dump-sig is a metadata-only debug mode, so it doesn't need a trace.
        return !opt.trace.empty() || !opt.dump_sig.empty();
    }

    bool writeReport(std::filesystem::path outputFilePath) {
        std::cerr << "[+] Generating JSON report...";
        using json = nlohmann::json;
        json report;

        report["version"] = 1;

        report["trace"]["path"] = g_report.trace_path;
        report["trace"]["arch"] = g_report.arch;
        report["trace"]["os"] = g_report.os_name;

        report["sample"]["md5"] = g_report.hashes.md5;
        report["sample"]["sha1"] = g_report.hashes.sha1;
        report["sample"]["sha256"] = g_report.hashes.sha256;

        for (ImportRecord& sampleImport : g_report.imports) {
            report["file"]["imports"].push_back({ {"dll", sampleImport.dll}, {"name", sampleImport.name}, {"va", sampleImport.va} });
        }

        for (ExportRecord& sampleExport : g_report.exports) {
            report["file"]["exports"].push_back({ {"name", sampleExport.name}, {"va", sampleExport.va} });
        }

        for (SectionRecord& sampleSection : g_report.sections) {
            report["file"]["sections"].push_back({ {"name", sampleSection.name}, {"va", sampleSection.va} });
        }

        report["file"]["strings"] = g_report.strings;

        json process;
        process["pid"] = g_report.process.pid;
        process["ppid"] = g_report.process.ppid;
        process["name"] = g_report.process.name;
        process["environ"] = g_report.process.env_strings;
        process["threads"] = g_report.process.threads;
        for (CallRecord& callRecord : g_report.process.calls) {
            json call;

            call["tid"] = callRecord.tid;
            call["seq"] = callRecord.seq;
            call["position"] = callRecord.position;

            std::string moduleStr(callRecord.module.begin(), callRecord.module.end());
            call["module"] = moduleStr;

            call["api"] = callRecord.api;
            // Always an array, even when empty -- a zero-parameter function is a
            // real result, not a missing field.
            call["args"] = json::array();
            for (ArgValue& argValue : callRecord.args) {
                if (std::holds_alternative<int64_t>(argValue)) {
                    call["args"].push_back(std::get<int64_t>(argValue));
                } else {
                    call["args"].push_back(std::get<std::string>(argValue));
                }
            }

            // The rich, metadata-derived view. capa matches on "args"; this is for
            // ttd-timeline and human triage, so it can afford to be verbose. Absent
            // entirely when we had no signature, so consumers can tell "no
            // parameters" apart from "we didn't know".
            if (callRecord.metadata) {
                call["params"] = json::array();
            }
            for (DecodedArg& decoded : callRecord.params) {
                json param;
                param["name"] = decoded.name ? decoded.name : "";
                param["type"] = decoded.type ? decoded.type : "";
                param["kind"] = win32meta::kindName(decoded.kind);
                param["value"] = decoded.raw;
                if (decoded.has_str) {
                    param["str"] = decoded.str;
                }
                if (decoded.has_deref) {
                    param["deref"] = decoded.deref;
                }
                if (decoded.has_fval) {
                    param["float"] = decoded.fval;
                }
                if (decoded.enum_index != 0xFFFFFFFFu) {
                    std::vector<std::string> names = win32meta::index().decodeEnum(decoded.enum_index, decoded.raw);
                    if (!names.empty()) {
                        param["flags"] = names;
                    }
                }
                if (!decoded.bytes.empty()) {
                    param["bytes"] = to_hex(decoded.bytes);
                    // Only when --max-buffer actually cut it short: a string buffer
                    // trimmed at its NUL is complete, not truncated.
                    if (decoded.bytes_capped) {
                        param["bytes_total"] = decoded.bytes_total;
                    }
                }
                if (decoded.is_out) {
                    param["out"] = true;
                }
                if (decoded.from_return) {
                    param["at_return"] = true;
                }
                call["params"].push_back(std::move(param));
            }

            call["ret"] = callRecord.has_ret ? callRecord.ret : 0;

            process["calls"].push_back(call);
        }

        report["processes"].push_back(process);
        
        std::ofstream reportFile(outputFilePath);
        if (!reportFile.is_open()) {
            std::cerr << "ERROR!\n[-] Unable to open report JSON!\n";
            return false;
        }

        // Recovered guest memory can always surprise us with a byte sequence that
        // isn't valid UTF-8. Substituting it beats throwing away an entire trace's
        // worth of extraction over one bad string.
        reportFile << report.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace) << std::endl;
        reportFile.close();
        std::cerr << "DONE!\n";
        return true;
    }
}
