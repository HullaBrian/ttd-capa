#ifndef UITLS_HPP
#define UITLS_HPP

#include "ttdutils.hpp"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>
#include <filesystem>

namespace ttdcapa {
    struct SampleHashes {
        std::string md5;
        std::string sha1;
        std::string sha256;
    };

    struct Report {
        std::string arch;
        std::string os_name;
        std::filesystem::path trace_path;
        ttdcapa::SampleHashes hashes;
        std::string sample_name;
        std::vector<ttdcapa::ImportRecord> imports;
        std::vector<ttdcapa::ExportRecord> exports;
        std::vector<ttdcapa::SectionRecord> sections;
        std::vector<std::string> strings;
        ttdcapa::ProcessRecord process;
    };

    struct Options {
        std::filesystem::path trace;
        std::filesystem::path sample;  // optional on-disk sample for hashing
        std::filesystem::path output;  // empty will output to stdout
        uint64_t max_calls = 0;        // 0 means unlimited
        bool with_stack_args = false;
    };
    
    // Compute MD5/SHA1/SHA256 (lowercase hex) of a file's contents via Windows CNG. Returns empty strings on failure (e.g. file missing).
    SampleHashes hashFile(const std::filesystem::path& path);

    // Writes generated CAPA JSON report to specified location
    bool writeReport(std::filesystem::path outputFilePath);

    void initializeReport(TTD::Replay::UniqueReplayEngine& engine, TTD::Replay::UniqueCursor& cursor, std::wstring samplePath);

    bool parse_args(int argc, wchar_t** argv, Options& opt);
};

#endif