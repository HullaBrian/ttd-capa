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
        std::filesystem::path sample;       // optional on-disk sample for hashing
        std::filesystem::path output;       // JSON report; empty means none
        // Binary report (see binreport.hpp). Much faster to write and effectively free to
        // load, but only the JSON form is what capa consumes.
        std::filesystem::path binary_output;
        std::filesystem::path win32_index;  // empty means search the default locations
        std::string dump_sig;               // print one signature and exit; no trace needed
        uint64_t max_calls = 0;             // 0 means unlimited
        // Bytes kept from any one counted buffer. Generous on purpose: buffer parameters
        // are well under 1% of the calls in a typical trace -- on a 654 MB report measured
        // here, 23k buffers across 3.4M calls totalling 1.1 MB -- so the cap is nowhere
        // near the dominant cost, while a buffer truncated below the interesting part is
        // simply lost. 64 KiB covers typical socket and file reads whole.
        size_t max_buffer = 65536;
        bool no_metadata = false;           // force the pre-metadata heuristic capture
        // Emit "[progress] <percent> <calls>" lines on stderr as the sweep runs, and
        // interrupt it when a line reading "cancel" arrives on stdin -- writing out
        // whatever was collected up to that point. Both are for a UI driving this as a
        // child process; interactive use is unaffected.
        bool report_progress = false;
        bool cancel_on_stdin = false;
        // Only affects calls with no metadata: blindly grab four extra stack slots.
        // Functions we have a signature for always capture their true arity.
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