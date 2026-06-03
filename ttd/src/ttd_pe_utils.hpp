#pragma once

#include "ttdutils.hpp"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include <TTD/IdnaBasicTypes.h>
#include <TTD/IReplayEngineStl.h>

namespace ttdcapa {
	// Read `size` bytes of guest virtual memory at `addr` into `dst`. Returns the number of bytes actually available/read (may be < size).
	using GuestReader = std::function<size_t(TTD::GuestAddress addr, void* dst, size_t size)>;

	// Parse the export directory of the PE image mapped at `base`. Appends one entry
	// per named export (forwarders are skipped). Returns false if `base` is not a
	// readable PE32+ image at this position.
	bool getModuleExports(TTD::Replay::UniqueCursor* cursor, TTD::GuestAddress moduleBaseAddress, std::vector<std::pair<uint64_t, std::string>>& out);

	// Parse the import directory of the PE image mapped at `base`.
	bool getModuleImports(TTD::Replay::UniqueCursor* cursor, TTD::GuestAddress moduleBaseAddress, std::vector<ImportRecord>& out);

	// Parse the section table of the PE image mapped at `base`.
	bool getModuleSections(TTD::Replay::UniqueCursor* cursor, TTD::GuestAddress moduleBaseAddress, std::vector<SectionRecord>& out);

	// Recover ASCII and UTF-16LE strings (length >= min_len) from the image's mapped
	// sections. Caps output at `max_strings` to keep the report bounded.
	bool getModuleStrings(TTD::Replay::UniqueCursor* cursor, TTD::GuestAddress moduleBaseAddress, std::vector<std::string>& out, size_t minLength = 5, size_t maxStrings = 2000);

	// Strip a path/extension from a module name: "C:\\WINDOWS\\System32\\kernel32.dll" -> "kernel32".
	std::string getModuleBaseName(const std::wstring& full);
}
