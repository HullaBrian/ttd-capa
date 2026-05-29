// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

#pragma once

#include <filesystem>
#include <string>

namespace ttdcapa {

struct SampleHashes {
    std::string md5;
    std::string sha1;
    std::string sha256;
};

// Compute MD5/SHA1/SHA256 (lowercase hex) of a file's contents via Windows CNG.
// Returns empty strings on failure (e.g. file missing).
SampleHashes hash_file(const std::filesystem::path& path);

}  // namespace ttdcapa
