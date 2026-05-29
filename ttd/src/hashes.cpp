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

#include "hashes.h"

#include <array>
#include <cstdint>
#include <fstream>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

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
std::string hash_buffer(LPCWSTR alg, const std::vector<uint8_t>& data) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (!BCRYPT_SUCCESS(::BCryptOpenAlgorithmProvider(&hAlg, alg, nullptr, 0))) {
        return {};
    }

    DWORD hash_len = 0, cb = 0;
    ::BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_len),
                        sizeof(hash_len), &cb, 0);

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

SampleHashes hash_file(const std::filesystem::path& path) {
    SampleHashes out;

    std::ifstream f(path, std::ios::binary);
    if (!f) {
        return out;
    }
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)),
                              std::istreambuf_iterator<char>());

    out.md5 = hash_buffer(BCRYPT_MD5_ALGORITHM, data);
    out.sha1 = hash_buffer(BCRYPT_SHA1_ALGORITHM, data);
    out.sha256 = hash_buffer(BCRYPT_SHA256_ALGORITHM, data);
    return out;
}

}  // namespace ttdcapa
