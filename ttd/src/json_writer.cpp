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

#include "json_writer.h"

#include <array>
#include <cstdio>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace ttdcapa {

void JsonWriter::write_escaped(std::string_view s) {
    m_os << '"';
    for (unsigned char c : s) {
        switch (c) {
            case '"':  m_os << "\\\""; break;
            case '\\': m_os << "\\\\"; break;
            case '\b': m_os << "\\b";  break;
            case '\f': m_os << "\\f";  break;
            case '\n': m_os << "\\n";  break;
            case '\r': m_os << "\\r";  break;
            case '\t': m_os << "\\t";  break;
            default:
                if (c < 0x20) {
                    // control characters must be \u-escaped
                    std::array<char, 8> buf{};
                    std::snprintf(buf.data(), buf.size(), "\\u%04x", c);
                    m_os << buf.data();
                } else {
                    // pass through bytes >= 0x20 verbatim; the input is already UTF-8
                    m_os << static_cast<char>(c);
                }
        }
    }
    m_os << '"';
}

std::string JsonWriter::narrow(const std::wstring& ws) {
    if (ws.empty()) {
        return {};
    }
    int needed = ::WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()),
                                       nullptr, 0, nullptr, nullptr);
    if (needed <= 0) {
        return {};
    }
    std::string out(static_cast<size_t>(needed), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()), out.data(), needed,
                          nullptr, nullptr);
    return out;
}

}  // namespace ttdcapa
