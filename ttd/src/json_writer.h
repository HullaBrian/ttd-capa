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

// Minimal streaming JSON writer. Just enough to emit the neutral "TTD report"
// consumed by capa's TTD backend (capa/features/extractors/ttd/models.py).
// Not a general-purpose library: it tracks comma placement per nesting level and
// escapes strings per RFC 8259.
#pragma once

#include <cstdint>
#include <ostream>
#include <string>
#include <string_view>
#include <vector>

namespace ttdcapa {

class JsonWriter {
public:
    explicit JsonWriter(std::ostream& os) : m_os(os) {}

    void begin_object() {
        prefix_value();
        m_os << '{';
        m_stack.push_back(false);
    }

    void end_object() {
        m_stack.pop_back();
        m_os << '}';
    }

    void begin_array() {
        prefix_value();
        m_os << '[';
        m_stack.push_back(false);
    }

    void end_array() {
        m_stack.pop_back();
        m_os << ']';
    }

    // Begin a named member whose value is an object/array; call begin_object()
    // or begin_array() immediately after.
    void key(std::string_view name) {
        prefix_value();
        write_escaped(name);
        m_os << ':';
        // the next emitted value must NOT prepend a comma, so mark this slot consumed
        m_pending_key = true;
    }

    void value(std::string_view s) {
        prefix_value();
        write_escaped(s);
    }

    void value(const std::wstring& ws) { value(narrow(ws)); }

    void value(int64_t n) {
        prefix_value();
        m_os << n;
    }

    void value(uint64_t n) {
        prefix_value();
        m_os << n;
    }

    void value_bool(bool b) {
        prefix_value();
        m_os << (b ? "true" : "false");
    }

    void value_null() {
        prefix_value();
        m_os << "null";
    }

    // Convenience: "key": value pairs.
    void member(std::string_view name, std::string_view s) { key(name); value(s); }
    void member(std::string_view name, const std::wstring& ws) { key(name); value(ws); }
    void member(std::string_view name, int64_t n) { key(name); value(n); }
    void member(std::string_view name, uint64_t n) { key(name); value(n); }
    void member_bool(std::string_view name, bool b) { key(name); value_bool(b); }

    // Convert a UTF-16 (Windows wide) string to UTF-8.
    static std::string narrow(const std::wstring& ws);

private:
    void prefix_value() {
        if (m_pending_key) {
            // value follows a key: no comma, and this counts as the slot's first element
            m_pending_key = false;
            return;
        }
        if (!m_stack.empty()) {
            if (m_stack.back()) {
                m_os << ',';
            } else {
                m_stack.back() = true;
            }
        }
    }

    void write_escaped(std::string_view s);

    std::ostream& m_os;
    std::vector<bool> m_stack;  // per-level: has at least one element been written?
    bool m_pending_key = false;
};

}  // namespace ttdcapa
