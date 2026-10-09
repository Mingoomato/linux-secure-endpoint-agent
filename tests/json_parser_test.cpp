#include "agent/json.hpp"

#include <string>
#include <vector>

namespace {
bool parses(const std::string &text) {
    try {
        (void)agent::json::Parser(text).parse();
        return true;
    } catch (...) {
        return false;
    }
}
}

int main() {
    const std::vector<std::string> valid = {
        "null", "true", "false", "0", "-0", "1", "-12", "0.25", "-0.5e+2",
        "1E-3", "{\"n\":1,\"items\":[true,null]}", " \t\r\n{\"ok\":true}"
    };
    for (const auto &text : valid) if (!parses(text)) return 1;

    const std::vector<std::string> invalid = {
        "+1", "01", "-01", ".5", "1.", "1e", "1e+", "--1", "NaN", "Infinity",
        "-Infinity", "0x10", "1 true", "{\"a\":1,\"a\":2}", "\vnull", "\fnull",
        "1e9999", "1e-9999"
    };
    for (const auto &text : invalid) if (parses(text)) return 2;

    std::string too_deep(33, '[');
    too_deep += '0';
    too_deep.append(33, ']');
    if (parses(too_deep)) return 3;

    std::string too_large(1024U * 1024U + 1U, ' ');
    if (parses(too_large)) return 4;
    return 0;
}
