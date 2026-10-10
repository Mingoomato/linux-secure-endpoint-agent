#include "agent/http.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
    constexpr std::size_t max_frame = agent::http::kMaxHttpHeader + 4U + agent::http::kMaxHttpBody;
    if (size > max_frame) return 0;
    try {
        (void)agent::http::parse_request(std::string_view(reinterpret_cast<const char *>(data), size));
    } catch (const std::exception &) {
        // Malformed inputs are expected; sanitizer findings and unexpected process exits are not.
    }
    return 0;
}
