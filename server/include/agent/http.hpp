#ifndef SEA_AGENT_HTTP_HPP
#define SEA_AGENT_HTTP_HPP

#include <algorithm>
#include <cstddef>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace agent::http {

inline constexpr std::size_t kMaxHttpHeader = 16U * 1024U;
inline constexpr std::size_t kMaxHttpBody = 1024U * 1024U;

struct Request {
    std::string method;
    std::string path;
    std::string body;
    std::string content_type;
};

struct RequestHead {
    Request request;
    std::size_t header_size;
    std::size_t body_size;
};

inline bool token_char(unsigned char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
        c == '!' || c == '#' || c == '$' || c == '%' || c == '&' || c == '\'' || c == '*' ||
        c == '+' || c == '-' || c == '.' || c == '^' || c == '_' || c == '`' || c == '|' || c == '~';
}

inline std::string lowercase_ascii(std::string value) {
    for (char &c : value) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return value;
}

inline std::size_t parse_content_length(std::string_view value) {
    if (value.empty()) throw std::runtime_error("empty Content-Length");
    std::size_t length = 0;
    for (unsigned char c : value) {
        if (c < '0' || c > '9') throw std::runtime_error("invalid Content-Length");
        std::size_t digit = static_cast<std::size_t>(c - '0');
        if (length > (kMaxHttpBody - digit) / 10U) throw std::runtime_error("request body too large");
        length = length * 10U + digit;
    }
    return length;
}

inline std::string_view trim_http_value(std::string_view value) {
    std::size_t first = value.find_first_not_of(" \t");
    if (first == std::string_view::npos) return {};
    std::size_t last = value.find_last_not_of(" \t");
    return value.substr(first, last - first + 1U);
}

// Returns no value while the TLS byte stream has not delivered a complete header.
// A returned head is independent of the transport and safe to test or fuzz directly.
inline std::optional<RequestHead> parse_request_head(std::string_view raw) {
    const std::size_t header_end = raw.find("\r\n\r\n");
    if (header_end == std::string_view::npos) {
        if (raw.size() > kMaxHttpHeader) throw std::runtime_error("HTTP headers too large");
        return std::nullopt;
    }
    if (header_end + 4U > kMaxHttpHeader) throw std::runtime_error("HTTP headers too large");

    const std::string_view headers = raw.substr(0, header_end);
    const std::size_t first_end = headers.find("\r\n");
    if (first_end == std::string_view::npos || first_end > 4096U)
        throw std::runtime_error("malformed HTTP request line");
    const std::string_view first = headers.substr(0, first_end);
    const std::size_t first_space = first.find(' ');
    const std::size_t second_space = first_space == std::string_view::npos ? std::string_view::npos : first.find(' ', first_space + 1U);
    if (first_space == std::string_view::npos || second_space == std::string_view::npos ||
        first_space == 0U || second_space == first_space + 1U || second_space + 1U >= first.size() ||
        first.find(' ', second_space + 1U) != std::string_view::npos)
        throw std::runtime_error("malformed HTTP request line");

    RequestHead head {{}, header_end + 4U, 0U};
    const std::string_view method = first.substr(0, first_space);
    const std::string_view path = first.substr(first_space + 1U, second_space - first_space - 1U);
    const std::string_view version = first.substr(second_space + 1U);
    if (!std::all_of(method.begin(), method.end(), [](unsigned char c) { return token_char(c); }) ||
        path.empty() || path.front() != '/' || version != "HTTP/1.1")
        throw std::runtime_error("unsupported HTTP request line");
    for (unsigned char c : path) if (c <= 0x20U || c >= 0x7fU)
        throw std::runtime_error("invalid HTTP request target");
    head.request.method.assign(method);
    head.request.path.assign(path);

    bool have_length = false;
    bool have_content_type = false;
    unsigned host_count = 0;
    std::size_t pos = first_end + 2U;
    while (pos < headers.size()) {
        const std::size_t line_end = headers.find("\r\n", pos);
        const std::string_view field = headers.substr(pos, line_end == std::string_view::npos ? std::string_view::npos : line_end - pos);
        if (field.empty() || field.front() == ' ' || field.front() == '\t')
            throw std::runtime_error("invalid or folded HTTP header");
        const std::size_t colon = field.find(':');
        if (colon == std::string_view::npos || colon == 0U)
            throw std::runtime_error("malformed HTTP header");
        const std::string_view name = field.substr(0, colon);
        if (!std::all_of(name.begin(), name.end(), [](unsigned char c) { return token_char(c); }))
            throw std::runtime_error("invalid HTTP header name");
        const std::string_view value = trim_http_value(field.substr(colon + 1U));
        for (unsigned char c : value) if ((c < 0x20U && c != '\t') || c == 0x7fU)
            throw std::runtime_error("invalid HTTP header value");
        const std::string normalized = lowercase_ascii(std::string(name));
        if (normalized == "host") {
            ++host_count;
            if (value.empty()) throw std::runtime_error("empty HTTP Host");
        } else if (normalized == "content-length") {
            if (have_length) throw std::runtime_error("duplicate Content-Length");
            head.body_size = parse_content_length(value);
            have_length = true;
        } else if (normalized == "content-type") {
            if (have_content_type) throw std::runtime_error("duplicate Content-Type");
            head.request.content_type.assign(value);
            have_content_type = true;
        } else if (normalized == "transfer-encoding") {
            throw std::runtime_error("Transfer-Encoding is unsupported");
        }
        if (line_end == std::string_view::npos) break;
        pos = line_end + 2U;
    }
    if (host_count != 1U) throw std::runtime_error("HTTP/1.1 requires exactly one Host");
    if (head.request.method == "POST" && !have_length)
        throw std::runtime_error("POST requires Content-Length");
    if (head.request.method == "GET" && head.body_size != 0U)
        throw std::runtime_error("GET request body is unsupported");
    return head;
}

inline Request parse_request(std::string_view raw) {
    const std::optional<RequestHead> head = parse_request_head(raw);
    if (!head) throw std::runtime_error("incomplete HTTP request headers");
    const std::size_t expected_size = head->header_size + head->body_size;
    if (raw.size() > expected_size) throw std::runtime_error("bytes follow the framed HTTP request");
    if (raw.size() < expected_size) throw std::runtime_error("incomplete HTTP request body");
    Request request = head->request;
    request.body.assign(raw.substr(head->header_size, head->body_size));
    return request;
}

} // namespace agent::http

#endif
