#include "agent/http.hpp"

#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {
void require(bool condition, const char *message) {
    if (!condition) throw std::runtime_error(message);
}

bool rejected(std::string_view raw) {
    try {
        (void)agent::http::parse_request(raw);
        return false;
    } catch (const std::exception &) {
        return true;
    }
}
}

int main() {
    try {
        const std::string get = "GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n";
        const auto get_head = agent::http::parse_request_head(get);
        require(get_head.has_value(), "complete GET head was not recognized");
        require(get_head->header_size == get.size() && get_head->body_size == 0U,
                "GET framing sizes were incorrect");
        const auto parsed_get = agent::http::parse_request(get);
        require(parsed_get.method == "GET" && parsed_get.path == "/healthz" && parsed_get.body.empty(),
                "GET request fields were not preserved");

        const std::string body = "{}";
        const std::string post = "POST /v1/agents/self/events:batch HTTP/1.1\r\nHost: localhost\r\n"
            "Content-Type: application/json\r\nAuthorization: Bearer lab-secret\r\n"
            "If-None-Match: \"abc123\"\r\n"
            "Content-Length: 2\r\n\r\n{}";
        const auto parsed_post = agent::http::parse_request(post);
        require(parsed_post.method == "POST" && parsed_post.path == "/v1/agents/self/events:batch" &&
                parsed_post.content_type == "application/json" &&
                parsed_post.authorization == "Bearer lab-secret" &&
                parsed_post.if_none_match == "\"abc123\"" && parsed_post.body == body,
                "POST request fields were not preserved");

        require(!agent::http::parse_request_head("GET /healthz HTTP/1.1\r\nHost: localhost\r\n"),
                "incomplete header was treated as complete");
        require(rejected("GET /healthz HTTP/1.1\r\nHost: localhost\r\n"),
                "incomplete request was accepted");
        require(rejected("GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n"), "HTTP/1.0 was accepted");
        require(rejected("GET healthz HTTP/1.1\r\nHost: localhost\r\n\r\n"), "non-origin target was accepted");
        require(rejected("GET /bad target HTTP/1.1\r\nHost: localhost\r\n\r\n"), "space in target was accepted");
        require(rejected("GET /healthz HTTP/1.1\r\nHost: localhost\r\nX-Bad Header: x\r\n\r\n"),
                "invalid header name was accepted");
        require(rejected("GET /healthz HTTP/1.1\r\nHost: localhost\r\n folded: x\r\n\r\n"),
                "folded header was accepted");
        require(rejected("GET /healthz HTTP/1.1\r\n\r\n"), "missing Host was accepted");
        require(rejected("GET /healthz HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"), "duplicate Host was accepted");
        require(rejected("POST /x HTTP/1.1\r\nHost: localhost\r\n\r\n"), "POST without length was accepted");
        require(rejected("POST /x HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n"
                         "Content-Length: 1\r\n\r\nx"), "duplicate Content-Length was accepted");
        require(rejected("POST /x HTTP/1.1\r\nHost: localhost\r\nContent-Length: +1\r\n\r\nx"),
                "signed Content-Length was accepted");
        require(rejected("POST /x HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1048577\r\n\r\n"),
                "oversized Content-Length was accepted");
        require(rejected("POST /x HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n"),
                "Transfer-Encoding was accepted");
        require(rejected("GET /x HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n\r\nx"),
                "GET body was accepted");
        require(rejected("POST /x HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\nx"),
                "truncated body was accepted");
        require(rejected(post + "x"), "bytes after the framed request were accepted");
        require(rejected("POST /x HTTP/1.1\r\nHost: localhost\r\nContent-Type: a\r\nContent-Type: b\r\n"
                         "Content-Length: 0\r\n\r\n"), "duplicate Content-Type was accepted");
        require(rejected("POST /x HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer one\r\n"
                         "Authorization: Bearer two\r\nContent-Length: 0\r\n\r\n"),
                "duplicate Authorization was accepted");
        require(rejected("GET /x HTTP/1.1\r\nHost: localhost\r\nIf-None-Match: one\r\n"
                         "If-None-Match: two\r\n\r\n"), "duplicate If-None-Match was accepted");
        require(rejected("POST /x HTTP/1.1\r\nHost: localhost\r\nX-Control: bad\x01value\r\n"
                         "Content-Length: 0\r\n\r\n"), "control byte in header value was accepted");
        require(rejected("GET /healthz HTTP/1.1\r\nHost: localhost\r\n" + std::string(17000U, 'a') + "\r\n\r\n"),
                "oversized headers were accepted");

        std::cout << "HTTP parser tests passed\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "HTTP parser test failed: " << error.what() << '\n';
        return 1;
    }
}
