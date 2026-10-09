#ifndef BDETECT_JSON_HPP
#define BDETECT_JSON_HPP

#include <cctype>
#include <charconv>
#include <cmath>
#include <cstddef>
#include <cerrno>
#include <cstdlib>
#include <map>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

namespace agent::json {
struct Value;
using Array = std::vector<Value>;
using Object = std::map<std::string, Value>;
struct Value {
    std::variant<std::nullptr_t, bool, double, std::string, Array, Object> data;
    const Value *get(std::string key) const {
        const auto *o = std::get_if<Object>(&data);
        if (!o) return nullptr;
        const auto it = o->find(key);
        return it == o->end() ? nullptr : &it->second;
    }
    std::string string_or(const std::string &fallback = {}) const {
        const auto *s = std::get_if<std::string>(&data);
        return s ? *s : fallback;
    }
    double number_or(double fallback = 0) const {
        const auto *n = std::get_if<double>(&data);
        return n ? *n : fallback;
    }
};

class Parser {
public:
    explicit Parser(const std::string &input) : input_(input) {
        if (input.size() > 1024U * 1024U) throw std::runtime_error("JSON record too large");
    }
    Value parse() {
        Value v = value(0);
        ws();
        if (pos_ != input_.size()) throw std::runtime_error("trailing JSON data");
        return v;
    }
private:
    const std::string &input_;
    std::size_t pos_ = 0;
    void ws() {
        while (pos_ < input_.size() && (input_[pos_] == ' ' || input_[pos_] == '\t' ||
               input_[pos_] == '\n' || input_[pos_] == '\r')) ++pos_;
    }
    static bool digit(char c) { return c >= '0' && c <= '9'; }
    double number() {
        const std::size_t start = pos_;
        if (input_[pos_] == '-') ++pos_;
        if (pos_ >= input_.size()) throw std::runtime_error("invalid JSON number");
        if (input_[pos_] == '0') {
            ++pos_;
            if (pos_ < input_.size() && digit(input_[pos_]))
                throw std::runtime_error("leading zero in JSON number");
        } else if (input_[pos_] >= '1' && input_[pos_] <= '9') {
            do { ++pos_; } while (pos_ < input_.size() && digit(input_[pos_]));
        } else throw std::runtime_error("invalid JSON number");
        if (pos_ < input_.size() && input_[pos_] == '.') {
            ++pos_;
            if (pos_ >= input_.size() || !digit(input_[pos_]))
                throw std::runtime_error("invalid JSON fraction");
            do { ++pos_; } while (pos_ < input_.size() && digit(input_[pos_]));
        }
        if (pos_ < input_.size() && (input_[pos_] == 'e' || input_[pos_] == 'E')) {
            ++pos_;
            if (pos_ < input_.size() && (input_[pos_] == '+' || input_[pos_] == '-')) ++pos_;
            if (pos_ >= input_.size() || !digit(input_[pos_]))
                throw std::runtime_error("invalid JSON exponent");
            do { ++pos_; } while (pos_ < input_.size() && digit(input_[pos_]));
        }
        double result = 0.0;
        const char *begin = input_.data() + start;
        const char *end = input_.data() + pos_;
        auto parsed = std::from_chars(begin, end, result, std::chars_format::general);
        if (parsed.ec != std::errc{} || parsed.ptr != end || !std::isfinite(result))
            throw std::runtime_error("JSON number out of range");
        return result;
    }
    char take() { if (pos_ >= input_.size()) throw std::runtime_error("unexpected end of JSON"); return input_[pos_++]; }
    bool eat(char c) { ws(); if (pos_ < input_.size() && input_[pos_] == c) { ++pos_; return true; } return false; }
    std::string string() {
        ws();
        if (take() != '"') throw std::runtime_error("expected JSON string");
        std::string out;
        while (pos_ < input_.size()) {
            unsigned char c = static_cast<unsigned char>(take());
            if (c == '"') return out;
            if (c < 0x20U) throw std::runtime_error("control byte in JSON string");
            if (c != '\\') { out.push_back(static_cast<char>(c)); continue; }
            char esc = take();
            switch (esc) {
            case '"': out.push_back('"'); break; case '\\': out.push_back('\\'); break;
            case '/': out.push_back('/'); break; case 'b': out.push_back('\b'); break;
            case 'f': out.push_back('\f'); break; case 'n': out.push_back('\n'); break;
            case 'r': out.push_back('\r'); break; case 't': out.push_back('\t'); break;
            case 'u': {
                unsigned code = 0;
                for (int i = 0; i < 4; ++i) {
                    char h = take(); code <<= 4U;
                    if (h >= '0' && h <= '9') code |= static_cast<unsigned>(h - '0');
                    else if (h >= 'a' && h <= 'f') code |= static_cast<unsigned>(h - 'a' + 10);
                    else if (h >= 'A' && h <= 'F') code |= static_cast<unsigned>(h - 'A' + 10);
                    else throw std::runtime_error("invalid unicode escape");
                }
                if (code >= 0xd800U && code <= 0xdfffU) throw std::runtime_error("surrogate escape unsupported");
                if (code < 0x80U) out.push_back(static_cast<char>(code));
                else if (code < 0x800U) {
                    out.push_back(static_cast<char>(0xc0U | (code >> 6U)));
                    out.push_back(static_cast<char>(0x80U | (code & 0x3fU)));
                } else {
                    out.push_back(static_cast<char>(0xe0U | (code >> 12U)));
                    out.push_back(static_cast<char>(0x80U | ((code >> 6U) & 0x3fU)));
                    out.push_back(static_cast<char>(0x80U | (code & 0x3fU)));
                }
                break;
            }
            default: throw std::runtime_error("invalid JSON escape");
            }
        }
        throw std::runtime_error("unterminated JSON string");
    }
    Value value(unsigned depth) {
        if (depth > 32U) throw std::runtime_error("JSON nesting limit");
        ws();
        if (pos_ >= input_.size()) throw std::runtime_error("missing JSON value");
        char c = input_[pos_];
        if (c == '"') return Value{string()};
        if (c == '{') {
            ++pos_; Object obj; ws();
            if (eat('}')) return Value{obj};
            do {
                std::string key = string();
                if (!eat(':')) throw std::runtime_error("expected colon");
                if (!obj.emplace(key, value(depth + 1U)).second) throw std::runtime_error("duplicate object key");
                ws();
                if (eat('}')) break;
                if (!eat(',')) throw std::runtime_error("expected comma");
            } while (true);
            return Value{obj};
        }
        if (c == '[') {
            ++pos_; Array arr; ws();
            if (eat(']')) return Value{arr};
            do {
                arr.push_back(value(depth + 1U)); ws();
                if (eat(']')) break;
                if (!eat(',')) throw std::runtime_error("expected comma");
            } while (true);
            return Value{arr};
        }
        if (input_.compare(pos_, 4, "true") == 0) { pos_ += 4; return Value{true}; }
        if (input_.compare(pos_, 5, "false") == 0) { pos_ += 5; return Value{false}; }
        if (input_.compare(pos_, 4, "null") == 0) { pos_ += 4; return Value{nullptr}; }
        return Value{number()};
    }
};
} // namespace agent::json

#endif
