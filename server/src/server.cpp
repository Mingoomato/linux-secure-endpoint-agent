#include "agent/json.hpp"
#include "agent/http.hpp"
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <sqlite3.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <signal.h>
#include <unistd.h>
#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cerrno>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <locale>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {
using agent::json::Value;
using agent::json::Array;
using agent::http::Request;
volatile sig_atomic_t stopping = 0;
void stop_signal(int sig) { (void)sig; stopping = 1; }

std::string arg(int argc, char **argv, const std::string &name, const std::string &fallback={}) {
    for (int i = 1; i + 1 < argc; ++i) if (argv[i] == name) return argv[i+1];
    return fallback;
}
std::string escape(const std::string &s) {
    std::ostringstream o;
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') o << '\\' << static_cast<char>(c);
        else if (c == '\n') o << "\\n";
        else if (c >= 0x20U) o << static_cast<char>(c);
    }
    return o.str();
}
const Value &required(const Value &v, const char *key) {
    const Value *p = v.get(key);
    if (!p) throw std::runtime_error(std::string("missing field ") + key);
    return *p;
}
void sql_check(int rc, sqlite3 *db, const char *where) {
    if (rc != SQLITE_OK && rc != SQLITE_DONE && rc != SQLITE_ROW)
        throw std::runtime_error(std::string(where) + ": " + sqlite3_errmsg(db));
}
sqlite3 *open_db(const std::string &path) {
    sqlite3 *db = nullptr;
    int rc = sqlite3_open_v2(path.c_str(), &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
    if (rc != SQLITE_OK) {
        std::string message = db ? sqlite3_errmsg(db) : "open failed";
        if (db) sqlite3_close(db);
        throw std::runtime_error(message);
    }
    (void)chmod(path.c_str(), 0600);
    sqlite3_busy_timeout(db, 5000);
    const char *schema =
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;"
        "CREATE TABLE IF NOT EXISTS agents(agent_id TEXT PRIMARY KEY,enabled INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS events(agent_id TEXT NOT NULL,event_id TEXT NOT NULL,"
        " sequence INTEGER NOT NULL,payload_hash TEXT NOT NULL,received_at INTEGER NOT NULL,"
        " PRIMARY KEY(agent_id,event_id));"
        "CREATE TABLE IF NOT EXISTS policies(tenant_scope TEXT PRIMARY KEY,revision INTEGER NOT NULL,"
        " policy_id TEXT NOT NULL,document BLOB NOT NULL,signature BLOB NOT NULL,published_at INTEGER NOT NULL);";
    char *error = nullptr;
    rc = sqlite3_exec(db, schema, nullptr, nullptr, &error);
    if (rc != SQLITE_OK) {
        std::string message = error ? error : sqlite3_errmsg(db);
        sqlite3_free(error); sqlite3_close(db); throw std::runtime_error(message);
    }
    return db;
}
std::set<std::string> read_allowlist(const std::string &path) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("cannot open --agents allowlist");
    std::set<std::string> result;
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty() && line.size() <= 128U) result.insert(line);
    }
    if (result.empty()) throw std::runtime_error("agent allowlist is empty");
    return result;
}
std::string peer_cn(SSL *ssl) {
    X509 *cert = SSL_get1_peer_certificate(ssl);
    if (!cert) return {};
    char cn[256] {};
    int n = X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, cn, sizeof(cn));
    X509_free(cert);
    return n > 0 ? std::string(cn, static_cast<std::size_t>(n)) : std::string{};
}
bool contains_sensitive_key(const Value &v, unsigned depth=0) {
    if (depth > 32U) return true;
    if (const auto *o = std::get_if<agent::json::Object>(&v.data)) {
        for (const auto &[key, child] : *o) {
            if (key == "path" || key == "content" || key == "environment" ||
                key == "token" || key == "private_key" || key == "secret")
                return true;
            if (contains_sensitive_key(child, depth + 1U)) return true;
        }
    } else if (const auto *a = std::get_if<Array>(&v.data)) {
        for (const auto &child : *a) if (contains_sensitive_key(child, depth + 1U)) return true;
    }
    return false;
}

agent::http::Request read_request(SSL *ssl, int socket_fd,
        std::chrono::steady_clock::time_point deadline) {
    std::string raw;
    std::array<char, 8192> buffer {};
    for (;;) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) throw std::runtime_error("HTTP request absolute deadline exceeded");
        if (raw.size() > agent::http::kMaxHttpHeader + 4U + agent::http::kMaxHttpBody)
            throw std::runtime_error("HTTP request exceeds size limit");
        const std::optional<agent::http::RequestHead> head = agent::http::parse_request_head(raw);
        if (head) {
            const std::size_t expected_size = head->header_size + head->body_size;
            if (raw.size() > expected_size) throw std::runtime_error("bytes follow the framed HTTP request");
            if (raw.size() == expected_size) return agent::http::parse_request(raw);
        }
        const auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(
            deadline - now + std::chrono::milliseconds(2));
        const auto max_io_budget = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::seconds(5));
        const bool deadline_limited = remaining <= max_io_budget;
        const auto io_budget = std::min(remaining, max_io_budget);
        const auto timeout_us = std::max<std::int64_t>(1, io_budget.count());
        timeval receive_timeout {
            static_cast<time_t>(timeout_us / 1000000),
            static_cast<suseconds_t>(timeout_us % 1000000)
        };
        if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &receive_timeout, sizeof(receive_timeout)) != 0)
            throw std::runtime_error("HTTP request deadline setup failed");
        int n = SSL_read(ssl, buffer.data(), static_cast<int>(buffer.size()));
        const int read_errno = errno;
        const int ssl_error = n <= 0 ? SSL_get_error(ssl, n) : SSL_ERROR_NONE;
        if (n <= 0) {
            if (std::chrono::steady_clock::now() >= deadline ||
                (deadline_limited && ssl_error == SSL_ERROR_SYSCALL &&
                    (read_errno == EAGAIN || read_errno == EWOULDBLOCK)))
                throw std::runtime_error("HTTP request absolute deadline exceeded");
            throw std::runtime_error("incomplete HTTP request body");
        }
        raw.append(buffer.data(), static_cast<std::size_t>(n));
    }
}
void write_all(SSL *ssl, const std::string &text) {
    std::size_t off = 0;
    while (off < text.size()) {
        int n = SSL_write(ssl, text.data() + off, static_cast<int>(text.size() - off));
        if (n <= 0) throw std::runtime_error("TLS response write failed");
        off += static_cast<std::size_t>(n);
    }
}
void respond(SSL *ssl, int status, const std::string &reason, const std::string &body,
             const std::string &extra_headers = {}) {
    std::string response = "HTTP/1.1 " + std::to_string(status) + " " + reason +
        "\r\nContent-Type: application/json\r\nConnection: close\r\n" + extra_headers +
        "Content-Length: " +
        std::to_string(body.size()) + "\r\n\r\n" + body;
    write_all(ssl, response);
}
void reject_sensitive(const Value &value) {
    if (contains_sensitive_key(value)) throw std::runtime_error("privacy field rejected");
}
struct ScopedFd {
    int value = -1;
    explicit ScopedFd(int fd) : value(fd) {}
    ~ScopedFd() { if (value >= 0) close(value); }
    ScopedFd(const ScopedFd &) = delete;
    ScopedFd &operator=(const ScopedFd &) = delete;
    int get() const { return value; }
};

std::string json_quote(const std::string &value) {
    std::ostringstream out;
    out << '"';
    static const char hex[] = "0123456789abcdef";
    for (unsigned char c : value) {
        if (c == '"' || c == '\\') out << '\\' << static_cast<char>(c);
        else if (c == '\b') out << "\\b";
        else if (c == '\f') out << "\\f";
        else if (c == '\n') out << "\\n";
        else if (c == '\r') out << "\\r";
        else if (c == '\t') out << "\\t";
        else if (c < 0x20U) out << "\\u00" << hex[c >> 4U] << hex[c & 0x0fU];
        else out << static_cast<char>(c);
    }
    out << '"';
    return out.str();
}
std::string canonical_json(const Value &value) {
    if (std::holds_alternative<std::nullptr_t>(value.data)) return "null";
    if (const auto *v = std::get_if<bool>(&value.data)) return *v ? "true" : "false";
    if (const auto *v = std::get_if<double>(&value.data)) {
        if (!std::isfinite(*v)) throw std::runtime_error("non-finite JSON number");
        std::ostringstream out;
        out.imbue(std::locale::classic());
        out << std::setprecision(17) << *v;
        return out.str();
    }
    if (const auto *v = std::get_if<std::string>(&value.data)) return json_quote(*v);
    if (const auto *v = std::get_if<Array>(&value.data)) {
        std::string out = "[";
        for (std::size_t i = 0; i < v->size(); ++i) {
            if (i) out += ',';
            out += canonical_json((*v)[i]);
        }
        out += ']';
        return out;
    }
    const auto *v = std::get_if<agent::json::Object>(&value.data);
    if (!v) throw std::runtime_error("unsupported JSON value");
    std::string out = "{";
    bool comma = false;
    for (const auto &[key, item] : *v) {
        if (comma) out += ',';
        comma = true;
        out += json_quote(key) + ':' + canonical_json(item);
    }
    out += '}';
    return out;
}
std::string sha256(const std::string &data) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    if (EVP_Digest(data.data(), data.size(), digest, &length, EVP_sha256(), nullptr) != 1 || length != 32U)
        throw std::runtime_error("payload SHA-256 failed");
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < length; ++i) out << std::setw(2) << static_cast<unsigned>(digest[i]);
    return out.str();
}

std::string read_admin_token(const std::string &path) {
    struct stat token_stat {};
    if (stat(path.c_str(), &token_stat) != 0 || !S_ISREG(token_stat.st_mode) ||
        token_stat.st_uid != geteuid() || (token_stat.st_mode & 0077) != 0)
        throw std::runtime_error("admin token file must be owned by the server user with mode 0600");
    std::ifstream input(path, std::ios::binary);
    std::string token;
    if (!std::getline(input, token) || token.size() < 32U || token.size() > 256U || input.peek() != EOF ||
        !std::all_of(token.begin(), token.end(), [](unsigned char c) {
            return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '~' || c == '-';
        }))
        throw std::runtime_error("admin token file must contain one 32-256 character token");
    return token;
}

EVP_PKEY *load_policy_signing_key(const std::string &path) {
    struct stat key_stat {};
    if (stat(path.c_str(), &key_stat) != 0 || !S_ISREG(key_stat.st_mode) ||
        key_stat.st_uid != geteuid() || (key_stat.st_mode & 0077) != 0)
        throw std::runtime_error("policy signing key must be owned by the server user with mode 0600");
    FILE *file = fopen(path.c_str(), "r");
    if (!file) throw std::runtime_error("cannot open policy signing key");
    EVP_PKEY *key = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
    fclose(file);
    if (!key || EVP_PKEY_id(key) != EVP_PKEY_ED25519) {
        if (key) EVP_PKEY_free(key);
        throw std::runtime_error("policy signing key must be Ed25519 PEM");
    }
    return key;
}

std::string sign_policy(EVP_PKEY *key, const std::string &document) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("policy signature context allocation failed");
    std::size_t signature_size = 0;
    bool ok = EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, key) == 1 &&
        EVP_DigestSign(ctx, nullptr, &signature_size,
            reinterpret_cast<const unsigned char *>(document.data()), document.size()) == 1 &&
        signature_size == 64U;
    std::string signature(signature_size, '\0');
    if (ok) ok = EVP_DigestSign(ctx, reinterpret_cast<unsigned char *>(signature.data()), &signature_size,
        reinterpret_cast<const unsigned char *>(document.data()), document.size()) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok || signature_size != 64U) throw std::runtime_error("policy signing failed");
    signature.resize(signature_size);
    return signature;
}

std::string hex_encode(const std::string &bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2U);
    for (unsigned char byte : bytes) {
        result.push_back(digits[byte >> 4U]);
        result.push_back(digits[byte & 0x0fU]);
    }
    return result;
}

std::string sha256_hex(const std::string &data) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest {};
    unsigned int size = 0;
    if (EVP_Digest(data.data(), data.size(), digest.data(), &size, EVP_sha256(), nullptr) != 1 || size != 32U)
        throw std::runtime_error("policy ETag digest failed");
    static constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(64U);
    for (unsigned int i = 0; i < size; ++i) {
        result.push_back(digits[digest[i] >> 4U]);
        result.push_back(digits[digest[i] & 0x0fU]);
    }
    return result;
}

std::time_t parse_policy_time(const std::string &value, const char *field) {
    std::tm parsed_time {};
    if (value.size() != 20U || value.back() != 'Z' ||
        strptime(value.c_str(), "%Y-%m-%dT%H:%M:%SZ", &parsed_time) != value.c_str() + value.size())
        throw std::runtime_error(std::string("policy ") + field + " format is invalid");
    const std::tm requested_time = parsed_time;
    const std::time_t epoch = timegm(&parsed_time);
    std::tm normalized_time {};
    if (epoch == static_cast<std::time_t>(-1) || gmtime_r(&epoch, &normalized_time) == nullptr ||
        normalized_time.tm_year != requested_time.tm_year || normalized_time.tm_mon != requested_time.tm_mon ||
        normalized_time.tm_mday != requested_time.tm_mday || normalized_time.tm_hour != requested_time.tm_hour ||
        normalized_time.tm_min != requested_time.tm_min || normalized_time.tm_sec != requested_time.tm_sec)
        throw std::runtime_error(std::string("policy ") + field + " calendar value is invalid");
    return epoch;
}

std::pair<std::string, std::uint64_t> validate_publishable_policy(
        const std::string &document, const std::string &expected_tenant) {
    if (document.empty() || document.size() > 65536U)
        throw std::runtime_error("policy document size is invalid");
    const Value policy = agent::json::Parser(document).parse();
    if (required(policy, "schema_version").string_or() != "policy.v1")
        throw std::runtime_error("unsupported policy schema");
    const auto *object = std::get_if<agent::json::Object>(&policy.data);
    if (!object) throw std::runtime_error("policy must be an object");
    const std::set<std::string> top_allowed = {"schema_version", "policy_id", "revision", "issuer", "issued_at",
        "expires_at", "tenant_scope", "allowed_actions", "settings"};
    for (const auto &[name, value] : *object) {
        (void)value;
        if (!top_allowed.contains(name)) throw std::runtime_error("policy field rejected");
    }
    const std::string policy_id = required(policy, "policy_id").string_or();
    const std::string issuer = required(policy, "issuer").string_or();
    const std::string tenant = required(policy, "tenant_scope").string_or();
    if (policy_id.empty() || policy_id.size() > 128U || issuer.empty() || issuer.size() > 128U ||
        tenant.empty() || tenant != expected_tenant)
        throw std::runtime_error("policy identity or tenant scope is invalid");
    const double revision_number = required(policy, "revision").number_or(-1.0);
    constexpr double max_safe_integer = 9007199254740991.0;
    if (revision_number < 1.0 || revision_number > max_safe_integer || std::floor(revision_number) != revision_number)
        throw std::runtime_error("SEA_POLICY_REVISION_INVALID");
    const auto revision = static_cast<std::uint64_t>(revision_number);

    const std::time_t issued_epoch = parse_policy_time(required(policy, "issued_at").string_or(), "issued_at");
    const std::time_t expiry_epoch = parse_policy_time(required(policy, "expires_at").string_or(), "expires_at");
    if (issued_epoch > std::time(nullptr) + 300)
        throw std::runtime_error("policy issued_at is in the future");
    if (expiry_epoch <= std::time(nullptr) || expiry_epoch <= issued_epoch)
        throw std::runtime_error("SEA_POLICY_EXPIRED: invalid or expired policy");

    const auto *actions = std::get_if<Array>(&required(policy, "allowed_actions").data);
    if (!actions || actions->empty() || actions->size() > 8U)
        throw std::runtime_error("policy actions must be a bounded non-empty array");
    for (const auto &action : *actions) {
        const std::string name = action.string_or();
        if (name != "telemetry.configure" && name != "monitor.roots.configure")
            throw std::runtime_error("policy action rejected");
    }
    const auto *settings = std::get_if<agent::json::Object>(&required(policy, "settings").data);
    if (!settings) throw std::runtime_error("policy settings must be an object");
    for (const auto &[name, value] : *settings) {
        if (name == "telemetry_enabled") {
            if (!std::get_if<bool>(&value.data)) throw std::runtime_error("telemetry_enabled must be boolean");
        } else if (name == "sample_rate") {
            const double rate = value.number_or(-1.0);
            if (rate < 0.0 || rate > 1.0) throw std::runtime_error("sample_rate is out of range");
        } else if (name == "monitored_roots") {
            const auto *roots = std::get_if<Array>(&value.data);
            if (!roots || roots->size() > 32U) throw std::runtime_error("monitored_roots must be a bounded array");
            for (const auto &root : *roots) {
                const std::string path = root.string_or();
                if (path.empty() || path.front() != '/' || path.find("/../") != std::string::npos ||
                    path.ends_with("/.."))
                    throw std::runtime_error("monitored root path is invalid");
            }
        } else throw std::runtime_error("policy setting rejected");
    }
    return {policy_id, revision};
}

struct PublishedPolicy {
    std::string policy_id;
    std::string document;
    std::string signature;
    std::uint64_t revision = 0;
    bool unchanged = false;
};

PublishedPolicy publish_policy(sqlite3 *db, EVP_PKEY *signing_key, const std::string &tenant,
                               const std::string &document) {
    auto [policy_id, revision] = validate_publishable_policy(document, tenant);
    std::string signature = sign_policy(signing_key, document);
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr) != SQLITE_OK)
        throw std::runtime_error("policy publish transaction unavailable");
    try {
        sqlite3_stmt *current = nullptr;
        sql_check(sqlite3_prepare_v2(db,
            "SELECT revision,document,signature,policy_id FROM policies WHERE tenant_scope=?1",
            -1, &current, nullptr), db, "prepare current policy read");
        sqlite3_bind_text(current, 1, tenant.c_str(), -1, SQLITE_TRANSIENT);
        const int current_rc = sqlite3_step(current);
        std::uint64_t old_revision = 0;
        std::string old_document;
        std::string old_signature;
        std::string old_policy_id;
        if (current_rc == SQLITE_ROW) {
            old_revision = static_cast<std::uint64_t>(sqlite3_column_int64(current, 0));
            const auto *doc_data = static_cast<const char *>(sqlite3_column_blob(current, 1));
            const int doc_size = sqlite3_column_bytes(current, 1);
            if (doc_data && doc_size > 0) old_document.assign(doc_data, static_cast<std::size_t>(doc_size));
            const auto *sig_data = static_cast<const char *>(sqlite3_column_blob(current, 2));
            const int sig_size = sqlite3_column_bytes(current, 2);
            if (sig_data && sig_size > 0) old_signature.assign(sig_data, static_cast<std::size_t>(sig_size));
            const auto *id_data = reinterpret_cast<const char *>(sqlite3_column_text(current, 3));
            if (id_data) old_policy_id = id_data;
        } else if (current_rc != SQLITE_DONE) {
            sqlite3_finalize(current);
            throw std::runtime_error("current policy read failed");
        }
        sqlite3_finalize(current);
        if (current_rc == SQLITE_ROW && revision <= old_revision) {
            if (revision == old_revision && document == old_document) {
                sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
                return {old_policy_id, old_document, old_signature, old_revision, true};
            }
            throw std::runtime_error("SEA_POLICY_ROLLBACK");
        }
        sqlite3_stmt *write = nullptr;
        sql_check(sqlite3_prepare_v2(db,
            "INSERT INTO policies(tenant_scope,revision,policy_id,document,signature,published_at)"
            " VALUES(?1,?2,?3,?4,?5,strftime('%s','now'))"
            " ON CONFLICT(tenant_scope) DO UPDATE SET revision=excluded.revision,policy_id=excluded.policy_id,"
            " document=excluded.document,signature=excluded.signature,published_at=excluded.published_at",
            -1, &write, nullptr), db, "prepare policy publish");
        sqlite3_bind_text(write, 1, tenant.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(write, 2, static_cast<sqlite3_int64>(revision));
        sqlite3_bind_text(write, 3, policy_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_blob(write, 4, document.data(), static_cast<int>(document.size()), SQLITE_TRANSIENT);
        sqlite3_bind_blob(write, 5, signature.data(), static_cast<int>(signature.size()), SQLITE_TRANSIENT);
        sql_check(sqlite3_step(write), db, "publish policy");
        sqlite3_finalize(write);
        if (sqlite3_exec(db, "COMMIT", nullptr, nullptr, nullptr) != SQLITE_OK)
            throw std::runtime_error("policy publish commit failed");
        return {policy_id, document, signature, revision, false};
    } catch (...) {
        sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

std::optional<PublishedPolicy> current_policy(sqlite3 *db, const std::string &tenant) {
    sqlite3_stmt *statement = nullptr;
    sql_check(sqlite3_prepare_v2(db,
        "SELECT revision,policy_id,document,signature FROM policies WHERE tenant_scope=?1",
        -1, &statement, nullptr), db, "prepare policy fetch");
    sqlite3_bind_text(statement, 1, tenant.c_str(), -1, SQLITE_TRANSIENT);
    const int rc = sqlite3_step(statement);
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(statement);
        return std::nullopt;
    }
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(statement);
        throw std::runtime_error("policy fetch failed");
    }
    PublishedPolicy result;
    result.revision = static_cast<std::uint64_t>(sqlite3_column_int64(statement, 0));
    const auto *id = reinterpret_cast<const char *>(sqlite3_column_text(statement, 1));
    if (id) result.policy_id = id;
    const auto *document = static_cast<const char *>(sqlite3_column_blob(statement, 2));
    const int document_size = sqlite3_column_bytes(statement, 2);
    if (document && document_size > 0) result.document.assign(document, static_cast<std::size_t>(document_size));
    const auto *signature = static_cast<const char *>(sqlite3_column_blob(statement, 3));
    const int signature_size = sqlite3_column_bytes(statement, 3);
    if (signature && signature_size > 0) result.signature.assign(signature, static_cast<std::size_t>(signature_size));
    sqlite3_finalize(statement);
    if (result.document.empty() || result.signature.size() != 64U)
        throw std::runtime_error("stored policy is incomplete");
    return result;
}

bool valid_admin_authorization(const std::string &header, const std::string &token) {
    const std::string expected = "Bearer " + token;
    return header.size() == expected.size() &&
        CRYPTO_memcmp(header.data(), expected.data(), expected.size()) == 0;
}

void ingest(sqlite3 *db, const std::set<std::string> &agents, SSL *ssl,
            const Request &request, const std::string &identity) {
    Value batch = agent::json::Parser(request.body).parse();
    if (required(batch, "schema_version").string_or() != "agent_batch.v1")
        throw std::runtime_error("protocol schema mismatch");
    std::string claimed = required(batch, "agent_id").string_or();
    if (claimed != identity || !agents.contains(identity))
        throw std::runtime_error("agent identity mismatch or not registered");
    const Value &events_value = required(batch, "events");
    const auto *events = std::get_if<Array>(&events_value.data);
    if (!events || events->size() > 100U) throw std::runtime_error("invalid batch size");
    std::vector<std::string> accepted, duplicates;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr) != SQLITE_OK)
        throw std::runtime_error("database transaction unavailable");
    try {
        sqlite3_stmt *stmt = nullptr;
        sql_check(sqlite3_prepare_v2(db,
            "INSERT OR IGNORE INTO events(agent_id,event_id,sequence,payload_hash,received_at)"
            " VALUES(?1,?2,?3,?4,strftime('%s','now'))", -1, &stmt, nullptr), db, "prepare ingest");
        for (const auto &event : *events) {
            reject_sensitive(event);
            std::string id = required(event, "event_id").string_or();
            std::string observed = required(event, "observed_at").string_or();
            std::string kind = required(event, "kind").string_or();
            std::string hash = required(event, "payload_hash").string_or();
            double sequence_number = required(event, "sequence").number_or(0);
            if (!std::isfinite(sequence_number) || sequence_number < 1 ||
                sequence_number > static_cast<double>(INT64_MAX) || std::floor(sequence_number) != sequence_number)
                throw std::runtime_error("invalid event sequence");
            std::uint64_t seq = static_cast<std::uint64_t>(sequence_number);
            const Value &payload = required(event, "payload");
            if (id.empty() || observed.empty() || kind.empty() || hash.size() != 64U || seq == 0 ||
                !std::all_of(hash.begin(), hash.end(), [](unsigned char c) {
                    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
                }) || sha256(canonical_json(payload)) != hash)
                throw std::runtime_error("invalid event record");
            sqlite3_bind_text(stmt, 1, identity.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(stmt, 3, static_cast<sqlite3_int64>(seq));
            sqlite3_bind_text(stmt, 4, hash.c_str(), -1, SQLITE_TRANSIENT);
            sql_check(sqlite3_step(stmt), db, "ingest event");
            if (sqlite3_changes(db) == 1) accepted.push_back(id);
            else {
                sqlite3_stmt *existing = nullptr;
                sql_check(sqlite3_prepare_v2(db,
                    "SELECT sequence,payload_hash FROM events WHERE agent_id=?1 AND event_id=?2",
                    -1, &existing, nullptr), db, "prepare duplicate check");
                sqlite3_bind_text(existing, 1, identity.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(existing, 2, id.c_str(), -1, SQLITE_TRANSIENT);
                int existing_rc = sqlite3_step(existing);
                bool identical = existing_rc == SQLITE_ROW &&
                    static_cast<std::uint64_t>(sqlite3_column_int64(existing, 0)) == seq &&
                    hash == reinterpret_cast<const char *>(sqlite3_column_text(existing, 1));
                sqlite3_finalize(existing);
                if (!identical) throw std::runtime_error("event ID reused with different content");
                duplicates.push_back(id);
            }
            sqlite3_reset(stmt); sqlite3_clear_bindings(stmt);
        }
        sqlite3_finalize(stmt);
        if (sqlite3_exec(db, "COMMIT", nullptr, nullptr, nullptr) != SQLITE_OK)
            throw std::runtime_error("database commit failed");
    } catch (...) {
        sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
    std::ostringstream body;
    body << "{\"schema_version\":\"agent_ack.v1\",\"accepted_ids\":[";
    for (std::size_t i=0;i<accepted.size();++i) { if(i)body<<','; body<<'"'<<escape(accepted[i])<<'"'; }
    body << "],\"duplicate_ids\":[";
    for (std::size_t i=0;i<duplicates.size();++i) { if(i)body<<','; body<<'"'<<escape(duplicates[i])<<'"'; }
    body << "],\"rejected\":[],\"server_time\":\"" << static_cast<long long>(time(nullptr)) << "\"}";
    respond(ssl, 200, "OK", body.str());
}

void serve_one(sqlite3 *db, const std::set<std::string> &agents, const std::set<std::string> &operators,
               const std::string &admin_token, const std::string &tenant, EVP_PKEY *policy_key,
               SSL_CTX *ctx, int fd, std::chrono::milliseconds request_deadline) {
    ScopedFd socket_fd(fd);
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl(SSL_new(ctx), SSL_free);
    if (!ssl) return;
    SSL_set_fd(ssl.get(), socket_fd.get());
    timeval io_timeout {5, 0};
    (void)setsockopt(socket_fd.get(), SOL_SOCKET, SO_RCVTIMEO, &io_timeout, sizeof(io_timeout));
    (void)setsockopt(socket_fd.get(), SOL_SOCKET, SO_SNDTIMEO, &io_timeout, sizeof(io_timeout));
    if (SSL_accept(ssl.get()) != 1 || SSL_get_verify_result(ssl.get()) != X509_V_OK) {
        return;
    }
    std::string identity = peer_cn(ssl.get());
    if (identity.empty() || (!agents.contains(identity) && !operators.contains(identity))) {
        respond(ssl.get(), 403, "Forbidden", "{\"error\":\"SEA_AGENT_UNAUTHORIZED\"}");
        SSL_shutdown(ssl.get()); return;
    }
    try {
        const auto deadline = std::chrono::steady_clock::now() + request_deadline;
        Request req = read_request(ssl.get(), socket_fd.get(), deadline);
        if (req.path == "/v1/admin/policies" && req.method == "POST") {
            if (!operators.contains(identity) || !valid_admin_authorization(req.authorization, admin_token)) {
                respond(ssl.get(), 403, "Forbidden", "{\"error\":\"SEA_OPERATOR_UNAUTHORIZED\"}");
            } else if (agent::http::lowercase_ascii(req.content_type) != "application/json") {
                respond(ssl.get(), 400, "Bad Request", "{\"error\":\"policy_requires_json\"}");
            } else {
                PublishedPolicy published = publish_policy(db, policy_key, tenant, req.body);
                std::string body = "{\"schema_version\":\"policy_publish_ack.v1\",\"revision\":" +
                    std::to_string(published.revision) + ",\"status\":" +
                    json_quote(published.unchanged ? "unchanged" : "published") + "}";
                respond(ssl.get(), published.unchanged ? 200 : 201,
                    published.unchanged ? "OK" : "Created", body);
            }
        } else if (req.path == "/healthz" && req.method == "GET") {
            respond(ssl.get(), 200, "OK", "{\"status\":\"ok\"}");
        } else if (!agents.contains(identity)) {
            respond(ssl.get(), 403, "Forbidden", "{\"error\":\"SEA_AGENT_UNAUTHORIZED\"}");
        } else if (req.path == "/v1/agents/self/events:batch" && req.method == "POST") {
            if (agent::http::lowercase_ascii(req.content_type) != "application/json")
                throw std::runtime_error("event batch requires application/json Content-Type");
            ingest(db, agents, ssl.get(), req, identity);
        } else if (req.path == "/v1/agents/self/heartbeat" && req.method == "POST") {
            respond(ssl.get(), 200, "OK", "{\"schema_version\":\"heartbeat_ack.v1\",\"status\":\"ok\"}");
        } else if (req.path == "/v1/agents/self/status" && req.method == "GET") {
            respond(ssl.get(), 200, "OK", "{\"schema_version\":\"agent_status.v1\",\"state\":\"registered\"}");
        } else if (req.path == "/v1/agents/self/policy" && req.method == "GET") {
            const auto policy = current_policy(db, tenant);
            if (!policy) {
                respond(ssl.get(), 404, "Not Found", "{\"error\":\"SEA_POLICY_NOT_FOUND\"}");
            } else {
                const std::string etag = "\"" + sha256_hex(policy->document) + "\"";
                if (req.if_none_match == etag) {
                    respond(ssl.get(), 304, "Not Modified", "",
                        "ETag: " + etag + "\r\nCache-Control: no-store\r\n");
                    SSL_shutdown(ssl.get());
                    return;
                }
                const std::string body = "{\"schema_version\":\"policy_envelope.v1\",\"policy_id\":" +
                    json_quote(policy->policy_id) + ",\"revision\":" + std::to_string(policy->revision) +
                    ",\"policy_document\":" + json_quote(policy->document) +
                    ",\"signature_hex\":" + json_quote(hex_encode(policy->signature)) + "}";
                respond(ssl.get(), 200, "OK", body,
                    "ETag: " + etag + "\r\nCache-Control: no-store\r\n");
            }
        } else {
            respond(ssl.get(), 404, "Not Found", "{\"error\":\"not_found\"}");
        }
    } catch (const std::exception &e) {
        std::cerr << "request rejected: " << e.what() << '\n';
        try { respond(ssl.get(), 400, "Bad Request", "{\"error\":\"request_rejected\"}"); } catch (...) {}
    }
    SSL_shutdown(ssl.get());
}

int run_server(int argc, char **argv) {
    std::string bind = arg(argc, argv, "--bind", "127.0.0.1");
    if (bind != "127.0.0.1" && bind != "localhost")
        throw std::runtime_error("SEA_SCOPE_INVALID: server is loopback-only");
    std::string cert = arg(argc, argv, "--cert"), key = arg(argc, argv, "--key");
    std::string ca = arg(argc, argv, "--ca"), agents_file = arg(argc, argv, "--agents");
    std::string operators_file = arg(argc, argv, "--operators");
    std::string admin_token_file = arg(argc, argv, "--admin-token-file");
    std::string policy_key_file = arg(argc, argv, "--policy-key");
    std::string tenant = arg(argc, argv, "--tenant");
    std::string dbfile = arg(argc, argv, "--db", "./server.sqlite");
    int port = std::stoi(arg(argc, argv, "--port", "8443"));
    if (port < 1024 || port > 65535) throw std::runtime_error("invalid listen port");
    const int request_deadline_ms = std::stoi(arg(argc, argv, "--request-deadline-ms", "10000"));
    if (request_deadline_ms < 100 || request_deadline_ms > 60000)
        throw std::runtime_error("request deadline must be between 100 and 60000 ms");
    const auto request_deadline = std::chrono::milliseconds(request_deadline_ms);
    std::set<std::string> agents = read_allowlist(agents_file);
    std::set<std::string> operators = read_allowlist(operators_file);
    if (tenant.empty() || tenant.size() > 128U) throw std::runtime_error("--tenant must be configured");
    const std::string admin_token = read_admin_token(admin_token_file);
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> policy_key(
        load_policy_signing_key(policy_key_file), EVP_PKEY_free);
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) throw std::runtime_error("TLS context allocation failed");
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    if (SSL_CTX_use_certificate_chain_file(ctx, cert.c_str()) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, key.c_str(), SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(ctx) != 1 || SSL_CTX_load_verify_locations(ctx, ca.c_str(), nullptr) != 1) {
        SSL_CTX_free(ctx); throw std::runtime_error("TLS certificate configuration failed");
    }
    struct stat key_stat {};
    if (stat(key.c_str(), &key_stat) != 0 || (key_stat.st_mode & 0077) != 0) {
        SSL_CTX_free(ctx); throw std::runtime_error("server key must have mode 0600");
    }
    sqlite3 *db = open_db(dbfile);
    int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0) { sqlite3_close(db); SSL_CTX_free(ctx); throw std::runtime_error("socket failed"); }
    int one = 1; (void)setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in address {};
    address.sin_family = AF_INET; address.sin_port = htons(static_cast<std::uint16_t>(port));
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(listener, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0) {
        close(listener); sqlite3_close(db); SSL_CTX_free(ctx); throw std::runtime_error("loopback bind failed");
    }
    if (listen(listener, 64) != 0) {
        close(listener); sqlite3_close(db); SSL_CTX_free(ctx); throw std::runtime_error("listen failed");
    }
    struct sigaction action {};
    action.sa_handler = stop_signal;
    sigemptyset(&action.sa_mask);
    (void)sigaction(SIGINT, &action, nullptr);
    (void)sigaction(SIGTERM, &action, nullptr);
    std::cout << "sw-server listening on 127.0.0.1:" << port << " (mTLS, lab only; request deadline "
              << request_deadline_ms << " ms)\n";
    while (!stopping) {
        sockaddr_storage peer {};
        socklen_t peer_len = sizeof(peer);
        int fd = accept4(listener, reinterpret_cast<sockaddr *>(&peer), &peer_len, SOCK_CLOEXEC);
        if (fd < 0 && errno == EINTR) {
            if (stopping) break;
            continue;
        }
        if (fd < 0) break;
        serve_one(db, agents, operators, admin_token, tenant, policy_key.get(), ctx, fd, request_deadline);
    }
    close(listener); sqlite3_close(db); SSL_CTX_free(ctx);
    return 0;
}
} // namespace

int main(int argc, char **argv) {
    try {
        if (argc < 2 || std::string(argv[1]) == "--help") {
            std::cout << "sw-server run --cert FILE --key FILE --ca FILE --agents FILE --operators FILE "
                         "--admin-token-file FILE --policy-key FILE --tenant ID "
                         "[--db FILE --port N --request-deadline-ms N]\n";
            return argc < 2 ? 2 : 0;
        }
        if (std::string(argv[1]) != "run") throw std::runtime_error("unknown command");
        return run_server(argc, argv);
    } catch (const std::exception &e) {
        std::cerr << "sw-server: " << e.what() << '\n'; return 2;
    }
}
