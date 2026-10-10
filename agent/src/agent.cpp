#include "agent/json.hpp"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <sqlite3.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <poll.h>
#include <dirent.h>
#include <signal.h>
#include <unistd.h>
#include <algorithm>
#include <array>
#include <cmath>
#include <chrono>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <initializer_list>
#include <iostream>
#include <locale>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include <sys/types.h>
#include <sys/time.h>

namespace {
using agent::json::Value;
using agent::json::Array;
using agent::json::Object;
struct Config {
    std::string host = "127.0.0.1", port = "8443", agent_id, ca, cert, key, store, tenant;
};
struct Queued {
    std::string id, observed, payload, hash;
    std::uint64_t sequence = 0;
};
struct RuntimePolicy {
    bool present = false;
    bool expired = false;
    bool telemetry_enabled = false;
    std::uint64_t revision = 0;
    double sample_rate = 0.0;
    std::size_t monitored_root_count = 0;
    std::vector<std::filesystem::path> monitored_roots;
    std::string issuer;
    std::string tenant;
};
RuntimePolicy active_policy(sqlite3 *db, const std::string &expected_tenant, bool require_scope);
volatile sig_atomic_t stopping = 0;
void stop_signal(int sig) { (void)sig; stopping = 1; }

std::string arg(int argc, char **argv, const std::string &name, const std::string &fallback={}) {
    for (int i = 1; i + 1 < argc; ++i) if (argv[i] == name) return argv[i+1];
    return fallback;
}
bool flag(int argc, char **argv, const std::string &name) {
    return std::find(argv + 1, argv + argc, name) != argv + argc;
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
std::string uuid() {
    std::array<unsigned char, 16> b {};
    if (RAND_bytes(b.data(), static_cast<int>(b.size())) != 1)
        throw std::runtime_error("secure random generation failed");
    b[6] = static_cast<unsigned char>((b[6] & 0x0fU) | 0x40U);
    b[8] = static_cast<unsigned char>((b[8] & 0x3fU) | 0x80U);
    char out[37];
    std::snprintf(out, sizeof(out),
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);
    return out;
}
std::string now_iso() {
    std::time_t now = std::time(nullptr);
    std::tm tm {};
    gmtime_r(&now, &tm);
    char out[32];
    if (std::strftime(out, sizeof(out), "%Y-%m-%dT%H:%M:%SZ", &tm) == 0)
        throw std::runtime_error("timestamp formatting failed");
    return out;
}
std::string sha256(const std::string &data) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest {};
    unsigned int len = 0;
    if (EVP_Digest(data.data(), data.size(), digest.data(), &len, EVP_sha256(), nullptr) != 1 || len != 32)
        throw std::runtime_error("SHA-256 failed");
    std::ostringstream out;
    out << std::hex;
    for (unsigned int i = 0; i < len; ++i)
        out.width(2), out.fill('0'), out << static_cast<unsigned>(digest[i]);
    return out.str();
}
bool is_loopback(const std::string &host) {
    if (host == "localhost") return true;
    in_addr v4 {};
    if (inet_pton(AF_INET, host.c_str(), &v4) == 1) return (ntohl(v4.s_addr) >> 24U) == 127U;
    in6_addr v6 {};
    return inet_pton(AF_INET6, host.c_str(), &v6) == 1 && IN6_IS_ADDR_LOOPBACK(&v6);
}
bool path_is_within(const std::filesystem::path &candidate, const std::filesystem::path &root) {
    auto candidate_part = candidate.begin();
    for (auto root_part = root.begin(); root_part != root.end(); ++root_part, ++candidate_part) {
        if (candidate_part == candidate.end() || *candidate_part != *root_part) return false;
    }
    return true;
}
void sql_check(int rc, sqlite3 *db, const char *where) {
    if (rc != SQLITE_OK && rc != SQLITE_DONE && rc != SQLITE_ROW)
        throw std::runtime_error(std::string(where) + ": " + sqlite3_errmsg(db));
}
struct ScopedStatement {
    sqlite3_stmt *value = nullptr;
    ~ScopedStatement() { if (value) sqlite3_finalize(value); }
    ScopedStatement() = default;
    ScopedStatement(const ScopedStatement &) = delete;
    ScopedStatement &operator=(const ScopedStatement &) = delete;
};
sqlite3 *open_queue(const std::string &store) {
    if (store.empty()) throw std::runtime_error("missing --store");
    std::filesystem::create_directories(store);
    struct stat store_metadata {};
    if (lstat(store.c_str(), &store_metadata) != 0 || !S_ISDIR(store_metadata.st_mode) ||
        store_metadata.st_uid != geteuid() || chmod(store.c_str(), 0700) != 0)
        throw std::runtime_error("spool directory must be owned by the agent user");
    std::string dbpath = store + "/spool.sqlite";
    sqlite3 *db = nullptr;
    int rc = sqlite3_open_v2(dbpath.c_str(), &db,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
    if (rc != SQLITE_OK) {
        std::string message = db ? sqlite3_errmsg(db) : "open failed";
        if (db) sqlite3_close(db);
        throw std::runtime_error("spool database: " + message);
    }
    if (chmod(dbpath.c_str(), 0600) != 0) {
        sqlite3_close(db);
        throw std::runtime_error("spool database permissions could not be restricted");
    }
    sqlite3_busy_timeout(db, 5000);
    const char *schema =
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;"
        "CREATE TABLE IF NOT EXISTS queue(event_id TEXT PRIMARY KEY,sequence INTEGER NOT NULL,"
        " observed_at TEXT NOT NULL,payload TEXT NOT NULL,payload_hash TEXT NOT NULL);"
        "CREATE TABLE IF NOT EXISTS imported_events(event_id TEXT PRIMARY KEY,payload_hash TEXT NOT NULL);"
        "CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);"
        "CREATE TABLE IF NOT EXISTS policy_state(issuer TEXT PRIMARY KEY,revision INTEGER NOT NULL,document BLOB NOT NULL);"
        "CREATE TABLE IF NOT EXISTS policy_audit(issuer TEXT NOT NULL,revision INTEGER NOT NULL,"
        " action TEXT NOT NULL,committed_at INTEGER NOT NULL,PRIMARY KEY(issuer,revision));";
    char *error = nullptr;
    rc = sqlite3_exec(db, schema, nullptr, nullptr, &error);
    if (rc != SQLITE_OK) {
        std::string message = error ? error : sqlite3_errmsg(db);
        sqlite3_free(error); sqlite3_close(db);
        throw std::runtime_error("spool schema: " + message);
    }
    rc = sqlite3_exec(db, "INSERT OR IGNORE INTO meta(key,value) VALUES('next_sequence','0')", nullptr, nullptr, nullptr);
    if (rc != SQLITE_OK) { sqlite3_close(db); throw std::runtime_error("sequence metadata unavailable"); }
    return db;
}
std::uint64_t next_sequence_in_transaction(sqlite3 *db) {
    sqlite3_int64 next = 0;
    {
        ScopedStatement statement;
        sql_check(sqlite3_prepare_v2(db,
            "SELECT CAST(value AS INTEGER) FROM meta WHERE key='next_sequence'", -1,
            &statement.value, nullptr), db, "sequence query");
        if (sqlite3_step(statement.value) != SQLITE_ROW)
            throw std::runtime_error("sequence unavailable");
        const sqlite3_int64 previous = sqlite3_column_int64(statement.value, 0);
        if (previous < 0 || previous >= INT64_MAX) throw std::runtime_error("sequence exhausted");
        next = previous + 1;
    }
    if (next < 1) throw std::runtime_error("sequence unavailable");
    const auto sequence = static_cast<std::uint64_t>(next);
    const std::string value = std::to_string(sequence);
    ScopedStatement update;
    sql_check(sqlite3_prepare_v2(db, "UPDATE meta SET value=?1 WHERE key='next_sequence'", -1,
        &update.value, nullptr), db, "sequence update");
    sql_check(sqlite3_bind_text(update.value, 1, value.c_str(), -1, SQLITE_TRANSIENT), db, "sequence bind");
    sql_check(sqlite3_step(update.value), db, "sequence update");
    if (sqlite3_changes(db) != 1) throw std::runtime_error("sequence update failed");
    return sequence;
}
std::uint64_t next_sequence(sqlite3 *db) {
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr) != SQLITE_OK)
        throw std::runtime_error("sequence transaction unavailable");
    try {
        const auto sequence = next_sequence_in_transaction(db);
        if (sqlite3_exec(db, "COMMIT", nullptr, nullptr, nullptr) != SQLITE_OK)
            throw std::runtime_error("sequence commit failed");
        return sequence;
    } catch (...) {
        sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}
void enqueue(sqlite3 *db, const std::string &event_id, std::uint64_t sequence, const std::string &observed) {
    sqlite3_stmt *count = nullptr;
    sql_check(sqlite3_prepare_v2(db, "SELECT count(*),COALESCE(sum(length(payload)),0) FROM queue", -1, &count, nullptr), db, "queue size");
    sqlite3_step(count);
    int rows = sqlite3_column_int(count, 0);
    sqlite3_int64 bytes = sqlite3_column_int64(count, 1);
    sqlite3_finalize(count);
    if (rows >= 10000 || bytes >= 64LL * 1024LL * 1024LL)
        throw std::runtime_error("SEA_QUEUE_FULL: spool quota reached; event retained nowhere");
    const std::string payload_data = "{\"source\":\"synthetic\",\"worker_count\":1}";
    const std::string payload_hash = sha256(payload_data);
    std::string payload = "{\"event_id\":\"" + event_id + "\",\"sequence\":" +
        std::to_string(sequence) + ",\"observed_at\":\"" + observed +
        "\",\"kind\":\"health.heartbeat\",\"coverage\":\"healthy\",\"payload\":" +
        payload_data + ",\"payload_hash\":\"" + payload_hash + "\"}";
    sqlite3_stmt *s = nullptr;
    sql_check(sqlite3_prepare_v2(db, "INSERT INTO queue(event_id,sequence,observed_at,payload,payload_hash) VALUES(?1,?2,?3,?4,?5)",
                                 -1, &s, nullptr), db, "prepare enqueue");
    sqlite3_bind_text(s, 1, event_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 2, static_cast<sqlite3_int64>(sequence));
    sqlite3_bind_text(s, 3, observed.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 4, payload.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 5, payload_hash.c_str(), -1, SQLITE_TRANSIENT);
    sql_check(sqlite3_step(s), db, "enqueue event");
    sqlite3_finalize(s);
}
bool enqueue_synthetic_if_enabled(sqlite3 *db, const std::string &tenant) {
    const RuntimePolicy policy = active_policy(db, tenant, true);
    if (!policy.telemetry_enabled || policy.sample_rate <= 0.0) return false;
    if (policy.sample_rate < 1.0) {
        std::array<unsigned char, 8> random_bytes {};
        if (RAND_bytes(random_bytes.data(), static_cast<int>(random_bytes.size())) != 1)
            throw std::runtime_error("secure random sampling failed");
        std::uint64_t random_value = 0;
        for (unsigned char byte : random_bytes) random_value = (random_value << 8U) | byte;
        constexpr std::uint64_t kSampleRange = 1ULL << 53U;
        const std::uint64_t sample = random_value >> 11U;
        const auto threshold = static_cast<std::uint64_t>(
            std::floor(policy.sample_rate * static_cast<double>(kSampleRange)));
        if (sample >= threshold) return false;
    }
    const std::uint64_t sequence = next_sequence(db);
    enqueue(db, uuid(), sequence, now_iso());
    return true;
}
std::vector<Queued> pending(sqlite3 *db, std::size_t limit) {
    sqlite3_stmt *s = nullptr;
    sql_check(sqlite3_prepare_v2(db, "SELECT event_id,sequence,observed_at,payload,payload_hash FROM queue ORDER BY sequence LIMIT ?1",
                                 -1, &s, nullptr), db, "prepare queue read");
    sqlite3_bind_int64(s, 1, static_cast<sqlite3_int64>(limit));
    std::vector<Queued> result;
    while (sqlite3_step(s) == SQLITE_ROW) {
        Queued q;
        q.id = reinterpret_cast<const char *>(sqlite3_column_text(s, 0));
        q.sequence = static_cast<std::uint64_t>(sqlite3_column_int64(s, 1));
        q.observed = reinterpret_cast<const char *>(sqlite3_column_text(s, 2));
        q.payload = reinterpret_cast<const char *>(sqlite3_column_text(s, 3));
        q.hash = reinterpret_cast<const char *>(sqlite3_column_text(s, 4));
        result.push_back(std::move(q));
    }
    sqlite3_finalize(s);
    return result;
}
void delete_acked(sqlite3 *db, const std::vector<std::string> &ids) {
    sqlite3_exec(db, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr);
    sqlite3_stmt *s = nullptr;
    sql_check(sqlite3_prepare_v2(db, "DELETE FROM queue WHERE event_id=?1", -1, &s, nullptr), db, "prepare ack delete");
    for (const auto &id : ids) {
        sqlite3_bind_text(s, 1, id.c_str(), -1, SQLITE_TRANSIENT);
        sql_check(sqlite3_step(s), db, "ack delete");
        sqlite3_reset(s); sqlite3_clear_bindings(s);
    }
    sqlite3_finalize(s);
    if (sqlite3_exec(db, "COMMIT", nullptr, nullptr, nullptr) != SQLITE_OK) {
        sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
        throw std::runtime_error("ack transaction failed");
    }
}
std::string client_cn(SSL_CTX *ctx) {
    X509 *cert = SSL_CTX_get0_certificate(ctx);
    if (!cert) return {};
    char cn[256] = {};
    int n = X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, cn, sizeof(cn));
    return n > 0 ? std::string(cn, static_cast<std::size_t>(n)) : std::string{};
}
SSL_CTX *client_context(const Config &c) {
    if (!is_loopback(c.host)) throw std::runtime_error("SEA_SCOPE_INVALID: lab client only connects to loopback");
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) throw std::runtime_error("TLS context allocation failed");
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    if (SSL_CTX_load_verify_locations(ctx, c.ca.c_str(), nullptr) != 1 ||
        SSL_CTX_use_certificate_chain_file(ctx, c.cert.c_str()) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, c.key.c_str(), SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(ctx) != 1) {
        SSL_CTX_free(ctx); throw std::runtime_error("TLS trust/certificate/key setup failed");
    }
    struct stat st {};
    if (stat(c.key.c_str(), &st) != 0 || (st.st_mode & 0077) != 0) {
        SSL_CTX_free(ctx); throw std::runtime_error("private key must have mode 0600");
    }
    if (client_cn(ctx) != c.agent_id) {
        SSL_CTX_free(ctx); throw std::runtime_error("client certificate CN must equal --agent-id");
    }
    return ctx;
}
int connect_socket(const std::string &host, const std::string &port) {
    addrinfo hints {};
    hints.ai_socktype = SOCK_STREAM; hints.ai_family = AF_UNSPEC;
    addrinfo *list = nullptr;
    int rc = getaddrinfo(host.c_str(), port.c_str(), &hints, &list);
    if (rc != 0) throw std::runtime_error(std::string("getaddrinfo: ") + gai_strerror(rc));
    int connected = -1;
    for (addrinfo *it = list; it; it = it->ai_next) {
        bool local = false;
        if (it->ai_family == AF_INET)
            local = (ntohl(reinterpret_cast<sockaddr_in *>(it->ai_addr)->sin_addr.s_addr) >> 24U) == 127U;
        else if (it->ai_family == AF_INET6)
            local = IN6_IS_ADDR_LOOPBACK(&reinterpret_cast<sockaddr_in6 *>(it->ai_addr)->sin6_addr);
        if (!local) continue;
        int fd = socket(it->ai_family, it->ai_socktype | SOCK_CLOEXEC, it->ai_protocol);
        if (fd < 0) continue;
        timeval timeout{5, 0};
        (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        if (connect(fd, it->ai_addr, it->ai_addrlen) == 0) { connected = fd; break; }
        close(fd);
    }
    freeaddrinfo(list);
    if (connected < 0) throw std::runtime_error("SEA_SERVER_UNREACHABLE: loopback connect failed");
    return connected;
}
constexpr std::size_t kMaxHttpHeader = 16U * 1024U;
constexpr std::size_t kMaxHttpBody = 1024U * 1024U;
bool http_token_char(unsigned char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
        c == '!' || c == '#' || c == '$' || c == '%' || c == '&' || c == '\'' || c == '*' ||
        c == '+' || c == '-' || c == '.' || c == '^' || c == '_' || c == '`' || c == '|' || c == '~';
}
std::string lowercase_ascii(std::string value) {
    for (char &c : value) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return value;
}
std::string trim_http_value(std::string value) {
    std::size_t first = value.find_first_not_of(" \t");
    if (first == std::string::npos) return {};
    std::size_t last = value.find_last_not_of(" \t");
    return value.substr(first, last - first + 1U);
}
std::size_t parse_http_content_length(const std::string &value) {
    if (value.empty()) throw std::runtime_error("SEA_ACK_MALFORMED: empty Content-Length");
    std::size_t length = 0;
    for (unsigned char c : value) {
        if (c < '0' || c > '9') throw std::runtime_error("SEA_ACK_MALFORMED: invalid Content-Length");
        std::size_t digit = static_cast<std::size_t>(c - '0');
        if (length > (kMaxHttpBody - digit) / 10U)
            throw std::runtime_error("SEA_ACK_MALFORMED: response body too large");
        length = length * 10U + digit;
    }
    return length;
}
struct ScopedFd {
    int value = -1;
    explicit ScopedFd(int fd) : value(fd) {}
    ~ScopedFd() { if (value >= 0) close(value); }
    ScopedFd(const ScopedFd &) = delete;
    ScopedFd &operator=(const ScopedFd &) = delete;
    int get() const { return value; }
};
struct TlsClientConnection {
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context;
    ScopedFd socket_fd;
    std::unique_ptr<SSL, decltype(&SSL_free)> session;
    explicit TlsClientConnection(const Config &config)
        : context(client_context(config), SSL_CTX_free),
          socket_fd(connect_socket(config.host, config.port)),
          session(nullptr, SSL_free) {
        session.reset(SSL_new(context.get()));
        if (!session) throw std::runtime_error("TLS session allocation failed");
        if (SSL_set_fd(session.get(), socket_fd.get()) != 1)
            throw std::runtime_error("TLS socket setup failed");
        in_addr ip4 {};
        in6_addr ip6 {};
        const int verify_name = (inet_pton(AF_INET, config.host.c_str(), &ip4) == 1)
            ? X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(session.get()), config.host.c_str())
            : ((inet_pton(AF_INET6, config.host.c_str(), &ip6) == 1)
                ? X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(session.get()), config.host.c_str())
                : SSL_set1_host(session.get(), config.host.c_str()));
        if (verify_name != 1) throw std::runtime_error("TLS hostname verifier setup failed");
        if (SSL_connect(session.get()) != 1 || SSL_get_verify_result(session.get()) != X509_V_OK)
            throw std::runtime_error("SEA_TLS_UNTRUSTED_SERVER: TLS handshake/hostname verification failed");
    }
};
std::string http_exchange(SSL *ssl, const std::string &request,
                          const std::vector<std::string> &allowed_statuses = {"200"}) {
    std::size_t sent = 0;
    while (sent < request.size()) {
        int n = SSL_write(ssl, request.data() + sent, static_cast<int>(request.size() - sent));
        if (n <= 0) throw std::runtime_error("TLS write failed");
        sent += static_cast<std::size_t>(n);
    }
    std::string response;
    std::array<char, 8192> buf {};
    std::size_t expected = 0;
    bool have_length = false;
    std::size_t header_end = std::string::npos;
    for (;;) {
        if (response.size() > kMaxHttpHeader + 4U + kMaxHttpBody)
            throw std::runtime_error("SEA_ACK_MALFORMED: HTTP response exceeds size limit");
        if (!have_length) {
            header_end = response.find("\r\n\r\n");
            if (header_end != std::string::npos) {
                if (header_end + 4U > kMaxHttpHeader)
                    throw std::runtime_error("SEA_ACK_MALFORMED: HTTP response headers too large");
                std::string headers = response.substr(0, header_end);
                std::size_t first_end = headers.find("\r\n");
                if (first_end == std::string::npos || first_end > 4096U)
                    throw std::runtime_error("SEA_ACK_MALFORMED: invalid HTTP status line");
                std::string status_line = headers.substr(0, first_end);
                std::size_t first_space = status_line.find(' ');
                std::size_t second_space = first_space == std::string::npos ? std::string::npos : status_line.find(' ', first_space + 1U);
                if (first_space == std::string::npos || second_space == std::string::npos ||
                    status_line.substr(0, first_space) != "HTTP/1.1" || second_space != first_space + 4U ||
                    !std::all_of(status_line.begin() + static_cast<std::ptrdiff_t>(first_space + 1U),
                        status_line.begin() + static_cast<std::ptrdiff_t>(second_space),
                        [](unsigned char c) { return c >= '0' && c <= '9'; }))
                    throw std::runtime_error("SEA_ACK_MALFORMED: invalid HTTP status line");
                std::string status_code = status_line.substr(first_space + 1U, 3U);
                if (std::find(allowed_statuses.begin(), allowed_statuses.end(), status_code) == allowed_statuses.end()) {
                    if (allowed_statuses.size() == 1U)
                        throw std::runtime_error("SEA_HTTP_STATUS: expected " + allowed_statuses.front() +
                            ", received " + status_code);
                    throw std::runtime_error("SEA_HTTP_STATUS: unexpected " + status_code);
                }
                bool found_length = false;
                std::size_t pos = first_end + 2U;
                while (pos < headers.size()) {
                    std::size_t line_end = headers.find("\r\n", pos);
                    std::string field = headers.substr(pos, line_end == std::string::npos ? std::string::npos : line_end - pos);
                    if (field.empty() || field.front() == ' ' || field.front() == '\t')
                        throw std::runtime_error("SEA_ACK_MALFORMED: invalid or folded HTTP header");
                    std::size_t colon = field.find(':');
                    if (colon == std::string::npos || colon == 0U)
                        throw std::runtime_error("SEA_ACK_MALFORMED: malformed HTTP header");
                    std::string name = field.substr(0, colon);
                    if (!std::all_of(name.begin(), name.end(), [](unsigned char c) { return http_token_char(c); }))
                        throw std::runtime_error("SEA_ACK_MALFORMED: invalid HTTP header name");
                    std::string value = trim_http_value(field.substr(colon + 1U));
                    for (unsigned char c : value) if ((c < 0x20U && c != '\t') || c == 0x7fU)
                        throw std::runtime_error("SEA_ACK_MALFORMED: invalid HTTP header value");
                    std::string normalized = lowercase_ascii(name);
                    if (normalized == "content-length") {
                        if (found_length) throw std::runtime_error("SEA_ACK_MALFORMED: duplicate Content-Length");
                        expected = parse_http_content_length(value);
                        found_length = true;
                    } else if (normalized == "transfer-encoding") {
                        throw std::runtime_error("SEA_ACK_MALFORMED: Transfer-Encoding is unsupported");
                    }
                    if (line_end == std::string::npos) break;
                    pos = line_end + 2U;
                }
                if (!found_length) throw std::runtime_error("SEA_ACK_MALFORMED: missing Content-Length");
                have_length = true;
                std::size_t expected_size = header_end + 4U + expected;
                if (response.size() > expected_size)
                    throw std::runtime_error("SEA_ACK_MALFORMED: bytes follow framed HTTP response");
                if (response.size() == expected_size) return response;
            } else if (response.size() > kMaxHttpHeader) {
                throw std::runtime_error("SEA_ACK_MALFORMED: HTTP response headers too large");
            }
        } else {
            std::size_t expected_size = header_end + 4U + expected;
            if (response.size() > expected_size)
                throw std::runtime_error("SEA_ACK_MALFORMED: bytes follow framed HTTP response");
            if (response.size() == expected_size) return response;
        }
        int n = SSL_read(ssl, buf.data(), static_cast<int>(buf.size()));
        if (n <= 0) throw std::runtime_error("SEA_ACK_MALFORMED: truncated HTTP response");
        response.append(buf.data(), static_cast<std::size_t>(n));
    }
}
std::vector<std::string> ack_ids(const std::string &response, const std::string &key) {
    auto header_end = response.find("\r\n\r\n");
    if (header_end == std::string::npos) throw std::runtime_error("malformed HTTP response");
    std::string body = response.substr(header_end + 4U);
    Value v = agent::json::Parser(body).parse();
    const Value *ids_value = v.get(key);
    if (!ids_value) throw std::runtime_error("SEA_ACK_MALFORMED: missing " + key);
    const auto *arr = std::get_if<Array>(&ids_value->data);
    if (!arr) throw std::runtime_error("SEA_ACK_MALFORMED: ID list not array");
    std::vector<std::string> ids;
    for (const auto &item : *arr) {
        std::string id = item.string_or();
        if (id.empty()) throw std::runtime_error("SEA_ACK_MALFORMED: empty event ID");
        ids.push_back(std::move(id));
    }
    return ids;
}
std::vector<std::string> send_batch(const Config &c, const std::vector<Queued> &events) {
    if (events.empty()) return {};
    TlsClientConnection connection(c);
    std::string batch = "{\"schema_version\":\"agent_batch.v1\",\"batch_id\":\"" + uuid() +
        "\",\"agent_id\":\"" + escape(c.agent_id) + "\",\"events\":[";
    for (std::size_t i = 0; i < events.size(); ++i) {
        if (i) batch += ',';
        batch += events[i].payload;
    }
    batch += "]}";
    std::string req = "POST /v1/agents/self/events:batch HTTP/1.1\r\nHost: " + c.host +
        "\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: " +
        std::to_string(batch.size()) + "\r\n\r\n" + batch;
    std::string response = http_exchange(connection.session.get(), req);
    (void)SSL_shutdown(connection.session.get());
    auto accepted = ack_ids(response, "accepted_ids");
    auto duplicates = ack_ids(response, "duplicate_ids");
    accepted.insert(accepted.end(), duplicates.begin(), duplicates.end());
    return accepted;
}
int flush(sqlite3 *db, const Config &c) {
    std::vector<std::string> acked;
    unsigned attempt = 0;
    while (true) {
        const RuntimePolicy policy = active_policy(db, c.tenant, true);
        if (!policy.telemetry_enabled) {
            std::cout << "flush_paused=policy_inactive\n";
            return 0;
        }
        auto batch = pending(db, 100);
        if (batch.empty()) break;
        try {
            auto ids = send_batch(c, batch);
            std::vector<std::string> safe_ids;
            for (const auto &id : ids) {
                if (std::any_of(batch.begin(), batch.end(), [&](const Queued &q) { return q.id == id; }))
                    safe_ids.push_back(id);
            }
            if (safe_ids.empty()) throw std::runtime_error("server acknowledged no queued IDs");
            acked.insert(acked.end(), safe_ids.begin(), safe_ids.end());
            delete_acked(db, safe_ids);
            attempt = 0;
        } catch (const std::exception &e) {
            if (attempt >= 3) { std::cerr << "queue retained: " << e.what() << '\n'; return 1; }
            unsigned char jitter = 0;
            (void)RAND_bytes(&jitter, 1);
            std::this_thread::sleep_for(std::chrono::milliseconds(200U * (1U << attempt) +
                static_cast<unsigned>(jitter % 100U)));
            ++attempt;
        }
    }
    std::cout << "acknowledged=" << acked.size() << '\n';
    return 0;
}

std::string read_limited(const std::string &path, std::size_t cap) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open " + path);
    std::string data(cap + 1U, '\0');
    in.read(data.data(), static_cast<std::streamsize>(data.size()));
    const auto count = in.gcount();
    if (count < 0 || static_cast<std::size_t>(count) > cap)
        throw std::runtime_error("input size limit exceeded");
    if (in.bad()) throw std::runtime_error("input read failed");
    data.resize(static_cast<std::size_t>(count));
    return data;
}
std::time_t parse_policy_time(const std::string &value, const char *field) {
    std::tm parsed {};
    if (value.size() != 20U || value.back() != 'Z' ||
        strptime(value.c_str(), "%Y-%m-%dT%H:%M:%SZ", &parsed) != value.c_str() + value.size())
        throw std::runtime_error(std::string("policy ") + field + " invalid");
    const std::tm requested = parsed;
    const std::time_t epoch = timegm(&parsed);
    std::tm normalized {};
    if (epoch == static_cast<std::time_t>(-1) || gmtime_r(&epoch, &normalized) == nullptr ||
        normalized.tm_year != requested.tm_year || normalized.tm_mon != requested.tm_mon ||
        normalized.tm_mday != requested.tm_mday || normalized.tm_hour != requested.tm_hour ||
        normalized.tm_min != requested.tm_min || normalized.tm_sec != requested.tm_sec)
        throw std::runtime_error(std::string("policy ") + field + " invalid");
    return epoch;
}
RuntimePolicy active_policy(sqlite3 *db, const std::string &expected_tenant, bool require_scope) {
    sqlite3_stmt *statement = nullptr;
    sql_check(sqlite3_prepare_v2(db,
        "SELECT issuer,revision,document FROM policy_state ORDER BY rowid DESC LIMIT 1", -1, &statement, nullptr),
        db, "active policy read prepare");
    const int rc = sqlite3_step(statement);
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(statement);
        return {};
    }
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(statement);
        throw std::runtime_error("active policy read failed");
    }
    RuntimePolicy policy;
    policy.present = true;
    const auto *stored_issuer_bytes = reinterpret_cast<const char *>(sqlite3_column_text(statement, 0));
    const int stored_issuer_length = sqlite3_column_bytes(statement, 0);
    const sqlite3_int64 stored_revision = sqlite3_column_int64(statement, 1);
    const auto *document_bytes = static_cast<const char *>(sqlite3_column_blob(statement, 2));
    const int document_length = sqlite3_column_bytes(statement, 2);
    if (!stored_issuer_bytes || stored_issuer_length <= 0 || stored_issuer_length > 128 ||
        stored_revision < 1 || !document_bytes || document_length <= 0 || document_length > 65536) {
        sqlite3_finalize(statement);
        throw std::runtime_error("active policy state is corrupt");
    }
    policy.issuer.assign(stored_issuer_bytes, static_cast<std::size_t>(stored_issuer_length));
    policy.revision = static_cast<std::uint64_t>(stored_revision);
    const std::string document(document_bytes, static_cast<std::size_t>(document_length));
    sqlite3_finalize(statement);

    const Value root = agent::json::Parser(document).parse();
    const Value *schema_value = root.get("schema_version");
    if (!schema_value || schema_value->string_or() != "policy.v1")
        throw std::runtime_error("active policy schema is corrupt");
    const Value *issuer_value = root.get("issuer");
    const Value *tenant_value = root.get("tenant_scope");
    const Value *revision_value = root.get("revision");
    const double document_revision = revision_value ? revision_value->number_or(-1.0) : -1.0;
    constexpr double kMaxSafeStoredRevision = 9007199254740991.0;
    if (!issuer_value || !tenant_value || !revision_value || issuer_value->string_or() != policy.issuer ||
        tenant_value->string_or().empty() || document_revision < 1.0 ||
        document_revision > kMaxSafeStoredRevision || std::floor(document_revision) != document_revision ||
        document_revision != static_cast<double>(policy.revision))
        throw std::runtime_error("active policy scope is corrupt");
    policy.tenant = tenant_value->string_or();
    if (require_scope && expected_tenant.empty())
        throw std::runtime_error("SEA_SCOPE_INVALID: --tenant is required to apply policy");
    if (!expected_tenant.empty() && policy.tenant != expected_tenant)
        throw std::runtime_error("SEA_SCOPE_INVALID: stored policy tenant mismatch");

    const Value *expiry_value = root.get("expires_at");
    const std::time_t expiry = parse_policy_time(expiry_value ? expiry_value->string_or() : "", "expires_at");
    policy.expired = expiry <= std::time(nullptr);
    const Value *settings_value = root.get("settings");
    const auto *settings = settings_value ? std::get_if<agent::json::Object>(&settings_value->data) : nullptr;
    if (!settings) throw std::runtime_error("active policy settings are corrupt");
    const Value *actions_value = root.get("allowed_actions");
    const auto *actions = actions_value ? std::get_if<Array>(&actions_value->data) : nullptr;
    if (!actions) throw std::runtime_error("active policy actions are corrupt");
    const bool telemetry_action = std::any_of(actions->begin(), actions->end(), [](const Value &action) {
        return action.string_or() == "telemetry.configure";
    });
    const bool roots_action = std::any_of(actions->begin(), actions->end(), [](const Value &action) {
        return action.string_or() == "monitor.roots.configure";
    });
    const Value *telemetry_value = settings_value->get("telemetry_enabled");
    if (telemetry_value) {
        const auto *enabled = std::get_if<bool>(&telemetry_value->data);
        if (!enabled || !telemetry_action) throw std::runtime_error("active policy telemetry setting is corrupt");
        policy.telemetry_enabled = *enabled;
    }
    const Value *sample_value = settings_value->get("sample_rate");
    if (sample_value) {
        if (!telemetry_action) throw std::runtime_error("active policy sampling action is missing");
        policy.sample_rate = sample_value->number_or(-1.0);
        if (!std::isfinite(policy.sample_rate) || policy.sample_rate < 0.0 || policy.sample_rate > 1.0)
            throw std::runtime_error("active policy sample-rate setting is corrupt");
    }
    const Value *roots_value = settings_value->get("monitored_roots");
    if (roots_value) {
        if (!roots_action) throw std::runtime_error("active policy roots action is missing");
        const auto *roots = std::get_if<Array>(&roots_value->data);
        if (!roots || roots->size() > 32U)
            throw std::runtime_error("active policy monitored-roots setting is corrupt");
        for (const auto &path : *roots) {
            const std::string raw_root = path.string_or();
            const std::filesystem::path configured_root(raw_root);
            std::error_code path_error;
            const auto canonical_root = std::filesystem::canonical(configured_root, path_error);
            if (raw_root.empty() || !configured_root.is_absolute() || path_error ||
                !std::filesystem::is_directory(canonical_root, path_error) || path_error ||
                configured_root.lexically_normal() != canonical_root)
                throw std::runtime_error("active policy monitored root is corrupt");
            policy.monitored_roots.push_back(canonical_root);
        }
        policy.monitored_root_count = roots->size();
    }
    if (policy.expired) policy.telemetry_enabled = false;
    return policy;
}

std::string quote_json(const std::string &value) {
    std::string result = "\"";
    static constexpr char hex[] = "0123456789abcdef";
    for (unsigned char c : value) {
        if (c == '"' || c == '\\') {
            result.push_back('\\');
            result.push_back(static_cast<char>(c));
        } else if (c == '\b') result += "\\b";
        else if (c == '\f') result += "\\f";
        else if (c == '\n') result += "\\n";
        else if (c == '\r') result += "\\r";
        else if (c == '\t') result += "\\t";
        else if (c < 0x20U) {
            result += "\\u00";
            result.push_back(hex[c >> 4U]);
            result.push_back(hex[c & 0x0fU]);
        } else result.push_back(static_cast<char>(c));
    }
    result.push_back('"');
    return result;
}
std::string canonical_json(const Value &value) {
    if (std::holds_alternative<std::nullptr_t>(value.data)) return "null";
    if (const auto *boolean = std::get_if<bool>(&value.data)) return *boolean ? "true" : "false";
    if (const auto *number = std::get_if<double>(&value.data)) {
        if (!std::isfinite(*number)) throw std::runtime_error("non-finite JSON number");
        std::ostringstream output;
        output.imbue(std::locale::classic());
        output << std::setprecision(17) << *number;
        return output.str();
    }
    if (const auto *string = std::get_if<std::string>(&value.data)) return quote_json(*string);
    if (const auto *array = std::get_if<Array>(&value.data)) {
        std::string output = "[";
        for (std::size_t i = 0; i < array->size(); ++i) {
            if (i != 0U) output.push_back(',');
            output += canonical_json((*array)[i]);
        }
        output.push_back(']');
        return output;
    }
    const auto *object = std::get_if<agent::json::Object>(&value.data);
    if (!object) throw std::runtime_error("unsupported JSON value");
    std::string output = "{";
    bool comma = false;
    for (const auto &[key, item] : *object) {
        if (comma) output.push_back(',');
        comma = true;
        output += quote_json(key) + ':' + canonical_json(item);
    }
    output.push_back('}');
    return output;
}
bool safe_token(const std::string &value, std::size_t maximum) {
    return !value.empty() && value.size() <= maximum &&
        std::all_of(value.begin(), value.end(), [](unsigned char c) {
            return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        });
}
bool valid_uuid(const std::string &value) {
    if (value.size() != 36U) return false;
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (i == 8U || i == 13U || i == 18U || i == 23U) {
            if (value[i] != '-') return false;
        } else if (!std::isxdigit(static_cast<unsigned char>(value[i]))) return false;
    }
    return true;
}
void require_only_fields(const Value &value, std::initializer_list<const char *> allowed,
                         const char *where) {
    const auto *object = std::get_if<agent::json::Object>(&value.data);
    if (!object) throw std::runtime_error(std::string(where) + " must be an object");
    for (const auto &[key, child] : *object) {
        (void)child;
        const bool found = std::any_of(allowed.begin(), allowed.end(), [&key](const char *name) {
            return key == name;
        });
        if (!found) throw std::runtime_error(std::string(where) + " field rejected: " + key);
    }
}
const Value &required_field(const Value &value, const char *name) {
    const Value *field = value.get(name);
    if (!field) throw std::runtime_error(std::string("event field missing: ") + name);
    return *field;
}
double nonnegative_safe_integer(const Value *value, const char *name, bool nullable) {
    if (!value || std::holds_alternative<std::nullptr_t>(value->data)) {
        if (nullable) return -1.0;
        throw std::runtime_error(std::string("event field missing: ") + name);
    }
    const auto *number = std::get_if<double>(&value->data);
    constexpr double maximum = 9007199254740991.0;
    if (!number || !std::isfinite(*number) || *number < 0.0 || *number > maximum ||
        std::floor(*number) != *number)
        throw std::runtime_error(std::string("event field is not a safe non-negative integer: ") + name);
    return *number;
}
std::array<unsigned char, 32> load_or_create_path_key(const std::string &store) {
    const std::string key_path = store + "/path-pseudonym.key";
    std::array<unsigned char, 32> key {};
    int fd = open(key_path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd >= 0) {
        if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1) {
            close(fd);
            unlink(key_path.c_str());
            throw std::runtime_error("path pseudonym key generation failed");
        }
        std::size_t offset = 0;
        while (offset < key.size()) {
            const ssize_t written = write(fd, key.data() + offset, key.size() - offset);
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0) {
                close(fd);
                unlink(key_path.c_str());
                OPENSSL_cleanse(key.data(), key.size());
                throw std::runtime_error("path pseudonym key write failed");
            }
            offset += static_cast<std::size_t>(written);
        }
        if (fsync(fd) != 0) {
            close(fd);
            unlink(key_path.c_str());
            OPENSSL_cleanse(key.data(), key.size());
            throw std::runtime_error("path pseudonym key sync failed");
        }
        close(fd);
        const int directory_fd = open(store.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (directory_fd < 0 || fsync(directory_fd) != 0) {
            if (directory_fd >= 0) close(directory_fd);
            unlink(key_path.c_str());
            OPENSSL_cleanse(key.data(), key.size());
            throw std::runtime_error("path pseudonym directory sync failed");
        }
        close(directory_fd);
        return key;
    }
    if (errno != EEXIST) throw std::runtime_error("path pseudonym key create failed");

    fd = open(key_path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) throw std::runtime_error("path pseudonym key open failed");
    struct stat metadata {};
    if (fstat(fd, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
        metadata.st_uid != geteuid() || (metadata.st_mode & 0077) != 0 || metadata.st_size != 32) {
        close(fd);
        throw std::runtime_error("path pseudonym key permissions or size invalid");
    }
    std::size_t offset = 0;
    while (offset < key.size()) {
        const ssize_t count = read(fd, key.data() + offset, key.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            close(fd);
            OPENSSL_cleanse(key.data(), key.size());
            throw std::runtime_error("path pseudonym key read failed");
        }
        offset += static_cast<std::size_t>(count);
    }
    close(fd);
    return key;
}
std::string pseudonymize_path(const std::string &store, const std::string &raw_path,
                              const RuntimePolicy &policy) {
    if (raw_path.empty() || raw_path.size() > 4096U || raw_path.find('\0') != std::string::npos)
        throw std::runtime_error("event target path is invalid");
    const std::filesystem::path path(raw_path);
    if (!path.is_absolute()) throw std::runtime_error("event target path must be absolute");
    std::error_code error;
    const auto canonical_path = std::filesystem::weakly_canonical(path, error);
    if (error || std::none_of(policy.monitored_roots.begin(), policy.monitored_roots.end(),
            [&canonical_path](const auto &root) { return path_is_within(canonical_path, root); }))
        throw std::runtime_error("event target outside active monitored roots");
    const std::string normalized = canonical_path.generic_string();
    auto key = load_or_create_path_key(store);
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest {};
    unsigned int length = 0;
    const unsigned char *result = HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
        reinterpret_cast<const unsigned char *>(normalized.data()), normalized.size(), digest.data(), &length);
    OPENSSL_cleanse(key.data(), key.size());
    if (!result || length != 32U) throw std::runtime_error("path pseudonym HMAC failed");
    std::ostringstream output;
    output << "hmac-sha256:" << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < length; ++i) output << std::setw(2) << static_cast<unsigned>(digest[i]);
    OPENSSL_cleanse(digest.data(), digest.size());
    return output.str();
}
Value normalize_imported_event(const Value &event, const std::string &store,
                               const RuntimePolicy &policy, std::string &event_id,
                               std::string &observed, std::string &kind,
                               std::string &coverage) {
    require_only_fields(event, {"schema_version", "event_id", "source", "host_id", "observed_at",
        "kind", "severity", "target", "actor", "evidence", "coverage"}, "event");
    if (required_field(event, "schema_version").string_or() != "event.v1")
        throw std::runtime_error("event schema version unsupported");
    event_id = required_field(event, "event_id").string_or();
    if (!valid_uuid(event_id)) throw std::runtime_error("event ID must be a UUID");
    const std::string source = required_field(event, "source").string_or();
    if (!safe_token(source, 64U)) throw std::runtime_error("event source is invalid");
    if (const Value *host = event.get("host_id")) {
        if (!safe_token(host->string_or(), 128U)) throw std::runtime_error("event host_id is invalid");
    }
    observed = required_field(event, "observed_at").string_or();
    (void)parse_policy_time(observed, "observed_at");
    kind = required_field(event, "kind").string_or();
    if (!safe_token(kind, 128U)) throw std::runtime_error("event kind is invalid");

    const Value &target = required_field(event, "target");
    require_only_fields(target, {"path", "device", "inode"}, "event target");
    std::string path_id;
    if (const Value *path = target.get("path")) {
        const std::string raw_path = path->string_or();
        if (raw_path.empty()) throw std::runtime_error("event target path is invalid");
        path_id = pseudonymize_path(store, raw_path, policy);
    }

    const Value &actor = required_field(event, "actor");
    require_only_fields(actor, {"pid", "start_time_ticks", "attribution"}, "event actor");
    const std::string attribution = required_field(actor, "attribution").string_or();
    if (!safe_token(attribution, 64U)) throw std::runtime_error("event attribution is invalid");
    const double pid = nonnegative_safe_integer(actor.get("pid"), "actor.pid", true);
    const double start_ticks = nonnegative_safe_integer(actor.get("start_time_ticks"),
        "actor.start_time_ticks", true);

    const Value &coverage_value = required_field(event, "coverage");
    require_only_fields(coverage_value, {"state", "reason"}, "event coverage");
    coverage = required_field(coverage_value, "state").string_or();
    if (coverage != "healthy" && coverage != "degraded" && coverage != "unsupported" &&
        coverage != "recovering")
        throw std::runtime_error("event coverage state is invalid");
    Value coverage_reason {nullptr};
    if (const Value *reason = coverage_value.get("reason")) {
        if (!std::holds_alternative<std::nullptr_t>(reason->data)) {
            const std::string reason_text = reason->string_or();
            if (!safe_token(reason_text, 128U)) throw std::runtime_error("event coverage reason is invalid");
            coverage_reason = Value{reason_text};
        }
    }
    if (path_id.empty() && !(kind.rfind("coverage.", 0U) == 0U && coverage != "healthy"))
        throw std::runtime_error("event target path is required outside non-healthy coverage events");

    Value severity_value {std::string("info")};
    if (const Value *severity = event.get("severity")) {
        const std::string text = severity->string_or();
        if (!safe_token(text, 32U)) throw std::runtime_error("event severity is invalid");
        severity_value = Value{text};
    }
    Object target_data;
    target_data.emplace("path_id", path_id.empty() ? Value{nullptr} : Value{path_id});
    const double device = nonnegative_safe_integer(target.get("device"), "target.device", true);
    const double inode = nonnegative_safe_integer(target.get("inode"), "target.inode", true);
    target_data.emplace("device", device < 0.0 ? Value{nullptr} : Value{device});
    target_data.emplace("inode", inode < 0.0 ? Value{nullptr} : Value{inode});
    Object actor_data;
    actor_data.emplace("attribution", Value{attribution});
    actor_data.emplace("pid", pid < 0.0 ? Value{nullptr} : Value{pid});
    actor_data.emplace("start_time_ticks", start_ticks < 0.0 ? Value{nullptr} : Value{start_ticks});
    Object evidence_data;
    if (const Value *evidence = event.get("evidence")) {
        require_only_fields(*evidence, {"source_event", "hash_status"}, "event evidence");
        if (const Value *source_event = evidence->get("source_event")) {
            const std::string text = source_event->string_or();
            if (!safe_token(text, 64U)) throw std::runtime_error("event source_event is invalid");
            evidence_data.emplace("source_event", Value{text});
        }
        if (const Value *hash_status = evidence->get("hash_status")) {
            const std::string text = hash_status->string_or();
            if (!safe_token(text, 64U)) throw std::runtime_error("event hash_status is invalid");
            evidence_data.emplace("hash_status", Value{text});
        }
    }
    Object coverage_data;
    coverage_data.emplace("reason", std::move(coverage_reason));
    coverage_data.emplace("state", Value{coverage});
    Object normalized;
    normalized.emplace("actor", Value{std::move(actor_data)});
    normalized.emplace("coverage", Value{std::move(coverage_data)});
    normalized.emplace("evidence", Value{std::move(evidence_data)});
    normalized.emplace("severity", std::move(severity_value));
    normalized.emplace("source", Value{source});
    normalized.emplace("target", Value{std::move(target_data)});
    return Value{std::move(normalized)};
}
bool sample_rate_admits(const RuntimePolicy &policy) {
    if (policy.sample_rate <= 0.0) return false;
    if (policy.sample_rate >= 1.0) return true;
    std::array<unsigned char, 8> random_bytes {};
    if (RAND_bytes(random_bytes.data(), static_cast<int>(random_bytes.size())) != 1)
        throw std::runtime_error("secure random sampling failed");
    std::uint64_t random_value = 0;
    for (unsigned char byte : random_bytes) random_value = (random_value << 8U) | byte;
    constexpr std::uint64_t sample_range = 1ULL << 53U;
    const std::uint64_t sample = random_value >> 11U;
    const auto threshold = static_cast<std::uint64_t>(std::floor(policy.sample_rate * static_cast<double>(sample_range)));
    return sample < threshold;
}
std::optional<std::uint64_t> enqueue_imported_event(sqlite3 *db, const std::string &event_id,
        const std::string &observed, const std::string &kind, const std::string &coverage,
        const std::string &payload_data, bool remember_import = true) {
    const std::string payload_hash = sha256(payload_data);
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr) != SQLITE_OK)
        throw std::runtime_error("event import transaction unavailable");
    try {
        bool duplicate = false;
        if (remember_import) {
            ScopedStatement existing;
            sql_check(sqlite3_prepare_v2(db,
                "SELECT payload_hash FROM imported_events WHERE event_id=?1", -1,
                &existing.value, nullptr), db, "import dedup prepare");
            sql_check(sqlite3_bind_text(existing.value, 1, event_id.c_str(), -1, SQLITE_TRANSIENT),
                db, "import dedup bind");
            const int rc = sqlite3_step(existing.value);
            if (rc == SQLITE_ROW) {
                const auto *stored = reinterpret_cast<const char *>(sqlite3_column_text(existing.value, 0));
                if (!stored || payload_hash != stored)
                    throw std::runtime_error("event ID reused with different normalized content");
                duplicate = true;
            } else if (rc != SQLITE_DONE) throw std::runtime_error("event import dedup read failed");
        }
        if (duplicate) {
            if (sqlite3_exec(db, "COMMIT", nullptr, nullptr, nullptr) != SQLITE_OK)
                throw std::runtime_error("event import duplicate commit failed");
            return std::nullopt;
        }
        if (remember_import) {
            ScopedStatement count;
            sql_check(sqlite3_prepare_v2(db, "SELECT count(*) FROM imported_events", -1,
                &count.value, nullptr), db, "import history count prepare");
            if (sqlite3_step(count.value) != SQLITE_ROW || sqlite3_column_int64(count.value, 0) >= 100000)
                throw std::runtime_error("SEA_IMPORT_HISTORY_FULL: local dedup history limit reached");
        }
        {
            ScopedStatement count;
            sql_check(sqlite3_prepare_v2(db,
                "SELECT count(*) FROM queue", -1,
                &count.value, nullptr), db, "queue quota prepare");
            if (sqlite3_step(count.value) != SQLITE_ROW) throw std::runtime_error("queue size unavailable");
            const sqlite3_int64 rows = sqlite3_column_int64(count.value, 0);
            if (rows >= 10000)
                throw std::runtime_error("SEA_QUEUE_FULL: spool quota reached; event retained nowhere");
        }
        const std::uint64_t sequence = next_sequence_in_transaction(db);
        const std::string envelope = "{\"event_id\":" + quote_json(event_id) +
            ",\"sequence\":" + std::to_string(sequence) + ",\"observed_at\":" + quote_json(observed) +
            ",\"kind\":" + quote_json(kind) + ",\"coverage\":" + quote_json(coverage) +
            ",\"payload\":" + payload_data + ",\"payload_hash\":" + quote_json(payload_hash) + "}";
        {
            ScopedStatement count;
            sql_check(sqlite3_prepare_v2(db,
                "SELECT COALESCE(sum(length(payload)),0) FROM queue", -1,
                &count.value, nullptr), db, "queue byte quota prepare");
            if (sqlite3_step(count.value) != SQLITE_ROW) throw std::runtime_error("queue size unavailable");
            const sqlite3_int64 bytes = sqlite3_column_int64(count.value, 0);
            if (bytes + static_cast<sqlite3_int64>(envelope.size()) > 64LL * 1024LL * 1024LL)
                throw std::runtime_error("SEA_QUEUE_FULL: spool quota reached; event retained nowhere");
        }
        {
            ScopedStatement insert;
            sql_check(sqlite3_prepare_v2(db,
                "INSERT INTO queue(event_id,sequence,observed_at,payload,payload_hash) VALUES(?1,?2,?3,?4,?5)",
                -1, &insert.value, nullptr), db, "event import queue prepare");
            sql_check(sqlite3_bind_text(insert.value, 1, event_id.c_str(), -1, SQLITE_TRANSIENT), db, "event import id bind");
            sql_check(sqlite3_bind_int64(insert.value, 2, static_cast<sqlite3_int64>(sequence)), db, "event import sequence bind");
            sql_check(sqlite3_bind_text(insert.value, 3, observed.c_str(), -1, SQLITE_TRANSIENT), db, "event import time bind");
            sql_check(sqlite3_bind_text(insert.value, 4, envelope.c_str(), -1, SQLITE_TRANSIENT), db, "event import payload bind");
            sql_check(sqlite3_bind_text(insert.value, 5, payload_hash.c_str(), -1, SQLITE_TRANSIENT), db, "event import hash bind");
            sql_check(sqlite3_step(insert.value), db, "event import queue insert");
        }
        if (remember_import) {
            ScopedStatement insert;
            sql_check(sqlite3_prepare_v2(db,
                "INSERT INTO imported_events(event_id,payload_hash) VALUES(?1,?2)", -1,
                &insert.value, nullptr), db, "import history prepare");
            sql_check(sqlite3_bind_text(insert.value, 1, event_id.c_str(), -1, SQLITE_TRANSIENT), db, "import history id bind");
            sql_check(sqlite3_bind_text(insert.value, 2, payload_hash.c_str(), -1, SQLITE_TRANSIENT), db, "import history hash bind");
            sql_check(sqlite3_step(insert.value), db, "import history insert");
        }
        if (sqlite3_exec(db, "COMMIT", nullptr, nullptr, nullptr) != SQLITE_OK)
            throw std::runtime_error("event import commit failed");
        return sequence;
    } catch (...) {
        sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

Value safe_metadata_number(std::uint64_t value) {
    constexpr std::uint64_t kMaxJsonSafeInteger = 9007199254740991ULL;
    if (value > kMaxJsonSafeInteger) return Value{nullptr};
    return Value{static_cast<double>(value)};
}

bool enqueue_agent_event(sqlite3 *db, const std::string &store, const RuntimePolicy &policy,
        const std::string &kind, const std::string &coverage_state,
        const std::string &coverage_reason, const std::string &path,
        const std::string &source_event) {
    if (!policy.present || policy.expired || !policy.telemetry_enabled || !sample_rate_admits(policy))
        return false;

    Object target;
    target.emplace("device", Value{nullptr});
    target.emplace("inode", Value{nullptr});
    if (!path.empty()) {
        target.emplace("path", Value{path});
        struct stat metadata {};
        if (lstat(path.c_str(), &metadata) == 0) {
            target["device"] = safe_metadata_number(static_cast<std::uint64_t>(metadata.st_dev));
            target["inode"] = safe_metadata_number(static_cast<std::uint64_t>(metadata.st_ino));
        }
    }

    Object actor;
    actor.emplace("attribution", Value{std::string("unknown")});
    actor.emplace("pid", Value{nullptr});
    actor.emplace("start_time_ticks", Value{nullptr});
    Object evidence;
    evidence.emplace("source_event", Value{source_event});
    Object coverage;
    coverage.emplace("reason", coverage_reason.empty() ? Value{nullptr} : Value{coverage_reason});
    coverage.emplace("state", Value{coverage_state});
    Object event;
    event.emplace("actor", Value{std::move(actor)});
    event.emplace("coverage", Value{std::move(coverage)});
    event.emplace("evidence", Value{std::move(evidence)});
    event.emplace("event_id", Value{uuid()});
    event.emplace("kind", Value{kind});
    event.emplace("observed_at", Value{now_iso()});
    event.emplace("schema_version", Value{std::string("event.v1")});
    event.emplace("severity", Value{coverage_state == "healthy" ? std::string("info") : std::string("warning")});
    event.emplace("source", Value{std::string("sea")});
    event.emplace("target", Value{std::move(target)});

    std::string event_id, observed, normalized_kind, normalized_coverage;
    const Value normalized = normalize_imported_event(Value{std::move(event)}, store, policy,
        event_id, observed, normalized_kind, normalized_coverage);
    const auto sequence = enqueue_imported_event(db, event_id, observed, normalized_kind,
        normalized_coverage, canonical_json(normalized), false);
    return sequence.has_value();
}

class InotifyCollector {
    struct Root {
        std::filesystem::path path;
        dev_t device = 0;
    };
    struct PendingMove {
        std::filesystem::path path;
        std::chrono::steady_clock::time_point observed_at;
    };
    int fd_ = -1;
    std::string store_;
    std::vector<Root> roots_;
    std::map<int, std::filesystem::path> watches_;
    std::map<std::uint32_t, PendingMove> pending_moves_;
    bool degraded_ = false;
    bool coverage_reported_ = false;
    std::chrono::steady_clock::time_point coverage_retry_after_{};
    std::string degraded_reason_ = "watch_unavailable";
    static constexpr std::size_t kMaxWatchedDirectories = 4096U;
    static constexpr std::size_t kMaxPendingMoves = 4096U;
    static constexpr auto kMovePairTimeout = std::chrono::seconds(1);

    int open_directory_without_symlinks(const std::filesystem::path &path) const {
        if (!path.is_absolute()) throw std::runtime_error("collector path must be absolute");
        int directory = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (directory < 0) throw std::runtime_error("collector root cannot be opened");
        for (const auto &component : path.relative_path()) {
            const std::string name = component.string();
            if (name.empty() || name == ".") continue;
            if (name == "..") {
                close(directory);
                throw std::runtime_error("collector path traversal rejected");
            }
            const int next = openat(directory, name.c_str(),
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            const int saved_errno = errno;
            close(directory);
            if (next < 0) {
                errno = saved_errno;
                throw std::runtime_error("collector directory is unavailable or changed");
            }
            directory = next;
        }
        return directory;
    }

    const Root *root_for(const std::filesystem::path &path) const {
        const Root *best = nullptr;
        for (const auto &root : roots_) {
            if (path_is_within(path, root.path) &&
                (!best || root.path.native().size() > best->path.native().size())) best = &root;
        }
        return best;
    }

    void add_directory_tree(int directory, const std::filesystem::path &display_path,
                            dev_t root_device) {
        if (watches_.size() >= kMaxWatchedDirectories)
            throw std::runtime_error("collector directory watch limit reached");
        const std::string proc_path = "/proc/self/fd/" + std::to_string(directory);
        std::error_code path_error;
        const auto actual_path = std::filesystem::canonical(proc_path, path_error);
        const Root *root = path_error ? nullptr : root_for(actual_path);
        struct stat metadata {};
        if (path_error || !root || root->device != root_device ||
            fstat(directory, &metadata) != 0 || !S_ISDIR(metadata.st_mode) ||
            metadata.st_dev != root_device)
            throw std::runtime_error("collector directory escaped its policy root");

        const int watch = inotify_add_watch(fd_, proc_path.c_str(),
            IN_CREATE | IN_CLOSE_WRITE | IN_ATTRIB | IN_DELETE | IN_MOVED_FROM |
            IN_MOVED_TO | IN_DELETE_SELF | IN_MOVE_SELF | IN_UNMOUNT | IN_ONLYDIR);
        if (watch < 0) throw std::runtime_error("collector watch cannot be installed");
        watches_[watch] = actual_path;

        const int scan_fd = dup(directory);
        if (scan_fd < 0) throw std::runtime_error("collector directory scan cannot start");
        DIR *stream = fdopendir(scan_fd);
        if (!stream) {
            close(scan_fd);
            throw std::runtime_error("collector directory scan cannot start");
        }
        errno = 0;
        while (dirent *entry = readdir(stream)) {
            const std::string name(entry->d_name);
            if (name == "." || name == "..") continue;
            struct stat child_metadata {};
            if (fstatat(directory, name.c_str(), &child_metadata, AT_SYMLINK_NOFOLLOW) != 0) {
                degraded_ = true;
                degraded_reason_ = "directory_entry_unavailable";
                errno = 0;
                continue;
            }
            if (!S_ISDIR(child_metadata.st_mode) || child_metadata.st_dev != root_device) continue;
            const int child = openat(directory, name.c_str(),
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (child < 0) {
                degraded_ = true;
                degraded_reason_ = "directory_changed_during_scan";
                errno = 0;
                continue;
            }
            try {
                add_directory_tree(child, actual_path / name, root_device);
            } catch (...) {
                close(child);
                closedir(stream);
                throw;
            }
            close(child);
            errno = 0;
        }
        const int scan_error = errno;
        closedir(stream);
        if (scan_error != 0) throw std::runtime_error("collector directory enumeration failed");
        (void)display_path;
    }

    bool rebuild() {
        for (const auto &[watch, path] : watches_) {
            (void)path;
            (void)inotify_rm_watch(fd_, watch);
        }
        watches_.clear();
        bool complete = true;
        for (const auto &root : roots_) {
            int directory = -1;
            try {
                directory = open_directory_without_symlinks(root.path);
                add_directory_tree(directory, root.path, root.device);
                close(directory);
            } catch (...) {
                if (directory >= 0) close(directory);
                complete = false;
                degraded_ = true;
                degraded_reason_ = "root_or_subdirectory_unavailable";
            }
        }
        if (watches_.empty()) {
            complete = false;
            degraded_ = true;
            degraded_reason_ = roots_.empty() ? "no_monitored_roots" : "no_active_watches";
        }
        return complete;
    }

    void report_degraded(sqlite3 *db, const RuntimePolicy &policy) {
        if (!degraded_ || coverage_reported_) return;
        if (std::chrono::steady_clock::now() < coverage_retry_after_) return;
        try {
            (void)enqueue_agent_event(db, store_, policy, "coverage.watch_degraded", "degraded",
                degraded_reason_, {}, "INOTIFY_COVERAGE_GAP");
            coverage_reported_ = true;
        } catch (const std::exception &error) {
            coverage_retry_after_ = std::chrono::steady_clock::now() + std::chrono::seconds(60);
            std::cerr << "collector coverage report deferred: " << error.what() << '\n';
        }
    }

    void process_file_event(sqlite3 *db, const RuntimePolicy &policy,
                            const std::filesystem::path &path, const char *kind,
                            const char *source_event) {
        try {
            (void)enqueue_agent_event(db, store_, policy, kind, "healthy", {}, path.string(), source_event);
        } catch (const std::exception &error) {
            if (std::string(error.what()).find("SEA_QUEUE_FULL") != std::string::npos) {
                degraded_ = true;
                degraded_reason_ = "queue_backpressure";
            } else {
                std::cerr << "collector event deferred: " << error.what() << '\n';
            }
        }
    }

    void flush_pending_moves(sqlite3 *db, const RuntimePolicy &policy, bool force) {
        const auto now = std::chrono::steady_clock::now();
        for (auto it = pending_moves_.begin(); it != pending_moves_.end();) {
            if (!force && now - it->second.observed_at < kMovePairTimeout) {
                ++it;
                continue;
            }
            process_file_event(db, policy, it->second.path, "file.moved_from", "IN_MOVED_FROM");
            it = pending_moves_.erase(it);
        }
    }

public:
    InotifyCollector(const std::string &store, const RuntimePolicy &policy) : store_(store) {
        fd_ = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        if (fd_ < 0) throw std::runtime_error("inotify initialization failed");
        for (const auto &root_path : policy.monitored_roots) {
            try {
                const int directory = open_directory_without_symlinks(root_path);
                struct stat metadata {};
                if (fstat(directory, &metadata) != 0 || !S_ISDIR(metadata.st_mode)) {
                    close(directory);
                    throw std::runtime_error("collector root is unavailable");
                }
                roots_.push_back(Root{root_path, metadata.st_dev});
                close(directory);
            } catch (...) {
                degraded_ = true;
                degraded_reason_ = "root_unavailable";
            }
        }
        if (roots_.size() != policy.monitored_roots.size()) degraded_ = true;
        if (!rebuild() && degraded_reason_ == "watch_unavailable")
            degraded_reason_ = "root_or_subdirectory_unavailable";
    }
    ~InotifyCollector() {
        if (fd_ >= 0) close(fd_);
    }
    InotifyCollector(const InotifyCollector &) = delete;
    InotifyCollector &operator=(const InotifyCollector &) = delete;

    bool ready_for_policy() const {
        return !degraded_ && !roots_.empty() && !watches_.empty();
    }

    void poll_once(sqlite3 *db, const RuntimePolicy &policy, int timeout_ms) {
        flush_pending_moves(db, policy, false);
        report_degraded(db, policy);
        pollfd descriptor{fd_, POLLIN, 0};
        const int ready = poll(&descriptor, 1, timeout_ms);
        if (ready < 0) {
            if (errno == EINTR) return;
            degraded_ = true;
            degraded_reason_ = "inotify_poll_failed";
            report_degraded(db, policy);
            return;
        }
        if (ready == 0) return;
        if ((descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            degraded_ = true;
            degraded_reason_ = "inotify_descriptor_failed";
            report_degraded(db, policy);
            return;
        }
        alignas(inotify_event) std::array<char, 64U * 1024U> buffer{};
        bool must_rebuild = false;
        for (;;) {
            const ssize_t length = read(fd_, buffer.data(), buffer.size());
            if (length < 0 && errno == EINTR) continue;
            if (length < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
            if (length <= 0) {
                degraded_ = true;
                degraded_reason_ = "inotify_read_failed";
                break;
            }
            std::size_t offset = 0;
            while (offset + sizeof(inotify_event) <= static_cast<std::size_t>(length)) {
                const auto *event = reinterpret_cast<const inotify_event *>(buffer.data() + offset);
                const std::size_t event_size = sizeof(inotify_event) + event->len;
                if (event_size > static_cast<std::size_t>(length) - offset) {
                    degraded_ = true;
                    degraded_reason_ = "inotify_record_malformed";
                    break;
                }
                offset += event_size;
                if ((event->mask & IN_Q_OVERFLOW) != 0) {
                    degraded_ = true;
                    degraded_reason_ = "inotify_queue_overflow";
                    must_rebuild = true;
                    flush_pending_moves(db, policy, true);
                    continue;
                }
                const auto watch_it = watches_.find(event->wd);
                if (watch_it == watches_.end()) continue;
                const std::filesystem::path parent = watch_it->second;
                if ((event->mask & IN_IGNORED) != 0) {
                    watches_.erase(watch_it);
                    continue;
                }
                if ((event->mask & (IN_DELETE_SELF | IN_MOVE_SELF | IN_UNMOUNT)) != 0) {
                    degraded_ = true;
                    degraded_reason_ = "watched_directory_moved_or_removed";
                    must_rebuild = true;
                    continue;
                }
                if (event->len == 0U || event->name[0] == '\0') continue;
                const std::filesystem::path changed = parent / event->name;
                const bool is_directory = (event->mask & IN_ISDIR) != 0;
                if (!is_directory && (event->mask & IN_MOVED_FROM) != 0) {
                    if (event->cookie != 0U) {
                        const auto existing = pending_moves_.find(event->cookie);
                        if (existing != pending_moves_.end()) {
                            process_file_event(db, policy, existing->second.path,
                                "file.moved_from", "IN_MOVED_FROM");
                            pending_moves_.erase(existing);
                        }
                        if (pending_moves_.size() < kMaxPendingMoves) {
                            pending_moves_.emplace(event->cookie,
                                PendingMove{changed, std::chrono::steady_clock::now()});
                        } else {
                            process_file_event(db, policy, changed, "file.moved_from", "IN_MOVED_FROM");
                        }
                    } else {
                        process_file_event(db, policy, changed, "file.moved_from", "IN_MOVED_FROM");
                    }
                    continue;
                }
                if (!is_directory && (event->mask & IN_MOVED_TO) != 0 && event->cookie != 0U) {
                    const auto from = pending_moves_.find(event->cookie);
                    if (from != pending_moves_.end()) {
                        process_file_event(db, policy, changed, "file.renamed", "IN_MOVED_PAIR");
                        pending_moves_.erase(from);
                        continue;
                    }
                }
                if ((event->mask & (IN_CREATE | IN_MOVED_TO)) != 0 &&
                    is_directory) {
                    try {
                        const Root *root = root_for(parent);
                        if (!root) throw std::runtime_error("collector directory outside policy roots");
                        int directory = open_directory_without_symlinks(changed);
                        try {
                            add_directory_tree(directory, changed, root->device);
                            close(directory);
                        } catch (...) {
                            close(directory);
                            throw;
                        }
                    } catch (...) {
                        degraded_ = true;
                        degraded_reason_ = "new_directory_watch_failed";
                    }
                    continue;
                }
                const struct {
                    std::uint32_t mask;
                    const char *kind;
                    const char *source;
                } mappings[] = {
                    {IN_CREATE, "file.created", "IN_CREATE"},
                    {IN_CLOSE_WRITE, "file.modified", "IN_CLOSE_WRITE"},
                    {IN_ATTRIB, "file.metadata_changed", "IN_ATTRIB"},
                    {IN_DELETE, "file.deleted", "IN_DELETE"},
                    {IN_MOVED_FROM, "file.moved_from", "IN_MOVED_FROM"},
                    {IN_MOVED_TO, "file.moved_to", "IN_MOVED_TO"}
                };
                for (const auto &mapping : mappings) {
                    if ((event->mask & mapping.mask) != 0) {
                        process_file_event(db, policy, changed, mapping.kind, mapping.source);
                        break;
                    }
                }
            }
        }
        if (must_rebuild) (void)rebuild();
        flush_pending_moves(db, policy, false);
        report_degraded(db, policy);
    }
};

int import_event(const Config &config, const std::string &file) {
    if (file.empty()) throw std::runtime_error("import-event requires --file");
    std::unique_ptr<sqlite3, decltype(&sqlite3_close)> database(open_queue(config.store), sqlite3_close);
    sqlite3 *db = database.get();
    const RuntimePolicy policy = active_policy(db, config.tenant, true);
    if (!policy.telemetry_enabled) throw std::runtime_error("SEA_POLICY_INACTIVE: event import is disabled");
    Value event = agent::json::Parser(read_limited(file, 1024U * 1024U)).parse();
    std::string event_id, observed, kind, coverage;
    const Value normalized = normalize_imported_event(event, config.store, policy,
        event_id, observed, kind, coverage);
    if (!sample_rate_admits(policy)) {
        std::cout << "{\"status\":\"sampled_out\",\"event_id\":" << quote_json(event_id) << "}\n";
        return 0;
    }
    const std::string payload_data = canonical_json(normalized);
    const auto sequence = enqueue_imported_event(db, event_id, observed, kind, coverage, payload_data);
    if (!sequence) {
        std::cout << "{\"status\":\"already_seen\",\"event_id\":" << quote_json(event_id) << "}\n";
        return 0;
    }
    std::cout << "{\"status\":\"queued\",\"event_id\":" << quote_json(event_id)
              << ",\"sequence\":" << *sequence << "}\n";
    return 0;
}
bool validate_policy_document(const Config &c, const std::string &document, const std::string &signature,
                              const std::string &pubfile, const std::string &tenant,
                              const std::string &allowed_root, bool allow_unchanged) {
    if (document.empty() || document.size() > 65536U)
        throw std::runtime_error("policy document size is invalid");
    if (signature.size() != 64) throw std::runtime_error("policy signature must be raw 64-byte Ed25519");
    FILE *keyf = fopen(pubfile.c_str(), "r");
    if (!keyf) throw std::runtime_error("cannot open policy public key");
    EVP_PKEY *key = PEM_read_PUBKEY(keyf, nullptr, nullptr, nullptr);
    fclose(keyf);
    if (!key || EVP_PKEY_id(key) != EVP_PKEY_ED25519) {
        if (key) EVP_PKEY_free(key);
        throw std::runtime_error("policy key must be Ed25519 PEM");
    }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int valid = ctx && EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, key) == 1 &&
        EVP_DigestVerify(ctx, reinterpret_cast<const unsigned char *>(signature.data()), signature.size(),
                         reinterpret_cast<const unsigned char *>(document.data()), document.size()) == 1;
    if (ctx) EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    if (!valid) throw std::runtime_error("SEA_POLICY_BAD_SIGNATURE");
    Value root = agent::json::Parser(document).parse();
    if (root.get("schema_version") == nullptr || root.get("schema_version")->string_or() != "policy.v1")
        throw std::runtime_error("SEA_PROTOCOL_UNSUPPORTED");
    const std::vector<std::string> top_allowed = {"schema_version","policy_id","revision","issuer","issued_at","expires_at",
        "tenant_scope","allowed_actions","settings"};
    const auto *obj = std::get_if<agent::json::Object>(&root.data);
    if (!obj) throw std::runtime_error("policy must be an object");
    for (const auto &[name, value] : *obj) {
        (void)value;
        if (std::find(top_allowed.begin(), top_allowed.end(), name) == top_allowed.end())
            throw std::runtime_error("policy field rejected: " + name);
    }
    std::string policy_id = root.get("policy_id") ? root.get("policy_id")->string_or() : "";
    std::string issuer = root.get("issuer") ? root.get("issuer")->string_or() : "";
    std::string policy_tenant = root.get("tenant_scope") ? root.get("tenant_scope")->string_or() : "";
    const Value *revision_value = root.get("revision");
    const double parsed_revision = revision_value ? revision_value->number_or(-1.0) : -1.0;
    constexpr double kMaxSafeJsonInteger = 9007199254740991.0;
    if (parsed_revision < 1.0 || parsed_revision > kMaxSafeJsonInteger ||
        std::floor(parsed_revision) != parsed_revision)
        throw std::runtime_error("SEA_POLICY_REVISION_INVALID");
    const auto revision = static_cast<std::uint64_t>(parsed_revision);
    RuntimePolicy staged_policy;
    staged_policy.present = true;
    staged_policy.revision = revision;
    staged_policy.issuer = issuer;
    staged_policy.tenant = policy_tenant;
    if (policy_id.empty() || policy_id.size() > 128U || issuer.empty() || issuer.size() > 128U ||
        policy_tenant.empty() || policy_tenant != tenant)
        throw std::runtime_error("SEA_SCOPE_INVALID: issuer or tenant scope invalid");
    const std::time_t issued_epoch = parse_policy_time(
        root.get("issued_at") ? root.get("issued_at")->string_or() : "", "issued_at");
    const std::time_t expiry_epoch = parse_policy_time(
        root.get("expires_at") ? root.get("expires_at")->string_or() : "", "expires_at");
    if (issued_epoch > std::time(nullptr) + 300) throw std::runtime_error("policy issued_at is in the future");
    if (expiry_epoch <= std::time(nullptr) || expiry_epoch <= issued_epoch)
        throw std::runtime_error("SEA_POLICY_EXPIRED");
    const Value *actions_v = root.get("allowed_actions");
    const auto *actions = actions_v ? std::get_if<Array>(&actions_v->data) : nullptr;
    if (!actions || actions->empty() || actions->size() > 8U)
        throw std::runtime_error("allowed_actions must be a bounded non-empty array");
    bool telemetry_action = false;
    bool roots_action = false;
    std::vector<std::string> seen_actions;
    for (const auto &action : *actions) {
        std::string name = action.string_or();
        if (name != "telemetry.configure" && name != "monitor.roots.configure")
            throw std::runtime_error("policy action rejected: " + name);
        if (std::find(seen_actions.begin(), seen_actions.end(), name) != seen_actions.end())
            throw std::runtime_error("duplicate policy action rejected");
        seen_actions.push_back(name);
        telemetry_action = telemetry_action || name == "telemetry.configure";
        roots_action = roots_action || name == "monitor.roots.configure";
    }
    const Value *settings = root.get("settings");
    const auto *setting_obj = settings ? std::get_if<agent::json::Object>(&settings->data) : nullptr;
    if (!setting_obj) throw std::runtime_error("settings must be an object");
    const std::filesystem::path configured_root(allowed_root);
    std::error_code path_error;
    if (!configured_root.is_absolute())
        throw std::runtime_error("policy root outside configured allowlist");
    const auto canonical_root = std::filesystem::canonical(configured_root, path_error);
    if (path_error || !std::filesystem::is_directory(canonical_root, path_error) || path_error)
        throw std::runtime_error("configured policy root must be an existing directory");
    for (const auto &[name, value] : *setting_obj) {
        if (name == "telemetry_enabled") {
            if (!telemetry_action) throw std::runtime_error("telemetry setting requires telemetry.configure");
            const auto *enabled = std::get_if<bool>(&value.data);
            if (!enabled) throw std::runtime_error("telemetry_enabled must be boolean");
            staged_policy.telemetry_enabled = *enabled;
        } else if (name == "sample_rate") {
            if (!telemetry_action) throw std::runtime_error("sample_rate requires telemetry.configure");
            double rate = value.number_or(-1);
            if (rate < 0 || rate > 1) throw std::runtime_error("sample_rate out of range");
            staged_policy.sample_rate = rate;
        } else if (name == "monitored_roots") {
            if (!roots_action) throw std::runtime_error("monitored_roots requires monitor.roots.configure");
            const auto *roots = std::get_if<Array>(&value.data);
            if (!roots || roots->size() > 32U) throw std::runtime_error("monitored_roots must be a bounded array");
            for (const auto &r : *roots) {
                const std::filesystem::path path(r.string_or());
                if (!path.is_absolute())
                    throw std::runtime_error("policy root outside configured allowlist");
                path_error.clear();
                const auto canonical_path = std::filesystem::canonical(path, path_error);
                if (path_error || !std::filesystem::is_directory(canonical_path, path_error) || path_error ||
                    !path_is_within(canonical_path, canonical_root))
                    throw std::runtime_error("policy root outside configured allowlist");
                staged_policy.monitored_roots.push_back(canonical_path);
            }
            staged_policy.monitored_root_count = roots->size();
        } else throw std::runtime_error("policy setting rejected: " + name);
    }
    if (staged_policy.telemetry_enabled && staged_policy.sample_rate > 0.0 &&
        !staged_policy.monitored_roots.empty()) {
        InotifyCollector staged_collector(c.store, staged_policy);
        if (!staged_collector.ready_for_policy())
            throw std::runtime_error("SEA_POLICY_WATCH_PREPARE_FAILED: monitored roots are not fully watchable");
    }
    std::unique_ptr<sqlite3, decltype(&sqlite3_close)> database(open_queue(c.store), sqlite3_close);
    sqlite3 *db = database.get();
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr) != SQLITE_OK)
        throw std::runtime_error("policy transaction unavailable");
    try {
        sqlite3_stmt *s = nullptr;
        sql_check(sqlite3_prepare_v2(db, "SELECT revision,document FROM policy_state WHERE issuer=?1", -1, &s, nullptr),
            db, "policy revision read");
        sql_check(sqlite3_bind_text(s, 1, issuer.c_str(), -1, SQLITE_TRANSIENT), db, "policy issuer bind");
        const int rc = sqlite3_step(s);
        std::uint64_t old = 0;
        std::string old_document;
        if (rc == SQLITE_ROW) {
            old = static_cast<std::uint64_t>(sqlite3_column_int64(s, 0));
            const auto *bytes = static_cast<const char *>(sqlite3_column_blob(s, 1));
            const int length = sqlite3_column_bytes(s, 1);
            if (bytes && length > 0) old_document.assign(bytes, static_cast<std::size_t>(length));
        }
        sqlite3_finalize(s);
        if (rc != SQLITE_ROW && rc != SQLITE_DONE) throw std::runtime_error("policy revision query failed");
        if (revision < old || (revision == old && (!allow_unchanged || document != old_document)))
            throw std::runtime_error("SEA_POLICY_ROLLBACK");
        if (revision == old) {
            sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
            return false;
        }
        sql_check(sqlite3_prepare_v2(db,
            "INSERT INTO policy_state(issuer,revision,document) VALUES(?1,?2,?3)"
            " ON CONFLICT(issuer) DO UPDATE SET revision=excluded.revision,document=excluded.document",
            -1, &s, nullptr), db, "policy prepare");
        sql_check(sqlite3_bind_text(s, 1, issuer.c_str(), -1, SQLITE_TRANSIENT), db, "policy issuer bind");
        sql_check(sqlite3_bind_int64(s, 2, static_cast<sqlite3_int64>(revision)), db, "policy revision bind");
        sql_check(sqlite3_bind_blob(s, 3, document.data(), static_cast<int>(document.size()), SQLITE_TRANSIENT),
            db, "policy document bind");
        const int write_rc = sqlite3_step(s);
        sqlite3_finalize(s);
        sql_check(write_rc, db, "policy write");
        sql_check(sqlite3_prepare_v2(db,
            "INSERT INTO policy_audit(issuer,revision,action,committed_at) VALUES(?1,?2,'last_good_stored',strftime('%s','now'))",
            -1, &s, nullptr), db, "policy audit prepare");
        sql_check(sqlite3_bind_text(s, 1, issuer.c_str(), -1, SQLITE_TRANSIENT), db, "policy audit issuer bind");
        sql_check(sqlite3_bind_int64(s, 2, static_cast<sqlite3_int64>(revision)), db, "policy audit revision bind");
        const int audit_rc = sqlite3_step(s);
        sqlite3_finalize(s);
        sql_check(audit_rc, db, "policy audit write");
        if (sqlite3_exec(db, "COMMIT", nullptr, nullptr, nullptr) != SQLITE_OK)
            throw std::runtime_error("policy atomic commit failed");
        return true;
    } catch (...) {
        sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

void validate_signed_policy(const Config &c, const std::string &file, const std::string &sigfile,
                            const std::string &pubfile, const std::string &tenant,
                            const std::string &allowed_root) {
    const std::string document = read_limited(file, 65536);
    const std::string signature = read_limited(sigfile, 128);
    (void)validate_policy_document(c, document, signature, pubfile, tenant, allowed_root, false);
    std::cout << "{\"valid\":true,\"stored_as\":\"last_good\"}\n";
}

std::string decode_policy_signature(const std::string &hex) {
    if (hex.size() != 128U) throw std::runtime_error("policy envelope signature length is invalid");
    std::string signature;
    signature.reserve(64U);
    auto digit = [](unsigned char c) -> int {
        if (c >= '0' && c <= '9') return static_cast<int>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<int>(c - 'a' + 10);
        if (c >= 'A' && c <= 'F') return static_cast<int>(c - 'A' + 10);
        return -1;
    };
    for (std::size_t i = 0; i < hex.size(); i += 2U) {
        const int high = digit(static_cast<unsigned char>(hex[i]));
        const int low = digit(static_cast<unsigned char>(hex[i + 1U]));
        if (high < 0 || low < 0) throw std::runtime_error("policy envelope signature is not hex");
        signature.push_back(static_cast<char>((high << 4) | low));
    }
    return signature;
}

std::string latest_local_policy_document(const Config &c) {
    std::unique_ptr<sqlite3, decltype(&sqlite3_close)> database(open_queue(c.store), sqlite3_close);
    sqlite3_stmt *statement = nullptr;
    sql_check(sqlite3_prepare_v2(database.get(),
        "SELECT document FROM policy_state ORDER BY rowid DESC LIMIT 1", -1, &statement, nullptr),
        database.get(), "policy ETag read prepare");
    const int rc = sqlite3_step(statement);
    std::string document;
    if (rc == SQLITE_ROW) {
        const auto *bytes = static_cast<const char *>(sqlite3_column_blob(statement, 0));
        const int length = sqlite3_column_bytes(statement, 0);
        if (bytes && length > 0) document.assign(bytes, static_cast<std::size_t>(length));
    } else if (rc != SQLITE_DONE) {
        sqlite3_finalize(statement);
        throw std::runtime_error("policy ETag read failed");
    }
    sqlite3_finalize(statement);
    return document;
}

std::string response_status(const std::string &response) {
    const std::size_t line_end = response.find("\r\n");
    if (line_end == std::string::npos || response.compare(0, 9, "HTTP/1.1 ") != 0)
        throw std::runtime_error("SEA_POLICY_ENVELOPE_INVALID");
    const std::size_t code_start = 9U;
    if (line_end < code_start + 3U) throw std::runtime_error("SEA_POLICY_ENVELOPE_INVALID");
    return response.substr(code_start, 3U);
}

void fetch_and_validate_policy(const Config &c, const std::string &pubfile,
                              const std::string &tenant, const std::string &allowed_root) {
    const std::string prior_document = latest_local_policy_document(c);
    TlsClientConnection connection(c);
    std::string request = "GET /v1/agents/self/policy HTTP/1.1\r\nHost: " + c.host + "\r\n";
    if (!prior_document.empty()) request += "If-None-Match: \"" + sha256(prior_document) + "\"\r\n";
    request += "Connection: close\r\n\r\n";
    const std::string response = http_exchange(connection.session.get(), request, {"200", "304"});
    (void)SSL_shutdown(connection.session.get());
    if (response_status(response) == "304") {
        if (prior_document.empty()) throw std::runtime_error("SEA_POLICY_ENVELOPE_INVALID: unexpected 304");
        std::cout << "{\"policy_status\":\"unchanged\"}\n";
        return;
    }
    const std::size_t header_end = response.find("\r\n\r\n");
    if (header_end == std::string::npos) throw std::runtime_error("SEA_POLICY_ENVELOPE_INVALID");
    const std::string body = response.substr(header_end + 4U);
    const Value envelope = agent::json::Parser(body).parse();
    if (!envelope.get("schema_version") || envelope.get("schema_version")->string_or() != "policy_envelope.v1")
        throw std::runtime_error("SEA_POLICY_ENVELOPE_INVALID");
    const Value *document_value = envelope.get("policy_document");
    const Value *signature_value = envelope.get("signature_hex");
    if (!document_value || !signature_value)
        throw std::runtime_error("SEA_POLICY_ENVELOPE_INVALID");
    const std::string document = document_value->string_or();
    const std::string signature = decode_policy_signature(signature_value->string_or());
    const bool changed = validate_policy_document(c, document, signature, pubfile, tenant, allowed_root, true);
    std::cout << "{\"policy_status\":\"" << (changed ? "stored_last_good" : "unchanged") << "\"}\n";
}

void write_pidfile(const std::string &path) {
    if (path.empty()) return;
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) throw std::runtime_error("pidfile exists or inaccessible");
    std::string value = std::to_string(getpid()) + "\n";
    if (write(fd, value.data(), value.size()) != static_cast<ssize_t>(value.size())) {
        close(fd); unlink(path.c_str()); throw std::runtime_error("pidfile write failed");
    }
    close(fd);
}
int stop_pid(const std::string &path) {
    std::ifstream in(path); long pid = 0;
    if (!(in >> pid) || pid <= 1 || pid == getpid()) throw std::runtime_error("invalid PID file");
    if (kill(static_cast<pid_t>(pid), SIGTERM) != 0) throw std::runtime_error("cannot signal agent");
    return 0;
}
} // namespace

int main(int argc, char **argv) {
    try {
        if (argc < 2 || std::string(argv[1]) == "--help") {
            std::cout << "sw-agentd enroll|run|status|doctor|flush|import-event|sync-policy|validate-policy|stop [options]\n"
                          "TLS options: --endpoint HOST --port PORT --agent-id UUID --ca FILE --cert FILE --key FILE\n"
                          "Storage: --store DIR; policy: --file JSON --signature RAW64 --pubkey PEM --tenant ID --root ABS\n"
                          "Long-running run: --interval-seconds N enables policy-root inotify collection; --policy-sync-interval-seconds N refreshes signed policy\n";
            return argc < 2 ? 2 : 0;
        }
        std::string command = argv[1];
        if (command == "stop") return stop_pid(arg(argc, argv, "--pidfile", "./sw-agentd.pid"));
        Config c;
        c.host = arg(argc, argv, "--endpoint", "127.0.0.1");
        c.port = arg(argc, argv, "--port", "8443");
        c.agent_id = arg(argc, argv, "--agent-id");
        c.ca = arg(argc, argv, "--ca");
        c.cert = arg(argc, argv, "--cert");
        c.key = arg(argc, argv, "--key");
        c.store = arg(argc, argv, "--store");
        c.tenant = arg(argc, argv, "--tenant");
        if (command == "status") {
            std::unique_ptr<sqlite3, decltype(&sqlite3_close)> database(open_queue(c.store), sqlite3_close);
            sqlite3 *db = database.get();
            sqlite3_stmt *s = nullptr;
            sql_check(sqlite3_prepare_v2(db, "SELECT count(*),COALESCE(sum(length(payload)),0) FROM queue", -1, &s, nullptr),
                db, "status queue prepare");
            const int rc = sqlite3_step(s);
            if (rc != SQLITE_ROW) {
                sqlite3_finalize(s);
                throw std::runtime_error("status queue read failed");
            }
            const int queued = sqlite3_column_int(s, 0);
            const sqlite3_int64 bytes = sqlite3_column_int64(s, 1);
            sqlite3_finalize(s);
            const RuntimePolicy policy = active_policy(db, c.tenant, false);
            const char *policy_status = !policy.present ? "NO_POLICY" :
                (policy.expired ? "STALE" : (policy.telemetry_enabled ? "ACTIVE" : "VALIDATED"));
            std::cout << "{\"state\":\"" << policy_status << "\",\"policy_status\":\"" << policy_status
                      << "\",\"policy_revision\":";
            if (policy.present) std::cout << policy.revision;
            else std::cout << "null";
            std::cout << ",\"telemetry_enabled\":" << (policy.telemetry_enabled ? "true" : "false")
                      << ",\"sample_rate\":" << policy.sample_rate
                      << ",\"monitored_root_count\":" << policy.monitored_root_count
                      << ",\"queued\":" << queued << ",\"bytes\":" << bytes << "}\n";
            return 0;
        }
        if (command == "doctor" || command == "enroll") {
            if (!is_loopback(c.host)) throw std::runtime_error("SEA_SCOPE_INVALID: endpoint must be loopback");
            SSL_CTX *ctx = client_context(c);
            SSL_CTX_free(ctx);
            sqlite3 *db = open_queue(c.store); sqlite3_close(db);
            std::cout << "{\"ready\":true,\"tls\":\"mTLS\",\"endpoint_scope\":\"loopback\"}\n";
            return 0;
        }
        if (command == "validate-policy") {
            validate_signed_policy(c, arg(argc, argv, "--file"), arg(argc, argv, "--signature"),
                arg(argc, argv, "--pubkey"), arg(argc, argv, "--tenant"), arg(argc, argv, "--root"));
            return 0;
        }
        if (command == "sync-policy") {
            fetch_and_validate_policy(c, arg(argc, argv, "--pubkey"),
                arg(argc, argv, "--tenant"), arg(argc, argv, "--root"));
            return 0;
        }
        if (command == "import-event") return import_event(c, arg(argc, argv, "--file"));
        if (command != "flush" && command != "run") throw std::runtime_error("unknown command");
        std::unique_ptr<sqlite3, decltype(&sqlite3_close)> database(open_queue(c.store), sqlite3_close);
        sqlite3 *db = database.get();
        signal(SIGINT, stop_signal); signal(SIGTERM, stop_signal);
        std::string pidfile = arg(argc, argv, "--pidfile");
        if (command == "run" && !pidfile.empty()) write_pidfile(pidfile);
        int interval = std::stoi(arg(argc, argv, "--interval-seconds", "0"));
        if (interval < 0 || interval > 86400) throw std::runtime_error("interval out of range");
        int rc = 0;
        if (command == "run" && interval > 0) {
            const std::string pubfile = arg(argc, argv, "--pubkey");
            const std::string allowed_root = arg(argc, argv, "--root");
            const std::string sync_default = pubfile.empty() ? "0" : "60";
            int sync_interval = std::stoi(arg(argc, argv, "--policy-sync-interval-seconds", sync_default));
            if (sync_interval < 0 || sync_interval > 86400)
                throw std::runtime_error("policy sync interval out of range");
            if (!pubfile.empty() && allowed_root.empty())
                throw std::runtime_error("--root is required when --pubkey is configured");
            if (sync_interval > 0 && pubfile.empty())
                throw std::runtime_error("--pubkey is required for periodic policy sync");

            if (!pubfile.empty()) {
                try {
                    fetch_and_validate_policy(c, pubfile, c.tenant, allowed_root);
                } catch (const std::exception &error) {
                    std::cerr << "policy sync deferred; last-good policy remains active: "
                              << error.what() << '\n';
                }
            }

            RuntimePolicy current_policy = active_policy(db, c.tenant, false);
            auto should_watch = [](const RuntimePolicy &policy) {
                return policy.present && !policy.expired && policy.telemetry_enabled &&
                    policy.sample_rate > 0.0 && !policy.monitored_roots.empty();
            };
            std::unique_ptr<InotifyCollector> collector;
            if (should_watch(current_policy))
                collector = std::make_unique<InotifyCollector>(c.store, current_policy);
            auto policy_identity = [](const RuntimePolicy &policy) {
                std::ostringstream identity;
                identity << policy.issuer << ':' << policy.revision << ':' << policy.expired << ':'
                         << policy.telemetry_enabled << ':' << std::setprecision(17) << policy.sample_rate;
                for (const auto &root : policy.monitored_roots) identity << ':' << root.native();
                return identity.str();
            };
            std::string deferred_policy_identity;
            std::chrono::steady_clock::time_point deferred_retry_after{};
            (void)enqueue_synthetic_if_enabled(db, c.tenant);
            rc = flush(db, c);

            using Clock = std::chrono::steady_clock;
            const auto flush_delay = std::chrono::seconds(interval);
            const auto sync_delay = std::chrono::seconds(sync_interval);
            auto next_flush = Clock::now() + flush_delay;
            auto next_heartbeat = next_flush;
            auto next_policy_sync = sync_interval > 0 ? Clock::now() + sync_delay : Clock::time_point::max();
            while (!stopping) {
                auto now = Clock::now();
                if (sync_interval > 0 && now >= next_policy_sync) {
                    try {
                        fetch_and_validate_policy(c, pubfile, c.tenant, allowed_root);
                    } catch (const std::exception &error) {
                        std::cerr << "policy sync deferred; last-good policy remains active: "
                                  << error.what() << '\n';
                    }
                    next_policy_sync = Clock::now() + sync_delay;
                }

                RuntimePolicy refreshed = active_policy(db, c.tenant, false);
                const bool policy_changed = refreshed.revision != current_policy.revision ||
                    refreshed.present != current_policy.present || refreshed.expired != current_policy.expired ||
                    refreshed.telemetry_enabled != current_policy.telemetry_enabled ||
                    refreshed.sample_rate != current_policy.sample_rate ||
                    refreshed.monitored_roots != current_policy.monitored_roots;
                if (policy_changed && (policy_identity(refreshed) != deferred_policy_identity ||
                    Clock::now() >= deferred_retry_after)) {
                    try {
                        std::unique_ptr<InotifyCollector> staged_collector;
                        if (should_watch(refreshed)) {
                            staged_collector = std::make_unique<InotifyCollector>(c.store, refreshed);
                            if (!staged_collector->ready_for_policy())
                                throw std::runtime_error("monitored roots are not fully watchable");
                        }
                        collector.swap(staged_collector);
                        current_policy = std::move(refreshed);
                        deferred_policy_identity.clear();
                        deferred_retry_after = Clock::time_point{};
                    } catch (const std::exception &error) {
                        deferred_policy_identity = policy_identity(refreshed);
                        deferred_retry_after = Clock::now() +
                            (sync_interval > 0 ? sync_delay : std::chrono::seconds(60));
                        std::cerr << "policy activation deferred; last active policy and watches remain active: "
                                  << error.what() << '\n';
                    }
                }

                const auto before_poll = Clock::now();
                auto wake_at = std::min(next_flush, next_heartbeat);
                wake_at = std::min(wake_at, next_policy_sync);
                const auto remaining = wake_at > before_poll ?
                    std::chrono::duration_cast<std::chrono::milliseconds>(wake_at - before_poll).count() : 0;
                const int wait_ms = static_cast<int>(std::min<std::int64_t>(250, std::max<std::int64_t>(0, remaining)));
                if (collector) collector->poll_once(db, current_policy, wait_ms);
                else std::this_thread::sleep_for(std::chrono::milliseconds(std::max(wait_ms, 1)));

                now = Clock::now();
                if (now >= next_heartbeat) {
                    (void)enqueue_synthetic_if_enabled(db, c.tenant);
                    next_heartbeat = now + flush_delay;
                }
                if (now >= next_flush) {
                    rc = flush(db, c);
                    next_flush = now + flush_delay;
                }
            }
        } else {
            if (command == "run" || flag(argc, argv, "--synthetic"))
                (void)enqueue_synthetic_if_enabled(db, c.tenant);
            do {
                rc = flush(db, c);
                if (interval == 0 || stopping) break;
                for (int i = 0; i < interval && !stopping; ++i)
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                if (!stopping) (void)enqueue_synthetic_if_enabled(db, c.tenant);
            } while (!stopping);
        }
        if (!pidfile.empty()) unlink(pidfile.c_str());
        return rc;
    } catch (const std::exception &e) {
        std::cerr << "sw-agentd: " << e.what() << '\n'; return 2;
    }
}
