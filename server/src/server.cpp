#include "agent/json.hpp"
#include "agent/http.hpp"
#include <openssl/err.h>
#include <openssl/evp.h>
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
#include <cmath>
#include <cerrno>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <ctime>
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
        " PRIMARY KEY(agent_id,event_id));";
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

agent::http::Request read_request(SSL *ssl) {
    std::string raw;
    std::array<char, 8192> buffer {};
    for (;;) {
        if (raw.size() > agent::http::kMaxHttpHeader + 4U + agent::http::kMaxHttpBody)
            throw std::runtime_error("HTTP request exceeds size limit");
        const std::optional<agent::http::RequestHead> head = agent::http::parse_request_head(raw);
        if (head) {
            const std::size_t expected_size = head->header_size + head->body_size;
            if (raw.size() > expected_size) throw std::runtime_error("bytes follow the framed HTTP request");
            if (raw.size() == expected_size) return agent::http::parse_request(raw);
        }
        int n = SSL_read(ssl, buffer.data(), static_cast<int>(buffer.size()));
        if (n <= 0) throw std::runtime_error("incomplete HTTP request body");
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
void respond(SSL *ssl, int status, const std::string &reason, const std::string &body) {
    std::string response = "HTTP/1.1 " + std::to_string(status) + " " + reason +
        "\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: " +
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

void serve_one(sqlite3 *db, const std::set<std::string> &agents, SSL_CTX *ctx, int fd) {
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
    if (identity.empty() || !agents.contains(identity)) {
        respond(ssl.get(), 403, "Forbidden", "{\"error\":\"SEA_AGENT_UNAUTHORIZED\"}");
        SSL_shutdown(ssl.get()); return;
    }
    try {
        Request req = read_request(ssl.get());
        if (req.path == "/healthz" && req.method == "GET") {
            respond(ssl.get(), 200, "OK", "{\"status\":\"ok\"}");
        } else if (req.path == "/v1/agents/self/events:batch" && req.method == "POST") {
            if (agent::http::lowercase_ascii(req.content_type) != "application/json")
                throw std::runtime_error("event batch requires application/json Content-Type");
            ingest(db, agents, ssl.get(), req, identity);
        } else if (req.path == "/v1/agents/self/heartbeat" && req.method == "POST") {
            respond(ssl.get(), 200, "OK", "{\"schema_version\":\"heartbeat_ack.v1\",\"status\":\"ok\"}");
        } else if (req.path == "/v1/agents/self/status" && req.method == "GET") {
            respond(ssl.get(), 200, "OK", "{\"schema_version\":\"agent_status.v1\",\"state\":\"registered\"}");
        } else if (req.path == "/v1/agents/self/policy" && req.method == "GET") {
            respond(ssl.get(), 304, "Not Modified", "{}");
        } else if (req.path == "/v1/admin/policies" && req.method == "POST") {
            respond(ssl.get(), 403, "Forbidden", "{\"error\":\"operator API is disabled in this lab build\"}");
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
    std::string dbfile = arg(argc, argv, "--db", "./server.sqlite");
    int port = std::stoi(arg(argc, argv, "--port", "8443"));
    if (port < 1024 || port > 65535) throw std::runtime_error("invalid listen port");
    std::set<std::string> agents = read_allowlist(agents_file);
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
    std::cout << "sw-server listening on 127.0.0.1:" << port << " (mTLS, lab only)\n";
    while (!stopping) {
        sockaddr_storage peer {};
        socklen_t peer_len = sizeof(peer);
        int fd = accept4(listener, reinterpret_cast<sockaddr *>(&peer), &peer_len, SOCK_CLOEXEC);
        if (fd < 0 && errno == EINTR) {
            if (stopping) break;
            continue;
        }
        if (fd < 0) break;
        serve_one(db, agents, ctx, fd);
    }
    close(listener); sqlite3_close(db); SSL_CTX_free(ctx);
    return 0;
}
} // namespace

int main(int argc, char **argv) {
    try {
        if (argc < 2 || std::string(argv[1]) == "--help") {
            std::cout << "sw-server run --cert FILE --key FILE --ca FILE --agents FILE [--db FILE --port N]\n";
            return argc < 2 ? 2 : 0;
        }
        if (std::string(argv[1]) != "run") throw std::runtime_error("unknown command");
        return run_server(argc, argv);
    } catch (const std::exception &e) {
        std::cerr << "sw-server: " << e.what() << '\n'; return 2;
    }
}
