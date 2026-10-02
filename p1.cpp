// p1.cpp (UPDATED - Boss-based reveal randomness, commitments from bidders_info.json)
// - Verifies Ed25519 signature, decrypts shares, verifies BabyJub Pedersen CCE (C1)
// - Stores ONLY valid bidders (good) and preserves ARRIVAL order as baseline indices 1..n
// - Computes permutation index vector from reconstructed IDs after MPC sort
// - Loads commitments from onchain/bidders_info.json (single shared file written by bidder-boss)
// - After auction reveal, requests randomness (r1_dec) ONCE from bidder-boss reveal server and saves JSON
//

// Requirements:
//   - node installed
//   - verifier_CCE.js present (or set --cce-verifier path)
//   - npm packages installed: circomlibjs
//
// Wire format (boss->P1) MUST MATCH previous bidder + P0:




#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/random.h>
#include <signal.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <optional>
#include <sstream>
#include <future>
#include <mutex>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <chrono>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>

#include <cstdio>

namespace fs = std::filesystem;

namespace {

static const char* DIRECT_MAGIC = "SFDAC-AUCTIONEER-DIRECT-V1";
static const char* EVIDENCE_MAGIC = "SFDAC-MERKLE-EVIDENCE-V1";
static const char* SIGNED_PACKET_DOMAIN = "SFDAC-BIDDER-SIGNED-PACKET-V3";
static const uint64_t MAX_RELAY_CIPHERTEXT_BYTES = 4096;
static std::mutex g_onchain_tx_mutex;

// =============================================================
// Basic wrap arithmetic
// =============================================================

uint64_t add_wrap(uint64_t a, uint64_t b) {
    return a + b;
}

uint64_t sub_wrap(uint64_t a, uint64_t b) {
    return a - b;
}

uint64_t mul_wrap(uint64_t a, uint64_t b) {
    return static_cast<uint64_t>(static_cast<unsigned __int128>(a) * b);
}

// =============================================================
// Randomness helpers
// =============================================================

uint64_t random_u64() {
    uint64_t value = 0;
    size_t filled = 0;
    uint8_t* ptr = reinterpret_cast<uint8_t*>(&value);

    while (filled < sizeof(value)) {
        ssize_t got = getrandom(ptr + filled, sizeof(value) - filled, 0);

        if (got < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error("getrandom failed");
        }

        filled += static_cast<size_t>(got);
    }

    return value;
}

uint64_t random_mask31() {
    return random_u64() & ((1ULL << 31) - 1);
}

// =============================================================
// Networking helpers
// =============================================================

void send_all(int fd, const void* data, size_t len) {
    const uint8_t* ptr = static_cast<const uint8_t*>(data);

    while (len > 0) {
        ssize_t sent = send(fd, ptr, len, 0);

        if (sent < 0 && errno == EINTR) {
            continue;
        }

        if (sent <= 0) {
            throw std::runtime_error("send failed");
        }

        ptr += static_cast<size_t>(sent);
        len -= static_cast<size_t>(sent);
    }
}

void recv_all(int fd, void* data, size_t len) {
    uint8_t* ptr = static_cast<uint8_t*>(data);

    while (len > 0) {
        ssize_t got = recv(fd, ptr, len, MSG_WAITALL);

        if (got < 0 && errno == EINTR) {
            continue;
        }

        if (got <= 0) {
            throw std::runtime_error("recv failed");
        }

        ptr += static_cast<size_t>(got);
        len -= static_cast<size_t>(got);
    }
}

static inline uint64_t htobe64_u64(uint64_t v) {
    return htobe64(v);
}

static inline uint64_t be64toh_u64(uint64_t v) {
    return be64toh(v);
}

void send_u64(int fd, uint64_t value) {
    uint64_t net = htobe64_u64(value);
    send_all(fd, &net, sizeof(net));
}

uint64_t recv_u64(int fd) {
    uint64_t net = 0;
    recv_all(fd, &net, sizeof(net));
    return be64toh_u64(net);
}

void send_u64_pair(int fd, uint64_t first, uint64_t second) {
    uint64_t buffer[2] = {
        htobe64_u64(first),
        htobe64_u64(second)
    };

    send_all(fd, buffer, sizeof(buffer));
}

void recv_u64_pair(int fd, uint64_t& first, uint64_t& second) {
    uint64_t buffer[2];
    recv_all(fd, buffer, sizeof(buffer));

    first = be64toh_u64(buffer[0]);
    second = be64toh_u64(buffer[1]);
}

void send_u64_vector(int fd, const std::vector<uint64_t>& values) {
    if (values.empty()) return;

    std::vector<uint64_t> buffer(values.size());

    for (size_t i = 0; i < values.size(); ++i) {
        buffer[i] = htobe64_u64(values[i]);
    }

    send_all(fd, buffer.data(), buffer.size() * sizeof(uint64_t));
}

void recv_u64_vector(int fd, std::vector<uint64_t>& values) {
    if (values.empty()) return;

    std::vector<uint64_t> buffer(values.size());
    recv_all(fd, buffer.data(), buffer.size() * sizeof(uint64_t));

    for (size_t i = 0; i < values.size(); ++i) {
        values[i] = be64toh_u64(buffer[i]);
    }
}


void send_string(int fd, const std::string& value) {
    send_u64(fd, static_cast<uint64_t>(value.size()));
    if (!value.empty()) {
        send_all(fd, value.data(), value.size());
    }
}

std::string recv_string(int fd) {
    uint64_t n = recv_u64(fd);
    if (n > (1ULL << 20)) {
        throw std::runtime_error("recv_string: unreasonable string length");
    }
    std::string value(static_cast<size_t>(n), '\0');
    if (n > 0) {
        recv_all(fd, value.data(), static_cast<size_t>(n));
    }
    return value;
}

void send_string_vector(int fd, const std::vector<std::string>& values) {
    send_u64(fd, static_cast<uint64_t>(values.size()));
    for (const auto& v : values) {
        send_string(fd, v);
    }
}

std::vector<std::string> recv_string_vector(int fd) {
    uint64_t n = recv_u64(fd);
    if (n > (1ULL << 20)) {
        throw std::runtime_error("recv_string_vector: unreasonable vector length");
    }
    std::vector<std::string> values;
    values.reserve(static_cast<size_t>(n));
    for (uint64_t i = 0; i < n; ++i) {
        values.push_back(recv_string(fd));
    }
    return values;
}

int create_listener(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0) {
        throw std::runtime_error("socket creation failed");
    }

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        int e = errno;
        close(fd);
        throw std::runtime_error("bind failed errno=" + std::to_string(e));
    }

    if (listen(fd, 128) < 0) {
        int e = errno;
        close(fd);
        throw std::runtime_error("listen failed errno=" + std::to_string(e));
    }

    return fd;
}

static void set_sock_timeouts(int fd, int seconds) {
    timeval tv{};
    tv.tv_sec = seconds;
    tv.tv_usec = 0;

    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

static int connect_to(const std::string& ip, uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0) {
        throw std::runtime_error("socket() failed");
    }

    set_sock_timeouts(fd, 10);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
        close(fd);
        throw std::runtime_error("inet_pton failed for " + ip);
    }

    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        int e = errno;
        close(fd);
        throw std::runtime_error("connect failed errno=" + std::to_string(e));
    }

    return fd;
}

static int connect_to_retry(
    const std::string& ip,
    uint16_t port,
    int attempts,
    int sleep_ms
) {
    int last_errno = 0;

    for (int attempt = 0; attempt < attempts; ++attempt) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);

        if (fd < 0) {
            throw std::runtime_error("socket() failed");
        }

        set_sock_timeouts(fd, 10);

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);

        if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
            close(fd);
            throw std::runtime_error("inet_pton failed for " + ip);
        }

        if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) {
            return fd;
        }

        last_errno = errno;
        close(fd);
        usleep(static_cast<useconds_t>(sleep_ms) * 1000);
    }

    throw std::runtime_error(
        "connect failed after retries errno=" + std::to_string(last_errno)
    );
}

static void send_lp_string(int fd, const std::string& s) {
    send_u64(fd, static_cast<uint64_t>(s.size()));

    if (!s.empty()) {
        send_all(fd, s.data(), s.size());
    }
}

static std::string recv_lp_string(int fd) {
    uint64_t n = recv_u64(fd);

    if (n > (128ULL << 20)) {
        throw std::runtime_error("lp_string too large");
    }

    std::string s(n, '\0');

    if (n) {
        recv_all(fd, &s[0], static_cast<size_t>(n));
    }

    return s;
}

// =============================================================
// Generic file/string helpers
// =============================================================

static int64_t now_ms_epoch() {
    using namespace std::chrono;

    return static_cast<int64_t>(
        duration_cast<milliseconds>(
            system_clock::now().time_since_epoch()
        ).count()
    );
}

static void ensure_parent_dir(const std::string& path) {
    fs::path p(path);

    if (p.has_parent_path()) {
        fs::create_directories(p.parent_path());
    }
}

static std::string json_escape(std::string s) {
    std::string out;
    out.reserve(s.size() + 8);

    for (unsigned char ch : s) {
        switch (ch) {
            case '\\':
                out += "\\\\";
                break;

            case '"':
                out += "\\\"";
                break;

            case '\n':
                out += "\\n";
                break;

            case '\r':
                out += "\\r";
                break;

            case '\t':
                out += "\\t";
                break;

            default:
                if (ch < 0x20) {
                    char buf[7];
                    std::snprintf(
                        buf,
                        sizeof(buf),
                        "\\u%04x",
                        static_cast<unsigned>(ch)
                    );
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(ch));
                }
        }
    }

    return out;
}

static std::string read_file_text(const std::string& path) {
    std::ifstream in(path);

    if (!in) {
        throw std::runtime_error("cannot open file: " + path);
    }

    std::string content{
        std::istreambuf_iterator<char>(in),
        std::istreambuf_iterator<char>()
    };

    return content;
}

static void write_file_text(const std::string& path, const std::string& data) {
    ensure_parent_dir(path);

    std::ofstream out(path);

    if (!out) {
        throw std::runtime_error("cannot write file: " + path);
    }

    out << data;
}

static std::string shell_escape_single_quotes(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);

    out.push_back('\'');

    for (char c : s) {
        if (c == '\'') {
            out += "'\"'\"'";
        } else {
            out.push_back(c);
        }
    }

    out.push_back('\'');

    return out;
}

// =============================================================
// Hex helpers
// =============================================================

static int hexval(char c) {
    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return 10 + (c - 'a');
    if ('A' <= c && c <= 'F') return 10 + (c - 'A');

    return -1;
}

static std::vector<uint8_t> hex_to_bytes_flex(std::string hex) {
    std::string h;
    h.reserve(hex.size());

    for (char c : hex) {
        if (!std::isspace(static_cast<unsigned char>(c))) {
            h.push_back(c);
        }
    }

    if (h.rfind("0x", 0) == 0 || h.rfind("0X", 0) == 0) {
        h = h.substr(2);
    }

    if (h.size() % 2 != 0) {
        throw std::runtime_error("hex length must be even");
    }

    std::vector<uint8_t> out(h.size() / 2);

    for (size_t i = 0; i < out.size(); ++i) {
        int hi = hexval(h[2 * i]);
        int lo = hexval(h[2 * i + 1]);

        if (hi < 0 || lo < 0) {
            throw std::runtime_error("invalid hex");
        }

        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }

    return out;
}

static std::string bytes_to_hex(const std::vector<uint8_t>& v) {
    static const char* hexd = "0123456789abcdef";

    std::string s;
    s.reserve(v.size() * 2);

    for (uint8_t b : v) {
        s.push_back(hexd[b >> 4]);
        s.push_back(hexd[b & 0x0f]);
    }

    return s;
}


static std::string normalize_hex32(std::string h) {
    while (!h.empty() && std::isspace(static_cast<unsigned char>(h.back()))) h.pop_back();
    while (!h.empty() && std::isspace(static_cast<unsigned char>(h.front()))) h.erase(h.begin());
    if (h.rfind("0x", 0) != 0 && h.rfind("0X", 0) != 0) h = "0x" + h;
    if (h.size() != 66) throw std::runtime_error("expected bytes32 hex, got length " + std::to_string(h.size()));
    return h;
}

static std::array<uint8_t, 32> hex32_to_array(std::string h) {
    h = normalize_hex32(h).substr(2);
    std::array<uint8_t, 32> out{};
    for (size_t i = 0; i < 32; ++i) {
        int hi = hexval(h[2 * i]);
        int lo = hexval(h[2 * i + 1]);
        if (hi < 0 || lo < 0) throw std::runtime_error("invalid bytes32 hex");
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return out;
}

static std::string bytes32_to_hex(const std::array<uint8_t, 32>& a) {
    static const char* hexd = "0123456789abcdef";
    std::string s = "0x";
    s.reserve(66);
    for (uint8_t b : a) {
        s.push_back(hexd[b >> 4]);
        s.push_back(hexd[b & 0x0f]);
    }
    return s;
}

static std::array<uint8_t, 32> sha256_pair(
    const std::array<uint8_t, 32>& left,
    const std::array<uint8_t, 32>& right
) {
    uint8_t buf[64];
    std::memcpy(buf, left.data(), 32);
    std::memcpy(buf + 32, right.data(), 32);
    std::array<uint8_t, 32> out{};
    SHA256(buf, sizeof(buf), out.data());
    return out;
}

static bool merkle_path_matches_root(
    const std::string& leaf_hash,
    const std::string& root_hash,
    const std::vector<std::string>& path_elements,
    const std::vector<uint64_t>& path_directions
) {
    if (path_elements.size() != path_directions.size()) return false;

    std::array<uint8_t, 32> cur = hex32_to_array(leaf_hash);

    for (size_t i = 0; i < path_elements.size(); ++i) {
        std::array<uint8_t, 32> sibling = hex32_to_array(path_elements[i]);
        if (path_directions[i] == 0) {
            cur = sha256_pair(cur, sibling);
        } else if (path_directions[i] == 1) {
            cur = sha256_pair(sibling, cur);
        } else {
            return false;
        }
    }

    return normalize_hex32(bytes32_to_hex(cur)) == normalize_hex32(root_hash);
}

static std::string join_string_csv(const std::vector<std::string>& values) {
    std::ostringstream os;
    for (size_t i = 0; i < values.size(); ++i) {
        if (i) os << ",";
        os << values[i];
    }
    return os.str();
}

static std::string join_u64_csv_values(const std::vector<uint64_t>& values) {
    std::ostringstream os;
    for (size_t i = 0; i < values.size(); ++i) {
        if (i) os << ",";
        os << values[i];
    }
    return os.str();
}

static std::vector<uint8_t> read_file_bytes_hex(const std::string& path) {
    std::ifstream in(path);

    if (!in) {
        throw std::runtime_error("cannot open hex file: " + path);
    }

    std::string hex{
        std::istreambuf_iterator<char>(in),
        std::istreambuf_iterator<char>()
    };

    return hex_to_bytes_flex(hex);
}

// =============================================================
// Boss reveal client
// =============================================================

struct RevealedRandomnessRec {
    std::string role;
    std::string name;
    uint64_t full_id = 0;
    std::string r_dec;
};

static std::vector<RevealedRandomnessRec> request_randomness_from_boss(
    const std::string& boss_ip,
    uint16_t boss_port,
    uint64_t which
) {
    int fd = connect_to(boss_ip, boss_port);

    send_lp_string(fd, "p1");
    send_u64(fd, which);

    uint64_t count = recv_u64(fd);

    std::vector<RevealedRandomnessRec> out;
    out.reserve(static_cast<size_t>(count));

    for (uint64_t i = 0; i < count; ++i) {
        RevealedRandomnessRec r;

        r.role = recv_lp_string(fd);
        r.name = recv_lp_string(fd);
        r.full_id = recv_u64(fd);
        r.r_dec = recv_lp_string(fd);

        out.push_back(std::move(r));
    }

    close(fd);

    return out;
}

// =============================================================
// secp256k1 context and bidder-share decryption
// =============================================================

struct Secp256k1Ctx {
    EC_GROUP* group{nullptr};
    BN_CTX* bn_ctx{nullptr};

    Secp256k1Ctx() {
        group = EC_GROUP_new_by_curve_name(NID_secp256k1);

        if (!group) {
            throw std::runtime_error("EC_GROUP_new_by_curve_name failed");
        }

        bn_ctx = BN_CTX_new();

        if (!bn_ctx) {
            throw std::runtime_error("BN_CTX_new failed");
        }
    }

    ~Secp256k1Ctx() {
        if (bn_ctx) {
            BN_CTX_free(bn_ctx);
        }

        if (group) {
            EC_GROUP_free(group);
        }
    }
};

Secp256k1Ctx& secp256k1_ctx() {
    static thread_local Secp256k1Ctx ctx;
    return ctx;
}

struct ElgamalPriv {
    std::array<uint8_t, 32> scalar;
};

ElgamalPriv load_elgamal_priv(const std::string& path) {
    auto bytes = read_file_bytes_hex(path);

    if (bytes.size() != 32) {
        throw std::runtime_error(
            "ElGamal private key must be 32 bytes in " + path
        );
    }

    ElgamalPriv p{};
    std::memcpy(p.scalar.data(), bytes.data(), p.scalar.size());

    return p;
}

static std::vector<uint8_t> bn_to_32(BIGNUM* bn) {
    std::vector<uint8_t> out(32, 0);

    int n = BN_num_bytes(bn);

    if (n > 32) {
        throw std::runtime_error("BIGNUM too large");
    }

    BN_bn2bin(bn, out.data() + (32 - n));

    return out;
}

uint64_t decrypt_u64_hybrid(
    const std::vector<uint8_t>& eph_pub,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& tag,
    const std::vector<uint8_t>& ciphertext,
    const ElgamalPriv& priv
) {
    // The buyer and seller receivers run concurrently. secp256k1_ctx() is
    // thread-local, so this function never shares BN_CTX/EC_GROUP state across
    // those worker threads.
    if (eph_pub.size() != 33) {
        throw std::runtime_error("Ephemeral public key must be exactly 33 bytes");
    }
    if (iv.size() != 12) {
        throw std::runtime_error("AES-GCM IV must be exactly 12 bytes");
    }
    if (tag.size() != 16) {
        throw std::runtime_error("AES-GCM tag must be exactly 16 bytes");
    }
    if (ciphertext.size() != 8) {
        throw std::runtime_error("Encrypted uint64 ciphertext must be exactly 8 bytes");
    }

    auto& ctx = secp256k1_ctx();

    using BNPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
    using PointPtr = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;
    using CipherPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

    BNPtr d(BN_bin2bn(priv.scalar.data(), static_cast<int>(priv.scalar.size()), nullptr), BN_free);
    BNPtr order(BN_new(), BN_free);
    if (!d || !order) {
        throw std::runtime_error("Failed to allocate private-key BIGNUM");
    }
    if (EC_GROUP_get_order(ctx.group, order.get(), ctx.bn_ctx) != 1) {
        throw std::runtime_error("Failed to read secp256k1 group order");
    }
    if (BN_is_zero(d.get()) || BN_is_negative(d.get()) || BN_cmp(d.get(), order.get()) >= 0) {
        throw std::runtime_error("ElGamal private key scalar is outside [1,n-1]");
    }

    PointPtr R(EC_POINT_new(ctx.group), EC_POINT_free);
    PointPtr S(EC_POINT_new(ctx.group), EC_POINT_free);
    if (!R || !S) {
        throw std::runtime_error("EC_POINT_new failed");
    }

    ERR_clear_error();
    if (EC_POINT_oct2point(ctx.group, R.get(), eph_pub.data(), eph_pub.size(), ctx.bn_ctx) != 1) {
        throw std::runtime_error("Ephemeral key decode failed");
    }
    if (EC_POINT_is_at_infinity(ctx.group, R.get()) == 1) {
        throw std::runtime_error("Ephemeral key is point-at-infinity");
    }
    if (EC_POINT_is_on_curve(ctx.group, R.get(), ctx.bn_ctx) != 1) {
        throw std::runtime_error("Ephemeral key is not on secp256k1");
    }

    ERR_clear_error();
    if (EC_POINT_mul(ctx.group, S.get(), nullptr, R.get(), d.get(), ctx.bn_ctx) != 1) {
        unsigned long err = ERR_get_error();
        char errbuf[256] = {0};
        if (err != 0) ERR_error_string_n(err, errbuf, sizeof(errbuf));
        throw std::runtime_error(std::string("ECDH failed") + (err != 0 ? std::string(": ") + errbuf : ""));
    }
    if (EC_POINT_is_at_infinity(ctx.group, S.get()) == 1) {
        throw std::runtime_error("ECDH produced point-at-infinity");
    }

    BNPtr sx(BN_new(), BN_free);
    BNPtr sy(BN_new(), BN_free);
    if (!sx || !sy) {
        throw std::runtime_error("BN_new failed");
    }
    if (EC_POINT_get_affine_coordinates(ctx.group, S.get(), sx.get(), sy.get(), ctx.bn_ctx) != 1) {
        throw std::runtime_error("get_affine failed");
    }

    std::vector<uint8_t> sx_bytes = bn_to_32(sx.get());
    std::array<uint8_t, SHA256_DIGEST_LENGTH> key{};
    SHA256(sx_bytes.data(), sx_bytes.size(), key.data());

    CipherPtr aes_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!aes_ctx) {
        OPENSSL_cleanse(key.data(), key.size());
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }

    if (EVP_DecryptInit_ex(aes_ctx.get(), EVP_aes_256_gcm(), nullptr, key.data(), iv.data()) != 1) {
        OPENSSL_cleanse(key.data(), key.size());
        throw std::runtime_error("AES Init failed");
    }

    std::array<uint8_t, 8> plaintext{};
    int len = 0;
    if (EVP_DecryptUpdate(
            aes_ctx.get(),
            plaintext.data(),
            &len,
            ciphertext.data(),
            static_cast<int>(ciphertext.size())
        ) != 1) {
        OPENSSL_cleanse(key.data(), key.size());
        throw std::runtime_error("AES Update failed");
    }

    if (EVP_CIPHER_CTX_ctrl(
            aes_ctx.get(),
            EVP_CTRL_GCM_SET_TAG,
            static_cast<int>(tag.size()),
            const_cast<uint8_t*>(tag.data())
        ) != 1) {
        OPENSSL_cleanse(key.data(), key.size());
        throw std::runtime_error("Set tag failed");
    }

    int final_len = 0;
    const int final_ok = EVP_DecryptFinal_ex(aes_ctx.get(), plaintext.data() + len, &final_len);
    OPENSSL_cleanse(key.data(), key.size());
    if (final_ok <= 0) {
        throw std::runtime_error("AES Decrypt/Tag verify failed");
    }
    if (len + final_len != static_cast<int>(plaintext.size())) {
        throw std::runtime_error("Decrypted uint64 has an unexpected length");
    }

    uint64_t be = 0;
    std::memcpy(&be, plaintext.data(), plaintext.size());
    OPENSSL_cleanse(plaintext.data(), plaintext.size());
    return be64toh_u64(be);
}

uint64_t decrypt_id_hybrid(
    const std::vector<uint8_t>& eph_pub,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& tag,
    const std::vector<uint8_t>& ciphertext,
    const ElgamalPriv& priv
) {
    return decrypt_u64_hybrid(eph_pub, iv, tag, ciphertext, priv);
}

// =============================================================
// Ed25519 bidder signature verification
// =============================================================

std::map<std::string, std::array<uint8_t, 32>> load_pubkeys_json(
    const std::string& path
) {
    std::ifstream in(path);

    if (!in) {
        throw std::runtime_error("cannot open pubkeys file: " + path);
    }

    std::string s{
        std::istreambuf_iterator<char>(in),
        std::istreambuf_iterator<char>()
    };

    std::vector<std::string> quoted;

    for (size_t i = 0; i < s.size(); ) {
        if (s[i] != '"') {
            ++i;
            continue;
        }

        size_t j = i + 1;
        std::string val;

        while (j < s.size()) {
            char c = s[j++];

            if (c == '\\') {
                if (j < s.size()) {
                    val.push_back(s[j++]);
                }

                continue;
            }

            if (c == '"') {
                break;
            }

            val.push_back(c);
        }

        quoted.push_back(val);
        i = j;
    }

    std::map<std::string, std::array<uint8_t, 32>> out;

    for (size_t i = 0; i + 1 < quoted.size(); i += 2) {
        auto bytes = hex_to_bytes_flex(quoted[i + 1]);

        if (bytes.size() == 32) {
            std::array<uint8_t, 32> pk{};
            std::memcpy(pk.data(), bytes.data(), 32);
            out[quoted[i]] = pk;
        }
    }

    return out;
}

bool verify_signature(
    const std::vector<uint8_t>& data,
    const std::array<uint8_t, 64>& sig,
    const std::array<uint8_t, 32>& pubkey
) {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519,
        nullptr,
        pubkey.data(),
        pubkey.size()
    );

    if (!pkey) {
        return false;
    }

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();

    if (!mdctx) {
        EVP_PKEY_free(pkey);
        return false;
    }

    int ret = 0;

    if (EVP_DigestVerifyInit(mdctx, nullptr, nullptr, nullptr, pkey) == 1) {
        ret = EVP_DigestVerify(
            mdctx,
            sig.data(),
            sig.size(),
            data.data(),
            data.size()
        );
    }

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);

    return ret == 1;
}

// =============================================================
// Transcript helpers for bidder wire verification
// =============================================================

static inline void tr_append_bytes(
    std::vector<uint8_t>& tr,
    const void* p,
    size_t n
) {
    const uint8_t* b = reinterpret_cast<const uint8_t*>(p);
    tr.insert(tr.end(), b, b + n);
}

static inline uint64_t recv_u64_and_tr(int fd, std::vector<uint8_t>& tr) {
    uint64_t net = 0;
    recv_all(fd, &net, 8);
    tr_append_bytes(tr, &net, 8);

    return be64toh_u64(net);
}

static inline void recv_bytes_and_tr(
    int fd,
    void* out,
    size_t n,
    std::vector<uint8_t>& tr
) {
    recv_all(fd, out, n);
    tr_append_bytes(tr, out, n);
}

static inline std::string recv_lp_string_and_tr(
    int fd,
    std::vector<uint8_t>& tr
) {
    uint64_t len = recv_u64_and_tr(fd, tr);

    std::string s(len, '\0');

    if (len > 0) {
        recv_bytes_and_tr(fd, &s[0], len, tr);
    }

    return s;
}

// =============================================================
// BabyJub CCE verification through verifier_CCE.js.
// P1 verifies c1 commitment from onchain/bidders_info.json.
// =============================================================

static std::string json_extract_string_field(
    const std::string& json,
    const std::string& key
) {
    std::string pat = "\"" + key + "\"";

    size_t pos = json.find(pat);

    if (pos == std::string::npos) {
        return "";
    }

    pos = json.find(':', pos);

    if (pos == std::string::npos) {
        return "";
    }

    pos = json.find('"', pos);

    if (pos == std::string::npos) {
        return "";
    }

    size_t end = json.find('"', pos + 1);

    if (end == std::string::npos) {
        return "";
    }

    return json.substr(pos + 1, end - (pos + 1));
}

static std::string json_extract_nested_string_field(
    const std::string& json,
    const std::string& parentKey,
    const std::string& childKey
) {
    std::string ppat = "\"" + parentKey + "\"";

    size_t p = json.find(ppat);

    if (p == std::string::npos) {
        return "";
    }

    p = json.find('{', p);

    if (p == std::string::npos) {
        return "";
    }

    size_t pend = json.find('}', p);

    if (pend == std::string::npos) {
        return "";
    }

    std::string sub = json.substr(p, pend - p + 1);

    return json_extract_string_field(sub, childKey);
}

static std::string find_last_bidder_record_obj(
    const std::string& content,
    const std::string& bidder_name
) {
    std::string pat = "\"name\":\"" + bidder_name + "\"";

    size_t pos = content.rfind(pat);

    if (pos == std::string::npos) {
        return "";
    }

    size_t start = content.rfind('{', pos);

    if (start == std::string::npos) {
        return "";
    }

    int depth = 0;
    size_t end = std::string::npos;

    for (size_t i = start; i < content.size(); ++i) {
        if (content[i] == '{') {
            depth++;
        } else if (content[i] == '}') {
            depth--;

            if (depth == 0) {
                end = i;
                break;
            }
        }
    }

    if (end == std::string::npos) {
        return "";
    }

    return content.substr(start, end - start + 1);
}

static std::pair<std::string, std::string> load_babyjub_commitment_c1_xy_dec(
    const std::string& bidder_name
) {
    std::string path = "onchain/bidders_info.json";

    std::ifstream in(path);

    if (!in) {
        throw std::runtime_error("cannot open commitments: " + path);
    }

    std::string s{
        std::istreambuf_iterator<char>(in),
        std::istreambuf_iterator<char>()
    };

    std::string obj = find_last_bidder_record_obj(s, bidder_name);

    if (obj.empty()) {
        throw std::runtime_error(
            "bidder not found in bidders_info.json: " + bidder_name
        );
    }

    std::string c1x = json_extract_nested_string_field(obj, "c1", "x");
    std::string c1y = json_extract_nested_string_field(obj, "c1", "y");

    if (c1x.empty() || c1y.empty()) {
        throw std::runtime_error(
            "missing c1 in bidders_info.json record for " + bidder_name
        );
    }

    return {c1x, c1y};
}

static bool run_babyjub_verifier_js(
    const std::string& node_path,
    const std::string& verifier_path,
    const std::string& commitDomain,
    const std::string& cceDomain,
    const std::string& role,
    const std::string& name,
    const std::string& Cx_dec,
    const std::string& Cy_dec,
    uint64_t x_u64,
    const std::vector<uint8_t>& eph,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& tag,
    const std::vector<uint8_t>& ct,
    const std::string& Ax_dec,
    const std::string& Ay_dec,
    const std::string& z_dec,
    std::string* out_json = nullptr
) {
    std::string ephHex = bytes_to_hex(eph);
    std::string ivHex = bytes_to_hex(iv);
    std::string tagHex = bytes_to_hex(tag);
    std::string ctHex = bytes_to_hex(ct);

    std::string cmd;

    cmd += shell_escape_single_quotes(node_path);
    cmd += " ";
    cmd += shell_escape_single_quotes(verifier_path);
    cmd += " ";
    cmd += shell_escape_single_quotes(commitDomain);
    cmd += " ";
    cmd += shell_escape_single_quotes(cceDomain);
    cmd += " ";
    cmd += shell_escape_single_quotes(role);
    cmd += " ";
    cmd += shell_escape_single_quotes(name);
    cmd += " ";
    cmd += shell_escape_single_quotes(Cx_dec);
    cmd += " ";
    cmd += shell_escape_single_quotes(Cy_dec);
    cmd += " ";
    cmd += std::to_string(x_u64);
    cmd += " ";
    cmd += shell_escape_single_quotes(ephHex);
    cmd += " ";
    cmd += shell_escape_single_quotes(ivHex);
    cmd += " ";
    cmd += shell_escape_single_quotes(tagHex);
    cmd += " ";
    cmd += shell_escape_single_quotes(ctHex);
    cmd += " ";
    cmd += shell_escape_single_quotes(Ax_dec);
    cmd += " ";
    cmd += shell_escape_single_quotes(Ay_dec);
    cmd += " ";
    cmd += shell_escape_single_quotes(z_dec);

    FILE* fp = popen(cmd.c_str(), "r");

    if (!fp) {
        throw std::runtime_error("failed to run verifier_CCE.js; popen failed");
    }

    std::string output;
    char buf[4096];

    while (true) {
        size_t n = fread(buf, 1, sizeof(buf), fp);

        if (n > 0) {
            output.append(buf, buf + n);
        }

        if (n < sizeof(buf)) {
            break;
        }
    }

    int rc = pclose(fp);

    if (out_json) {
        *out_json = output;
    }

    return rc == 0;
}

// sending hash of permutation index vector to smart contract 
static void submit_perm_hash_to_contract(
    const std::string& node_path,
    const std::string& submit_hash_tool,
    const std::string& rpc_url,
    const std::string& contract_address,
    const std::string& eth_priv_file,
    uint64_t session_id,
    uint64_t dataset_kind,
    uint64_t party_id,
    const std::string& perm_hash_decimal_or_hex
) {
    if (contract_address.empty()) {
        throw std::runtime_error(
            "missing smart contract address; pass --perm-registry 0x..."
        );
    }

    if (eth_priv_file.empty()) {
        throw std::runtime_error(
            "missing ethereum private key file; pass --eth-priv keys/p0.eth.priv or keys/p1.eth.priv"
        );
    }

    std::string cmd;

    cmd += shell_escape_single_quotes(node_path);
    cmd += " ";
    cmd += shell_escape_single_quotes(submit_hash_tool);

    cmd += " --rpc ";
    cmd += shell_escape_single_quotes(rpc_url);

    cmd += " --contract ";
    cmd += shell_escape_single_quotes(contract_address);

    cmd += " --priv-file ";
    cmd += shell_escape_single_quotes(eth_priv_file);

    cmd += " --session-id ";
    cmd += std::to_string(session_id);

    cmd += " --dataset-kind ";
    cmd += std::to_string(dataset_kind);

    cmd += " --party-id ";
    cmd += std::to_string(party_id);

    cmd += " --hash ";
    cmd += shell_escape_single_quotes(perm_hash_decimal_or_hex);

    FILE* fp = popen(cmd.c_str(), "r");

    if (!fp) {
        throw std::runtime_error("failed to run submit_perm_hash.js");
    }

    std::string output;
    char buf[2048];

    while (fgets(buf, sizeof(buf), fp)) {
        output += buf;
    }

    int rc = pclose(fp);

    if (rc != 0) {
        throw std::runtime_error(
            "submit_perm_hash.js failed. Output:\n" + output
        );
    }

    std::cout << "on-chain permutation hash submit output:\n"
              << output << "\n";
}


static std::vector<uint64_t> apply_perm_1based_to_u64_vector(
    const std::vector<uint64_t>& values,
    const std::vector<uint64_t>& perm1based
) {
    if (values.size() != perm1based.size()) {
        throw std::runtime_error("apply_perm_1based_to_u64_vector: size mismatch");
    }

    std::vector<uint64_t> out;
    out.reserve(values.size());

    for (uint64_t idx1 : perm1based) {
        if (idx1 == 0 || idx1 > values.size()) {
            throw std::runtime_error("apply_perm_1based_to_u64_vector: invalid 1-based index");
        }
        out.push_back(values[static_cast<size_t>(idx1 - 1)]);
    }

    return out;
}

static void save_sorted_share_bids_hash_json(
    const std::string& path,
    const std::string& dataset_label,
    uint64_t n,
    const std::vector<uint64_t>& sorted_share_bids,
    const std::string& poseidon_hash_str
) {
    std::ofstream out(path);
    if (!out) {
        throw std::runtime_error("cannot write sorted share bids hash json file: " + path);
    }

    out << "{\n";
    out << "  \"dataset\": \"" << json_escape(dataset_label) << "\",\n";
    out << "  \"n\": " << n << ",\n";
    out << "  \"sorted_share_bid_vector_dec\": [";
    for (size_t i = 0; i < sorted_share_bids.size(); ++i) {
        if (i) out << ", ";
        out << "\"" << sorted_share_bids[i] << "\"";
    }
    out << "],\n";
    out << "  \"sorted_share_bid_vector_hash_poseidon\": \"" << json_escape(poseidon_hash_str) << "\"\n";
    out << "}\n";
}

static void submit_sorted_share_bids_hash_to_contract(
    const std::string& node_path,
    const std::string& submit_sorted_hash_tool,
    const std::string& rpc_url,
    const std::string& contract_address,
    const std::string& eth_priv_file,
    uint64_t session_id,
    uint64_t dataset_kind,
    uint64_t party_id,
    const std::string& sorted_share_bids_hash_decimal_or_hex
) {
    if (contract_address.empty()) {
        throw std::runtime_error(
            "missing smart contract address; pass --perm-registry 0x..."
        );
    }

    if (eth_priv_file.empty()) {
        throw std::runtime_error(
            "missing ethereum private key file; pass --eth-priv keys/p0.eth.priv or keys/p1.eth.priv"
        );
    }

    std::string cmd;
    cmd += shell_escape_single_quotes(node_path);
    cmd += " ";
    cmd += shell_escape_single_quotes(submit_sorted_hash_tool);
    cmd += " --rpc ";
    cmd += shell_escape_single_quotes(rpc_url);
    cmd += " --contract ";
    cmd += shell_escape_single_quotes(contract_address);
    cmd += " --priv-file ";
    cmd += shell_escape_single_quotes(eth_priv_file);
    cmd += " --session-id ";
    cmd += std::to_string(session_id);
    cmd += " --dataset-kind ";
    cmd += std::to_string(dataset_kind);
    cmd += " --party-id ";
    cmd += std::to_string(party_id);
    cmd += " --hash ";
    cmd += shell_escape_single_quotes(sorted_share_bids_hash_decimal_or_hex);

    FILE* fp = popen(cmd.c_str(), "r");
    if (!fp) {
        throw std::runtime_error("failed to run submit_sorted_share_bids_hash.js");
    }

    std::string output;
    char buf[2048];
    while (fgets(buf, sizeof(buf), fp)) {
        output += buf;
    }

    int rc = pclose(fp);
    if (rc != 0) {
        throw std::runtime_error(
            "submit_sorted_share_bids_hash.js failed. Output:\n" + output
        );
    }

    std::cout << "on-chain sorted share-bid vector hash submit output:\n"
              << output << "\n";
}


static void check_split_registry_compatibility_or_throw(
    const std::string& node_path,
    const std::string& checker_tool,
    const std::string& rpc_url,
    const std::string& contract_address
) {
    std::string cmd;
    cmd += shell_escape_single_quotes(node_path);
    cmd += " ";
    cmd += shell_escape_single_quotes(checker_tool);
    cmd += " --rpc ";
    cmd += shell_escape_single_quotes(rpc_url);
    cmd += " --contract ";
    cmd += shell_escape_single_quotes(contract_address);

    FILE* fp = popen(cmd.c_str(), "r");
    if (!fp) throw std::runtime_error("failed to run split registry compatibility checker");

    std::string output;
    char buf[2048];
    while (fgets(buf, sizeof(buf), fp)) output += buf;
    int rc = pclose(fp);
    if (rc != 0) {
        throw std::runtime_error(
            "split AuctionRegistry compatibility check failed before auction start.\n" + output
        );
    }
    std::cout << output;
}

static void submit_signed_dataset_vector_hashes_to_contract(
    const std::string& node_path,
    const std::string& submit_vector_hashes_tool,
    const std::string& rpc_url,
    const std::string& contract_address,
    const std::string& eth_priv_file,
    uint64_t session_id,
    uint64_t dataset_kind,
    uint64_t party_id,
    const std::string& signed_payload_path
) {
    if (contract_address.empty()) {
        throw std::runtime_error(
            "missing smart contract address; pass --perm-registry 0x..."
        );
    }

    if (eth_priv_file.empty()) {
        throw std::runtime_error(
            "missing ethereum private key file; pass --eth-priv keys/p0.eth.priv or keys/p1.eth.priv"
        );
    }

    std::string cmd;

    cmd += shell_escape_single_quotes(node_path);
    cmd += " ";
    cmd += shell_escape_single_quotes(submit_vector_hashes_tool);

    cmd += " --rpc ";
    cmd += shell_escape_single_quotes(rpc_url);

    cmd += " --contract ";
    cmd += shell_escape_single_quotes(contract_address);

    cmd += " --priv-file ";
    cmd += shell_escape_single_quotes(eth_priv_file);

    cmd += " --session-id ";
    cmd += std::to_string(session_id);

    cmd += " --dataset-kind ";
    cmd += std::to_string(dataset_kind);

    cmd += " --party-id ";
    cmd += std::to_string(party_id);

    cmd += " --payload ";
    cmd += shell_escape_single_quotes(signed_payload_path);

    FILE* fp = popen(cmd.c_str(), "r");

    if (!fp) {
        throw std::runtime_error("failed to run submit_split_dataset_signature_hashes.js");
    }

    std::string output;
    char buf[2048];

    while (fgets(buf, sizeof(buf), fp)) {
        output += buf;
    }

    int rc = pclose(fp);

    if (rc != 0) {
        throw std::runtime_error(
            "submit_split_dataset_signature_hashes.js failed. Output:\n" + output
        );
    }

    std::cout << "on-chain split dataset-signature hashes submit output:\n"
              << output << "\n";
}

static std::string join_u64_csv_local(const std::vector<uint64_t>& values) {
    std::ostringstream os;

    for (size_t i = 0; i < values.size(); ++i) {
        if (i) {
            os << ",";
        }

        os << values[i];
    }

    return os.str();
}

static void submit_auction_result_to_contract(
    const std::string& node_path,
    const std::string& submit_result_tool,
    const std::string& rpc_url,
    const std::string& contract_address,
    const std::string& eth_priv_file,
    uint64_t session_id,
    uint64_t party_id,
    uint64_t K,
    uint64_t Pb,
    uint64_t Ps,
    const std::vector<uint64_t>& winner_buyer_ids,
    const std::vector<uint64_t>& winner_seller_ids
) {
    if (contract_address.empty()) {
        throw std::runtime_error(
            "missing smart contract address; pass --perm-registry 0x..."
        );
    }

    if (eth_priv_file.empty()) {
        throw std::runtime_error(
            "missing ethereum private key file; pass --eth-priv keys/p0.eth.priv or keys/p1.eth.priv"
        );
    }

    std::string cmd;

    cmd += shell_escape_single_quotes(node_path);
    cmd += " ";
    cmd += shell_escape_single_quotes(submit_result_tool);

    cmd += " --rpc ";
    cmd += shell_escape_single_quotes(rpc_url);

    cmd += " --contract ";
    cmd += shell_escape_single_quotes(contract_address);

    cmd += " --priv-file ";
    cmd += shell_escape_single_quotes(eth_priv_file);

    cmd += " --session-id ";
    cmd += std::to_string(session_id);

    cmd += " --party-id ";
    cmd += std::to_string(party_id);

    cmd += " --K ";
    cmd += std::to_string(K);

    cmd += " --Pb ";
    cmd += std::to_string(Pb);

    cmd += " --Ps ";
    cmd += std::to_string(Ps);

    cmd += " --winner-buyers ";
    cmd += shell_escape_single_quotes(join_u64_csv_local(winner_buyer_ids));

    cmd += " --winner-sellers ";
    cmd += shell_escape_single_quotes(join_u64_csv_local(winner_seller_ids));


    FILE* fp = popen(cmd.c_str(), "r");

    if (!fp) {
        throw std::runtime_error("failed to run submit_auction_result.js");
    }

    std::string output;
    char buf[2048];

    while (fgets(buf, sizeof(buf), fp)) {
        output += buf;
    }

    int rc = pclose(fp);

    if (rc != 0) {
        throw std::runtime_error(
            "submit_auction_result.js failed. Output:\n" + output
        );
    }

    std::cout << "on-chain auction result submit output:\n"
              << output << "\n";
}



static std::vector<uint64_t> pad_winner_ids_for_poseidon(
    const std::vector<uint64_t>& values,
    uint64_t nbuyers,
    uint64_t nsellers
) {
    const uint64_t l = std::min(nbuyers, nsellers);
    const uint64_t w = (l == 0) ? 0 : (l - 1);

    if (values.size() > w) {
        throw std::runtime_error(
            "winner IDs vector is longer than W=min(nbuyers,nsellers)-1"
        );
    }

    std::vector<uint64_t> out = values;
    while (out.size() < w) {
        out.push_back(0);
    }

    return out;
}

static void submit_winner_ids_poseidon_hashes_to_contract(
    const std::string& node_path,
    const std::string& submit_winner_hashes_tool,
    const std::string& rpc_url,
    const std::string& contract_address,
    const std::string& eth_priv_file,
    uint64_t session_id,
    uint64_t party_id,
    const std::vector<uint64_t>& winner_buyer_ids,
    const std::vector<uint64_t>& winner_seller_ids
) {
    if (contract_address.empty()) {
        throw std::runtime_error(
            "missing smart contract address; pass --perm-registry 0x..."
        );
    }

    if (eth_priv_file.empty()) {
        throw std::runtime_error(
            "missing ethereum private key file; pass --eth-priv keys/p0.eth.priv or keys/p1.eth.priv"
        );
    }

    std::string cmd;

    cmd += shell_escape_single_quotes(node_path);
    cmd += " ";
    cmd += shell_escape_single_quotes(submit_winner_hashes_tool);

    cmd += " --rpc ";
    cmd += shell_escape_single_quotes(rpc_url);

    cmd += " --contract ";
    cmd += shell_escape_single_quotes(contract_address);

    cmd += " --priv-file ";
    cmd += shell_escape_single_quotes(eth_priv_file);

    cmd += " --session-id ";
    cmd += std::to_string(session_id);

    cmd += " --party-id ";
    cmd += std::to_string(party_id);

    cmd += " --winner-buyers ";
    cmd += shell_escape_single_quotes(join_u64_csv_local(winner_buyer_ids));

    cmd += " --winner-sellers ";
    cmd += shell_escape_single_quotes(join_u64_csv_local(winner_seller_ids));

    FILE* fp = popen(cmd.c_str(), "r");

    if (!fp) {
        throw std::runtime_error("failed to run submit_winner_ids_poseidon_hashes.js");
    }

    std::string output;
    char buf[2048];

    while (fgets(buf, sizeof(buf), fp)) {
        output += buf;
    }

    int rc = pclose(fp);

    if (rc != 0) {
        throw std::runtime_error(
            "submit_winner_ids_poseidon_hashes.js failed. Output:\n" + output
        );
    }

    std::cout << "on-chain winner ID Poseidon hashes submit output:\n"
              << output << "\n";
}

// =============================================================
// Bidder Ethereum CCE packet signature verification (NO share_x)
// =============================================================

static bool run_cce_packet_sig_verifier_js(
    const std::string& node_path,
    const std::string& verifier_script,
    const std::string& rpc_url,
    const std::string& registry_contract_address,
    uint64_t session_id,
    uint64_t party_id,
    const std::string& role,
    const std::string& name,
    uint64_t bidder_id,
    const std::string& commit_domain,
    const std::string& cce_domain,
    const std::string& Cx_dec,
    const std::string& Cy_dec,
    const std::vector<uint8_t>& eph,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& tag,
    const std::vector<uint8_t>& ct,
    const std::string& Ax_dec,
    const std::string& Ay_dec,
    const std::string& z_dec,
    const std::string& bidder_eth_sig_hex,
    std::string* out_json = nullptr
) {
    std::string cmd;
    cmd += shell_escape_single_quotes(node_path);
    cmd += " ";
    cmd += shell_escape_single_quotes(verifier_script);
    cmd += " --rpc ";
    cmd += shell_escape_single_quotes(rpc_url);
    cmd += " --contract ";
    cmd += shell_escape_single_quotes(registry_contract_address);
    cmd += " --session-id ";
    cmd += std::to_string(session_id);
    cmd += " --party-id ";
    cmd += std::to_string(party_id);
    cmd += " --role ";
    cmd += shell_escape_single_quotes(role);
    cmd += " --name ";
    cmd += shell_escape_single_quotes(name);
    cmd += " --bidder-id ";
    cmd += std::to_string(bidder_id);
    cmd += " --commit-domain ";
    cmd += shell_escape_single_quotes(commit_domain);
    cmd += " --cce-domain ";
    cmd += shell_escape_single_quotes(cce_domain);
    cmd += " --Cx ";
    cmd += shell_escape_single_quotes(Cx_dec);
    cmd += " --Cy ";
    cmd += shell_escape_single_quotes(Cy_dec);
    cmd += " --eph ";
    cmd += shell_escape_single_quotes(bytes_to_hex(eph));
    cmd += " --iv ";
    cmd += shell_escape_single_quotes(bytes_to_hex(iv));
    cmd += " --tag ";
    cmd += shell_escape_single_quotes(bytes_to_hex(tag));
    cmd += " --ct ";
    cmd += shell_escape_single_quotes(bytes_to_hex(ct));
    cmd += " --Ax ";
    cmd += shell_escape_single_quotes(Ax_dec);
    cmd += " --Ay ";
    cmd += shell_escape_single_quotes(Ay_dec);
    cmd += " --z ";
    cmd += shell_escape_single_quotes(z_dec);
    cmd += " --signature ";
    cmd += shell_escape_single_quotes(bidder_eth_sig_hex);

    FILE* fp = popen(cmd.c_str(), "r");
    if (!fp) {
        throw std::runtime_error("failed to run verify_cce_packet_sig.js");
    }

    std::string output;
    char buf[4096];
    while (fgets(buf, sizeof(buf), fp)) {
        output += buf;
    }

    int rc = pclose(fp);
    if (out_json) {
        *out_json = output;
    }
    return rc == 0;
}

// =============================================================
// Poseidon script helper for local debug JSON.
// This is only for debugging output; proof payload uses JS helper.
// =============================================================

static std::string compute_poseidon_hash_js(
    const std::string& node_path,
    const std::string& script_path,
    const std::vector<uint64_t>& perm
) {
    std::string cmd =
        shell_escape_single_quotes(node_path) +
        " " +
        shell_escape_single_quotes(script_path);

    for (uint64_t x : perm) {
        cmd += " " + std::to_string(x);
    }

    FILE* fp = popen(cmd.c_str(), "r");

    if (!fp) {
        throw std::runtime_error("failed to run poseidon script; popen failed");
    }

    std::string output;
    char buf[256];

    while (fgets(buf, sizeof(buf), fp) != nullptr) {
        output += buf;
    }

    int rc = pclose(fp);

    if (rc != 0) {
        throw std::runtime_error("Poseidon script returned non-zero exit code");
    }

    while (!output.empty() &&
           (output.back() == '\n' ||
            output.back() == '\r' ||
            output.back() == '\t' ||
            output.back() == ' ')) {
        output.pop_back();
    }

    return output;
}

static void save_perm_json(
    const std::string& path,
    const std::string& dataset_label,
    uint64_t n,
    const std::vector<uint64_t>& perm1based,
    const std::string& poseidon_hash_str
) {
    std::ofstream out(path);

    if (!out) {
        throw std::runtime_error("cannot write json file: " + path);
    }

    out << "{\n";
    out << "  \"dataset\": \"" << json_escape(dataset_label) << "\",\n";
    out << "  \"n\": " << n << ",\n";
    out << "  \"perm_1based\": [";

    for (size_t i = 0; i < perm1based.size(); ++i) {
        out << perm1based[i];

        if (i + 1 != perm1based.size()) {
            out << ", ";
        }
    }

    out << "],\n";
    out << "  \"perm_hash_poseidon\": \"" << json_escape(poseidon_hash_str) << "\"\n";
    out << "}\n";
}

// =============================================================
// MPC shuffle/sort structs and helpers
// =============================================================

std::vector<uint64_t> apply_shuffle_masks(
    const std::vector<uint64_t>& c_share,
    const std::vector<uint64_t>& a_share,
    const std::vector<uint64_t>& b_share,
    const std::vector<uint64_t>& e_total,
    const std::vector<uint64_t>& f_total,
    uint64_t n,
    bool include_public_term
) {
    std::vector<uint64_t> result = c_share;

    for (uint64_t col = 0; col < n; ++col) {
        uint64_t acc = result[col];

        for (uint64_t row = 0; row < n; ++row) {
            uint64_t offset = row * n + col;

            uint64_t eb = mul_wrap(e_total[row], b_share[offset]);
            uint64_t af = mul_wrap(a_share[row], f_total[offset]);

            uint64_t contribution = add_wrap(eb, af);

            if (include_public_term) {
                uint64_t ef = mul_wrap(e_total[row], f_total[offset]);
                contribution = add_wrap(contribution, ef);
            }

            acc = add_wrap(acc, contribution);
        }

        result[col] = acc;
    }

    return result;
}

std::vector<std::pair<uint64_t, uint64_t>> build_bubble_schedule(uint64_t n) {
    std::vector<std::pair<uint64_t, uint64_t>> schedule;
    schedule.reserve(n * (n - 1) / 2);

    for (uint64_t pass = 0; pass < n - 1; ++pass) {
        for (uint64_t i = 0; i < n - 1 - pass; ++i) {
            schedule.emplace_back(i, i + 1);
        }
    }

    return schedule;
}

struct BeaverShare {
    uint64_t a;
    uint64_t b;
    uint64_t c;
};

struct CompareTriples {
    BeaverShare t2;
    BeaverShare bid_f_y_minus_x;
    BeaverShare bid_f_x_minus_y;
    BeaverShare id_f_y_minus_x;
    BeaverShare id_f_x_minus_y;
};

struct ClearingTriples {
    BeaverShare cond1_t2;
    BeaverShare ge_forward_t2;
    BeaverShare ge_reverse_t2;
    BeaverShare eq_and;
    BeaverShare final_and;
    BeaverShare k_update;
};

enum class DatasetKind : uint64_t {
    Buyers = 0,
    Sellers = 1
};

struct RunConfig {
    DatasetKind kind;
    bool descending;
    std::string label;
    std::vector<std::string> names;
    std::vector<std::string> roles;
    std::vector<uint64_t> bid_shares;
    std::vector<uint64_t> id_shares;
};

struct SortedResult {
    RunConfig run;

    std::vector<uint64_t> bid_shares;
    std::vector<uint64_t> id_shares;

    std::vector<uint64_t> peer_bid_shares;
    std::vector<uint64_t> peer_id_shares;

    std::vector<int64_t> id_totals;
    std::vector<uint64_t> perm_index_1based;
};

int64_t to_signed(uint64_t v) {
    return static_cast<int64_t>(v);
}

struct BidderRecord {
    std::string role;
    uint64_t bid_share = 0;
    uint64_t id_share = 0;
};

struct GoodBidders {
    std::map<std::string, BidderRecord> by_name;
    std::vector<std::string> order;
};


static std::vector<std::string> names_from_good_bidders(
    const std::optional<GoodBidders>& gb
) {
    if (!gb.has_value()) return {};
    return gb->order;
}

static bool string_vector_contains(
    const std::vector<std::string>& values,
    const std::string& target
) {
    return std::find(values.begin(), values.end(), target) != values.end();
}

static void align_good_bidders_to_p0_canonical_order(
    std::optional<GoodBidders>& local,
    const std::vector<std::string>& p0_names,
    const std::vector<std::string>& p1_names,
    const std::string& party_label,
    const std::string& dataset_label
) {
    if (!local.has_value()) return;

    GoodBidders aligned;

    // P0's order is the deterministic canonical order.
    // If one auctioneer rejects a bidder, both sides exclude it before MPC.
    for (const auto& name : p0_names) {
        if (!string_vector_contains(p1_names, name)) {
            continue;
        }
        auto it = local->by_name.find(name);
        if (it == local->by_name.end()) {
            continue;
        }
        aligned.by_name[name] = it->second;
        aligned.order.push_back(name);
    }

    for (const auto& name : local->order) {
        if (!aligned.by_name.count(name)) {
            std::cout << party_label << ": excluding " << dataset_label
                      << " bidder '" << name
                      << "' from MPC sorting because it is not valid for both P0 and P1\n";
        }
    }

    std::cout << party_label << ": aligned " << dataset_label
              << " bidders for MPC: local=" << local->order.size()
              << ", P0-valid=" << p0_names.size()
              << ", P1-valid=" << p1_names.size()
              << ", intersection=" << aligned.order.size() << "\n";

    local = aligned;
}

static std::string find_revealed_randomness_or_empty(
    const std::vector<RevealedRandomnessRec>& recs,
    const std::string& role,
    const std::string& name
) {
    for (const auto& r : recs) {
        if (r.role == role && r.name == name) {
            return r.r_dec;
        }
    }

    return "";
}

static void dump_share_bids_dataset_json(
    std::ofstream& out,
    const char* key,
    const std::optional<GoodBidders>& gb
) {
    out << "    \"" << key << "\": ";

    if (!gb.has_value()) {
        out << "null";
        return;
    }

    const auto& b = gb.value();

    out << "{\n";
    out << "      \"count\": " << static_cast<uint64_t>(b.order.size()) << ",\n";
    out << "      \"records\": [\n";

    for (size_t i = 0; i < b.order.size(); ++i) {
        const std::string& nm = b.order[i];
        const auto& rec = b.by_name.at(nm);

        out << "        {\"role\":\"" << json_escape(rec.role)
            << "\",\"name\":\"" << json_escape(nm)
            << "\",\"bid_share\":" << rec.bid_share
            << ",\"bid_share_dec\":\"" << rec.bid_share << "\""
            << ",\"id_share\":" << rec.id_share
            << ",\"id_share_dec\":\"" << rec.id_share << "\"}"
            << (i + 1 == b.order.size() ? "\n" : ",\n");
    }

    out << "      ]\n";
    out << "    }";
}

static void save_revealed_randomness_json(
    const std::string& path,
    const std::string& who,
    uint64_t which,
    const std::vector<RevealedRandomnessRec>& recs,
    const std::optional<GoodBidders>& buyers,
    const std::optional<GoodBidders>& sellers
) {
    ensure_parent_dir(path);

    std::ofstream out(path);

    if (!out) {
        throw std::runtime_error("cannot write reveal json: " + path);
    }

    out << "{\n";
    out << "  \"ts_ms\": " << now_ms_epoch() << ",\n";
    out << "  \"who\": \"" << json_escape(who) << "\",\n";
    out << "  \"which\": " << which << ",\n";
    out << "  \"count\": " << static_cast<uint64_t>(recs.size()) << ",\n";
    out << "  \"records\": [\n";

    for (size_t i = 0; i < recs.size(); ++i) {
        const auto& r = recs[i];

        out << "    {\"role\":\"" << json_escape(r.role)
            << "\",\"name\":\"" << json_escape(r.name)
            << "\",\"id\":" << r.full_id
            << ",\"r_dec\":\"" << json_escape(r.r_dec) << "\"}"
            << (i + 1 == recs.size() ? "\n" : ",\n");
    }

    out << "  ],\n";
    out << "  \"share_bids\": {\n";
    dump_share_bids_dataset_json(out, "buyers", buyers);
    out << ",\n";
    dump_share_bids_dataset_json(out, "sellers", sellers);
    out << "\n";
    out << "  }\n";
    out << "}\n";
}

// =============================================================
// Local JSON dump of P1 received shares
// =============================================================

static void save_sharebids_p1_json(
    const std::string& path,
    const std::optional<GoodBidders>& buyers,
    const std::optional<GoodBidders>& sellers
) {
    ensure_parent_dir(path);

    std::ofstream out(path);

    if (!out) {
        throw std::runtime_error("cannot write sharebids json: " + path);
    }

    auto dump_dataset = [&](const char* key, const std::optional<GoodBidders>& gb) {
        out << "  \"" << key << "\": ";

        if (!gb.has_value()) {
            out << "null";
            return;
        }

        const auto& b = gb.value();

        out << "{\n";
        out << "    \"count\": " << static_cast<uint64_t>(b.order.size()) << ",\n";
        out << "    \"records\": [\n";

        for (size_t i = 0; i < b.order.size(); ++i) {
            const std::string& nm = b.order[i];
            const auto& rec = b.by_name.at(nm);

            out << "      {\"role\":\"" << json_escape(rec.role)
                << "\",\"name\":\"" << json_escape(nm)
                << "\",\"bid_share\":" << rec.bid_share
                << ",\"id_share\":" << rec.id_share
                << "}";

            out << (i + 1 == b.order.size() ? "\n" : ",\n");
        }

        out << "    ]\n";
        out << "  }";
    };

    out << "{\n";
    out << "  \"ts_ms\": " << now_ms_epoch() << ",\n";
    out << "  \"who\": \"p1\",\n";

    dump_dataset("buyers", buyers);
    out << ",\n";
    dump_dataset("sellers", sellers);
    out << "\n";

    out << "}\n";
}

// =============================================================
// Compute permutation from reconstructed IDs.
// perm[k] = original index, 1-based, of ID now at sorted position k.
// =============================================================

static std::vector<uint64_t> compute_perm_from_ids(
    const std::vector<int64_t>& original_ids,
    const std::vector<int64_t>& sorted_ids
) {
    std::map<int64_t, uint64_t> pos;

    for (uint64_t i = 0; i < original_ids.size(); ++i) {
        int64_t id = original_ids[i];

        if (pos.count(id)) {
            throw std::runtime_error("Duplicate ID detected; permutation is ambiguous");
        }

        pos[id] = i + 1;
    }

    std::vector<uint64_t> perm(sorted_ids.size());

    for (uint64_t k = 0; k < sorted_ids.size(); ++k) {
        int64_t id = sorted_ids[k];

        auto it = pos.find(id);

        if (it == pos.end()) {
            throw std::runtime_error("Sorted ID not found in original IDs; inconsistent permutation");
        }

        perm[k] = it->second;
    }

    return perm;
}



static bool json_bool_field_local(
    const std::string& json,
    const std::string& key,
    bool* present = nullptr
) {
    if (present) *present = false;
    const std::string pat = "\"" + key + "\"";
    const size_t p = json.find(pat);
    if (p == std::string::npos) return false;
    const size_t colon = json.find(':', p + pat.size());
    if (colon == std::string::npos) return false;

    size_t value = colon + 1;
    while (value < json.size() && std::isspace(static_cast<unsigned char>(json[value]))) {
        ++value;
    }
    if (json.compare(value, 4, "true") == 0) {
        if (present) *present = true;
        return true;
    }
    if (json.compare(value, 5, "false") == 0) {
        if (present) *present = true;
        return false;
    }
    return false;
}

static bool run_sigma_cce_local_verifier_js(
    const std::string& node_path,
    const std::string& verifier_script,
    const std::string& rpc_url,
    const std::string& registry_contract_address,
    const std::string& sigma_proof_json,
    const std::string& bidder_eth_sig_hex,
    bool* signature_ok,
    bool* proof_ok,
    std::string* out_json = nullptr
) {
    if (signature_ok) *signature_ok = false;
    if (proof_ok) *proof_ok = false;

    std::string cmd;
    cmd += shell_escape_single_quotes(node_path);
    cmd += " ";
    cmd += shell_escape_single_quotes(verifier_script);
    cmd += " --rpc ";
    cmd += shell_escape_single_quotes(rpc_url);
    cmd += " --contract ";
    cmd += shell_escape_single_quotes(registry_contract_address);
    cmd += " --sigma-proof-json ";
    cmd += shell_escape_single_quotes(sigma_proof_json);
    cmd += " --signature ";
    cmd += shell_escape_single_quotes(bidder_eth_sig_hex);

    FILE* fp = popen(cmd.c_str(), "r");
    if (!fp) {
        throw std::runtime_error("failed to run verify_sigma_cce_local.js");
    }

    std::string output;
    char buf[4096];
    while (fgets(buf, sizeof(buf), fp)) {
        output += buf;
    }
    const int rc = pclose(fp);

    bool signature_present = false;
    bool proof_present = false;
    const bool parsed_signature_ok = json_bool_field_local(output, "signatureOk", &signature_present);
    const bool parsed_proof_ok = json_bool_field_local(output, "proofOk", &proof_present);

    // Some verifier versions return exit status 1 for a cryptographically invalid
    // proof. That is a normal verification result, not a process failure. Accept
    // any well-formed JSON result containing both fields; reserve exceptions for
    // crashes, syntax errors, missing output, or malformed output.
    if (!signature_present || !proof_present) {
        throw std::runtime_error(
            "verify_sigma_cce_local.js did not return signatureOk/proofOk" +
            std::string(rc != 0 ? " (non-zero exit status)" : "") +
            ". Output:\n" + output
        );
    }

    if (out_json) *out_json = output;
    if (signature_ok) *signature_ok = parsed_signature_ok;
    if (proof_ok) *proof_ok = parsed_proof_ok;
    return true;
}

static void report_invalid_cce_dispute_to_contract(
    const std::string& node_path,
    const std::string& tool_path,
    const std::string& rpc_url,
    const std::string& contract_address,
    const std::string& eth_priv_file,
    uint64_t session_id,
    uint64_t party_id,
    const std::string& role,
    const std::string& name,
    uint64_t bidder_id,
    const std::string& commit_domain,
    const std::string& cce_domain,
    const std::string& c0x,
    const std::string& c0y,
    const std::string& c1x,
    const std::string& c1y,
    const std::vector<uint8_t>& eph,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& tag,
    const std::vector<uint8_t>& ct,
    const std::string& Ax,
    const std::string& Ay,
    const std::string& z,
    const std::string& bidder_eth_sig_hex,
    const std::string& commitment_eth_sig_hex,
    const std::string& zk_proof_json,
    const std::string& zk_public_signals_json
) {
    if (contract_address.empty()) {
        throw std::runtime_error("missing smart contract address; pass --perm-registry 0x...");
    }

    if (eth_priv_file.empty()) {
        throw std::runtime_error("missing ethereum private key file; pass --eth-priv keys/p0.eth.priv or keys/p1.eth.priv");
    }

    if (bidder_eth_sig_hex.empty()) {
        throw std::runtime_error("missing bidder Ethereum signature for CCE dispute");
    }

    if (commitment_eth_sig_hex.empty()) {
        throw std::runtime_error("missing bidder commitment Ethereum signature for CCE dispute");
    }

    if (zk_proof_json.empty()) {
        throw std::runtime_error("missing Sigma Fiat-Shamir CCE packet JSON for dispute");
    }

    std::lock_guard<std::mutex> lk(g_onchain_tx_mutex);

    std::string cmd;
    cmd += shell_escape_single_quotes(node_path);
    cmd += " ";
    cmd += shell_escape_single_quotes(tool_path);
    cmd += " --rpc ";
    cmd += shell_escape_single_quotes(rpc_url);
    cmd += " --contract ";
    cmd += shell_escape_single_quotes(contract_address);
    cmd += " --priv-file ";
    cmd += shell_escape_single_quotes(eth_priv_file);
    cmd += " --session-id ";
    cmd += std::to_string(session_id);
    cmd += " --party-id ";
    cmd += std::to_string(party_id);
    cmd += " --role ";
    cmd += shell_escape_single_quotes(role);
    cmd += " --name ";
    cmd += shell_escape_single_quotes(name);
    cmd += " --bidder-id ";
    cmd += std::to_string(bidder_id);
    cmd += " --commit-domain ";
    cmd += shell_escape_single_quotes(commit_domain);
    cmd += " --cce-domain ";
    cmd += shell_escape_single_quotes(cce_domain);
    cmd += " --c0x ";
    cmd += shell_escape_single_quotes(c0x);
    cmd += " --c0y ";
    cmd += shell_escape_single_quotes(c0y);
    cmd += " --c1x ";
    cmd += shell_escape_single_quotes(c1x);
    cmd += " --c1y ";
    cmd += shell_escape_single_quotes(c1y);
    cmd += " --sigma-proof-json ";
    cmd += shell_escape_single_quotes(zk_proof_json);
    cmd += " --bidder-eth-sig ";
    cmd += shell_escape_single_quotes(bidder_eth_sig_hex);
    cmd += " --commitment-sig ";
    cmd += shell_escape_single_quotes(commitment_eth_sig_hex);

    FILE* fp = popen(cmd.c_str(), "r");
    if (!fp) {
        throw std::runtime_error("failed to run no-share CCE dispute tool");
    }

    std::string output;
    char buf[2048];
    while (fgets(buf, sizeof(buf), fp)) {
        output += buf;
    }

    int rc = pclose(fp);
    if (rc != 0) {
        throw std::runtime_error("no-share CCE dispute tool failed. Output:\n" + output);
    }

    std::cout << "P1: no-share CCE dispute evidence output:\n"
              << output << "\n";
}





static std::string read_onchain_commitment_root(
    const std::string& node_path,
    const std::string& tool_path,
    const std::string& rpc_url,
    const std::string& contract_address,
    uint64_t session_id,
    const std::string& role,
    uint64_t party_id
) {
    std::string cmd;
    cmd += shell_escape_single_quotes(node_path);
    cmd += " ";
    cmd += shell_escape_single_quotes(tool_path);
    cmd += " --rpc ";
    cmd += shell_escape_single_quotes(rpc_url);
    cmd += " --contract ";
    cmd += shell_escape_single_quotes(contract_address);
    cmd += " --session-id ";
    cmd += std::to_string(session_id);
    cmd += " --party-id ";
    cmd += std::to_string(party_id);
    cmd += " --role ";
    cmd += shell_escape_single_quotes(role);
    cmd += " --party-id ";
    cmd += std::to_string(party_id);

    FILE* fp = popen(cmd.c_str(), "r");
    if (!fp) {
        throw std::runtime_error("failed to run read_commitment_root.js");
    }

    std::string output;
    char buf[2048];
    while (fgets(buf, sizeof(buf), fp)) {
        output += buf;
    }

    int rc = pclose(fp);
    if (rc != 0) {
        throw std::runtime_error("read_commitment_root.js failed. Output:\n" + output);
    }

    std::string key = "\"root\"";
    size_t k = output.find(key);
    if (k == std::string::npos) {
        throw std::runtime_error("read_commitment_root.js output missing root: " + output);
    }
    size_t colon = output.find(':', k);
    size_t q1 = output.find('"', colon + 1);
    size_t q2 = output.find('"', q1 + 1);
    if (colon == std::string::npos || q1 == std::string::npos || q2 == std::string::npos) {
        throw std::runtime_error("cannot parse on-chain root from output: " + output);
    }

    return output.substr(q1 + 1, q2 - q1 - 1);
}

static void report_invalid_merkle_proof_to_contract(
    const std::string& node_path,
    const std::string& tool_path,
    const std::string& rpc_url,
    const std::string& contract_address,
    const std::string& eth_priv_file,
    uint64_t session_id,
    uint64_t party_id,
    const std::string& role,
    const std::string& name,
    uint64_t bidder_id,
    const std::string& commit_domain,
    const std::string& c0x,
    const std::string& c0y,
    const std::string& c1x,
    const std::string& c1y,
    const std::string& bidderboss_receipt_signature,
    const std::string& evidence_root,
    const std::string& merkle_evidence_signature,
    const std::vector<std::string>& path_elements,
    const std::vector<uint64_t>& path_directions
) {
    if (contract_address.empty()) {
        throw std::runtime_error("missing smart contract address; pass --perm-registry 0x...");
    }

    if (eth_priv_file.empty()) {
        throw std::runtime_error("missing ethereum private key file; pass --eth-priv keys/p0.eth.priv or keys/p1.eth.priv");
    }

    std::lock_guard<std::mutex> lk(g_onchain_tx_mutex);

    std::string cmd;
    cmd += shell_escape_single_quotes(node_path);
    cmd += " ";
    cmd += shell_escape_single_quotes(tool_path);
    cmd += " --rpc ";
    cmd += shell_escape_single_quotes(rpc_url);
    cmd += " --contract ";
    cmd += shell_escape_single_quotes(contract_address);
    cmd += " --priv-file ";
    cmd += shell_escape_single_quotes(eth_priv_file);
    cmd += " --session-id ";
    cmd += std::to_string(session_id);
    cmd += " --party-id ";
    cmd += std::to_string(party_id);
    cmd += " --role ";
    cmd += shell_escape_single_quotes(role);
    cmd += " --name ";
    cmd += shell_escape_single_quotes(name);
    cmd += " --bidder-id ";
    cmd += std::to_string(bidder_id);
    cmd += " --commit-domain ";
    cmd += shell_escape_single_quotes(commit_domain);
    cmd += " --c0x ";
    cmd += shell_escape_single_quotes(c0x);
    cmd += " --c0y ";
    cmd += shell_escape_single_quotes(c0y);
    cmd += " --c1x ";
    cmd += shell_escape_single_quotes(c1x);
    cmd += " --c1y ";
    cmd += shell_escape_single_quotes(c1y);
    cmd += " --receipt-sig ";
    cmd += shell_escape_single_quotes(bidderboss_receipt_signature);
    cmd += " --evidence-root ";
    cmd += shell_escape_single_quotes(evidence_root);
    cmd += " --evidence-sig ";
    cmd += shell_escape_single_quotes(merkle_evidence_signature);
    cmd += " --path-elements ";
    cmd += shell_escape_single_quotes(join_string_csv(path_elements));
    cmd += " --path-directions ";
    cmd += shell_escape_single_quotes(join_u64_csv_values(path_directions));

    FILE* fp = popen(cmd.c_str(), "r");
    if (!fp) {
        throw std::runtime_error("failed to run submit_auctioneer_merkle_proof_check.js");
    }

    std::string output;
    char buf[2048];
    while (fgets(buf, sizeof(buf), fp)) {
        output += buf;
    }

    int rc = pclose(fp);
    if (rc != 0) {
        throw std::runtime_error("submit_auctioneer_merkle_proof_check.js failed. Output:\n" + output);
    }

    std::cout << "P1: on-chain Merkle proof dispute output:\n"
              << output << "\n";
}

static void finalize_cce_check_requests_to_contract(
    const std::string& node_path,
    const std::string& tool_path,
    const std::string& rpc_url,
    const std::string& contract_address,
    const std::string& eth_priv_file,
    uint64_t session_id,
    uint64_t party_id
) {
    if (contract_address.empty()) {
        throw std::runtime_error("missing smart contract address; pass --perm-registry 0x...");
    }

    if (eth_priv_file.empty()) {
        throw std::runtime_error("missing ethereum private key file; pass --eth-priv keys/p0.eth.priv or keys/p1.eth.priv");
    }

    std::lock_guard<std::mutex> lk(g_onchain_tx_mutex);

    std::string cmd;
    cmd += shell_escape_single_quotes(node_path);
    cmd += " ";
    cmd += shell_escape_single_quotes(tool_path);
    cmd += " --rpc ";
    cmd += shell_escape_single_quotes(rpc_url);
    cmd += " --contract ";
    cmd += shell_escape_single_quotes(contract_address);
    cmd += " --priv-file ";
    cmd += shell_escape_single_quotes(eth_priv_file);
    cmd += " --session-id ";
    cmd += std::to_string(session_id);
    cmd += " --party-id ";
    cmd += std::to_string(party_id);

    FILE* fp = popen(cmd.c_str(), "r");
    if (!fp) {
        throw std::runtime_error("failed to run finalize_cce_check_requests.js");
    }

    std::string output;
    char buf[2048];
    while (fgets(buf, sizeof(buf), fp)) {
        output += buf;
    }

    int rc = pclose(fp);
    if (rc != 0) {
        throw std::runtime_error("finalize_cce_check_requests.js failed. Output:\n" + output);
    }

    std::cout << "P1: on-chain CCE check finalization output:\n"
              << output << "\n";
}

// =============================================================
// Receive bidders on P1 ports
// =============================================================


static GoodBidders recv_bidders_decrypt(
    uint16_t port,
    uint64_t expected_n,
    const std::string& group_label,
    const ElgamalPriv& elg_priv,
    const std::string& pubkeys_path,
    const std::string& commitDomain,
    const std::string& cceDomain,
    const std::string& node_path,
    const std::string& verifier_path,
    const std::string& rpc_url,
    const std::string& registry_contract_address,
    const std::string& dispute_manager_contract_address,
    const std::string& eth_priv_file,
    const std::string& cce_dispute_tool,
    bool report_cce_disputes_onchain,
    const std::string& merkle_dispute_tool,
    const std::string& commitment_consistency_dispute_tool,
    const std::string& read_root_tool,
    bool report_merkle_disputes_onchain,
    bool force_false_cce_dispute_onchain,
    uint64_t force_false_cce_dispute_id,
    uint64_t session_id
) {
    auto pubkeys = load_pubkeys_json(pubkeys_path);
    const std::string dispute_contract_address = dispute_manager_contract_address.empty()
        ? registry_contract_address
        : dispute_manager_contract_address;
    int listener = create_listener(port);

    std::cout << "P1: waiting for " << expected_n << " " << group_label
              << " direct bidder packets + BidderBoss Merkle evidence on port " << port << "...\n";

    struct PartyWirePacket {
        std::vector<uint8_t> bid_eph, bid_iv, bid_tag, bid_ct;
        std::vector<uint8_t> id_eph, id_iv, id_tag, id_ct;
        std::string Ax, Ay, z;
        std::array<uint8_t,64> sig{};
        std::string bidder_eth_sig_hex;
        std::string commitment_eth_sig_hex;
        // Groth16 ZK-CCE proof JSON, produced by bidder and signed in bidder_eth_sig_hex.
        std::string zk_proof_json;
        std::string zk_public_signals_json;
        std::vector<uint8_t> sig_tr;
    };

    struct DirectRecord {
        bool present = false;
        std::string role, name, commit_domain;
        uint64_t bidder_id = 0;
        std::string c0x, c0y, c1x, c1y;
        PartyWirePacket packet;
    };

    struct EvidenceRecord {
        bool present = false;
        std::string role, name, commit_domain;
        uint64_t bidder_id = 0;
        std::string c0x, c0y, c1x, c1y;
        std::string receipt_hash, leaf_hash, receipt_signature, root, evidence_signature, vector_signature;
        std::vector<std::string> path_elements;
        std::vector<uint64_t> path_directions;
        PartyWirePacket boss_packet;
    };

    auto append_string_to_tr = [](std::vector<uint8_t>& tr, const std::string& value) {
        uint64_t net = htobe64_u64(static_cast<uint64_t>(value.size()));
        tr_append_bytes(tr, &net, 8);
        if (!value.empty()) {
            tr_append_bytes(tr, value.data(), value.size());
        }
    };

    auto key_for = [](const std::string& role, const std::string& name, uint64_t bidder_id) {
        return role + "|" + name + "|" + std::to_string(bidder_id);
    };

    auto write_packet_json = [&](std::ostringstream& js,
                                 const char* key,
                                 const std::string& role,
                                 const std::string& name,
                                 uint64_t bidder_id,
                                 const std::string& commit_domain,
                                 const std::string& c0x,
                                 const std::string& c0y,
                                 const std::string& c1x,
                                 const std::string& c1y,
                                 uint64_t share_x,
                                 const PartyWirePacket& pkt) {
        js << "  \"" << key << "\": {\n";
        js << "    \"partyId\": 1,\n";
        js << "    \"role\": \"" << json_escape(role) << "\",\n";
        js << "    \"bidderName\": \"" << json_escape(name) << "\",\n";
        js << "    \"bidderId\": " << bidder_id << ",\n";
        js << "    \"c0\": {\"x\":\"" << json_escape(c0x) << "\",\"y\":\"" << json_escape(c0y) << "\"},\n";
        js << "    \"c1\": {\"x\":\"" << json_escape(c1x) << "\",\"y\":\"" << json_escape(c1y) << "\"},\n";
        js << "    \"commitDomain\": \"" << json_escape(commit_domain) << "\",\n";
        js << "    \"cceDomain\": \"" << json_escape(cceDomain) << "\",\n";
        js << "    \"decryptedShareX\": " << share_x << ",\n";
        js << "    \"bidEphPub\": \"" << bytes_to_hex(pkt.bid_eph) << "\",\n";
        js << "    \"bidIv\": \"" << bytes_to_hex(pkt.bid_iv) << "\",\n";
        js << "    \"bidTag\": \"" << bytes_to_hex(pkt.bid_tag) << "\",\n";
        js << "    \"bidCiphertext\": \"" << bytes_to_hex(pkt.bid_ct) << "\",\n";
        js << "    \"proof\": {\"Ax\":\"" << json_escape(pkt.Ax) << "\",\"Ay\":\"" << json_escape(pkt.Ay) << "\",\"z\":\"" << json_escape(pkt.z) << "\"},\n";
        js << "    \"bidderSignature\": \"" << json_escape(pkt.bidder_eth_sig_hex) << "\",\n";
        js << "    \"commitmentSignature\": \"" << json_escape(pkt.commitment_eth_sig_hex) << "\"\n";
        js << "  }";
    };

    auto report_commitment_consistency_dispute_to_contract = [&](const DirectRecord& d,
                                                                 const EvidenceRecord& e,
                                                                 uint64_t direct_share_x,
                                                                 uint64_t boss_share_x) {
        if (registry_contract_address.empty()) {
            throw std::runtime_error("missing registry contract address; pass --perm-registry 0x...");
        }
        if (eth_priv_file.empty()) {
            throw std::runtime_error("missing ethereum private key file; pass --eth-priv keys/p1.eth.priv");
        }

        std::ostringstream js;
        js << "{\n";
        js << "  \"sessionId\": " << session_id << ",\n";
        js << "  \"partyId\": 1,\n";
        write_packet_json(js,
                          "auctioneerPacket",
                          d.role,
                          d.name,
                          d.bidder_id,
                          d.commit_domain.empty() ? commitDomain : d.commit_domain,
                          d.c0x,
                          d.c0y,
                          d.c1x,
                          d.c1y,
                          direct_share_x,
                          d.packet);
        js << ",\n";
        write_packet_json(js,
                          "bidderBossPacket",
                          e.role,
                          e.name,
                          e.bidder_id,
                          e.commit_domain.empty() ? commitDomain : e.commit_domain,
                          e.c0x,
                          e.c0y,
                          e.c1x,
                          e.c1y,
                          boss_share_x,
                          e.boss_packet);
        js << ",\n";
        js << "  \"bidderBossMerkleInput\": {\n";
        js << "    \"role\": \"" << json_escape(e.role) << "\",\n";
        js << "    \"name\": \"" << json_escape(e.name) << "\",\n";
        js << "    \"bidderId\": " << e.bidder_id << ",\n";
        js << "    \"commitDomain\": \"" << json_escape(e.commit_domain.empty() ? commitDomain : e.commit_domain) << "\",\n";
        js << "    \"c0\": {\"x\":\"" << json_escape(e.c0x) << "\",\"y\":\"" << json_escape(e.c0y) << "\"},\n";
        js << "    \"c1\": {\"x\":\"" << json_escape(e.c1x) << "\",\"y\":\"" << json_escape(e.c1y) << "\"},\n";
        js << "    \"receiptHash\": \"" << json_escape(e.receipt_hash) << "\",\n";
        js << "    \"leafHash\": \"" << json_escape(e.leaf_hash) << "\",\n";
        js << "    \"bidderBossReceiptSignature\": \"" << json_escape(e.receipt_signature) << "\",\n";
        js << "    \"bidderBossEvidenceSignature\": \"" << json_escape(e.evidence_signature) << "\"\n";
        js << "  },\n";
        js << "  \"bidderBossVectorRoot\": \"" << json_escape(e.root) << "\",\n";
        js << "  \"bidderBossVectorSignature\": \"" << json_escape(e.vector_signature) << "\",\n";
        js << "  \"pathElements\": [";
        for (size_t i = 0; i < e.path_elements.size(); ++i) {
            if (i) js << ",";
            js << "\"" << json_escape(e.path_elements[i]) << "\"";
        }
        js << "],\n";
        js << "  \"pathDirections\": [";
        for (size_t i = 0; i < e.path_directions.size(); ++i) {
            if (i) js << ",";
            js << (e.path_directions[i] ? "true" : "false");
        }
        js << "]\n";
        js << "}\n";

        std::string file = "onchain/commitment_consistency_dispute_p1_" +
                           d.role + "_" + std::to_string(d.bidder_id) + ".json";
        write_file_text(file, js.str());

        std::lock_guard<std::mutex> lk(g_onchain_tx_mutex);

        std::string cmd;
        cmd += shell_escape_single_quotes(node_path);
        cmd += " ";
        cmd += shell_escape_single_quotes(commitment_consistency_dispute_tool);
        cmd += " --rpc ";
        cmd += shell_escape_single_quotes(rpc_url);
        cmd += " --contract ";
        cmd += shell_escape_single_quotes(registry_contract_address);
        cmd += " --priv-file ";
        cmd += shell_escape_single_quotes(eth_priv_file);
        cmd += " --file ";
        cmd += shell_escape_single_quotes(file);

        const char* gas_env = std::getenv("COMMITMENT_CONSISTENCY_DISPUTE_GAS_LIMIT");
        if (gas_env && std::string(gas_env).size()) {
            cmd += " --gas-limit ";
            cmd += shell_escape_single_quotes(gas_env);
        }

        FILE* fp = popen(cmd.c_str(), "r");
        if (!fp) {
            throw std::runtime_error("failed to run commitment consistency dispute tool");
        }
        std::string output;
        char buf[2048];
        while (fgets(buf, sizeof(buf), fp)) {
            output += buf;
        }
        int rc = pclose(fp);
        if (rc != 0) {
            throw std::runtime_error("commitment consistency dispute tool failed. Output:\n" + output);
        }
        std::cout << "P1: on-chain commitment consistency dispute output:\n"
                  << output << "\n";
    };

    auto recv_party_wire_packet = [&](int sock,
                                      uint64_t packet_session_id,
                                      uint64_t packet_party_id,
                                      const std::string& role,
                                      const std::string& name,
                                      uint64_t bidder_id,
                                      const std::string& commit_domain,
                                      const std::string& selected_cx,
                                      const std::string& selected_cy) {
        PartyWirePacket p;
        append_string_to_tr(p.sig_tr, SIGNED_PACKET_DOMAIN);
        uint64_t session_be = htobe64_u64(packet_session_id);
        uint64_t party_be = htobe64_u64(packet_party_id);
        uint64_t bidder_be = htobe64_u64(bidder_id);
        tr_append_bytes(p.sig_tr, &session_be, 8);
        tr_append_bytes(p.sig_tr, &party_be, 8);
        append_string_to_tr(p.sig_tr, role);
        append_string_to_tr(p.sig_tr, name);
        tr_append_bytes(p.sig_tr, &bidder_be, 8);
        append_string_to_tr(p.sig_tr, commit_domain);
        append_string_to_tr(p.sig_tr, selected_cx);
        append_string_to_tr(p.sig_tr, selected_cy);

        p.bid_eph.assign(33, 0);
        p.bid_iv.assign(12, 0);
        p.bid_tag.assign(16, 0);
        recv_bytes_and_tr(sock, p.bid_eph.data(), 33, p.sig_tr);
        recv_bytes_and_tr(sock, p.bid_iv.data(), 12, p.sig_tr);
        recv_bytes_and_tr(sock, p.bid_tag.data(), 16, p.sig_tr);
        uint64_t bid_len = recv_u64_and_tr(sock, p.sig_tr);
        if (bid_len > MAX_RELAY_CIPHERTEXT_BYTES) {
            throw std::runtime_error("bid ciphertext too large/corrupted for " + name);
        }
        p.bid_ct.assign(static_cast<size_t>(bid_len), 0);
        if (bid_len) recv_bytes_and_tr(sock, p.bid_ct.data(), bid_len, p.sig_tr);

        p.id_eph.assign(33, 0);
        p.id_iv.assign(12, 0);
        p.id_tag.assign(16, 0);
        recv_bytes_and_tr(sock, p.id_eph.data(), 33, p.sig_tr);
        recv_bytes_and_tr(sock, p.id_iv.data(), 12, p.sig_tr);
        recv_bytes_and_tr(sock, p.id_tag.data(), 16, p.sig_tr);
        uint64_t id_len = recv_u64_and_tr(sock, p.sig_tr);
        if (id_len > MAX_RELAY_CIPHERTEXT_BYTES) {
            throw std::runtime_error("id ciphertext too large/corrupted for " + name);
        }
        p.id_ct.assign(static_cast<size_t>(id_len), 0);
        if (id_len) recv_bytes_and_tr(sock, p.id_ct.data(), id_len, p.sig_tr);

        p.Ax = recv_lp_string_and_tr(sock, p.sig_tr);
        p.Ay = recv_lp_string_and_tr(sock, p.sig_tr);
        p.z = recv_lp_string_and_tr(sock, p.sig_tr);
        recv_all(sock, p.sig.data(), 64);
        p.bidder_eth_sig_hex = recv_lp_string(sock);
        p.commitment_eth_sig_hex = recv_lp_string(sock);
        // The Sigma JSON contains AC/AU/AV and zx/zr/zk. Include it and the
        // Ethereum signatures in the Ed25519 transcript before verification.
        p.zk_proof_json = recv_lp_string(sock);
        p.zk_public_signals_json = recv_lp_string(sock);
        append_string_to_tr(p.sig_tr, p.zk_proof_json);
        append_string_to_tr(p.sig_tr, p.bidder_eth_sig_hex);
        append_string_to_tr(p.sig_tr, p.commitment_eth_sig_hex);
        return p;
    };

    std::map<std::string, DirectRecord> direct_records;
    std::map<std::string, EvidenceRecord> evidence_records;
    uint64_t direct_count = 0;
    uint64_t evidence_count = 0;

    while (direct_count < expected_n || evidence_count < expected_n) {
        int sock = accept(listener, nullptr, nullptr);
        if (sock < 0) {
            close(listener);
            throw std::runtime_error("accept bidder/evidence failed");
        }

        try {
            std::string magic = recv_lp_string(sock);
            uint64_t msg_session_id = recv_u64(sock);
            uint64_t msg_party_id = recv_u64(sock);
            if (msg_session_id != session_id) throw std::runtime_error("session mismatch in incoming packet");
            if (msg_party_id != 1) throw std::runtime_error("party mismatch in incoming packet");

            std::string role = recv_lp_string(sock);
            std::string name = recv_lp_string(sock);
            uint64_t bidder_id = recv_u64(sock);
            std::string relay_commit_domain = recv_lp_string(sock);
            std::string c0x = recv_lp_string(sock);
            std::string c0y = recv_lp_string(sock);
            std::string c1x = recv_lp_string(sock);
            std::string c1y = recv_lp_string(sock);
            std::string key = key_for(role, name, bidder_id);

            if (magic == DIRECT_MAGIC) {
                DirectRecord d;
                d.present = true;
                d.role = role;
                d.name = name;
                d.bidder_id = bidder_id;
                d.commit_domain = relay_commit_domain;
                d.c0x = c0x; d.c0y = c0y; d.c1x = c1x; d.c1y = c1y;
                d.packet = recv_party_wire_packet(sock, msg_session_id, msg_party_id, role, name, bidder_id, relay_commit_domain, c1x, c1y);
                direct_records[key] = std::move(d);
                direct_count += 1;
                std::cout << "P1: received direct signed packet from bidder " << bidder_id << " (" << name << ")\n";
            } else if (magic == EVIDENCE_MAGIC) {
                EvidenceRecord e;
                e.present = true;
                e.role = role;
                e.name = name;
                e.bidder_id = bidder_id;
                e.commit_domain = relay_commit_domain;
                e.c0x = c0x; e.c0y = c0y; e.c1x = c1x; e.c1y = c1y;
                e.receipt_hash = recv_lp_string(sock);
                e.leaf_hash = recv_lp_string(sock);
                e.receipt_signature = recv_lp_string(sock);
                e.root = recv_lp_string(sock);
                uint64_t path_len = recv_u64(sock);
                if (path_len > 1024) throw std::runtime_error("Merkle path too large/corrupted for " + name);
                e.path_elements.reserve(static_cast<size_t>(path_len));
                e.path_directions.reserve(static_cast<size_t>(path_len));
                for (uint64_t i = 0; i < path_len; ++i) {
                    e.path_elements.push_back(recv_lp_string(sock));
                    e.path_directions.push_back(recv_u64(sock));
                }
                e.evidence_signature = recv_lp_string(sock);
                e.vector_signature = recv_lp_string(sock);
                e.boss_packet = recv_party_wire_packet(sock, msg_session_id, msg_party_id, role, name, bidder_id, relay_commit_domain, c1x, c1y);
                evidence_records[key] = std::move(e);
                evidence_count += 1;
                std::cout << "P1: received BidderBoss Merkle evidence for bidder " << bidder_id << " (" << name << ")\n";
            } else {
                throw std::runtime_error("bad incoming packet magic: " + magic);
            }
        } catch (...) {
            close(sock);
            throw;
        }
        close(sock);
    }

    close(listener);

    GoodBidders out;
    bool root_inconsistency_vector_dispute_sent = false;

    for (const auto& kv : direct_records) {
        const DirectRecord& d = kv.second;
        auto ev_it = evidence_records.find(kv.first);
        const EvidenceRecord* e = ev_it == evidence_records.end() ? nullptr : &ev_it->second;

        if (d.role != group_label) {
            std::cerr << "P1: WARNING expected " << group_label << " packet on this port, got role=" << d.role << " for " << d.name << "\n";
        }

        const bool have_evidence = e != nullptr;
        const bool commitments_same = have_evidence &&
            d.c0x == e->c0x && d.c0y == e->c0y && d.c1x == e->c1x && d.c1y == e->c1y;

        bool merkle_path_ok = false;
        bool merkle_root_ok = false;
        bool merkle_root_read_ok = false;
        bool merkle_ok = false;
        std::string onchain_root;

        if (have_evidence) {
            try {
                merkle_path_ok = merkle_path_matches_root(e->leaf_hash, e->root, e->path_elements, e->path_directions);
            } catch (const std::exception& ex) {
                std::cerr << "P1: Merkle path verification error for bidder " << d.bidder_id << " (" << d.name << "): " << ex.what() << "\n";
                merkle_path_ok = false;
            }

            try {
                onchain_root = read_onchain_commitment_root(node_path, read_root_tool, rpc_url, registry_contract_address, session_id, d.role, 1);
                merkle_root_read_ok = true;
                merkle_root_ok = normalize_hex32(e->root) == normalize_hex32(onchain_root);
            } catch (const std::exception& ex) {
                std::cerr << "P1: could not read/check on-chain Merkle root for bidder " << d.bidder_id << " (" << d.name << "): " << ex.what() << "\n";
                std::cerr << "P1: root-read failure is a technical failure, not a Merkle fault; no Merkle dispute will be submitted from this failure.\n";
                merkle_root_ok = false;
            }
        }

        merkle_ok = have_evidence && commitments_same && merkle_path_ok && merkle_root_ok;

        std::cout << "P1: merkle root of P1 " << d.role
                  << " tree is " << (merkle_root_ok ? "valid" : "invalid") << "\n";

        std::cout << "P1: merkle proof of " << d.bidder_id
                  << " is " << (merkle_ok ? "valid" : "invalid")
                  << " (path=" << (merkle_path_ok ? "valid" : "invalid")
                  << ", root=" << (merkle_root_ok ? "valid" : "invalid")
                  << ", commitments=" << (commitments_same ? "same" : "different/missing")
                  << ")\n";

        if (!merkle_ok && have_evidence && !commitments_same) {
            std::cerr << "P1: commitment mismatch for bidder " << d.bidder_id
                      << ". This is possible bidder equivocation: direct commitment differs from BidderBoss evidence.\n";
        } else if (!merkle_ok && merkle_root_read_ok && have_evidence && commitments_same) {
            std::cerr << "P1: commitment vectors are the same, but Merkle path/root is inconsistent for bidder "
                      << d.bidder_id << " (" << d.name << "). This indicates possible BidderBoss root/vector manipulation.\n";
        }

        if (!merkle_ok && have_evidence && merkle_root_read_ok && !report_merkle_disputes_onchain) {
            std::cerr << "P1: auctioneer Merkle/vector dispute reporting is disabled; bidder-side challenges may still be submitted by bidders.\n";
        }

        uint64_t bid_share = 0;
        bool bid_dec_ok = true;
        try {
            bid_share = decrypt_u64_hybrid(d.packet.bid_eph, d.packet.bid_iv, d.packet.bid_tag, d.packet.bid_ct, elg_priv);
        } catch (const std::exception& ex) {
            bid_dec_ok = false;
            std::cerr << "P1: bid decrypt error for " << d.name << ": " << ex.what() << "\n";
        }

        uint64_t boss_bid_share = 0;
        bool boss_bid_dec_ok = false;
        if (have_evidence) {
            try {
                boss_bid_share = decrypt_u64_hybrid(e->boss_packet.bid_eph, e->boss_packet.bid_iv, e->boss_packet.bid_tag, e->boss_packet.bid_ct, elg_priv);
                boss_bid_dec_ok = true;
            } catch (const std::exception& ex) {
                std::cerr << "P1: BidderBoss packet decrypt error for " << d.name << ": " << ex.what() << "\n";
            }
        }

        const bool should_submit_vector_dispute = have_evidence && !merkle_ok && merkle_root_read_ok &&
            report_merkle_disputes_onchain && !commitment_consistency_dispute_tool.empty() && bid_dec_ok && boss_bid_dec_ok;

        if (should_submit_vector_dispute) {
            const bool root_inconsistency_case = commitments_same && (!merkle_path_ok || !merkle_root_ok);
            if (root_inconsistency_case && root_inconsistency_vector_dispute_sent) {
                std::cerr << "P1: root inconsistency dispute for this " << d.role
                          << "/P1 tree was already submitted once; skipping duplicate dispute for bidder "
                          << d.bidder_id << ".\n";
            } else {
                try {
                    report_commitment_consistency_dispute_to_contract(d, *e, bid_share, boss_bid_share);
                    if (root_inconsistency_case) root_inconsistency_vector_dispute_sent = true;
                } catch (const std::exception& ex) {
                    std::cerr << "P1: failed to report vector commitment/root dispute on-chain for "
                              << d.name << ": " << ex.what() << "\n";
                }
            }
        }

        uint64_t id_share = 0;
        bool id_dec_ok = true;
        try {
            id_share = decrypt_id_hybrid(d.packet.id_eph, d.packet.id_iv, d.packet.id_tag, d.packet.id_ct, elg_priv);
        } catch (const std::exception& ex) {
            id_dec_ok = false;
            std::cerr << "P1: id decrypt error for " << d.name << ": " << ex.what() << "\n";
        }

        bool sig_ok = false;
        auto it = pubkeys.find(d.name);
        if (it != pubkeys.end()) {
            sig_ok = verify_signature(d.packet.sig_tr, d.packet.sig, it->second);
        } else {
            std::cerr << "P1: Unknown bidder '" << d.name << "', cannot verify Ed25519 signature.\n";
        }

        bool cce_eth_sig_ok = false;
        bool cce_ok = false;
        std::string verifier_out;
        if (sig_ok) {
            try {
                bool signature_valid = false;
                bool proof_valid = false;
                run_sigma_cce_local_verifier_js(
                    node_path,
                    "js/verify_sigma_cce_local.js",
                    rpc_url,
                    registry_contract_address,
                    d.packet.zk_proof_json,
                    d.packet.bidder_eth_sig_hex,
                    &signature_valid,
                    &proof_valid,
                    &verifier_out
                );
                cce_eth_sig_ok = signature_valid;
                cce_ok = proof_valid;
                if (!cce_eth_sig_ok) {
                    std::cerr << "P1: bidder Ethereum Sigma-CCE packet signature invalid for "
                              << d.name << ". Verifier output:\n" << verifier_out << "\n";
                } else if (!cce_ok) {
                    std::cerr << "P1: Sigma CCE proof invalid for " << d.name
                              << ". Verifier output:\n" << verifier_out << "\n";
                }
            } catch (const std::exception& ex) {
                std::cerr << "P1: Sigma CCE verification tool error for "
                          << d.name << ": " << ex.what() << "\n";
                cce_eth_sig_ok = false;
                cce_ok = false;
            }
        }

        std::cout << "P1: Sigma CCE proof of " << d.bidder_id << " is " << (cce_ok ? "valid" : "invalid") << "\n";

        if (sig_ok && cce_eth_sig_ok && bid_dec_ok && !cce_ok && report_cce_disputes_onchain) {
            try {
                report_invalid_cce_dispute_to_contract(
                    node_path, cce_dispute_tool, rpc_url, dispute_contract_address, eth_priv_file,
                    session_id, 1, d.role, d.name,
                    d.bidder_id,
                    d.commit_domain.empty() ? commitDomain : d.commit_domain,
                    cceDomain,
                    d.c0x,
                    d.c0y,
                    d.c1x,
                    d.c1y,
                    d.packet.bid_eph,
                    d.packet.bid_iv,
                    d.packet.bid_tag,
                    d.packet.bid_ct,
                    d.packet.Ax,
                    d.packet.Ay,
                    d.packet.z,
                    d.packet.bidder_eth_sig_hex,
                    d.packet.commitment_eth_sig_hex,
                    d.packet.zk_proof_json,
                    d.packet.zk_public_signals_json
                );
            } catch (const std::exception& ex) {
                std::cerr << "P1: failed to report invalid CCE on-chain for " << d.name << ": " << ex.what() << "\n";
            }
        }

        // TEST ONLY: intentionally submit a false CCE dispute for a VALID CCE proof.
        // This is used to test the contract rule:
        // if an auctioneer reports a CCE proof as invalid but the on-chain verifier
        // confirms it is valid, the auctioneer must be slashed.
        if (
            sig_ok &&
            cce_eth_sig_ok &&
            bid_dec_ok &&
            cce_ok &&
            report_cce_disputes_onchain &&
            force_false_cce_dispute_onchain &&
            d.bidder_id == force_false_cce_dispute_id
        ) {
            try {
                std::cerr << "P1-TEST: intentionally submitting FALSE CCE dispute for valid bidder "
                          << d.bidder_id << " (" << d.name << "). "
                          << "The auctioneer should be slashed if the smart contract verifies CCE=valid.\n";

                report_invalid_cce_dispute_to_contract(
                    node_path, cce_dispute_tool, rpc_url, dispute_contract_address, eth_priv_file,
                    session_id, 1, d.role, d.name,
                    d.bidder_id,
                    d.commit_domain.empty() ? commitDomain : d.commit_domain,
                    cceDomain,
                    d.c0x,
                    d.c0y,
                    d.c1x,
                    d.c1y,
                    d.packet.bid_eph,
                    d.packet.bid_iv,
                    d.packet.bid_tag,
                    d.packet.bid_ct,
                    d.packet.Ax,
                    d.packet.Ay,
                    d.packet.z,
                    d.packet.bidder_eth_sig_hex,
                    d.packet.commitment_eth_sig_hex,
                    d.packet.zk_proof_json,
                    d.packet.zk_public_signals_json
                );
            } catch (const std::exception& ex) {
                std::cerr << "P1-TEST: failed to submit FALSE CCE dispute for "
                          << d.name << ": " << ex.what() << "\n";
            }
        }

        const bool usable_for_auction = sig_ok && cce_eth_sig_ok && bid_dec_ok && id_dec_ok && cce_ok && merkle_ok;

        std::cout << "P1: Received share from " << d.name
                  << " | Sig=" << (sig_ok ? "VALID" : "INVALID")
                  << " | EthCCE=" << (cce_eth_sig_ok ? "VALID" : "INVALID")
                  << " | BidDec=" << (bid_dec_ok ? "OK" : "FAIL")
                  << " | IdDec=" << (id_dec_ok ? "OK" : "FAIL")
                  << " | CCE=" << (cce_ok ? "VALID" : "INVALID")
                  << " | Merkle=" << (merkle_ok ? "VALID" : "INVALID")
                  << " => " << (usable_for_auction ? "GOOD" : "BAD_OR_DISPUTED")
                  << "\n";

        if (usable_for_auction) {
            if (out.by_name.count(d.name)) {
                std::cerr << "P1: WARNING duplicate bidder name '" << d.name << "' ignored\n";
            } else {
                BidderRecord br;
                br.role = d.role;
                br.bid_share = bid_share;
                br.id_share = id_share;
                out.by_name[d.name] = br;
                out.order.push_back(d.name);
            }
        }
    }

    return out;
}

static RunConfig make_run_from_bidders(
    DatasetKind kind,
    bool descending,
    const GoodBidders& bidders
) {
    RunConfig run;

    run.kind = kind;
    run.descending = descending;
    run.label = (kind == DatasetKind::Buyers) ? "buyer bids" : "seller asks";
    run.label += descending ? " (descending)" : " (ascending)";

    for (const auto& nm : bidders.order) {
        const auto& rec = bidders.by_name.at(nm);

        run.names.push_back(nm);
        run.roles.push_back(rec.role);
        run.bid_shares.push_back(rec.bid_share);
        run.id_shares.push_back(rec.id_share);
    }

    return run;
}

static void rebuild_runs_after_alignment(
    std::vector<RunConfig>& runs,
    const std::optional<GoodBidders>& buyers_dump,
    const std::optional<GoodBidders>& sellers_dump,
    bool include_buyers,
    bool include_sellers
) {
    runs.clear();

    if (include_buyers && buyers_dump.has_value()) {
        runs.push_back(make_run_from_bidders(DatasetKind::Buyers, true, buyers_dump.value()));
    }

    if (include_sellers && sellers_dump.has_value()) {
        runs.push_back(make_run_from_bidders(DatasetKind::Sellers, false, sellers_dump.value()));
    }

    if (runs.empty()) {
        throw std::runtime_error("No aligned datasets remain for sorting");
    }
}


// =============================================================
// P1 -> ProverParty: build split-signature dataset payload, sign, encrypt, and send.
//
// Opening Signature A binds:
//   Poseidon(share_bid_vector_dec),
//   Poseidon(randomness_vector_dec),
//   Poseidon(id_share_vector_dec).
//
// Permutation Signature B independently binds:
//   Poseidon(permutation_index_1based).
//
// Circuit domain tags:
//   opening     = 918273646
//   permutation = 918273647
// =============================================================

static void write_text_file_local(const std::string& path, const std::string& data) {
    ensure_parent_dir(path);

    std::ofstream out(path);

    if (!out) {
        throw std::runtime_error("cannot write file: " + path);
    }

    out << data;
}

static void write_u64_json_array(
    std::ostringstream& os,
    const std::vector<uint64_t>& values
) {
    os << "[";

    for (size_t i = 0; i < values.size(); ++i) {
        if (i) {
            os << ",";
        }

        os << "\"" << values[i] << "\"";
    }

    os << "]";
}

static std::string build_auctioneer_dataset_payload_json(
    const std::string& sender,
    uint64_t party_id,
    uint64_t session_id,
    uint64_t max_n,
    const SortedResult& result,
    const GoodBidders& original_bidders,
    const std::vector<RevealedRandomnessRec>& revealed_randomness
) {
    static const uint64_t OPENING_DOMAIN_TAG = 918273646;
    static const uint64_t PERMUTATION_DOMAIN_TAG = 918273647;

    const uint64_t dataset_kind = static_cast<uint64_t>(result.run.kind);
    const char* randomness_label = (party_id == 0) ? "r0_dec" : "r1_dec";

    if (result.perm_index_1based.empty()) {
        throw std::runtime_error("cannot build prover payload for empty permutation vector");
    }

    if (result.perm_index_1based.size() > max_n) {
        throw std::runtime_error("permutation vector exceeds max_n");
    }

    std::ostringstream os;

    os << "{\n";
    os << "  \"protocol\": \"SFDAC-AuctioneerDatasetPayload-v2\",\n";
    os << "  \"payload_type\": \"auctioneer_dataset_reveal_split_signatures\",\n";
    os << "  \"signature_profile\": \"babyjub-eddsa-poseidon-split-dataset-v2\",\n";
    os << "  \"sender\": \"" << json_escape(sender) << "\",\n";
    os << "  \"party_id\": " << party_id << ",\n";
    os << "  \"session_id\": " << session_id << ",\n";
    os << "  \"dataset_kind\": " << dataset_kind << ",\n";
    os << "  \"dataset_label\": \"" << json_escape(result.run.label) << "\",\n";
    os << "  \"n\": " << static_cast<uint64_t>(result.perm_index_1based.size()) << ",\n";
    os << "  \"max_n\": " << max_n << ",\n";

    os << "  \"opening_signature_request\": {\n";
    os << "    \"scheme\": \"babyjub-eddsa-poseidon-opening-v2\",\n";
    os << "    \"domain_tag\": \"" << OPENING_DOMAIN_TAG << "\",\n";
    os << "    \"message_layout\": \"Poseidon(domain,session,dataset,party,shareHash,randomnessHash,idShareHash)\"\n";
    os << "  },\n";

    os << "  \"permutation_signature_request\": {\n";
    os << "    \"scheme\": \"babyjub-eddsa-poseidon-permutation-v2\",\n";
    os << "    \"domain_tag\": \"" << PERMUTATION_DOMAIN_TAG << "\",\n";
    os << "    \"message_layout\": \"Poseidon(domain,session,dataset,party,permutationHash)\"\n";
    os << "  },\n";
    os << "  \"permutation_index_1based\": ";
    write_u64_json_array(os, result.perm_index_1based);
    os << ",\n";

    // These explicit arrays are required by js/prover_payload_tool_babyjub_split_v2.cjs.
    // The helper signs:
    //   Poseidon(permutation_index_1based),
    //   Poseidon(share_bid_vector_dec),
    //   Poseidon(randomness_vector_dec)
    // so the arrays must be present in the plaintext payload.
    // They must stay in the same primary order as original_bidders.order.
    std::vector<uint64_t> share_bid_vector_dec;
    std::vector<uint64_t> id_share_vector_dec;
    std::vector<std::string> randomness_vector_dec;

    share_bid_vector_dec.reserve(original_bidders.order.size());
    id_share_vector_dec.reserve(original_bidders.order.size());
    randomness_vector_dec.reserve(original_bidders.order.size());

    for (const std::string& name : original_bidders.order) {
        const auto& rec = original_bidders.by_name.at(name);
        std::string r_dec = find_revealed_randomness_or_empty(
            revealed_randomness,
            rec.role,
            name
        );

        if (r_dec.empty()) {
            throw std::runtime_error(
                "missing revealed randomness for " + rec.role + " " + name
            );
        }

        share_bid_vector_dec.push_back(rec.bid_share);
        id_share_vector_dec.push_back(rec.id_share);
        randomness_vector_dec.push_back(r_dec);
    }

    os << "  \"share_bid_vector_dec\": ";
    write_u64_json_array(os, share_bid_vector_dec);
    os << ",\n";

    os << "  \"id_share_vector_dec\": ";
    write_u64_json_array(os, id_share_vector_dec);
    os << ",\n";

    os << "  \"randomness_vector_dec\": [";
    for (size_t i = 0; i < randomness_vector_dec.size(); ++i) {
        if (i) {
            os << ",";
        }

        os << "\"" << json_escape(randomness_vector_dec[i]) << "\"";
    }
    os << "],\n";

    os << "  \"signed_vector_note\": \"opening signature covers share/randomness/id-share hashes; permutation signature covers only permutation hash\",\n";

    os << "  \"share_bid_openings\": [\n";

    for (size_t i = 0; i < original_bidders.order.size(); ++i) {
        const std::string& name = original_bidders.order[i];
        const auto& rec = original_bidders.by_name.at(name);
        std::string r_dec = find_revealed_randomness_or_empty(
            revealed_randomness,
            rec.role,
            name
        );

        if (r_dec.empty()) {
            throw std::runtime_error(
                "missing revealed randomness for " + rec.role + " " + name
            );
        }

        os << "    {"
           << "\"role\":\"" << json_escape(rec.role) << "\","
           << "\"name\":\"" << json_escape(name) << "\","
           << "\"bid_share\":" << rec.bid_share << ","
           << "\"bid_share_dec\":\"" << rec.bid_share << "\","
           << "\"id_share\":" << rec.id_share << ","
           << "\"id_share_dec\":\"" << rec.id_share << "\","
           << "\"randomness_label\":\"" << randomness_label << "\","
           << "\"r_dec\":\"" << json_escape(r_dec) << "\""
           << "}";

        os << (i + 1 == original_bidders.order.size() ? "\n" : ",\n");
    }

    os << "  ]\n";
    os << "}\n";

    return os.str();
}


struct SignedPayloadArtifacts {
    std::string encrypted_transport_json;
    std::string signed_payload_path;
};

static SignedPayloadArtifacts run_prover_payload_sign_encrypt_and_read_json(
    const std::string& party_label,
    const std::string& node_path,
    const std::string& tool_path,
    const std::string& signing_seed_path,
    const std::string& prover_pub_path,
    const std::string& plain_path,
    const std::string& signed_path,
    const std::string& encrypted_path
) {
    std::string cmd;
    cmd += shell_escape_single_quotes(node_path);
    cmd += " ";
    cmd += shell_escape_single_quotes(tool_path);
    cmd += " sign-encrypt";
    cmd += " --in ";
    cmd += shell_escape_single_quotes(plain_path);
    cmd += " --sign-priv ";
    cmd += shell_escape_single_quotes(signing_seed_path);
    cmd += " --prover-pub ";
    cmd += shell_escape_single_quotes(prover_pub_path);
    cmd += " --signed-out ";
    cmd += shell_escape_single_quotes(signed_path);
    cmd += " --out ";
    cmd += shell_escape_single_quotes(encrypted_path);

    FILE* fp = popen(cmd.c_str(), "r");
    if (!fp) {
        throw std::runtime_error("failed to start split-signature payload helper");
    }

    std::string output;
    char buf[2048];
    while (fgets(buf, sizeof(buf), fp)) output += buf;
    int rc = pclose(fp);
    if (rc != 0) {
        throw std::runtime_error(
            "split-signature payload helper failed. Output:\n" + output
        );
    }

    const std::string profile = json_extract_string_field(output, "signature_profile");
    const std::string opening_scheme = json_extract_string_field(output, "opening_signature_scheme");
    const std::string permutation_scheme = json_extract_string_field(output, "permutation_signature_scheme");
    const std::string permutation_hash = json_extract_string_field(output, "permutation_hash_poseidon");
    const std::string share_hash = json_extract_string_field(output, "share_bid_vector_hash_poseidon");
    const std::string randomness_hash = json_extract_string_field(output, "randomness_vector_hash_poseidon");
    const std::string id_share_hash = json_extract_string_field(output, "id_share_vector_hash_poseidon");
    const std::string opening_message_hash = json_extract_string_field(output, "opening_signed_message_hash_poseidon");
    const std::string permutation_message_hash = json_extract_string_field(output, "permutation_signed_message_hash_poseidon");
    const std::string helper_signed_path = json_extract_string_field(output, "signed_payload_path");

    if (profile != "babyjub-eddsa-poseidon-split-dataset-v2" ||
        opening_scheme != "babyjub-eddsa-poseidon-opening-v2" ||
        permutation_scheme != "babyjub-eddsa-poseidon-permutation-v2") {
        throw std::runtime_error(
            "wrong helper profile; expected babyjub-eddsa-poseidon-split-dataset-v2"
        );
    }

    if (permutation_hash.empty() || share_hash.empty() ||
        randomness_hash.empty() || id_share_hash.empty() ||
        opening_message_hash.empty() || permutation_message_hash.empty()) {
        throw std::runtime_error(
            "split-signature helper output is missing a required hash"
        );
    }

    if (!helper_signed_path.empty() && helper_signed_path != signed_path) {
        throw std::runtime_error("split-signature helper returned unexpected signed payload path");
    }

    std::cout << party_label << ": confirmed independent opening/permutation signatures\n"
              << party_label << ": permutation_hash_poseidon = " << permutation_hash << "\n"
              << party_label << ": share_bid_vector_hash_poseidon = " << share_hash << "\n"
              << party_label << ": randomness_vector_hash_poseidon = " << randomness_hash << "\n"
              << party_label << ": id_share_vector_hash_poseidon = " << id_share_hash << "\n"
              << party_label << ": opening_signed_message_hash_poseidon = " << opening_message_hash << "\n"
              << party_label << ": permutation_signed_message_hash_poseidon = " << permutation_message_hash << "\n";

    SignedPayloadArtifacts a;
    a.encrypted_transport_json = read_file_text(encrypted_path);
    a.signed_payload_path = signed_path;
    return a;
}

static void send_encrypted_payload_to_prover_socket(
    const std::string& prover_host,
    uint16_t prover_port,
    const std::string& encrypted_transport_json
) {
    int fd = connect_to(prover_host, prover_port);

    try {
        send_lp_string(fd, encrypted_transport_json);

        std::string ack = recv_lp_string(fd);

        close(fd);

        if (ack.find("\"ok\":true") == std::string::npos) {
            throw std::runtime_error("ProverParty returned non-ok ACK: " + ack);
        }

        std::cout << "P1: ProverParty ACK: " << ack << "\n";
    } catch (...) {
        close(fd);
        throw;
    }
}



static void sign_encrypt_send_dataset_payload_to_prover(
    const std::string& node_path,
    const std::string& payload_tool,
    const std::string& signing_seed_path,
    const std::string& prover_pub_path,
    const std::string& prover_host,
    uint16_t prover_port,
    const std::string& out_dir,
    uint64_t session_id,
    uint64_t max_n,
    const std::string& sender,
    uint64_t party_id,
    const SortedResult& result,
    const GoodBidders& original_bidders,
    const std::vector<RevealedRandomnessRec>& revealed_randomness,
    bool submit_vector_hashes_onchain,
    const std::string& submit_vector_hashes_tool,
    const std::string& chain_rpc,
    const std::string& contract_address,
    const std::string& eth_priv_file
) {
    const uint64_t dataset_kind = static_cast<uint64_t>(result.run.kind);
    fs::create_directories(out_dir);

    const std::string base = out_dir + "/" + sender +
        "_auctioneer_dataset_session_" + std::to_string(session_id) +
        "_dataset_" + std::to_string(dataset_kind);
    const std::string plain_path = base + ".plain.reveal.v2.json";
    const std::string signed_path = base + ".signed.reveal.v2.json";
    const std::string encrypted_path = base + ".encrypted.transport.v2.json";

    const std::string plain_json = build_auctioneer_dataset_payload_json(
        sender, party_id, session_id, max_n, result,
        original_bidders, revealed_randomness
    );
    write_text_file_local(plain_path, plain_json);

    SignedPayloadArtifacts artifacts =
        run_prover_payload_sign_encrypt_and_read_json(
            "P1", node_path, payload_tool, signing_seed_path,
            prover_pub_path, plain_path, signed_path, encrypted_path
        );

    // Try to bind the exact signed payload on-chain before revealing it.
    // If the chain submission fails, still deliver the already-signed payload to
    // ProverParty so the signed evidence is preserved in sended_p1data.json.
    std::string onchain_submit_error;
    if (submit_vector_hashes_onchain) {
        try {
            submit_signed_dataset_vector_hashes_to_contract(
                node_path, submit_vector_hashes_tool, chain_rpc,
                contract_address, eth_priv_file, session_id,
                dataset_kind, party_id, artifacts.signed_payload_path
            );
            std::cout << "P1: submitted split opening/permutation hashes"
                      << " session_id=" << session_id
                      << " dataset_kind=" << dataset_kind
                      << " party_id=" << party_id << "\n";
        } catch (const std::exception& ex) {
            onchain_submit_error = ex.what();
            std::cerr << "P1: WARNING split hashes were not published on-chain; "
                      << "the signed payload will still be delivered to ProverParty: "
                      << onchain_submit_error << "\n";
        }
    } else {
        std::cout << "P1: split-signature on-chain submit disabled\n";
    }

    send_encrypted_payload_to_prover_socket(
        prover_host, prover_port, artifacts.encrypted_transport_json
    );

    std::cout << "P1: sent encrypted split-signature payload to ProverParty "
              << prover_host << ":" << prover_port
              << " dataset_kind=" << dataset_kind << "\n";

    if (!onchain_submit_error.empty()) {
        throw std::runtime_error(
            "signed payload was saved by ProverParty, but split hash publication failed: " +
            onchain_submit_error
        );
    }
}


// =============================================================
// Args
// =============================================================

struct Args {
    bool include_buyers = false;
    bool include_sellers = false;

    uint64_t nbuyers = 0;
    uint64_t nsellers = 0;

    std::string elg_priv_path = "keys/p1.elg.priv";
    std::string pubkeys_path = "pubkeys.json";
    std::string sharebids_out = "zk-snark/circuits/circomlib/sharebids_p1.json";

    std::string node_path = "node";
    std::string verifier_path = "verifier_CCE.js";
    std::string poseidon_script = "poseidon_hash.js";

    std::string commit_domain ="SFDAC-BabyJub-Pedersen-v1";
    std::string cce_domain ="PPCR-SIGMA-CCE-v1";

    std::string p0_ip = "127.0.0.1";
    uint16_t p0_port = 6000;

    uint16_t p2_listen_port = 6002;

    std::string boss_ip = "127.0.0.1";
    uint16_t boss_reveal_port = 7700;
    std::string reveal_out = "onchain/p1_revealed_randomness.json";

    bool send_perm_to_prover = true;

    std::string prover_host = "127.0.0.1";
    uint16_t prover_port = 7800;
    std::string prover_pub_path = "keys/ProverParty.elg.pub";

    std::string p1_signing_seed_path = "keys/p1.perm.babyjub.priv";
    std::string perm_payload_tool = "js/prover_payload_tool_babyjub_split_v2.cjs";
    std::string perm_payload_out_dir = "zk-snark/perm_payloads";

    uint64_t perm_max_n = 128;
    uint64_t perm_session_id = 0;
    bool submit_perm_hash_onchain = false; // split submission records signed permutation hash

    std::string chain_rpc = "http://127.0.0.1:8545";
    std::string perm_registry_contract = "0x5FbDB2315678afecb367f032d93F642f64180aa3"; 
    std::string dispute_manager_contract;
    std::string eth_priv_file = "keys/p1.eth.priv";
    std::string submit_hash_tool = "js/submit_perm_hash.js";
    bool submit_sorted_share_bids_hashes_onchain = true;
    std::string submit_sorted_share_bids_hash_tool = "js/submit_sorted_share_bids_hash.js";
    bool submit_vector_hashes_onchain = true;
    std::string submit_vector_hashes_tool = "js/submit_split_dataset_signature_hashes.js";
    std::string split_registry_check_tool = "js/check_split_registry_compatibility.js";
    bool submit_auction_result_onchain = true;
    std::string submit_result_tool = "js/submit_auction_result.js";
    bool submit_winner_ids_poseidon_hashes_onchain = true;
    std::string submit_winner_ids_poseidon_hashes_tool = "js/submit_winner_ids_poseidon_hashes.js";

    bool report_cce_disputes_onchain = true;
    std::string cce_dispute_tool = "js/submit_sigma_cce_dispute.js";
    bool report_merkle_disputes_onchain = false;
    std::string merkle_dispute_tool;
    std::string commitment_consistency_dispute_tool;
    std::string read_root_tool = "scripts/read_commitment_root.js";
    std::string finalize_cce_checks_tool = "js/finalize_cce_check_requests.js";
    bool finalize_cce_checks_after_result = false;

    // TEST ONLY: force this auctioneer to submit a CCE dispute even when the
    // local CCE verifier says the bidder proof is valid. The smart contract
    // should punish this auctioneer as a false reporter.
    bool force_false_cce_dispute_onchain = false;
    uint64_t force_false_cce_dispute_id = 0;
};

static Args parse_args(int argc, char** argv) {
    Args a;

    for (int i = 1; i < argc; ++i) {
        std::string s(argv[i]);

        auto need = [&](const std::string& flag) -> std::string {
            if (i + 1 >= argc) {
                throw std::invalid_argument("missing value for " + flag);
            }

            return std::string(argv[++i]);
        };

        if (s == "--buyers") {
            a.include_buyers = true;
        } else if (s == "--sellers") {
            a.include_sellers = true;
        } else if (s == "--nbuyers") {
            a.nbuyers = std::stoull(need("--nbuyers"));
        } else if (s == "--nsellers") {
            a.nsellers = std::stoull(need("--nsellers"));
        } else if (s == "--elg-priv") {
            a.elg_priv_path = need("--elg-priv");
        } else if (s == "--pubkeys") {
            a.pubkeys_path = need("--pubkeys");
        } else if (s == "--sharebids-out") {
            a.sharebids_out = need("--sharebids-out");
        } else if (s == "--node") {
            a.node_path = need("--node");
        } else if (s == "--cce-verifier") {
            a.verifier_path = need("--cce-verifier");
        } else if (s == "--poseidon-script") {
            a.poseidon_script = need("--poseidon-script");
        } else if (s == "--commit-domain") {
            a.commit_domain = need("--commit-domain");
        } else if (s == "--cce-domain") {
            a.cce_domain = need("--cce-domain");
        } else if (s == "--p0") {
            a.p0_ip = need("--p0");
        } else if (s == "--p0-port") {
            a.p0_port = static_cast<uint16_t>(std::stoul(need("--p0-port")));
        } else if (s == "--p2-listen-port") {
            a.p2_listen_port = static_cast<uint16_t>(
                std::stoul(need("--p2-listen-port"))
            );
        } else if (s == "--boss") {
            a.boss_ip = need("--boss");
        } else if (s == "--boss-reveal-port") {
            a.boss_reveal_port = static_cast<uint16_t>(
                std::stoul(need("--boss-reveal-port"))
            );
        } else if (s == "--reveal-out") {
            a.reveal_out = need("--reveal-out");
        } else if (s == "--prover-host") {
            a.prover_host = need("--prover-host");
        } else if (s == "--prover-port") {
            a.prover_port = static_cast<uint16_t>(
                std::stoul(need("--prover-port"))
            );
        } else if (s == "--prover-pub") {
            a.prover_pub_path = need("--prover-pub");
        } else if (s == "--p1-signing-seed" || s == "--p1-perm-signing-key") {
            a.p1_signing_seed_path = need(s);
        } else if (s == "--perm-payload-tool") {
            a.perm_payload_tool = need("--perm-payload-tool");
        } else if (s == "--perm-payload-out-dir") {
            a.perm_payload_out_dir = need("--perm-payload-out-dir");
        } else if (s == "--perm-max-n") {
            a.perm_max_n = std::stoull(need("--perm-max-n"));
        } else if (s == "--perm-session-id") {
            a.perm_session_id = std::stoull(need("--perm-session-id"));
        } else if (s == "--disable-prover-send") {
            a.send_perm_to_prover = false;
        }else if (s == "--chain-rpc") {
            a.chain_rpc = need("--chain-rpc");
        } else if (s == "--perm-registry") {
            a.perm_registry_contract = need("--perm-registry");
        } else if (s == "--dispute-manager") {
            a.dispute_manager_contract = need("--dispute-manager");
        } else if (s == "--eth-priv") {
            a.eth_priv_file = need("--eth-priv");
        } else if (s == "--submit-hash-tool") {
            a.submit_hash_tool = need("--submit-hash-tool");
        } else if (s == "--submit-sorted-share-bids-hash-tool") {
            a.submit_sorted_share_bids_hash_tool = need("--submit-sorted-share-bids-hash-tool");
        } else if (s == "--disable-sorted-share-bids-hash-submit") {
            a.submit_sorted_share_bids_hashes_onchain = false;
        } else if (s == "--submit-vector-hashes-tool") {
            a.submit_vector_hashes_tool = need("--submit-vector-hashes-tool");
        } else if (s == "--split-registry-check-tool") {
            a.split_registry_check_tool = need("--split-registry-check-tool");
        } else if (s == "--disable-vector-hash-submit") {
            a.submit_vector_hashes_onchain = false;
        } else if (s == "--disable-chain-submit") {
            a.submit_perm_hash_onchain = false;
            a.submit_sorted_share_bids_hashes_onchain = false;
            a.submit_vector_hashes_onchain = false;
            a.submit_winner_ids_poseidon_hashes_onchain = false;
        } else if (s == "--submit-result-tool") {
            a.submit_result_tool = need("--submit-result-tool");
        } else if (s == "--submit-winner-hashes-tool" || s == "--submit-winner-ids-poseidon-hashes-tool") {
            a.submit_winner_ids_poseidon_hashes_tool = need(s);
        } else if (s == "--disable-result-submit") {
            a.submit_auction_result_onchain = false;
            a.submit_winner_ids_poseidon_hashes_onchain = false;
        } else if (s == "--disable-winner-hash-submit" || s == "--disable-winner-ids-poseidon-hash-submit") {
            a.submit_winner_ids_poseidon_hashes_onchain = false;
        } else if (s == "--cce-dispute-tool") {
            a.cce_dispute_tool = need("--cce-dispute-tool");
        } else if (s == "--merkle-dispute-tool") {
            a.merkle_dispute_tool = need("--merkle-dispute-tool");
            a.report_merkle_disputes_onchain = true;
        } else if (s == "--commitment-consistency-dispute-tool") {
            a.commitment_consistency_dispute_tool = need("--commitment-consistency-dispute-tool");
            a.report_merkle_disputes_onchain = true;
        } else if (s == "--read-root-tool") {
            a.read_root_tool = need("--read-root-tool");
        } else if (s == "--disable-merkle-dispute-report") {
            a.report_merkle_disputes_onchain = false;
        } else if (s == "--disable-cce-dispute-report") {
            a.report_cce_disputes_onchain = false;
        } else if (s == "--force-false-cce-dispute-id") {
            a.force_false_cce_dispute_onchain = true;
            a.force_false_cce_dispute_id = std::stoull(need("--force-false-cce-dispute-id"));
        } else {
            throw std::invalid_argument("Unknown argument: " + s);
        }
    }

    if (!a.include_buyers && !a.include_sellers) {
        a.include_buyers = true;
    }

    if (a.dispute_manager_contract.empty()) {
        a.dispute_manager_contract = a.perm_registry_contract; // backward-compatible; split mode should pass --dispute-manager
    }

    return a;
}

} // namespace

int main(int argc, char** argv) {
    try {
        signal(SIGPIPE, SIG_IGN);

        std::optional<GoodBidders> buyers_dump;
        std::optional<GoodBidders> sellers_dump;

        std::ios::sync_with_stdio(false);
        std::cin.tie(nullptr);

        std::cout.setf(std::ios::unitbuf);
        std::cerr.setf(std::ios::unitbuf);

        Args args = parse_args(argc, argv);

        if (args.submit_vector_hashes_onchain) {
            std::cout << "P1: checking split AuctionRegistry API before starting auction...\n";
            check_split_registry_compatibility_or_throw(
                args.node_path,
                args.split_registry_check_tool,
                args.chain_rpc,
                args.perm_registry_contract
            );
        }

        std::cout << "[P1] Reading private key from "
                  << args.elg_priv_path << "...\n";

        ElgamalPriv elg_priv = load_elgamal_priv(args.elg_priv_path);

        std::vector<RunConfig> runs;

        // Start buyer and seller direct/evidence listeners in parallel.
        // This prevents the previous deadlock:
        //   P1 waited for buyer Merkle evidence before opening seller port,
        //   while seller bidders waited for the seller port before BidderBoss could collect all commitments.
        std::future<GoodBidders> buyers_future;
        std::future<GoodBidders> sellers_future;

        if (args.include_buyers) {
            if (args.nbuyers == 0) {
                throw std::runtime_error("P1: --nbuyers must be > 0 when --buyers set");
            }

            buyers_future = std::async(std::launch::async, [&, elg_priv]() mutable {
                return recv_bidders_decrypt(
                    7001,
                    args.nbuyers,
                    "buyer",
                    elg_priv,
                    args.pubkeys_path,
                    args.commit_domain,
                    args.cce_domain,
                    args.node_path,
                    args.verifier_path,
                    args.chain_rpc,
                    args.perm_registry_contract,
                    args.dispute_manager_contract,
                    args.eth_priv_file,
                    args.cce_dispute_tool,
                    args.report_cce_disputes_onchain,
                    args.merkle_dispute_tool,
                    args.commitment_consistency_dispute_tool,
                    args.read_root_tool,
                    args.report_merkle_disputes_onchain,
                    args.force_false_cce_dispute_onchain,
                    args.force_false_cce_dispute_id,
                    args.perm_session_id
                );
            });
        }

        if (args.include_sellers) {
            if (args.nsellers == 0) {
                throw std::runtime_error("P1: --nsellers must be > 0 when --sellers set");
            }

            sellers_future = std::async(std::launch::async, [&, elg_priv]() mutable {
                return recv_bidders_decrypt(
                    7003,
                    args.nsellers,
                    "seller",
                    elg_priv,
                    args.pubkeys_path,
                    args.commit_domain,
                    args.cce_domain,
                    args.node_path,
                    args.verifier_path,
                    args.chain_rpc,
                    args.perm_registry_contract,
                    args.dispute_manager_contract,
                    args.eth_priv_file,
                    args.cce_dispute_tool,
                    args.report_cce_disputes_onchain,
                    args.merkle_dispute_tool,
                    args.commitment_consistency_dispute_tool,
                    args.read_root_tool,
                    args.report_merkle_disputes_onchain,
                    args.force_false_cce_dispute_onchain,
                    args.force_false_cce_dispute_id,
                    args.perm_session_id
                );
            });
        }

        if (args.include_buyers) {
            auto buyers = buyers_future.get();
            buyers_dump = buyers;
            runs.push_back(make_run_from_bidders(DatasetKind::Buyers, true, buyers));
        }

        if (args.include_sellers) {
            auto sellers = sellers_future.get();
            sellers_dump = sellers;
            runs.push_back(make_run_from_bidders(DatasetKind::Sellers, false, sellers));
        }

        if (runs.empty()) {
            throw std::runtime_error("No datasets selected for sorting");
        }

        try {
            save_sharebids_p1_json(args.sharebids_out, buyers_dump, sellers_dump);
            std::cout << "P1: saved share bids json: "
                      << args.sharebids_out << "\n";
        } catch (const std::exception& ex) {
            std::cerr << "P1: WARNING could not save share bids json: "
                      << ex.what() << "\n";
        }

        std::cout << "P1: connecting to P0 "
                  << args.p0_ip << ":" << args.p0_port << "...\n";

        int sock_p0 = connect_to_retry(
            args.p0_ip,
            args.p0_port,
            30,
            500
        );

        std::cout << "P1: connected to P0\n";

        // Align P0/P1 valid bidder sets before opening P2.
        // P0 sends canonical order. P1 filters its local data to the intersection.
        {
            std::vector<std::string> p0_buyer_names = recv_string_vector(sock_p0);
            std::vector<std::string> p1_buyer_names = names_from_good_bidders(buyers_dump);
            send_string_vector(sock_p0, p1_buyer_names);

            std::vector<std::string> p0_seller_names = recv_string_vector(sock_p0);
            std::vector<std::string> p1_seller_names = names_from_good_bidders(sellers_dump);
            send_string_vector(sock_p0, p1_seller_names);

            align_good_bidders_to_p0_canonical_order(buyers_dump, p0_buyer_names, p1_buyer_names, "P1", "buyer");
            align_good_bidders_to_p0_canonical_order(sellers_dump, p0_seller_names, p1_seller_names, "P1", "seller");

            rebuild_runs_after_alignment(runs, buyers_dump, sellers_dump, args.include_buyers, args.include_sellers);

            try {
                save_sharebids_p1_json(args.sharebids_out, buyers_dump, sellers_dump);
                std::cout << "P1: saved ALIGNED share bids json: " << args.sharebids_out << "\n";
            } catch (const std::exception& ex) {
                std::cerr << "P1: WARNING could not save aligned share bids json: " << ex.what() << "\n";
            }
        }

        // Protocol termination rule after honest-set alignment:
        // If the number of honest buyers and honest sellers is not equal, the auction must end
        // before MPC sorting/clearing. If both sides are equal and non-zero, the auction may continue.
        {
            const uint64_t aligned_buyer_count = buyers_dump.has_value() ? static_cast<uint64_t>(buyers_dump->order.size()) : 0;
            const uint64_t aligned_seller_count = sellers_dump.has_value() ? static_cast<uint64_t>(sellers_dump->order.size()) : 0;

            if (aligned_buyer_count == 0 || aligned_seller_count == 0 || aligned_buyer_count != aligned_seller_count) {
                std::cout << "P1: honest buyer/seller counts are unequal or zero after dispute filtering. "
                          << "honest_buyers=" << aligned_buyer_count
                          << " honest_sellers=" << aligned_seller_count
                          << ". Auction ends with no trade; MPC sorting and P2 connection are skipped.\n";

                if (args.submit_auction_result_onchain) {
                    try {
                        submit_auction_result_to_contract(
                            args.node_path,
                            args.submit_result_tool,
                            args.chain_rpc,
                            args.perm_registry_contract,
                            args.eth_priv_file,
                            args.perm_session_id,
                            1,
                            0,
                            0,
                            0,
                            std::vector<uint64_t>{},
                            std::vector<uint64_t>{}
                        );

                        if (args.submit_winner_ids_poseidon_hashes_onchain) {
                            const auto padded_winner_buyer_ids = pad_winner_ids_for_poseidon(
                                std::vector<uint64_t>{},
                                args.nbuyers,
                                args.nsellers
                            );
                            const auto padded_winner_seller_ids = pad_winner_ids_for_poseidon(
                                std::vector<uint64_t>{},
                                args.nbuyers,
                                args.nsellers
                            );

                            submit_winner_ids_poseidon_hashes_to_contract(
                                args.node_path,
                                args.submit_winner_ids_poseidon_hashes_tool,
                                args.chain_rpc,
                                args.perm_registry_contract,
                                args.eth_priv_file,
                                args.perm_session_id,
                                1,
                                padded_winner_buyer_ids,
                                padded_winner_seller_ids
                            );

                            std::cout << "P1: submitted NO-TRADE winner-ID Poseidon hashes on-chain"
                                      << " session_id=" << args.perm_session_id
                                      << " party_id=1"
                                      << " padded_winner_count=" << padded_winner_buyer_ids.size()
                                      << "\n";
                        } else {
                            std::cout << "P1: NO-TRADE winner-ID Poseidon hash submit disabled by --disable-winner-hash-submit\n";
                        }

                        std::cout << "P1: submitted NO-TRADE auction result on-chain"
                                  << " session_id=" << args.perm_session_id
                                  << " party_id=1 K=0 Pb=0 Ps=0 winner_count=0\n";
                    } catch (const std::exception& ex) {
                        std::cerr << "P1: ERROR could not submit NO-TRADE auction result on-chain: "
                                  << ex.what() << "\n";
                        throw;
                    }
                } else {
                    std::cout << "P1: no-trade auction result submit disabled by --disable-result-submit\n";
                }

            close(sock_p0);
                return 0;
            }

            std::cout << "P1: honest buyer/seller counts are equal and non-zero after dispute filtering. "
                      << "honest_buyers=" << aligned_buyer_count
                      << " honest_sellers=" << aligned_seller_count
                      << ". Auction continues to MPC sorting/clearing.\n";
        }

        int listener_p2 = create_listener(args.p2_listen_port);

        std::cout << "P1: waiting for P2 on port "
                  << args.p2_listen_port << "...\n";

        int sock_p2 = accept(listener_p2, nullptr, nullptr);

        if (sock_p2 < 0) {
            close(sock_p0);
            close(listener_p2);
            throw std::runtime_error("accept P2 failed");
        }

        std::cout << "P1: P2 connected\n";

        uint64_t dataset_count = recv_u64(sock_p0);

        if (dataset_count != runs.size()) {
            throw std::runtime_error("P1 dataset count mismatch with P0");
        }

        std::optional<SortedResult> buyer_result;
        std::optional<SortedResult> seller_result;

        for (size_t run_idx = 0; run_idx < runs.size(); ++run_idx) {
            const RunConfig& run = runs[run_idx];

            std::vector<uint64_t> bid_shares = run.bid_shares;
            std::vector<uint64_t> id_shares = run.id_shares;

            uint64_t n = bid_shares.size();

            std::vector<uint64_t> orig_id_shares = id_shares;

            uint64_t dataset_kind_wire = recv_u64(sock_p0);
            uint64_t n_wire = recv_u64(sock_p0);
            uint64_t descending_flag = recv_u64(sock_p0);

            bool descending_wire = descending_flag != 0;

            if (dataset_kind_wire != static_cast<uint64_t>(run.kind)) {
                throw std::runtime_error("P1 dataset ordering mismatch with P0");
            }

            if (n_wire != n || n_wire != id_shares.size()) {
                throw std::runtime_error("P1 received unexpected bid count for dataset");
            }

            if (descending_wire != run.descending) {
                throw std::runtime_error("P1 mode mismatch with P0");
            }

            std::vector<uint64_t> peer_orig_id_shares(n);
            recv_u64_vector(sock_p0, peer_orig_id_shares);
            send_u64_vector(sock_p0, orig_id_shares);

            std::vector<uint64_t> a_bid_share(n), c_bid_share(n);
            std::vector<uint64_t> a_id_share(n), c_id_share(n);
            std::vector<uint64_t> b_share(n * n), w_share(n * n);

            recv_u64_vector(sock_p2, a_bid_share);
            recv_u64_vector(sock_p2, c_bid_share);
            recv_u64_vector(sock_p2, a_id_share);
            recv_u64_vector(sock_p2, c_id_share);
            recv_u64_vector(sock_p2, b_share);
            recv_u64_vector(sock_p2, w_share);

            std::vector<uint64_t> e_bid_peer(n);
            recv_u64_vector(sock_p0, e_bid_peer);

            std::vector<uint64_t> e_bid_local(n);

            for (uint64_t i = 0; i < n; ++i) {
                e_bid_local[i] = sub_wrap(bid_shares[i], a_bid_share[i]);
            }

            send_u64_vector(sock_p0, e_bid_local);

            std::vector<uint64_t> e_bid_total(n);

            for (uint64_t i = 0; i < n; ++i) {
                e_bid_total[i] = add_wrap(e_bid_local[i], e_bid_peer[i]);
            }

            std::vector<uint64_t> e_id_peer(n);
            recv_u64_vector(sock_p0, e_id_peer);

            std::vector<uint64_t> e_id_local(n);

            for (uint64_t i = 0; i < n; ++i) {
                e_id_local[i] = sub_wrap(id_shares[i], a_id_share[i]);
            }

            send_u64_vector(sock_p0, e_id_local);

            std::vector<uint64_t> e_id_total(n);

            for (uint64_t i = 0; i < n; ++i) {
                e_id_total[i] = add_wrap(e_id_local[i], e_id_peer[i]);
            }

            std::vector<uint64_t> f_peer(n * n);
            recv_u64_vector(sock_p0, f_peer);

            std::vector<uint64_t> f_local(n * n);

            for (uint64_t idx = 0; idx < n * n; ++idx) {
                f_local[idx] = sub_wrap(w_share[idx], b_share[idx]);
            }

            send_u64_vector(sock_p0, f_local);

            std::vector<uint64_t> f_total(n * n);

            for (uint64_t idx = 0; idx < n * n; ++idx) {
                f_total[idx] = add_wrap(f_local[idx], f_peer[idx]);
            }

            bid_shares = apply_shuffle_masks(
                c_bid_share,
                a_bid_share,
                b_share,
                e_bid_total,
                f_total,
                n,
                false
            );

            id_shares = apply_shuffle_masks(
                c_id_share,
                a_id_share,
                b_share,
                e_id_total,
                f_total,
                n,
                false
            );

            const size_t comparisons = n * (n - 1) / 2;
            const auto schedule = build_bubble_schedule(n);

            uint64_t total_triples = recv_u64(sock_p2);

            if (total_triples != comparisons * 5) {
                throw std::runtime_error("P1 triple count mismatch");
            }

            std::vector<CompareTriples> triples(comparisons);
            std::vector<uint64_t> triple_buffer(total_triples * 3);

            recv_u64_vector(sock_p2, triple_buffer);

            size_t cur = 0;

            for (size_t i = 0; i < comparisons; ++i) {
                auto& t = triples[i];

                t.t2.a = triple_buffer[cur++];
                t.t2.b = triple_buffer[cur++];
                t.t2.c = triple_buffer[cur++];

                t.bid_f_y_minus_x.a = triple_buffer[cur++];
                t.bid_f_y_minus_x.b = triple_buffer[cur++];
                t.bid_f_y_minus_x.c = triple_buffer[cur++];

                t.bid_f_x_minus_y.a = triple_buffer[cur++];
                t.bid_f_x_minus_y.b = triple_buffer[cur++];
                t.bid_f_x_minus_y.c = triple_buffer[cur++];

                t.id_f_y_minus_x.a = triple_buffer[cur++];
                t.id_f_y_minus_x.b = triple_buffer[cur++];
                t.id_f_y_minus_x.c = triple_buffer[cur++];

                t.id_f_x_minus_y.a = triple_buffer[cur++];
                t.id_f_x_minus_y.b = triple_buffer[cur++];
                t.id_f_x_minus_y.c = triple_buffer[cur++];
            }

            size_t compare_idx = 0;

            for (const auto& cmp : schedule) {
                uint64_t i = cmp.first;
                uint64_t j = cmp.second;

                CompareTriples& triple = triples[compare_idx++];

                uint64_t diff_share = sub_wrap(bid_shares[i], bid_shares[j]);

                uint64_t r_share = (random_mask31() << 1);

                uint64_t d_local_t2 = sub_wrap(diff_share, triple.t2.a);
                uint64_t e_local_t2 = sub_wrap(r_share, triple.t2.b);

                uint64_t d_peer_t2 = 0;
                uint64_t e_peer_t2 = 0;

                recv_u64_pair(sock_p0, d_peer_t2, e_peer_t2);
                send_u64_pair(sock_p0, d_local_t2, e_local_t2);

                uint64_t d_t2 = add_wrap(d_local_t2, d_peer_t2);
                uint64_t e_t2 = add_wrap(e_local_t2, e_peer_t2);

                uint64_t t2_share = triple.t2.c;
                t2_share = add_wrap(t2_share, mul_wrap(d_t2, triple.t2.b));
                t2_share = add_wrap(t2_share, mul_wrap(e_t2, triple.t2.a));

                send_u64(sock_p2, t2_share);

                uint64_t swap_flag_share = recv_u64(sock_p2);

                uint64_t y_minus_x = sub_wrap(bid_shares[j], bid_shares[i]);

                uint64_t d_local_fyx =
                    sub_wrap(swap_flag_share, triple.bid_f_y_minus_x.a);
                uint64_t e_local_fyx =
                    sub_wrap(y_minus_x, triple.bid_f_y_minus_x.b);

                uint64_t d_peer_fyx = 0;
                uint64_t e_peer_fyx = 0;

                recv_u64_pair(sock_p0, d_peer_fyx, e_peer_fyx);
                send_u64_pair(sock_p0, d_local_fyx, e_local_fyx);

                uint64_t d_fyx = add_wrap(d_local_fyx, d_peer_fyx);
                uint64_t e_fyx = add_wrap(e_local_fyx, e_peer_fyx);

                uint64_t product_fyx = triple.bid_f_y_minus_x.c;
                product_fyx = add_wrap(
                    product_fyx,
                    mul_wrap(d_fyx, triple.bid_f_y_minus_x.b)
                );
                product_fyx = add_wrap(
                    product_fyx,
                    mul_wrap(e_fyx, triple.bid_f_y_minus_x.a)
                );

                uint64_t x_minus_y = diff_share;

                uint64_t d_local_fxy =
                    sub_wrap(swap_flag_share, triple.bid_f_x_minus_y.a);
                uint64_t e_local_fxy =
                    sub_wrap(x_minus_y, triple.bid_f_x_minus_y.b);

                uint64_t d_peer_fxy = 0;
                uint64_t e_peer_fxy = 0;

                recv_u64_pair(sock_p0, d_peer_fxy, e_peer_fxy);
                send_u64_pair(sock_p0, d_local_fxy, e_local_fxy);

                uint64_t d_fxy = add_wrap(d_local_fxy, d_peer_fxy);
                uint64_t e_fxy = add_wrap(e_local_fxy, e_peer_fxy);

                uint64_t product_fxy = triple.bid_f_x_minus_y.c;
                product_fxy = add_wrap(
                    product_fxy,
                    mul_wrap(d_fxy, triple.bid_f_x_minus_y.b)
                );
                product_fxy = add_wrap(
                    product_fxy,
                    mul_wrap(e_fxy, triple.bid_f_x_minus_y.a)
                );

                bid_shares[i] = add_wrap(bid_shares[i], product_fyx);
                bid_shares[j] = add_wrap(bid_shares[j], product_fxy);

                uint64_t id_y_minus_x =
                    sub_wrap(id_shares[j], id_shares[i]);

                uint64_t d_local_id_fyx =
                    sub_wrap(swap_flag_share, triple.id_f_y_minus_x.a);
                uint64_t e_local_id_fyx =
                    sub_wrap(id_y_minus_x, triple.id_f_y_minus_x.b);

                uint64_t d_peer_id_fyx = 0;
                uint64_t e_peer_id_fyx = 0;

                recv_u64_pair(sock_p0, d_peer_id_fyx, e_peer_id_fyx);
                send_u64_pair(sock_p0, d_local_id_fyx, e_local_id_fyx);

                uint64_t d_id_fyx = add_wrap(d_local_id_fyx, d_peer_id_fyx);
                uint64_t e_id_fyx = add_wrap(e_local_id_fyx, e_peer_id_fyx);

                uint64_t product_id_fyx = triple.id_f_y_minus_x.c;
                product_id_fyx = add_wrap(
                    product_id_fyx,
                    mul_wrap(d_id_fyx, triple.id_f_y_minus_x.b)
                );
                product_id_fyx = add_wrap(
                    product_id_fyx,
                    mul_wrap(e_id_fyx, triple.id_f_y_minus_x.a)
                );

                uint64_t id_x_minus_y =
                    sub_wrap(id_shares[i], id_shares[j]);

                uint64_t d_local_id_fxy =
                    sub_wrap(swap_flag_share, triple.id_f_x_minus_y.a);
                uint64_t e_local_id_fxy =
                    sub_wrap(id_x_minus_y, triple.id_f_x_minus_y.b);

                uint64_t d_peer_id_fxy = 0;
                uint64_t e_peer_id_fxy = 0;

                recv_u64_pair(sock_p0, d_peer_id_fxy, e_peer_id_fxy);
                send_u64_pair(sock_p0, d_local_id_fxy, e_local_id_fxy);

                uint64_t d_id_fxy = add_wrap(d_local_id_fxy, d_peer_id_fxy);
                uint64_t e_id_fxy = add_wrap(e_local_id_fxy, e_peer_id_fxy);

                uint64_t product_id_fxy = triple.id_f_x_minus_y.c;
                product_id_fxy = add_wrap(
                    product_id_fxy,
                    mul_wrap(d_id_fxy, triple.id_f_x_minus_y.b)
                );
                product_id_fxy = add_wrap(
                    product_id_fxy,
                    mul_wrap(e_id_fxy, triple.id_f_x_minus_y.a)
                );

                id_shares[i] = add_wrap(id_shares[i], product_id_fyx);
                id_shares[j] = add_wrap(id_shares[j], product_id_fxy);
            }

            std::vector<uint64_t> peer_bid(n);
            std::vector<uint64_t> peer_id(n);

            recv_u64_vector(sock_p0, peer_bid);
            recv_u64_vector(sock_p0, peer_id);

            send_u64_vector(sock_p0, bid_shares);
            send_u64_vector(sock_p0, id_shares);

            std::vector<int64_t> id_totals(n);

            for (uint64_t i = 0; i < n; ++i) {
                id_totals[i] = to_signed(add_wrap(peer_id[i], id_shares[i]));
            }

            std::vector<int64_t> orig_id_totals(n);

            for (uint64_t i = 0; i < n; ++i) {
                orig_id_totals[i] = to_signed(
                    add_wrap(peer_orig_id_shares[i], orig_id_shares[i])
                );
            }

            std::vector<uint64_t> perm_index_1based =
                compute_perm_from_ids(orig_id_totals, id_totals);

            std::cout << "P1: permutation index vector for dataset ["
                      << run.label << "] = [";

            for (size_t i = 0; i < perm_index_1based.size(); ++i) {
                std::cout << perm_index_1based[i]
                          << (i + 1 == perm_index_1based.size() ? "" : ", ");
            }

            std::cout << "]\n";

            try {
                std::string pos_hash =
                    compute_poseidon_hash_js(
                        args.node_path,
                        args.poseidon_script,
                        perm_index_1based
                    );

                std::string json_path =
                    "permutation_" +
                    std::to_string(static_cast<uint64_t>(run.kind)) +
                    "_p1.json";

                save_perm_json(
                    json_path,
                    run.label,
                    n,
                    perm_index_1based,
                    pos_hash
                );
                if (args.submit_perm_hash_onchain) {
                try {
                submit_perm_hash_to_contract(
                args.node_path,
                args.submit_hash_tool,
                args.chain_rpc,
                args.perm_registry_contract,
                args.eth_priv_file,
                args.perm_session_id,
                static_cast<uint64_t>(run.kind),
                1,
                pos_hash
            );

            std::cout << "P1: submitted permutation hash to smart contract"
                  << " session_id=" << args.perm_session_id
                  << " dataset_kind=" << static_cast<uint64_t>(run.kind)
                  << " party_id=1"
                  << " hash=" << pos_hash
                  << "\n";
        } catch (const std::exception& ex) {
            std::cerr << "P1: ERROR could not submit permutation hash on-chain: "
                  << ex.what() << "\n";
            throw;
        }
    }

                std::vector<uint64_t> sorted_share_bid_vector =
                    apply_perm_1based_to_u64_vector(run.bid_shares, perm_index_1based);

                std::string sorted_share_bid_hash =
                    compute_poseidon_hash_js(
                        args.node_path,
                        args.poseidon_script,
                        sorted_share_bid_vector
                    );

                std::string sorted_share_json_path =
                    "sorted_share_bids_" +
                    std::to_string(static_cast<uint64_t>(run.kind)) +
                    "_p1.json";

                save_sorted_share_bids_hash_json(
                    sorted_share_json_path,
                    run.label,
                    n,
                    sorted_share_bid_vector,
                    sorted_share_bid_hash
                );

                if (args.submit_sorted_share_bids_hashes_onchain) {
                    try {
                        submit_sorted_share_bids_hash_to_contract(
                            args.node_path,
                            args.submit_sorted_share_bids_hash_tool,
                            args.chain_rpc,
                            args.perm_registry_contract,
                            args.eth_priv_file,
                            args.perm_session_id,
                            static_cast<uint64_t>(run.kind),
                            1,
                            sorted_share_bid_hash
                        );

                        std::cout << "P1: submitted sorted share-bid vector hash to smart contract"
                                  << " session_id=" << args.perm_session_id
                                  << " dataset_kind=" << static_cast<uint64_t>(run.kind)
                                  << " party_id=1"
                                  << " hash=" << sorted_share_bid_hash
                                  << "\n";
                    } catch (const std::exception& ex) {
                        std::cerr << "P1: ERROR could not submit sorted share-bid vector hash on-chain: "
                                  << ex.what() << "\n";
                        throw;
                    }
                }

                std::cout << "P1: saved sorted share-bid vector hash json: " << sorted_share_json_path << "\n";
                std::cout << "P1: sorted share-bid vector hash poseidon = " << sorted_share_bid_hash << "\n";

                std::cout << "P1: saved permutation json: "
                          << json_path << "\n";
                std::cout << "P1: perm hash poseidon = "
                          << pos_hash << "\n";
            } catch (const std::exception& ex) {
                std::cerr << "P1: WARNING could not compute/save poseidon hash: "
                          << ex.what() << "\n";
            }

            SortedResult res;
            res.run = run;
            res.bid_shares = bid_shares;
            res.id_shares = id_shares;
            res.peer_bid_shares = peer_bid;
            res.peer_id_shares = peer_id;
            res.id_totals = id_totals;
            res.perm_index_1based = perm_index_1based;

            if (run.kind == DatasetKind::Buyers) {
                buyer_result = res;
            } else {
                seller_result = res;
            }
        }

        bool have_auction_result = false;
        uint64_t auction_K = 0;
        uint64_t auction_Pb = 0;
        uint64_t auction_Ps = 0;
        std::vector<uint64_t> auction_winner_buyer_ids;
        std::vector<uint64_t> auction_winner_seller_ids;

        uint64_t clearing_flag = recv_u64(sock_p0);
        send_u64(sock_p2, clearing_flag);

        if (clearing_flag) {
            if (!buyer_result.has_value() || !seller_result.has_value()) {
                throw std::runtime_error("P1 clearing requested but buyer/seller result missing");
            }

            const auto& buyers = buyer_result.value();
            const auto& sellers = seller_result.value();

            uint64_t buyer_count = recv_u64(sock_p0);
            uint64_t seller_count = recv_u64(sock_p0);

            if (buyer_count != buyers.bid_shares.size() ||
                seller_count != sellers.bid_shares.size()) {
                throw std::runtime_error("P1 clearing sizes mismatch");
            }

            uint64_t total_triples = recv_u64(sock_p2);
            uint64_t clearing_pairs = std::min(buyer_count, seller_count);

            if (total_triples != clearing_pairs * 6) {
                throw std::runtime_error("P1 clearing triple count mismatch");
            }

            std::vector<uint64_t> triple_buffer(total_triples * 3);
            recv_u64_vector(sock_p2, triple_buffer);

            std::vector<ClearingTriples> clearing_triples(clearing_pairs);

            size_t cur2 = 0;

            for (uint64_t k = 0; k < clearing_pairs; ++k) {
                auto& t = clearing_triples[k];

                t.cond1_t2.a = triple_buffer[cur2++];
                t.cond1_t2.b = triple_buffer[cur2++];
                t.cond1_t2.c = triple_buffer[cur2++];

                t.ge_forward_t2.a = triple_buffer[cur2++];
                t.ge_forward_t2.b = triple_buffer[cur2++];
                t.ge_forward_t2.c = triple_buffer[cur2++];

                t.ge_reverse_t2.a = triple_buffer[cur2++];
                t.ge_reverse_t2.b = triple_buffer[cur2++];
                t.ge_reverse_t2.c = triple_buffer[cur2++];

                t.eq_and.a = triple_buffer[cur2++];
                t.eq_and.b = triple_buffer[cur2++];
                t.eq_and.c = triple_buffer[cur2++];

                t.final_and.a = triple_buffer[cur2++];
                t.final_and.b = triple_buffer[cur2++];
                t.final_and.c = triple_buffer[cur2++];

                t.k_update.a = triple_buffer[cur2++];
                t.k_update.b = triple_buffer[cur2++];
                t.k_update.c = triple_buffer[cur2++];
            }

            uint64_t k_share = 0;

            auto run_compare = [&](uint64_t lhs_share, uint64_t rhs_share, const BeaverShare& triple) {
                uint64_t diff_share = sub_wrap(lhs_share, rhs_share);
                uint64_t r_share = (random_mask31() << 1);

                uint64_t d_self = sub_wrap(diff_share, triple.a);
                uint64_t e_self = sub_wrap(r_share, triple.b);

                uint64_t d_peer = 0;
                uint64_t e_peer = 0;

                recv_u64_pair(sock_p0, d_peer, e_peer);
                send_u64_pair(sock_p0, d_self, e_self);

                uint64_t d = add_wrap(d_self, d_peer);
                uint64_t e = add_wrap(e_self, e_peer);

                uint64_t product = triple.c;
                product = add_wrap(product, mul_wrap(d, triple.b));
                product = add_wrap(product, mul_wrap(e, triple.a));

                send_u64(sock_p2, product);

                return recv_u64(sock_p2);
            };

            auto beaver_product = [&](uint64_t x_share, uint64_t y_share, const BeaverShare& triple) {
                uint64_t d_self = sub_wrap(x_share, triple.a);
                uint64_t e_self = sub_wrap(y_share, triple.b);

                uint64_t d_peer = 0;
                uint64_t e_peer = 0;

                recv_u64_pair(sock_p0, d_peer, e_peer);
                send_u64_pair(sock_p0, d_self, e_self);

                uint64_t d = add_wrap(d_self, d_peer);
                uint64_t e = add_wrap(e_self, e_peer);

                uint64_t product = triple.c;
                product = add_wrap(product, mul_wrap(d, triple.b));
                product = add_wrap(product, mul_wrap(e, triple.a));

                return product;
            };

            for (uint64_t k = 0; k < clearing_pairs; ++k) {
                const auto& t = clearing_triples[k];

                uint64_t ge_bid_vs_ask =
                    run_compare(
                        buyers.bid_shares[k],
                        sellers.bid_shares[k],
                        t.cond1_t2
                    );

                const uint64_t one_share = 0;
                uint64_t neq_flag = one_share;

                if (k > 0) {
                    uint64_t ge_forward =
                        run_compare(
                            buyers.bid_shares[k],
                            buyers.bid_shares[k - 1],
                            t.ge_forward_t2
                        );

                    uint64_t ge_reverse =
                        run_compare(
                            buyers.bid_shares[k - 1],
                            buyers.bid_shares[k],
                            t.ge_reverse_t2
                        );

                    uint64_t eq_share =
                        beaver_product(
                            ge_forward,
                            ge_reverse,
                            t.eq_and
                        );

                    neq_flag = sub_wrap(one_share, eq_share);
                }

                uint64_t final_flag =
                    beaver_product(
                        ge_bid_vs_ask,
                        neq_flag,
                        t.final_and
                    );

                uint64_t delta =
                    sub_wrap(static_cast<uint64_t>(0), k_share);

                uint64_t update =
                    beaver_product(
                        final_flag,
                        delta,
                        t.k_update
                    );

                k_share = add_wrap(k_share, update);
            }

            uint64_t k_peer = recv_u64(sock_p0);
            send_u64(sock_p0, k_share);

            uint64_t k_total = add_wrap(k_share, k_peer);

            if (k_total == 0 || k_total > clearing_pairs) {
                std::cout << "P1: clearing stage found no valid trades\n";
                have_auction_result = true;
                auction_K = 0;
                auction_Pb = 0;
                auction_Ps = 0;
                auction_winner_buyer_ids.clear();
                auction_winner_seller_ids.clear();
            } else {
                uint64_t winner_count = k_total - 1;
                uint64_t idx = k_total - 1;

                uint64_t Pb =
                    add_wrap(
                        buyers.bid_shares[idx],
                        buyers.peer_bid_shares[idx]
                    );

                uint64_t Ps =
                    add_wrap(
                        sellers.bid_shares[idx],
                        sellers.peer_bid_shares[idx]
                    );

                have_auction_result = true;
                auction_K = k_total;
                auction_Pb = Pb;
                auction_Ps = Ps;
                auction_winner_buyer_ids.clear();
                auction_winner_seller_ids.clear();

                for (uint64_t i = 0; i < winner_count; ++i) {
                    auction_winner_buyer_ids.push_back(
                        static_cast<uint64_t>(buyers.id_totals[i])
                    );
                    auction_winner_seller_ids.push_back(
                        static_cast<uint64_t>(sellers.id_totals[i])
                    );
                }

                std::cout << "P1: clearing index K=" << k_total << "\n";
                std::cout << "P1: buyer clearing price Pb=" << Pb << "\n";
                std::cout << "P1: seller clearing price Ps=" << Ps << "\n";

                std::cout << "P1: winning buyers IDs:\n";

                for (uint64_t i = 0; i < winner_count; ++i) {
                    std::cout << "  buyer "
                              << auction_winner_buyer_ids[i]
                              << "\n";
                }

                std::cout << "P1: winning sellers IDs:\n";

                for (uint64_t i = 0; i < winner_count; ++i) {
                    std::cout << "  seller "
                              << auction_winner_seller_ids[i]
                              << "\n";
                }
            }
        }

        if (args.submit_auction_result_onchain && have_auction_result) {
            try {
                submit_auction_result_to_contract(
                    args.node_path,
                    args.submit_result_tool,
                    args.chain_rpc,
                    args.perm_registry_contract,
                    args.eth_priv_file,
                    args.perm_session_id,
                    1,
                    auction_K,
                    auction_Pb,
                    auction_Ps,
                    auction_winner_buyer_ids,
                    auction_winner_seller_ids
                );

                if (args.submit_winner_ids_poseidon_hashes_onchain) {
                    const auto padded_winner_buyer_ids = pad_winner_ids_for_poseidon(
                        auction_winner_buyer_ids,
                        args.nbuyers,
                        args.nsellers
                    );
                    const auto padded_winner_seller_ids = pad_winner_ids_for_poseidon(
                        auction_winner_seller_ids,
                        args.nbuyers,
                        args.nsellers
                    );

                    submit_winner_ids_poseidon_hashes_to_contract(
                        args.node_path,
                        args.submit_winner_ids_poseidon_hashes_tool,
                        args.chain_rpc,
                        args.perm_registry_contract,
                        args.eth_priv_file,
                        args.perm_session_id,
                        1,
                        padded_winner_buyer_ids,
                        padded_winner_seller_ids
                    );

                    std::cout << "P1: submitted winner-ID Poseidon hashes on-chain"
                              << " session_id=" << args.perm_session_id
                              << " party_id=1"
                              << " padded_winner_count=" << padded_winner_buyer_ids.size()
                              << "\n";
                } else {
                    std::cout << "P1: winner-ID Poseidon hash submit disabled by --disable-winner-hash-submit\n";
                }

                std::cout << "P1: submitted auction result on-chain"
                          << " session_id=" << args.perm_session_id
                          << " party_id=1"
                          << " K=" << auction_K
                          << " Pb=" << auction_Pb
                          << " Ps=" << auction_Ps
                          << " winner_count=" << auction_winner_buyer_ids.size()
                          << "\n";

                if (args.report_cce_disputes_onchain && args.finalize_cce_checks_after_result) {
                    finalize_cce_check_requests_to_contract(
                        args.node_path,
                        args.finalize_cce_checks_tool,
                        args.chain_rpc,
                        args.dispute_manager_contract,
                        args.eth_priv_file,
                        args.perm_session_id,
                        1
                    );
                }
            } catch (const std::exception& ex) {
                std::cerr << "P1: ERROR could not submit auction result on-chain: "
                          << ex.what() << "\n";
                throw;
            }
        } else if (!args.submit_auction_result_onchain) {
            std::cout << "P1: auction result on-chain submit disabled by --disable-result-submit\n";
        }

        std::vector<RevealedRandomnessRec> revealed_recs;
        bool have_revealed_recs = false;

        try {
            std::cout << "P1: requesting r1_dec from bidder-boss "
                      << args.boss_ip << ":" << args.boss_reveal_port
                      << " ...\n";

            revealed_recs =
                request_randomness_from_boss(
                    args.boss_ip,
                    args.boss_reveal_port,
                    1
                );

            have_revealed_recs = true;

            save_revealed_randomness_json(
                args.reveal_out,
                "p1",
                1,
                revealed_recs,
                buyers_dump,
                sellers_dump
            );

            std::cout << "P1: saved revealed randomness + share bids to "
                      << args.reveal_out
                      << " count=" << revealed_recs.size()
                      << "\n";

        } catch (const std::exception& ex) {
            std::cerr << "P1: WARNING could not request/save randomness from boss: "
                      << ex.what() << "\n";
        }

        if (args.send_perm_to_prover) {
            try {
                if (!have_revealed_recs) {
                    throw std::runtime_error(
                        "cannot send ProverParty payload without revealed commitment randomness"
                    );
                }

                if (buyer_result.has_value() && buyers_dump.has_value()) {
                    sign_encrypt_send_dataset_payload_to_prover(
                        args.node_path,
                        args.perm_payload_tool,
                        args.p1_signing_seed_path,
                        args.prover_pub_path,
                        args.prover_host,
                        args.prover_port,
                        args.perm_payload_out_dir,
                        args.perm_session_id,
                        args.perm_max_n,
                        "p1",
                        1,
                        buyer_result.value(),
                        buyers_dump.value(),
                        revealed_recs,
                        args.submit_vector_hashes_onchain,
                        args.submit_vector_hashes_tool,
                        args.chain_rpc,
                        args.perm_registry_contract,
                        args.eth_priv_file
                    );
                }

                if (seller_result.has_value() && sellers_dump.has_value()) {
                    sign_encrypt_send_dataset_payload_to_prover(
                        args.node_path,
                        args.perm_payload_tool,
                        args.p1_signing_seed_path,
                        args.prover_pub_path,
                        args.prover_host,
                        args.prover_port,
                        args.perm_payload_out_dir,
                        args.perm_session_id,
                        args.perm_max_n,
                        "p1",
                        1,
                        seller_result.value(),
                        sellers_dump.value(),
                        revealed_recs,
                        args.submit_vector_hashes_onchain,
                        args.submit_vector_hashes_tool,
                        args.chain_rpc,
                        args.perm_registry_contract,
                        args.eth_priv_file
                    );
                }
            } catch (const std::exception& ex) {
                std::cerr << "P1: ERROR sending encrypted signed reveal payload to ProverParty: "
                          << ex.what() << "\n";

                close(sock_p2);
                close(listener_p2);
                close(sock_p0);

                return 1;
            }
        } else {
            std::cout << "P1: prover payload send disabled by --disable-prover-send\n";
        }

        close(sock_p2);
        close(listener_p2);
        close(sock_p0);

        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "P1 error: " << ex.what() << "\n";
        return 1;
    }
}




