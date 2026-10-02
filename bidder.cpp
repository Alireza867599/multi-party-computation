// bidder.cpp
// Normal bidder creates additive shares, BabyJub commitments, encrypted packets,
// CCE proofs, and signatures. It sends the complete signed packet to BidderBoss.
// BidderBoss must only sign a receipt, build Merkle trees, and relay the packet.
//
// Build:
//   g++ -O2 -std=c++17 bidder.cpp -lcrypto -o bidder
//
// Submit example:
//   ./bidder --mode submit --boss 127.0.0.1 --port 7500 --session-id 0 \
//     --role buyer --name Alice --bid 90 --id 101 \
//     --p0pub keys/p0.elg.pub --p1pub keys/p1.elg.pub \
//     --chain-rpc http://127.0.0.1:8545 \
//     --auction-registry 0x5FbDB2315678afecb367f032d93F642f64180aa3 \
//     --eth-priv keys/Alice.eth.priv \
//     --out receipts/Alice_receipt.json
//
// Default behavior in submit mode:
//   after BidderBoss sends root/path, bidder verifies the path locally.
//   if the path is missing/invalid, bidder automatically sends challenge to contract.
//
// Manual challenge example:
//   ./bidder --mode challenge --receipt-file receipts/Alice_receipt.json \
//     --chain-rpc http://127.0.0.1:8545 \
//     --auction-registry 0x5FbDB2315678afecb367f032d93F642f64180aa3 \
//     --eth-priv keys/Alice.eth.priv
//
// Invalid CCE test flags (work for both buyers and sellers):
//   --invalid-cce-p0        make only the P0 packet invalid
//   --invalid-cce-p1        make only the P1 packet invalid
//   --invalid-cce-both      make both P0 and P1 packets invalid
//   --invalid-cce-delta 1   difference added to encrypted/opened share
//
// Required helper scripts in current working directory:
//   node babyjub_commit.js ...
//   node babyjub_schnorr_open.js ...
//   node js/sign_cce_packet.js ...
//   node scripts/challenge_commitment_exclusion.js ...

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

static const char* WIRE_MAGIC = "SFDAC-BIDDER-PACKET-V2";
static const char* DIRECT_MAGIC = "SFDAC-AUCTIONEER-DIRECT-V1";
static const char* SIGNED_PACKET_DOMAIN = "SFDAC-BIDDER-SIGNED-PACKET-V3";
static const std::string DEFAULT_COMMIT_DOMAIN = "SFDAC-BabyJub-Pedersen-v1";
static const std::string DEFAULT_CCE_DOMAIN = "PPCR-SIGMA-CCE-v1";
static const char* BABYJUB_SUBORDER_DEC =
    "2736030358979909402780800718157159386076813972158567259200215660948447373041";

struct Args {
    std::string mode = "submit"; // submit or challenge
    std::string boss_ip = "127.0.0.1";
    uint16_t port = 7500;
    // Option-1 direct delivery: bidder sends signed encrypted packet directly to P0/P1.
    std::string p0_host = "127.0.0.1";
    std::string p1_host = "127.0.0.1";
    uint16_t p0_buyer_port = 7000;
    uint16_t p1_buyer_port = 7001;
    uint16_t p0_seller_port = 7002;
    uint16_t p1_seller_port = 7003;
    uint64_t session_id = 0;
    std::string role;
    std::string name;
    uint64_t bid = 0;
    uint64_t id = 0;
    std::string p0_pub_path = "keys/p0.elg.pub";
    std::string p1_pub_path = "keys/p1.elg.pub";
    std::string ed25519_priv_dir = "keys";
    std::string bidder_eth_priv_dir = "keys";
    std::string commit_domain = DEFAULT_COMMIT_DOMAIN;
    std::string cce_domain = DEFAULT_CCE_DOMAIN;
    std::string chain_rpc;
    std::string auction_registry;
    std::string dispute_manager;
    std::string cce_packet_sign_tool = "js/sign_sigma_cce_packet.js";
    std::string commitment_packet_sign_tool = "js/sign_commitment_packet.js";
    std::string sigma_cce_proof_tool = "js/sigma_cce_prove.js";
    std::string derive_commitment_h_tool = "js/derive_commitment_H.js";
    std::string p0_babyjub_pub_path = "keys/p0.babyjub.pub.json";
    std::string p1_babyjub_pub_path = "keys/p1.babyjub.pub.json";
    std::string challenge_tool = "scripts/challenge_commitment_exclusion.js"; // updated script calls AuctionRegistry.submitBidderMerkleEvidenceChallenge
    std::string read_root_tool = "scripts/read_commitment_root.js";
    uint64_t path_check_delay_sec = 60;

    // Demo/test options: make the CCE proof invalid for P0 and/or P1 while
    // keeping bidder signatures valid. This works for both buyer and seller roles.
    // It simulates a bidder encrypting a share that is inconsistent with the
    // corresponding commitment. The affected auctioneer should detect this
    // off-chain and submit the signed packet to the contract as evidence.
    bool invalid_cce_p0 = false;
    bool invalid_cce_p1 = false;
    uint64_t invalid_cce_delta = 1;

    // TEST ONLY: send a different signed commitment packet directly to P0/P1
    // than the one sent to BidderBoss. This creates bidder equivocation evidence.
    bool inconsistent_p0_commitment = false;
    bool inconsistent_p1_commitment = false;
    uint64_t inconsistent_commitment_delta = 1;

    std::string eth_priv; // bidder Ethereum private key for automatic/manual challenge
    std::string out = "receipt.json";
    std::string receipt_file;
};

static std::string need(int& i, int argc, char** argv, const std::string& flag) {
    if (i + 1 >= argc) throw std::runtime_error("missing value for " + flag);
    return argv[++i];
}

static Args parse_args(int argc, char** argv) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        if (s == "--mode") a.mode = need(i, argc, argv, s);
        else if (s == "--boss") a.boss_ip = need(i, argc, argv, s);
        else if (s == "--port") a.port = static_cast<uint16_t>(std::stoul(need(i, argc, argv, s)));
        else if (s == "--p0-host") a.p0_host = need(i, argc, argv, s);
        else if (s == "--p1-host") a.p1_host = need(i, argc, argv, s);
        else if (s == "--p0-buyer-port") a.p0_buyer_port = static_cast<uint16_t>(std::stoul(need(i, argc, argv, s)));
        else if (s == "--p1-buyer-port") a.p1_buyer_port = static_cast<uint16_t>(std::stoul(need(i, argc, argv, s)));
        else if (s == "--p0-seller-port") a.p0_seller_port = static_cast<uint16_t>(std::stoul(need(i, argc, argv, s)));
        else if (s == "--p1-seller-port") a.p1_seller_port = static_cast<uint16_t>(std::stoul(need(i, argc, argv, s)));
        else if (s == "--session-id") a.session_id = std::stoull(need(i, argc, argv, s));
        else if (s == "--role") a.role = need(i, argc, argv, s);
        else if (s == "--name") a.name = need(i, argc, argv, s);
        else if (s == "--bid") a.bid = std::stoull(need(i, argc, argv, s));
        else if (s == "--id") a.id = std::stoull(need(i, argc, argv, s));
        else if (s == "--p0pub") a.p0_pub_path = need(i, argc, argv, s);
        else if (s == "--p1pub") a.p1_pub_path = need(i, argc, argv, s);
        else if (s == "--ed25519-priv-dir") a.ed25519_priv_dir = need(i, argc, argv, s);
        else if (s == "--bidder-eth-priv-dir") a.bidder_eth_priv_dir = need(i, argc, argv, s);
        else if (s == "--commit-domain") a.commit_domain = need(i, argc, argv, s);
        else if (s == "--cce-domain") a.cce_domain = need(i, argc, argv, s);
        else if (s == "--chain-rpc") a.chain_rpc = need(i, argc, argv, s);
        else if (s == "--auction-registry" || s == "--registry") a.auction_registry = need(i, argc, argv, s);
        else if (s == "--dispute-manager") a.dispute_manager = need(i, argc, argv, s);
        else if (s == "--cce-packet-sign-tool") a.cce_packet_sign_tool = need(i, argc, argv, s);
        else if (s == "--sigma-cce-proof-tool") a.sigma_cce_proof_tool = need(i, argc, argv, s);
        else if (s == "--derive-commitment-h-tool") a.derive_commitment_h_tool = need(i, argc, argv, s);
        else if (s == "--p0-babyjub-pub") a.p0_babyjub_pub_path = need(i, argc, argv, s);
        else if (s == "--p1-babyjub-pub") a.p1_babyjub_pub_path = need(i, argc, argv, s);
        else if (s == "--commitment-packet-sign-tool") a.commitment_packet_sign_tool = need(i, argc, argv, s);
        else if (s == "--challenge-tool") a.challenge_tool = need(i, argc, argv, s);
        else if (s == "--read-root-tool") a.read_root_tool = need(i, argc, argv, s);
        else if (s == "--path-check-delay-sec") a.path_check_delay_sec = std::stoull(need(i, argc, argv, s));
        else if (s == "--invalid-cce-p0") a.invalid_cce_p0 = true;
        else if (s == "--invalid-cce-p1") a.invalid_cce_p1 = true;
        else if (s == "--invalid-cce-both") { a.invalid_cce_p0 = true; a.invalid_cce_p1 = true; }
        else if (s == "--invalid-cce-delta") a.invalid_cce_delta = std::stoull(need(i, argc, argv, s));
        else if (s == "--inconsistent-p0-commitment") a.inconsistent_p0_commitment = true;
        else if (s == "--inconsistent-p1-commitment") a.inconsistent_p1_commitment = true;
        else if (s == "--inconsistent-both-commitments") { a.inconsistent_p0_commitment = true; a.inconsistent_p1_commitment = true; }
        else if (s == "--inconsistent-commitment-delta") a.inconsistent_commitment_delta = std::stoull(need(i, argc, argv, s));
        else if (s == "--eth-priv") a.eth_priv = need(i, argc, argv, s);
        else if (s == "--out") a.out = need(i, argc, argv, s);
        else if (s == "--receipt-file") a.receipt_file = need(i, argc, argv, s);
        else throw std::runtime_error("unknown arg: " + s);
    }
    if (a.mode != "submit" && a.mode != "challenge") throw std::runtime_error("--mode must be submit or challenge");
    if (a.mode == "submit") {
        if (a.role != "buyer" && a.role != "seller") throw std::runtime_error("--role must be buyer or seller");
        if (a.name.empty()) throw std::runtime_error("--name required");
        if (a.chain_rpc.empty() || a.auction_registry.empty() || a.eth_priv.empty()) {
            throw std::runtime_error("submit mode requires --chain-rpc --auction-registry --eth-priv for automatic challenge");
        }
        if (a.dispute_manager.empty()) a.dispute_manager = a.auction_registry; // backward-compatible, but split mode should pass --dispute-manager
    } else {
        if (a.receipt_file.empty()) throw std::runtime_error("--receipt-file required");
        if (a.chain_rpc.empty() || a.auction_registry.empty() || a.eth_priv.empty()) {
            throw std::runtime_error("challenge mode requires --chain-rpc --auction-registry --eth-priv");
        }
        if (a.dispute_manager.empty()) a.dispute_manager = a.auction_registry; // backward-compatible, but split mode should pass --dispute-manager
    }
    return a;
}

static void ensure_parent_dir(const std::string& path) {
    fs::path p(path);
    if (!p.parent_path().empty()) fs::create_directories(p.parent_path());
}

static void set_sock_timeouts(int fd, int seconds) {
    timeval tv{}; tv.tv_sec = seconds; tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

static void send_all(int fd, const void* data, size_t len) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    while (len > 0) {
        ssize_t n = ::send(fd, p, len, MSG_NOSIGNAL);
        if (n < 0) { if (errno == EINTR) continue; throw std::runtime_error("send failed: " + std::string(strerror(errno))); }
        if (n == 0) throw std::runtime_error("send failed: peer closed");
        p += static_cast<size_t>(n); len -= static_cast<size_t>(n);
    }
}

static void recv_all(int fd, void* data, size_t len) {
    uint8_t* p = static_cast<uint8_t*>(data);
    while (len > 0) {
        ssize_t n = ::recv(fd, p, len, MSG_WAITALL);
        if (n < 0) { if (errno == EINTR) continue; throw std::runtime_error("recv failed: " + std::string(strerror(errno))); }
        if (n == 0) throw std::runtime_error("recv failed: peer closed");
        p += static_cast<size_t>(n); len -= static_cast<size_t>(n);
    }
}

static void send_u64(int fd, uint64_t v) { uint64_t be = htobe64(v); send_all(fd, &be, 8); }
static uint64_t recv_u64(int fd) { uint64_t be = 0; recv_all(fd, &be, 8); return be64toh(be); }
static void send_string(int fd, const std::string& s) { send_u64(fd, s.size()); if (!s.empty()) send_all(fd, s.data(), s.size()); }
static std::string recv_string(int fd) { uint64_t n = recv_u64(fd); std::string s(n, '\0'); if (n) recv_all(fd, &s[0], n); return s; }

static int connect_to(const std::string& ip, uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) throw std::runtime_error("socket failed");
    set_sock_timeouts(fd, 120);
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &a.sin_addr) != 1) { close(fd); throw std::runtime_error("bad ip"); }
    if (connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) < 0) { close(fd); throw std::runtime_error("connect failed: " + std::string(strerror(errno))); }
    return fd;
}

static int connect_to_retry(
    const std::string& ip,
    uint16_t port,
    const std::string& label,
    int attempts = 120,
    int sleep_ms = 500
) {
    int last_errno = 0;

    for (int attempt = 1; attempt <= attempts; ++attempt) {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) throw std::runtime_error("socket failed");

        set_sock_timeouts(fd, 120);

        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port = htons(port);

        if (inet_pton(AF_INET, ip.c_str(), &a.sin_addr) != 1) {
            close(fd);
            throw std::runtime_error("bad ip");
        }

        if (connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0) {
            if (attempt > 1) {
                std::cout << "[BIDDER] connected to " << label << " "
                          << ip << ":" << port << " after attempt "
                          << attempt << "/" << attempts << "\n";
            }
            return fd;
        }

        last_errno = errno;
        close(fd);

        if (attempt == 1 || attempt % 10 == 0) {
            std::cout << "[BIDDER] waiting for " << label << " listener "
                      << ip << ":" << port << " attempt="
                      << attempt << "/" << attempts
                      << " errno=" << last_errno << "\n";
        }

        usleep(static_cast<useconds_t>(sleep_ms) * 1000);
    }

    throw std::runtime_error(
        "connect failed to " + label + " " + ip + ":" +
        std::to_string(port) + " after retries errno=" +
        std::to_string(last_errno)
    );
}

static uint64_t random_u64() {
    uint64_t v = 0;
    if (getrandom(&v, sizeof(v), 0) != static_cast<ssize_t>(sizeof(v))) throw std::runtime_error("getrandom failed");
    return v;
}

static int hexval(char c) {
    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return 10 + c - 'a';
    if ('A' <= c && c <= 'F') return 10 + c - 'A';
    return -1;
}

static std::vector<uint8_t> hex_to_bytes(std::string hex) {
    hex.erase(std::remove_if(hex.begin(), hex.end(), [](unsigned char c){ return std::isspace(c); }), hex.end());
    if (hex.rfind("0x", 0) == 0 || hex.rfind("0X", 0) == 0) hex = hex.substr(2);
    if (hex.size() % 2) throw std::runtime_error("odd hex length");
    std::vector<uint8_t> out(hex.size()/2);
    for (size_t i=0;i<out.size();++i) { int hi=hexval(hex[2*i]), lo=hexval(hex[2*i+1]); if (hi<0||lo<0) throw std::runtime_error("bad hex"); out[i] = (hi<<4)|lo; }
    return out;
}

static std::string bytes_to_hex(const uint8_t* p, size_t n) {
    static const char* lut = "0123456789abcdef";
    std::string s(n*2, '0');
    for (size_t i=0;i<n;++i) { s[2*i]=lut[p[i]>>4]; s[2*i+1]=lut[p[i]&15]; }
    return s;
}

static std::string normalize_hex32(std::string h) {
    h.erase(std::remove_if(h.begin(), h.end(), [](unsigned char c){ return std::isspace(c); }), h.end());
    if (h.rfind("0x", 0) == 0 || h.rfind("0X", 0) == 0) h = h.substr(2);
    std::transform(h.begin(), h.end(), h.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    if (h.size() != 64) throw std::runtime_error("expected bytes32 hex");
    return "0x" + h;
}

static std::array<uint8_t,32> hex32_to_array(const std::string& h) {
    auto v = hex_to_bytes(h);
    if (v.size() != 32) throw std::runtime_error("expected 32-byte hex value");
    std::array<uint8_t,32> out{};
    std::copy(v.begin(), v.end(), out.begin());
    return out;
}

static std::string sha256_pair_hex(const std::string& left_hex, const std::string& right_hex) {
    auto left = hex32_to_array(left_hex);
    auto right = hex32_to_array(right_hex);
    uint8_t buf[64];
    std::memcpy(buf, left.data(), 32);
    std::memcpy(buf + 32, right.data(), 32);
    std::array<uint8_t,32> out{};
    SHA256(buf, 64, out.data());
    return "0x" + bytes_to_hex(out.data(), 32);
}

static bool merkle_path_matches_root(
    const std::string& leaf_hash,
    const std::string& root,
    const std::vector<std::string>& path_elems,
    const std::vector<uint64_t>& path_dirs
) {
    if (path_elems.size() != path_dirs.size()) return false;
    std::string current = normalize_hex32(leaf_hash);
    for (size_t i = 0; i < path_elems.size(); ++i) {
        std::string sibling = normalize_hex32(path_elems[i]);
        if (path_dirs[i] == 0) {
            // current is left, sibling is right
            current = sha256_pair_hex(current, sibling);
        } else if (path_dirs[i] == 1) {
            // sibling is left, current is right
            current = sha256_pair_hex(sibling, current);
        } else {
            return false;
        }
    }
    return normalize_hex32(current) == normalize_hex32(root);
}

static std::vector<uint8_t> read_hex_file(const std::string& path) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("cannot open " + path);
    std::string s((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return hex_to_bytes(s);
}

static std::string shell_quote(const std::string& s) {
    std::string out = "'";
    for (char c: s) out += (c == '\'') ? "'\\''" : std::string(1, c);
    out += "'";
    return out;
}

static std::string rtrim(std::string s) {
    while (!s.empty() && (s.back()=='\n'||s.back()=='\r'||s.back()==' '||s.back()=='\t')) s.pop_back();
    return s;
}

static std::string exec_cmd(const std::string& cmd) {
    std::array<char,4096> buf{}; std::string out;
    FILE* fp = popen(cmd.c_str(), "r");
    if (!fp) throw std::runtime_error("popen failed");
    while (true) { size_t n = fread(buf.data(),1,buf.size(),fp); if (n) out.append(buf.data(),n); if (n < buf.size()) break; }
    int rc = pclose(fp);
    if (rc != 0) throw std::runtime_error("cmd failed: " + cmd + "\n" + out);
    return out;
}

static std::string json_escape(const std::string& s) {
    std::string o;
    for (unsigned char c: s) {
        if (c == '\\') o += "\\\\";
        else if (c == '"') o += "\\\"";
        else if (c == '\n') o += "\\n";
        else if (c == '\r') o += "\\r";
        else if (c == '\t') o += "\\t";
        else o.push_back(static_cast<char>(c));
    }
    return o;
}

static std::string json_get_string(const std::string& json, const std::string& key) {
    std::string pat = "\"" + key + "\"";
    size_t k = json.find(pat); if (k == std::string::npos) throw std::runtime_error("missing json key " + key);
    size_t colon = json.find(':', k); if (colon == std::string::npos) throw std::runtime_error("bad json key " + key);
    size_t p = colon + 1; while (p < json.size() && std::isspace(static_cast<unsigned char>(json[p]))) p++;
    if (p >= json.size() || json[p] != '"') throw std::runtime_error("json key not string " + key);
    size_t end = json.find('"', p+1); if (end == std::string::npos) throw std::runtime_error("unterminated json string");
    return json.substr(p+1, end-p-1);
}

static void append_u64_be(std::vector<uint8_t>& b, uint64_t v) { uint64_t be=htobe64(v); const uint8_t* p=reinterpret_cast<const uint8_t*>(&be); b.insert(b.end(),p,p+8); }
static void append_str(std::vector<uint8_t>& b, const std::string& s) { append_u64_be(b, s.size()); b.insert(b.end(), s.begin(), s.end()); }

static std::array<uint8_t,64> sign_ed25519(const std::vector<uint8_t>& data, const std::vector<uint8_t>& seed) {
    if (seed.size() != 32) throw std::runtime_error("Ed25519 seed must be 32 bytes");
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed.data(), seed.size());
    if (!pkey) throw std::runtime_error("EVP_PKEY_new_raw_private_key failed");
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) { EVP_PKEY_free(pkey); throw std::runtime_error("EVP_MD_CTX_new failed"); }
    if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) != 1) throw std::runtime_error("DigestSignInit failed");
    std::array<uint8_t,64> sig{}; size_t siglen = sig.size();
    if (EVP_DigestSign(ctx, sig.data(), &siglen, data.data(), data.size()) != 1) throw std::runtime_error("DigestSign failed");
    EVP_MD_CTX_free(ctx); EVP_PKEY_free(pkey); return sig;
}

struct SecpCtx { EC_GROUP* group=nullptr; BN_CTX* bn=nullptr; BIGNUM* order=nullptr; SecpCtx(){ group=EC_GROUP_new_by_curve_name(NID_secp256k1); bn=BN_CTX_new(); order=BN_new(); if(!group||!bn||!order) throw std::runtime_error("secp alloc failed"); if(EC_GROUP_get_order(group, order, bn)!=1) throw std::runtime_error("secp order failed"); } ~SecpCtx(){ if(order)BN_free(order); if(bn)BN_CTX_free(bn); if(group)EC_GROUP_free(group); } };
static SecpCtx& secp(){ static SecpCtx c; return c; }

static std::array<uint8_t,33> read_pubkey33(const std::string& path) { auto v=read_hex_file(path); if(v.size()!=33) throw std::runtime_error("pubkey must be 33 bytes: "+path); std::array<uint8_t,33> o{}; std::copy(v.begin(),v.end(),o.begin()); return o; }
static std::array<uint8_t,33> point_to33(const EC_POINT* P) { auto& c=secp(); std::array<uint8_t,33> o{}; size_t n=EC_POINT_point2oct(c.group,P,POINT_CONVERSION_COMPRESSED,o.data(),o.size(),c.bn); if(n!=33) throw std::runtime_error("point_to33 failed"); return o; }

struct HybridCiphertext { std::array<uint8_t,33> eph{}; std::array<uint8_t,12> iv{}; std::array<uint8_t,16> tag{}; std::vector<uint8_t> ct; };

static HybridCiphertext encrypt_u64(uint64_t val, const std::array<uint8_t,33>& pub_bytes) {
    auto& c=secp();
    EC_POINT* pub=EC_POINT_new(c.group); EC_POINT* R=EC_POINT_new(c.group); EC_POINT* S=EC_POINT_new(c.group);
    BIGNUM* r=BN_new(); BIGNUM* sx=BN_new(); BIGNUM* sy=BN_new();
    if(!pub||!R||!S||!r||!sx||!sy) throw std::runtime_error("ec alloc failed");
    if(EC_POINT_oct2point(c.group,pub,pub_bytes.data(),pub_bytes.size(),c.bn)!=1) throw std::runtime_error("bad pubkey");
    BN_rand_range(r,c.order);
    if(EC_POINT_mul(c.group,R,r,nullptr,nullptr,c.bn)!=1) throw std::runtime_error("R mul failed");
    if(EC_POINT_mul(c.group,S,nullptr,pub,r,c.bn)!=1) throw std::runtime_error("S mul failed");
    if(EC_POINT_get_affine_coordinates(c.group,S,sx,sy,c.bn)!=1) throw std::runtime_error("affine failed");
    std::vector<uint8_t> sx_bytes(BN_num_bytes(sx)); BN_bn2bin(sx,sx_bytes.data());
    if(sx_bytes.size()<32){ std::vector<uint8_t> pad(32-sx_bytes.size(),0); pad.insert(pad.end(),sx_bytes.begin(),sx_bytes.end()); sx_bytes.swap(pad); }
    uint8_t key[SHA256_DIGEST_LENGTH]; SHA256(sx_bytes.data(), sx_bytes.size(), key);
    HybridCiphertext out; out.eph=point_to33(R); if(getrandom(out.iv.data(),out.iv.size(),0)!=(ssize_t)out.iv.size()) throw std::runtime_error("iv failed");
    uint64_t be=htobe64(val); uint8_t pt[8]; std::memcpy(pt,&be,8); out.ct.resize(8);
    EVP_CIPHER_CTX* ctx=EVP_CIPHER_CTX_new(); if(!ctx) throw std::runtime_error("cipher ctx failed");
    int len=0, flen=0; if(EVP_EncryptInit_ex(ctx,EVP_aes_256_gcm(),nullptr,key,out.iv.data())!=1) throw std::runtime_error("enc init failed");
    if(EVP_EncryptUpdate(ctx,out.ct.data(),&len,pt,8)!=1) throw std::runtime_error("enc update failed");
    if(EVP_EncryptFinal_ex(ctx,out.ct.data()+len,&flen)!=1) throw std::runtime_error("enc final failed");
    if(EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_GET_TAG,16,out.tag.data())!=1) throw std::runtime_error("tag failed");
    EVP_CIPHER_CTX_free(ctx); EC_POINT_free(pub); EC_POINT_free(R); EC_POINT_free(S); BN_free(r); BN_free(sx); BN_free(sy);
    return out;
}

static std::string random_babyjub_scalar_dec() {
    uint8_t rnd[32]; if(getrandom(rnd,sizeof(rnd),0)!=(ssize_t)sizeof(rnd)) throw std::runtime_error("random scalar failed");
    BIGNUM *x=BN_new(), *m=nullptr; BN_CTX* ctx=BN_CTX_new(); if(!x||!ctx) throw std::runtime_error("bn alloc");
    BN_bin2bn(rnd, sizeof(rnd), x); if(BN_dec2bn(&m, BABYJUB_SUBORDER_DEC)==0) throw std::runtime_error("bad modulus");
    BN_mod(x,x,m,ctx); char* dec=BN_bn2dec(x); std::string s(dec); OPENSSL_free(dec); BN_free(x); BN_free(m); BN_CTX_free(ctx); return s;
}

struct BabyJubPointDec { std::string x; std::string y; };
struct OpenProof { std::string Ax; std::string Ay; std::string z; };

static BabyJubPointDec babyjub_commit(const std::string& domain, uint64_t value, const std::string& r_dec) {
    std::ostringstream cmd; cmd << "node babyjub_commit.js " << shell_quote(domain) << " " << value << " " << shell_quote(r_dec);
    std::string out = rtrim(exec_cmd(cmd.str()));
    return BabyJubPointDec{json_get_string(out,"Cx"), json_get_string(out,"Cy")};
}

static OpenProof babyjub_open_proof(const std::string& commit_domain, const std::string& cce_domain, const std::string& role, const std::string& name, const BabyJubPointDec& C, uint64_t x_value, const HybridCiphertext& h, const std::string& r_dec) {
    std::ostringstream cmd;
    cmd << "node babyjub_schnorr_open.js "
        << shell_quote(commit_domain) << " " << shell_quote(cce_domain) << " "
        << shell_quote(role) << " " << shell_quote(name) << " "
        << shell_quote(C.x) << " " << shell_quote(C.y) << " " << x_value << " " << shell_quote(r_dec) << " "
        << shell_quote(bytes_to_hex(h.eph.data(),33)) << " " << shell_quote(bytes_to_hex(h.iv.data(),12)) << " "
        << shell_quote(bytes_to_hex(h.tag.data(),16)) << " " << shell_quote(bytes_to_hex(h.ct.data(),h.ct.size()));
    std::string out = rtrim(exec_cmd(cmd.str()));
    return OpenProof{json_get_string(out,"Ax"), json_get_string(out,"Ay"), json_get_string(out,"z")};
}

static void append_hybrid(std::vector<uint8_t>& b, const HybridCiphertext& h) { b.insert(b.end(),h.eph.begin(),h.eph.end()); b.insert(b.end(),h.iv.begin(),h.iv.end()); b.insert(b.end(),h.tag.begin(),h.tag.end()); append_u64_be(b,h.ct.size()); b.insert(b.end(),h.ct.begin(),h.ct.end()); }
static void append_proof(std::vector<uint8_t>& b, const OpenProof& p) { append_str(b,p.Ax); append_str(b,p.Ay); append_str(b,p.z); }


static std::string read_text_simple(const std::string& path) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("cannot read " + path);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

static BabyJubPointDec load_babyjub_pub_json(const std::string& path) {
    std::string json = read_text_simple(path);
    return BabyJubPointDec{json_get_string(json, "x"), json_get_string(json, "y")};
}

static BabyJubPointDec derive_commitment_H(const Args& args) {
    std::ostringstream cmd;
    cmd << "node " << shell_quote(args.derive_commitment_h_tool)
        << " " << shell_quote(args.commit_domain);
    std::string out = exec_cmd(cmd.str());
    return BabyJubPointDec{json_get_string(out, "Hx"), json_get_string(out, "Hy")};
}

static std::string safe_name_component(std::string s) {
    for (char& c : s) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' && c != '-') c = '_';
    }
    return s;
}

static std::string sigma_cce_prove_json(
    const Args& args,
    uint64_t party_id,
    uint64_t share_x,
    const BabyJubPointDec& C,
    const std::string& r_dec,
    const BabyJubPointDec& H,
    const BabyJubPointDec& auctioneer_pub,
    bool intentionally_invalid
) {
    std::string out_path = "onchain/sigma_cce_" + safe_name_component(args.name) + "_p" + std::to_string(party_id);
    if (intentionally_invalid) out_path += "_BAD";
    out_path += ".json";

    std::ostringstream cmd;
    cmd << "node " << shell_quote(args.sigma_cce_proof_tool)
        << " --rpc " << shell_quote(args.chain_rpc)
        << " --contract " << shell_quote(args.auction_registry)
        << " --session-id " << args.session_id
        << " --party-id " << party_id
        << " --role " << shell_quote(args.role)
        << " --name " << shell_quote(args.name)
        << " --bidder-id " << args.id
        << " --commit-domain " << shell_quote(args.commit_domain)
        << " --cce-domain " << shell_quote(args.cce_domain)
        << " --x " << share_x
        << " --r " << shell_quote(r_dec)
        << " --Cx " << shell_quote(C.x)
        << " --Cy " << shell_quote(C.y)
        << " --Hx " << shell_quote(H.x)
        << " --Hy " << shell_quote(H.y)
        << " --auctioneer-pub-x " << shell_quote(auctioneer_pub.x)
        << " --auctioneer-pub-y " << shell_quote(auctioneer_pub.y)
        << " --out " << shell_quote(out_path);
    if (intentionally_invalid) cmd << " --invalid-proof";
    exec_cmd(cmd.str());
    return read_text_simple(out_path);
}

static std::string sign_cce_packet_eth(const Args& args, const std::string& name, const std::string& sigma_cce_json) {
    std::string priv_file = args.bidder_eth_priv_dir + "/" + name + ".eth.priv";
    std::ostringstream cmd;
    cmd << "node " << shell_quote(args.cce_packet_sign_tool)
        << " --rpc " << shell_quote(args.chain_rpc)
        << " --contract " << shell_quote(args.auction_registry)
        << " --priv-file " << shell_quote(priv_file)
        << " --sigma-proof-json " << shell_quote(sigma_cce_json);
    std::string out = exec_cmd(cmd.str());
    return json_get_string(out, "signature");
}

static std::string sign_commitment_packet_eth(const Args& args, uint64_t party_id, const std::string& role, const std::string& name, uint64_t bidder_id, const BabyJubPointDec& C) {
    std::string priv_file = args.bidder_eth_priv_dir + "/" + name + ".eth.priv";
    std::ostringstream cmd;
    cmd << "node " << shell_quote(args.commitment_packet_sign_tool)
        << " --rpc " << shell_quote(args.chain_rpc)
        << " --contract " << shell_quote(args.auction_registry)
        << " --priv-file " << shell_quote(priv_file)
        << " --session-id " << args.session_id
        << " --party-id " << party_id
        << " --role " << shell_quote(role)
        << " --name " << shell_quote(name)
        << " --bidder-id " << bidder_id
        << " --commit-domain " << shell_quote(args.commit_domain)
        << " --Cx " << shell_quote(C.x)
        << " --Cy " << shell_quote(C.y);
    std::string out = exec_cmd(cmd.str());
    return json_get_string(out, "signature");
}

struct PartyPacket {
    HybridCiphertext enc_bid;
    HybridCiphertext enc_id;
    OpenProof proof;
    std::array<uint8_t,64> ed_sig{};
    std::string eth_sig;
    std::string commitment_sig;
    // PPCR Sigma Fiat-Shamir CCE packet JSON. This is signed by eth_sig and verified by P0/P1 and the contract.
    std::string sigma_cce_json;
};

static PartyPacket make_party_packet(const Args& args, uint64_t party_id, const std::array<uint8_t,33>& pub, const std::vector<uint8_t>& ed_seed, uint64_t bid_share, uint64_t id_share, const BabyJubPointDec& C, const std::string& r_dec, const BabyJubPointDec& H, const BabyJubPointDec& auctioneer_pub) {
    PartyPacket p;
    p.enc_bid = encrypt_u64(bid_share, pub);
    p.enc_id = encrypt_u64(id_share, pub);
    p.proof = babyjub_open_proof(args.commit_domain, args.cce_domain, args.role, args.name, C, bid_share, p.enc_bid, r_dec);

    // The Sigma packet already contains AC/AU/AV and the responses zx/zr/zk.
    // The Ethereum signer must use the full-evidence digest produced by
    // sign_sigma_cce_packet.js, while the Fiat-Shamir challenge remains
    // derived from the response-free challenge hash.
    p.sigma_cce_json = sigma_cce_prove_json(args, party_id, bid_share, C, r_dec, H, auctioneer_pub, false);
    p.eth_sig = sign_cce_packet_eth(args, args.name, p.sigma_cce_json);
    p.commitment_sig = sign_commitment_packet_eth(args, party_id, args.role, args.name, args.id, C);

    // Ed25519 authenticates the complete transport envelope as an additional
    // anti-splicing layer, including the complete Sigma JSON and both Ethereum
    // signatures. Wire order is unchanged, so BidderBoss can relay it verbatim.
    std::vector<uint8_t> tr;
    append_str(tr, SIGNED_PACKET_DOMAIN);
    append_u64_be(tr, args.session_id);
    append_u64_be(tr, party_id);
    append_str(tr, args.role);
    append_str(tr, args.name);
    append_u64_be(tr, args.id);
    append_str(tr, args.commit_domain);
    append_str(tr, C.x);
    append_str(tr, C.y);
    append_hybrid(tr, p.enc_bid);
    append_hybrid(tr, p.enc_id);
    append_proof(tr, p.proof);
    append_str(tr, p.sigma_cce_json);
    append_str(tr, p.eth_sig);
    append_str(tr, p.commitment_sig);
    p.ed_sig = sign_ed25519(tr, ed_seed);
    return p;
}

// Build a deliberately invalid CCE packet for P0 while keeping both bidder
// signatures valid. The P0 commitment C is still C = Commit(real_bid_share, r),
// but the encrypted share decrypts to bad_bid_share. The proof is generated
// using the wrong share value with the old randomness, so it should fail
// verification against C. Because we sign this exact invalid packet, P0 can
// submit it to the smart contract as valid bidder-signed evidence.
static PartyPacket make_invalid_cce_party_packet(
    const Args& args,
    uint64_t party_id,
    const std::array<uint8_t,33>& pub,
    const std::vector<uint8_t>& ed_seed,
    uint64_t real_bid_share,
    uint64_t bad_bid_share,
    uint64_t id_share,
    const BabyJubPointDec& C,
    const std::string& r_dec,
    const BabyJubPointDec& H,
    const BabyJubPointDec& auctioneer_pub
) {
    (void)real_bid_share;
    PartyPacket p;
    p.enc_bid = encrypt_u64(bad_bid_share, pub);
    p.enc_id = encrypt_u64(id_share, pub);

    // This proof is intentionally invalid because C was computed from the
    // real share, but the proof uses bad_bid_share.
    p.proof = babyjub_open_proof(
        args.commit_domain,
        args.cce_domain,
        args.role,
        args.name,
        C,
        bad_bid_share,
        p.enc_bid,
        r_dec
    );

    p.sigma_cce_json = sigma_cce_prove_json(args, party_id, bad_bid_share, C, r_dec, H, auctioneer_pub, true);
    p.eth_sig = sign_cce_packet_eth(args, args.name, p.sigma_cce_json);
    p.commitment_sig = sign_commitment_packet_eth(args, party_id, args.role, args.name, args.id, C);

    std::vector<uint8_t> tr;
    append_str(tr, SIGNED_PACKET_DOMAIN);
    append_u64_be(tr, args.session_id);
    append_u64_be(tr, party_id);
    append_str(tr, args.role);
    append_str(tr, args.name);
    append_u64_be(tr, args.id);
    append_str(tr, args.commit_domain);
    append_str(tr, C.x);
    append_str(tr, C.y);
    append_hybrid(tr, p.enc_bid);
    append_hybrid(tr, p.enc_id);
    append_proof(tr, p.proof);
    append_str(tr, p.sigma_cce_json);
    append_str(tr, p.eth_sig);
    append_str(tr, p.commitment_sig);
    p.ed_sig = sign_ed25519(tr, ed_seed);

    return p;
}

static void send_hybrid(int fd, const HybridCiphertext& h) { send_all(fd,h.eph.data(),33); send_all(fd,h.iv.data(),12); send_all(fd,h.tag.data(),16); send_u64(fd,h.ct.size()); if(!h.ct.empty()) send_all(fd,h.ct.data(),h.ct.size()); }
static HybridCiphertext recv_hybrid(int fd) { HybridCiphertext h; recv_all(fd,h.eph.data(),33); recv_all(fd,h.iv.data(),12); recv_all(fd,h.tag.data(),16); uint64_t n=recv_u64(fd); h.ct.resize(n); if(n) recv_all(fd,h.ct.data(),n); return h; }
static void send_proof(int fd, const OpenProof& p) { send_string(fd,p.Ax); send_string(fd,p.Ay); send_string(fd,p.z); }

static void send_party_packet(int fd, const PartyPacket& p) {
    send_hybrid(fd, p.enc_bid); send_hybrid(fd, p.enc_id); send_proof(fd, p.proof); send_all(fd, p.ed_sig.data(), p.ed_sig.size()); send_string(fd, p.eth_sig); send_string(fd, p.commitment_sig); send_string(fd, p.sigma_cce_json); send_string(fd, "");
}

static uint16_t direct_port_for(const Args& args, uint64_t party_id) {
    const bool is_buyer = args.role == "buyer";
    if (party_id == 0) return is_buyer ? args.p0_buyer_port : args.p0_seller_port;
    return is_buyer ? args.p1_buyer_port : args.p1_seller_port;
}

static void send_direct_to_auctioneer(const Args& args, uint64_t party_id, const BabyJubPointDec& c0, const BabyJubPointDec& c1, const PartyPacket& packet) {
    const std::string host = party_id == 0 ? args.p0_host : args.p1_host;
    const uint16_t port = direct_port_for(args, party_id);
    int fd = connect_to_retry(
        host,
        port,
        std::string("P") + std::to_string(party_id) + " " + args.role + " direct port"
    );
    send_string(fd, DIRECT_MAGIC);
    send_u64(fd, args.session_id);
    send_u64(fd, party_id);
    send_string(fd, args.role);
    send_string(fd, args.name);
    send_u64(fd, args.id);
    send_string(fd, args.commit_domain);
    send_string(fd, c0.x); send_string(fd, c0.y); send_string(fd, c1.x); send_string(fd, c1.y);
    send_party_packet(fd, packet);
    close(fd);
    std::cout << "[BIDDER] sent direct signed packet to P" << party_id << " at " << host << ":" << port << "\n";
}

static std::string read_text(const std::string& path) { std::ifstream in(path); if(!in) throw std::runtime_error("cannot read "+path); return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>()); }
static void write_text(const std::string& path, const std::string& data) { ensure_parent_dir(path); std::ofstream out(path); if(!out) throw std::runtime_error("cannot write "+path); out << data; }

static void write_json_path_arrays(
    std::ostringstream& os,
    const char* prefix,
    const std::vector<std::string>& path_elems,
    const std::vector<uint64_t>& path_dirs
) {
    os << "  \"" << prefix << "PathElements\": [";
    for(size_t i=0;i<path_elems.size();++i){ if(i) os << ","; os << "\"" << path_elems[i] << "\""; }
    os << "],\n  \"" << prefix << "PathDirections\": [";
    for(size_t i=0;i<path_dirs.size();++i){ if(i) os << ","; os << path_dirs[i]; }
    os << "]";
}

static void save_receipt_json(
    const std::string& path,
    const Args& args,
    const BabyJubPointDec& c0,
    const BabyJubPointDec& c1,
    const std::string& p0_receipt_hash,
    const std::string& p0_leaf_hash,
    const std::string& p0_receipt_sig,
    const std::string& p0_root,
    const std::vector<std::string>& p0_path_elems,
    const std::vector<uint64_t>& p0_path_dirs,
    const std::string& p0_evidence_signature,
    const std::string& p1_receipt_hash,
    const std::string& p1_leaf_hash,
    const std::string& p1_receipt_sig,
    const std::string& p1_root,
    const std::vector<std::string>& p1_path_elems,
    const std::vector<uint64_t>& p1_path_dirs,
    const std::string& p1_evidence_signature,
    uint64_t challenge_party_id
) {
    std::ostringstream os;
    os << "{\n"
       << "  \"sessionId\": \"" << args.session_id << "\",\n"
       << "  \"role\": \"" << json_escape(args.role) << "\",\n"
       << "  \"name\": \"" << json_escape(args.name) << "\",\n"
       << "  \"bidderId\": \"" << args.id << "\",\n"
       << "  \"commitDomain\": \"" << json_escape(args.commit_domain) << "\",\n"
       << "  \"c0x\": \"" << c0.x << "\",\n"
       << "  \"c0y\": \"" << c0.y << "\",\n"
       << "  \"c1x\": \"" << c1.x << "\",\n"
       << "  \"c1y\": \"" << c1.y << "\",\n"
       << "  \"challengePartyId\": \"" << challenge_party_id << "\",\n"
       << "  \"p0ReceiptHash\": \"" << p0_receipt_hash << "\",\n"
       << "  \"p0LeafHash\": \"" << p0_leaf_hash << "\",\n"
       << "  \"p0Signature\": \"" << p0_receipt_sig << "\",\n"
       << "  \"p0Root\": \"" << p0_root << "\",\n";
    write_json_path_arrays(os, "p0", p0_path_elems, p0_path_dirs);
    os << ",\n"
       << "  \"p0EvidenceSignature\": \"" << json_escape(p0_evidence_signature) << "\",\n"
       << "  \"p1ReceiptHash\": \"" << p1_receipt_hash << "\",\n"
       << "  \"p1LeafHash\": \"" << p1_leaf_hash << "\",\n"
       << "  \"p1Signature\": \"" << p1_receipt_sig << "\",\n"
       << "  \"p1Root\": \"" << p1_root << "\",\n";
    write_json_path_arrays(os, "p1", p1_path_elems, p1_path_dirs);
    os << ",\n"
       << "  \"p1EvidenceSignature\": \"" << json_escape(p1_evidence_signature) << "\"";

    // Backward-compatible aliases use the currently challenged party.
    const bool use_p1 = (challenge_party_id == 1);
    os << ",\n"
       << "  \"receiptHash\": \"" << (use_p1 ? p1_receipt_hash : p0_receipt_hash) << "\",\n"
       << "  \"leafHash\": \"" << (use_p1 ? p1_leaf_hash : p0_leaf_hash) << "\",\n"
       << "  \"signature\": \"" << (use_p1 ? p1_receipt_sig : p0_receipt_sig) << "\",\n"
       << "  \"root\": \"" << (use_p1 ? p1_root : p0_root) << "\",\n"
       << "  \"pathElements\": [] ,\n"
       << "  \"pathDirections\": []\n"
       << "}\n";
    write_text(path, os.str());
}

static int run_challenge_file(
    const std::string& challenge_tool,
    const std::string& chain_rpc,
    const std::string& auction_registry,
    const std::string& eth_priv,
    uint64_t session_id,
    const std::string& receipt_file
);

static std::string read_onchain_commitment_root(
    const std::string& tool_path,
    const std::string& rpc_url,
    const std::string& contract_address,
    uint64_t session_id,
    const std::string& role,
    uint64_t party_id
) {
    std::ostringstream cmd;
    cmd << "node " << shell_quote(tool_path)
        << " --rpc " << shell_quote(rpc_url)
        << " --contract " << shell_quote(contract_address)
        << " --session-id " << session_id
        << " --role " << shell_quote(role)
        << " --party-id " << party_id;

    std::string output = exec_cmd(cmd.str());
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

static int run_submit(const Args& args) {
    auto p0_pub = read_pubkey33(args.p0_pub_path);
    auto p1_pub = read_pubkey33(args.p1_pub_path);
    auto ed_seed = read_hex_file(args.ed25519_priv_dir + "/" + args.name + ".priv");
    if (ed_seed.size() != 32) throw std::runtime_error("bad Ed25519 seed for " + args.name);

    BabyJubPointDec H = derive_commitment_H(args);
    BabyJubPointDec p0_babyjub_pub = load_babyjub_pub_json(args.p0_babyjub_pub_path);
    BabyJubPointDec p1_babyjub_pub = load_babyjub_pub_json(args.p1_babyjub_pub_path);

    uint64_t bid0 = random_u64();
    uint64_t bid1 = args.bid - bid0;
    uint64_t id0 = random_u64();
    uint64_t id1 = args.id - id0;
    std::string r0 = random_babyjub_scalar_dec();
    std::string r1 = random_babyjub_scalar_dec();

    BabyJubPointDec c0 = babyjub_commit(args.commit_domain, bid0, r0);
    BabyJubPointDec c1 = babyjub_commit(args.commit_domain, bid1, r1);

    PartyPacket p0 = make_party_packet(args, 0, p0_pub, ed_seed, bid0, id0, c0, r0, H, p0_babyjub_pub);
    PartyPacket p1 = make_party_packet(args, 1, p1_pub, ed_seed, bid1, id1, c1, r1, H, p1_babyjub_pub);

    if (args.invalid_cce_p0) {
        uint64_t bad_bid0 = bid0 + args.invalid_cce_delta;
        if (bad_bid0 == bid0) {
            bad_bid0 = bid0 ^ 1ULL;
        }

        std::cout
            << "[BIDDER-TEST] Invalid CCE demo enabled for P0. "
            << "role=" << args.role << ", name=" << args.name
            << ", commitment C0 is for real share=" << bid0
            << ", but P0 ciphertext/proof/signature packet uses bad decrypted share="
            << bad_bid0 << "\n";

        p0 = make_invalid_cce_party_packet(
            args,
            0,
            p0_pub,
            ed_seed,
            bid0,
            bad_bid0,
            id0,
            c0,
            r0,
            H,
            p0_babyjub_pub
        );
    }

    if (args.invalid_cce_p1) {
        uint64_t bad_bid1 = bid1 + args.invalid_cce_delta;
        if (bad_bid1 == bid1) {
            bad_bid1 = bid1 ^ 1ULL;
        }

        std::cout
            << "[BIDDER-TEST] Invalid CCE demo enabled for P1. "
            << "role=" << args.role << ", name=" << args.name
            << ", commitment C1 is for real share=" << bid1
            << ", but P1 ciphertext/proof/signature packet uses bad decrypted share="
            << bad_bid1 << "\n";

        p1 = make_invalid_cce_party_packet(
            args,
            1,
            p1_pub,
            ed_seed,
            bid1,
            bad_bid1,
            id1,
            c1,
            r1,
            H,
            p1_babyjub_pub
        );
    }


    // Direct packets are normally identical to the packets sent to BidderBoss.
    // In the inconsistency test, only the direct packet sent to the target auctioneer
    // is changed and re-signed by the bidder. BidderBoss keeps the original signed
    // packet and relays it as evidence. The target auctioneer then has two valid
    // bidder-signed packets for the same session/role/bidderId/partyId but with
    // different commitments.
    BabyJubPointDec direct_c0 = c0;
    BabyJubPointDec direct_c1 = c1;
    PartyPacket direct_p0 = p0;
    PartyPacket direct_p1 = p1;

    if (args.inconsistent_p0_commitment) {
        uint64_t direct_bid0 = bid0 + args.inconsistent_commitment_delta;
        if (direct_bid0 == bid0) {
            direct_bid0 = bid0 ^ 1ULL;
        }
        std::string direct_r0 = random_babyjub_scalar_dec();
        direct_c0 = babyjub_commit(args.commit_domain, direct_bid0, direct_r0);
        direct_p0 = make_party_packet(args, 0, p0_pub, ed_seed, direct_bid0, id0, direct_c0, direct_r0, H, p0_babyjub_pub);

        std::cout
            << "[BIDDER-TEST] Commitment inconsistency enabled for P0. "
            << "BidderBoss receives original C0 for share=" << bid0
            << ", but P0 receives different valid signed C0 for share="
            << direct_bid0 << "\n";
    }

    if (args.inconsistent_p1_commitment) {
        uint64_t direct_bid1 = bid1 + args.inconsistent_commitment_delta;
        if (direct_bid1 == bid1) {
            direct_bid1 = bid1 ^ 1ULL;
        }
        std::string direct_r1 = random_babyjub_scalar_dec();
        direct_c1 = babyjub_commit(args.commit_domain, direct_bid1, direct_r1);
        direct_p1 = make_party_packet(args, 1, p1_pub, ed_seed, direct_bid1, id1, direct_c1, direct_r1, H, p1_babyjub_pub);

        std::cout
            << "[BIDDER-TEST] Commitment inconsistency enabled for P1. "
            << "BidderBoss receives original C1 for share=" << bid1
            << ", but P1 receives different valid signed C1 for share="
            << direct_bid1 << "\n";
    }

    // Option 1 ordering fix:
    // First send the signed packets/commitments to BidderBoss so BidderBoss can
    // collect all buyers and sellers and generate Merkle roots/evidence.
    // After BidderBoss returns the receipt hashes, send the same signed packets
    // directly to P0/P1. This prevents the old deadlock where seller bidders
    // waited for P0/P1 seller ports while P0/P1 were still waiting for buyer
    // Merkle evidence from BidderBoss.
    int fd = connect_to_retry(args.boss_ip, args.port, "BidderBoss", 120, 500);
    send_string(fd, WIRE_MAGIC);
    send_u64(fd, args.session_id);
    send_string(fd, args.role);
    send_string(fd, args.name);
    send_u64(fd, args.id);
    send_string(fd, args.commit_domain);
    send_string(fd, c0.x); send_string(fd, c0.y); send_string(fd, c1.x); send_string(fd, c1.y);
    // randomness is not sent to P0/P1 directly here; BidderBoss stores only randomness and reveals r0/r1 later.
    // It still cannot open commitments because it does not know encrypted bid shares.
    send_string(fd, r0); send_string(fd, r1);
    send_party_packet(fd, p0);
    send_party_packet(fd, p1);

    std::string p0_receipt_hash = recv_string(fd);
    std::string p0_leaf_hash = recv_string(fd);
    std::string p0_receipt_sig = recv_string(fd);
    std::string p1_receipt_hash = recv_string(fd);
    std::string p1_leaf_hash = recv_string(fd);
    std::string p1_receipt_sig = recv_string(fd);
    std::cout << "[BIDDER] received BidderBoss receipts p0Leaf=" << p0_leaf_hash
              << " p1Leaf=" << p1_leaf_hash << "\n";

    // Now send the signed encrypted share packets directly to P0 and P1.
    // These are the same packets that were sent to BidderBoss above.
    if (args.inconsistent_p0_commitment && !args.inconsistent_p1_commitment) {
        send_direct_to_auctioneer(args, 0, direct_c0, c1, direct_p0);
        send_direct_to_auctioneer(args, 1, c0, c1, p1);
    } else if (args.inconsistent_p1_commitment && !args.inconsistent_p0_commitment) {
        send_direct_to_auctioneer(args, 0, c0, c1, p0);
        send_direct_to_auctioneer(args, 1, c0, direct_c1, direct_p1);
    } else if (args.inconsistent_p0_commitment && args.inconsistent_p1_commitment) {
        send_direct_to_auctioneer(args, 0, direct_c0, c1, direct_p0);
        send_direct_to_auctioneer(args, 1, c0, direct_c1, direct_p1);
    } else {
        send_direct_to_auctioneer(args, 0, c0, c1, p0);
        send_direct_to_auctioneer(args, 1, c0, c1, p1);
    }

    if (args.path_check_delay_sec > 0) {
        std::cout << "[BIDDER] waiting " << args.path_check_delay_sec
                  << " seconds before checking Merkle roots/paths...\n";
        sleep(static_cast<unsigned int>(args.path_check_delay_sec));
    }

    std::string p0_root = "0x0000000000000000000000000000000000000000000000000000000000000000";
    std::string p1_root = "0x0000000000000000000000000000000000000000000000000000000000000000";
    std::vector<std::string> p0_path_elems, p1_path_elems;
    std::vector<uint64_t> p0_path_dirs, p1_path_dirs;
    std::string p0_evidence_signature, p1_evidence_signature;
    bool p0_path_received = false;
    bool p1_path_received = false;

    try {
        p0_root = recv_string(fd);
        uint64_t p0_path_len = recv_u64(fd);
        for(uint64_t i=0;i<p0_path_len;++i){ p0_path_elems.push_back(recv_string(fd)); p0_path_dirs.push_back(recv_u64(fd)); }
        p0_evidence_signature = recv_string(fd);
        p0_path_received = true;
        p1_root = recv_string(fd);
        uint64_t p1_path_len = recv_u64(fd);
        for(uint64_t i=0;i<p1_path_len;++i){ p1_path_elems.push_back(recv_string(fd)); p1_path_dirs.push_back(recv_u64(fd)); }
        p1_evidence_signature = recv_string(fd);
        p1_path_received = true;
    } catch (const std::exception& ex) {
        std::cerr << "[BIDDER] did not receive valid P0/P1 Merkle root/path from BidderBoss: " << ex.what() << "\n";
    }

    close(fd);

    bool p0_path_ok = false;
    bool p1_path_ok = false;
    bool p0_root_ok = false;
    bool p1_root_ok = false;
    bool p0_included = false;
    bool p1_included = false;
    std::string p0_onchain_root, p1_onchain_root;

    try {
        p0_path_ok = p0_path_received && merkle_path_matches_root(p0_leaf_hash, p0_root, p0_path_elems, p0_path_dirs);
    } catch (const std::exception& ex) {
        std::cerr << "[BIDDER] P0 Merkle path verification error: " << ex.what() << "\n";
        p0_path_ok = false;
    }
    try {
        p1_path_ok = p1_path_received && merkle_path_matches_root(p1_leaf_hash, p1_root, p1_path_elems, p1_path_dirs);
    } catch (const std::exception& ex) {
        std::cerr << "[BIDDER] P1 Merkle path verification error: " << ex.what() << "\n";
        p1_path_ok = false;
    }

    try {
        p0_onchain_root = read_onchain_commitment_root(args.read_root_tool, args.chain_rpc, args.auction_registry, args.session_id, args.role, 0);
        p0_root_ok = normalize_hex32(p0_root) == normalize_hex32(p0_onchain_root);
    } catch (const std::exception& ex) {
        std::cerr << "[BIDDER] could not read/check on-chain P0 Merkle root: " << ex.what() << "\n";
        p0_root_ok = false;
    }
    try {
        p1_onchain_root = read_onchain_commitment_root(args.read_root_tool, args.chain_rpc, args.auction_registry, args.session_id, args.role, 1);
        p1_root_ok = normalize_hex32(p1_root) == normalize_hex32(p1_onchain_root);
    } catch (const std::exception& ex) {
        std::cerr << "[BIDDER] could not read/check on-chain P1 Merkle root: " << ex.what() << "\n";
        p1_root_ok = false;
    }

    p0_included = p0_path_ok && p0_root_ok;
    p1_included = p1_path_ok && p1_root_ok;

    std::cout << "[BIDDER] merkle root of P0 " << args.role << " tree is " << (p0_root_ok ? "valid" : "invalid") << "\n";
    std::cout << "[BIDDER] merkle root of P1 " << args.role << " tree is " << (p1_root_ok ? "valid" : "invalid") << "\n";
    std::cout << "[BIDDER] merkle proof for P0 tree is " << (p0_included ? "valid" : "invalid")
              << " (path=" << (p0_path_ok ? "valid" : "invalid")
              << ", root=" << (p0_root_ok ? "valid" : "invalid") << ")\n";
    std::cout << "[BIDDER] merkle proof for P1 tree is " << (p1_included ? "valid" : "invalid")
              << " (path=" << (p1_path_ok ? "valid" : "invalid")
              << ", root=" << (p1_root_ok ? "valid" : "invalid") << ")\n";

    bool p0_has_signed_evidence = p0_path_received && !p0_evidence_signature.empty();
    bool p1_has_signed_evidence = p1_path_received && !p1_evidence_signature.empty();

    uint64_t challenge_party_id = 0;
    bool can_submit_merkle_challenge = false;

    if (!p0_included && p0_has_signed_evidence) {
        challenge_party_id = 0;
        can_submit_merkle_challenge = true;
    } else if (!p1_included && p1_has_signed_evidence) {
        challenge_party_id = 1;
        can_submit_merkle_challenge = true;
    }

    save_receipt_json(args.out, args, c0, c1,
        p0_receipt_hash, p0_leaf_hash, p0_receipt_sig, p0_root, p0_path_elems, p0_path_dirs, p0_evidence_signature,
        p1_receipt_hash, p1_leaf_hash, p1_receipt_sig, p1_root, p1_path_elems, p1_path_dirs, p1_evidence_signature,
        challenge_party_id);
    std::cout << "[BIDDER] saved receipt/paths to " << args.out << "\n";

    if (p0_included && p1_included) {
        std::cout << "[BIDDER] Both P0 and P1 Merkle paths are valid. No challenge sent.\n";
        return 0;
    }

    if (!can_submit_merkle_challenge) {
        std::cerr
            << "[BIDDER] Merkle paths/roots are missing or not yet signed by BidderBoss. "
            << "No automatic Merkle dispute is submitted, because the contract needs "
            << "BidderBoss-signed Merkle evidence. Start all expected bidders and wait until "
            << "BidderBoss sends paths.\n";
        return 0;
    }

    std::cerr << "[BIDDER] Signed Merkle evidence is present but invalid. Sending automatic challenge to smart contract...\n";
    return run_challenge_file(
        args.challenge_tool,
        args.chain_rpc,
        args.auction_registry,
        args.eth_priv,
        args.session_id,
        args.out
    );
}

static int run_challenge_file(
    const std::string& challenge_tool,
    const std::string& chain_rpc,
    const std::string& auction_registry,
    const std::string& eth_priv,
    uint64_t session_id,
    const std::string& receipt_file
) {
    std::ostringstream cmd;
    cmd << "node " << shell_quote(challenge_tool)
        << " --rpc " << shell_quote(chain_rpc)
        << " --contract " << shell_quote(auction_registry)
        << " --priv-file " << shell_quote(eth_priv)
        << " --session-id " << session_id
        << " --receipt-file " << shell_quote(receipt_file);
    std::cout << exec_cmd(cmd.str()) << "\n";
    return 0;
}

static int run_challenge(const Args& args) {
    return run_challenge_file(
        args.challenge_tool,
        args.chain_rpc,
        args.auction_registry,
        args.eth_priv,
        args.session_id,
        args.receipt_file
    );
}


} // namespace

int main(int argc, char** argv) {
    try {
        signal(SIGPIPE, SIG_IGN);
        Args args = parse_args(argc, argv);
        if (args.mode == "challenge") return run_challenge(args);
        return run_submit(args);
    } catch (const std::exception& e) {
        std::cerr << "bidder.cpp error: " << e.what() << "\n";
        return 1;
    }
}
