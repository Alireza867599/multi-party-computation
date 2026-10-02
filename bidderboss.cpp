// bidderboss.cpp
// BidderBoss receives complete signed bidder packets from normal bidders.
// It does NOT create shares, commitments, encrypted shares, or CCE proofs.
// It signs a receipt, builds four Merkle trees from commitment receipts
// (buyer-P0, buyer-P1, seller-P0, seller-P1). After receiving all expected
// bidders, it immediately submits the four roots to AuctionRegistry,
// relays Merkle evidence to P0/P1, and serves
// randomness reveal requests. It can also answer a Merkle challenge on-chain.
//
// Build:
//   g++ -O2 -std=c++17 bidderboss.cpp -lcrypto -o bidderboss
//
// Collect/relay/root example:
//   ./bidderboss --mode run --nbuyers 2 --nsellers 2 --listen 7500 \
//     --session-id 0 --p0 127.0.0.1 --p1 127.0.0.1 \
//     --chain-rpc http://127.0.0.1:8545 \
//     --auction-registry 0x5FbDB2315678afecb367f032d93F642f64180aa3 \
//     --eth-priv keys/bidderboss.eth.priv
//
// Answer challenge example:
//   ./bidderboss --mode answer-challenge --challenge-id 0 \
//     --path-file onchain/merkle_path_session0_buyer_Alice.json \
//     --chain-rpc http://127.0.0.1:8545 \
//     --auction-registry 0x5FbDB2315678afecb367f032d93F642f64180aa3 \
//     --eth-priv keys/bidderboss.eth.priv
//
// NOTE: P0/P1 must parse the new V2 relay packet because it includes commitment
// fields before the encrypted packet/proof fields.

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

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
static const char* RELAY_MAGIC = "SFDAC-MERKLE-EVIDENCE-V1";

struct Args {
    std::string mode = "run"; // run, answer-challenge, finalize-challenge
    uint64_t nbuyers = 0;
    uint64_t nsellers = 0;
    uint16_t listen_port = 7500;
    uint16_t reveal_port = 7700;
    uint64_t session_id = 0;
    std::string p0_ip = "127.0.0.1";
    std::string p1_ip = "127.0.0.1";
    std::string chain_rpc;
    std::string auction_registry;
    std::string eth_priv;
    std::string sign_receipt_tool = "scripts/sign_commitment_receipt.js";
    std::string sign_merkle_evidence_tool = "scripts/sign_merkle_evidence.js";
    std::string sign_commitment_vector_tool = "scripts/sign_commitment_vector.js";
    std::string submit_roots_tool = "scripts/submit_commitment_roots.js";
    std::string answer_challenge_tool = "scripts/answer_commitment_challenge.js";
    std::string metadata_dir = "onchain";
    std::string metadata_uri_prefix = "file://onchain";
    uint64_t challenge_id = 0;
    std::string path_file;
};

struct HybridCiphertext {
    std::array<uint8_t,33> eph{};
    std::array<uint8_t,12> iv{};
    std::array<uint8_t,16> tag{};
    std::vector<uint8_t> ct;
};

struct OpenProof { std::string Ax, Ay, z; };

struct PartyPacket {
    HybridCiphertext enc_bid;
    HybridCiphertext enc_id;
    OpenProof proof;
    std::array<uint8_t,64> ed_sig{};
    std::string eth_sig;
    std::string commitment_sig;
    // Keep this wire format in sync with bidder.cpp::send_party_packet().
    // The Sigma CCE JSON is signed by eth_sig and must be relayed to P0/P1 so
    // they can submit/verify signed invalid-CCE evidence.
    std::string sigma_cce_json;
    // Reserved/legacy field currently sent by bidder.cpp as an empty string.
    std::string reserved;
};

struct MerkleEvidence {
    std::string receipt_hash;
    std::string leaf_hash;
    std::string receipt_signature;
    std::string root;
    std::string evidence_signature;
    std::string vector_signature;
    std::vector<std::string> path_elements;
    std::vector<uint8_t> path_directions;
};

struct Entry {
    int sock = -1;
    uint64_t session_id = 0;
    std::string role;
    std::string name;
    uint64_t bidder_id = 0;
    std::string commit_domain;
    std::string c0x, c0y, c1x, c1y;
    std::string r0, r1;
    PartyPacket p0;
    PartyPacket p1;
    MerkleEvidence p0_merkle;
    MerkleEvidence p1_merkle;
};

static std::string need(int& i, int argc, char** argv, const std::string& flag) {
    if (i + 1 >= argc) throw std::runtime_error("missing value for " + flag);
    return argv[++i];
}

static Args parse_args(int argc, char** argv) {
    Args a;
    for (int i=1;i<argc;++i) {
        std::string s = argv[i];
        if (s == "--mode") a.mode = need(i,argc,argv,s);
        else if (s == "--nbuyers") a.nbuyers = std::stoull(need(i,argc,argv,s));
        else if (s == "--nsellers") a.nsellers = std::stoull(need(i,argc,argv,s));
        else if (s == "--listen") a.listen_port = static_cast<uint16_t>(std::stoul(need(i,argc,argv,s)));
        else if (s == "--reveal-port") a.reveal_port = static_cast<uint16_t>(std::stoul(need(i,argc,argv,s)));
        else if (s == "--session-id") a.session_id = std::stoull(need(i,argc,argv,s));
        else if (s == "--p0") a.p0_ip = need(i,argc,argv,s);
        else if (s == "--p1") a.p1_ip = need(i,argc,argv,s);
        else if (s == "--chain-rpc") a.chain_rpc = need(i,argc,argv,s);
        else if (s == "--auction-registry" || s == "--registry") a.auction_registry = need(i,argc,argv,s);
        else if (s == "--eth-priv") a.eth_priv = need(i,argc,argv,s);
        else if (s == "--sign-receipt-tool") a.sign_receipt_tool = need(i,argc,argv,s);
        else if (s == "--sign-merkle-evidence-tool") a.sign_merkle_evidence_tool = need(i,argc,argv,s);
        else if (s == "--sign-commitment-vector-tool") a.sign_commitment_vector_tool = need(i,argc,argv,s);
        else if (s == "--submit-roots-tool") a.submit_roots_tool = need(i,argc,argv,s);
        else if (s == "--answer-challenge-tool") a.answer_challenge_tool = need(i,argc,argv,s);
        else if (s == "--metadata-dir") a.metadata_dir = need(i,argc,argv,s);
        else if (s == "--metadata-uri-prefix") a.metadata_uri_prefix = need(i,argc,argv,s);
        else if (s == "--challenge-id") a.challenge_id = std::stoull(need(i,argc,argv,s));
        else if (s == "--path-file") a.path_file = need(i,argc,argv,s);
        else throw std::runtime_error("unknown arg: " + s);
    }
    if (a.mode != "run" && a.mode != "answer-challenge" && a.mode != "finalize-challenge") throw std::runtime_error("bad --mode");
    if (a.chain_rpc.empty() || a.auction_registry.empty() || a.eth_priv.empty()) throw std::runtime_error("--chain-rpc --auction-registry --eth-priv required");
    if (a.mode == "run" && a.nbuyers + a.nsellers == 0) throw std::runtime_error("run mode requires --nbuyers/--nsellers");
    if (a.mode == "answer-challenge" && a.path_file.empty()) throw std::runtime_error("answer-challenge requires --path-file");
    return a;
}

static void ensure_parent_dir(const std::string& path) { fs::path p(path); if(!p.parent_path().empty()) fs::create_directories(p.parent_path()); }
static void set_sock_timeouts(int fd, int seconds) { timeval tv{}; tv.tv_sec=seconds; tv.tv_usec=0; setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv)); setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv)); }
static void clear_sock_timeouts(int fd) { timeval tv{}; setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv)); setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv)); }

static void send_all(int fd, const void* data, size_t len) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    while(len>0){ ssize_t n=::send(fd,p,len,MSG_NOSIGNAL); if(n<0){ if(errno==EINTR)continue; throw std::runtime_error("send failed: "+std::string(strerror(errno))); } if(n==0) throw std::runtime_error("send peer closed"); p+=n; len-=n; }
}
static void recv_all(int fd, void* data, size_t len) {
    uint8_t* p = static_cast<uint8_t*>(data);
    while(len>0){ ssize_t n=::recv(fd,p,len,MSG_WAITALL); if(n<0){ if(errno==EINTR)continue; throw std::runtime_error("recv failed: "+std::string(strerror(errno))); } if(n==0) throw std::runtime_error("recv peer closed"); p+=n; len-=n; }
}
static void send_u64(int fd, uint64_t v) { uint64_t be=htobe64(v); send_all(fd,&be,8); }
static uint64_t recv_u64(int fd) { uint64_t be=0; recv_all(fd,&be,8); return be64toh(be); }
static void send_string(int fd, const std::string& s) { send_u64(fd,s.size()); if(!s.empty()) send_all(fd,s.data(),s.size()); }
static std::string recv_string(int fd) { uint64_t n=recv_u64(fd); std::string s(n,'\0'); if(n) recv_all(fd,&s[0],n); return s; }

static int create_listener(uint16_t port) {
    int fd=::socket(AF_INET,SOCK_STREAM,0); if(fd<0) throw std::runtime_error("socket failed");
    int opt=1; setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
    sockaddr_in a{}; a.sin_family=AF_INET; a.sin_addr.s_addr=INADDR_ANY; a.sin_port=htons(port);
    if(bind(fd,reinterpret_cast<sockaddr*>(&a),sizeof(a))<0) throw std::runtime_error("bind failed: "+std::string(strerror(errno)));
    if(listen(fd,128)<0) throw std::runtime_error("listen failed");
    return fd;
}

static int connect_to(const std::string& ip, uint16_t port) {
    int fd=::socket(AF_INET,SOCK_STREAM,0); if(fd<0) throw std::runtime_error("socket failed");
    set_sock_timeouts(fd,20); sockaddr_in a{}; a.sin_family=AF_INET; a.sin_port=htons(port);
    if(inet_pton(AF_INET,ip.c_str(),&a.sin_addr)!=1){ close(fd); throw std::runtime_error("bad ip"); }
    if(connect(fd,reinterpret_cast<sockaddr*>(&a),sizeof(a))<0){ close(fd); throw std::runtime_error("connect failed: "+std::string(strerror(errno))); }
    return fd;
}

static int connect_to_retry(const std::string& ip, uint16_t port, const std::string& label, int attempts = 180, int sleep_ms = 500) {
    int last_errno = 0;
    for (int attempt = 1; attempt <= attempts; ++attempt) {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) throw std::runtime_error("socket failed");
        set_sock_timeouts(fd, 20);

        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port = htons(port);
        if (inet_pton(AF_INET, ip.c_str(), &a.sin_addr) != 1) {
            close(fd);
            throw std::runtime_error("bad ip");
        }

        if (connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0) {
            if (attempt > 1) {
                std::cout << "[BOSS] connected to " << label << " " << ip << ":" << port
                          << " after attempt " << attempt << "/" << attempts << "\n";
            }
            return fd;
        }

        last_errno = errno;
        close(fd);
        if (attempt == 1 || attempt % 10 == 0 || attempt == attempts) {
            std::cout << "[BOSS] waiting for " << label << " " << ip << ":" << port
                      << " attempt=" << attempt << "/" << attempts
                      << " errno=" << last_errno << "\n";
        }
        usleep(static_cast<useconds_t>(sleep_ms) * 1000);
    }

    throw std::runtime_error("connect failed to " + label + " " + ip + ":" + std::to_string(port) + " after retries errno=" + std::to_string(last_errno));
}

static uint16_t p0_port_for(const std::string& role) { return role == "buyer" ? 7000 : 7002; }
static uint16_t p1_port_for(const std::string& role) { return role == "buyer" ? 7001 : 7003; }

static std::string shell_quote(const std::string& s) { std::string o="'"; for(char c:s) o += (c=='\'') ? "'\\''" : std::string(1,c); o += "'"; return o; }
static std::string rtrim(std::string s){ while(!s.empty()&&(s.back()=='\n'||s.back()=='\r'||s.back()==' '||s.back()=='\t')) s.pop_back(); return s; }
static std::string exec_cmd(const std::string& cmd) { std::array<char,4096> buf{}; std::string out; FILE* fp=popen(cmd.c_str(),"r"); if(!fp) throw std::runtime_error("popen failed"); while(true){ size_t n=fread(buf.data(),1,buf.size(),fp); if(n) out.append(buf.data(),n); if(n<buf.size()) break; } int rc=pclose(fp); if(rc!=0) throw std::runtime_error("cmd failed: "+cmd+"\n"+out); return out; }
static std::string json_escape(const std::string& s){ std::string o; for(unsigned char c:s){ if(c=='\\')o+="\\\\"; else if(c=='"')o+="\\\""; else if(c=='\n')o+="\\n"; else if(c=='\r')o+="\\r"; else if(c=='\t')o+="\\t"; else o.push_back(c);} return o; }
static std::string json_get_string(const std::string& json, const std::string& key){ std::string pat="\""+key+"\""; size_t k=json.find(pat); if(k==std::string::npos) throw std::runtime_error("missing key "+key); size_t c=json.find(':',k); size_t p=c+1; while(p<json.size()&&std::isspace((unsigned char)json[p]))p++; if(p>=json.size()||json[p]!='"') throw std::runtime_error("not string "+key); size_t e=json.find('"',p+1); if(e==std::string::npos) throw std::runtime_error("unterminated"); return json.substr(p+1,e-p-1); }

static std::string bytes_to_hex(const uint8_t* p, size_t n){ static const char* lut="0123456789abcdef"; std::string s(n*2,'0'); for(size_t i=0;i<n;++i){ s[2*i]=lut[p[i]>>4]; s[2*i+1]=lut[p[i]&15]; } return s; }
static std::string hex32_normalize(std::string h){ while(!h.empty()&&std::isspace((unsigned char)h.back()))h.pop_back(); if(h.rfind("0x",0)!=0) h="0x"+h; return h; }
static std::array<uint8_t,32> hex32_to_bytes(std::string h){ if(h.rfind("0x",0)==0) h=h.substr(2); if(h.size()!=64) throw std::runtime_error("expected bytes32 hex"); std::array<uint8_t,32> out{}; auto hv=[](char c){ if('0'<=c&&c<='9') return c-'0'; if('a'<=c&&c<='f') return 10+c-'a'; if('A'<=c&&c<='F') return 10+c-'A'; return -1; }; for(size_t i=0;i<32;++i){ int hi=hv(h[2*i]),lo=hv(h[2*i+1]); if(hi<0||lo<0) throw std::runtime_error("bad hex32"); out[i]=(hi<<4)|lo; } return out; }
static std::string bytes32_hex(const std::array<uint8_t,32>& b){ return "0x" + bytes_to_hex(b.data(),32); }
static std::string read_text(const std::string& path){ std::ifstream in(path); if(!in) throw std::runtime_error("cannot read "+path); return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>()); }
static void write_text(const std::string& path,const std::string& data){ ensure_parent_dir(path); std::ofstream out(path); if(!out) throw std::runtime_error("cannot write "+path); out<<data; }
static std::string sha256_text_hex(const std::string& data){ uint8_t d[32]; SHA256(reinterpret_cast<const uint8_t*>(data.data()), data.size(), d); return "0x"+bytes_to_hex(d,32); }

static HybridCiphertext recv_hybrid(int fd){ HybridCiphertext h; recv_all(fd,h.eph.data(),33); recv_all(fd,h.iv.data(),12); recv_all(fd,h.tag.data(),16); uint64_t n=recv_u64(fd); h.ct.resize(n); if(n) recv_all(fd,h.ct.data(),n); return h; }
static void send_hybrid(int fd,const HybridCiphertext& h){ send_all(fd,h.eph.data(),33); send_all(fd,h.iv.data(),12); send_all(fd,h.tag.data(),16); send_u64(fd,h.ct.size()); if(!h.ct.empty()) send_all(fd,h.ct.data(),h.ct.size()); }
static OpenProof recv_proof(int fd){ return OpenProof{recv_string(fd), recv_string(fd), recv_string(fd)}; }
static void send_proof(int fd,const OpenProof& p){ send_string(fd,p.Ax); send_string(fd,p.Ay); send_string(fd,p.z); }
static PartyPacket recv_party_packet(int fd){
    PartyPacket p;
    p.enc_bid=recv_hybrid(fd);
    p.enc_id=recv_hybrid(fd);
    p.proof=recv_proof(fd);
    recv_all(fd,p.ed_sig.data(),64);
    p.eth_sig=recv_string(fd);
    p.commitment_sig=recv_string(fd);
    p.sigma_cce_json=recv_string(fd);
    p.reserved=recv_string(fd);
    return p;
}

static Entry recv_entry(int sock) {
    std::string magic = recv_string(sock);
    if (magic != WIRE_MAGIC) throw std::runtime_error("bad bidder packet magic: " + magic);
    Entry e; e.sock = sock; e.session_id = recv_u64(sock); e.role = recv_string(sock); e.name = recv_string(sock); e.bidder_id = recv_u64(sock); e.commit_domain = recv_string(sock);
    e.c0x=recv_string(sock); e.c0y=recv_string(sock); e.c1x=recv_string(sock); e.c1y=recv_string(sock);
    e.r0=recv_string(sock); e.r1=recv_string(sock);
    e.p0=recv_party_packet(sock); e.p1=recv_party_packet(sock);
    if(e.role!="buyer" && e.role!="seller") throw std::runtime_error("bad role from bidder: "+e.role);
    return e;
}

static const MerkleEvidence& merkle_for_party(const Entry& e, uint64_t party_id) {
    return party_id == 0 ? e.p0_merkle : e.p1_merkle;
}

static MerkleEvidence& merkle_for_party_mut(Entry& e, uint64_t party_id) {
    return party_id == 0 ? e.p0_merkle : e.p1_merkle;
}

static void send_receipt_to_bidder(const Entry& e) {
    // Send both party-specific receipts. The bidder verifies inclusion in both
    // P0 and P1 trees after BidderBoss sends the paths.
    send_string(e.sock, e.p0_merkle.receipt_hash);
    send_string(e.sock, e.p0_merkle.leaf_hash);
    send_string(e.sock, e.p0_merkle.receipt_signature);
    send_string(e.sock, e.p1_merkle.receipt_hash);
    send_string(e.sock, e.p1_merkle.leaf_hash);
    send_string(e.sock, e.p1_merkle.receipt_signature);
}

static void send_one_path_to_bidder(int sock, const MerkleEvidence& m) {
    send_string(sock, m.root);
    send_u64(sock, m.path_elements.size());
    for(size_t i=0;i<m.path_elements.size();++i){
        send_string(sock, m.path_elements[i]);
        send_u64(sock, m.path_directions[i]);
    }
    send_string(sock, m.evidence_signature);
}

static void send_path_to_bidder(const Entry& e) {
    send_one_path_to_bidder(e.sock, e.p0_merkle);
    send_one_path_to_bidder(e.sock, e.p1_merkle);
}

static void send_merkle_evidence_to_auctioneer(const std::string& ip, uint16_t port, const Entry& e, uint64_t party_id) {
    const PartyPacket& p = (party_id == 0) ? e.p0 : e.p1;
    const MerkleEvidence& m = merkle_for_party(e, party_id);
    std::string label = std::string("auctioneer Merkle evidence port for ") + e.role + " " + e.name;
    int fd = connect_to_retry(ip, port, label);
    send_string(fd, RELAY_MAGIC);
    send_u64(fd, e.session_id);
    send_u64(fd, party_id);
    send_string(fd, e.role);
    send_string(fd, e.name);
    send_u64(fd, e.bidder_id);
    send_string(fd, e.commit_domain);
    send_string(fd, e.c0x); send_string(fd, e.c0y); send_string(fd, e.c1x); send_string(fd, e.c1y);

    // Party-specific Merkle evidence generated by BidderBoss for this exact
    // accepted packet. P0 receives ONLY buyerP0/sellerP0 evidence.
    // P1 receives ONLY buyerP1/sellerP1 evidence. Neither auctioneer receives
    // or verifies the other auctioneer's Merkle tree.
    send_string(fd, m.receipt_hash);
    send_string(fd, m.leaf_hash);
    send_string(fd, m.receipt_signature);
    send_string(fd, m.root);
    send_u64(fd, m.path_elements.size());
    for (size_t i = 0; i < m.path_elements.size(); ++i) {
        send_string(fd, m.path_elements[i]);
        send_u64(fd, m.path_directions[i]);
    }
    send_string(fd, m.evidence_signature);
    send_string(fd, m.vector_signature);

    send_hybrid(fd, p.enc_bid);
    send_hybrid(fd, p.enc_id);
    send_proof(fd, p.proof);
    send_all(fd, p.ed_sig.data(), p.ed_sig.size());
    send_string(fd, p.eth_sig);
    send_string(fd, p.commitment_sig);
    send_string(fd, p.sigma_cce_json);
    send_string(fd, p.reserved);
    close(fd);
}

static std::string sign_receipt(const Args& args, const Entry& e, uint64_t party_id) {
    std::ostringstream cmd;
    cmd << "node " << shell_quote(args.sign_receipt_tool)
        << " --rpc " << shell_quote(args.chain_rpc)
        << " --contract " << shell_quote(args.auction_registry)
        << " --priv-file " << shell_quote(args.eth_priv)
        << " --session-id " << e.session_id
        << " --party-id " << party_id
        << " --role " << shell_quote(e.role)
        << " --name " << shell_quote(e.name)
        << " --bidder-id " << e.bidder_id
        << " --commit-domain " << shell_quote(e.commit_domain)
        << " --c0x " << shell_quote(e.c0x)
        << " --c0y " << shell_quote(e.c0y)
        << " --c1x " << shell_quote(e.c1x)
        << " --c1y " << shell_quote(e.c1y);
    return exec_cmd(cmd.str());
}

static std::string join_string_csv(const std::vector<std::string>& values) {
    std::ostringstream os;
    for (size_t i = 0; i < values.size(); ++i) {
        if (i) os << ",";
        os << values[i];
    }
    return os.str();
}

static std::string join_dir_csv(const std::vector<uint8_t>& values) {
    std::ostringstream os;
    for (size_t i = 0; i < values.size(); ++i) {
        if (i) os << ",";
        os << static_cast<uint64_t>(values[i]);
    }
    return os.str();
}

static std::string sign_merkle_evidence(const Args& args, const Entry& e, uint64_t party_id) {
    const MerkleEvidence& m = merkle_for_party(e, party_id);
    std::ostringstream cmd;
    cmd << "node " << shell_quote(args.sign_merkle_evidence_tool)
        << " --rpc " << shell_quote(args.chain_rpc)
        << " --contract " << shell_quote(args.auction_registry)
        << " --priv-file " << shell_quote(args.eth_priv)
        << " --session-id " << e.session_id
        << " --party-id " << party_id
        << " --role " << shell_quote(e.role)
        << " --name " << shell_quote(e.name)
        << " --bidder-id " << e.bidder_id
        << " --receipt-hash " << shell_quote(m.receipt_hash)
        << " --root " << shell_quote(m.root)
        << " --path-elements " << shell_quote(join_string_csv(m.path_elements))
        << " --path-directions " << shell_quote(join_dir_csv(m.path_directions));
    return exec_cmd(cmd.str());
}

static std::string sign_commitment_vector(const Args& args, const std::string& role, uint64_t party_id, const std::string& root, uint64_t count) {
    std::ostringstream cmd;
    cmd << "node " << shell_quote(args.sign_commitment_vector_tool)
        << " --rpc " << shell_quote(args.chain_rpc)
        << " --contract " << shell_quote(args.auction_registry)
        << " --priv-file " << shell_quote(args.eth_priv)
        << " --session-id " << args.session_id
        << " --party-id " << party_id
        << " --role " << shell_quote(role)
        << " --root " << shell_quote(root)
        << " --count " << count;
    return exec_cmd(cmd.str());
}

static std::array<uint8_t,32> sha_pair(const std::array<uint8_t,32>& a, const std::array<uint8_t,32>& b){ uint8_t buf[64]; std::memcpy(buf,a.data(),32); std::memcpy(buf+32,b.data(),32); std::array<uint8_t,32> out{}; SHA256(buf,64,out.data()); return out; }

struct MerkleTree {
    std::vector<std::string> leaves_hex;
    std::vector<std::vector<std::array<uint8_t,32>>> levels;
};

static MerkleTree build_tree(const std::vector<std::string>& leaves_hex) {
    MerkleTree t; t.leaves_hex = leaves_hex;
    std::vector<std::array<uint8_t,32>> cur;
    for (const auto& h: leaves_hex) cur.push_back(hex32_to_bytes(h));
    if (cur.empty()) { std::array<uint8_t,32> zero{}; cur.push_back(zero); }
    t.levels.push_back(cur);
    while (cur.size() > 1) {
        std::vector<std::array<uint8_t,32>> next;
        for (size_t i=0;i<cur.size();i+=2) {
            auto left = cur[i];
            auto right = (i+1 < cur.size()) ? cur[i+1] : cur[i];
            next.push_back(sha_pair(left, right));
        }
        cur = next; t.levels.push_back(cur);
    }
    return t;
}

static std::string tree_root(const MerkleTree& t) { return bytes32_hex(t.levels.back()[0]); }

static void fill_path_from_tree(MerkleEvidence& m, const MerkleTree& t, size_t leaf_index) {
    m.root = tree_root(t);
    m.path_elements.clear();
    m.path_directions.clear();
    size_t idx = leaf_index;
    for (size_t level = 0; level + 1 < t.levels.size(); ++level) {
        const auto& nodes = t.levels[level];
        bool is_right = (idx % 2) == 1;
        size_t sibling = is_right ? idx - 1 : idx + 1;
        if (sibling >= nodes.size()) sibling = idx;
        m.path_elements.push_back(bytes32_hex(nodes[sibling]));
        m.path_directions.push_back(is_right ? 1 : 0);
        idx /= 2;
    }
}

static void write_one_path_file(const Args& args, const Entry& e, uint64_t party_id) {
    const MerkleEvidence& m = merkle_for_party(e, party_id);
    std::ostringstream path;
    path << args.metadata_dir << "/merkle_path_session" << e.session_id << "_" << e.role << "_p" << party_id << "_" << e.name << ".json";
    std::ostringstream os; os << "{\n  \"partyId\": " << party_id << ",\n  \"pathElements\": [";
    for(size_t i=0;i<m.path_elements.size();++i){ if(i) os << ","; os << "\"" << m.path_elements[i] << "\""; }
    os << "],\n  \"pathDirections\": [";
    for(size_t i=0;i<m.path_directions.size();++i){ if(i) os << ","; os << (uint64_t)m.path_directions[i]; }
    os << "],\n  \"root\": \"" << m.root << "\",\n  \"evidenceSignature\": \"" << m.evidence_signature << "\"\n}\n";
    write_text(path.str(), os.str());
}

static void write_path_files(const Args& args, const Entry& e) {
    write_one_path_file(args, e, 0);
    write_one_path_file(args, e, 1);
}

static std::string build_metadata_json(
    const Args& args,
    const std::vector<Entry>& entries,
    const std::string& buyer_p0_root,
    const std::string& buyer_p1_root,
    const std::string& seller_p0_root,
    const std::string& seller_p1_root
) {
    std::ostringstream os;
    os << "{\n  \"sessionId\": \"" << args.session_id << "\",\n"
       << "  \"buyerP0Root\": \"" << buyer_p0_root << "\",\n"
       << "  \"buyerP1Root\": \"" << buyer_p1_root << "\",\n"
       << "  \"sellerP0Root\": \"" << seller_p0_root << "\",\n"
       << "  \"sellerP1Root\": \"" << seller_p1_root << "\",\n"
       << "  \"entries\": [\n";
    for(size_t i=0;i<entries.size();++i){
        const auto& e=entries[i]; if(i) os << ",\n"; os
       << "    {\"role\":\"" << json_escape(e.role) << "\",\"name\":\"" << json_escape(e.name) << "\",\"bidderId\":\"" << e.bidder_id << "\","
       << "\"commitDomain\":\"" << json_escape(e.commit_domain) << "\","
       << "\"c0x\":\"" << e.c0x << "\",\"c0y\":\"" << e.c0y << "\",\"c1x\":\"" << e.c1x << "\",\"c1y\":\"" << e.c1y << "\","
       << "\"p0ReceiptHash\":\"" << e.p0_merkle.receipt_hash << "\",\"p0LeafHash\":\"" << e.p0_merkle.leaf_hash << "\",\"p0ReceiptSignature\":\"" << e.p0_merkle.receipt_signature << "\","
       << "\"p1ReceiptHash\":\"" << e.p1_merkle.receipt_hash << "\",\"p1LeafHash\":\"" << e.p1_merkle.leaf_hash << "\",\"p1ReceiptSignature\":\"" << e.p1_merkle.receipt_signature << "\"}";
    }
    os << "\n  ]\n}\n";
    return os.str();
}

static void submit_roots(
    const Args& args,
    const std::string& buyer_p0_root,
    const std::string& buyer_p1_root,
    const std::string& seller_p0_root,
    const std::string& seller_p1_root,
    uint64_t buyer_count,
    uint64_t seller_count,
    const std::string& metadata_hash,
    const std::string& metadata_uri
) {
    std::ostringstream cmd;
    cmd << "node " << shell_quote(args.submit_roots_tool)
        << " --rpc " << shell_quote(args.chain_rpc)
        << " --contract " << shell_quote(args.auction_registry)
        << " --priv-file " << shell_quote(args.eth_priv)
        << " --session-id " << args.session_id
        << " --buyer-p0-root " << shell_quote(buyer_p0_root)
        << " --buyer-p1-root " << shell_quote(buyer_p1_root)
        << " --seller-p0-root " << shell_quote(seller_p0_root)
        << " --seller-p1-root " << shell_quote(seller_p1_root)
        << " --buyer-count " << buyer_count
        << " --seller-count " << seller_count
        << " --metadata-hash " << shell_quote(metadata_hash)
        << " --metadata-uri " << shell_quote(metadata_uri);
    std::cout << exec_cmd(cmd.str()) << "\n";
}

static void serve_reveal(uint16_t port, const std::vector<Entry>& entries) {
    int listener = create_listener(port); clear_sock_timeouts(listener);
    std::cout << "[BOSS] reveal server on port " << port << "\n";
    while (true) {
        int sock = accept(listener, nullptr, nullptr); if(sock<0){ if(errno==EINTR) continue; continue; }
        set_sock_timeouts(sock, 30);
        try {
            std::string who = recv_string(sock); uint64_t which = recv_u64(sock);
            send_u64(sock, entries.size());
            for(const auto& e: entries){ send_string(sock,e.role); send_string(sock,e.name); send_u64(sock,e.bidder_id); send_string(sock, which==0 ? e.r0 : e.r1); }
            std::cout << "[BOSS] served randomness to " << who << " party=" << which << " count=" << entries.size() << "\n";
        } catch(const std::exception& ex){ std::cerr << "[BOSS] reveal error: " << ex.what() << "\n"; }
        close(sock);
    }
}

static int run_mode(const Args& args) {
    fs::create_directories(args.metadata_dir);
    int listener = create_listener(args.listen_port);
    std::vector<Entry> entries; entries.reserve(args.nbuyers + args.nsellers);
    uint64_t buyers=0, sellers=0;
    std::cout << "[BOSS] listening on " << args.listen_port << "\n";
    while (buyers < args.nbuyers || sellers < args.nsellers) {
        int sock = accept(listener, nullptr, nullptr); if(sock<0) continue; set_sock_timeouts(sock, 180);
        try {
            Entry e = recv_entry(sock);
            if(e.session_id != args.session_id) throw std::runtime_error("wrong session id");
            if(e.role == "buyer") { if(buyers >= args.nbuyers) throw std::runtime_error("too many buyers"); buyers++; }
            else { if(sellers >= args.nsellers) throw std::runtime_error("too many sellers"); sellers++; }
            std::string js0 = sign_receipt(args, e, 0);
            e.p0_merkle.receipt_hash = hex32_normalize(json_get_string(js0, "receiptHash"));
            e.p0_merkle.leaf_hash = hex32_normalize(json_get_string(js0, "leafHash"));
            e.p0_merkle.receipt_signature = json_get_string(js0, "signature");
            std::string js1 = sign_receipt(args, e, 1);
            e.p1_merkle.receipt_hash = hex32_normalize(json_get_string(js1, "receiptHash"));
            e.p1_merkle.leaf_hash = hex32_normalize(json_get_string(js1, "leafHash"));
            e.p1_merkle.receipt_signature = json_get_string(js1, "signature");
            send_receipt_to_bidder(e);
            std::cout << "[BOSS] accepted " << e.role << " " << e.name
                      << " p0Leaf=" << e.p0_merkle.leaf_hash
                      << " p1Leaf=" << e.p1_merkle.leaf_hash << "\n";
            entries.push_back(std::move(e));
        } catch(const std::exception& ex) { std::cerr << "[BOSS] receive error: " << ex.what() << "\n"; close(sock); }
    }
    close(listener);

    std::vector<std::string> buyer_p0_leaves, buyer_p1_leaves, seller_p0_leaves, seller_p1_leaves;
    std::vector<size_t> buyer_idx, seller_idx;
    for(size_t i=0;i<entries.size();++i){
        if(entries[i].role=="buyer"){
            buyer_p0_leaves.push_back(entries[i].p0_merkle.leaf_hash);
            buyer_p1_leaves.push_back(entries[i].p1_merkle.leaf_hash);
            buyer_idx.push_back(i);
        } else {
            seller_p0_leaves.push_back(entries[i].p0_merkle.leaf_hash);
            seller_p1_leaves.push_back(entries[i].p1_merkle.leaf_hash);
            seller_idx.push_back(i);
        }
    }
    MerkleTree buyer_p0_tree = build_tree(buyer_p0_leaves);
    MerkleTree buyer_p1_tree = build_tree(buyer_p1_leaves);
    MerkleTree seller_p0_tree = build_tree(seller_p0_leaves);
    MerkleTree seller_p1_tree = build_tree(seller_p1_leaves);
    std::string buyer_p0_root = tree_root(buyer_p0_tree);
    std::string buyer_p1_root = tree_root(buyer_p1_tree);
    std::string seller_p0_root = tree_root(seller_p0_tree);
    std::string seller_p1_root = tree_root(seller_p1_tree);
    for(size_t i=0;i<buyer_idx.size();++i) {
        fill_path_from_tree(entries[buyer_idx[i]].p0_merkle, buyer_p0_tree, i);
        fill_path_from_tree(entries[buyer_idx[i]].p1_merkle, buyer_p1_tree, i);
    }
    for(size_t i=0;i<seller_idx.size();++i) {
        fill_path_from_tree(entries[seller_idx[i]].p0_merkle, seller_p0_tree, i);
        fill_path_from_tree(entries[seller_idx[i]].p1_merkle, seller_p1_tree, i);
    }

    std::string buyer_p0_vector_sig = json_get_string(sign_commitment_vector(args, "buyer", 0, buyer_p0_root, buyers), "signature");
    std::string buyer_p1_vector_sig = json_get_string(sign_commitment_vector(args, "buyer", 1, buyer_p1_root, buyers), "signature");
    std::string seller_p0_vector_sig = json_get_string(sign_commitment_vector(args, "seller", 0, seller_p0_root, sellers), "signature");
    std::string seller_p1_vector_sig = json_get_string(sign_commitment_vector(args, "seller", 1, seller_p1_root, sellers), "signature");

    for(auto& e: entries) {
        if (e.role == "buyer") {
            e.p0_merkle.vector_signature = buyer_p0_vector_sig;
            e.p1_merkle.vector_signature = buyer_p1_vector_sig;
        } else {
            e.p0_merkle.vector_signature = seller_p0_vector_sig;
            e.p1_merkle.vector_signature = seller_p1_vector_sig;
        }
        std::string ev0 = sign_merkle_evidence(args, e, 0);
        e.p0_merkle.evidence_signature = json_get_string(ev0, "signature");
        std::string ev1 = sign_merkle_evidence(args, e, 1);
        e.p1_merkle.evidence_signature = json_get_string(ev1, "signature");
    }

    for(const auto& e: entries) write_path_files(args, e);

    std::string metadata = build_metadata_json(args, entries, buyer_p0_root, buyer_p1_root, seller_p0_root, seller_p1_root);
    std::ostringstream meta_path; meta_path << args.metadata_dir << "/commitment_metadata_session" << args.session_id << ".json";
    write_text(meta_path.str(), metadata);
    std::string metadata_hash = sha256_text_hex(metadata);
    std::ostringstream uri; uri << args.metadata_uri_prefix << "/commitment_metadata_session" << args.session_id << ".json";

    std::cout << "[BOSS] buyerP0Root=" << buyer_p0_root
              << " buyerP1Root=" << buyer_p1_root
              << " sellerP0Root=" << seller_p0_root
              << " sellerP1Root=" << seller_p1_root << "\n";
    std::cout << "[BOSS] submitting Merkle roots to contract now...\n";
    submit_roots(args, buyer_p0_root, buyer_p1_root, seller_p0_root, seller_p1_root, buyers, sellers, metadata_hash, uri.str());

    // First send paths back to bidder clients and close their sockets.
    // Bidders wait on the original BidderBoss connection to check their own
    // inclusion after roots are submitted. Sending these paths before relaying
    // seller evidence prevents bidders from timing out while P0/P1 are still
    // moving from buyer ports to seller ports.
    for (const auto& e: entries) {
        try {
            send_path_to_bidder(e);
            std::cout << "[BOSS] sent Merkle paths to bidder " << e.name << "\n";
        } catch(const std::exception& ex) {
            std::cerr << "[BOSS] failed sending path to " << e.name << ": " << ex.what() << "\n";
        }
        if (e.sock >= 0) close(e.sock);
    }

    // Relay complete Merkle evidence packets to auctioneers. This uses retry
    // because P0/P1 open seller ports only after they finish buyer verification.
    for (const auto& e: entries) {
        send_merkle_evidence_to_auctioneer(args.p0_ip, p0_port_for(e.role), e, 0);
        send_merkle_evidence_to_auctioneer(args.p1_ip, p1_port_for(e.role), e, 1);
        std::cout << "[BOSS] sent party-specific Merkle evidence for " << e.role << " " << e.name << " (P0 gets P0 tree only, P1 gets P1 tree only)\n";
    }

    std::cout << "[BOSS] all bidder paths and auctioneer evidence sent. Starting randomness reveal server.\n";
    serve_reveal(args.reveal_port, entries);
    return 0;
}

static int challenge_mode(const Args& args, bool finalize_only) {
    std::ostringstream cmd;
    cmd << "node " << shell_quote(args.answer_challenge_tool)
        << " --rpc " << shell_quote(args.chain_rpc)
        << " --contract " << shell_quote(args.auction_registry)
        << " --priv-file " << shell_quote(args.eth_priv)
        << " --challenge-id " << args.challenge_id;
    if (finalize_only) cmd << " --finalize-only";
    else cmd << " --path-file " << shell_quote(args.path_file);
    std::cout << exec_cmd(cmd.str()) << "\n";
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    try {
        signal(SIGPIPE, SIG_IGN);
        Args args = parse_args(argc, argv);
        if (args.mode == "answer-challenge") return challenge_mode(args, false);
        if (args.mode == "finalize-challenge") return challenge_mode(args, true);
        return run_mode(args);
    } catch (const std::exception& e) {
        std::cerr << "bidderboss.cpp error: " << e.what() << "\n";
        return 1;
    }
}
