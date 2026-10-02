//p2.cpp

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <exception>
#include <iostream>
#include <limits>
#include <numeric>
#include <stdexcept>
#include <string>
#include <vector>
#include <sys/random.h>


namespace {

uint64_t add_wrap(uint64_t a, uint64_t b) { return a + b; }
uint64_t sub_wrap(uint64_t a, uint64_t b) { return a - b; }

uint64_t mul_wrap(uint64_t a, uint64_t b) {
    return static_cast<uint64_t>(static_cast<unsigned __int128>(a) * b);
}

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

uint64_t random_bounded(uint64_t bound) {
    if (bound == 0) return 0;
    uint64_t limit = std::numeric_limits<uint64_t>::max() -
                     (std::numeric_limits<uint64_t>::max() % bound);
    while (true) {
        uint64_t candidate = random_u64();
        if (candidate < limit) return candidate % bound;
    }
}

std::vector<uint64_t> row_times_matrix(const std::vector<uint64_t>& row,
                                       const std::vector<uint64_t>& matrix,
                                       uint64_t n) {
    std::vector<uint64_t> result(n, 0);
    for (uint64_t col = 0; col < n; ++col) {
        uint64_t acc = 0;
        for (uint64_t k = 0; k < n; ++k) {
            acc = add_wrap(acc, mul_wrap(row[k], matrix[k * n + col]));
        }
        result[col] = acc;
    }
    return result;
}

void send_all(int fd, const void* data, size_t len) {
    const uint8_t* ptr = static_cast<const uint8_t*>(data);
    while (len > 0) {
        ssize_t sent = send(fd, ptr, len, 0);
        if (sent <= 0) throw std::runtime_error("send failed");
        ptr += sent;
        len -= static_cast<size_t>(sent);
    }
}

void recv_all(int fd, void* data, size_t len) {
    uint8_t* ptr = static_cast<uint8_t*>(data);
    while (len > 0) {
        ssize_t got = recv(fd, ptr, len, MSG_WAITALL);
        if (got <= 0) throw std::runtime_error("recv failed");
        ptr += got;
        len -= static_cast<size_t>(got);
    }
}

void send_u64(int fd, uint64_t value) {
    uint64_t net = htobe64(value);
    send_all(fd, &net, sizeof(net));
}

uint64_t recv_u64(int fd) {
    uint64_t net = 0;
    recv_all(fd, &net, sizeof(net));
    return be64toh(net);
}

void send_u64_vector(int fd, const std::vector<uint64_t>& values) {
    if (values.empty()) return;
    std::vector<uint64_t> buffer(values.size());
    for (size_t i = 0; i < values.size(); ++i) buffer[i] = htobe64(values[i]);
    send_all(fd, buffer.data(), buffer.size() * sizeof(uint64_t));
}

int connect_to(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) throw std::runtime_error("socket creation failed");
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        throw std::runtime_error("connection failed");
    }
    return fd;
}

} // namespace

enum class DatasetKind : uint64_t { Buyers = 0, Sellers = 1 };

std::string describe_dataset(DatasetKind kind, bool descending) {
    std::string label = (kind == DatasetKind::Buyers) ? "buyer bids" : "seller asks";
    label += descending ? " (descending)" : " (ascending)";
    return label;
}

int main() {
    try {
        int sock_p0 = connect_to(6001);
        int sock_p1 = connect_to(6002);

        uint64_t dataset_count = recv_u64(sock_p0);

        for (uint64_t dataset_index = 0; dataset_index < dataset_count; ++dataset_index) {
            uint64_t dataset_kind_wire = recv_u64(sock_p0);
            uint64_t n = recv_u64(sock_p0);
            uint64_t descending_flag = recv_u64(sock_p0);
            bool descending = descending_flag != 0;
            DatasetKind kind = static_cast<DatasetKind>(dataset_kind_wire);
            std::string dataset_label = describe_dataset(kind, descending);

            // random permutation
            std::vector<uint64_t> perm(n);
            std::iota(perm.begin(), perm.end(), 0);
            for (uint64_t remaining = n; remaining > 1; --remaining) {
                uint64_t j = random_bounded(remaining);
                std::swap(perm[remaining - 1], perm[j]);
            }

            // permutation matrix W
            std::vector<uint64_t> w_matrix(n * n, 0);
            for (uint64_t col = 0; col < n; ++col) {
                uint64_t row = perm[col];
                w_matrix[row * n + col] = 1;
            }

            // random A vectors and B matrix
            std::vector<uint64_t> a_bid_vector(n), a_id_vector(n);
            for (uint64_t i = 0; i < n; ++i) {
                a_bid_vector[i] = random_u64();
                a_id_vector[i]  = random_u64();
            }

            std::vector<uint64_t> b_matrix(n * n);
            for (uint64_t idx = 0; idx < n * n; ++idx) b_matrix[idx] = random_u64();

            std::vector<uint64_t> c_bid_vector = row_times_matrix(a_bid_vector, b_matrix, n);
            std::vector<uint64_t> c_id_vector  = row_times_matrix(a_id_vector,  b_matrix, n);

            auto send_shares = [&](const std::vector<uint64_t>& values, const char* label) {
                std::vector<uint64_t> shares_p0(values.size());
                std::vector<uint64_t> shares_p1(values.size());
                for (size_t idx = 0; idx < values.size(); ++idx) {
                    uint64_t share0 = random_u64();
                    shares_p0[idx] = share0;
                    shares_p1[idx] = sub_wrap(values[idx], share0);
                }
                send_u64_vector(sock_p0, shares_p0);
                send_u64_vector(sock_p1, shares_p1);
                std::cout << "P2: dataset '" << dataset_label << "' sent shares for " << label << "\n";
            };

            send_shares(a_bid_vector, "bid A vector");
            send_shares(c_bid_vector, "bid C vector");
            send_shares(a_id_vector,  "ID A vector");
            send_shares(c_id_vector,  "ID C vector");
            send_shares(b_matrix,     "B matrix");
            send_shares(w_matrix,     "permutation matrix W");

            uint64_t comparisons = n * (n - 1) / 2;
            uint64_t total_triples = comparisons * 5;
            send_u64(sock_p0, total_triples);
            send_u64(sock_p1, total_triples);

            std::vector<uint64_t> triples_p0(total_triples * 3);
            std::vector<uint64_t> triples_p1(total_triples * 3);
            size_t off = 0;

            auto distribute_triple = [&](uint64_t a, uint64_t b) {
                uint64_t c = mul_wrap(a, b);

                uint64_t a0 = random_u64(), b0 = random_u64(), c0 = random_u64();
                uint64_t a1 = sub_wrap(a, a0);
                uint64_t b1 = sub_wrap(b, b0);
                uint64_t c1 = sub_wrap(c, c0);

                triples_p0[off] = a0; triples_p1[off++] = a1;
                triples_p0[off] = b0; triples_p1[off++] = b1;
                triples_p0[off] = c0; triples_p1[off++] = c1;
            };

            for (uint64_t i = 0; i < comparisons; ++i) {
                distribute_triple(random_u64(), random_u64()); // t2
                distribute_triple(random_u64(), random_u64()); // bid f*(y-x)
                distribute_triple(random_u64(), random_u64()); // bid f*(x-y)
                distribute_triple(random_u64(), random_u64()); // ID f*(y-x)
                distribute_triple(random_u64(), random_u64()); // ID f*(x-y)
            }

            send_u64_vector(sock_p0, triples_p0);
            send_u64_vector(sock_p1, triples_p1);

            for (uint64_t i = 0; i < comparisons; ++i) {
                uint64_t t2_p0 = recv_u64(sock_p0);
                uint64_t t2_p1 = recv_u64(sock_p1);
                uint64_t t2 = add_wrap(t2_p0, t2_p1);
                int64_t signed_t2 = static_cast<int64_t>(t2);
                uint64_t flag = (signed_t2 >= 0) ? 1 : 0;

                uint64_t swap_flag = descending ? sub_wrap(1, flag) : flag;

                uint64_t f0 = random_u64();
                uint64_t f1 = sub_wrap(swap_flag, f0);
                send_u64(sock_p0, f0);
                send_u64(sock_p1, f1);
            }
        }

        // clearing stage
        uint64_t clearing_flag = recv_u64(sock_p0);
        uint64_t clearing_flag_p1 = recv_u64(sock_p1);
        if (clearing_flag != clearing_flag_p1) throw std::runtime_error("P2 clearing flag mismatch");

        if (clearing_flag) {
            uint64_t buyer_count = recv_u64(sock_p0);
            uint64_t seller_count = recv_u64(sock_p0);
            uint64_t clearing_pairs = std::min(buyer_count, seller_count);

            uint64_t total_triples = clearing_pairs * 6;
            send_u64(sock_p0, total_triples);
            send_u64(sock_p1, total_triples);

            std::vector<uint64_t> triples_p0(total_triples * 3);
            std::vector<uint64_t> triples_p1(total_triples * 3);
            size_t cur = 0;

            for (uint64_t k = 0; k < clearing_pairs; ++k) {
                for (int bucket = 0; bucket < 6; ++bucket) {
                    uint64_t a = random_u64();
                    uint64_t b = random_u64();
                    uint64_t c = mul_wrap(a, b);

                    uint64_t a0 = random_u64(), b0 = random_u64(), c0 = random_u64();
                    uint64_t a1 = sub_wrap(a, a0);
                    uint64_t b1 = sub_wrap(b, b0);
                    uint64_t c1 = sub_wrap(c, c0);

                    triples_p0[cur] = a0; triples_p1[cur++] = a1;
                    triples_p0[cur] = b0; triples_p1[cur++] = b1;
                    triples_p0[cur] = c0; triples_p1[cur++] = c1;
                }
            }

            send_u64_vector(sock_p0, triples_p0);
            send_u64_vector(sock_p1, triples_p1);

            uint64_t comparison_total =
                clearing_pairs + (clearing_pairs > 0 ? 2 * (clearing_pairs - 1) : 0);

            for (uint64_t idx = 0; idx < comparison_total; ++idx) {
                uint64_t t2_p0 = recv_u64(sock_p0);
                uint64_t t2_p1 = recv_u64(sock_p1);
                uint64_t t2 = add_wrap(t2_p0, t2_p1);
                int64_t signed_t2 = static_cast<int64_t>(t2);
                uint64_t flag = (signed_t2 >= 0) ? 1 : 0;

                uint64_t f0 = random_u64();
                uint64_t f1 = sub_wrap(flag, f0);
                send_u64(sock_p0, f0);
                send_u64(sock_p1, f1);
            }
        }

        close(sock_p0);
        close(sock_p1);
        return 0;

    } catch (const std::exception& ex) {
        std::cerr << "P2 error: " << ex.what() << "\n";
        return 1;
    }
}





