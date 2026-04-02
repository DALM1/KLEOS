#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/event.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <array>
#include <cerrno>
#include <iostream>
#include <random>
#include <string>
#include <unordered_map>
#include <vector>
#include <fcntl.h>

namespace {

enum class FrameType : uint8_t {
    Hello = 1,
    SendMessage = 2,
    DeliverMessage = 3,
    Error = 4,
    Register = 5,
    LoginBegin = 6,
    LoginChallenge = 7,
    LoginResponse = 8,
    LoginOk = 9,
    FriendAdd = 10,
    FriendRemove = 11,
    FriendListReq = 12,
    FriendListResp = 13,
    Block = 14,
    Unblock = 15,
    Ok = 16,
    Presence = 17,
};

struct OfflineMsg {
    std::string from;
    std::string text;
};

struct Sha256Digest {
    std::array<uint8_t, 32> bytes{};
};

void AppendU16(std::vector<uint8_t>& out, uint16_t v) {
    uint16_t be = htons(v);
    auto* p = reinterpret_cast<uint8_t*>(&be);
    out.insert(out.end(), p, p + sizeof(be));
}

void AppendU32(std::vector<uint8_t>& out, uint32_t v) {
    uint32_t be = htonl(v);
    auto* p = reinterpret_cast<uint8_t*>(&be);
    out.insert(out.end(), p, p + sizeof(be));
}

bool ReadU16(const std::vector<uint8_t>& in, size_t& off, uint16_t& v) {
    if (off + 2 > in.size()) return false;
    uint16_t be = 0;
    std::memcpy(&be, in.data() + off, 2);
    off += 2;
    v = ntohs(be);
    return true;
}

bool ReadU32(const std::vector<uint8_t>& in, size_t& off, uint32_t& v) {
    if (off + 4 > in.size()) return false;
    uint32_t be = 0;
    std::memcpy(&be, in.data() + off, 4);
    off += 4;
    v = ntohl(be);
    return true;
}

bool ReadStringU16(const std::vector<uint8_t>& in, size_t& off, std::string& s) {
    uint16_t len = 0;
    if (!ReadU16(in, off, len)) return false;
    if (off + len > in.size()) return false;
    s.assign(reinterpret_cast<const char*>(in.data() + off), len);
    off += len;
    return true;
}

bool ReadStringU32(const std::vector<uint8_t>& in, size_t& off, std::string& s) {
    uint32_t len = 0;
    if (!ReadU32(in, off, len)) return false;
    if (off + len > in.size()) return false;
    s.assign(reinterpret_cast<const char*>(in.data() + off), len);
    off += len;
    return true;
}

std::vector<uint8_t> MakeFrame(FrameType type, const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> out;
    out.reserve(1 + 4 + payload.size());
    out.push_back(static_cast<uint8_t>(type));
    AppendU32(out, static_cast<uint32_t>(payload.size()));
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

std::vector<uint8_t> PayloadError(const std::string& msg) {
    std::vector<uint8_t> p;
    if (msg.size() > 0xFFFF) return p;
    AppendU16(p, static_cast<uint16_t>(msg.size()));
    p.insert(p.end(), msg.begin(), msg.end());
    return p;
}

std::vector<uint8_t> PayloadDeliver(const std::string& from, const std::string& text) {
    std::vector<uint8_t> p;
    if (from.size() > 0xFFFF) return p;
    AppendU16(p, static_cast<uint16_t>(from.size()));
    p.insert(p.end(), from.begin(), from.end());
    AppendU32(p, static_cast<uint32_t>(text.size()));
    p.insert(p.end(), text.begin(), text.end());
    return p;
}

std::vector<uint8_t> PayloadNonce(const std::array<uint8_t, 32>& nonce) {
    std::vector<uint8_t> p;
    p.insert(p.end(), nonce.begin(), nonce.end());
    return p;
}

std::vector<uint8_t> PayloadOk(const std::string& msg) {
    std::vector<uint8_t> p;
    if (msg.size() > 0xFFFF) return p;
    AppendU16(p, static_cast<uint16_t>(msg.size()));
    p.insert(p.end(), msg.begin(), msg.end());
    return p;
}

std::vector<uint8_t> PayloadFriendList(const std::vector<std::pair<std::string, uint8_t>>& entries) {
    std::vector<uint8_t> p;
    if (entries.size() > 0xFFFF) return p;
    AppendU16(p, static_cast<uint16_t>(entries.size()));
    for (const auto& e : entries) {
        if (e.first.size() > 0xFFFF) return {};
        AppendU16(p, static_cast<uint16_t>(e.first.size()));
        p.insert(p.end(), e.first.begin(), e.first.end());
        p.push_back(e.second);
    }
    return p;
}

std::vector<uint8_t> PayloadPresence(const std::string& handle, uint8_t online) {
    std::vector<uint8_t> p;
    if (handle.size() > 0xFFFF) return p;
    AppendU16(p, static_cast<uint16_t>(handle.size()));
    p.insert(p.end(), handle.begin(), handle.end());
    p.push_back(online);
    return p;
}

static bool SetNonBlocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return false;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static void SetNoDelay(int fd) {
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
}

static std::string Base64Encode(const std::string& in) {
    static const char* k = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((in.size() + 2) / 3) * 4);
    uint32_t val = 0;
    int valb = -6;
    for (uint8_t c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(k[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(k[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

static bool Base64Decode(const std::string& in, std::string& out) {
    static const int8_t T[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,
        -1,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };
    out.clear();
    out.reserve(in.size() * 3 / 4);
    int val = 0;
    int valb = -8;
    for (uint8_t c : in) {
        int8_t d = T[c];
        if (d == -1) return false;
        if (d == -2) break;
        val = (val << 6) + d;
        valb += 6;
        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return true;
}

static std::string HexEncode(const uint8_t* data, size_t size) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.resize(size * 2);
    for (size_t i = 0; i < size; ++i) {
        uint8_t b = data[i];
        out[i * 2 + 0] = kHex[(b >> 4) & 0xF];
        out[i * 2 + 1] = kHex[b & 0xF];
    }
    return out;
}

static bool ReadU16Ptr(const uint8_t* data, size_t size, size_t& off, uint16_t& v) {
    if (off + 2 > size) return false;
    uint16_t be = 0;
    std::memcpy(&be, data + off, 2);
    off += 2;
    v = ntohs(be);
    return true;
}

static bool ReadU32Ptr(const uint8_t* data, size_t size, size_t& off, uint32_t& v) {
    if (off + 4 > size) return false;
    uint32_t be = 0;
    std::memcpy(&be, data + off, 4);
    off += 4;
    v = ntohl(be);
    return true;
}

static bool ReadStringU16Ptr(const uint8_t* data, size_t size, size_t& off, std::string& s) {
    uint16_t len = 0;
    if (!ReadU16Ptr(data, size, off, len)) return false;
    if (off + len > size) return false;
    s.assign(reinterpret_cast<const char*>(data + off), len);
    off += len;
    return true;
}

static bool ReadStringU32Ptr(const uint8_t* data, size_t size, size_t& off, std::string& s) {
    uint32_t len = 0;
    if (!ReadU32Ptr(data, size, off, len)) return false;
    if (off + len > size) return false;
    s.assign(reinterpret_cast<const char*>(data + off), len);
    off += len;
    return true;
}

Sha256Digest Sha256(const uint8_t* data, size_t len) {
    auto rotr = [](uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); };
    auto ch = [](uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); };
    auto maj = [](uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); };
    auto bsig0 = [&](uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); };
    auto bsig1 = [&](uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); };
    auto ssig0 = [&](uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); };
    auto ssig1 = [&](uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); };

    static const uint32_t k[64] = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u,
        0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu,
        0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu,
        0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
        0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
        0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
        0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
        0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
        0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u,
        0xc67178f2u,
    };

    uint32_t h[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                     0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};

    uint64_t bit_len = static_cast<uint64_t>(len) * 8;
    std::vector<uint8_t> msg(data, data + len);
    msg.push_back(0x80);
    while ((msg.size() % 64) != 56) msg.push_back(0x00);
    for (int i = 7; i >= 0; --i) msg.push_back(static_cast<uint8_t>((bit_len >> (i * 8)) & 0xFF));

    uint32_t w[64];
    for (size_t chunk = 0; chunk < msg.size(); chunk += 64) {
        for (int i = 0; i < 16; ++i) {
            size_t off = chunk + static_cast<size_t>(i * 4);
            w[i] = (static_cast<uint32_t>(msg[off]) << 24) | (static_cast<uint32_t>(msg[off + 1]) << 16) |
                   (static_cast<uint32_t>(msg[off + 2]) << 8) | static_cast<uint32_t>(msg[off + 3]);
        }
        for (int i = 16; i < 64; ++i) w[i] = ssig1(w[i - 2]) + w[i - 7] + ssig0(w[i - 15]) + w[i - 16];

        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t t1 = hh + bsig1(e) + ch(e, f, g) + k[i] + w[i];
            uint32_t t2 = bsig0(a) + maj(a, b, c);
            hh = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
    }

    Sha256Digest out;
    for (int i = 0; i < 8; ++i) {
        out.bytes[static_cast<size_t>(i * 4 + 0)] = static_cast<uint8_t>((h[i] >> 24) & 0xFF);
        out.bytes[static_cast<size_t>(i * 4 + 1)] = static_cast<uint8_t>((h[i] >> 16) & 0xFF);
        out.bytes[static_cast<size_t>(i * 4 + 2)] = static_cast<uint8_t>((h[i] >> 8) & 0xFF);
        out.bytes[static_cast<size_t>(i * 4 + 3)] = static_cast<uint8_t>((h[i] >> 0) & 0xFF);
    }
    return out;
}

Sha256Digest HmacSha256(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len) {
    std::array<uint8_t, 64> k0{};
    if (key_len > k0.size()) {
        auto hk = Sha256(key, key_len);
        std::memcpy(k0.data(), hk.bytes.data(), hk.bytes.size());
    } else {
        std::memcpy(k0.data(), key, key_len);
    }

    std::array<uint8_t, 64> o_key_pad{};
    std::array<uint8_t, 64> i_key_pad{};
    for (size_t i = 0; i < k0.size(); ++i) {
        o_key_pad[i] = static_cast<uint8_t>(k0[i] ^ 0x5c);
        i_key_pad[i] = static_cast<uint8_t>(k0[i] ^ 0x36);
    }

    std::vector<uint8_t> inner;
    inner.reserve(i_key_pad.size() + data_len);
    inner.insert(inner.end(), i_key_pad.begin(), i_key_pad.end());
    inner.insert(inner.end(), data, data + data_len);
    auto inner_hash = Sha256(inner.data(), inner.size());

    std::vector<uint8_t> outer;
    outer.reserve(o_key_pad.size() + inner_hash.bytes.size());
    outer.insert(outer.end(), o_key_pad.begin(), o_key_pad.end());
    outer.insert(outer.end(), inner_hash.bytes.begin(), inner_hash.bytes.end());
    return Sha256(outer.data(), outer.size());
}

bool ConstantTimeEq(const uint8_t* a, const uint8_t* b, size_t n) {
    uint8_t v = 0;
    for (size_t i = 0; i < n; ++i) v |= static_cast<uint8_t>(a[i] ^ b[i]);
    return v == 0;
}

struct RelayState {
    bool RegisterUser(const std::string& handle, const Sha256Digest& secret_hash) {
        if (credentials_.find(handle) != credentials_.end()) return false;
        credentials_[handle] = secret_hash;
        return true;
    }

    bool IsRegistered(const std::string& handle) {
        return credentials_.find(handle) != credentials_.end();
    }

    bool GetSecretHash(const std::string& handle, Sha256Digest& out) {
        auto it = credentials_.find(handle);
        if (it == credentials_.end()) return false;
        out = it->second;
        return true;
    }

    void SetOnline(const std::string& handle, int fd) {
        online_[handle] = fd;
    }

    void ClearOnline(const std::string& handle, int fd) {
        auto it = online_.find(handle);
        if (it != online_.end() && it->second == fd) online_.erase(it);
    }

    int FindOnlineFd(const std::string& handle) {
        auto it = online_.find(handle);
        if (it == online_.end()) return -1;
        return it->second;
    }

    std::deque<OfflineMsg> TakeOffline(const std::string& handle) {
        auto it = offline_.find(handle);
        if (it == offline_.end()) return {};
        auto q = std::move(it->second);
        offline_.erase(it);
        return q;
    }

    void EnqueueOffline(const std::string& to, OfflineMsg msg) {
        auto& q = offline_[to];
        q.push_back(std::move(msg));
        while (q.size() > kMaxOfflinePerUser) q.pop_front();
    }

    static constexpr size_t kMaxOfflinePerUser = 50;
    std::unordered_map<std::string, Sha256Digest> credentials_;
    std::unordered_map<std::string, int> online_;
    std::unordered_map<std::string, std::deque<OfflineMsg>> offline_;
};

bool IsValidHandle(const std::string& handle) {
    if (handle.empty() || handle.size() > 32) return false;
    for (char c : handle) {
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
        if (!ok) return false;
    }
    return true;
}

static bool ParseHello(const uint8_t* data, size_t size, std::string& handle) {
    size_t off = 0;
    if (!ReadStringU16Ptr(data, size, off, handle)) return false;
    return off == size;
}

static bool ParseRegister(const uint8_t* data, size_t size, std::string& handle, Sha256Digest& secret_hash) {
    size_t off = 0;
    if (!ReadStringU16Ptr(data, size, off, handle)) return false;
    if (size - off != secret_hash.bytes.size()) return false;
    std::memcpy(secret_hash.bytes.data(), data + off, secret_hash.bytes.size());
    off += secret_hash.bytes.size();
    return off == size;
}

static bool ParseLoginResponse(const uint8_t* data, size_t size, std::string& handle, std::array<uint8_t, 32>& hmac) {
    size_t off = 0;
    if (!ReadStringU16Ptr(data, size, off, handle)) return false;
    if (size - off != hmac.size()) return false;
    std::memcpy(hmac.data(), data + off, hmac.size());
    off += hmac.size();
    return off == size;
}

static bool ParseSend(const uint8_t* data, size_t size, std::string& to, std::string& text) {
    size_t off = 0;
    if (!ReadStringU16Ptr(data, size, off, to)) return false;
    if (!ReadStringU32Ptr(data, size, off, text)) return false;
    return off == size;
}

static bool ParsePeerU16(const uint8_t* data, size_t size, std::string& peer) {
    size_t off = 0;
    if (!ReadStringU16Ptr(data, size, off, peer)) return false;
    return off == size;
}

struct ConnState {
    enum class Stage { AwaitFirst, AwaitLoginBegin, AwaitLoginResponse, AwaitHubAuth, Authed };
    int fd = -1;
    Stage stage = Stage::AwaitFirst;
    std::string handle;
    std::array<uint8_t, 32> nonce{};
    std::vector<uint8_t> inbuf;
    size_t in_off = 0;
    std::vector<uint8_t> outbuf;
    size_t out_off = 0;
    bool want_close = false;
};

static uint32_t kMaxPayload = 256 * 1024;
static constexpr size_t kMaxInBufferBytes = 1024 * 1024;
static constexpr size_t kMaxOutBufferBytes = 1024 * 1024;

struct PendingRoute {
    std::string to;
    std::string from;
    std::string text;
    int sender_fd;

    PendingRoute() : sender_fd(-1) {}
    PendingRoute(std::string to_, std::string from_, std::string text_, int sender_fd_)
        : to(std::move(to_)), from(std::move(from_)), text(std::move(text_)), sender_fd(sender_fd_) {}
};

struct PendingRel {
    int sender_fd;
    uint8_t op;

    PendingRel() : sender_fd(-1), op(0) {}
    PendingRel(int sender_fd_, uint8_t op_) : sender_fd(sender_fd_), op(op_) {}
};

struct PendingAuth {
    int sender_fd;
    uint8_t kind;
    std::string handle;

    PendingAuth() : sender_fd(-1), kind(0) {}
    PendingAuth(int sender_fd_, uint8_t kind_, std::string handle_) : sender_fd(sender_fd_), kind(kind_), handle(std::move(handle_)) {}
};

struct HubConn {
    int fd = -1;
    bool enabled = false;
    bool connected = false;
    bool connecting = false;
    in_addr_t addr = 0;
    uint16_t port = 0;
    std::string public_host;
    uint16_t public_port = 0;
    std::string inbuf;
    std::vector<uint8_t> outbuf;
    size_t out_off = 0;
    uint64_t seq = 0;
    std::unordered_map<uint64_t, PendingRoute> pending;
    std::unordered_map<uint64_t, PendingRel> pending_rel;
    std::unordered_map<uint64_t, PendingAuth> pending_auth;
};

static void QueueBytes(ConnState& c, const std::vector<uint8_t>& bytes) {
    if (bytes.empty()) return;
    c.outbuf.insert(c.outbuf.end(), bytes.begin(), bytes.end());
}

static void QueueFrame(ConnState& c, FrameType type, const std::vector<uint8_t>& payload) {
    auto bytes = MakeFrame(type, payload);
    QueueBytes(c, bytes);
}

static void EnableWrite(int kq, int fd) {
    struct kevent ev;
    EV_SET(&ev, static_cast<uintptr_t>(fd), EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, nullptr);
    kevent(kq, &ev, 1, nullptr, 0, nullptr);
}

static void DisableWrite(int kq, int fd) {
    struct kevent ev;
    EV_SET(&ev, static_cast<uintptr_t>(fd), EVFILT_WRITE, EV_ADD | EV_DISABLE, 0, 0, nullptr);
    kevent(kq, &ev, 1, nullptr, 0, nullptr);
}

static void HubQueueLine(int kq, HubConn& hub, const std::string& line) {
    if (!hub.enabled || !hub.connected || hub.fd < 0) return;
    hub.outbuf.insert(hub.outbuf.end(), line.begin(), line.end());
    EnableWrite(kq, hub.fd);
}

static void HubReset(int kq, HubConn& hub) {
    if (hub.fd >= 0) {
        struct kevent ev[2];
        EV_SET(&ev[0], static_cast<uintptr_t>(hub.fd), EVFILT_READ, EV_DELETE, 0, 0, nullptr);
        EV_SET(&ev[1], static_cast<uintptr_t>(hub.fd), EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);
        kevent(kq, ev, 2, nullptr, 0, nullptr);
        ::close(hub.fd);
    }
    hub.fd = -1;
    hub.connected = false;
    hub.connecting = false;
    hub.inbuf.clear();
    hub.outbuf.clear();
    hub.out_off = 0;
}

static void HubFailPendingToOffline(RelayState& state, HubConn& hub) {
    for (const auto& kv : hub.pending) {
        const PendingRoute& pr = kv.second;
        state.EnqueueOffline(pr.to, OfflineMsg{pr.from, pr.text});
    }
    hub.pending.clear();
    hub.pending_rel.clear();
    hub.pending_auth.clear();
}

static void CloseConn(int kq, RelayState& state, std::unordered_map<int, ConnState>& conns, HubConn& hub, int fd) {
    auto it = conns.find(fd);
    if (it != conns.end()) {
        if (!it->second.handle.empty()) {
            state.ClearOnline(it->second.handle, fd);
            HubQueueLine(kq, hub, "OFFLINE " + it->second.handle + "\n");
        }
        conns.erase(it);
    }
    struct kevent ev[2];
    EV_SET(&ev[0], static_cast<uintptr_t>(fd), EVFILT_READ, EV_DELETE, 0, 0, nullptr);
    EV_SET(&ev[1], static_cast<uintptr_t>(fd), EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);
    kevent(kq, ev, 2, nullptr, 0, nullptr);
    ::close(fd);
}

static void MaybeCompactIn(ConnState& c) {
    if (c.in_off == 0) return;
    if (c.in_off >= 4096 && c.in_off >= c.inbuf.size() / 2) {
        c.inbuf.erase(c.inbuf.begin(), c.inbuf.begin() + static_cast<std::ptrdiff_t>(c.in_off));
        c.in_off = 0;
    }
}

static void MaybeCompactOut(ConnState& c) {
    if (c.out_off == 0) return;
    if (c.out_off >= 4096 && c.out_off >= c.outbuf.size() / 2) {
        c.outbuf.erase(c.outbuf.begin(), c.outbuf.begin() + static_cast<std::ptrdiff_t>(c.out_off));
        c.out_off = 0;
    }
}

static void HandleFrame(int kq, RelayState& state, std::unordered_map<int, ConnState>& conns, HubConn& hub, ConnState& c, FrameType type, const uint8_t* payload, size_t payload_size) {
    if (c.stage == ConnState::Stage::AwaitFirst) {
        if (type == FrameType::Register) {
            std::string handle;
            Sha256Digest secret_hash;
            if (!ParseRegister(payload, payload_size, handle, secret_hash) || !IsValidHandle(handle)) {
                QueueFrame(c, FrameType::Error, PayloadError("inscription invalide"));
                c.want_close = true;
                EnableWrite(kq, c.fd);
                return;
            }
            if (hub.enabled) {
                if (!hub.connected) {
                    QueueFrame(c, FrameType::Error, PayloadError("hub indisponible"));
                    c.want_close = true;
                    EnableWrite(kq, c.fd);
                    return;
                }
                uint64_t reqid = ++hub.seq;
                hub.pending_auth[reqid] = PendingAuth{c.fd, 1, handle};
                std::string hex = HexEncode(secret_hash.bytes.data(), secret_hash.bytes.size());
                HubQueueLine(kq, hub, "AUTH REG " + std::to_string(reqid) + " " + handle + " " + hex + "\n");
                c.stage = ConnState::Stage::AwaitHubAuth;
                return;
            }

            if (!state.RegisterUser(handle, secret_hash)) {
                QueueFrame(c, FrameType::Error, PayloadError("handle déjà utilisé"));
                c.want_close = true;
                EnableWrite(kq, c.fd);
                return;
            }
            QueueFrame(c, FrameType::LoginOk, {});
            c.want_close = true;
            EnableWrite(kq, c.fd);
            return;
        }
        if (type != FrameType::LoginBegin) {
            QueueFrame(c, FrameType::Error, PayloadError("connexion requise"));
            c.want_close = true;
            EnableWrite(kq, c.fd);
            return;
        }
        std::string handle;
        if (!ParseHello(payload, payload_size, handle) || !IsValidHandle(handle)) {
            QueueFrame(c, FrameType::Error, PayloadError("connexion invalide"));
            c.want_close = true;
            EnableWrite(kq, c.fd);
            return;
        }
        if (hub.enabled) {
            if (!hub.connected) {
                QueueFrame(c, FrameType::Error, PayloadError("hub indisponible"));
                c.want_close = true;
                EnableWrite(kq, c.fd);
                return;
            }
        } else {
            Sha256Digest secret_hash;
            if (!state.GetSecretHash(handle, secret_hash)) {
                QueueFrame(c, FrameType::Error, PayloadError("compte introuvable"));
                c.want_close = true;
                EnableWrite(kq, c.fd);
                return;
            }
        }
        c.handle = handle;
        {
            std::random_device rd;
            for (auto& b : c.nonce) b = static_cast<uint8_t>(rd());
        }
        QueueFrame(c, FrameType::LoginChallenge, PayloadNonce(c.nonce));
        c.stage = ConnState::Stage::AwaitLoginResponse;
        EnableWrite(kq, c.fd);
        return;
    }

    if (c.stage == ConnState::Stage::AwaitLoginResponse) {
        if (type != FrameType::LoginResponse) {
            QueueFrame(c, FrameType::Error, PayloadError("auth invalide"));
            c.want_close = true;
            EnableWrite(kq, c.fd);
            return;
        }
        std::string handle2;
        std::array<uint8_t, 32> hmac{};
        if (!ParseLoginResponse(payload, payload_size, handle2, hmac) || handle2 != c.handle) {
            QueueFrame(c, FrameType::Error, PayloadError("auth invalide"));
            c.want_close = true;
            EnableWrite(kq, c.fd);
            return;
        }
        if (hub.enabled) {
            if (!hub.connected) {
                QueueFrame(c, FrameType::Error, PayloadError("hub indisponible"));
                c.want_close = true;
                EnableWrite(kq, c.fd);
                return;
            }
            uint64_t reqid = ++hub.seq;
            hub.pending_auth[reqid] = PendingAuth{c.fd, 2, c.handle};
            std::string nonce_bytes(reinterpret_cast<const char*>(c.nonce.data()), c.nonce.size());
            std::string nonce_b64 = Base64Encode(nonce_bytes);
            std::string hmac_hex = HexEncode(hmac.data(), hmac.size());
            HubQueueLine(kq, hub, "AUTH VERIFY " + std::to_string(reqid) + " " + c.handle + " " + nonce_b64 + " " + hmac_hex + "\n");
            c.stage = ConnState::Stage::AwaitHubAuth;
            return;
        }
        Sha256Digest secret_hash;
        if (!state.GetSecretHash(c.handle, secret_hash)) {
            QueueFrame(c, FrameType::Error, PayloadError("compte introuvable"));
            c.want_close = true;
            EnableWrite(kq, c.fd);
            return;
        }
        auto expected = HmacSha256(secret_hash.bytes.data(), secret_hash.bytes.size(), c.nonce.data(), c.nonce.size());
        if (!ConstantTimeEq(expected.bytes.data(), hmac.data(), hmac.size())) {
            QueueFrame(c, FrameType::Error, PayloadError("mot de passe incorrect"));
            c.want_close = true;
            EnableWrite(kq, c.fd);
            return;
        }
        state.SetOnline(c.handle, c.fd);
        QueueFrame(c, FrameType::LoginOk, {});
        auto offline = state.TakeOffline(c.handle);
        for (const auto& m : offline) {
            auto p = PayloadDeliver(m.from, m.text);
            if (!p.empty()) QueueFrame(c, FrameType::DeliverMessage, p);
        }
        HubQueueLine(kq, hub, "ONLINE " + c.handle + "\n");
        if (hub.enabled && hub.connected) {
            uint64_t reqid = ++hub.seq;
            hub.pending_rel[reqid] = PendingRel{c.fd, 1};
            HubQueueLine(kq, hub, "REL " + std::to_string(reqid) + " LIST " + c.handle + " _\n");
        }
        c.stage = ConnState::Stage::Authed;
        EnableWrite(kq, c.fd);
        return;
    }

    if (c.stage == ConnState::Stage::AwaitHubAuth) {
        QueueFrame(c, FrameType::Error, PayloadError("auth en cours"));
        c.want_close = true;
        EnableWrite(kq, c.fd);
        return;
    }

    if (c.stage == ConnState::Stage::Authed) {
        if (type == FrameType::SendMessage) {
            std::string to;
            std::string text;
            if (!ParseSend(payload, payload_size, to, text) || to.empty() || !IsValidHandle(to) || to == c.handle) {
                QueueFrame(c, FrameType::Error, PayloadError("invalid send"));
                EnableWrite(kq, c.fd);
                return;
            }

            if (hub.enabled && hub.connected) {
                uint64_t msgid = ++hub.seq;
                hub.pending[msgid] = PendingRoute{to, c.handle, text, c.fd};
                std::string b64 = Base64Encode(text);
                HubQueueLine(kq, hub, "ROUTE " + std::to_string(msgid) + " " + to + " " + c.handle + " " + b64 + "\n");
                return;
            }

            if (!state.IsRegistered(to)) {
                QueueFrame(c, FrameType::Error, PayloadError("destinataire inconnu"));
                EnableWrite(kq, c.fd);
                return;
            }
            int rfd = state.FindOnlineFd(to);
            if (rfd >= 0) {
                auto it = conns.find(rfd);
                if (it != conns.end()) {
                    auto p = PayloadDeliver(c.handle, text);
                    if (!p.empty()) {
                        QueueFrame(it->second, FrameType::DeliverMessage, p);
                        EnableWrite(kq, rfd);
                    }
                } else {
                    state.EnqueueOffline(to, OfflineMsg{c.handle, text});
                }
            } else {
                state.EnqueueOffline(to, OfflineMsg{c.handle, text});
            }
            return;
        }

        if (type == FrameType::FriendAdd || type == FrameType::FriendRemove || type == FrameType::Block || type == FrameType::Unblock) {
            if (!(hub.enabled && hub.connected)) {
                QueueFrame(c, FrameType::Error, PayloadError("hub indisponible"));
                EnableWrite(kq, c.fd);
                return;
            }
            std::string peer;
            if (!ParsePeerU16(payload, payload_size, peer) || !IsValidHandle(peer) || peer == c.handle) {
                QueueFrame(c, FrameType::Error, PayloadError("relation invalide"));
                EnableWrite(kq, c.fd);
                return;
            }

            const char* op = "ADD";
            uint8_t op_id = 2;
            if (type == FrameType::FriendRemove) {
                op = "DEL";
                op_id = 3;
            } else if (type == FrameType::Block) {
                op = "BLOCK";
                op_id = 4;
            } else if (type == FrameType::Unblock) {
                op = "UNBLOCK";
                op_id = 5;
            }

            uint64_t reqid = ++hub.seq;
            hub.pending_rel[reqid] = PendingRel{c.fd, op_id};
            HubQueueLine(kq, hub, "REL " + std::to_string(reqid) + " " + op + " " + c.handle + " " + peer + "\n");
            return;
        }

        if (type == FrameType::FriendListReq) {
            if (!(hub.enabled && hub.connected)) {
                QueueFrame(c, FrameType::Error, PayloadError("hub indisponible"));
                EnableWrite(kq, c.fd);
                return;
            }
            uint64_t reqid = ++hub.seq;
            hub.pending_rel[reqid] = PendingRel{c.fd, 1};
            HubQueueLine(kq, hub, "REL " + std::to_string(reqid) + " LIST " + c.handle + " _\n");
            return;
        }

        QueueFrame(c, FrameType::Error, PayloadError("unknown frame"));
        EnableWrite(kq, c.fd);
        return;
    }
}

uint16_t ParsePort(int argc, char** argv) {
    if (argc < 2) return 5555;
    int p = std::atoi(argv[1]);
    if (p <= 0 || p > 65535) return 5555;
    return static_cast<uint16_t>(p);
}

uint32_t ParseMaxPayload(int argc, char** argv) {
    if (argc < 3) return 256 * 1024;
    long v = std::atol(argv[2]);
    if (v < 1024) return 1024;
    if (v > 1024L * 1024L) return 1024 * 1024;
    return static_cast<uint32_t>(v);
}

uint32_t ParseHost(int argc, char** argv, in_addr_t& out_addr) {
    out_addr = htonl(INADDR_LOOPBACK);
    if (argc < 4) return 0;
    if (std::strcmp(argv[3], "0.0.0.0") == 0) {
        out_addr = htonl(INADDR_ANY);
        return 0;
    }
    in_addr addr{};
    if (inet_pton(AF_INET, argv[3], &addr) == 1) {
        out_addr = addr.s_addr;
        return 0;
    }
    return 1;
}

bool ParseIpv4(const char* s, in_addr_t& out_addr) {
    in_addr addr{};
    if (inet_pton(AF_INET, s, &addr) != 1) return false;
    out_addr = addr.s_addr;
    return true;
}

uint16_t ParseU16Arg(const char* s, uint16_t def) {
    int v = std::atoi(s);
    if (v <= 0 || v > 65535) return def;
    return static_cast<uint16_t>(v);
}

int ConnectTcpIpv4(in_addr_t addr, uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    sockaddr_in sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = addr;
    sa.sin_port = htons(port);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) != 0) {
        ::close(fd);
        return -1;
    }
    SetNoDelay(fd);
    SetNonBlocking(fd);
    return fd;
}

int ConnectTcpIpv4NonBlocking(in_addr_t addr, uint16_t port, bool& out_in_progress) {
    out_in_progress = false;
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    SetNoDelay(fd);
    if (!SetNonBlocking(fd)) {
        ::close(fd);
        return -1;
    }
    sockaddr_in sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = addr;
    sa.sin_port = htons(port);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == 0) {
        out_in_progress = false;
        return fd;
    }
    if (errno == EINPROGRESS) {
        out_in_progress = true;
        return fd;
    }
    ::close(fd);
    return -1;
}

void TryRaiseNoFileLimit() {
    rlimit lim{};
    if (getrlimit(RLIMIT_NOFILE, &lim) != 0) return;
    rlimit desired = lim;
    desired.rlim_cur = desired.rlim_max;
    if (desired.rlim_cur < 65535) desired.rlim_cur = 65535;
    if (desired.rlim_cur > 1048576) desired.rlim_cur = 1048576;
    setrlimit(RLIMIT_NOFILE, &desired);
}

}  // namespace

int main(int argc, char** argv) {
    uint16_t port = ParsePort(argc, argv);
    uint32_t max_payload = ParseMaxPayload(argc, argv);
    kMaxPayload = max_payload;
    in_addr_t bind_addr = htonl(INADDR_LOOPBACK);
    if (ParseHost(argc, argv, bind_addr) != 0) {
        std::cerr << "invalid host, use 0.0.0.0 or an IPv4 address\n";
        return 1;
    }

    TryRaiseNoFileLimit();

    int listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        std::cerr << "socket failed\n";
        return 1;
    }

    int yes = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));
    setsockopt(listen_fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes));

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = bind_addr;
    addr.sin_port = htons(port);

    if (::bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        std::cerr << "bind failed\n";
        ::close(listen_fd);
        return 1;
    }

    if (::listen(listen_fd, 4096) != 0) {
        std::cerr << "listen failed\n";
        ::close(listen_fd);
        return 1;
    }

    char addr_buf[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &addr.sin_addr, addr_buf, sizeof(addr_buf));
    std::cout << "KleosRelay listening on " << addr_buf << ":" << port << " (max_payload=" << max_payload << ")\n";

    SetNonBlocking(listen_fd);
    int kq = kqueue();
    if (kq < 0) {
        std::cerr << "kqueue failed\n";
        ::close(listen_fd);
        return 1;
    }

    struct kevent ev;
    EV_SET(&ev, static_cast<uintptr_t>(listen_fd), EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, nullptr);
    kevent(kq, &ev, 1, nullptr, 0, nullptr);
    EV_SET(&ev, 1, EVFILT_TIMER, EV_ADD | EV_ENABLE, NOTE_SECONDS, 1, nullptr);
    kevent(kq, &ev, 1, nullptr, 0, nullptr);

    RelayState state;
    std::unordered_map<int, ConnState> conns;
    HubConn hub;
    std::vector<struct kevent> events;
    events.resize(1024);

    {
        const char* hub_env = std::getenv("KLEOS_HUB");
        if (hub_env && hub_env[0]) {
            std::string s(hub_env);
            auto colon = s.find(':');
            std::string host = (colon == std::string::npos) ? s : s.substr(0, colon);
            std::string port_s = (colon == std::string::npos) ? "7000" : s.substr(colon + 1);
            in_addr_t ha = 0;
            if (ParseIpv4(host.c_str(), ha)) {
                uint16_t hp = ParseU16Arg(port_s.c_str(), 7000);
                if (hp != 0) {
                    hub.enabled = true;
                    hub.addr = ha;
                    hub.port = hp;
                }
            }
        }
        const char* pub_host_env = std::getenv("KLEOS_RELAY_PUBLIC_HOST");
        const char* pub_port_env = std::getenv("KLEOS_RELAY_PUBLIC_PORT");
        if (pub_host_env && pub_host_env[0]) hub.public_host = pub_host_env;
        if (pub_port_env && pub_port_env[0]) hub.public_port = ParseU16Arg(pub_port_env, port);
    }

    while (true) {
        int n = kevent(kq, nullptr, 0, events.data(), static_cast<int>(events.size()), nullptr);
        if (n < 0) {
            if (errno == EINTR) continue;
            std::cerr << "kevent failed\n";
            break;
        }
        if (n == static_cast<int>(events.size())) events.resize(events.size() * 2);

        for (int i = 0; i < n; ++i) {
            const struct kevent& e = events[static_cast<size_t>(i)];
            int fd = static_cast<int>(e.ident);
            if (e.filter == EVFILT_TIMER) {
                std::cout << "stats connections=" << conns.size() << " online=" << state.online_.size() << " registered=" << state.credentials_.size() << "\n";
                if (hub.enabled && !hub.connected && !hub.connecting && hub.fd < 0) {
                    bool in_progress = false;
                    int hfd = ConnectTcpIpv4NonBlocking(hub.addr, hub.port, in_progress);
                    if (hfd >= 0) {
                        hub.fd = hfd;
                        hub.connecting = in_progress;
                        hub.connected = !in_progress;
                        struct kevent he[2];
                        EV_SET(&he[0], static_cast<uintptr_t>(hub.fd), EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, nullptr);
                        EV_SET(&he[1], static_cast<uintptr_t>(hub.fd), EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, nullptr);
                        kevent(kq, he, 2, nullptr, 0, nullptr);
                        if (hub.connected) {
                            if (hub.public_host.empty()) hub.public_host = addr_buf;
                            if (hub.public_port == 0) hub.public_port = port;
                            HubQueueLine(kq, hub, "RELAY " + hub.public_host + " " + std::to_string(hub.public_port) + "\n");
                            for (const auto& kv : state.online_) HubQueueLine(kq, hub, "ONLINE " + kv.first + "\n");
                        }
                    }
                }
                continue;
            }
            if (fd == listen_fd) {
                while (true) {
                    sockaddr_in client_addr;
                    socklen_t client_len = sizeof(client_addr);
                    int cfd = ::accept(listen_fd, reinterpret_cast<sockaddr*>(&client_addr), &client_len);
                    if (cfd < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        break;
                    }
                    SetNoDelay(cfd);
                    SetNonBlocking(cfd);
                    ConnState cs;
                    cs.fd = cfd;
                    conns.emplace(cfd, std::move(cs));

                    struct kevent ce[2];
                    EV_SET(&ce[0], static_cast<uintptr_t>(cfd), EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, nullptr);
                    EV_SET(&ce[1], static_cast<uintptr_t>(cfd), EVFILT_WRITE, EV_ADD | EV_DISABLE, 0, 0, nullptr);
                    kevent(kq, ce, 2, nullptr, 0, nullptr);
                }
                continue;
            }

            if (hub.enabled && hub.fd >= 0 && fd == hub.fd) {
                if (e.filter == EVFILT_READ) {
                    char buf[64 * 1024];
                    while (true) {
                        ssize_t r = ::recv(hub.fd, buf, sizeof(buf), 0);
                        if (r > 0) {
                            hub.inbuf.append(buf, buf + r);
                            if (hub.inbuf.size() > 8 * 1024 * 1024) {
                                HubFailPendingToOffline(state, hub);
                                HubReset(kq, hub);
                                break;
                            }
                        } else if (r == 0) {
                            HubFailPendingToOffline(state, hub);
                            HubReset(kq, hub);
                            break;
                        } else {
                            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                            HubFailPendingToOffline(state, hub);
                            HubReset(kq, hub);
                            break;
                        }
                    }

                    size_t nl = 0;
                    while (hub.fd >= 0) {
                        nl = hub.inbuf.find('\n');
                        if (nl == std::string::npos) break;
                        std::string line = hub.inbuf.substr(0, nl);
                        hub.inbuf.erase(0, nl + 1);
                        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();

                        if (line.rfind("FOUND ", 0) == 0) {
                            std::string msgid_s = line.substr(6);
                            uint64_t msgid = static_cast<uint64_t>(std::strtoull(msgid_s.c_str(), nullptr, 10));
                            hub.pending.erase(msgid);
                        } else if (line.rfind("NOTFOUND ", 0) == 0) {
                            std::string msgid_s = line.substr(9);
                            uint64_t msgid = static_cast<uint64_t>(std::strtoull(msgid_s.c_str(), nullptr, 10));
                            hub.pending.erase(msgid);
                        } else if (line.rfind("NOUSER ", 0) == 0) {
                            std::string msgid_s = line.substr(7);
                            uint64_t msgid = static_cast<uint64_t>(std::strtoull(msgid_s.c_str(), nullptr, 10));
                            auto pit = hub.pending.find(msgid);
                            if (pit != hub.pending.end()) {
                                int sfd = pit->second.sender_fd;
                                hub.pending.erase(pit);
                                auto sit = conns.find(sfd);
                                if (sit != conns.end()) {
                                    QueueFrame(sit->second, FrameType::Error, PayloadError("destinataire inconnu"));
                                    EnableWrite(kq, sfd);
                                }
                            }
                        } else if (line.rfind("BLOCKED ", 0) == 0) {
                            std::string msgid_s = line.substr(8);
                            uint64_t msgid = static_cast<uint64_t>(std::strtoull(msgid_s.c_str(), nullptr, 10));
                            auto pit = hub.pending.find(msgid);
                            if (pit != hub.pending.end()) {
                                int sfd = pit->second.sender_fd;
                                hub.pending.erase(pit);
                                auto sit = conns.find(sfd);
                                if (sit != conns.end()) {
                                    QueueFrame(sit->second, FrameType::Error, PayloadError("message bloqué"));
                                    EnableWrite(kq, sfd);
                                }
                            }
                        } else if (line.rfind("AUTH_OK ", 0) == 0) {
                            std::string reqid_s = line.substr(8);
                            uint64_t reqid = static_cast<uint64_t>(std::strtoull(reqid_s.c_str(), nullptr, 10));
                            auto itp = hub.pending_auth.find(reqid);
                            if (itp != hub.pending_auth.end()) {
                                int sfd = itp->second.sender_fd;
                                uint8_t kind = itp->second.kind;
                                std::string handle = itp->second.handle;
                                hub.pending_auth.erase(itp);
                                auto sit = conns.find(sfd);
                                if (sit != conns.end()) {
                                    ConnState& sc = sit->second;
                                    if (kind == 1) {
                                        QueueFrame(sc, FrameType::LoginOk, {});
                                        sc.want_close = true;
                                        EnableWrite(kq, sfd);
                                    } else if (kind == 2 && sc.stage == ConnState::Stage::AwaitHubAuth && sc.handle == handle) {
                                        state.SetOnline(sc.handle, sc.fd);
                                        QueueFrame(sc, FrameType::LoginOk, {});
                                        auto offline = state.TakeOffline(sc.handle);
                                        for (const auto& m : offline) {
                                            auto p = PayloadDeliver(m.from, m.text);
                                            if (!p.empty()) QueueFrame(sc, FrameType::DeliverMessage, p);
                                        }
                                        HubQueueLine(kq, hub, "ONLINE " + sc.handle + "\n");
                                        {
                                            uint64_t reqid2 = ++hub.seq;
                                            hub.pending_rel[reqid2] = PendingRel{sc.fd, 1};
                                            HubQueueLine(kq, hub, "REL " + std::to_string(reqid2) + " LIST " + sc.handle + " _\n");
                                        }
                                        sc.stage = ConnState::Stage::Authed;
                                        EnableWrite(kq, sfd);
                                    }
                                }
                            }
                        } else if (line.rfind("AUTH_ERR ", 0) == 0 || line.rfind("AUTH_FAIL ", 0) == 0) {
                            size_t prefix = (line.rfind("AUTH_ERR ", 0) == 0) ? 9 : 10;
                            std::string rest = line.substr(prefix);
                            size_t sp = rest.find(' ');
                            std::string reqid_s = (sp == std::string::npos) ? rest : rest.substr(0, sp);
                            std::string reason = (sp == std::string::npos) ? "auth invalide" : rest.substr(sp + 1);
                            uint64_t reqid = static_cast<uint64_t>(std::strtoull(reqid_s.c_str(), nullptr, 10));
                            auto itp = hub.pending_auth.find(reqid);
                            if (itp != hub.pending_auth.end()) {
                                int sfd = itp->second.sender_fd;
                                uint8_t kind = itp->second.kind;
                                hub.pending_auth.erase(itp);
                                auto sit = conns.find(sfd);
                                if (sit != conns.end()) {
                                    std::string msg = "auth invalide";
                                    if (kind == 1 && reason == "exists") msg = "handle déjà utilisé";
                                    else if (reason == "no_user") msg = "compte introuvable";
                                    else if (reason == "bad_password") msg = "mot de passe incorrect";
                                    QueueFrame(sit->second, FrameType::Error, PayloadError(msg));
                                    sit->second.want_close = true;
                                    EnableWrite(kq, sfd);
                                }
                            }
                        } else if (line.rfind("REL_OK ", 0) == 0) {
                            std::string reqid_s = line.substr(7);
                            uint64_t reqid = static_cast<uint64_t>(std::strtoull(reqid_s.c_str(), nullptr, 10));
                            auto itp = hub.pending_rel.find(reqid);
                            if (itp != hub.pending_rel.end()) {
                                int sfd = itp->second.sender_fd;
                                uint8_t op = itp->second.op;
                                hub.pending_rel.erase(itp);
                                auto sit = conns.find(sfd);
                                if (sit != conns.end()) {
                                    const char* msg = "ok";
                                    if (op == 2) msg = "ami ajouté";
                                    else if (op == 3) msg = "ami supprimé";
                                    else if (op == 4) msg = "bloqué";
                                    else if (op == 5) msg = "débloqué";
                                    QueueFrame(sit->second, FrameType::Ok, PayloadOk(msg));
                                    EnableWrite(kq, sfd);
                                }
                            }
                        } else if (line.rfind("REL_ERR ", 0) == 0) {
                            std::string rest = line.substr(8);
                            size_t sp = rest.find(' ');
                            std::string reqid_s = (sp == std::string::npos) ? rest : rest.substr(0, sp);
                            std::string reason = (sp == std::string::npos) ? "erreur" : rest.substr(sp + 1);
                            uint64_t reqid = static_cast<uint64_t>(std::strtoull(reqid_s.c_str(), nullptr, 10));
                            auto itp = hub.pending_rel.find(reqid);
                            if (itp != hub.pending_rel.end()) {
                                int sfd = itp->second.sender_fd;
                                hub.pending_rel.erase(itp);
                                auto sit = conns.find(sfd);
                                if (sit != conns.end()) {
                                    QueueFrame(sit->second, FrameType::Error, PayloadError(reason));
                                    EnableWrite(kq, sfd);
                                }
                            }
                        } else if (line.rfind("REL_LIST ", 0) == 0) {
                            std::string rest = line.substr(9);
                            size_t sp = rest.find(' ');
                            if (sp == std::string::npos) continue;
                            std::string reqid_s = rest.substr(0, sp);
                            std::string b64 = rest.substr(sp + 1);
                            uint64_t reqid = static_cast<uint64_t>(std::strtoull(reqid_s.c_str(), nullptr, 10));
                            auto itp = hub.pending_rel.find(reqid);
                            if (itp != hub.pending_rel.end()) {
                                int sfd = itp->second.sender_fd;
                                hub.pending_rel.erase(itp);
                                auto sit = conns.find(sfd);
                                if (sit != conns.end()) {
                                    std::string decoded;
                                    std::vector<std::pair<std::string, uint8_t>> entries;
                                    if (Base64Decode(b64, decoded)) {
                                        size_t start = 0;
                                        while (start < decoded.size()) {
                                            size_t nl2 = decoded.find('\n', start);
                                            if (nl2 == std::string::npos) nl2 = decoded.size();
                                            std::string line2 = decoded.substr(start, nl2 - start);
                                            start = nl2 + 1;
                                            if (line2.empty()) continue;
                                            size_t tab = line2.find('\t');
                                            if (tab == std::string::npos) continue;
                                            std::string peer = line2.substr(0, tab);
                                            std::string kind = line2.substr(tab + 1);
                                            if (!IsValidHandle(peer)) continue;
                                            uint8_t k = 0;
                                            if (kind == "friend") k = 1;
                                            else if (kind == "blocked") k = 2;
                                            if (k == 0) continue;
                                            entries.push_back({peer, k});
                                        }
                                    }
                                    QueueFrame(sit->second, FrameType::FriendListResp, PayloadFriendList(entries));
                                    EnableWrite(kq, sfd);
                                }
                            }
                        } else if (line.rfind("PRESENCE ", 0) == 0) {
                            std::string rest = line.substr(9);
                            size_t sp = rest.find(' ');
                            if (sp == std::string::npos) continue;
                            std::string handle = rest.substr(0, sp);
                            std::string state_s = rest.substr(sp + 1);
                            uint8_t online = (state_s == "online") ? 1 : 0;
                            if (!IsValidHandle(handle)) continue;
                            for (auto& kv : conns) {
                                ConnState& cc = kv.second;
                                if (cc.stage == ConnState::Stage::Authed) {
                                    auto p = PayloadPresence(handle, online);
                                    QueueFrame(cc, FrameType::Presence, p);
                                    EnableWrite(kq, cc.fd);
                                }
                            }
                        } else if (line.rfind("DELIVER ", 0) == 0) {
                            std::string rest = line.substr(8);
                            size_t p1 = rest.find(' ');
                            if (p1 == std::string::npos) continue;
                            size_t p2 = rest.find(' ', p1 + 1);
                            if (p2 == std::string::npos) continue;
                            std::string to = rest.substr(0, p1);
                            std::string from = rest.substr(p1 + 1, p2 - (p1 + 1));
                            std::string b64 = rest.substr(p2 + 1);
                            if (!IsValidHandle(to) || !IsValidHandle(from)) continue;
                            std::string text;
                            if (!Base64Decode(b64, text)) continue;

                            int rfd = state.FindOnlineFd(to);
                            if (rfd >= 0) {
                                auto it = conns.find(rfd);
                                if (it != conns.end()) {
                                    auto p = PayloadDeliver(from, text);
                                    if (!p.empty()) {
                                        QueueFrame(it->second, FrameType::DeliverMessage, p);
                                        EnableWrite(kq, rfd);
                                    }
                                } else {
                                    state.EnqueueOffline(to, OfflineMsg{from, text});
                                }
                            } else {
                                state.EnqueueOffline(to, OfflineMsg{from, text});
                            }
                        }
                    }
                } else if (e.filter == EVFILT_WRITE) {
                    if (hub.connecting) {
                        int err = 0;
                        socklen_t len = sizeof(err);
                        if (getsockopt(hub.fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0 || err != 0) {
                            HubFailPendingToOffline(state, hub);
                            HubReset(kq, hub);
                            continue;
                        }
                        hub.connecting = false;
                        hub.connected = true;
                        if (hub.public_host.empty()) hub.public_host = addr_buf;
                        if (hub.public_port == 0) hub.public_port = port;
                        HubQueueLine(kq, hub, "RELAY " + hub.public_host + " " + std::to_string(hub.public_port) + "\n");
                        for (const auto& kv : state.online_) HubQueueLine(kq, hub, "ONLINE " + kv.first + "\n");
                    }

                    while (hub.out_off < hub.outbuf.size()) {
                        ssize_t w = ::send(hub.fd, hub.outbuf.data() + hub.out_off, hub.outbuf.size() - hub.out_off, 0);
                        if (w > 0) {
                            hub.out_off += static_cast<size_t>(w);
                        } else if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                            break;
                        } else {
                            HubFailPendingToOffline(state, hub);
                            HubReset(kq, hub);
                            break;
                        }
                    }
                    if (hub.fd < 0) continue;
                    if (hub.out_off >= hub.outbuf.size()) {
                        hub.outbuf.clear();
                        hub.out_off = 0;
                        DisableWrite(kq, hub.fd);
                    } else if (hub.out_off >= 4096 && hub.out_off >= hub.outbuf.size() / 2) {
                        hub.outbuf.erase(hub.outbuf.begin(), hub.outbuf.begin() + static_cast<std::ptrdiff_t>(hub.out_off));
                        hub.out_off = 0;
                    }
                    if (hub.outbuf.size() > 8 * 1024 * 1024) {
                        HubFailPendingToOffline(state, hub);
                        HubReset(kq, hub);
                    }
                }
                continue;
            }

            auto it = conns.find(fd);
            if (it == conns.end()) continue;
            ConnState& c = it->second;

            if (e.filter == EVFILT_READ) {
                uint8_t buf[64 * 1024];
                while (true) {
                    ssize_t r = ::recv(fd, buf, sizeof(buf), 0);
                    if (r > 0) {
                        c.inbuf.insert(c.inbuf.end(), buf, buf + r);
                        if (c.inbuf.size() > kMaxInBufferBytes) {
                            CloseConn(kq, state, conns, hub, fd);
                            break;
                        }
                    } else if (r == 0) {
                        CloseConn(kq, state, conns, hub, fd);
                        break;
                    } else {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        CloseConn(kq, state, conns, hub, fd);
                        break;
                    }
                }
                if (conns.find(fd) == conns.end()) continue;

                while (true) {
                    if (c.inbuf.size() - c.in_off < 5) break;
                    FrameType type = static_cast<FrameType>(c.inbuf[c.in_off]);
                    uint32_t be_len = 0;
                    std::memcpy(&be_len, c.inbuf.data() + c.in_off + 1, 4);
                    uint32_t len = ntohl(be_len);
                    if (len > kMaxPayload) {
                        QueueFrame(c, FrameType::Error, PayloadError("payload trop grand"));
                        c.want_close = true;
                        EnableWrite(kq, fd);
                        c.in_off = c.inbuf.size();
                        break;
                    }
                    if (c.inbuf.size() - c.in_off < 5 + static_cast<size_t>(len)) break;
                    const uint8_t* payload = c.inbuf.data() + c.in_off + 5;
                    HandleFrame(kq, state, conns, hub, c, type, payload, len);
                    c.in_off += 5 + static_cast<size_t>(len);
                    MaybeCompactIn(c);
                    if (c.outbuf.size() - c.out_off > kMaxOutBufferBytes) {
                        CloseConn(kq, state, conns, hub, fd);
                        break;
                    }
                }
            } else if (e.filter == EVFILT_WRITE) {
                while (c.out_off < c.outbuf.size()) {
                    ssize_t w = ::send(fd, c.outbuf.data() + c.out_off, c.outbuf.size() - c.out_off, 0);
                    if (w > 0) {
                        c.out_off += static_cast<size_t>(w);
                    } else if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                        break;
                    } else {
                        CloseConn(kq, state, conns, hub, fd);
                        break;
                    }
                }
                if (conns.find(fd) == conns.end()) continue;
                if (c.out_off >= c.outbuf.size()) {
                    c.outbuf.clear();
                    c.out_off = 0;
                    DisableWrite(kq, fd);
                    if (c.want_close) {
                        CloseConn(kq, state, conns, hub, fd);
                    }
                } else {
                    MaybeCompactOut(c);
                }
            }
        }
    }

    ::close(kq);
    ::close(listen_fd);
}
