#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <GLFW/glfw3.h>

#include "src/image_loader.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <array>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <deque>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <mutex>
#include <unordered_map>
#include <string>
#include <thread>
#include <vector>
#include <sys/stat.h>

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

struct InboundMessage {
    std::string from;
    std::string text;
};

struct Sha256Digest {
    std::array<uint8_t, 32> bytes{};
};

bool WriteAll(int fd, const uint8_t* data, size_t size) {
    size_t sent = 0;
    while (sent < size) {
        ssize_t n = ::send(fd, data + sent, size - sent, 0);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

bool ReadExact(int fd, uint8_t* out, size_t size) {
    size_t got = 0;
    while (got < size) {
        ssize_t n = ::recv(fd, out + got, size - got, 0);
        if (n <= 0) return false;
        got += static_cast<size_t>(n);
    }
    return true;
}

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

bool RecvFrame(int fd, FrameType& type, std::vector<uint8_t>& payload) {
    uint8_t header[5];
    if (!ReadExact(fd, header, sizeof(header))) return false;
    type = static_cast<FrameType>(header[0]);
    uint32_t be_len = 0;
    std::memcpy(&be_len, header + 1, 4);
    uint32_t len = ntohl(be_len);
    payload.assign(len, 0);
    if (len == 0) return true;
    return ReadExact(fd, payload.data(), len);
}

std::vector<uint8_t> PayloadHello(const std::string& handle) {
    std::vector<uint8_t> p;
    if (handle.size() > 0xFFFF) return p;
    AppendU16(p, static_cast<uint16_t>(handle.size()));
    p.insert(p.end(), handle.begin(), handle.end());
    return p;
}

std::vector<uint8_t> PayloadRegister(const std::string& handle, const Sha256Digest& secret_hash) {
    std::vector<uint8_t> p;
    if (handle.size() > 0xFFFF) return p;
    AppendU16(p, static_cast<uint16_t>(handle.size()));
    p.insert(p.end(), handle.begin(), handle.end());
    p.insert(p.end(), secret_hash.bytes.begin(), secret_hash.bytes.end());
    return p;
}

std::vector<uint8_t> PayloadLoginBegin(const std::string& handle) {
    return PayloadHello(handle);
}

std::vector<uint8_t> PayloadLoginResponse(const std::string& handle, const std::array<uint8_t, 32>& hmac) {
    std::vector<uint8_t> p;
    if (handle.size() > 0xFFFF) return p;
    AppendU16(p, static_cast<uint16_t>(handle.size()));
    p.insert(p.end(), handle.begin(), handle.end());
    p.insert(p.end(), hmac.begin(), hmac.end());
    return p;
}

std::vector<uint8_t> PayloadSend(const std::string& to, const std::string& text) {
    std::vector<uint8_t> p;
    if (to.size() > 0xFFFF) return p;
    AppendU16(p, static_cast<uint16_t>(to.size()));
    p.insert(p.end(), to.begin(), to.end());
    AppendU32(p, static_cast<uint32_t>(text.size()));
    p.insert(p.end(), text.begin(), text.end());
    return p;
}

std::vector<uint8_t> PayloadPeerU16(const std::string& peer) {
    std::vector<uint8_t> p;
    if (peer.size() > 0xFFFF) return p;
    AppendU16(p, static_cast<uint16_t>(peer.size()));
    p.insert(p.end(), peer.begin(), peer.end());
    return p;
}

bool ParseDeliver(const std::vector<uint8_t>& payload, InboundMessage& msg) {
    size_t off = 0;
    if (!ReadStringU16(payload, off, msg.from)) return false;
    if (!ReadStringU32(payload, off, msg.text)) return false;
    return off == payload.size();
}

bool ParseError(const std::vector<uint8_t>& payload, std::string& text) {
    size_t off = 0;
    if (!ReadStringU16(payload, off, text)) return false;
    return off == payload.size();
}

bool ParseOk(const std::vector<uint8_t>& payload, std::string& text) {
    return ParseError(payload, text);
}

struct PresenceEntry {
    bool online = false;
};

class ChatClient {
public:
    ~ChatClient() { Shutdown(); }

    bool IsConnected() const { return connected_.load(); }
    bool IsBusy() const { return busy_.load(); }

    std::string StatusText() const {
        std::lock_guard<std::mutex> lock(status_mu_);
        return status_;
    }

    std::string LocalHandle() const {
        std::lock_guard<std::mutex> lock(identity_mu_);
        return local_handle_;
    }

    void Shutdown() {
        Disconnect();
        if (worker_.joinable()) worker_.join();
    }

    void Disconnect() {
        if (!connected_.exchange(false)) return;
        int fd = fd_;
        fd_ = -1;
        if (fd >= 0) ::shutdown(fd, SHUT_RDWR);
        if (reader_.joinable()) reader_.join();
        if (fd >= 0) ::close(fd);
        {
            std::lock_guard<std::mutex> lock(identity_mu_);
            local_handle_.clear();
        }
        SetStatus("déconnecté");
    }

    bool StartRegister(const std::string& handle, const std::string& password) {
        if (IsBusy() || IsConnected()) return false;
        busy_.store(true);
        if (worker_.joinable()) worker_.join();
        worker_ = std::thread([this, handle, password] { RegisterFlow(handle, password); });
        return true;
    }

    bool StartLogin(const std::string& handle, const std::string& password) {
        if (IsBusy() || IsConnected()) return false;
        busy_.store(true);
        if (worker_.joinable()) worker_.join();
        worker_ = std::thread([this, handle, password] { LoginFlow(handle, password); });
        return true;
    }

    bool SendMessage(const std::string& to, const std::string& text) {
        if (!IsConnected()) return false;
        auto payload = PayloadSend(to, text);
        auto frame = MakeFrame(FrameType::SendMessage, payload);
        std::lock_guard<std::mutex> lock(send_mu_);
        return WriteAll(fd_, frame.data(), frame.size());
    }

    bool FriendAdd(const std::string& peer) {
        if (!IsConnected()) return false;
        auto payload = PayloadPeerU16(peer);
        auto frame = MakeFrame(FrameType::FriendAdd, payload);
        std::lock_guard<std::mutex> lock(send_mu_);
        return WriteAll(fd_, frame.data(), frame.size());
    }

    bool FriendRemove(const std::string& peer) {
        if (!IsConnected()) return false;
        auto payload = PayloadPeerU16(peer);
        auto frame = MakeFrame(FrameType::FriendRemove, payload);
        std::lock_guard<std::mutex> lock(send_mu_);
        return WriteAll(fd_, frame.data(), frame.size());
    }

    bool Block(const std::string& peer) {
        if (!IsConnected()) return false;
        auto payload = PayloadPeerU16(peer);
        auto frame = MakeFrame(FrameType::Block, payload);
        std::lock_guard<std::mutex> lock(send_mu_);
        return WriteAll(fd_, frame.data(), frame.size());
    }

    bool Unblock(const std::string& peer) {
        if (!IsConnected()) return false;
        auto payload = PayloadPeerU16(peer);
        auto frame = MakeFrame(FrameType::Unblock, payload);
        std::lock_guard<std::mutex> lock(send_mu_);
        return WriteAll(fd_, frame.data(), frame.size());
    }

    bool RequestFriendList() {
        if (!IsConnected()) return false;
        auto frame = MakeFrame(FrameType::FriendListReq, {});
        std::lock_guard<std::mutex> lock(send_mu_);
        return WriteAll(fd_, frame.data(), frame.size());
    }

    std::vector<InboundMessage> DrainInbound() {
        std::vector<InboundMessage> out;
        std::lock_guard<std::mutex> lock(in_mu_);
        while (!inbound_.empty()) {
            out.push_back(std::move(inbound_.front()));
            inbound_.pop_front();
        }
        return out;
    }

private:
    static constexpr const char* kDefaultHost = "127.0.0.1";
    static constexpr uint16_t kDefaultPort = 5555;

    static int ConnectSocket() {
        const char* host_env = std::getenv("KLEOS_SERVER_HOST");
        const char* port_env = std::getenv("KLEOS_SERVER_PORT");
        const char* host = (host_env && host_env[0]) ? host_env : kDefaultHost;
        uint16_t port = kDefaultPort;
        if (port_env && port_env[0]) {
            int p = std::atoi(port_env);
            if (p > 0 && p < 65536) port = static_cast<uint16_t>(p);
        }

        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return -1;

        sockaddr_in addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (::inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
            ::close(fd);
            return -1;
        }
        if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            ::close(fd);
            return -1;
        }
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        return fd;
    }

    void RegisterFlow(const std::string& handle, const std::string& password) {
        SetStatus("inscription…");
        int fd = ConnectSocket();
        if (fd < 0) {
            SetStatus("connexion impossible");
            busy_.store(false);
            return;
        }

        auto secret_hash = Sha256(reinterpret_cast<const uint8_t*>(password.data()), password.size());
        auto payload = PayloadRegister(handle, secret_hash);
        auto frame = MakeFrame(FrameType::Register, payload);
        if (!WriteAll(fd, frame.data(), frame.size())) {
            ::close(fd);
            SetStatus("erreur réseau");
            busy_.store(false);
            return;
        }

        FrameType t;
        std::vector<uint8_t> p;
        if (!RecvFrame(fd, t, p)) {
            ::close(fd);
            SetStatus("erreur réseau");
            busy_.store(false);
            return;
        }

        if (t == FrameType::LoginOk) {
            SetStatus("inscription réussie");
        } else if (t == FrameType::Error) {
            std::string err;
            if (ParseError(p, err)) SetStatus(err);
            else SetStatus("inscription refusée");
        } else {
            SetStatus("réponse inconnue");
        }
        ::close(fd);
        busy_.store(false);
    }

    void LoginFlow(const std::string& handle, const std::string& password) {
        SetStatus("connexion…");
        int fd = ConnectSocket();
        if (fd < 0) {
            SetStatus("connexion impossible");
            busy_.store(false);
            return;
        }

        auto begin_payload = PayloadLoginBegin(handle);
        auto begin_frame = MakeFrame(FrameType::LoginBegin, begin_payload);
        if (!WriteAll(fd, begin_frame.data(), begin_frame.size())) {
            ::close(fd);
            SetStatus("erreur réseau");
            busy_.store(false);
            return;
        }

        FrameType t;
        std::vector<uint8_t> p;
        if (!RecvFrame(fd, t, p)) {
            ::close(fd);
            SetStatus("erreur réseau");
            busy_.store(false);
            return;
        }

        if (t == FrameType::Error) {
            std::string err;
            if (ParseError(p, err)) SetStatus(err);
            else SetStatus("connexion refusée");
            ::close(fd);
            busy_.store(false);
            return;
        }
        if (t != FrameType::LoginChallenge || p.size() != 32) {
            ::close(fd);
            SetStatus("handshake invalide");
            busy_.store(false);
            return;
        }

        std::array<uint8_t, 32> nonce{};
        std::memcpy(nonce.data(), p.data(), nonce.size());

        auto secret_hash = Sha256(reinterpret_cast<const uint8_t*>(password.data()), password.size());
        auto mac = HmacSha256(secret_hash.bytes.data(), secret_hash.bytes.size(), nonce.data(), nonce.size());
        std::array<uint8_t, 32> hmac{};
        std::memcpy(hmac.data(), mac.bytes.data(), hmac.size());

        auto resp_payload = PayloadLoginResponse(handle, hmac);
        auto resp_frame = MakeFrame(FrameType::LoginResponse, resp_payload);
        if (!WriteAll(fd, resp_frame.data(), resp_frame.size())) {
            ::close(fd);
            SetStatus("erreur réseau");
            busy_.store(false);
            return;
        }

        FrameType t2;
        std::vector<uint8_t> p2;
        if (!RecvFrame(fd, t2, p2)) {
            ::close(fd);
            SetStatus("erreur réseau");
            busy_.store(false);
            return;
        }

        if (t2 == FrameType::Error) {
            std::string err;
            if (ParseError(p2, err)) SetStatus(err);
            else SetStatus("connexion refusée");
            ::close(fd);
            busy_.store(false);
            return;
        }
        if (t2 != FrameType::LoginOk) {
            ::close(fd);
            SetStatus("handshake invalide");
            busy_.store(false);
            return;
        }

        fd_ = fd;
        connected_.store(true);
        {
            std::lock_guard<std::mutex> lock(identity_mu_);
            local_handle_ = handle;
        }
        reader_ = std::thread([this] { ReaderLoop(); });
        SetStatus("connecté");
        busy_.store(false);
    }

    void ReaderLoop() {
        while (connected_.load()) {
            FrameType type;
            std::vector<uint8_t> payload;
            if (!RecvFrame(fd_, type, payload)) break;
            if (type == FrameType::DeliverMessage) {
                InboundMessage msg;
                if (ParseDeliver(payload, msg)) PushInbound(std::move(msg));
            } else if (type == FrameType::Error) {
                std::string err;
                if (ParseError(payload, err)) PushInbound(InboundMessage{"server", err});
            } else if (type == FrameType::Ok) {
                std::string ok;
                if (ParseOk(payload, ok)) PushInbound(InboundMessage{"server", ok});
            } else if (type == FrameType::FriendListResp) {
                size_t off = 0;
                uint16_t count = 0;
                if (!ReadU16(payload, off, count)) continue;
                std::string lines;
                for (uint16_t i = 0; i < count; ++i) {
                    std::string peer;
                    if (!ReadStringU16(payload, off, peer)) break;
                    if (off >= payload.size()) break;
                    uint8_t kind = payload[off++];
                    const char* k = nullptr;
                    if (kind == 1) k = "friend";
                    else if (kind == 2) k = "blocked";
                    if (!k) continue;
                    lines.append(peer);
                    lines.push_back('\t');
                    lines.append(k);
                    lines.push_back('\n');
                }
                if (!lines.empty()) PushInbound(InboundMessage{"__friends__", lines});
            } else if (type == FrameType::Presence) {
                size_t off = 0;
                std::string handle;
                uint16_t hl = 0;
                if (!ReadU16(payload, off, hl)) continue;
                if (off + hl > payload.size()) continue;
                handle.assign(reinterpret_cast<const char*>(payload.data() + off), hl);
                off += hl;
                if (off >= payload.size()) continue;
                uint8_t online = payload[off];
                PushInbound(InboundMessage{"__presence__", handle + "\t" + (online ? "1" : "0")});
            }
        }
        connected_.store(false);
        SetStatus("connexion perdue");
    }

    void PushInbound(InboundMessage msg) {
        std::lock_guard<std::mutex> lock(in_mu_);
        inbound_.push_back(std::move(msg));
        while (inbound_.size() > 1000) inbound_.pop_front();
    }

    void SetStatus(std::string s) const {
        std::lock_guard<std::mutex> lock(status_mu_);
        status_ = std::move(s);
    }

    int fd_ = -1;
    std::atomic<bool> connected_{false};
    std::atomic<bool> busy_{false};
    std::thread worker_;
    std::thread reader_;
    std::mutex send_mu_;

    mutable std::mutex status_mu_;
    mutable std::string status_ = "déconnecté";

    mutable std::mutex identity_mu_;
    mutable std::string local_handle_;

    std::mutex in_mu_;
    std::deque<InboundMessage> inbound_;
};

struct ChatMessage {
    bool outgoing;
    std::string from;
    std::string text;

    ChatMessage(bool outgoing_, std::string from_, std::string text_) : outgoing(outgoing_), from(std::move(from_)), text(std::move(text_)) {}
};

static ImFont* g_font_title = nullptr;
static ImFont* g_font_ui = nullptr;
static AnimatedGif g_bg_login;
static AnimatedGif g_bg_chat;
static bool g_force_save_state = false;

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

static std::string GetStateRootDir() {
    const char* home = getenv("HOME");
    std::string base = home ? home : ".";
    std::string dir = base + "/.kleos";
    mkdir(dir.c_str(), 0755);
    return dir;
}

static std::string GetLegacyStatePath() {
    return GetStateRootDir() + "/client_state.v1";
}

static std::string GetLegacyMigratedStatePath() {
    return GetStateRootDir() + "/client_state.v1.migrated";
}

static std::string GetStatePathForHandle(const std::string& handle) {
    std::string root = GetStateRootDir();
    std::string safe = handle.empty() ? "anon" : handle;
    std::string dir = root + "/" + safe;
    mkdir(dir.c_str(), 0755);
    return dir + "/client_state.v1";
}

static void SaveClientState(const std::vector<std::string>& contacts,
                            int selected,
                            const std::unordered_map<std::string, std::vector<ChatMessage>>& conversations,
                            const std::string& local_handle) {
    std::ofstream f(GetStatePathForHandle(local_handle), std::ios::binary | std::ios::trunc);
    if (!f) return;
    f << "v1\n";
    f << "owner\t" << local_handle << "\n";
    f << "selected\t" << ((selected >= 0 && static_cast<size_t>(selected) < contacts.size()) ? contacts[static_cast<size_t>(selected)] : "") << "\n";
    for (const auto& c : contacts) f << "contact\t" << c << "\n";
    for (const auto& kv : conversations) {
        const std::string& peer = kv.first;
        for (const auto& m : kv.second) {
            f << "msg\t" << peer << "\t" << (m.outgoing ? "1" : "0") << "\t" << m.from << "\t" << Base64Encode(m.text) << "\n";
        }
    }
}

static void LoadClientState(std::vector<std::string>& contacts,
                            int& selected,
                            std::unordered_map<std::string, std::vector<ChatMessage>>& conversations,
                            const std::string& local_handle) {
    auto parse = [&](std::istream& in) {
        std::string line;
        if (!std::getline(in, line)) return false;
        if (line != "v1") return false;

        contacts.clear();
        conversations.clear();
        selected = -1;
        std::string selected_handle;
        while (std::getline(in, line)) {
            if (line.rfind("owner\t", 0) == 0) {
                continue;
            }
            if (line.rfind("selected\t", 0) == 0) {
                selected_handle = line.substr(std::string("selected\t").size());
                continue;
            }
            if (line.rfind("contact\t", 0) == 0) {
                std::string c = line.substr(std::string("contact\t").size());
                if (!c.empty()) contacts.push_back(std::move(c));
                continue;
            }
            if (line.rfind("msg\t", 0) == 0) {
                size_t a = line.find('\t');                // msg
                size_t b = line.find('\t', a + 1);         // peer
                size_t c = line.find('\t', b + 1);         // outgoing
                size_t d = line.find('\t', c + 1);         // from
                if (a == std::string::npos || b == std::string::npos || c == std::string::npos || d == std::string::npos) continue;
                std::string peer = line.substr(a + 1, b - (a + 1));
                std::string outgoing_s = line.substr(b + 1, c - (b + 1));
                std::string from = line.substr(c + 1, d - (c + 1));
                std::string text_b64 = line.substr(d + 1);
                bool outgoing = outgoing_s == "1";
                std::string text;
                if (!Base64Decode(text_b64, text)) continue;
                conversations[peer].push_back(ChatMessage{outgoing, std::move(from), std::move(text)});
                continue;
            }
        }
        if (!selected_handle.empty()) {
            for (size_t i = 0; i < contacts.size(); ++i) {
                if (contacts[i] == selected_handle) {
                    selected = static_cast<int>(i);
                    break;
                }
            }
        }

        if (!local_handle.empty()) {
            conversations.erase(local_handle);
            contacts.erase(std::remove(contacts.begin(), contacts.end(), local_handle), contacts.end());
            if (selected >= static_cast<int>(contacts.size())) selected = -1;
        }
        return true;
    };

    std::ifstream f(GetStatePathForHandle(local_handle), std::ios::binary);
    if (f && parse(f)) return;

    std::ifstream legacy(GetLegacyStatePath(), std::ios::binary);
    if (!legacy) return;
    if (!parse(legacy)) return;
    SaveClientState(contacts, selected, conversations, local_handle);
    std::string legacy_path = GetLegacyStatePath();
    std::string migrated_path = GetLegacyMigratedStatePath();
    std::rename(legacy_path.c_str(), migrated_path.c_str());
}

void ApplyKleosStyle() {
    auto& style = ImGui::GetStyle();
    style.WindowRounding = 14.0f;
    style.ChildRounding = 14.0f;
    style.FrameRounding = 12.0f;
    style.PopupRounding = 16.0f;
    style.ScrollbarRounding = 10.0f;
    style.GrabRounding = 10.0f;
    style.WindowPadding = ImVec2(14, 14);
    style.FramePadding = ImVec2(12, 8);
    style.ItemSpacing = ImVec2(10, 10);
    style.ItemInnerSpacing = ImVec2(8, 8);
    style.WindowBorderSize = 0.0f;
    style.ChildBorderSize = 0.0f;
    style.PopupBorderSize = 1.0f;
    style.DisabledAlpha = 0.45f;

    auto& c = style.Colors;
    c[ImGuiCol_Text] = ImVec4(0.97f, 0.98f, 0.99f, 1.0f);
    c[ImGuiCol_TextDisabled] = ImVec4(0.74f, 0.77f, 0.80f, 1.0f);
    c[ImGuiCol_Border] = ImVec4(1.0f, 1.0f, 1.0f, 0.10f);
    c[ImGuiCol_BorderShadow] = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
    c[ImGuiCol_WindowBg] = ImVec4(0.03f, 0.04f, 0.05f, 1.0f);
    c[ImGuiCol_PopupBg] = ImVec4(0.08f, 0.09f, 0.11f, 0.86f);
    c[ImGuiCol_TitleBg] = ImVec4(0.08f, 0.09f, 0.11f, 0.88f);
    c[ImGuiCol_TitleBgActive] = ImVec4(0.08f, 0.09f, 0.11f, 0.92f);
    c[ImGuiCol_TitleBgCollapsed] = ImVec4(0.08f, 0.09f, 0.11f, 0.72f);
    c[ImGuiCol_FrameBg] = ImVec4(0.14f, 0.15f, 0.17f, 0.72f);
    c[ImGuiCol_FrameBgHovered] = ImVec4(0.18f, 0.19f, 0.22f, 0.78f);
    c[ImGuiCol_FrameBgActive] = ImVec4(0.20f, 0.21f, 0.24f, 0.84f);
    c[ImGuiCol_Button] = ImVec4(0.20f, 0.22f, 0.26f, 0.82f);
    c[ImGuiCol_ButtonHovered] = ImVec4(0.26f, 0.28f, 0.32f, 0.86f);
    c[ImGuiCol_ButtonActive] = ImVec4(0.16f, 0.18f, 0.22f, 0.90f);
    c[ImGuiCol_Header] = ImVec4(0.14f, 0.16f, 0.18f, 0.72f);
    c[ImGuiCol_HeaderHovered] = ImVec4(0.18f, 0.20f, 0.23f, 0.80f);
    c[ImGuiCol_HeaderActive] = ImVec4(0.20f, 0.22f, 0.26f, 0.86f);
    c[ImGuiCol_Separator] = ImVec4(1.0f, 1.0f, 1.0f, 0.06f);
    c[ImGuiCol_SeparatorHovered] = ImVec4(1.0f, 1.0f, 1.0f, 0.14f);
    c[ImGuiCol_SeparatorActive] = ImVec4(1.0f, 1.0f, 1.0f, 0.22f);
    c[ImGuiCol_CheckMark] = ImVec4(0.82f, 0.84f, 0.86f, 1.0f);
    c[ImGuiCol_SliderGrab] = ImVec4(0.62f, 0.66f, 0.70f, 0.85f);
    c[ImGuiCol_SliderGrabActive] = ImVec4(0.72f, 0.75f, 0.78f, 0.95f);
    c[ImGuiCol_Tab] = ImVec4(0.12f, 0.13f, 0.15f, 0.80f);
    c[ImGuiCol_TabHovered] = ImVec4(0.18f, 0.20f, 0.23f, 0.86f);
    c[ImGuiCol_TabActive] = ImVec4(0.16f, 0.18f, 0.21f, 0.86f);
    c[ImGuiCol_TabUnfocused] = ImVec4(0.12f, 0.13f, 0.15f, 0.70f);
    c[ImGuiCol_TabUnfocusedActive] = ImVec4(0.16f, 0.18f, 0.21f, 0.80f);
}

static ImVec2 VAdd(const ImVec2& a, const ImVec2& b) { return ImVec2(a.x + b.x, a.y + b.y); }
static ImVec2 VSub(const ImVec2& a, const ImVec2& b) { return ImVec2(a.x - b.x, a.y - b.y); }

static void DrawGlassPanel(ImDrawList* draw_list, const ImVec2& min, const ImVec2& max, float rounding) {
    ImU32 shadow = ImGui::GetColorU32(ImVec4(0.0f, 0.0f, 0.0f, 0.38f));
    ImU32 base = ImGui::GetColorU32(ImVec4(0.06f, 0.07f, 0.08f, 0.72f));
    ImU32 border = ImGui::GetColorU32(ImVec4(1.0f, 1.0f, 1.0f, 0.08f));
    ImU32 top = ImGui::GetColorU32(ImVec4(0.12f, 0.14f, 0.16f, 0.30f));
    ImU32 bot = ImGui::GetColorU32(ImVec4(0.02f, 0.03f, 0.04f, 0.10f));

    draw_list->AddRectFilled(VAdd(min, ImVec2(0, 7)), VAdd(max, ImVec2(0, 7)), shadow, rounding);
    draw_list->AddRectFilled(min, max, base, rounding);
    draw_list->AddRectFilledMultiColor(VAdd(min, ImVec2(1, 1)), VSub(max, ImVec2(1, 1)), top, top, bot, bot);
    draw_list->AddRect(min, max, border, rounding, 0, 1.0f);
    draw_list->AddLine(VAdd(min, ImVec2(rounding, 1)), ImVec2(max.x - rounding, min.y + 1), ImGui::GetColorU32(ImVec4(1, 1, 1, 0.10f)), 1.0f);
}

static bool BeginGlassChild(const char* id, ImVec2 size, float rounding, ImGuiChildFlags child_flags = ImGuiChildFlags_None) {
    ImVec2 avail = ImGui::GetContentRegionAvail();
    if (size.x <= 0) size.x = avail.x;
    if (size.y <= 0) size.y = avail.y;
    ImVec2 min = ImGui::GetCursorScreenPos();
    ImVec2 max = VAdd(min, size);
    DrawGlassPanel(ImGui::GetWindowDrawList(), min, max, rounding);
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0, 0, 0, 0));
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, rounding);
    bool ok = ImGui::BeginChild(id, size, child_flags | ImGuiChildFlags_AlwaysUseWindowPadding);
    ImGui::PopStyleVar();
    ImGui::PopStyleColor();
    return ok;
}

static void EndGlassChild() { ImGui::EndChild(); }

static bool BeginGlassChildNoScroll(const char* id, ImVec2 size, float rounding, ImGuiChildFlags child_flags = ImGuiChildFlags_None) {
    ImVec2 avail = ImGui::GetContentRegionAvail();
    if (size.x <= 0) size.x = avail.x;
    if (size.y <= 0) size.y = avail.y;
    ImVec2 min = ImGui::GetCursorScreenPos();
    ImVec2 max = VAdd(min, size);
    DrawGlassPanel(ImGui::GetWindowDrawList(), min, max, rounding);
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0, 0, 0, 0));
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, rounding);
    bool ok = ImGui::BeginChild(id, size, child_flags | ImGuiChildFlags_AlwaysUseWindowPadding,
                                ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
    ImGui::PopStyleVar();
    ImGui::PopStyleColor();
    return ok;
}

static std::string TruncateOneLine(const std::string& s, size_t max_len) {
    if (s.size() <= max_len) return s;
    if (max_len <= 1) return s.substr(0, max_len);
    return s.substr(0, max_len - 1) + "…";
}

void RenderBubble(const ChatMessage& msg, float max_width) {
    float avail = ImGui::GetContentRegionAvail().x;
    float width = max_width < avail ? max_width : avail;
    if (msg.outgoing && width < avail) ImGui::SetCursorPosX(ImGui::GetCursorPosX() + (avail - width));
    float wrap = width - 24.0f;
    if (wrap < 80.0f) wrap = 80.0f;

    ImVec4 bubble_bg = msg.outgoing ? ImVec4(0.20f, 0.22f, 0.26f, 0.86f) : ImVec4(0.08f, 0.09f, 0.11f, 0.78f);
    ImVec4 bubble_text = ImVec4(0.94f, 0.95f, 0.97f, 1.0f);

    ImGui::PushStyleColor(ImGuiCol_ChildBg, bubble_bg);
    ImGui::PushStyleColor(ImGuiCol_Text, bubble_text);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(12, 10));

    ImGui::BeginChild(ImGui::GetID(&msg), ImVec2(width, 0), ImGuiChildFlags_AutoResizeY | ImGuiChildFlags_Border);
    if (!msg.outgoing) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.70f, 0.76f, 0.90f, 1.0f));
        ImGui::TextUnformatted(msg.from.c_str());
        ImGui::PopStyleColor();
    }
    ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + wrap);
    ImGui::TextUnformatted(msg.text.c_str());
    ImGui::PopTextWrapPos();
    ImGui::EndChild();

    ImGui::PopStyleVar();
    ImGui::PopStyleColor(2);
}

void RenderChatUI(ChatClient& client) {
    static bool style_applied = false;
    if (!style_applied) {
        ApplyKleosStyle();
        style_applied = true;
    }

    static bool bg_loaded = false;
    if (!bg_loaded) {
        LoadAnimatedGifFromFile("/Users/dalm1/Desktop/reroll/Progra/Kleos/assets/ERL.gif", g_bg_login);
        LoadAnimatedGifFromFile("/Users/dalm1/Desktop/reroll/Progra/Kleos/assets/ERL1.gif", g_bg_chat);
        bg_loaded = true;
    }

    static char reg_handle[64] = "";
    static char reg_pass[64] = "";
    static char reg_pass2[64] = "";
    static char login_handle[64] = "";
    static char login_pass[64] = "";

    static char add_contact[64] = "";
    static char message[1024] = "";
    static std::string toast_text;
    static double toast_until_t = 0.0;

    static std::vector<std::string> contacts;
    static int selected = -1;
    static std::unordered_map<std::string, std::vector<ChatMessage>> conversations;
    static std::unordered_map<std::string, int> unread;
    static bool state_loaded = false;
    static bool state_dirty = false;
    static double last_save_t = 0.0;
    static std::string state_handle;
    static bool friends_requested = false;
    static std::string friends_handle;
    static std::unordered_map<std::string, bool> blocked;
    static std::unordered_map<std::string, PresenceEntry> presence;

    std::string current_handle = client.IsConnected() ? client.LocalHandle() : "";
    if (!current_handle.empty() && (!state_loaded || state_handle != current_handle)) {
        if (state_loaded && state_dirty && !state_handle.empty()) {
            SaveClientState(contacts, selected, conversations, state_handle);
            state_dirty = false;
        }
        contacts.clear();
        conversations.clear();
        unread.clear();
        selected = -1;
        LoadClientState(contacts, selected, conversations, current_handle);
        for (const auto& kv : conversations) {
            if (std::find(contacts.begin(), contacts.end(), kv.first) == contacts.end()) contacts.push_back(kv.first);
        }
        state_handle = current_handle;
        state_loaded = true;
        friends_requested = false;
        friends_handle.clear();
        blocked.clear();
        presence.clear();
    }

    if (client.IsConnected() && !current_handle.empty() && (!friends_requested || friends_handle != current_handle)) {
        client.RequestFriendList();
        friends_requested = true;
        friends_handle = current_handle;
    }

    for (auto& msg : client.DrainInbound()) {
        if (msg.from == "server") {
            toast_text = msg.text;
            toast_until_t = ImGui::GetTime() + 4.0;
            continue;
        }
        if (msg.from == "__presence__") {
            size_t tab = msg.text.find('\t');
            if (tab != std::string::npos) {
                std::string peer = msg.text.substr(0, tab);
                std::string online_s = msg.text.substr(tab + 1);
                bool on = (online_s == "1");
                presence[peer].online = on;
            }
            continue;
        }
        if (msg.from == "__friends__") {
            std::vector<std::string> new_contacts;
            blocked.clear();

            size_t start = 0;
            while (start < msg.text.size()) {
                size_t nl = msg.text.find('\n', start);
                if (nl == std::string::npos) nl = msg.text.size();
                std::string line = msg.text.substr(start, nl - start);
                start = nl + 1;
                if (line.empty()) continue;
                size_t tab = line.find('\t');
                if (tab == std::string::npos) continue;
                std::string peer = line.substr(0, tab);
                std::string kind = line.substr(tab + 1);
                if (peer.empty() || peer == state_handle) continue;
                if (kind == "friend") {
                    new_contacts.push_back(peer);
                    if (conversations.find(peer) == conversations.end()) conversations[peer] = {};
                } else if (kind == "blocked") {
                    blocked[peer] = true;
                }
            }

            std::string prev_peer;
            if (selected >= 0 && static_cast<size_t>(selected) < contacts.size()) prev_peer = contacts[static_cast<size_t>(selected)];
            contacts = std::move(new_contacts);
            std::sort(contacts.begin(), contacts.end());
            contacts.erase(std::unique(contacts.begin(), contacts.end()), contacts.end());

            selected = -1;
            if (!prev_peer.empty()) {
                for (size_t i = 0; i < contacts.size(); ++i) {
                    if (contacts[i] == prev_peer) {
                        selected = static_cast<int>(i);
                        break;
                    }
                }
            }
            state_dirty = true;
            continue;
        }
        if (conversations.find(msg.from) == conversations.end()) conversations[msg.from] = {};
        conversations[msg.from].push_back(ChatMessage{false, msg.from, msg.text});
        bool is_friend = std::find(contacts.begin(), contacts.end(), msg.from) != contacts.end();
        if (!is_friend) {
            toast_text = "Message reçu d'un utilisateur non ajouté: " + msg.from;
            toast_until_t = ImGui::GetTime() + 4.0;
        } else {
            if (selected < 0 || contacts[static_cast<size_t>(selected)] != msg.from) unread[msg.from] += 1;
        }
        state_dirty = true;
    }

    ImGuiIO& io = ImGui::GetIO();
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(io.DisplaySize);
    ImGuiWindowFlags root_flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
                                 ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoBringToFrontOnFocus |
                                 ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;
    ImGui::Begin("Kleos", nullptr, root_flags);

    if (!client.IsConnected()) {
        {
            unsigned int tex = AnimatedGifTextureAtTime(g_bg_login, ImGui::GetTime());
            if (tex) {
                ImDrawList* dl = ImGui::GetWindowDrawList();
                ImVec2 pos = ImGui::GetWindowPos();
                ImVec2 size = ImGui::GetWindowSize();
                dl->AddImage((ImTextureID)(intptr_t)tex, pos, ImVec2(pos.x + size.x, pos.y + size.y));
                dl->AddRectFilled(pos, ImVec2(pos.x + size.x, pos.y + size.y), ImGui::GetColorU32(ImVec4(0, 0, 0, 0.58f)));
            }
        }
        ImVec2 size = ImVec2(420, 0);
        ImVec2 center = ImVec2((io.DisplaySize.x - size.x) * 0.5f, (io.DisplaySize.y - 360.0f) * 0.5f);
        ImGui::SetCursorPos(center);
        ImGui::BeginChild("auth_card", size, ImGuiChildFlags_Border | ImGuiChildFlags_AutoResizeY);

        if (g_font_title) ImGui::PushFont(g_font_title);
        ImGui::TextUnformatted("Kleos");
        if (g_font_title) ImGui::PopFont();
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.86f, 0.88f, 0.90f, 1.0f));
        ImGui::TextUnformatted("Chat rapide et sécurisé");
        ImGui::PopStyleColor();
        ImGui::Spacing();

        if (ImGui::BeginTabBar("auth_tabs")) {
            if (ImGui::BeginTabItem("Se connecter")) {
                ImGui::InputText("Username", login_handle, sizeof(login_handle));
                ImGui::InputText("Mot de passe", login_pass, sizeof(login_pass), ImGuiInputTextFlags_Password);
                bool can = !client.IsBusy() && std::strlen(login_handle) > 0 && std::strlen(login_pass) > 0;
                if (!can) ImGui::BeginDisabled();
                if (ImGui::Button("Connexion", ImVec2(-1, 0))) {
                    client.StartLogin(login_handle, login_pass);
                }
                if (!can) ImGui::EndDisabled();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Créer un compte")) {
                ImGui::InputText("Username", reg_handle, sizeof(reg_handle));
                ImGui::InputText("Mot de passe", reg_pass, sizeof(reg_pass), ImGuiInputTextFlags_Password);
                ImGui::InputText("Confirmer", reg_pass2, sizeof(reg_pass2), ImGuiInputTextFlags_Password);

                bool can = !client.IsBusy() && std::strlen(reg_handle) > 0 && std::strlen(reg_pass) >= 6 &&
                           std::strcmp(reg_pass, reg_pass2) == 0;
                if (!can) ImGui::BeginDisabled();
                if (ImGui::Button("S'inscrire", ImVec2(-1, 0))) {
                    client.StartRegister(reg_handle, reg_pass);
                }
                if (!can) ImGui::EndDisabled();
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }

        ImGui::Spacing();
        if (client.IsBusy()) {
            ImGui::TextDisabled("Veuillez patienter…");
        } else {
            std::string st = client.StatusText();
            if (st != "déconnecté" && st != "connecté") {
                bool ok = st == "inscription réussie";
                ImGui::PushStyleColor(ImGuiCol_Text, ok ? ImVec4(0.45f, 0.85f, 0.55f, 1.0f) : ImVec4(0.95f, 0.55f, 0.55f, 1.0f));
                ImGui::TextUnformatted(st.c_str());
                ImGui::PopStyleColor();
            }
        }

        ImGui::EndChild();
        ImGui::End();
        return;
    }

    ImDrawList* root_draw_list = ImGui::GetWindowDrawList();
    ImVec2 wpos = ImGui::GetWindowPos();
    ImVec2 wsize = ImGui::GetWindowSize();
    root_draw_list->AddRectFilledMultiColor(wpos, VAdd(wpos, wsize), ImGui::GetColorU32(ImVec4(0.04f, 0.05f, 0.06f, 1.0f)),
                                           ImGui::GetColorU32(ImVec4(0.04f, 0.05f, 0.06f, 1.0f)), ImGui::GetColorU32(ImVec4(0.01f, 0.02f, 0.02f, 1.0f)),
                                           ImGui::GetColorU32(ImVec4(0.01f, 0.02f, 0.02f, 1.0f)));
    {
        unsigned int tex = AnimatedGifTextureAtTime(g_bg_chat, ImGui::GetTime());
        if (tex) {
            root_draw_list->AddImage((ImTextureID)(intptr_t)tex, wpos, VAdd(wpos, wsize));
            root_draw_list->AddRectFilled(wpos, VAdd(wpos, wsize), ImGui::GetColorU32(ImVec4(0, 0, 0, 0.52f)));
        }
    }

    static bool open_add_contact = false;
    static bool open_settings = false;
    static char contacts_search[64] = "";
    static char global_search[64] = "";

    if (open_add_contact) {
        ImGui::OpenPopup("Nouveau contact");
        open_add_contact = false;
    }
    if (open_settings) {
        ImGui::OpenPopup("Paramètres");
        open_settings = false;
    }

    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(18, 16));
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(12, 10));
    bool popup_contact_open = ImGui::BeginPopupModal("Nouveau contact", nullptr, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoMove);
    if (popup_contact_open) {
        ImGui::TextUnformatted("Ajouter un contact");
        ImGui::Spacing();
        ImGui::InputText("Username", add_contact, sizeof(add_contact));
        ImGui::Spacing();
        bool can = std::strlen(add_contact) > 0;
        if (!can) ImGui::BeginDisabled();
        if (ImGui::Button("Ajouter", ImVec2(120, 0))) {
            std::string c(add_contact);
            if (c == state_handle) {
                toast_text = "Impossible de discuter avec soi-même";
                toast_until_t = ImGui::GetTime() + 4.0;
            } else {
                if (!client.IsConnected()) {
                    toast_text = "Non connecté";
                    toast_until_t = ImGui::GetTime() + 4.0;
                } else if (!client.FriendAdd(c)) {
                    toast_text = "Échec ajout";
                    toast_until_t = ImGui::GetTime() + 4.0;
                } else {
                    client.RequestFriendList();
                }
            }
            add_contact[0] = '\0';
            ImGui::CloseCurrentPopup();
        }
        if (!can) ImGui::EndDisabled();
        ImGui::SameLine();
        if (ImGui::Button("Annuler", ImVec2(120, 0))) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
    if (popup_contact_open) {
        ImGui::PopStyleVar(2);
    } else {
        ImGui::PopStyleVar(2);
    }

    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(18, 16));
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(12, 10));
    bool popup_settings_open = ImGui::BeginPopupModal("Paramètres", nullptr, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoMove);
    if (popup_settings_open) {
        ImGui::TextUnformatted("Paramètres");
        ImGui::Spacing();
        ImGui::Text("Connecté en tant que %s", client.LocalHandle().c_str());
        if (!blocked.empty()) {
            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();
            ImGui::TextUnformatted("Bloqués");
            ImGui::Spacing();
            for (const auto& kv : blocked) {
                const std::string& b = kv.first;
                ImGui::TextUnformatted(b.c_str());
                ImGui::SameLine();
                ImGui::SetCursorPosX(ImGui::GetWindowContentRegionMax().x - 120.0f);
                if (ImGui::Button(("Débloquer##" + b).c_str(), ImVec2(110, 0))) {
                    client.Unblock(b);
                    client.RequestFriendList();
                }
            }
        }
        ImGui::Spacing();
        if (ImGui::Button("Déconnexion", ImVec2(-1, 0))) {
            client.Disconnect();
            ImGui::CloseCurrentPopup();
        }
        if (ImGui::Button("Fermer", ImVec2(-1, 0))) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
    ImGui::PopStyleVar(2);

    float sidebar_w = 330.0f;
    float top_h = 74.0f;

    BeginGlassChildNoScroll("topbar", ImVec2(0, top_h), 18.0f);
    ImGui::AlignTextToFramePadding();
    float topbar_y = ImGui::GetCursorPosY();
    ImGui::TextUnformatted(client.LocalHandle().c_str());
    ImGui::SameLine();

    float right = ImGui::GetWindowContentRegionMax().x;
    float gap = 10.0f;
    float button_w = ImGui::GetFrameHeight();
    float min_search_w = 160.0f;
    float max_search_w = 320.0f;
    float available = right - ImGui::GetCursorPosX();
    float search_w = available - (button_w * 2.0f + gap * 2.0f);
    if (search_w > max_search_w) search_w = max_search_w;
    if (search_w < min_search_w) search_w = min_search_w;
    float needed = search_w + button_w * 2.0f + gap * 2.0f;
    float x = right - needed;
    float min_x = ImGui::GetCursorPosX() + 8.0f;
    if (x < min_x) x = min_x;
    ImGui::SetCursorPosY(topbar_y);
    ImGui::SetCursorPosX(x);
    ImGui::SetNextItemWidth(search_w);
    ImGui::InputTextWithHint("##global_search", "Rechercher", global_search, sizeof(global_search));
    ImGui::SameLine();
    if (ImGui::Button("+", ImVec2(button_w, 0))) open_add_contact = true;
    ImGui::SameLine();
    if (ImGui::Button("⋯", ImVec2(button_w, 0))) open_settings = true;
    EndGlassChild();

    ImGui::Spacing();

    BeginGlassChild("body", ImVec2(0, 0), 18.0f);
    BeginGlassChild("sidebar", ImVec2(sidebar_w, 0), 16.0f);

    ImGui::TextUnformatted("Contacts");
    ImGui::Spacing();
    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##contacts_search", "Filtrer", contacts_search, sizeof(contacts_search));
    ImGui::Spacing();

    for (size_t i = 0; i < contacts.size(); ++i) {
        const std::string& c = contacts[i];
        if (contacts_search[0] != '\0') {
            std::string needle(contacts_search);
            if (c.find(needle) == std::string::npos) continue;
        }

        auto it_conv = conversations.find(c);
        std::string preview;
        if (it_conv != conversations.end() && !it_conv->second.empty()) preview = it_conv->second.back().text;
        preview = TruncateOneLine(preview, 42);

        bool is_selected = selected == static_cast<int>(i);
        ImGui::PushID(static_cast<int>(i));
        ImDrawList* draw_list = ImGui::GetWindowDrawList();
        ImVec2 row_size(ImGui::GetContentRegionAvail().x, 56.0f);
        ImVec2 pmin = ImGui::GetCursorScreenPos();
        ImVec2 pmax = VAdd(pmin, row_size);
        ImU32 bg = ImGui::GetColorU32(is_selected ? ImVec4(0.12f, 0.13f, 0.15f, 0.85f) : ImVec4(1.0f, 1.0f, 1.0f, 0.02f));
        ImU32 br = ImGui::GetColorU32(is_selected ? ImVec4(1.0f, 1.0f, 1.0f, 0.10f) : ImVec4(1.0f, 1.0f, 1.0f, 0.06f));
        draw_list->AddRectFilled(pmin, pmax, bg, 14.0f);
        draw_list->AddRect(pmin, pmax, br, 14.0f, 0, 1.0f);
        bool clicked = ImGui::InvisibleButton("contact_row", row_size);
        if (ImGui::BeginPopupContextItem("contact_ctx")) {
            if (ImGui::MenuItem("Supprimer")) {
                client.FriendRemove(c);
                client.RequestFriendList();
            }
            if (ImGui::MenuItem("Bloquer")) {
                client.Block(c);
                client.RequestFriendList();
            }
            ImGui::EndPopup();
        }

        ImU32 name_col = ImGui::GetColorU32(ImVec4(0.95f, 0.96f, 0.97f, 1.0f));
        ImU32 preview_col = ImGui::GetColorU32(ImVec4(0.74f, 0.77f, 0.80f, 1.0f));
        ImVec2 name_pos = VAdd(pmin, ImVec2(14, 12));
        ImVec2 preview_pos = VAdd(pmin, ImVec2(14, 34));
        draw_list->AddText(name_pos, name_col, c.c_str());
        draw_list->AddText(preview_pos, preview_col, preview.empty() ? "—" : preview.c_str());

        int u = 0;
        auto it_u = unread.find(c);
        if (it_u != unread.end()) u = it_u->second;
        bool online = false;
        auto it_p = presence.find(c);
        if (it_p != presence.end()) online = it_p->second.online;
        if (u > 0) {
            std::string badge = std::to_string(u);
            ImVec2 badge_pad(10, 6);
            ImVec2 text_sz = ImGui::CalcTextSize(badge.c_str());
            ImVec2 badge_sz(text_sz.x + badge_pad.x * 2, text_sz.y + badge_pad.y * 2);
            ImVec2 bmax = VAdd(ImVec2(pmax.x - 10, pmin.y + 18), ImVec2(0, badge_sz.y));
            ImVec2 bmin = VSub(bmax, badge_sz);
            draw_list->AddRectFilled(bmin, bmax, ImGui::GetColorU32(ImVec4(0.70f, 0.74f, 0.78f, 0.92f)), 999.0f);
            draw_list->AddRect(bmin, bmax, ImGui::GetColorU32(ImVec4(1, 1, 1, 0.12f)), 999.0f);
            draw_list->AddText(VAdd(bmin, badge_pad), ImGui::GetColorU32(ImVec4(0.02f, 0.03f, 0.03f, 1.0f)), badge.c_str());
        } else {
            ImVec2 dot = VAdd(pmin, ImVec2(pmax.x - pmin.x - 16.0f, 22.0f));
            ImU32 col = ImGui::GetColorU32(online ? ImVec4(0.90f, 0.94f, 0.98f, 0.90f) : ImVec4(0.65f, 0.70f, 0.74f, 0.50f));
            draw_list->AddCircleFilled(dot, 4.0f, col, 16);
        }

        if (clicked) {
            selected = static_cast<int>(i);
            unread[c] = 0;
            state_dirty = true;
        }
        ImGui::Spacing();
        ImGui::PopID();
    }
    EndGlassChild();

    ImGui::SameLine();
    BeginGlassChild("main", ImVec2(0, 0), 16.0f);

    if (selected < 0 || selected >= static_cast<int>(contacts.size())) {
        ImVec2 avail = ImGui::GetContentRegionAvail();
        ImVec2 p = ImGui::GetCursorPos();
        ImGui::SetCursorPos(VAdd(p, ImVec2((avail.x - 360.0f) * 0.5f, (avail.y - 120.0f) * 0.5f)));
        BeginGlassChild("empty_state", ImVec2(360, 120), 16.0f);
        ImGui::TextUnformatted("Aucun chat ouvert");
        ImGui::Spacing();
        ImGui::TextDisabled("Crée un contact pour démarrer.");
        ImGui::Spacing();
        if (ImGui::Button("Nouveau chat", ImVec2(-1, 0))) open_add_contact = true;
        EndGlassChild();
        EndGlassChild();
        EndGlassChild();
        ImGui::End();
        return;
    }

    const std::string peer = contacts[static_cast<size_t>(selected)];
    auto& msgs = conversations[peer];

    BeginGlassChildNoScroll("chat_header", ImVec2(0, 64.0f), 16.0f);
    ImGui::TextUnformatted(peer.c_str());
    ImGui::SameLine();
    ImGui::TextDisabled("— sécurisé");
    ImGui::SameLine();
    ImGui::SetCursorPosX(ImGui::GetWindowContentRegionMax().x - 120.0f);
    if (ImGui::Button("Infos", ImVec2(110, 0))) open_settings = true;
    EndGlassChild();

    ImGui::Spacing();

    BeginGlassChild("messages", ImVec2(0, -78.0f), 16.0f);
    float bubble_w = ImGui::GetContentRegionAvail().x * 0.74f;
    if (bubble_w < 260.0f) bubble_w = 260.0f;

    bool at_bottom = ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 2.0f;
    for (size_t i = 0; i < msgs.size(); ++i) {
        RenderBubble(msgs[i], bubble_w);
        ImGui::Spacing();
    }
    if (at_bottom) ImGui::SetScrollHereY(1.0f);
    EndGlassChild();

    ImGui::Spacing();

    BeginGlassChildNoScroll("composer", ImVec2(0, 64.0f), 16.0f);
    float send_w = 110.0f;
    float icon_w = 44.0f;
    float input_w = ImGui::GetContentRegionAvail().x - (send_w + icon_w * 2.0f + 20.0f);
    if (input_w < 120.0f) input_w = 120.0f;
    if (ImGui::Button("＋", ImVec2(icon_w, 0))) {}
    ImGui::SameLine();
    if (ImGui::Button("⌁", ImVec2(icon_w, 0))) {}
    ImGui::SameLine();
    ImGui::SetNextItemWidth(input_w);
    bool send_now = ImGui::InputTextWithHint("##msg", "Écrire un message…", message, sizeof(message), ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    if (ImGui::Button("Envoyer", ImVec2(send_w, 0))) send_now = true;
    if (send_now) {
        std::string text(message);
        if (!text.empty()) {
            if (peer == state_handle) {
                toast_text = "Impossible de discuter avec soi-même";
                toast_until_t = ImGui::GetTime() + 4.0;
                message[0] = '\0';
            } else {
                bool ok = client.SendMessage(peer, text);
                if (ok) {
                    msgs.push_back(ChatMessage{true, client.LocalHandle(), text});
                    state_dirty = true;
                } else {
                    toast_text = "Envoi impossible (connexion)";
                    toast_until_t = ImGui::GetTime() + 4.0;
                }
            }
        }
        message[0] = '\0';
    }
    EndGlassChild();

    EndGlassChild();
    EndGlassChild();

    if (!toast_text.empty() && ImGui::GetTime() < toast_until_t) {
        ImVec2 pad(18, 14);
        ImVec2 text_sz = ImGui::CalcTextSize(toast_text.c_str());
        ImVec2 box_sz(text_sz.x + pad.x * 2, text_sz.y + pad.y * 2);
        if (box_sz.x > 520.0f) box_sz.x = 520.0f;
        ImVec2 pos = ImVec2(io.DisplaySize.x - box_sz.x - 22.0f, io.DisplaySize.y - box_sz.y - 22.0f);
        ImGui::SetCursorPos(pos);
        BeginGlassChildNoScroll("toast", box_sz, 14.0f);
        ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + box_sz.x - pad.x);
        ImGui::TextUnformatted(toast_text.c_str());
        ImGui::PopTextWrapPos();
        EndGlassChild();
    }

    ImGui::End();

    if (state_dirty) {
        double now = ImGui::GetTime();
        if (g_force_save_state || now - last_save_t > 0.6) {
            if (!state_handle.empty()) SaveClientState(contacts, selected, conversations, state_handle);
            last_save_t = now;
            state_dirty = false;
        }
    }
}

}  // namespace

int main() {
    if (!glfwInit())
        return -1;

    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);

    GLFWwindow* window = glfwCreateWindow(1280, 720, "Kleos", NULL, NULL);
    if (window == NULL)
        return -1;

    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    ImGui::StyleColorsDark();

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 150");

    g_font_title = io.Fonts->AddFontFromFileTTF("/Users/dalm1/Desktop/reroll/Progra/Kleos/assets/Orbitron-VariableFont_wght.ttf", 20.0f);
    g_font_ui = io.Fonts->AddFontFromFileTTF("/Users/dalm1/Desktop/reroll/Progra/Kleos/assets/Rajdhani-Variable.ttf", 18.0f);
    if (g_font_ui) io.FontDefault = g_font_ui;
    ImGui_ImplOpenGL3_CreateFontsTexture();

    ChatClient client;

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();
        g_force_save_state = glfwWindowShouldClose(window);

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        RenderChatUI(client);

        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.02f, 0.03f, 0.03f, 1.00f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window);
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}
