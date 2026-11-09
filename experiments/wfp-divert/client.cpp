#include <cstdint>
#include <stdexcept>
#include <string>

namespace client {
enum class StartGateState { Waiting, Released, TimedOut };

bool start_gate_enabled(bool has_start, const std::string& start,
                        bool has_ready, const std::string& ready) {
    if (!has_start && !has_ready) return false;
    if (!has_start || !has_ready || start.empty() || ready.empty())
        throw std::runtime_error("start-file and ready-file require paired nonempty paths");
    const auto normalize = [](std::string path) {
        for (auto& value : path) {
            if (value == '/') value = '\\';
            if (value >= 'A' && value <= 'Z') value = static_cast<char>(value - 'A' + 'a');
        }
        return path;
    };
    if (normalize(start) == normalize(ready))
        throw std::runtime_error("start-file and ready-file must be distinct");
    return true;
}

StartGateState start_gate_state(bool signaled, uint64_t elapsed_ms) {
    if (elapsed_ms >= 10000) return StartGateState::TimedOut;
    return signaled ? StartGateState::Released : StartGateState::Waiting;
}

bool reset_observed(int received, int error) {
    return received == -1 && error == 10054;
}

struct EchoPolicy {
    unsigned hold_ms = 0;
    bool shutdown_after_send = false;
};

EchoPolicy echo_policy(const std::string& value, bool udp, bool connect_only,
                       bool expect_reset, bool reset_close) {
    EchoPolicy result;
    if (value.empty()) throw std::runtime_error("hold-open-ms requires an integer from 0 to 5000");
    for (const unsigned char digit : value) {
        if (digit < '0' || digit > '9' || result.hold_ms > (5000u - (digit - '0')) / 10)
            throw std::runtime_error("hold-open-ms requires an integer from 0 to 5000");
        result.hold_ms = result.hold_ms * 10 + digit - '0';
    }
    if (connect_only && udp) throw std::runtime_error("connect-only requires TCP");
    if (expect_reset && (udp || connect_only)) throw std::runtime_error("expect-reset requires TCP echo");
    if (result.hold_ms && (connect_only || expect_reset))
        throw std::runtime_error("hold-open-ms requires an echo without expect-reset");
    result.shutdown_after_send = !udp && !connect_only && !expect_reset && !reset_close && !result.hold_ms;
    return result;
}
}

#ifdef WFP_CLIENT_STATE_TEST
#include <cassert>
#include <iostream>

int main() {
    assert(!client::start_gate_enabled(false, "", false, ""));
    assert(client::start_gate_enabled(true, "C:\\lab\\start", true, "C:\\lab\\ready"));
    const auto bad_gate = [](bool has_start, const std::string& start,
                             bool has_ready, const std::string& ready) {
        try { client::start_gate_enabled(has_start, start, has_ready, ready); }
        catch (const std::exception&) { return true; }
        return false;
    };
    assert(bad_gate(true, "start", false, ""));
    assert(bad_gate(false, "", true, "ready"));
    assert(bad_gate(true, "", true, "ready"));
    assert(bad_gate(true, "start", true, ""));
    assert(bad_gate(true, "same", true, "same"));
    assert(bad_gate(true, "C:\\Lab\\START", true, "c:/lab/start"));
    assert(client::start_gate_state(false, 0) == client::StartGateState::Waiting);
    assert(client::start_gate_state(false, 9999) == client::StartGateState::Waiting);
    assert(client::start_gate_state(true, 9999) == client::StartGateState::Released);
    assert(client::start_gate_state(false, 10000) == client::StartGateState::TimedOut);
    assert(client::start_gate_state(true, 10000) == client::StartGateState::TimedOut);
    assert(client::start_gate_state(true, 10001) == client::StartGateState::TimedOut);
    assert(client::reset_observed(-1, 10054));
    assert(!client::reset_observed(0, 0));
    assert(!client::reset_observed(-1, 10060));
    assert(!client::reset_observed(-1, 10053));
    assert(!client::reset_observed(1, 10054));
    assert(client::echo_policy("0", false, false, false, false).shutdown_after_send);
    assert(!client::echo_policy("0", true, false, false, false).shutdown_after_send);
    assert(!client::echo_policy("0", false, false, true, false).shutdown_after_send);
    assert(!client::echo_policy("0", false, false, false, true).shutdown_after_send);
    for (const bool udp : {false, true}) {
        const auto policy = client::echo_policy("500", udp, false, false, false);
        assert(policy.hold_ms == 500 && !policy.shutdown_after_send);
        assert(client::echo_policy("5000", udp, false, false, false).hold_ms == 5000);
    }
    const auto rejected = [](const std::string& value, bool udp = false,
                             bool connect_only = false, bool expect_reset = false) {
        try { client::echo_policy(value, udp, connect_only, expect_reset, false); }
        catch (const std::exception&) { return true; }
        return false;
    };
    for (const auto* value : {"", "-1", "+1", "1x", " 1", "5001", "99999999999999999999"})
        assert(rejected(value));
    assert(rejected("1", false, true));
    assert(rejected("1", false, false, true));
    assert(rejected("0", true, true));
    assert(rejected("0", true, false, true));
    assert(rejected("0", false, true, true));
    assert(client::echo_policy("0", false, true, false, false).hold_ms == 0);
    std::cout << "client echo/reset policy self-tests passed\n";
}
#else
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <map>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")
static_assert(SOCKET_ERROR == -1 && WSAECONNRESET == 10054);

static long long qpc() {
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    return now.QuadPart;
}

static sockaddr_in address(const std::string& ip, int port) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<u_short>(port));
    if (port < 0 || port > 65535 || InetPtonA(AF_INET, ip.c_str(), &addr.sin_addr) != 1)
        throw std::runtime_error("invalid IPv4 endpoint");
    return addr;
}

struct Socket {
    SOCKET value;
    ~Socket() { if (value != INVALID_SOCKET) closesocket(value); }
};

static std::string full_path(const std::string& path) {
    const DWORD size = GetFullPathNameA(path.c_str(), 0, nullptr, nullptr);
    if (!size) throw std::runtime_error("start gate path resolution failed");
    std::vector<char> buffer(size);
    const DWORD length = GetFullPathNameA(path.c_str(), size, buffer.data(), nullptr);
    if (!length || length >= size) throw std::runtime_error("start gate path resolution failed");
    return std::string(buffer.data(), length);
}

static bool start_file_exists(const std::string& path) {
    const DWORD attributes = GetFileAttributesA(path.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES) {
        if (attributes & FILE_ATTRIBUTE_DIRECTORY) throw std::runtime_error("start-file must be a file");
        return true;
    }
    const DWORD error = GetLastError();
    if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND)
        throw std::runtime_error("start-file status query failed");
    return false;
}

static void wait_start_gate(const std::string& start, const std::string& ready) {
    const auto start_path = full_path(start);
    const auto ready_path = full_path(ready);
    client::start_gate_enabled(true, start_path, true, ready_path);
    if (start_file_exists(start_path)) throw std::runtime_error("start-file already exists");
    const auto began = GetTickCount64();
    {
        struct ReadyFile {
            HANDLE value;
            ~ReadyFile() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
        } flag{CreateFileA(ready_path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                           CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr)};
        if (flag.value == INVALID_HANDLE_VALUE) throw std::runtime_error("ready-file creation failed");
        const char value = '1';
        DWORD written = 0;
        if (!WriteFile(flag.value, &value, 1, &written, nullptr) || written != 1 || !FlushFileBuffers(flag.value))
            throw std::runtime_error("ready-file write failed");
    }
    for (;;) {
        const bool signaled = start_file_exists(start_path);
        const auto elapsed = GetTickCount64() - began;
        switch (client::start_gate_state(signaled, elapsed)) {
        case client::StartGateState::Released: return;
        case client::StartGateState::TimedOut: throw std::runtime_error("start-file wait timed out");
        case client::StartGateState::Waiting: Sleep(1); break;
        }
    }
}

int main(int argc, char** argv) {
    WSADATA data;
    if (WSAStartup(MAKEWORD(2, 2), &data)) return 2;
    try {
        std::map<std::string, std::string> args;
        for (int i = 1; i < argc; i += 2) {
            if (i + 1 == argc) throw std::runtime_error("missing argument value");
            args[argv[i]] = argv[i + 1];
        }
        const bool gated = client::start_gate_enabled(args.count("--start-file") != 0,
            args.count("--start-file") ? args.at("--start-file") : "",
            args.count("--ready-file") != 0, args.count("--ready-file") ? args.at("--ready-file") : "");
        const auto ip = args.at("--target");
        const auto nonce = args.at("--nonce");
        const bool udp = args.at("--protocol") == "udp";
        const bool connect_only = args.count("--connect-only") && args.at("--connect-only") == "1";
        const bool expect_reset = args.count("--expect-reset") && args.at("--expect-reset") == "1";
        const auto close_mode = args.count("--close-mode") ? args.at("--close-mode") : "fin";
        if (close_mode != "fin" && close_mode != "reset") throw std::runtime_error("invalid close mode");
        const auto policy = client::echo_policy(args.count("--hold-open-ms") ? args.at("--hold-open-ms") : "0",
                                                udp, connect_only, expect_reset, close_mode == "reset");
        if (!udp && args.at("--protocol") != "tcp") throw std::runtime_error("invalid protocol");
        if (nonce.empty() || nonce.size() > 32768 ||
            nonce.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.") != std::string::npos)
            throw std::runtime_error("nonce must be a bounded ASCII token");
        Socket socket{::socket(AF_INET, udp ? SOCK_DGRAM : SOCK_STREAM, udp ? IPPROTO_UDP : IPPROTO_TCP)};
        if (socket.value == INVALID_SOCKET) throw std::runtime_error("socket failed");
        DWORD timeout = 8000;
        setsockopt(socket.value, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));
        setsockopt(socket.value, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));
        const auto bind_ip = args.count("--local-ip") ? args.at("--local-ip") :
            (ip.rfind("127.", 0) == 0 ? ip : "0.0.0.0");
        const auto local = address(bind_ip, args.count("--source-port") ? std::stoi(args.at("--source-port")) : 0);
        if (bind(socket.value, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) != 0)
            throw std::runtime_error("bind failed");
        std::vector<int> ports{std::stoi(args.at("--port"))};
        if (args.count("--second-port")) {
            if (!udp) throw std::runtime_error("second port requires UDP");
            ports.push_back(std::stoi(args.at("--second-port")));
        }
        if (gated) wait_start_gate(args.at("--start-file"), args.at("--ready-file"));
        for (const int port : ports) {
            const auto remote = address(ip, port);
            const auto started = qpc();
            if (args.count("--attempt-out")) {
                sockaddr_in attempt{};
                int size = sizeof(attempt);
                char attempt_ip[INET_ADDRSTRLEN]{};
                if (getsockname(socket.value, reinterpret_cast<sockaddr*>(&attempt), &size) ||
                    !InetNtopA(AF_INET, &attempt.sin_addr, attempt_ip, sizeof(attempt_ip)))
                    throw std::runtime_error("attempt endpoint query failed");
                std::ofstream out(args.at("--attempt-out"), std::ios::app);
                out << "{\"kind\":\"client_attempt\",\"pid\":" << GetCurrentProcessId()
                    << ",\"attempt_qpc\":" << started << ",\"local_ip\":\"" << attempt_ip
                    << "\",\"local_port\":" << ntohs(attempt.sin_port)
                    << ",\"remote_ip\":\"" << ip << "\",\"remote_port\":" << port
                    << ",\"protocol\":" << (udp ? 17 : 6) << ",\"nonce\":\"" << nonce << "\"}\n";
                out.flush();
                if (!out) throw std::runtime_error("attempt log failed");
            }
            if (!udp && connect(socket.value, reinterpret_cast<const sockaddr*>(&remote), sizeof(remote)) != 0)
                throw std::runtime_error("connect failed");
            if (connect_only) {
                sockaddr_in bound{};
                int length = sizeof(bound);
                char local_ip[INET_ADDRSTRLEN]{};
                if (getsockname(socket.value, reinterpret_cast<sockaddr*>(&bound), &length) ||
                    !InetNtopA(AF_INET, &bound.sin_addr, local_ip, sizeof(local_ip)))
                    throw std::runtime_error("connected endpoint query failed");
                std::cout << "{\"kind\":\"client\",\"pid\":" << GetCurrentProcessId()
                    << ",\"start_qpc\":" << started << ",\"done_qpc\":" << qpc()
                    << ",\"local_ip\":\"" << local_ip << "\",\"local_port\":" << ntohs(bound.sin_port)
                    << ",\"remote_ip\":\"" << ip << "\",\"remote_port\":" << port
                    << ",\"protocol\":6,\"nonce\":\"" << nonce << "\",\"status\":\"connected\"}" << std::endl;
                continue;
            }
            if (udp) {
                if (sendto(socket.value, nonce.data(), static_cast<int>(nonce.size()), 0,
                           reinterpret_cast<const sockaddr*>(&remote), sizeof(remote)) != static_cast<int>(nonce.size()))
                    throw std::runtime_error("sendto failed");
            } else {
                size_t sent = 0;
                while (sent < nonce.size()) {
                    int n = send(socket.value, nonce.data() + sent, static_cast<int>(nonce.size() - sent), 0);
                    if (n <= 0) throw std::runtime_error("send failed");
                    sent += n;
                }
                if (policy.shutdown_after_send) shutdown(socket.value, SD_SEND);
            }
            std::string reply;
            do {
                char buffer[65536];
                sockaddr_in sender{};
                int sender_length = sizeof(sender);
                int n = udp ? recvfrom(socket.value, buffer, sizeof(buffer), 0,
                                       reinterpret_cast<sockaddr*>(&sender), &sender_length)
                            : recv(socket.value, buffer, sizeof(buffer), 0);
                if (n <= 0) throw std::runtime_error("reply missing");
                if (udp && (sender.sin_addr.s_addr != remote.sin_addr.s_addr || sender.sin_port != remote.sin_port))
                    throw std::runtime_error("reply source differs");
                reply.append(buffer, n);
            } while (!udp && reply.size() < nonce.size());
            if (reply != nonce) throw std::runtime_error("echo differs");
            const auto echo_completed = qpc();
            if (policy.hold_ms) Sleep(policy.hold_ms);
            const auto hold_completed = policy.hold_ms ? qpc() : echo_completed;
            const char* status = "echo_ok";
            if (expect_reset) {
                char byte = 0;
                const int received = recv(socket.value, &byte, 1, 0);
                const int error = received == SOCKET_ERROR ? WSAGetLastError() : 0;
                if (!client::reset_observed(received, error))
                    throw std::runtime_error("expected TCP reset was not observed");
                status = "reset_observed";
            }
            if (!udp && close_mode == "reset") {
                linger reset{1, 0};
                if (setsockopt(socket.value, SOL_SOCKET, SO_LINGER, reinterpret_cast<const char*>(&reset), sizeof(reset)))
                    throw std::runtime_error("reset close setup failed");
            }
            sockaddr_in bound{};
            int length = sizeof(bound);
            if (getsockname(socket.value, reinterpret_cast<sockaddr*>(&bound), &length))
                throw std::runtime_error("getsockname failed");
            char local_ip[INET_ADDRSTRLEN]{};
            if (!InetNtopA(AF_INET, &bound.sin_addr, local_ip, sizeof(local_ip)))
                throw std::runtime_error("InetNtop failed");
            std::cout << "{\"kind\":\"client\",\"pid\":" << GetCurrentProcessId()
                      << ",\"start_qpc\":" << started << ",\"done_qpc\":" << qpc()
                      << ",\"echo_qpc\":" << echo_completed << ",\"hold_end_qpc\":" << hold_completed
                      << ",\"hold_open_ms\":" << policy.hold_ms
                      << ",\"local_ip\":\"" << local_ip << "\""
                      << ",\"local_port\":" << ntohs(bound.sin_port)
                      << ",\"remote_ip\":\"" << ip << "\",\"remote_port\":" << port
                      << ",\"protocol\":" << (udp ? 17 : 6)
                      << ",\"nonce\":\"" << nonce << "\",\"status\":\"" << status << "\"}" << std::endl;
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << "; WSA=" << WSAGetLastError() << std::endl;
        return 1;
    }
}
#endif
