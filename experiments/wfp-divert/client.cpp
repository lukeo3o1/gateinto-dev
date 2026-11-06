#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")

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

int main(int argc, char** argv) {
    WSADATA data;
    if (WSAStartup(MAKEWORD(2, 2), &data)) return 2;
    try {
        std::map<std::string, std::string> args;
        for (int i = 1; i < argc; i += 2) {
            if (i + 1 == argc) throw std::runtime_error("missing argument value");
            args[argv[i]] = argv[i + 1];
        }
        const auto ip = args.at("--target");
        const auto nonce = args.at("--nonce");
        const bool udp = args.at("--protocol") == "udp";
        const auto close_mode = args.count("--close-mode") ? args.at("--close-mode") : "fin";
        if (close_mode != "fin" && close_mode != "reset") throw std::runtime_error("invalid close mode");
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
                if (close_mode == "fin") shutdown(socket.value, SD_SEND);
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
                      << ",\"local_ip\":\"" << local_ip << "\""
                      << ",\"local_port\":" << ntohs(bound.sin_port)
                      << ",\"remote_ip\":\"" << ip << "\",\"remote_port\":" << port
                      << ",\"protocol\":" << (udp ? 17 : 6)
                      << ",\"nonce\":\"" << nonce << "\",\"status\":\"echo_ok\"}" << std::endl;
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << "; WSA=" << WSAGetLastError() << std::endl;
        return 1;
    }
}
