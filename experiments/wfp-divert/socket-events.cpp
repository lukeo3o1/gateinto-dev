#include <array>
#include <cstdint>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>

namespace socket_probe {

struct Tuple {
    uint32_t local = 0, remote = 0;
    uint16_t local_port = 0, remote_port = 0;
    uint8_t protocol = 0;
};

struct TimeBounds {
    int64_t lower = 0, upper = 0;
};

enum class CreationGuard { Compatible, Uncertain, Newer };
enum class SocketFilter { Scoped, Connect };

std::optional<uint32_t> mapped_ipv4(const std::array<uint32_t, 4>&);
uint32_t wire_ipv4(const unsigned char*);
bool connect_eligible(unsigned, bool, const Tuple&, uint32_t, uint16_t, uint8_t);
TimeBounds event_time_bounds(int64_t, int64_t, int64_t, int64_t, int64_t);
CreationGuard creation_guard(int64_t, TimeBounds);
std::string json(const std::string&);
SocketFilter parse_socket_filter(const std::string&);
std::string socket_filter_expression(SocketFilter, const std::string&, uint16_t, uint8_t);
bool socket_record_allowed(SocketFilter, bool);

SocketFilter parse_socket_filter(const std::string& value) {
    if (value == "scoped") return SocketFilter::Scoped;
    if (value == "connect") return SocketFilter::Connect;
    throw std::runtime_error("Socket filter must be scoped or connect");
}

const char* socket_filter_name(SocketFilter profile) {
    return profile == SocketFilter::Scoped ? "scoped" : "connect";
}

std::string socket_filter_expression(SocketFilter profile, const std::string& target,
                                      uint16_t port, uint8_t protocol) {
    if (profile == SocketFilter::Connect) return "event == CONNECT";
    return "protocol == " + std::to_string(protocol) + " and remoteAddr == " + target +
        " and remotePort == " + std::to_string(port);
}

bool socket_record_allowed(SocketFilter profile, bool eligible) {
    return profile == SocketFilter::Scoped || eligible;
}

std::optional<uint32_t> mapped_ipv4(const std::array<uint32_t, 4>& address) {
    if (address[1] != 0x0000FFFFu || address[2] || address[3]) return {};
    return address[0];
}

uint32_t wire_ipv4(const unsigned char* address) {
    return (uint32_t(address[0]) << 24) | (uint32_t(address[1]) << 16) |
        (uint32_t(address[2]) << 8) | uint32_t(address[3]);
}

bool connect_eligible(unsigned event, bool ipv6, const Tuple& tuple,
                      uint32_t target, uint16_t port, uint8_t protocol) {
    return event == 4 && !ipv6 && tuple.local && tuple.local_port &&
        tuple.remote == target && tuple.remote_port == port && tuple.protocol == protocol;
}

static int64_t add_time(int64_t left, int64_t right) {
    if ((right > 0 && left > std::numeric_limits<int64_t>::max() - right) ||
        (right < 0 && left < std::numeric_limits<int64_t>::min() - right))
        throw std::runtime_error("Time conversion overflow");
    return left + right;
}

static int64_t scale_qpc(int64_t delta, int64_t frequency, bool round_up) {
    constexpr int64_t units = 10'000'000;
    const auto whole = delta / frequency;
    if (whole > std::numeric_limits<int64_t>::max() / units ||
        whole < std::numeric_limits<int64_t>::min() / units)
        throw std::runtime_error("QPC conversion overflow");
    const auto remainder = (delta % frequency) * units;
    auto fraction = remainder / frequency;
    if (round_up && remainder % frequency > 0) ++fraction;
    if (!round_up && remainder % frequency < 0) --fraction;
    return add_time(whole * units, fraction);
}

TimeBounds event_time_bounds(int64_t event, int64_t before, int64_t after,
                             int64_t utc, int64_t frequency) {
    if (event < 0 || before < 0 || after < before || utc < 0 || frequency <= 0 ||
        frequency > std::numeric_limits<int64_t>::max() / 10'000'000)
        throw std::runtime_error("Invalid QPC bracket");
    return {add_time(utc, scale_qpc(event - after, frequency, false)),
            add_time(utc, scale_qpc(event - before, frequency, true))};
}

CreationGuard creation_guard(int64_t creation, TimeBounds event) {
    if (creation <= event.lower) return CreationGuard::Compatible;
    return creation > event.upper ? CreationGuard::Newer : CreationGuard::Uncertain;
}

std::string json(const std::string& value) {
    const char* hex = "0123456789abcdef";
    std::string result = "\"";
    for (unsigned char c : value) {
        switch (c) {
        case '"': result += "\\\""; break;
        case '\\': result += "\\\\"; break;
        case '\n': result += "\\n"; break;
        case '\r': result += "\\r"; break;
        case '\t': result += "\\t"; break;
        default:
            if (c < 32) {
                result += "\\u00";
                result += hex[c >> 4];
                result += hex[c & 15];
            } else result += static_cast<char>(c);
        }
    }
    return result + '"';
}

int self_test() {
    if (parse_socket_filter("scoped") != SocketFilter::Scoped ||
        parse_socket_filter("connect") != SocketFilter::Connect)
        throw std::runtime_error("Exact socket filter profiles");
    for (const char* invalid : {"", "true", "CONNECT", "all", "scope"}) {
        bool rejected = false;
        try { parse_socket_filter(invalid); } catch (const std::runtime_error&) { rejected = true; }
        if (!rejected) throw std::runtime_error("Unknown socket filter profile");
    }
    if (socket_filter_expression(SocketFilter::Scoped, "203.0.113.9", 443, 6) !=
            "protocol == 6 and remoteAddr == 203.0.113.9 and remotePort == 443" ||
        socket_filter_expression(SocketFilter::Connect, "203.0.113.9", 443, 6) != "event == CONNECT")
        throw std::runtime_error("SOCKET scoped profile omits packet-only ip predicate");
    if (!socket_record_allowed(SocketFilter::Scoped, false) ||
        !socket_record_allowed(SocketFilter::Connect, true) || socket_record_allowed(SocketFilter::Connect, false))
        throw std::runtime_error("Broad unrelated events never become identity records");
    const auto mapped = mapped_ipv4({0xCB007109u, 0x0000FFFFu, 0, 0});
    if (!mapped || *mapped != 0xCB007109u) throw std::runtime_error("Mapped IPv4 host order");
    if (mapped_ipv4({0xCB007109u, 0, 0, 0}) || mapped_ipv4({0xCB007109u, 0xFFFFu, 1, 0}))
        throw std::runtime_error("Only IPv4 mapped addresses normalize to IPv4");
    const unsigned char wire[]{203, 0, 113, 9};
    if (wire_ipv4(wire) != *mapped) throw std::runtime_error("Wire and socket addresses agree");
    Tuple tuple{0xC0000202u, *mapped, 40001, 443, 6};
    if (!connect_eligible(4, false, tuple, *mapped, 443, 6)) throw std::runtime_error("Exact connect tuple");
    for (unsigned event : {0u, 3u, 5u, 6u, 7u, 99u})
        if (connect_eligible(event, false, tuple, *mapped, 443, 6))
            throw std::runtime_error("Only CONNECT supplies outbound socket identity");
    if (connect_eligible(4, true, tuple, *mapped, 443, 6) ||
        connect_eligible(4, false, tuple, *mapped + 1, 443, 6) ||
        connect_eligible(4, false, tuple, *mapped, 8443, 6) ||
        connect_eligible(4, false, tuple, *mapped, 443, 17))
        throw std::runtime_error("Connect requires the complete requested tuple scope");
    tuple.local_port = 0;
    if (connect_eligible(4, false, tuple, *mapped, 443, 6)) throw std::runtime_error("Unknown local port");
    const auto before = event_time_bounds(90, 100, 102, 1000, 10'000'000);
    if (before.lower != 988 || before.upper != 990) throw std::runtime_error("QPC bracket before anchor");
    const auto fractional = event_time_bounds(3, 4, 5, 1000, 30'000'000);
    if (fractional.lower != 999 || fractional.upper != 1000) throw std::runtime_error("Outward FILETIME rounding");
    if (creation_guard(988, before) != CreationGuard::Compatible ||
        creation_guard(989, before) != CreationGuard::Uncertain ||
        creation_guard(991, before) != CreationGuard::Newer)
        throw std::runtime_error("PID reuse and uncertainty do not qualify identity");
    if (json("a\"\\\n\t") != "\"a\\\"\\\\\\n\\t\"") throw std::runtime_error("Private JSON escaping");
    return 0;
}

}

#ifndef _WIN32
int main() { return socket_probe::self_test(); }
#endif

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <windows.h>
#include "windivert.h"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <fstream>
#include <mutex>
#include <sstream>
#include <thread>
#include <vector>

#pragma comment(lib, "WinDivert.lib")
#pragma comment(lib, "Ws2_32.lib")

namespace socket_probe {

static_assert(WINDIVERT_EVENT_SOCKET_CONNECT == 4);

static int64_t qpc() {
    LARGE_INTEGER value{};
    QueryPerformanceCounter(&value);
    return value.QuadPart;
}

static uint64_t filetime(FILETIME value) {
    return (uint64_t(value.dwHighDateTime) << 32) | value.dwLowDateTime;
}

struct Options {
    std::string target, output, stop_file, protocol_name;
    SocketFilter socket_filter = SocketFilter::Scoped;
    uint32_t target_address = 0;
    uint16_t port = 0;
    uint8_t protocol = 0;
    unsigned seconds = 35;
};

static unsigned number(const std::string& text, unsigned low, unsigned high) {
    size_t used = 0;
    const auto value = std::stoul(text, &used);
    if (used != text.size() || value < low || value > high) throw std::runtime_error("Invalid number");
    return static_cast<unsigned>(value);
}

static Options options(int argc, char** argv) {
    Options result;
    for (int i = 1; i < argc; i += 2) {
        if (i + 1 >= argc) throw std::runtime_error("Missing option value");
        const std::string key = argv[i], value = argv[i + 1];
        if (key == "--target") result.target = value;
        else if (key == "--port") result.port = static_cast<uint16_t>(number(value, 1, 65535));
        else if (key == "--protocol") result.protocol_name = value;
        else if (key == "--socket-filter") result.socket_filter = parse_socket_filter(value);
        else if (key == "--out") result.output = value;
        else if (key == "--stop-file") result.stop_file = value;
        else if (key == "--seconds") result.seconds = number(value, 1, 3600);
        else throw std::runtime_error("Unknown option");
    }
    if (result.target.empty() || !result.port || result.output.empty() ||
        !WinDivertHelperParseIPv4Address(result.target.c_str(), &result.target_address))
        throw std::runtime_error("Target IPv4, port and output are required");
    if (result.protocol_name == "tcp") result.protocol = IPPROTO_TCP;
    else if (result.protocol_name == "udp") result.protocol = IPPROTO_UDP;
    else throw std::runtime_error("Protocol must be tcp or udp");
    char canonical[32]{};
    if (!WinDivertHelperFormatIPv4Address(result.target_address, canonical, sizeof(canonical)))
        throw std::runtime_error("Cannot format target");
    result.target = canonical;
    return result;
}

class Output {
    static constexpr size_t MAX_RECORDS = 50'000, MAX_BYTES = 64 * 1024 * 1024;
    static constexpr size_t MAX_PENDING_RECORDS = 8192, MAX_PENDING_BYTES = 8 * 1024 * 1024;
    std::ofstream file;
    std::mutex mutex;
    std::condition_variable wake;
    std::deque<std::string> pending;
    size_t pending_bytes = 0, accepted_records = 0, accepted_bytes = 0;
    bool closing = false;
    std::thread writer;
    std::atomic<bool> failed_flag{false};
public:
    std::atomic<uint64_t> queue_dropped{0}, budget_dropped{0}, output_errors{0}, records_written{0};
    std::atomic<bool> truncated{false};

    explicit Output(const std::string& path) : file(path, std::ios::binary | std::ios::trunc) {
        if (!file) throw std::runtime_error("Cannot create private output");
        writer = std::thread([this] {
            std::unique_lock<std::mutex> lock(mutex);
            for (;;) {
                wake.wait(lock, [this] { return closing || !pending.empty(); });
                if (pending.empty() && closing) break;
                auto line = std::move(pending.front());
                pending.pop_front();
                pending_bytes -= line.size() + 1;
                lock.unlock();
                if (!output_errors) {
                    file << line << '\n';
                    file.flush();
                    if (file) ++records_written;
                    else { ++output_errors; failed_flag = true; }
                }
                lock.lock();
            }
        });
    }

    bool push(std::string line) {
        std::lock_guard<std::mutex> lock(mutex);
        const size_t bytes = line.size() + 1;
        if (closing || bytes > MAX_PENDING_BYTES || accepted_records >= MAX_RECORDS ||
            bytes > MAX_BYTES - accepted_bytes) {
            ++budget_dropped;
            truncated = true;
            failed_flag = true;
            return false;
        }
        if (pending.size() >= MAX_PENDING_RECORDS || bytes > MAX_PENDING_BYTES - pending_bytes) {
            ++queue_dropped;
            failed_flag = true;
            return false;
        }
        pending.push_back(std::move(line));
        pending_bytes += bytes;
        accepted_bytes += bytes;
        ++accepted_records;
        wake.notify_one();
        return true;
    }

    bool failed() const { return failed_flag.load(); }

    void finish() {
        if (!writer.joinable()) return;
        { std::lock_guard<std::mutex> lock(mutex); closing = true; }
        wake.notify_one();
        writer.join();
    }

    bool summary(const std::string& line) {
        finish();
        file << line << '\n';
        file.flush();
        if (!file) { ++output_errors; failed_flag = true; return false; }
        return true;
    }

    ~Output() { finish(); }
};

struct ProcessIdentity {
    std::string path, status = "open_process_failed";
    std::optional<uint64_t> creation;
    std::optional<TimeBounds> event_time;
    DWORD error = ERROR_SUCCESS;
    bool valid = false;
};

static ProcessIdentity process_identity(DWORD pid, int64_t event, int64_t frequency) {
    ProcessIdentity result;
    FILETIME now{};
    const auto before = qpc();
    GetSystemTimePreciseAsFileTime(&now);
    const auto after = qpc();
    try {
        result.event_time = event_time_bounds(event, before, after, static_cast<int64_t>(filetime(now)), frequency);
    } catch (...) {
        result.status = "time_mapping_failed";
        result.error = ERROR_INVALID_DATA;
        return result;
    }
    struct Process {
        HANDLE handle;
        ~Process() { if (handle) CloseHandle(handle); }
    } process{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid)};
    if (!process.handle) { result.error = GetLastError(); return result; }
    FILETIME creation{}, exit{}, kernel{}, user{};
    if (!GetProcessTimes(process.handle, &creation, &exit, &kernel, &user)) {
        result.status = "process_times_failed";
        result.error = GetLastError();
        return result;
    }
    result.creation = filetime(creation);
    std::vector<wchar_t> path(32768);
    DWORD length = static_cast<DWORD>(path.size());
    if (!QueryFullProcessImageNameW(process.handle, 0, path.data(), &length)) {
        result.status = "query_path_failed";
        result.error = GetLastError();
        return result;
    }
    const auto utf8_length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, path.data(),
        static_cast<int>(length), nullptr, 0, nullptr, nullptr);
    if (!utf8_length) { result.status = "utf8_failed"; result.error = GetLastError(); return result; }
    result.path.resize(static_cast<size_t>(utf8_length));
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, path.data(), static_cast<int>(length),
        result.path.data(), utf8_length, nullptr, nullptr) != utf8_length) {
        result.path.clear();
        result.status = "utf8_failed";
        result.error = GetLastError();
        return result;
    }
    const auto guard = creation_guard(static_cast<int64_t>(*result.creation), *result.event_time);
    if (guard != CreationGuard::Compatible) {
        result.status = guard == CreationGuard::Newer ? "pid_reused" : "creation_time_uncertain";
        result.error = guard == CreationGuard::Newer ? ERROR_INVALID_DATA : ERROR_RETRY;
        return result;
    }
    result.status = "ok";
    result.valid = !result.path.empty();
    return result;
}

static const char* event_name(unsigned event) {
    switch (event) {
    case WINDIVERT_EVENT_SOCKET_BIND: return "bind";
    case WINDIVERT_EVENT_SOCKET_CONNECT: return "connect";
    case WINDIVERT_EVENT_SOCKET_LISTEN: return "listen";
    case WINDIVERT_EVENT_SOCKET_ACCEPT: return "accept";
    case WINDIVERT_EVENT_SOCKET_CLOSE: return "close";
    default: return "other";
    }
}

static std::string socket_address(const UINT32* address) {
    char buffer[64]{};
    if (!WinDivertHelperFormatIPv6Address(address, buffer, sizeof(buffer)))
        throw std::runtime_error("Cannot format socket address");
    return buffer;
}

static std::string ipv4_address(uint32_t address) {
    char buffer[32]{};
    if (!WinDivertHelperFormatIPv4Address(address, buffer, sizeof(buffer)))
        throw std::runtime_error("Cannot format packet address");
    return buffer;
}

static int windows_self_test() {
    self_test();
    const UINT32 mapped[]{0xCB007109u, 0x0000FFFFu, 0, 0};
    if (socket_address(mapped) != "203.0.113.9" || ipv4_address(mapped[0]) != "203.0.113.9")
        throw std::runtime_error("WinDivert DLL address normalization");
    WINDIVERT_ADDRESS address{};
    address.Layer = WINDIVERT_LAYER_SOCKET;
    address.Event = WINDIVERT_EVENT_SOCKET_CONNECT;
    address.Socket.Protocol = IPPROTO_TCP;
    address.Socket.LocalAddr[0] = 0xC0000202u;
    address.Socket.LocalAddr[1] = 0x0000FFFFu;
    address.Socket.RemoteAddr[0] = mapped[0];
    address.Socket.RemoteAddr[1] = mapped[1];
    address.Socket.LocalPort = 40001;
    address.Socket.RemotePort = 443;
    const auto scope = socket_filter_expression(SocketFilter::Scoped, "203.0.113.9", 443, IPPROTO_TCP);
    const auto connect = socket_filter_expression(SocketFilter::Connect, "203.0.113.9", 443, IPPROTO_TCP);
    if (!WinDivertHelperEvalFilter(scope.c_str(), nullptr, 0, &address) ||
        !WinDivertHelperEvalFilter(connect.c_str(), nullptr, 0, &address))
        throw std::runtime_error("WinDivert DLL socket filters match documented tuple fields");
    if (WinDivertHelperEvalFilter(("ip and " + scope).c_str(), nullptr, 0, &address) || GetLastError() != ERROR_SUCCESS)
        throw std::runtime_error("WinDivert 2.2.2 SOCKET ip predicate requires a packet header");
    return 0;
}

class Probe {
    Options config;
    Output& output;
    HANDLE socket_handle = INVALID_HANDLE_VALUE, network_handle = INVALID_HANDLE_VALUE;
    std::thread socket_receiver, network_receiver;
    std::atomic<bool> stopping{false}, socket_abort{false}, network_abort{false};
    std::atomic<bool> socket_done{true}, network_done{true};
    std::atomic<unsigned> started{0};
    std::atomic<uint64_t> errors{0}, socket_received{0}, socket_relevant{0};
    std::atomic<uint64_t> socket_protocol_matches{0}, socket_ipv4_matches{0}, socket_ipv4_mapped_matches{0};
    std::atomic<uint64_t> socket_remote_address_matches{0}, socket_remote_port_matches{0}, socket_scope_matches{0};
    std::atomic<uint64_t> socket_unrelated_discarded{0};
    std::atomic<uint64_t> network_received{0}, network_relevant{0}, lookup_failures{0};
    int64_t frequency = 0;
    bool stopped = false;

    void error(const char* operation, DWORD code) {
        ++errors;
        output.push("{\"kind\":\"error\",\"source\":\"socket_probe\",\"operation\":" + json(operation) +
            ",\"code\":" + std::to_string(code) + ",\"recv_qpc\":" + std::to_string(qpc()) + "}");
    }

    bool configure(HANDLE handle) {
        for (const auto parameter : {WINDIVERT_PARAM_QUEUE_LENGTH, WINDIVERT_PARAM_QUEUE_SIZE, WINDIVERT_PARAM_QUEUE_TIME}) {
            const UINT64 value = parameter == WINDIVERT_PARAM_QUEUE_LENGTH ? 16384 :
                parameter == WINDIVERT_PARAM_QUEUE_SIZE ? 33554432 : 2000;
            if (!WinDivertSetParam(handle, parameter, value)) {
                error("WinDivertSetParam", GetLastError());
                return false;
            }
        }
        return true;
    }

    void receive_socket() {
        ++started;
        for (;;) {
            if (socket_abort) break;
            WINDIVERT_ADDRESS address{};
            const BOOL received = WinDivertRecv(socket_handle, nullptr, 0, nullptr, &address);
            const DWORD code = received ? ERROR_SUCCESS : GetLastError();
            const auto received_qpc = qpc();
            if (!received) {
                if (!(stopping && code == ERROR_NO_DATA) && !(socket_abort && code == ERROR_OPERATION_ABORTED))
                    error("WinDivertRecv_socket", code);
                break;
            }
            ++socket_received;
            if (address.Layer != WINDIVERT_LAYER_SOCKET) { error("socket_layer", ERROR_INVALID_DATA); continue; }
            const auto& socket = address.Socket;
            const auto local = mapped_ipv4({socket.LocalAddr[0], socket.LocalAddr[1], socket.LocalAddr[2], socket.LocalAddr[3]});
            const auto remote = mapped_ipv4({socket.RemoteAddr[0], socket.RemoteAddr[1], socket.RemoteAddr[2], socket.RemoteAddr[3]});
            const Tuple tuple{local.value_or(0), remote.value_or(0), socket.LocalPort, socket.RemotePort, socket.Protocol};
            const bool ipv4_match = !address.IPv6;
            const bool protocol_match = socket.Protocol == config.protocol;
            const bool address_match = remote && *remote == config.target_address;
            const bool port_match = socket.RemotePort == config.port;
            if (ipv4_match) ++socket_ipv4_matches;
            if (local && remote) ++socket_ipv4_mapped_matches;
            if (protocol_match) ++socket_protocol_matches;
            if (address_match) ++socket_remote_address_matches;
            if (port_match) ++socket_remote_port_matches;
            if (ipv4_match && protocol_match && address_match && port_match) ++socket_scope_matches;
            const bool relevant = connect_eligible(address.Event, address.IPv6 != 0, tuple,
                config.target_address, config.port, config.protocol);
            if (relevant) ++socket_relevant;
            if (!socket_record_allowed(config.socket_filter, relevant)) { ++socket_unrelated_discarded; continue; }
            const auto identity = process_identity(socket.ProcessId, address.Timestamp, frequency);
            const auto app_ready = qpc();
            if (!identity.valid) ++lookup_failures;
            std::ostringstream line;
            line << "{\"kind\":\"socket_event\",\"source\":\"socket_probe\",\"event\":" << address.Event
                << ",\"event_name\":" << json(event_name(address.Event))
                << ",\"event_qpc\":" << address.Timestamp << ",\"recv_qpc\":" << received_qpc
                << ",\"app_ready_qpc\":" << app_ready << ",\"pid\":" << socket.ProcessId
                << ",\"endpoint_id\":" << socket.EndpointId << ",\"parent_endpoint_id\":" << socket.ParentEndpointId
                << ",\"local_ip\":" << json(socket_address(socket.LocalAddr)) << ",\"local_port\":" << socket.LocalPort
                << ",\"remote_ip\":" << json(socket_address(socket.RemoteAddr)) << ",\"remote_port\":" << socket.RemotePort
                << ",\"protocol\":" << unsigned(socket.Protocol) << ",\"ipv6\":" << (address.IPv6 ? "true" : "false")
                << ",\"outbound\":" << (address.Outbound ? "true" : "false")
                << ",\"connect_eligible\":" << (relevant ? "true" : "false")
                << ",\"app_path\":" << json(identity.path) << ",\"app_path_status\":" << json(identity.status)
                << ",\"identity_valid\":" << (identity.valid ? "true" : "false")
                << ",\"lookup_error\":" << identity.error << ",\"process_creation_filetime\":"
                << (identity.creation ? std::to_string(*identity.creation) : "null")
                << ",\"event_filetime_lower\":" << (identity.event_time ? std::to_string(identity.event_time->lower) : "null")
                << ",\"event_filetime_upper\":" << (identity.event_time ? std::to_string(identity.event_time->upper) : "null") << "}";
            output.push(line.str());
        }
    }

    void receive_network() {
        std::vector<unsigned char> bytes(65535);
        ++started;
        for (;;) {
            if (network_abort) break;
            WINDIVERT_ADDRESS address{};
            UINT length = 0;
            const BOOL received = WinDivertRecv(network_handle, bytes.data(), static_cast<UINT>(bytes.size()), &length, &address);
            const DWORD code = received ? ERROR_SUCCESS : GetLastError();
            const auto received_qpc = qpc();
            if (!received) {
                if (!(stopping && code == ERROR_NO_DATA) && !(network_abort && code == ERROR_OPERATION_ABORTED))
                    error("WinDivertRecv_network", code);
                break;
            }
            ++network_received;
            PWINDIVERT_IPHDR ip = nullptr;
            PWINDIVERT_TCPHDR tcp = nullptr;
            PWINDIVERT_UDPHDR udp = nullptr;
            UINT8 protocol = 0;
            if (address.Layer != WINDIVERT_LAYER_NETWORK ||
                !WinDivertHelperParsePacket(bytes.data(), length, &ip, nullptr, &protocol,
                    nullptr, nullptr, &tcp, &udp, nullptr, nullptr, nullptr, nullptr) || !ip || (!tcp && !udp)) {
                error("network_parse", ERROR_INVALID_DATA);
                continue;
            }
            const Tuple tuple{wire_ipv4(reinterpret_cast<const unsigned char*>(&ip->SrcAddr)),
                wire_ipv4(reinterpret_cast<const unsigned char*>(&ip->DstAddr)),
                ntohs(tcp ? tcp->SrcPort : udp->SrcPort), ntohs(tcp ? tcp->DstPort : udp->DstPort), protocol};
            const bool relevant = !address.IPv6 && address.Outbound && tuple.local && tuple.local_port &&
                tuple.remote == config.target_address && tuple.remote_port == config.port && tuple.protocol == config.protocol &&
                ((tcp && tcp->Syn && !tcp->Ack) || (udp && protocol == IPPROTO_UDP));
            if (!relevant) continue;
            ++network_relevant;
            std::ostringstream line;
            line << "{\"kind\":\"packet\",\"source\":\"socket_probe\",\"capture_qpc\":" << address.Timestamp
                << ",\"event_qpc\":" << address.Timestamp << ",\"recv_qpc\":" << received_qpc
                << ",\"local_ip\":" << json(ipv4_address(tuple.local)) << ",\"local_port\":" << tuple.local_port
                << ",\"remote_ip\":" << json(ipv4_address(tuple.remote)) << ",\"remote_port\":" << tuple.remote_port
                << ",\"protocol\":" << unsigned(tuple.protocol) << ",\"ipv6\":false,\"outbound\":true"
                << ",\"tcp_syn\":" << (tcp && tcp->Syn ? "true" : "false")
                << ",\"tcp_ack\":" << (tcp && tcp->Ack ? "true" : "false")
                << ",\"tcp_fin\":" << (tcp && tcp->Fin ? "true" : "false")
                << ",\"tcp_rst\":" << (tcp && tcp->Rst ? "true" : "false")
                << ",\"udp\":" << (udp ? "true" : "false") << ",\"packet_bytes\":" << length << "}";
            output.push(line.str());
        }
    }

    void stop() {
        if (stopped) return;
        stopped = true;
        stopping = true;
        if (socket_handle != INVALID_HANDLE_VALUE && !WinDivertShutdown(socket_handle, WINDIVERT_SHUTDOWN_RECV)) {
            error("WinDivertShutdown_socket", GetLastError());
            socket_abort = true;
        }
        if (network_handle != INVALID_HANDLE_VALUE && !WinDivertShutdown(network_handle, WINDIVERT_SHUTDOWN_RECV)) {
            error("WinDivertShutdown_network", GetLastError());
            network_abort = true;
        }
        while (!socket_done || !network_done) {
            if (socket_abort && !socket_done && socket_receiver.joinable())
                CancelSynchronousIo(static_cast<HANDLE>(socket_receiver.native_handle()));
            if (network_abort && !network_done && network_receiver.joinable())
                CancelSynchronousIo(static_cast<HANDLE>(network_receiver.native_handle()));
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        if (socket_receiver.joinable()) socket_receiver.join();
        if (network_receiver.joinable()) network_receiver.join();
        if (socket_handle != INVALID_HANDLE_VALUE && !WinDivertClose(socket_handle)) error("WinDivertClose_socket", GetLastError());
        if (network_handle != INVALID_HANDLE_VALUE && !WinDivertClose(network_handle)) error("WinDivertClose_network", GetLastError());
        socket_handle = network_handle = INVALID_HANDLE_VALUE;
    }

public:
    Probe(Options value, Output& target) : config(std::move(value)), output(target) {}

    int run() {
        try {
            LARGE_INTEGER value{};
            if (!QueryPerformanceFrequency(&value) || value.QuadPart <= 0) throw std::runtime_error("QPC frequency");
            frequency = value.QuadPart;
            const auto scope = socket_filter_expression(SocketFilter::Scoped, config.target, config.port, config.protocol);
            const auto socket_filter = socket_filter_expression(config.socket_filter, config.target, config.port, config.protocol);
            const std::string network_filter = "outbound and ip and " + scope +
                (config.protocol == IPPROTO_TCP ? " and tcp.Syn and !tcp.Ack" : " and udp");
            const UINT64 flags = WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY;
            socket_handle = WinDivertOpen(socket_filter.c_str(), WINDIVERT_LAYER_SOCKET, 0, flags);
            if (socket_handle == INVALID_HANDLE_VALUE) { error("WinDivertOpen_socket", GetLastError()); throw std::runtime_error("Socket open"); }
            network_handle = WinDivertOpen(network_filter.c_str(), WINDIVERT_LAYER_NETWORK, 0, flags);
            if (network_handle == INVALID_HANDLE_VALUE) { error("WinDivertOpen_network", GetLastError()); throw std::runtime_error("Network open"); }
            if (!configure(socket_handle) || !configure(network_handle)) throw std::runtime_error("Queue setup");
            socket_receiver = std::thread([this] {
                socket_done = false;
                try { receive_socket(); } catch (...) { error("socket_receiver_exception", ERROR_INVALID_DATA); }
                socket_done = true;
            });
            network_receiver = std::thread([this] {
                network_done = false;
                try { receive_network(); } catch (...) { error("network_receiver_exception", ERROR_INVALID_DATA); }
                network_done = true;
            });
            const auto start_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
            while (started < 2 && !errors && std::chrono::steady_clock::now() < start_deadline)
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            if (started != 2 || errors) throw std::runtime_error("Receiver startup");
            output.push("{\"kind\":\"ready\",\"source\":\"socket_probe\",\"qpc_frequency\":" + std::to_string(frequency) +
                ",\"recv_qpc\":" + std::to_string(qpc()) + ",\"socket_ready\":true,\"network_ready\":true"
                ",\"capture_only\":true,\"routing_authority\":false,\"driver_queue_loss_known\":false"
                ",\"socket_filter\":" + json(socket_filter_name(config.socket_filter)) +
                ",\"time_mapping\":\"per_lookup_qpc_filetime_bracket\",\"socket_outbound_authority\":\"connect_event\"}");
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(config.seconds);
            while (!errors && !output.failed() && std::chrono::steady_clock::now() < deadline) {
                if (!config.stop_file.empty() && GetFileAttributesA(config.stop_file.c_str()) != INVALID_FILE_ATTRIBUTES) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        } catch (...) { error("probe_exception", ERROR_GEN_FAILURE); }
        stop();
        output.finish();
        const bool success = !errors && !output.failed();
        std::ostringstream summary;
        summary << "{\"kind\":\"summary\",\"source\":\"socket_probe\",\"success\":" << (success ? "true" : "false")
            << ",\"capture_only\":true,\"routing_authority\":false,\"driver_queue_loss_known\":false"
            << ",\"socket_filter\":" << json(socket_filter_name(config.socket_filter))
            << ",\"errors\":" << errors.load() << ",\"queue_dropped\":" << output.queue_dropped.load()
            << ",\"budget_dropped\":" << output.budget_dropped.load() << ",\"output_errors\":" << output.output_errors.load()
            << ",\"truncated\":" << (output.truncated ? "true" : "false")
            << ",\"socket_received\":" << socket_received.load() << ",\"socket_relevant\":" << socket_relevant.load()
            << ",\"socket_protocol_matches\":" << socket_protocol_matches.load()
            << ",\"socket_ipv4_matches\":" << socket_ipv4_matches.load()
            << ",\"socket_ipv4_mapped_matches\":" << socket_ipv4_mapped_matches.load()
            << ",\"socket_remote_address_matches\":" << socket_remote_address_matches.load()
            << ",\"socket_remote_port_matches\":" << socket_remote_port_matches.load()
            << ",\"socket_scope_matches\":" << socket_scope_matches.load()
            << ",\"socket_unrelated_discarded\":" << socket_unrelated_discarded.load()
            << ",\"network_received\":" << network_received.load() << ",\"network_relevant\":" << network_relevant.load()
            << ",\"lookup_failures\":" << lookup_failures.load() << ",\"records_written\":" << output.records_written.load() << "}";
        const bool written = output.summary(summary.str());
        return success && written ? 0 : 2;
    }

    ~Probe() { try { stop(); } catch (...) {} }
};

}

int main(int argc, char** argv) {
    try {
        if (argc == 2 && std::string(argv[1]) == "--self-test") return socket_probe::windows_self_test();
        auto config = socket_probe::options(argc, argv);
        socket_probe::Output output(config.output);
        socket_probe::Probe probe(std::move(config), output);
        return probe.run();
    } catch (...) { return 2; }
}
#endif
