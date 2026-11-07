#include <algorithm>
#include <cmath>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace inproc {

enum class MatchOutcome { NoEvent, Matched, Ambiguous };

struct EventRef {
    int64_t event_filetime = 0;
    uint32_t layer_id = 0;
    bool outbound = false;
    bool tuple_match = false;
    std::string app_path;
    uint32_t ip_version = 0;
    uint32_t raw_local_addr = 0;
    uint32_t raw_remote_addr = 0;
    uint16_t match_local_port = 0;
    uint16_t match_remote_port = 0;
    uint8_t match_protocol = 0;
};

struct MatchConfig {
    int64_t window_before = 5'000'000;
    int64_t window_after = 500'000;
    uint32_t ale_connect_v4 = 48;
    uint32_t ale_connect_v6 = 50;
};

struct MatchResult {
    MatchOutcome outcome = MatchOutcome::NoEvent;
    std::string app_path;
    int64_t event_filetime = 0;
};

static bool qualifies(const EventRef& event, int64_t capture, const MatchConfig& config) {
    return event.tuple_match && event.outbound &&
        (event.layer_id == config.ale_connect_v4 || event.layer_id == config.ale_connect_v6) &&
        event.event_filetime >= capture - config.window_before &&
        event.event_filetime <= capture + config.window_after;
}

MatchResult match_generation(const std::vector<EventRef>& events, int64_t capture,
                             const MatchConfig& config) {
    MatchResult result;
    std::set<std::string> apps;
    const EventRef* newest = nullptr;
    for (const auto& event : events) {
        if (!qualifies(event, capture, config)) continue;
        apps.insert(event.app_path);
        if (!newest || event.event_filetime > newest->event_filetime) newest = &event;
    }
    if (!newest) return result;
    if (apps.size() != 1) {
        result.outcome = MatchOutcome::Ambiguous;
        return result;
    }
    result.outcome = MatchOutcome::Matched;
    result.app_path = newest->app_path;
    result.event_filetime = newest->event_filetime;
    return result;
}

std::vector<uint16_t> pending_ports(const std::vector<uint16_t>& ports) {
    std::set<uint16_t> unique(ports.begin(), ports.end());
    return {unique.begin(), unique.end()};
}

struct Window {
    int64_t start;
    int64_t end;
};

Window lookup_window(const std::vector<int64_t>& captures, int64_t now, int64_t lookback) {
    int64_t earliest = now;
    for (int64_t capture : captures) earliest = std::min(earliest, capture);
    return {earliest - lookback, now};
}

std::vector<int> backoff_schedule(int64_t remaining_ms, int cap_ms) {
    std::vector<int> schedule;
    int wait = 0;
    int64_t elapsed = 0;
    while (elapsed < remaining_ms) {
        schedule.push_back(wait);
        const int next = wait == 0 ? 1 : std::min(wait * 2, cap_ms);
        elapsed += next;
        wait = next;
    }
    return schedule;
}

struct Distribution {
    size_t count = 0;
    double p50 = 0, p95 = 0, max = 0;
};

static double percentile(const std::vector<double>& sorted, double fraction) {
    if (sorted.empty()) return 0;
    const auto rank = static_cast<int64_t>(std::ceil(static_cast<double>(sorted.size()) * fraction)) - 1;
    const size_t index = rank < 0 ? 0 : std::min(static_cast<size_t>(rank), sorted.size() - 1);
    return sorted[index];
}

Distribution distribution(std::vector<double> values) {
    Distribution result;
    if (values.empty()) return result;
    std::sort(values.begin(), values.end());
    result.count = values.size();
    result.p50 = percentile(values, 0.5);
    result.p95 = percentile(values, 0.95);
    result.max = values.back();
    return result;
}

}  // namespace inproc

#if !defined(_WIN32) || defined(INPROC_TEST)
#include <cassert>
#include <iostream>

static inproc::EventRef event_a(int64_t when, uint32_t layer = 48,
                                 const std::string& app = "\\device\\lab\\app-a.exe") {
    inproc::EventRef event;
    event.event_filetime = when;
    event.layer_id = layer;
    event.outbound = true;
    event.tuple_match = true;
    event.app_path = app;
    return event;
}

int inproc_self_test() {
    using namespace inproc;
    MatchConfig config;
    config.window_before = 5'000'000;
    config.window_after = 500'000;

    const int64_t capture = 100'000'000;

    assert(match_generation({}, capture, config).outcome == MatchOutcome::NoEvent);

    auto exact = match_generation({event_a(capture - 1'000)}, capture, config);
    assert(exact.outcome == MatchOutcome::Matched);
    assert(exact.app_path == "\\device\\lab\\app-a.exe");

    EventRef inbound = event_a(capture);
    inbound.outbound = false;
    assert(match_generation({inbound}, capture, config).outcome == MatchOutcome::NoEvent);

    EventRef wrong_tuple = event_a(capture);
    wrong_tuple.tuple_match = false;
    assert(match_generation({wrong_tuple}, capture, config).outcome == MatchOutcome::NoEvent);

    assert(match_generation({event_a(capture, 44)}, capture, config).outcome == MatchOutcome::NoEvent);
    assert(match_generation({event_a(capture, 50)}, capture, config).outcome == MatchOutcome::Matched);

    assert(match_generation({event_a(capture - 6'000'000)}, capture, config).outcome == MatchOutcome::NoEvent);
    assert(match_generation({event_a(capture + 600'000)}, capture, config).outcome == MatchOutcome::NoEvent);
    assert(match_generation({event_a(capture + 400'000)}, capture, config).outcome == MatchOutcome::Matched);

    auto two_apps = match_generation(
        {event_a(capture - 1000), event_a(capture - 2000, 48, "\\device\\lab\\app-b.exe")}, capture, config);
    assert(two_apps.outcome == MatchOutcome::Ambiguous);
    assert(two_apps.app_path.empty());

    auto reused = match_generation(
        {event_a(capture - 4'000'000), event_a(capture - 1000), event_a(capture - 2'000'000)}, capture, config);
    assert(reused.outcome == MatchOutcome::Matched);
    assert(reused.event_filetime == capture - 1000);

    assert((pending_ports({40000, 40000, 40001, 39999}) == std::vector<uint16_t>{39999, 40000, 40001}));

    auto window = lookup_window({capture, capture - 3'000'000, capture - 1'000'000}, capture + 10'000, 5'000'000);
    assert(window.start == capture - 3'000'000 - 5'000'000);
    assert(window.end == capture + 10'000);

    assert((backoff_schedule(0, 8) == std::vector<int>{}));
    assert((backoff_schedule(1, 8) == std::vector<int>{0}));
    assert((backoff_schedule(16, 8) == std::vector<int>{0, 1, 2, 4, 8}));

    assert(distribution({}).count == 0);
    auto spread = distribution({5, 1, 4, 2, 3});
    assert(spread.count == 5);
    assert(spread.p50 == 3);
    assert(spread.p95 == 5);
    assert(spread.max == 5);

    std::cout << "inproc engine helper self-tests passed\n";
    return 0;
}

#ifndef _WIN32
int main() { return inproc_self_test(); }
#endif
#endif

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000006
#endif
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <initguid.h>
#include <fwpmu.h>
#include "windivert.h"
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <thread>
#include <tuple>

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")

#ifndef CREATE_WAITABLE_TIMER_HIGH_RESOLUTION
#define CREATE_WAITABLE_TIMER_HIGH_RESOLUTION 0x00000002
#endif

namespace {

constexpr uint32_t ALE_AUTH_CONNECT_V4 = 48;
constexpr uint32_t ALE_AUTH_CONNECT_V6 = 50;

int64_t qpc() {
    LARGE_INTEGER value;
    QueryPerformanceCounter(&value);
    return value.QuadPart;
}

int64_t qpf() {
    LARGE_INTEGER value;
    QueryPerformanceFrequency(&value);
    return value.QuadPart;
}

uint64_t filetime(FILETIME value) {
    return (static_cast<uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
}

uint64_t utc_now() {
    FILETIME value{};
    GetSystemTimePreciseAsFileTime(&value);
    return filetime(value);
}

FILETIME to_filetime(uint64_t value) {
    FILETIME result{};
    result.dwLowDateTime = static_cast<DWORD>(value);
    result.dwHighDateTime = static_cast<DWORD>(value >> 32);
    return result;
}

std::string json(const std::string& value) {
    const char* digits = "0123456789abcdef";
    std::string result = "\"";
    for (unsigned char c : value) {
        switch (c) {
        case '"': result += "\\\""; break;
        case '\\': result += "\\\\"; break;
        case '\n': result += "\\n"; break;
        case '\r': result += "\\r"; break;
        case '\t': result += "\\t"; break;
        default:
            if (c < 32) { result += "\\u00"; result += digits[c >> 4]; result += digits[c & 15]; }
            else result += static_cast<char>(c);
        }
    }
    return result + '"';
}

std::string ip(uint32_t address) {
    char buffer[INET_ADDRSTRLEN]{};
    IN_ADDR value;
    value.s_addr = address;
    if (!InetNtopA(AF_INET, &value, buffer, sizeof(buffer))) return "invalid";
    return buffer;
}

uint32_t parse_ip(const std::string& text) {
    IN_ADDR value;
    if (InetPtonA(AF_INET, text.c_str(), &value) != 1)
        throw std::runtime_error("IPv4 literal required: " + text);
    return value.s_addr;
}

std::string lower(std::string value) {
    for (char& c : value) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return value;
}

std::string blob_path(const FWP_BYTE_BLOB& blob) {
    if (!blob.data || blob.size % sizeof(wchar_t)) return {};
    std::vector<wchar_t> text(blob.size / sizeof(wchar_t));
    std::memcpy(text.data(), blob.data, blob.size);
    while (!text.empty() && text.back() == L'\0') text.pop_back();
    if (text.empty()) return {};
    int count = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (count <= 0) return {};
    std::string result(static_cast<size_t>(count), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), count, nullptr, nullptr);
    return result;
}

struct Tuple {
    uint32_t local, remote;
    uint16_t local_port, remote_port;
    uint8_t protocol;
    bool operator<(const Tuple& rhs) const {
        return std::tie(local, local_port, remote, remote_port, protocol) <
               std::tie(rhs.local, rhs.local_port, rhs.remote, rhs.remote_port, rhs.protocol);
    }
    bool operator==(const Tuple& rhs) const {
        return local == rhs.local && remote == rhs.remote && local_port == rhs.local_port &&
               remote_port == rhs.remote_port && protocol == rhs.protocol;
    }
};

std::string fields(const Tuple& tuple) {
    std::ostringstream out;
    out << "\"local_ip\":\"" << ip(tuple.local) << "\",\"local_port\":" << tuple.local_port
        << ",\"remote_ip\":\"" << ip(tuple.remote) << "\",\"remote_port\":" << tuple.remote_port
        << ",\"protocol\":" << unsigned(tuple.protocol);
    return out.str();
}

struct Packet {
    std::vector<unsigned char> bytes;
    WINDIVERT_ADDRESS address{};
    int64_t received = 0;
};

struct Parsed {
    PWINDIVERT_IPHDR ip_header = nullptr;
    PWINDIVERT_TCPHDR tcp = nullptr;
    PWINDIVERT_UDPHDR udp = nullptr;
    Tuple tuple{};
    bool valid = false;
    explicit Parsed(Packet& packet) {
        UINT8 protocol = 0;
        if (!WinDivertHelperParsePacket(packet.bytes.data(), static_cast<UINT>(packet.bytes.size()),
            &ip_header, nullptr, &protocol, nullptr, nullptr, &tcp, &udp, nullptr, nullptr,
            nullptr, nullptr) || !ip_header || (!tcp && !udp)) return;
        tuple.local = ip_header->SrcAddr;
        tuple.remote = ip_header->DstAddr;
        tuple.local_port = ntohs(tcp ? tcp->SrcPort : udp->SrcPort);
        tuple.remote_port = ntohs(tcp ? tcp->DstPort : udp->DstPort);
        tuple.protocol = protocol;
        valid = true;
    }
};

class Log {
    std::ofstream output;
    std::mutex mutex;
public:
    explicit Log(const std::string& path) : output(path, std::ios::trunc) {
        if (!output) throw std::runtime_error("cannot create inproc log");
    }
    void write(const std::string& line) {
        std::lock_guard<std::mutex> lock(mutex);
        output << line << '\n';
        output.flush();
    }
};

struct Options {
    std::string target;
    std::string output;
    std::string summary;
    std::string selected_app;
    std::string stop_file;
    std::string state_out;
    std::string mode = "hold";
    uint16_t port = 0;
    uint16_t udp_port = 0;
    uint16_t quic_port = 443;
    uint16_t listener_port = 0;
    int seconds = 35;
    int hold_ms = 1000;
    int window_before_ms = 500;
    int window_after_ms = 50;
    int leak_ms = 2000;
    bool send_rst = false;
};

unsigned number(const std::string& value, unsigned min, unsigned max) {
    size_t count = 0;
    unsigned long result = std::stoul(value, &count);
    if (count != value.size() || result < min || result > max)
        throw std::runtime_error("numeric option out of range");
    return static_cast<unsigned>(result);
}

Options options(int argc, char** argv) {
    Options result;
    for (int i = 1; i < argc; i += 2) {
        if (i + 1 == argc) throw std::runtime_error("missing option value");
        std::string key = argv[i], value = argv[i + 1];
        if (key == "--target") { parse_ip(value); result.target = value; }
        else if (key == "--port") result.port = static_cast<uint16_t>(number(value, 1, 65535));
        else if (key == "--udp-port") result.udp_port = static_cast<uint16_t>(number(value, 1, 65535));
        else if (key == "--quic-port") result.quic_port = static_cast<uint16_t>(number(value, 1, 65535));
        else if (key == "--listener-port") result.listener_port = static_cast<uint16_t>(number(value, 1, 65535));
        else if (key == "--mode") result.mode = value;
        else if (key == "--selected-app") result.selected_app = value;
        else if (key == "--seconds") result.seconds = static_cast<int>(number(value, 1, 600));
        else if (key == "--hold-ms") result.hold_ms = static_cast<int>(number(value, 1, 10000));
        else if (key == "--window-before-ms") result.window_before_ms = static_cast<int>(number(value, 0, 10000));
        else if (key == "--window-after-ms") result.window_after_ms = static_cast<int>(number(value, 0, 10000));
        else if (key == "--leak-ms") result.leak_ms = static_cast<int>(number(value, 0, 10000));
        else if (key == "--send-rst") result.send_rst = number(value, 0, 1) != 0;
        else if (key == "--out") result.output = value;
        else if (key == "--summary") result.summary = value;
        else if (key == "--stop-file") result.stop_file = value;
        else if (key == "--state-out") result.state_out = value;
        else throw std::runtime_error("unknown option: " + key);
    }
    if (result.target.empty() || !result.port || result.output.empty() || result.summary.empty())
        throw std::runtime_error("required: --target IPv4 --port N --out PATH --summary PATH");
    if (result.mode != "hold" && result.mode != "redirect")
        throw std::runtime_error("mode must be hold or redirect");
    if (result.mode == "redirect" && !result.listener_port)
        throw std::runtime_error("redirect mode requires --listener-port");
    if (result.listener_port == result.port)
        throw std::runtime_error("listener and controlled target ports must differ");
    return result;
}

struct Bfe {
    HANDLE engine = nullptr;
    UINT32 old_collect = 0, old_keywords = 0;
    bool collect_changed = false, keywords_changed = false;

    static void check(DWORD result, const char* operation) {
        if (result != ERROR_SUCCESS) throw std::runtime_error(std::string(operation) + ": " + std::to_string(result));
    }
    UINT32 get(FWPM_ENGINE_OPTION option) {
        FWP_VALUE0* value = nullptr;
        check(FwpmEngineGetOption0(engine, option, &value), "FwpmEngineGetOption0");
        if (!value) throw std::runtime_error("Null engine option");
        const bool valid = value->type == FWP_UINT32;
        const UINT32 result = value->uint32;
        FwpmFreeMemory0(reinterpret_cast<void**>(&value));
        if (!valid) throw std::runtime_error("Engine option is not UINT32");
        return result;
    }
    DWORD set(FWPM_ENGINE_OPTION option, UINT32 value_number) {
        FWP_VALUE0 value{}; value.type = FWP_UINT32; value.uint32 = value_number;
        return FwpmEngineSetOption0(engine, option, &value);
    }
    void start(const std::string& state_path) {
        check(FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &engine), "FwpmEngineOpen0");
        old_collect = get(FWPM_ENGINE_COLLECT_NET_EVENTS);
        old_keywords = get(FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS);
        if (!state_path.empty()) {
            std::ofstream backup(state_path, std::ios::binary | std::ios::trunc);
            backup << "{\"version\":1,\"old_collect\":" << old_collect
                   << ",\"old_keywords\":" << old_keywords << "}\n";
            backup.flush();
            if (!backup) throw std::runtime_error("Cannot persist BFE state before mutation");
        }
        if (old_collect != 1) {
            check(set(FWPM_ENGINE_COLLECT_NET_EVENTS, 1), "Set COLLECT_NET_EVENTS");
            collect_changed = true;
        }
        if (!(old_keywords & FWPM_NET_EVENT_KEYWORD_CLASSIFY_ALLOW)) {
            check(set(FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS,
                      old_keywords | FWPM_NET_EVENT_KEYWORD_CLASSIFY_ALLOW), "Set CLASSIFY_ALLOW keyword");
            keywords_changed = true;
        }
    }
    void restore(FWPM_ENGINE_OPTION option, UINT32 previous, const char* operation) noexcept {
        try {
            if (get(option) == previous) return;
            const auto result = set(option, previous);
            if (result) std::cerr << operation << " failed: " << result << '\n';
        } catch (...) { std::cerr << operation << " failed\n"; }
    }
    ~Bfe() {
        if (!engine) return;
        if (keywords_changed) restore(FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS, old_keywords, "Restore MATCH_ANY_KEYWORDS");
        if (collect_changed) restore(FWPM_ENGINE_COLLECT_NET_EVENTS, old_collect, "Restore COLLECT_NET_EVENTS");
        FwpmEngineClose0(engine);
    }
};

struct Lookup {
    std::string filter;
    unsigned calls = 0;
    std::vector<double> durations_ms;
};

struct Flow {
    int64_t generation = 0;
    int64_t capture_qpc = 0;
    uint64_t capture_filetime = 0;
    int64_t deadline_qpc = 0;
    uint8_t protocol = 6;
    bool outbound_loopback = false;
    std::string action = "pending";
    int64_t next_retry_qpc = 0;
    int backoff_ms = 0;
    bool saw_syn = false;
    uint32_t syn_sequence = 0;
    uint32_t last_seq = 0;
    uint32_t last_ack = 0;
    unsigned lookup_calls = 0;
    SOCKET reservation = INVALID_SOCKET;
    uint16_t alias = 0;
    bool leak_selected = false;
    bool rst_sent = false;
    std::deque<Packet> held;
    ~Flow() { if (reservation != INVALID_SOCKET) closesocket(reservation); }
};

class Engine {
    Options config;
    Log log;
    std::ofstream summary_file;
    uint32_t target = 0;
    int64_t frequency = 0;
    int64_t anchor_qpc = 0;
    uint64_t anchor_filetime = 0;
    std::string selected_app;

    HANDLE divert = INVALID_HANDLE_VALUE;
    HANDLE session = nullptr;
    Bfe bfe;

    std::atomic<bool> stopping{false};
    std::atomic<DWORD> receive_error{0};
    std::atomic<bool> fatal_send{false};
    std::thread receiver;
    std::mutex mutex;
    std::condition_variable wake;
    std::deque<Packet> input;

    std::map<Tuple, std::unique_ptr<Flow>> flows;
    std::map<std::pair<uint32_t, uint16_t>, Tuple> aliases;

    Lookup lookup;
    std::vector<double> decision_latency_ms;
    std::vector<double> added_held_ms, added_direct_ms, added_proxy_ms;
    std::vector<double> lookups_per_flow;
    unsigned unattributed = 0, leaked = 0, rst_count = 0, quic_drops = 0;
    unsigned decided_proxy = 0, decided_direct = 0;
    bool reuse_disrupted = false;
    std::deque<std::pair<Tuple, int64_t>> leak_watch;

    static constexpr size_t MAX_BYTES = 8 * 1024 * 1024;
    static constexpr size_t MAX_FLOWS = 4096;

    uint64_t to_filetime_from_qpc(int64_t capture) const {
        return anchor_filetime + static_cast<uint64_t>((capture - anchor_qpc) * 10'000'000 / frequency);
    }

    void send(Packet& packet, const char* reason) {
        UINT sent = 0;
        bool success = WinDivertSend(divert, packet.bytes.data(), static_cast<UINT>(packet.bytes.size()),
                                    &sent, &packet.address) != 0;
        DWORD error = success ? ERROR_SUCCESS : GetLastError();
        success = success && sent == packet.bytes.size();
        if (!success) {
            fatal_send = true;
            log.write("{\"kind\":\"error\",\"operation\":\"send\",\"reason\":" + json(reason) +
                      ",\"code\":" + std::to_string(error) + "}");
        }
    }

    void record_added(bool held, const std::string& action, int64_t capture_qpc) {
        const double ms = static_cast<double>(qpc() - capture_qpc) * 1000.0 / static_cast<double>(frequency);
        if (held) added_held_ms.push_back(ms);
        else if (action == "proxy") added_proxy_ms.push_back(ms);
        else added_direct_ms.push_back(ms);
    }

    bool reserve(const Tuple& tuple, Flow& flow) {
        SOCKET socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (socket == INVALID_SOCKET) return false;
        BOOL exclusive = TRUE;
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = tuple.local;
        if (setsockopt(socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                       reinterpret_cast<const char*>(&exclusive), sizeof(exclusive)) ||
            bind(socket, reinterpret_cast<sockaddr*>(&address), sizeof(address))) {
            closesocket(socket);
            return false;
        }
        int size = sizeof(address);
        if (getsockname(socket, reinterpret_cast<sockaddr*>(&address), &size)) {
            closesocket(socket);
            return false;
        }
        uint16_t alias = ntohs(address.sin_port);
        if (alias == config.listener_port || aliases.count({tuple.local, alias})) {
            closesocket(socket);
            return false;
        }
        flow.reservation = socket;
        flow.alias = alias;
        aliases.emplace(std::make_pair(tuple.local, alias), tuple);
        std::ostringstream line;
        line << "{\"kind\":\"translation\"," << fields(tuple)
             << ",\"peer_ip\":\"" << ip(tuple.local) << "\",\"peer_port\":" << alias
             << ",\"listener_ip\":\"" << ip(tuple.local) << "\",\"listener_port\":" << config.listener_port
             << ",\"original_ip\":\"" << ip(tuple.remote) << "\",\"original_port\":" << tuple.remote_port
             << ",\"generation\":" << flow.generation << ",\"qpc\":" << qpc() << "}";
        log.write(line.str());
        return true;
    }

    void forward(Packet& packet, const Tuple& tuple, Flow& flow, bool held) {
        Parsed parsed(packet);
        if (flow.action == "proxy") {
            if (!parsed.tcp || !flow.alias) { fatal_send = true; return; }
            parsed.ip_header->DstAddr = tuple.local;
            parsed.tcp->SrcPort = htons(flow.alias);
            parsed.tcp->DstPort = htons(config.listener_port);
            packet.address.Outbound = 1;
            packet.address.Loopback = 1;
            WinDivertHelperCalcChecksums(packet.bytes.data(), static_cast<UINT>(packet.bytes.size()),
                                        &packet.address, 0);
        }
        record_added(held, flow.action, packet.received);
        send(packet, "forward");
    }

    void flush(Flow& flow, const Tuple& tuple) {
        while (!flow.held.empty()) {
            Packet packet = std::move(flow.held.front());
            flow.held.pop_front();
            forward(packet, tuple, flow, true);
        }
    }

    bool reverse(Packet& packet, Parsed& parsed) {
        if (!parsed.tcp || parsed.tuple.local_port != config.listener_port) return false;
        auto alias = aliases.find({parsed.tuple.remote, parsed.tuple.remote_port});
        if (alias == aliases.end()) return false;
        const Tuple& original = alias->second;
        auto flow_it = flows.find(original);
        if (flow_it == flows.end() || parsed.tuple.local != original.local) return false;
        Flow& flow = *flow_it->second;
        parsed.ip_header->SrcAddr = original.remote;
        parsed.ip_header->DstAddr = original.local;
        parsed.tcp->SrcPort = htons(original.remote_port);
        parsed.tcp->DstPort = htons(original.local_port);
        packet.address.Outbound = flow.outbound_loopback ? 1 : 0;
        packet.address.Loopback = flow.outbound_loopback ? 1 : 0;
        WinDivertHelperCalcChecksums(packet.bytes.data(), static_cast<UINT>(packet.bytes.size()),
                                    &packet.address, 0);
        send(packet, "reverse");
        return true;
    }

    void send_rst(const Tuple& tuple, Flow& flow) {
        unsigned char buffer[40]{};
        WINDIVERT_IPHDR* ip_header = reinterpret_cast<WINDIVERT_IPHDR*>(buffer);
        WINDIVERT_TCPHDR* tcp = reinterpret_cast<WINDIVERT_TCPHDR*>(buffer + 20);
        ip_header->Version = 4;
        ip_header->HdrLength = 5;
        ip_header->Length = htons(40);
        ip_header->TTL = 64;
        ip_header->Protocol = IPPROTO_TCP;
        ip_header->SrcAddr = tuple.local;
        ip_header->DstAddr = tuple.remote;
        tcp->SrcPort = htons(tuple.local_port);
        tcp->DstPort = htons(tuple.remote_port);
        tcp->SeqNum = htonl(flow.last_seq);
        tcp->AckNum = htonl(flow.last_ack);
        tcp->HdrLength = 5;
        tcp->Rst = 1;
        tcp->Ack = flow.last_ack ? 1 : 0;
        tcp->Window = 0;
        Packet packet;
        packet.bytes.assign(buffer, buffer + 40);
        packet.address.Outbound = 1;
        packet.address.Loopback = flow.outbound_loopback ? 1 : 0;
        if (!WinDivertHelperCalcChecksums(packet.bytes.data(), 40, &packet.address, 0)) return;
        UINT sent = 0;
        WinDivertSend(divert, packet.bytes.data(), 40, &sent, &packet.address);
        flow.rst_sent = true;
        ++rst_count;
        log.write("{\"kind\":\"rst\"," + fields(tuple) + ",\"generation\":" +
                  std::to_string(flow.generation) + ",\"qpc\":" + std::to_string(qpc()) + "}");
    }

    std::vector<inproc::EventRef> enumerate(uint8_t protocol, const std::vector<uint16_t>& ports,
                                            uint64_t window_start) {
        std::vector<inproc::EventRef> result;
        if (!session) return result;
        std::vector<FWPM_FILTER_CONDITION0> conditions;
        FWPM_FILTER_CONDITION0 type_condition{};
        type_condition.fieldKey = FWPM_CONDITION_NET_EVENT_TYPE;
        type_condition.matchType = FWP_MATCH_EQUAL;
        type_condition.conditionValue.type = FWP_UINT32;
        type_condition.conditionValue.uint32 = static_cast<UINT32>(FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW);
        FWPM_FILTER_CONDITION0 protocol_condition{};
        protocol_condition.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
        protocol_condition.matchType = FWP_MATCH_EQUAL;
        protocol_condition.conditionValue.type = FWP_UINT8;
        protocol_condition.conditionValue.uint8 = protocol;
        std::vector<FWPM_FILTER_CONDITION0> port_conditions;
        for (uint16_t port : ports) {
            FWPM_FILTER_CONDITION0 condition{};
            condition.fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
            condition.matchType = FWP_MATCH_EQUAL;
            condition.conditionValue.type = FWP_UINT16;
            condition.conditionValue.uint16 = port;
            port_conditions.push_back(condition);
        }

        auto build = [&](int level) {
            conditions.clear();
            conditions.push_back(type_condition);
            if (level >= 1) conditions.push_back(protocol_condition);
            if (level >= 2) for (const auto& c : port_conditions) conditions.push_back(c);
        };

        FWPM_NET_EVENT_ENUM_TEMPLATE0 range{};
        range.startTime = to_filetime(window_start);
        GetSystemTimePreciseAsFileTime(&range.endTime);

        HANDLE handle = nullptr;
        int level = port_conditions.empty() ? 1 : 2;
        std::string chosen;
        for (;;) {
            build(level);
            range.numFilterConditions = static_cast<UINT32>(conditions.size());
            range.filterCondition = conditions.data();
            const auto created = FwpmNetEventCreateEnumHandle0(session, &range, &handle);
            if (!created) {
                chosen = level >= 2 ? "type+protocol+local_port" : level == 1 ? "type+protocol" : "type";
                break;
            }
            if (level == 0) {
                FWPM_NET_EVENT_ENUM_TEMPLATE0 bare{};
                bare.startTime = range.startTime;
                bare.endTime = range.endTime;
                if (FwpmNetEventCreateEnumHandle0(session, &bare, &handle)) return result;
                chosen = "time_window_only";
                break;
            }
            --level;
        }
        if (!lookup.filter.empty() && lookup.filter != chosen)
            lookup.filter += "|" + chosen;
        else if (lookup.filter.empty())
            lookup.filter = chosen;

        const UINT32 batch = 256;
        for (;;) {
            FWPM_NET_EVENT3** entries = nullptr;
            UINT32 count = 0;
            if (FwpmNetEventEnum3(session, handle, batch, &entries, &count)) break;
            for (UINT32 i = 0; i < count; ++i) {
                const auto* entry = entries[i];
                if (!entry || entry->type != FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW) continue;
                const auto& header = entry->header;
                const auto* allow = entry->classifyAllow;
                inproc::EventRef ref;
                ref.event_filetime = static_cast<int64_t>(filetime(header.timeStamp));
                ref.layer_id = allow ? allow->layerId : 0;
                ref.outbound = allow && allow->msFwpDirection == FWP_DIRECTION_OUTBOUND;
                ref.app_path = lower(blob_path(header.appId));
                ref.tuple_match = false;
                ref.raw_local_addr = header.localAddrV4;
                ref.raw_remote_addr = header.remoteAddrV4;
                ref.match_local_port = static_cast<uint16_t>(header.localPort);
                ref.match_remote_port = static_cast<uint16_t>(header.remotePort);
                ref.match_protocol = static_cast<uint8_t>(header.ipProtocol);
                ref.ip_version = header.ipVersion;
                result.push_back(std::move(ref));
            }
            if (entries) FwpmFreeMemory0(reinterpret_cast<void**>(&entries));
            if (count < batch) break;
        }
        FwpmNetEventDestroyEnumHandle0(session, handle);
        return result;
    }

    inproc::MatchResult match(const Tuple& tuple, int64_t capture_filetime,
                              std::vector<inproc::EventRef>& events) {
        for (auto& event : events) {
            event.tuple_match = event.ip_version == FWP_IP_VERSION_V4 &&
                htonl(event.raw_local_addr) == tuple.local &&
                htonl(event.raw_remote_addr) == tuple.remote &&
                event.match_local_port == tuple.local_port &&
                event.match_remote_port == tuple.remote_port &&
                event.match_protocol == tuple.protocol;
        }
        inproc::MatchConfig match_config;
        match_config.window_before = static_cast<int64_t>(config.window_before_ms) * 10000;
        match_config.window_after = static_cast<int64_t>(config.window_after_ms) * 10000;
        match_config.ale_connect_v4 = ALE_AUTH_CONNECT_V4;
        match_config.ale_connect_v6 = ALE_AUTH_CONNECT_V6;
        return inproc::match_generation(events, capture_filetime, match_config);
    }

    void resolve_pending(int64_t now) {
        std::vector<uint16_t> tcp_ports, udp_ports;
        uint64_t window_start = utc_now();
        bool due = false;
        for (auto& entry : flows) {
            Flow& flow = *entry.second;
            if (flow.action != "pending") continue;
            if (flow.next_retry_qpc <= now || now >= flow.deadline_qpc) due = true;
            window_start = (std::min)(window_start, flow.capture_filetime);
            if (flow.protocol == 6) tcp_ports.push_back(entry.first.local_port);
            else udp_ports.push_back(entry.first.local_port);
        }
        if (!due) return;
        window_start -= static_cast<uint64_t>(config.window_before_ms) * 10000;

        auto ports_tcp = inproc::pending_ports(tcp_ports);
        auto ports_udp = inproc::pending_ports(udp_ports);
        std::vector<inproc::EventRef> tcp_events, udp_events;
        if (!tcp_ports.empty()) {
            const auto began = qpc();
            tcp_events = enumerate(6, ports_tcp, window_start);
            lookup.durations_ms.push_back(static_cast<double>(qpc() - began) * 1000.0 / static_cast<double>(frequency));
            ++lookup.calls;
        }
        if (!udp_ports.empty()) {
            const auto began = qpc();
            udp_events = enumerate(17, ports_udp, window_start);
            lookup.durations_ms.push_back(static_cast<double>(qpc() - began) * 1000.0 / static_cast<double>(frequency));
            ++lookup.calls;
        }

        for (auto& entry : flows) {
            Flow& flow = *entry.second;
            if (flow.action != "pending") continue;
            ++flow.lookup_calls;
            auto& events = flow.protocol == 6 ? tcp_events : udp_events;
            auto outcome = match(entry.first, static_cast<int64_t>(flow.capture_filetime), events);
            if (outcome.outcome == inproc::MatchOutcome::NoEvent) {
                if (now >= flow.deadline_qpc) { decide(entry.first, flow, "direct", "timeout", now); continue; }
                flow.backoff_ms = flow.backoff_ms == 0 ? 1 : (std::min)(flow.backoff_ms * 2, 8);
                flow.next_retry_qpc = (std::min)(now + frequency * flow.backoff_ms / 1000, flow.deadline_qpc);
                continue;
            }
            if (outcome.outcome == inproc::MatchOutcome::Ambiguous) {
                decide(entry.first, flow, "direct", "ambiguous", now);
                continue;
            }
            const bool selected = outcome.app_path == selected_app;
            if (!selected) { decide(entry.first, flow, "direct", "other_app", now); continue; }
            if (flow.protocol == 17) {
                if (entry.first.remote_port == config.quic_port) {
                    decide(entry.first, flow, "drop_quic", "selected_quic", now);
                } else {
                    decide(entry.first, flow, "direct", "selected_udp_direct", now);
                }
                continue;
            }
            const bool proxy = config.mode == "redirect";
            decide(entry.first, flow, proxy ? "proxy" : "direct", "selected", now);
        }
    }

    void decide(const Tuple& tuple, Flow& flow, const std::string& action, const char* reason, int64_t now) {
        decision_latency_ms.push_back(static_cast<double>(now - flow.capture_qpc) * 1000.0 / static_cast<double>(frequency));
        lookups_per_flow.push_back(static_cast<double>(flow.lookup_calls));
        if (action == "drop_quic") {
            flow.action = "drop";
            ++quic_drops;
            while (!flow.held.empty()) {
                log_decision(tuple, flow, "drop", "selected_quic");
                flow.held.pop_front();
            }
            if (config.send_rst) send_rst(tuple, flow);
            return;
        }
        flow.action = action;
        if (action == "proxy" && !reserve(tuple, flow)) {
            flow.action = "direct";
            log.write("{\"kind\":\"error\",\"operation\":\"reserve_alias_direct\"}");
        }
        if (flow.action == "proxy") ++decided_proxy;
        else {
            ++decided_direct;
            if (std::string(reason) == "timeout") {
                ++unattributed;
                leak_watch.emplace_back(tuple, now + frequency * config.leak_ms / 1000);
            }
        }
        log_decision(tuple, flow, flow.action, reason);
        flush(flow, tuple);
    }

    void log_decision(const Tuple& tuple, Flow& flow, const std::string& action, const std::string& reason) {
        log.write("{\"kind\":\"decision\"," + fields(tuple) + ",\"generation\":" +
                  std::to_string(flow.generation) + ",\"action\":" + json(action) +
                  ",\"reason\":" + json(reason) + ",\"qpc\":" + std::to_string(qpc()) + "}");
    }

    void check_leaks(int64_t now) {
        if (leak_watch.empty()) return;
        std::vector<uint16_t> ports;
        uint64_t window_start = utc_now();
        for (const auto& watch : leak_watch) {
            ports.push_back(watch.first.local_port);
            auto flow_it = flows.find(watch.first);
            if (flow_it != flows.end())
                window_start = (std::min)(window_start, flow_it->second->capture_filetime);
        }
        window_start -= static_cast<uint64_t>(config.window_before_ms) * 10000;
        auto events = enumerate(6, inproc::pending_ports(ports), window_start);
        std::deque<std::pair<Tuple, int64_t>> remaining;
        for (auto& watch : leak_watch) {
            auto flow_it = flows.find(watch.first);
            if (flow_it == flows.end()) continue;
            Flow& flow = *flow_it->second;
            auto outcome = match(watch.first, static_cast<int64_t>(flow.capture_filetime), events);
            if (outcome.outcome == inproc::MatchOutcome::Matched && outcome.app_path == selected_app) {
                if (!flow.leak_selected) {
                    flow.leak_selected = true;
                    ++leaked;
                    log.write("{\"kind\":\"leaked\"," + fields(watch.first) + ",\"generation\":" +
                              std::to_string(flow.generation) + ",\"qpc\":" + std::to_string(qpc()) + "}");
                    if (config.send_rst && !flow.rst_sent) send_rst(watch.first, flow);
                }
                continue;
            }
            if (now < watch.second) remaining.push_back(watch);
        }
        leak_watch.swap(remaining);
    }

    void handle(Packet packet) {
        Parsed parsed(packet);
        if (!parsed.valid) { send(packet, "unparsed"); return; }
        if (config.listener_port && reverse(packet, parsed)) return;
        const Tuple tuple = parsed.tuple;
        const bool controlled = tuple.remote == target && packet.address.Outbound &&
            ((tuple.protocol == 6 && tuple.remote_port == config.port) ||
             (tuple.protocol == 17 && config.udp_port && tuple.remote_port == config.udp_port) ||
             (tuple.protocol == 17 && tuple.remote_port == config.quic_port));
        if (!controlled) { send(packet, "uncontrolled"); return; }

        auto found = flows.find(tuple);
        if (found == flows.end()) {
            if (flows.size() >= MAX_FLOWS) { send(packet, "flow_capacity"); return; }
            auto flow = std::make_unique<Flow>();
            flow->generation = packet.address.Timestamp;
            flow->capture_qpc = packet.address.Timestamp;
            flow->capture_filetime = to_filetime_from_qpc(packet.address.Timestamp);
            flow->deadline_qpc = packet.received + frequency * config.hold_ms / 1000;
            flow->protocol = tuple.protocol;
            flow->outbound_loopback = packet.address.Loopback != 0;
            if (parsed.tcp && parsed.tcp->Syn && !parsed.tcp->Ack) {
                flow->saw_syn = true;
                flow->syn_sequence = parsed.tcp->SeqNum;
            } else if (parsed.tcp) {
                flow->action = "direct";
            }
            found = flows.emplace(tuple, std::move(flow)).first;
        }
        Flow& flow = *found->second;
        if (parsed.tcp) {
            flow.last_seq = ntohl(parsed.tcp->SeqNum);
            flow.last_ack = ntohl(parsed.tcp->AckNum);
            if (parsed.tcp->Syn && !parsed.tcp->Ack && flow.action == "proxy" &&
                flow.saw_syn && parsed.tcp->SeqNum != flow.syn_sequence) {
                log_decision(tuple, flow, "drop", "ambiguous_reuse_of_proxy_tuple");
                reuse_disrupted = true;
                return;
            }
        }
        if (flow.action == "drop") {
            log_decision(tuple, flow, "drop", "selected_quic");
            return;
        }
        if (flow.action != "pending") {
            forward(packet, tuple, flow, false);
            return;
        }
        if (flow.held.size() >= 256) {
            decide(tuple, flow, "direct", "pending_capacity", qpc());
            forward(packet, tuple, flow, false);
            return;
        }
        flow.held.push_back(std::move(packet));
    }

    int64_t next_deadline() const {
        int64_t soonest = 0;
        const auto consider = [&soonest](int64_t candidate) {
            if (candidate && (soonest == 0 || candidate < soonest)) soonest = candidate;
        };
        for (const auto& entry : flows) {
            const Flow& flow = *entry.second;
            if (flow.action != "pending") continue;
            consider(flow.next_retry_qpc ? flow.next_retry_qpc : flow.deadline_qpc);
            consider(flow.deadline_qpc);
        }
        for (const auto& watch : leak_watch) consider(watch.second);
        return soonest;
    }

    void receive() {
        while (!stopping) {
            Packet packet;
            packet.bytes.resize(65535);
            UINT length = 0;
            if (!WinDivertRecv(divert, packet.bytes.data(), static_cast<UINT>(packet.bytes.size()),
                               &length, &packet.address)) {
                DWORD error = GetLastError();
                if (!stopping) receive_error = error;
                break;
            }
            packet.received = qpc();
            packet.bytes.resize(length);
            {
                std::lock_guard<std::mutex> lock(mutex);
                input.push_back(std::move(packet));
            }
            wake.notify_one();
        }
        wake.notify_one();
    }

public:
    explicit Engine(Options value)
        : config(std::move(value)), log(config.output),
          summary_file(config.summary, std::ios::trunc) {
        if (!summary_file) throw std::runtime_error("cannot create summary file");
        target = parse_ip(config.target);
        frequency = qpf();
        selected_app = lower(config.selected_app);
    }

    ~Engine() {
        stopping = true;
        wake.notify_all();
        if (divert != INVALID_HANDLE_VALUE) WinDivertShutdown(divert, WINDIVERT_SHUTDOWN_RECV);
        if (receiver.joinable()) receiver.join();
        if (divert != INVALID_HANDLE_VALUE) WinDivertClose(divert);
        if (session) FwpmEngineClose0(session);
    }

    int run() {
        bfe.start(config.state_out);
        if (FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &session))
            throw std::runtime_error("FwpmEngineOpen0 lookup session");

        anchor_qpc = qpc();
        anchor_filetime = utc_now();

        std::string filter = "ip and !impostor and ((outbound and ip.DstAddr == " + config.target +
            " and ((tcp and tcp.DstPort == " + std::to_string(config.port) + ")";
        if (config.udp_port)
            filter += " or (udp and udp.DstPort == " + std::to_string(config.udp_port) + ")";
        filter += " or (udp and udp.DstPort == " + std::to_string(config.quic_port) + ")))";
        if (config.listener_port)
            filter += " or (outbound and tcp and tcp.SrcPort == " + std::to_string(config.listener_port) + ")";
        filter += ")";

        divert = WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
        if (divert == INVALID_HANDLE_VALUE) {
            log.write("{\"kind\":\"error\",\"operation\":\"open\",\"code\":" + std::to_string(GetLastError()) + "}");
            return 2;
        }
        if (!WinDivertSetParam(divert, WINDIVERT_PARAM_QUEUE_LENGTH, 4096) ||
            !WinDivertSetParam(divert, WINDIVERT_PARAM_QUEUE_SIZE, MAX_BYTES) ||
            !WinDivertSetParam(divert, WINDIVERT_PARAM_QUEUE_TIME, 2048))
            throw std::runtime_error("cannot configure WinDivert queue");

        log.write("{\"kind\":\"ready\",\"qpc\":" + std::to_string(qpc()) +
                  ",\"qpc_frequency\":" + std::to_string(frequency) +
                  ",\"anchor_qpc\":" + std::to_string(anchor_qpc) +
                  ",\"anchor_filetime\":" + std::to_string(anchor_filetime) +
                  ",\"mode\":" + json(config.mode) + ",\"hold_ms\":" + std::to_string(config.hold_ms) + "}");

        receiver = std::thread([this] { receive(); });
        const int64_t end = qpc() + frequency * config.seconds;

        while (qpc() < end && !receive_error && !fatal_send) {
            if (!config.stop_file.empty() &&
                GetFileAttributesA(config.stop_file.c_str()) != INVALID_FILE_ATTRIBUTES) break;
            std::deque<Packet> batch;
            {
                std::unique_lock<std::mutex> lock(mutex);
                if (input.empty()) {
                    int64_t deadline = next_deadline();
                    if (deadline) {
                        int64_t wait_ticks = deadline - qpc();
                        if (wait_ticks < 0) wait_ticks = 0;
                        wake.wait_for(lock, std::chrono::microseconds(wait_ticks * 1'000'000 / frequency));
                    } else {
                        wake.wait_for(lock, std::chrono::milliseconds(50));
                    }
                }
                batch.swap(input);
            }
            for (auto& packet : batch) handle(std::move(packet));
            const int64_t now = qpc();
            resolve_pending(now);
            check_leaks(now);
        }

        stopping = true;
        WinDivertShutdown(divert, WINDIVERT_SHUTDOWN_RECV);
        wake.notify_all();
        if (receiver.joinable()) receiver.join();
        {
            std::deque<Packet> batch;
            { std::lock_guard<std::mutex> lock(mutex); batch.swap(input); }
            for (auto& packet : batch) handle(std::move(packet));
        }
        const int64_t now = qpc();
        resolve_pending(now);
        for (auto& entry : flows) {
            Flow& flow = *entry.second;
            if (flow.action == "pending") { flow.action = "direct"; ++unattributed; }
            flush(flow, entry.first);
        }
        check_leaks(qpc());

        write_summary();
        if (receive_error)
            log.write("{\"kind\":\"error\",\"operation\":\"receive\",\"code\":" +
                      std::to_string(receive_error.load()) + "}");
        log.write("{\"kind\":\"complete\",\"qpc\":" + std::to_string(qpc()) +
                  ",\"flows\":" + std::to_string(flows.size()) +
                  ",\"success\":" + ((!receive_error && !fatal_send) ? "true" : "false") + "}");
        return receive_error || fatal_send ? 3 : 0;
    }

    void write_summary() {
        auto dist = [](const std::vector<double>& values) {
            auto d = inproc::distribution(values);
            std::ostringstream out;
            out << "{\"count\":" << d.count << ",\"p50\":" << d.p50 << ",\"p95\":" << d.p95
                << ",\"max\":" << d.max << "}";
            return out.str();
        };
        std::ostringstream out;
        out << "{\"engine\":\"inproc\",\"mode\":" << json(config.mode)
            << ",\"topology\":\"single-host-local\""
            << ",\"selected_app\":" << json(selected_app)
            << ",\"first_packet_decision_latency_ms\":" << dist(decision_latency_ms)
            << ",\"lookup_calls\":" << lookup.calls
            << ",\"lookup_calls_per_flow\":" << dist(lookups_per_flow)
            << ",\"lookup_duration_ms\":" << dist(lookup.durations_ms)
            << ",\"added_latency_held_ms\":" << dist(added_held_ms)
            << ",\"added_latency_direct_ms\":" << dist(added_direct_ms)
            << ",\"added_latency_proxy_ms\":" << dist(added_proxy_ms)
            << ",\"decided_proxy\":" << decided_proxy
            << ",\"decided_direct\":" << decided_direct
            << ",\"unattributed\":" << unattributed
            << ",\"leaked\":" << leaked
            << ",\"rst_count\":" << rst_count
            << ",\"quic_drops\":" << quic_drops
            << ",\"nonselected_client_disrupted\":" << (reuse_disrupted ? "true" : "false")
            << ",\"enum_filter\":" << json(lookup.filter.empty() ? "none" : lookup.filter)
            << ",\"window_before_ms\":" << config.window_before_ms
            << ",\"window_after_ms\":" << config.window_after_ms
            << ",\"send_rst\":" << (config.send_rst ? "true" : "false")
            << ",\"success\":" << ((!receive_error && !fatal_send) ? "true" : "false") << "}";
        summary_file << out.str() << '\n';
        summary_file.flush();
        log.write("{\"kind\":\"summary\",\"enum_filter\":" + json(lookup.filter.empty() ? "none" : lookup.filter) +
                  ",\"lookup_calls\":" + std::to_string(lookup.calls) +
                  ",\"decided_proxy\":" + std::to_string(decided_proxy) +
                  ",\"decided_direct\":" + std::to_string(decided_direct) +
                  ",\"unattributed\":" + std::to_string(unattributed) +
                  ",\"leaked\":" + std::to_string(leaked) +
                  ",\"rst_count\":" + std::to_string(rst_count) +
                  ",\"quic_drops\":" + std::to_string(quic_drops) + "}");
    }
};

}  // namespace

int main(int argc, char** argv) {
    WSADATA winsock{};
    if (WSAStartup(MAKEWORD(2, 2), &winsock)) return 1;
    int result = 1;
    try {
        Engine engine(options(argc, argv));
        result = engine.run();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
    }
    WSACleanup();
    return result;
}
#endif
