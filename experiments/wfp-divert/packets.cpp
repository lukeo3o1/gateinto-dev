#include <cstdint>
#include <stdexcept>
#include <string>

struct Decision {
    int64_t generation;
    int64_t deadline;
    uint8_t protocol;
    std::string action = "pending";

    Decision(int64_t gen, int64_t end, uint8_t proto)
        : generation(gen), deadline(end), protocol(proto) {}

    void expire(int64_t now) {
        if (action == "pending" && now >= deadline) action = "direct";
    }

    bool resolve(int64_t gen, int64_t now, const std::string& next) {
        expire(now);
        if (action != "pending" || gen != generation ||
            (next != "direct" && next != "proxy") ||
            (next == "proxy" && protocol != 6)) return false;
        action = next;
        return true;
    }
};

struct SynDrop {
    bool dropped = false;

    bool should_drop(bool enabled, uint8_t protocol, bool syn, bool ack,
                     const std::string& action) {
        if (!enabled || dropped || protocol != 6 || !syn || ack ||
            (action != "direct" && action != "proxy")) return false;
        dropped = true;
        return true;
    }
};

static bool controlled_port(uint8_t protocol, uint16_t destination,
                            uint16_t primary, uint16_t secondary) {
    return (protocol == 6 || protocol == 17) &&
        (destination == primary || (protocol == 17 && secondary && destination == secondary));
}

#ifdef WFP_PACKET_STATE_TEST
#include <cassert>
int main() {
    Decision pending(100, 200, 6);
    assert(pending.resolve(100, 150, "proxy"));
    assert(pending.action == "proxy");
    assert(!pending.resolve(100, 160, "direct"));
    Decision expired(100, 200, 6);
    expired.expire(200);
    assert(expired.action == "direct");
    assert(!expired.resolve(100, 201, "proxy"));
    Decision generation(300, 400, 6);
    assert(!generation.resolve(100, 320, "proxy"));
    assert(generation.action == "pending");
    Decision udp(100, 200, 17);
    assert(!udp.resolve(100, 110, "proxy"));
    assert(udp.resolve(100, 110, "direct"));
    SynDrop retransmit;
    assert(!retransmit.should_drop(true, 6, true, false, "pending"));
    assert(!retransmit.should_drop(true, 17, false, false, "direct"));
    assert(!retransmit.should_drop(true, 6, false, true, "proxy"));
    assert(retransmit.should_drop(true, 6, true, false, "proxy"));
    assert(!retransmit.should_drop(true, 6, true, false, "proxy"));
    SynDrop disabled;
    assert(!disabled.should_drop(false, 6, true, false, "direct"));
    assert(controlled_port(6, 8000, 8000, 8001));
    assert(!controlled_port(6, 8001, 8000, 8001));
    assert(controlled_port(17, 8000, 8000, 8001));
    assert(controlled_port(17, 8001, 8000, 8001));
    assert(!controlled_port(17, 8002, 8000, 8001));
    assert(!controlled_port(17, 8001, 8000, 0));
}
#endif

#ifndef WFP_PACKET_STATE_TEST
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "windivert.h"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <thread>
#include <tuple>
#include <vector>

static int64_t qpc() {
    LARGE_INTEGER value;
    QueryPerformanceCounter(&value);
    return value.QuadPart;
}

struct Tuple {
    uint32_t local;
    uint32_t remote;
    uint16_t local_port;
    uint16_t remote_port;
    uint8_t protocol;

    bool operator<(const Tuple& rhs) const {
        return std::tie(local, local_port, remote, remote_port, protocol) <
               std::tie(rhs.local, rhs.local_port, rhs.remote, rhs.remote_port, rhs.protocol);
    }
};

static std::string ip(uint32_t address) {
    char buffer[INET_ADDRSTRLEN]{};
    IN_ADDR value;
    value.s_addr = address;
    if (!InetNtopA(AF_INET, &value, buffer, sizeof(buffer))) return "invalid";
    return buffer;
}

static uint32_t parse_ip(const std::string& text) {
    IN_ADDR value;
    if (InetPtonA(AF_INET, text.c_str(), &value) != 1)
        throw std::runtime_error("IPv4 literal required: " + text);
    return value.s_addr;
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

static std::string fields(const Tuple& tuple) {
    std::ostringstream out;
    out << "\"local_ip\":\"" << ip(tuple.local) << "\",\"local_port\":" << tuple.local_port
        << ",\"remote_ip\":\"" << ip(tuple.remote) << "\",\"remote_port\":" << tuple.remote_port
        << ",\"protocol\":" << unsigned(tuple.protocol);
    return out.str();
}

class Log {
    std::ofstream output;
    std::mutex mutex;
public:
    explicit Log(const std::string& path) : output(path, std::ios::trunc) {
        if (!output) throw std::runtime_error("cannot create packet log");
    }
    void write(const std::string& line) {
        std::lock_guard<std::mutex> lock(mutex);
        output << line << '\n';
        output.flush();
    }
};

struct Flow {
    Decision decision;
    uint32_t syn_sequence = 0;
    bool saw_syn = false;
    bool saw_close = false;
    bool native_confirmed = false;
    bool original_loopback = false;
    SynDrop syn_drop;
    SOCKET reservation = INVALID_SOCKET;
    uint16_t alias = 0;
    std::deque<Packet> held;

    Flow(int64_t generation, int64_t deadline, uint8_t protocol, bool loopback)
        : decision(generation, deadline, protocol), original_loopback(loopback) {}
    ~Flow() { if (reservation != INVALID_SOCKET) closesocket(reservation); }
};

struct Options {
    std::string target;
    std::string output;
    std::string control;
    std::string stop_file;
    uint16_t port = 0;
    uint16_t second_port = 0;
    bool drop_first_syn = false;
    uint16_t listener_port = 0;
    int seconds = 15;
    int hold_ms = 250;
};

static unsigned number(const std::string& value, unsigned min, unsigned max) {
    size_t count = 0;
    unsigned long result = std::stoul(value, &count);
    if (count != value.size() || result < min || result > max)
        throw std::runtime_error("numeric option out of range");
    return static_cast<unsigned>(result);
}

static Options options(int argc, char** argv) {
    Options result;
    for (int i = 1; i < argc; i += 2) {
        if (i + 1 == argc) throw std::runtime_error("missing option value");
        std::string key = argv[i], value = argv[i + 1];
        if (key == "--target") { parse_ip(value); result.target = value; }
        else if (key == "--port") result.port = static_cast<uint16_t>(number(value, 1, 65535));
        else if (key == "--second-port") result.second_port = static_cast<uint16_t>(number(value, 1, 65535));
        else if (key == "--drop-first-syn") result.drop_first_syn = number(value, 0, 1) != 0;
        else if (key == "--listener-port") result.listener_port = static_cast<uint16_t>(number(value, 1, 65535));
        else if (key == "--seconds") result.seconds = number(value, 1, 600);
        else if (key == "--hold-ms") result.hold_ms = number(value, 1, 10000);
        else if (key == "--out") result.output = value;
        else if (key == "--control") result.control = value;
        else if (key == "--stop-file") result.stop_file = value;
        else throw std::runtime_error("unknown option: " + key);
    }
    if (result.target.empty() || !result.port || result.output.empty() || result.control.empty())
        throw std::runtime_error("required: --target IPv4 --port N --out PATH --control PATH");
    if (result.listener_port == result.port)
        throw std::runtime_error("listener and controlled target ports must differ");
    if (result.second_port == result.port)
        throw std::runtime_error("second UDP destination must differ from the primary port");
    return result;
}

class Capture {
    Options config;
    Log log;
    HANDLE handle = INVALID_HANDLE_VALUE;
    std::atomic<bool> stopping{false};
    std::atomic<DWORD> receive_error{0};
    std::thread receiver;
    std::mutex input_mutex;
    std::condition_variable input_space;
    std::deque<Packet> input;
    size_t input_bytes = 0;
    size_t held_bytes = 0;
    std::map<Tuple, std::unique_ptr<Flow>> flows;
    std::map<std::pair<uint32_t, uint16_t>, Tuple> aliases;
    std::streamoff control_offset = 0;
    int64_t frequency = 0;
    uint32_t target = 0;
    bool fatal_send = false;
    static constexpr size_t MAX_BYTES = 8 * 1024 * 1024;
    static constexpr size_t MAX_FLOWS = 4096;

    void send(Packet& packet) {
        UINT sent = 0;
        bool success = WinDivertSend(handle, packet.bytes.data(), static_cast<UINT>(packet.bytes.size()),
                                    &sent, &packet.address) != 0;
        DWORD error = success ? ERROR_SUCCESS : GetLastError();
        success = success && sent == packet.bytes.size();
        Parsed parsed(packet);
        std::ostringstream line;
        line << "{\"kind\":\"injection\",\"capture_qpc\":" << packet.address.Timestamp
             << ",\"qpc\":" << qpc() << ",\"outbound\":" << unsigned(packet.address.Outbound)
             << ",\"loopback\":" << unsigned(packet.address.Loopback)
             << ",\"impostor\":" << unsigned(packet.address.Impostor)
             << ",\"if_idx\":" << packet.address.Network.IfIdx
             << ",\"sub_if_idx\":" << packet.address.Network.SubIfIdx
             << ",\"length\":" << packet.bytes.size() << ",\"sent_length\":" << sent
             << ",\"success\":" << (success ? "true" : "false") << ",\"error\":" << error;
        if (parsed.valid)
            line << ",\"src_ip\":\"" << ip(parsed.tuple.local)
                 << "\",\"src_port\":" << parsed.tuple.local_port
                 << ",\"dst_ip\":\"" << ip(parsed.tuple.remote)
                 << "\",\"dst_port\":" << parsed.tuple.remote_port
                 << ",\"protocol\":" << unsigned(parsed.tuple.protocol);
        line << "}";
        log.write(line.str());
        if (!success) {
            fatal_send = true;
            log.write("{\"kind\":\"error\",\"operation\":\"send\",\"code\":" +
                      std::to_string(error) + "}");
        }
    }

    void packet_log(Packet& packet, const Tuple& tuple, const Flow* flow,
                    const std::string& action, const std::string& reason) {
        Parsed parsed(packet);
        std::ostringstream line;
        line << "{\"kind\":\"packet\"," << fields(tuple)
             << ",\"generation\":" << (flow ? flow->decision.generation : packet.address.Timestamp)
             << ",\"capture_qpc\":" << packet.address.Timestamp
             << ",\"recv_qpc\":" << packet.received << ",\"decision_qpc\":" << qpc()
             << ",\"outbound\":" << unsigned(packet.address.Outbound)
             << ",\"loopback\":" << unsigned(packet.address.Loopback)
             << ",\"impostor\":" << unsigned(packet.address.Impostor)
             << ",\"length\":" << packet.bytes.size() << ",\"action\":\"" << action
             << "\",\"reason\":\"" << reason << "\",\"syn\":" << (parsed.tcp ? unsigned(parsed.tcp->Syn) : 0)
             << ",\"ack\":" << (parsed.tcp ? unsigned(parsed.tcp->Ack) : 0)
             << ",\"fin\":" << (parsed.tcp ? unsigned(parsed.tcp->Fin) : 0)
             << ",\"rst\":" << (parsed.tcp ? unsigned(parsed.tcp->Rst) : 0)
             << ",\"sequence\":" << (parsed.tcp ? ntohl(parsed.tcp->SeqNum) : 0) << "}";
        log.write(line.str());
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
             << ",\"generation\":" << flow.decision.generation << ",\"qpc\":" << qpc() << "}";
        log.write(line.str());
        return true;
    }

    void forward(Packet& packet, const Tuple& tuple, Flow& flow, const std::string& reason) {
        Parsed parsed(packet);
        if (flow.syn_drop.should_drop(config.drop_first_syn && flow.native_confirmed, tuple.protocol,
                parsed.tcp && parsed.tcp->Syn, parsed.tcp && parsed.tcp->Ack,
                flow.decision.action)) {
            packet_log(packet, tuple, &flow, "drop", "injected_first_syn_drop");
            return;
        }
        packet_log(packet, tuple, &flow, flow.decision.action, reason);
        if (flow.decision.action == "proxy") {
            if (!parsed.tcp || !flow.alias) {
                fatal_send = true;
                return;
            }
            parsed.ip_header->DstAddr = tuple.local;
            parsed.tcp->SrcPort = htons(flow.alias);
            parsed.tcp->DstPort = htons(config.listener_port);
            packet.address.Outbound = 1;
            packet.address.Loopback = 1;
            WinDivertHelperCalcChecksums(packet.bytes.data(), static_cast<UINT>(packet.bytes.size()),
                                        &packet.address, 0);
        }
        send(packet);
    }

    void flush(const Tuple& tuple, Flow& flow, const std::string& reason) {
        while (!flow.held.empty()) {
            Packet packet = std::move(flow.held.front());
            flow.held.pop_front();
            held_bytes -= packet.bytes.size();
            forward(packet, tuple, flow, reason);
        }
    }

    void receive() {
        while (!stopping) {
            Packet packet;
            packet.bytes.resize(65535);
            UINT length = 0;
            if (!WinDivertRecv(handle, packet.bytes.data(), static_cast<UINT>(packet.bytes.size()),
                               &length, &packet.address)) {
                DWORD error = GetLastError();
                if (!stopping) receive_error = error;
                break;
            }
            packet.received = qpc();
            packet.bytes.resize(length);
            std::unique_lock<std::mutex> lock(input_mutex);
            input_space.wait(lock, [&] { return stopping || input_bytes + length <= MAX_BYTES; });
            input_bytes += length;
            input.push_back(std::move(packet));
        }
    }

    bool reverse(Packet& packet, Parsed& parsed) {
        if (!parsed.tcp || parsed.tuple.local_port != config.listener_port) return false;
        auto alias = aliases.find({parsed.tuple.remote, parsed.tuple.remote_port});
        if (alias == aliases.end()) return false;
        const Tuple& original = alias->second;
        Flow& flow = *flows.at(original);
        if (parsed.tuple.local != original.local) return false;
        packet_log(packet, original, &flow, "reverse", "listener_reply");
        parsed.ip_header->SrcAddr = original.remote;
        parsed.ip_header->DstAddr = original.local;
        parsed.tcp->SrcPort = htons(original.remote_port);
        parsed.tcp->DstPort = htons(original.local_port);
        packet.address.Outbound = flow.original_loopback ? 1 : 0;
        packet.address.Loopback = flow.original_loopback ? 1 : 0;
        WinDivertHelperCalcChecksums(packet.bytes.data(), static_cast<UINT>(packet.bytes.size()),
                                    &packet.address, 0);
        send(packet);
        return true;
    }

    void accept(Packet packet) {
        Parsed parsed(packet);
        if (!parsed.valid) {
            log.write("{\"kind\":\"unsupported\",\"reason\":\"unparsed_packet_reinjected\"}");
            send(packet);
            return;
        }
        if (config.listener_port && reverse(packet, parsed)) return;
        const Tuple tuple = parsed.tuple;
        if (tuple.remote != target ||
            !controlled_port(tuple.protocol, tuple.remote_port, config.port, config.second_port) ||
            !packet.address.Outbound) {
            send(packet);
            return;
        }
        auto found = flows.find(tuple);
        if (found == flows.end()) {
            if (flows.size() >= MAX_FLOWS) {
                packet_log(packet, tuple, nullptr, "direct", "flow_capacity");
                send(packet);
                return;
            }
            auto flow = std::make_unique<Flow>(packet.address.Timestamp,
                packet.received + frequency * config.hold_ms / 1000, tuple.protocol,
                packet.address.Loopback != 0);
            if (parsed.tcp && parsed.tcp->Syn && !parsed.tcp->Ack) {
                flow->saw_syn = true;
                flow->syn_sequence = parsed.tcp->SeqNum;
            } else if (parsed.tcp) {
                flow->decision.action = "direct";
            }
            found = flows.emplace(tuple, std::move(flow)).first;
        }
        Flow& flow = *found->second;
        if (parsed.tcp && parsed.tcp->Syn && !parsed.tcp->Ack &&
            (flow.saw_close || (flow.saw_syn && parsed.tcp->SeqNum != flow.syn_sequence))) {
            if (flow.decision.action == "proxy") {
                packet_log(packet, tuple, &flow, "drop", "ambiguous_reuse_of_proxy_tuple");
                return;
            }
            flow.decision.action = "direct";
            flush(tuple, flow, "ambiguous_reuse_direct");
        }
        if (parsed.tcp && (parsed.tcp->Fin || parsed.tcp->Rst)) flow.saw_close = true;
        flow.decision.expire(qpc());
        if (flow.decision.action != "pending") {
            flush(tuple, flow, "decision_or_timeout");
            forward(packet, tuple, flow, "pinned");
        } else if (held_bytes + packet.bytes.size() > MAX_BYTES || flow.held.size() >= 256) {
            flow.decision.action = "direct";
            flush(tuple, flow, "pending_capacity");
            forward(packet, tuple, flow, "pending_capacity");
        } else {
            packet_log(packet, tuple, &flow, "pending", "await_native_ownership");
            held_bytes += packet.bytes.size();
            flow.held.push_back(std::move(packet));
        }
    }

    void controls() {
        std::ifstream input_file(config.control, std::ios::binary);
        if (!input_file) return;
        input_file.seekg(0, std::ios::end);
        if (input_file.tellg() < control_offset) {
            log.write("{\"kind\":\"error\",\"operation\":\"control_truncated\"}");
            return;
        }
        input_file.seekg(control_offset);
        std::string line;
        while (std::getline(input_file, line)) {
            if (input_file.eof()) break;
            control_offset = input_file.tellg();
            std::istringstream command(line);
            std::string verb, local, remote, action, trailing;
            unsigned local_port, remote_port, protocol;
            int64_t generation;
            if (!(command >> verb >> local >> local_port >> remote >> remote_port >> protocol
                          >> generation >> action) || (command >> trailing) || verb != "decision" ||
                local_port > 65535 || remote_port > 65535 || protocol > 255) {
                log.write("{\"kind\":\"control_rejected\",\"reason\":\"syntax\"}");
                continue;
            }
            Tuple tuple{};
            try { tuple = {parse_ip(local), parse_ip(remote), static_cast<uint16_t>(local_port),
                           static_cast<uint16_t>(remote_port), static_cast<uint8_t>(protocol)}; }
            catch (...) { continue; }
            auto found = flows.find(tuple);
            bool accepted = false;
            if (found != flows.end()) {
                Flow& flow = *found->second;
                if (action == "proxy" && !config.listener_port) {
                    log.write("{\"kind\":\"control_rejected\",\"reason\":\"listener_missing\"}");
                    continue;
                }
                accepted = flow.decision.resolve(generation, qpc(), action);
                if (accepted) flow.native_confirmed = true;
                if (accepted && action == "proxy" && !reserve(tuple, flow)) {
                    flow.decision.action = "direct";
                    log.write("{\"kind\":\"error\",\"operation\":\"reserve_alias_direct\"}");
                }
                if (accepted) flush(tuple, flow, "native_control");
            }
            log.write("{\"kind\":\"control\"," + fields(tuple) + ",\"generation\":" +
                      std::to_string(generation) + ",\"accepted\":" + (accepted ? "true" : "false") +
                      ",\"action\":\"" + action + "\",\"qpc\":" + std::to_string(qpc()) + "}");
        }
    }

public:
    explicit Capture(Options value) : config(std::move(value)), log(config.output) {
        target = parse_ip(config.target);
        LARGE_INTEGER value_frequency;
        QueryPerformanceFrequency(&value_frequency);
        frequency = value_frequency.QuadPart;
    }

    ~Capture() {
        stopping = true;
        input_space.notify_all();
        if (handle != INVALID_HANDLE_VALUE) WinDivertShutdown(handle, WINDIVERT_SHUTDOWN_RECV);
        if (receiver.joinable()) receiver.join();
        if (handle != INVALID_HANDLE_VALUE) WinDivertClose(handle);
    }

    int run() {
        std::string udp_ports = "udp.DstPort == " + std::to_string(config.port);
        if (config.second_port) udp_ports += " or udp.DstPort == " + std::to_string(config.second_port);
        std::string filter = "ip and !impostor and ((outbound and ip.DstAddr == " + config.target +
            " and ((tcp and tcp.DstPort == " + std::to_string(config.port) +
            ") or (udp and (" + udp_ports + "))))";
        if (config.listener_port)
            filter += " or (outbound and tcp and tcp.SrcPort == " + std::to_string(config.listener_port) + ")";
        filter += ")";
        handle = WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
        if (handle == INVALID_HANDLE_VALUE) {
            log.write("{\"kind\":\"error\",\"operation\":\"open\",\"code\":" + std::to_string(GetLastError()) + "}");
            return 2;
        }
        if (!WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_LENGTH, 4096) ||
            !WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_SIZE, MAX_BYTES) ||
            !WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_TIME, 2048))
            throw std::runtime_error("cannot configure WinDivert queue");
        log.write("{\"kind\":\"ready\",\"qpc\":" + std::to_string(qpc()) +
                  ",\"qpc_frequency\":" + std::to_string(frequency) +
                  ",\"hold_ms\":" + std::to_string(config.hold_ms) +
                  ",\"second_port\":" + std::to_string(config.second_port) +
                  ",\"drop_first_syn\":" + (config.drop_first_syn ? "true" : "false") +
                  ",\"queue_length\":4096,\"queue_size\":8388608,\"queue_time_ms\":2048}");
        receiver = std::thread([this] { receive(); });
        int64_t end = qpc() + frequency * config.seconds;
        while (qpc() < end && !receive_error && !fatal_send) {
            if (!config.stop_file.empty() &&
                GetFileAttributesA(config.stop_file.c_str()) != INVALID_FILE_ATTRIBUTES) break;
            std::deque<Packet> received;
            {
                std::lock_guard<std::mutex> lock(input_mutex);
                received.swap(input);
                input_bytes = 0;
            }
            input_space.notify_all();
            for (auto& packet : received) accept(std::move(packet));
            controls();
            for (auto& entry : flows) {
                Flow& flow = *entry.second;
                flow.decision.expire(qpc());
                if (flow.decision.action != "pending") flush(entry.first, flow, "timeout_or_decision");
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        stopping = true;
        input_space.notify_all();
        WinDivertShutdown(handle, WINDIVERT_SHUTDOWN_RECV);
        receiver.join();
        for (auto& packet : input) accept(std::move(packet));
        input.clear();
        for (;;) {
            Packet packet;
            packet.bytes.resize(65535);
            UINT length = 0;
            if (!WinDivertRecv(handle, packet.bytes.data(), static_cast<UINT>(packet.bytes.size()),
                               &length, &packet.address)) {
                DWORD error = GetLastError();
                if (error != ERROR_NO_DATA) receive_error = error;
                break;
            }
            packet.received = qpc();
            packet.bytes.resize(length);
            accept(std::move(packet));
        }
        for (auto& entry : flows) {
            Flow& flow = *entry.second;
            if (flow.decision.action == "pending") flow.decision.action = "direct";
            flush(entry.first, flow, "shutdown");
        }
        if (receive_error)
            log.write("{\"kind\":\"error\",\"operation\":\"receive\",\"code\":" +
                      std::to_string(receive_error.load()) + "}");
        log.write("{\"kind\":\"complete\",\"qpc\":" + std::to_string(qpc()) +
                  ",\"flows\":" + std::to_string(flows.size()) +
                  ",\"success\":" + ((!receive_error && !fatal_send) ? "true" : "false") + "}");
        return receive_error || fatal_send ? 3 : 0;
    }
};

int main(int argc, char** argv) {
    WSADATA winsock{};
    if (WSAStartup(MAKEWORD(2, 2), &winsock)) return 1;
    int result = 1;
    try {
        Capture capture(options(argc, argv));
        result = capture.run();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
    }
    WSACleanup();
    return result;
}
#endif
