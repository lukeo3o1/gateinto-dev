#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace job_dscp_route {

struct Args {
    std::map<std::string, std::string> values;
    std::set<std::string> flags;
    std::vector<std::string> rest;
};

struct Ipv4Tcp {
    size_t ip_header = 0;
    size_t total = 0;
    uint8_t tos = 0;
    uint8_t flags = 0;
    uint32_t src = 0, dst = 0;
    uint16_t sport = 0, dport = 0;
    uint32_t seq = 0;
};

enum class Parse { ok, malformed, fragment };
enum class Action { inject, drop };

struct Flow {
    uint32_t local = 0, remote = 0;
    uint16_t local_port = 0, remote_port = 0;
    uint64_t generation = 0;
    uint32_t isn = 0;
};

class FlowTable {
public:
    explicit FlowTable(size_t capacity) : capacity_(capacity) {}
    const Flow* find(uint32_t remote, uint16_t local_port) const;
    bool full() const { return flows_.size() >= capacity_; }
    size_t size() const { return flows_.size(); }
    uint64_t next_generation() const { return generations_ + 1; }
    void insert(const Flow& flow);

private:
    static uint64_t key(uint32_t remote, uint16_t local_port) { return (uint64_t(remote) << 16) | local_port; }
    size_t capacity_;
    std::map<uint64_t, Flow> flows_;
    uint64_t generations_ = 0;
};

struct Counters {
    uint64_t captured = 0, new_flows = 0, reflected = 0, replies_restored = 0, syn_retransmits = 0,
             send_errors = 0, recv_errors = 0, checksum_errors = 0, orphan_dropped = 0, key_collisions = 0,
             unknown_reply_dropped = 0, fragment_dropped = 0, malformed_dropped = 0, table_full = 0,
             map_write_errors = 0, contained_udp = 0, contained_other = 0;
};

using RecordSink = std::function<bool(const std::string&)>;

constexpr uint8_t kTcpFin = 0x01, kTcpSyn = 0x02, kTcpRst = 0x04, kTcpPsh = 0x08, kTcpAck = 0x10;
constexpr size_t kFlowCapacity = 4096;

uint16_t read16(const uint8_t* p);
uint32_t read32(const uint8_t* p);
std::string ipv4_text(uint32_t address);
Parse parse_ipv4_tcp(const uint8_t* data, size_t length, Ipv4Tcp& out);
bool pure_syn(uint8_t flags);
void reflect_to_listener(uint8_t* packet, const Ipv4Tcp& header, uint16_t listener_port);
void restore_reply(uint8_t* packet, const Ipv4Tcp& header, uint16_t original_port);
std::string translation_json(const Flow& flow, uint16_t listener_port);
std::string counters_json(const Counters& counters);
std::string engine_filter(int listener_port);
std::string engine_filter(int listener_port, int match_dscp, bool contain);
std::string containment_json(const Counters& counters);
int ipv4_protocol(const uint8_t* data, size_t length);
bool parse_ipv4(const std::string& text, uint32_t& address);
uint32_t table_address(uint32_t value);
uint16_t table_port(uint32_t value);
Action process_packet(uint8_t* packet, size_t length, uint16_t listener_port, FlowTable& table, Counters& counters,
                      const RecordSink& sink, bool contain = false);
std::vector<uint8_t> build_packet(uint32_t src, uint32_t dst, uint16_t sport, uint16_t dport, uint8_t tos,
                                  uint8_t flags, size_t ip_options = 0, size_t payload = 0, uint8_t protocol = 6);
void fill_checksums(uint8_t* packet, size_t length);
bool checksums_valid(const uint8_t* packet, size_t length);
std::string json_string(const std::string& value);
std::string quote_arg(const std::string& value);
std::string join_command(const std::vector<std::string>& args);
Args parse_args(const std::vector<std::string>& args, const std::set<std::string>& flag_names);
int parse_int(const std::string& value, int low, int high);

uint16_t read16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }

uint32_t read32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}

static void write16(uint8_t* p, uint16_t value) {
    p[0] = static_cast<uint8_t>(value >> 8);
    p[1] = static_cast<uint8_t>(value & 0xFF);
}

static void write32(uint8_t* p, uint32_t value) {
    write16(p, static_cast<uint16_t>(value >> 16));
    write16(p + 2, static_cast<uint16_t>(value & 0xFFFF));
}

std::string ipv4_text(uint32_t address) {
    return std::to_string(address >> 24) + "." + std::to_string((address >> 16) & 0xFF) + "." +
        std::to_string((address >> 8) & 0xFF) + "." + std::to_string(address & 0xFF);
}

Parse parse_ipv4_tcp(const uint8_t* data, size_t length, Ipv4Tcp& out) {
    if (length < 20 || (data[0] >> 4) != 4) return Parse::malformed;
    const size_t ihl = size_t(data[0] & 0x0F) * 4;
    const size_t total = read16(data + 2);
    if (ihl < 20 || ihl > length || total < ihl || total > length) return Parse::malformed;
    if (read16(data + 6) & 0x3FFF) return Parse::fragment;
    if (data[9] != 6 || total - ihl < 20) return Parse::malformed;
    const size_t data_offset = size_t(data[ihl + 12] >> 4) * 4;
    if (data_offset < 20 || ihl + data_offset > total) return Parse::malformed;
    out.ip_header = ihl;
    out.total = total;
    out.tos = data[1];
    out.flags = data[ihl + 13];
    out.src = read32(data + 12);
    out.dst = read32(data + 16);
    out.sport = read16(data + ihl);
    out.dport = read16(data + ihl + 2);
    out.seq = read32(data + ihl + 4);
    return Parse::ok;
}

bool pure_syn(uint8_t flags) { return (flags & (kTcpSyn | kTcpAck | kTcpRst | kTcpFin)) == kTcpSyn; }

static void swap_addresses(uint8_t* packet) {
    for (int i = 0; i < 4; ++i) std::swap(packet[12 + i], packet[16 + i]);
}

void reflect_to_listener(uint8_t* packet, const Ipv4Tcp& header, uint16_t listener_port) {
    swap_addresses(packet);
    write16(packet + header.ip_header + 2, listener_port);
    packet[1] = static_cast<uint8_t>(packet[1] & 0x03);
}

void restore_reply(uint8_t* packet, const Ipv4Tcp& header, uint16_t original_port) {
    swap_addresses(packet);
    write16(packet + header.ip_header, original_port);
}

const Flow* FlowTable::find(uint32_t remote, uint16_t local_port) const {
    const auto found = flows_.find(key(remote, local_port));
    return found == flows_.end() ? nullptr : &found->second;
}

void FlowTable::insert(const Flow& flow) {
    flows_[key(flow.remote, flow.local_port)] = flow;
    ++generations_;
}

std::string translation_json(const Flow& flow, uint16_t listener_port) {
    return "{\"kind\":\"translation\",\"peer_ip\":\"" + ipv4_text(flow.remote) +
        "\",\"peer_port\":" + std::to_string(flow.local_port) + ",\"listener_ip\":\"" + ipv4_text(flow.local) +
        "\",\"listener_port\":" + std::to_string(listener_port) + ",\"original_ip\":\"" + ipv4_text(flow.remote) +
        "\",\"original_port\":" + std::to_string(flow.remote_port) +
        ",\"generation\":" + std::to_string(flow.generation) + "}";
}

std::string counters_json(const Counters& c) {
    const std::pair<const char*, uint64_t> fields[] = {
        {"captured", c.captured}, {"new_flows", c.new_flows}, {"reflected", c.reflected},
        {"replies_restored", c.replies_restored}, {"syn_retransmits", c.syn_retransmits},
        {"send_errors", c.send_errors}, {"recv_errors", c.recv_errors}, {"checksum_errors", c.checksum_errors},
        {"orphan_dropped", c.orphan_dropped}, {"key_collisions", c.key_collisions},
        {"unknown_reply_dropped", c.unknown_reply_dropped}, {"fragment_dropped", c.fragment_dropped},
        {"malformed_dropped", c.malformed_dropped}, {"table_full", c.table_full},
        {"map_write_errors", c.map_write_errors}};
    std::string result;
    for (const auto& field : fields) {
        if (!result.empty()) result += ',';
        result += std::string("\"") + field.first + "\":" + std::to_string(field.second);
    }
    return result;
}

std::string engine_filter(int listener_port) {
    return "outbound and !loopback and ip and tcp and (ip.TOS >= 4 or tcp.SrcPort == " +
        std::to_string(listener_port) + ")";
}

std::string engine_filter(int listener_port, int match_dscp, bool contain) {
    if (match_dscp < 0) return engine_filter(listener_port);
    const std::string range = "(ip.TOS >= " + std::to_string(match_dscp * 4) + " and ip.TOS <= " +
        std::to_string(match_dscp * 4 + 3) + ")";
    const std::string port = std::to_string(listener_port);
    if (contain) return "outbound and !loopback and ip and (" + range + " or (tcp and tcp.SrcPort == " + port + "))";
    return "outbound and !loopback and ip and tcp and (" + range + " or tcp.SrcPort == " + port + ")";
}

std::string containment_json(const Counters& c) {
    return "\"contained_udp\":" + std::to_string(c.contained_udp) + ",\"contained_other\":" +
        std::to_string(c.contained_other);
}

int ipv4_protocol(const uint8_t* data, size_t length) {
    if (length < 20 || (data[0] >> 4) != 4) return -1;
    return data[9];
}

bool parse_ipv4(const std::string& text, uint32_t& address) {
    uint32_t result = 0;
    size_t position = 0;
    for (int part = 0; part < 4; ++part) {
        if (part) {
            if (position >= text.size() || text[position] != '.') return false;
            ++position;
        }
        size_t digits = 0;
        uint32_t value = 0;
        while (position < text.size() && text[position] >= '0' && text[position] <= '9' && digits < 4) {
            value = value * 10 + uint32_t(text[position] - '0');
            ++position;
            ++digits;
        }
        if (digits == 0 || digits > 3 || value > 255) return false;
        result = (result << 8) | value;
    }
    if (position != text.size()) return false;
    address = result;
    return true;
}

uint32_t table_address(uint32_t value) {
    return ((value & 0xFF) << 24) | ((value & 0xFF00) << 8) | ((value >> 8) & 0xFF00) | (value >> 24);
}

uint16_t table_port(uint32_t value) { return static_cast<uint16_t>(((value & 0xFF) << 8) | ((value >> 8) & 0xFF)); }

Action process_packet(uint8_t* packet, size_t length, uint16_t listener_port, FlowTable& table, Counters& counters,
                      const RecordSink& sink, bool contain) {
    ++counters.captured;
    const int protocol = ipv4_protocol(packet, length);
    if (contain && protocol >= 0 && protocol != 6) {
        ++(protocol == 17 ? counters.contained_udp : counters.contained_other);
        return Action::drop;
    }
    Ipv4Tcp header;
    const Parse parsed = parse_ipv4_tcp(packet, length, header);
    if (parsed == Parse::malformed) {
        ++counters.malformed_dropped;
        return Action::drop;
    }
    if (parsed == Parse::fragment) {
        ++counters.fragment_dropped;
        return Action::drop;
    }
    if (header.sport == listener_port) {
        const Flow* flow = table.find(header.dst, header.dport);
        if (!flow) {
            ++counters.unknown_reply_dropped;
            return Action::drop;
        }
        restore_reply(packet, header, flow->remote_port);
        ++counters.replies_restored;
        return Action::inject;
    }
    const Flow* flow = table.find(header.dst, header.sport);
    const bool syn = pure_syn(header.flags);
    bool start = false;
    if (!flow) {
        if (!syn) {
            ++counters.orphan_dropped;
            return Action::drop;
        }
        if (table.full()) {
            ++counters.table_full;
            return Action::drop;
        }
        start = true;
    } else if (flow->remote_port != header.dport) {
        ++counters.key_collisions;
        return Action::drop;
    } else if (syn && header.seq == flow->isn) {
        ++counters.syn_retransmits;
    } else if (syn) {
        start = true;
    }
    if (start) {
        Flow created;
        created.local = header.src;
        created.remote = header.dst;
        created.local_port = header.sport;
        created.remote_port = header.dport;
        created.generation = table.next_generation();
        created.isn = header.seq;
        if (!sink(translation_json(created, listener_port))) {
            ++counters.map_write_errors;
            return Action::drop;
        }
        table.insert(created);
        ++counters.new_flows;
    }
    reflect_to_listener(packet, header, listener_port);
    ++counters.reflected;
    return Action::inject;
}

static uint64_t sum_words(const uint8_t* data, size_t length, uint64_t sum) {
    for (size_t i = 0; i + 1 < length; i += 2) sum += read16(data + i);
    if (length % 2) sum += uint64_t(data[length - 1]) << 8;
    return sum;
}

static uint16_t fold(uint64_t sum) {
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum & 0xFFFF);
}

static size_t checksum_offset(uint8_t protocol) { return protocol == 6 ? 16 : protocol == 17 ? 6 : 0; }

static bool checksum_layout(const uint8_t* packet, size_t length, size_t& ihl, size_t& total) {
    if (length < 20) return false;
    ihl = size_t(packet[0] & 0x0F) * 4;
    total = read16(packet + 2);
    return ihl >= 20 && ihl <= total && total <= length;
}

static uint64_t pseudo_header_sum(const uint8_t* packet, size_t transport_length) {
    return sum_words(packet + 12, 8, 0) + packet[9] + transport_length;
}

void fill_checksums(uint8_t* packet, size_t length) {
    size_t ihl = 0, total = 0;
    if (!checksum_layout(packet, length, ihl, total)) return;
    write16(packet + 10, 0);
    write16(packet + 10, fold(sum_words(packet, ihl, 0)));
    const size_t offset = checksum_offset(packet[9]);
    const size_t transport_length = total - ihl;
    if (!offset || transport_length < offset + 2) return;
    uint8_t* transport = packet + ihl;
    write16(transport + offset, 0);
    uint16_t value = fold(sum_words(transport, transport_length, pseudo_header_sum(packet, transport_length)));
    if (packet[9] == 17 && value == 0) value = 0xFFFF;
    write16(transport + offset, value);
}

bool checksums_valid(const uint8_t* packet, size_t length) {
    size_t ihl = 0, total = 0;
    if (!checksum_layout(packet, length, ihl, total) || fold(sum_words(packet, ihl, 0)) != 0) return false;
    const size_t offset = checksum_offset(packet[9]);
    const size_t transport_length = total - ihl;
    if (!offset) return true;
    if (transport_length < offset + 2) return false;
    const uint8_t* transport = packet + ihl;
    if (packet[9] == 17 && read16(transport + offset) == 0) return true;
    return fold(sum_words(transport, transport_length, pseudo_header_sum(packet, transport_length))) == 0;
}

std::vector<uint8_t> build_packet(uint32_t src, uint32_t dst, uint16_t sport, uint16_t dport, uint8_t tos,
                                  uint8_t flags, size_t ip_options, size_t payload, uint8_t protocol) {
    const size_t ihl = 20 + ip_options;
    const size_t transport = protocol == 6 ? 20 : 8;
    std::vector<uint8_t> packet(ihl + transport + payload, 0);
    uint8_t* p = packet.data();
    p[0] = static_cast<uint8_t>(0x40 | (ihl / 4));
    p[1] = tos;
    write16(p + 2, static_cast<uint16_t>(packet.size()));
    write16(p + 4, 0x1234);
    p[6] = 0x40;
    p[8] = 128;
    p[9] = protocol;
    write32(p + 12, src);
    write32(p + 16, dst);
    for (size_t i = 20; i < ihl; ++i) p[i] = 0x01;
    uint8_t* t = p + ihl;
    write16(t, sport);
    write16(t + 2, dport);
    if (protocol == 6) {
        write32(t + 4, 0x01020304);
        write32(t + 8, (flags & kTcpAck) ? 0x0A0B0C0D : 0);
        t[12] = 0x50;
        t[13] = flags;
        write16(t + 14, 0xFAF0);
    } else {
        write16(t + 4, static_cast<uint16_t>(transport + payload));
    }
    for (size_t i = 0; i < payload; ++i) t[transport + i] = static_cast<uint8_t>('a' + i % 26);
    fill_checksums(p, packet.size());
    return packet;
}

std::string json_string(const std::string& value) {
    static const char digits[] = "0123456789abcdef";
    std::string result = "\"";
    for (const char c : value) {
        const auto byte = static_cast<unsigned char>(c);
        if (c == '"') result += "\\\"";
        else if (c == '\\') result += "\\\\";
        else if (c == '\n') result += "\\n";
        else if (c == '\r') result += "\\r";
        else if (c == '\t') result += "\\t";
        else if (byte < 0x20) {
            result += "\\u00";
            result += digits[byte >> 4];
            result += digits[byte & 0xF];
        } else result += c;
    }
    return result + "\"";
}

std::string quote_arg(const std::string& value) {
    if (!value.empty() && value.find_first_of(" \t\n\v\"") == std::string::npos) return value;
    std::string result = "\"";
    for (size_t i = 0;; ++i) {
        size_t backslashes = 0;
        while (i < value.size() && value[i] == '\\') { ++i; ++backslashes; }
        if (i == value.size()) {
            result.append(backslashes * 2, '\\');
            break;
        }
        if (value[i] == '"') {
            result.append(backslashes * 2 + 1, '\\');
            result += '"';
        } else {
            result.append(backslashes, '\\');
            result += value[i];
        }
    }
    return result + "\"";
}

std::string join_command(const std::vector<std::string>& args) {
    std::string result;
    for (const auto& arg : args) {
        if (!result.empty()) result += ' ';
        result += quote_arg(arg);
    }
    return result;
}

Args parse_args(const std::vector<std::string>& args, const std::set<std::string>& flag_names) {
    Args result;
    for (size_t i = 0; i < args.size(); ++i) {
        const auto& arg = args[i];
        if (arg == "--") {
            result.rest.assign(args.begin() + static_cast<std::ptrdiff_t>(i) + 1, args.end());
            break;
        }
        if (arg.size() < 3 || arg.compare(0, 2, "--") != 0) throw std::invalid_argument("unexpected argument");
        if (result.values.count(arg) || result.flags.count(arg)) throw std::invalid_argument("duplicate option");
        if (flag_names.count(arg)) {
            result.flags.insert(arg);
            continue;
        }
        if (i + 1 >= args.size()) throw std::invalid_argument("missing option value");
        result.values[arg] = args[++i];
    }
    return result;
}

int parse_int(const std::string& value, int low, int high) {
    if (value.empty() || value.size() > 9) throw std::invalid_argument("invalid integer");
    long long result = 0;
    for (const char c : value) {
        if (c < '0' || c > '9') throw std::invalid_argument("invalid integer");
        result = result * 10 + (c - '0');
    }
    if (result < low || result > high) throw std::invalid_argument("integer out of range");
    return static_cast<int>(result);
}

static void check(bool condition, const char* what) {
    if (!condition) throw std::runtime_error(what);
}

constexpr uint32_t kLocal = 0x0A010004;
constexpr uint32_t kRemote = 0xC000020A;
constexpr uint32_t kOtherRemote = 0xC000020B;
constexpr uint16_t kListener = 8443;

static bool rejected_args(const std::vector<std::string>& args) {
    try { parse_args(args, {}); } catch (const std::invalid_argument&) { return true; }
    return false;
}

static bool rejected_int(const char* value) {
    try { parse_int(value, 0, 63); } catch (const std::invalid_argument&) { return true; }
    return false;
}

static void parse_tests() {
    auto syn = build_packet(kLocal, kRemote, 50000, 443, 0x2B, kTcpSyn);
    Ipv4Tcp h;
    check(syn.size() == 40 && parse_ipv4_tcp(syn.data(), syn.size(), h) == Parse::ok, "parse syn");
    check(h.ip_header == 20 && h.total == 40 && h.tos == 0x2B && h.flags == kTcpSyn, "syn header fields");
    check(h.src == kLocal && h.dst == kRemote && h.sport == 50000 && h.dport == 443, "syn addresses and ports");
    check(ipv4_text(h.src) == "10.1.0.4" && ipv4_text(h.dst) == "192.0.2.10", "address text");

    auto options = build_packet(kLocal, kRemote, 50001, 443, 0x28, kTcpAck | kTcpPsh, 8, 5);
    check(parse_ipv4_tcp(options.data(), options.size(), h) == Parse::ok, "parse ip options");
    check(h.ip_header == 28 && h.total == 53 && h.sport == 50001 && h.dport == 443, "ports after ip options");
    check(options[28] == 0xC3 && options[29] == 0x51, "tcp header follows options");

    auto bad = syn;
    check(parse_ipv4_tcp(syn.data(), 19, h) == Parse::malformed, "short header");
    bad[0] = 0x65;
    check(parse_ipv4_tcp(bad.data(), bad.size(), h) == Parse::malformed, "not ipv4");
    bad = syn;
    bad[0] = 0x44;
    check(parse_ipv4_tcp(bad.data(), bad.size(), h) == Parse::malformed, "ihl too small");
    bad[0] = 0x4F;
    check(parse_ipv4_tcp(bad.data(), bad.size(), h) == Parse::malformed, "ihl beyond packet");
    check(parse_ipv4_tcp(syn.data(), 39, h) == Parse::malformed, "total length beyond packet");
    bad = syn;
    bad[3] = 30;
    check(parse_ipv4_tcp(bad.data(), bad.size(), h) == Parse::malformed, "total length shorter than tcp header");
    bad = syn;
    bad[32] = 0x40;
    check(parse_ipv4_tcp(bad.data(), bad.size(), h) == Parse::malformed, "tcp data offset too small");
    bad[32] = 0x60;
    check(parse_ipv4_tcp(bad.data(), bad.size(), h) == Parse::malformed, "tcp data offset beyond packet");
    auto udp = build_packet(kLocal, kRemote, 50000, 443, 0x28, 0, 0, 4, 17);
    check(parse_ipv4_tcp(udp.data(), udp.size(), h) == Parse::malformed, "udp is not tcp");
    bad = syn;
    bad[6] = 0x20;
    check(parse_ipv4_tcp(bad.data(), bad.size(), h) == Parse::fragment, "more fragments flag");
    bad = syn;
    bad[6] = 0x40;
    bad[7] = 0x01;
    check(parse_ipv4_tcp(bad.data(), bad.size(), h) == Parse::fragment, "fragment offset");
    bad = syn;
    bad[6] = 0x40;
    bad[7] = 0x00;
    check(parse_ipv4_tcp(bad.data(), bad.size(), h) == Parse::ok, "dont fragment is not a fragment");

    check(pure_syn(kTcpSyn) && pure_syn(kTcpSyn | 0xC0), "pure syn including ecn setup");
    check(!pure_syn(kTcpSyn | kTcpAck) && !pure_syn(kTcpAck) && !pure_syn(kTcpSyn | kTcpRst) &&
          !pure_syn(kTcpSyn | kTcpFin), "not pure syn");
}

static void checksum_tests() {
    auto packet = build_packet(kLocal, kRemote, 50000, 443, 0x2B, kTcpSyn, 4, 7);
    check(checksums_valid(packet.data(), packet.size()), "built packet checksums");
    auto corrupted = packet;
    corrupted[corrupted.size() - 1] ^= 0x01;
    check(!checksums_valid(corrupted.data(), corrupted.size()), "payload corruption detected");
    corrupted = packet;
    corrupted[8] ^= 0x01;
    check(!checksums_valid(corrupted.data(), corrupted.size()), "ip header corruption detected");
    auto udp = build_packet(kLocal, kRemote, 50000, 53, 0, 0, 0, 3, 17);
    check(checksums_valid(udp.data(), udp.size()), "udp checksums");

    Ipv4Tcp h;
    check(parse_ipv4_tcp(packet.data(), packet.size(), h) == Parse::ok, "parse before rewrite");
    reflect_to_listener(packet.data(), h, kListener);
    check(!checksums_valid(packet.data(), packet.size()), "rewrite invalidates tcp checksum");
    fill_checksums(packet.data(), packet.size());
    check(checksums_valid(packet.data(), packet.size()), "recalculated checksums");
}

static void rewrite_tests() {
    auto packet = build_packet(kLocal, kRemote, 50000, 443, 0x2B, kTcpSyn, 8, 3);
    const auto original = packet;
    Ipv4Tcp h;
    parse_ipv4_tcp(packet.data(), packet.size(), h);
    reflect_to_listener(packet.data(), h, kListener);
    Ipv4Tcp r;
    check(parse_ipv4_tcp(packet.data(), packet.size(), r) == Parse::ok, "reflected parses");
    check(r.src == kRemote && r.dst == kLocal && r.sport == 50000 && r.dport == kListener, "reflected endpoints");
    check(r.tos == 0x03, "dscp cleared and ecn kept");
    check(std::vector<uint8_t>(packet.begin() + 20, packet.begin() + 28) ==
          std::vector<uint8_t>(original.begin() + 20, original.begin() + 28), "ip options kept");
    check(std::vector<uint8_t>(packet.begin() + 32, packet.end()) ==
          std::vector<uint8_t>(original.begin() + 32, original.end()), "tcp sequence, flags and payload kept");

    auto reply = build_packet(kLocal, kRemote, kListener, 50000, 0x00, kTcpSyn | kTcpAck);
    parse_ipv4_tcp(reply.data(), reply.size(), h);
    restore_reply(reply.data(), h, 443);
    check(parse_ipv4_tcp(reply.data(), reply.size(), r) == Parse::ok, "restored parses");
    check(r.src == kRemote && r.dst == kLocal && r.sport == 443 && r.dport == 50000, "restored endpoints");
    check(r.tos == 0 && r.flags == (kTcpSyn | kTcpAck), "restored keeps tos and flags");
}

static Action run(std::vector<uint8_t>& packet, FlowTable& table, Counters& counters,
                  std::vector<std::string>& records, bool sink_ok = true) {
    return process_packet(packet.data(), packet.size(), kListener, table, counters,
                          [&](const std::string& line) {
                              if (sink_ok) records.push_back(line);
                              return sink_ok;
                          });
}

static void engine_tests() {
    FlowTable table(kFlowCapacity);
    Counters c;
    std::vector<std::string> records;
    Ipv4Tcp h;

    auto syn = build_packet(kLocal, kRemote, 50000, 443, 0x28, kTcpSyn);
    check(run(syn, table, c, records) == Action::inject, "new syn injected");
    check(c.new_flows == 1 && c.reflected == 1 && records.size() == 1, "new flow recorded");
    check(records[0] == "{\"kind\":\"translation\",\"peer_ip\":\"192.0.2.10\",\"peer_port\":50000,"
                        "\"listener_ip\":\"10.1.0.4\",\"listener_port\":8443,\"original_ip\":\"192.0.2.10\","
                        "\"original_port\":443,\"generation\":1}", "translation record");
    parse_ipv4_tcp(syn.data(), syn.size(), h);
    check(h.src == kRemote && h.dst == kLocal && h.sport == 50000 && h.dport == kListener && h.tos == 0,
          "syn reflected to the listener");

    auto retransmit = build_packet(kLocal, kRemote, 50000, 443, 0x28, kTcpSyn);
    check(run(retransmit, table, c, records) == Action::inject, "retransmitted syn injected");
    check(c.syn_retransmits == 1 && c.new_flows == 1 && records.size() == 1, "retransmit keeps the flow");

    auto ack = build_packet(kLocal, kRemote, 50000, 443, 0x29, kTcpAck, 0, 10);
    check(run(ack, table, c, records) == Action::inject && c.reflected == 3, "flow data reflected");
    parse_ipv4_tcp(ack.data(), ack.size(), h);
    check(h.dport == kListener && h.tos == 0x01, "data reflected with ecn kept");

    auto reply = build_packet(kLocal, kRemote, kListener, 50000, 0, kTcpSyn | kTcpAck);
    check(run(reply, table, c, records) == Action::inject && c.replies_restored == 1, "reply restored");
    parse_ipv4_tcp(reply.data(), reply.size(), h);
    check(h.src == kRemote && h.sport == 443 && h.dst == kLocal && h.dport == 50000, "reply looks like the server");

    auto unknown = build_packet(kLocal, kRemote, kListener, 50001, 0, kTcpAck);
    check(run(unknown, table, c, records) == Action::drop && c.unknown_reply_dropped == 1, "unknown reply dropped");
    auto unknown_remote = build_packet(kLocal, kOtherRemote, kListener, 50000, 0, kTcpAck);
    check(run(unknown_remote, table, c, records) == Action::drop && c.unknown_reply_dropped == 2,
          "reply to another remote dropped");

    auto orphan = build_packet(kLocal, kRemote, 50002, 443, 0x28, kTcpAck);
    check(run(orphan, table, c, records) == Action::drop && c.orphan_dropped == 1, "non-syn orphan dropped");

    auto collision = build_packet(kLocal, kRemote, 50000, 80, 0x28, kTcpSyn);
    check(run(collision, table, c, records) == Action::drop && c.key_collisions == 1, "key collision dropped");
    check(c.new_flows == 1, "collision creates no flow");

    auto other = build_packet(kLocal, kOtherRemote, 50000, 443, 0x50, kTcpSyn);
    check(run(other, table, c, records) == Action::inject && c.new_flows == 2, "same port to another remote");
    check(records.size() == 2 && records[1].find("\"generation\":2}") != std::string::npos, "second generation");

    auto fragment = build_packet(kLocal, kRemote, 50000, 443, 0x28, kTcpAck);
    fragment[6] = 0x20;
    check(run(fragment, table, c, records) == Action::drop && c.fragment_dropped == 1, "fragment dropped");
    auto shorty = build_packet(kLocal, kRemote, 50000, 443, 0x28, kTcpAck);
    check(process_packet(shorty.data(), 30, kListener, table, c, [](const std::string&) { return true; }) ==
              Action::drop && c.malformed_dropped == 1, "short packet dropped");

    auto unrecorded = build_packet(kLocal, kRemote, 50003, 443, 0x28, kTcpSyn);
    check(run(unrecorded, table, c, records, false) == Action::drop && c.map_write_errors == 1,
          "unrecorded syn dropped");
    check(table.find(kRemote, 50003) == nullptr, "unrecorded syn creates no flow");
    unrecorded = build_packet(kLocal, kRemote, 50003, 443, 0x28, kTcpSyn);
    check(run(unrecorded, table, c, records) == Action::inject && c.new_flows == 3, "recorded on retry");
    check(c.captured == 13, "every packet counted as captured");

    FlowTable small(2);
    Counters s;
    std::vector<std::string> small_records;
    for (uint16_t port : {uint16_t(1), uint16_t(2)}) {
        auto packet = build_packet(kLocal, kRemote, port, 443, 0x28, kTcpSyn);
        check(run(packet, small, s, small_records) == Action::inject, "flow within capacity");
    }
    auto third = build_packet(kLocal, kRemote, 3, 443, 0x28, kTcpSyn);
    check(run(third, small, s, small_records) == Action::drop && s.table_full == 1 && small.size() == 2,
          "table bound");
    auto existing = build_packet(kLocal, kRemote, 2, 443, 0x28, kTcpAck);
    check(run(existing, small, s, small_records) == Action::inject, "existing flow still served when full");
}

static void format_tests() {
    check(engine_filter(8443) ==
          "outbound and !loopback and ip and tcp and (ip.TOS >= 4 or tcp.SrcPort == 8443)", "engine filter");
    Counters c;
    c.captured = 3;
    c.send_errors = 1;
    check(counters_json(c) ==
          "\"captured\":3,\"new_flows\":0,\"reflected\":0,\"replies_restored\":0,\"syn_retransmits\":0,"
          "\"send_errors\":1,\"recv_errors\":0,\"checksum_errors\":0,\"orphan_dropped\":0,\"key_collisions\":0,"
          "\"unknown_reply_dropped\":0,\"fragment_dropped\":0,\"malformed_dropped\":0,\"table_full\":0,"
          "\"map_write_errors\":0", "counters json");
    check(json_string("a\"\\\n\t\x01") == "\"a\\\"\\\\\\n\\t\\u0001\"", "json escaping");
    check(quote_arg("plain") == "plain" && quote_arg("") == "\"\"" && quote_arg("a b") == "\"a b\"", "quoting");
    check(quote_arg("C:\\dir with\\") == "\"C:\\dir with\\\\\"", "trailing backslash");
    check(quote_arg("{\"code\":\"%{http_code}\"}") == "\"{\\\"code\\\":\\\"%{http_code}\\\"}\"",
          "curl write-out format");
    check(quote_arg("*") == "*" && quote_arg("C:\\x\\y.exe") == "C:\\x\\y.exe", "unquoted values");
    check(join_command({"a b", "c"}) == "\"a b\" c", "join command");
    auto args = parse_args({"--dscp", "10", "--", "x", "--y"}, {});
    check(args.values.at("--dscp") == "10" && (args.rest == std::vector<std::string>{"x", "--y"}), "options");
    check(rejected_args({"--dscp"}) && rejected_args({"positional"}) && rejected_args({"--a", "1", "--a", "2"}),
          "invalid options");
    check(parse_int("63", 0, 63) == 63, "int range");
    for (const char* bad : {"64", "-1", "", "1x", "99999999999"}) check(rejected_int(bad), "int rejected");
}

static void reuse_tests() {
    FlowTable table(8);
    Counters c;
    std::vector<std::string> records;
    auto syn = build_packet(kLocal, kRemote, 50000, 443, 0x28, kTcpSyn);
    check(run(syn, table, c, records) == Action::inject && c.new_flows == 1, "first connection");
    auto retransmit = build_packet(kLocal, kRemote, 50000, 443, 0x28, kTcpSyn);
    check(run(retransmit, table, c, records) == Action::inject && c.syn_retransmits == 1 && c.new_flows == 1,
          "same sequence is a retransmit");
    auto reused = build_packet(kLocal, kRemote, 50000, 443, 0x28, kTcpSyn);
    reused[24] = 0x7F;
    check(run(reused, table, c, records) == Action::inject, "reused port injected");
    check(c.new_flows == 2 && c.syn_retransmits == 1 && records.size() == 2, "new sequence starts a new flow");
    check(records[1].find("\"generation\":2}") != std::string::npos, "reused port gets a new generation");
    check(table.size() == 1, "reused port replaces the flow");
    auto again = build_packet(kLocal, kRemote, 50000, 443, 0x28, kTcpSyn);
    again[24] = 0x7F;
    check(run(again, table, c, records) == Action::inject && c.syn_retransmits == 2 && c.new_flows == 2,
          "retransmit of the reused connection");
    auto other = build_packet(kLocal, kRemote, 50001, 443, 0x28, kTcpSyn);
    check(run(other, table, c, records) == Action::inject && records.back().find("\"generation\":3}") !=
          std::string::npos, "generations stay unique");
    auto collision = build_packet(kLocal, kRemote, 50000, 80, 0x28, kTcpSyn);
    collision[24] = 0x11;
    check(run(collision, table, c, records) == Action::drop && c.key_collisions == 1,
          "new sequence to another port is still a collision");
    auto unrecorded = build_packet(kLocal, kRemote, 50000, 443, 0x28, kTcpSyn);
    unrecorded[24] = 0x22;
    check(run(unrecorded, table, c, records, false) == Action::drop && c.map_write_errors == 1 &&
          c.new_flows == 3, "unrecorded reuse dropped");
}

static void option_tests() {
    check(engine_filter(8443, -1, false) == engine_filter(8443), "default filter unchanged");
    check(engine_filter(8443, 43, false) ==
          "outbound and !loopback and ip and tcp and ((ip.TOS >= 172 and ip.TOS <= 175) or tcp.SrcPort == 8443)",
          "exact match filter");
    check(engine_filter(8443, 43, true) ==
          "outbound and !loopback and ip and ((ip.TOS >= 172 and ip.TOS <= 175) or (tcp and tcp.SrcPort == 8443))",
          "containment filter");
    check(engine_filter(9000, 1, false).find("(ip.TOS >= 4 and ip.TOS <= 7)") != std::string::npos, "dscp 1");
    check(engine_filter(9000, 63, true).find("(ip.TOS >= 252 and ip.TOS <= 255)") != std::string::npos, "dscp 63");

    auto syn = build_packet(kLocal, kRemote, 50000, 443, 0xAC, kTcpSyn);
    check(ipv4_protocol(syn.data(), syn.size()) == 6, "tcp protocol");
    auto udp = build_packet(kLocal, kRemote, 50000, 443, 0xAC, 0, 0, 4, 17);
    check(ipv4_protocol(udp.data(), udp.size()) == 17, "udp protocol");
    check(ipv4_protocol(udp.data(), 19) == -1, "short header has no protocol");
    auto v6 = udp;
    v6[0] = 0x60;
    check(ipv4_protocol(v6.data(), v6.size()) == -1, "not ipv4");

    FlowTable table(16);
    Counters c;
    std::vector<std::string> records;
    auto sink = [&](const std::string& line) { records.push_back(line); return true; };
    check(process_packet(udp.data(), udp.size(), kListener, table, c, sink) == Action::drop &&
          c.malformed_dropped == 1 && c.contained_udp == 0, "udp without containment is malformed");
    check(process_packet(udp.data(), udp.size(), kListener, table, c, sink, true) == Action::drop &&
          c.contained_udp == 1, "udp contained");
    auto fragment = udp;
    fragment[6] = 0x20;
    check(process_packet(fragment.data(), fragment.size(), kListener, table, c, sink, true) == Action::drop &&
          c.contained_udp == 2 && c.fragment_dropped == 0, "udp fragment contained");
    auto icmp = build_packet(kLocal, kRemote, 0, 0, 0xAC, 0, 0, 8, 1);
    check(process_packet(icmp.data(), icmp.size(), kListener, table, c, sink, true) == Action::drop &&
          c.contained_other == 1, "other protocol contained");
    check(process_packet(syn.data(), syn.size(), kListener, table, c, sink, true) == Action::inject &&
          c.new_flows == 1 && records.size() == 1, "tcp still routed with containment");
    check(process_packet(syn.data(), 10, kListener, table, c, sink, true) == Action::drop &&
          c.malformed_dropped == 2, "short packet malformed with containment");
    check(c.captured == 6, "contained packets counted as captured");
    check(containment_json(c) == "\"contained_udp\":2,\"contained_other\":1", "containment json");
    check(counters_json(c).find("contained") == std::string::npos, "core counters unchanged");

    uint32_t address = 0;
    check(parse_ipv4("192.0.2.10", address) && address == kRemote, "parse address");
    check(parse_ipv4("0.0.0.0", address) && address == 0, "parse zero address");
    for (const char* bad : {"", "1.2.3", "1.2.3.4.5", "256.1.1.1", "a.b.c.d", "1..2.3", "1.2.3.4 ", "01234.1.1.1"})
        check(!parse_ipv4(bad, address), "invalid address rejected");
    check(table_address(0x0A0200C0) == kRemote, "table address byte order");
    check(table_port(0x0000BB01) == 443 && table_port(0xFFFF50C3) == 50000, "table port byte order");
}

int self_test() {
    reuse_tests();
    option_tests();
    parse_tests();
    checksum_tests();
    rewrite_tests();
    engine_tests();
    format_tests();
    return 0;
}

}

#ifndef _WIN32
int main() {
    try {
        job_dscp_route::self_test();
        std::puts("job-dscp-route portable self-test passed");
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "self-test failed: %s\n", error.what());
        return 1;
    }
}
#endif

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <atomic>
#include <chrono>
#include <fstream>
#include <iostream>
#include <mutex>
#include <thread>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include "windivert.h"

#pragma comment(lib, "WinDivert.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

namespace job_dscp_route {

constexpr DWORD kNetRateEnable = 0x1;
constexpr DWORD kNetRateDscpTag = 0x4;
constexpr UINT64 kDivertFlags = 0;

// Mirrors JOBOBJECT_NET_RATE_CONTROL_INFORMATION and JobObjectNetRateControlInformation (32) so the program
// does not depend on which SDK header revision guards them.
struct NetRateControl {
    DWORD64 MaxBandwidth;
    DWORD ControlFlags;
    BYTE DscpTag;
};
static_assert(sizeof(NetRateControl) == 16, "JOBOBJECT_NET_RATE_CONTROL_INFORMATION layout");
const JOBOBJECTINFOCLASS kNetRateControlClass = static_cast<JOBOBJECTINFOCLASS>(32);

static const char* json_bool(bool value) { return value ? "true" : "false"; }

static std::vector<std::string> arguments(int argc, char** argv, int first) {
    std::vector<std::string> result;
    for (int i = first; i < argc; ++i) result.emplace_back(argv[i]);
    return result;
}

static const std::string& required(const Args& args, const char* name) {
    const auto found = args.values.find(name);
    if (found == args.values.end()) throw std::invalid_argument(std::string("missing ") + name);
    return found->second;
}

static const std::string* value_or_null(const Args& args, const char* name) {
    const auto found = args.values.find(name);
    return found == args.values.end() ? nullptr : &found->second;
}

static WINDIVERT_ADDRESS network_address(bool outbound, bool loopback) {
    WINDIVERT_ADDRESS address{};
    address.Layer = WINDIVERT_LAYER_NETWORK;
    address.Outbound = outbound ? 1 : 0;
    address.Loopback = loopback ? 1 : 0;
    return address;
}

static void compile_filter(const std::string& filter) {
    const char* error = nullptr;
    UINT position = 0;
    if (!WinDivertHelperCompileFilter(filter.c_str(), WINDIVERT_LAYER_NETWORK, nullptr, 0, &error, &position))
        throw std::runtime_error("WinDivert filter compilation: " + std::string(error ? error : "unknown") + " at " +
                                 std::to_string(position));
}

static void check_filter(const char* name, const std::string& filter, std::vector<uint8_t> packet, bool outbound,
                         bool loopback, bool expected) {
    WINDIVERT_ADDRESS address = network_address(outbound, loopback);
    if (!WinDivertHelperCalcChecksums(packet.data(), static_cast<UINT>(packet.size()), &address, 0))
        throw std::runtime_error(std::string("WinDivert checksum helper: ") + name);
    SetLastError(ERROR_SUCCESS);
    const BOOL matched = WinDivertHelperEvalFilter(filter.c_str(), packet.data(), static_cast<UINT>(packet.size()),
                                                   &address);
    const DWORD error = GetLastError();
    if (bool(matched) != expected || (!matched && error != ERROR_SUCCESS))
        throw std::runtime_error(std::string("WinDivert filter evaluation: ") + name + " matched=" +
                                 std::to_string(matched) + " error=" + std::to_string(error));
}

static void check_windivert_checksums(const char* name, std::vector<uint8_t> packet) {
    auto portable = packet;
    fill_checksums(portable.data(), portable.size());
    WINDIVERT_ADDRESS address = network_address(false, false);
    if (!WinDivertHelperCalcChecksums(packet.data(), static_cast<UINT>(packet.size()), &address, 0))
        throw std::runtime_error(std::string("WinDivert checksum helper: ") + name);
    check(checksums_valid(packet.data(), packet.size()), name);
    check(packet == portable, name);
}

static int windows_self_test() {
    self_test();
    const std::string filter = engine_filter(kListener);
    compile_filter(filter);
    check_filter("tagged outbound syn", filter, build_packet(kLocal, kRemote, 50000, 443, 0x28, kTcpSyn), true,
                 false, true);
    check_filter("tagged outbound data", filter, build_packet(kLocal, kRemote, 50000, 443, 0x52, kTcpAck, 0, 9),
                 true, false, true);
    check_filter("untagged outbound", filter, build_packet(kLocal, kRemote, 50000, 443, 0x00, kTcpSyn), true,
                 false, false);
    check_filter("ecn only", filter, build_packet(kLocal, kRemote, 50000, 443, 0x03, kTcpSyn), true, false, false);
    check_filter("tagged loopback", filter, build_packet(kLocal, kLocal, 50000, 443, 0x28, kTcpSyn), true, true,
                 false);
    check_filter("tagged inbound", filter, build_packet(kRemote, kLocal, 443, 50000, 0x28, kTcpAck), false, false,
                 false);
    check_filter("tagged udp", filter, build_packet(kLocal, kRemote, 50000, 443, 0x28, 0, 0, 4, 17), true, false,
                 false);
    check_filter("listener reply", filter,
                 build_packet(kLocal, kRemote, kListener, 50000, 0x00, kTcpSyn | kTcpAck), true, false, true);
    check_filter("listener reply on loopback", filter,
                 build_packet(kLocal, kLocal, kListener, 50000, 0x00, kTcpAck), true, true, false);
    check_filter("other source port", filter, build_packet(kLocal, kRemote, kListener + 1, 50000, 0x00, kTcpAck),
                 true, false, false);

    const std::string exact = engine_filter(kListener, 43, false);
    compile_filter(exact);
    check_filter("exact dscp 43", exact, build_packet(kLocal, kRemote, 50000, 443, 0xAC, kTcpSyn), true, false, true);
    check_filter("exact dscp 43 with ecn", exact, build_packet(kLocal, kRemote, 50000, 443, 0xAF, kTcpAck), true,
                 false, true);
    check_filter("exact rejects dscp 10", exact, build_packet(kLocal, kRemote, 50000, 443, 0x28, kTcpSyn), true,
                 false, false);
    check_filter("exact rejects dscp 42", exact, build_packet(kLocal, kRemote, 50000, 443, 0xAB, kTcpSyn), true,
                 false, false);
    check_filter("exact rejects dscp 44", exact, build_packet(kLocal, kRemote, 50000, 443, 0xB0, kTcpSyn), true,
                 false, false);
    check_filter("exact rejects untagged", exact, build_packet(kLocal, kRemote, 50000, 443, 0x00, kTcpSyn), true,
                 false, false);
    check_filter("exact listener reply", exact, build_packet(kLocal, kRemote, kListener, 50000, 0, kTcpAck), true,
                 false, true);
    check_filter("exact ignores udp", exact, build_packet(kLocal, kRemote, 50000, 443, 0xAC, 0, 0, 4, 17), true,
                 false, false);
    check_filter("exact ignores loopback", exact, build_packet(kLocal, kLocal, 50000, 443, 0xAC, kTcpSyn), true,
                 true, false);
    const std::string contain = engine_filter(kListener, 43, true);
    compile_filter(contain);
    check_filter("contain tcp 43", contain, build_packet(kLocal, kRemote, 50000, 443, 0xAC, kTcpSyn), true, false,
                 true);
    check_filter("contain udp 43", contain, build_packet(kLocal, kRemote, 50000, 443, 0xAC, 0, 0, 4, 17), true,
                 false, true);
    check_filter("contain icmp 43", contain, build_packet(kLocal, kRemote, 0, 0, 0xAC, 0, 0, 8, 1), true, false,
                 true);
    check_filter("contain ignores udp 10", contain, build_packet(kLocal, kRemote, 50000, 443, 0x28, 0, 0, 4, 17),
                 true, false, false);
    check_filter("contain ignores untagged udp", contain,
                 build_packet(kLocal, kRemote, 50000, 443, 0x00, 0, 0, 4, 17), true, false, false);
    check_filter("contain ignores untagged udp from listener port", contain,
                 build_packet(kLocal, kRemote, kListener, 443, 0x00, 0, 0, 4, 17), true, false, false);
    check_filter("contain listener reply", contain, build_packet(kLocal, kRemote, kListener, 50000, 0, kTcpAck),
                 true, false, true);
    check_filter("contain ignores loopback udp", contain,
                 build_packet(kLocal, kLocal, 50000, 443, 0xAC, 0, 0, 4, 17), true, true, false);

    FlowTable table(4);
    Counters counters;
    auto forward = build_packet(kLocal, kRemote, 50000, 443, 0x2B, kTcpSyn, 8, 13);
    check(process_packet(forward.data(), forward.size(), kListener, table, counters,
                         [](const std::string&) { return true; }) == Action::inject, "reflect for checksum");
    check_filter("reflected packet is inbound", filter, forward, false, false, false);
    check_windivert_checksums("reflected checksums", forward);
    auto reply = build_packet(kLocal, kRemote, kListener, 50000, 0x00, kTcpAck | kTcpPsh, 0, 101);
    check(process_packet(reply.data(), reply.size(), kListener, table, counters,
                         [](const std::string&) { return true; }) == Action::inject, "restore for checksum");
    check_windivert_checksums("restored checksums", reply);
    std::cout << "{\"kind\":\"self_test\",\"passed\":true}" << std::endl;
    return 0;
}

static int env_command() {
    OSVERSIONINFOEXW version{};
    version.dwOSVersionInfoSize = sizeof version;
    bool version_ok = false;
    if (const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll")) {
        using RtlGetVersionFn = LONG(WINAPI*)(OSVERSIONINFOW*);
        const auto rtl_get_version = reinterpret_cast<RtlGetVersionFn>(
            reinterpret_cast<void*>(GetProcAddress(ntdll, "RtlGetVersion")));
        version_ok = rtl_get_version && rtl_get_version(reinterpret_cast<OSVERSIONINFOW*>(&version)) == 0;
    }
    DWORD ubr = 0, ubr_size = sizeof ubr;
    const bool ubr_ok = RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"UBR",
                                     RRF_RT_REG_DWORD, nullptr, &ubr, &ubr_size) == ERROR_SUCCESS;
    bool elevated = false;
    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elevation{};
        DWORD returned = 0;
        elevated = GetTokenInformation(token, TokenElevation, &elevation, sizeof elevation, &returned) &&
            elevation.TokenIsElevated;
        CloseHandle(token);
    }
    BOOL in_job = FALSE;
    const bool in_job_ok = IsProcessInJob(GetCurrentProcess(), nullptr, &in_job) != FALSE;
    std::cout << "{\"kind\":\"env\",\"version_ok\":" << json_bool(version_ok)
              << ",\"os_major\":" << version.dwMajorVersion << ",\"os_minor\":" << version.dwMinorVersion
              << ",\"os_build\":" << version.dwBuildNumber << ",\"os_ubr\":" << (ubr_ok ? std::to_string(ubr) : "null")
              << ",\"product_type\":" << unsigned(version.wProductType) << ",\"elevated\":" << json_bool(elevated)
              << ",\"in_job\":" << (in_job_ok ? json_bool(in_job != FALSE) : "null") << "}" << std::endl;
    return 0;
}

struct Step {
    bool ok = false;
    DWORD error = 0;
    void record(bool success) {
        ok = success;
        error = success ? 0 : GetLastError();
    }
};

// The child inherits exactly these three handles through PROC_THREAD_ATTRIBUTE_HANDLE_LIST, so inheritable
// handles this process received from its own parent never leak into the job.
class Redirect {
public:
    HANDLE handles[3] = {INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE};
    LPPROC_THREAD_ATTRIBUTE_LIST list = nullptr;

    bool open(const std::string* out, const std::string* err) {
        handles[0] = open_file(nullptr, false);
        handles[1] = open_file(out, true);
        handles[2] = open_file(err, true);
        for (const HANDLE handle : handles)
            if (handle == INVALID_HANDLE_VALUE) return false;
        SIZE_T size = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
        if (size == 0) return false;
        storage_.resize(size);
        const auto candidate = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage_.data());
        if (!InitializeProcThreadAttributeList(candidate, 1, 0, &size)) return false;
        list = candidate;
        return UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles, sizeof handles,
                                         nullptr, nullptr) != FALSE;
    }

    ~Redirect() {
        if (list) DeleteProcThreadAttributeList(list);
        for (const HANDLE handle : handles)
            if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
    }

private:
    std::vector<uint8_t> storage_;

    static HANDLE open_file(const std::string* path, bool write) {
        SECURITY_ATTRIBUTES security{};
        security.nLength = sizeof security;
        security.bInheritHandle = TRUE;
        if (!path)
            return CreateFileA("NUL", write ? GENERIC_WRITE : GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        return CreateFileA(path->c_str(), GENERIC_WRITE, FILE_SHARE_READ, &security, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    }
};

static void configure_job(HANDLE job, int dscp, Step& kill_step, Step& dscp_step, Step& readback_step,
                          NetRateControl& readback) {
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    kill_step.record(SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof limits));
    NetRateControl rate{};
    rate.ControlFlags = kNetRateEnable | kNetRateDscpTag;
    rate.DscpTag = static_cast<BYTE>(dscp);
    dscp_step.record(SetInformationJobObject(job, kNetRateControlClass, &rate, sizeof rate));
    DWORD returned = 0;
    readback_step.record(QueryInformationJobObject(job, kNetRateControlClass, &readback, sizeof readback, &returned));
}

static int launch_command(const Args& args) {
    const int dscp = parse_int(required(args, "--dscp"), 0, 63);
    if (args.rest.empty()) throw std::invalid_argument("missing child command line");
    const std::string* out = value_or_null(args, "--stdout");
    const std::string* err = value_or_null(args, "--stderr");
    const std::string* job_name = value_or_null(args, "--job-name");
    for (const auto& entry : args.values)
        if (entry.first != "--dscp" && entry.first != "--stdout" && entry.first != "--stderr" &&
            entry.first != "--job-name")
            throw std::invalid_argument("unexpected option");
    const bool redirected = out || err;
    Step job_step, kill_step, dscp_step, readback_step, redirect_step, create_step, assign_step, resume_step;
    NetRateControl readback{};
    HANDLE job = nullptr;
    if (job_name) {
        job = OpenJobObjectA(JOB_OBJECT_ASSIGN_PROCESS | JOB_OBJECT_QUERY, FALSE, job_name->c_str());
        job_step.record(job != nullptr);
        if (job) {
            DWORD returned = 0;
            readback_step.record(
                QueryInformationJobObject(job, kNetRateControlClass, &readback, sizeof readback, &returned));
        }
    } else {
        job = CreateJobObjectW(nullptr, nullptr);
        job_step.record(job != nullptr);
        if (job) configure_job(job, dscp, kill_step, dscp_step, readback_step, readback);
    }
    Redirect redirect;
    if (redirected) redirect_step.record(redirect.open(out, err));
    else redirect_step.ok = true;
    bool child_ran = false;
    DWORD child_exit = 0;
    const bool tagged = readback_step.ok && (job_name || (kill_step.ok && dscp_step.ok)) &&
        (readback.ControlFlags & (kNetRateEnable | kNetRateDscpTag)) == (kNetRateEnable | kNetRateDscpTag) &&
        readback.DscpTag == dscp;
    const auto emit = [&](const char* kind) {
        std::cout << "{\"kind\":\"" << kind << "\",\"dscp\":" << dscp << (job_name ? ",\"shared_job\":true" : "")
                  << ",\"job_created\":" << json_bool(job_step.ok) << ",\"job_error\":" << job_step.error
                  << ",\"kill_on_close_set\":" << json_bool(kill_step.ok)
                  << ",\"kill_on_close_error\":" << kill_step.error
                  << ",\"dscp_set\":" << json_bool(dscp_step.ok) << ",\"dscp_error\":" << dscp_step.error
                  << ",\"readback_ok\":" << json_bool(readback_step.ok) << ",\"readback_error\":" << readback_step.error
                  << ",\"readback_flags\":" << readback.ControlFlags
                  << ",\"readback_dscp\":" << unsigned(readback.DscpTag)
                  << ",\"redirected\":" << json_bool(redirected) << ",\"redirect_ok\":" << json_bool(redirect_step.ok)
                  << ",\"redirect_error\":" << redirect_step.error
                  << ",\"process_created\":" << json_bool(create_step.ok) << ",\"process_error\":" << create_step.error
                  << ",\"assigned\":" << json_bool(assign_step.ok) << ",\"assign_error\":" << assign_step.error
                  << ",\"resumed\":" << json_bool(resume_step.ok) << ",\"resume_error\":" << resume_step.error
                  << ",\"child_ran\":" << json_bool(child_ran) << ",\"child_exit_code\":" << child_exit << "}"
                  << std::endl;
    };
    if (job && tagged && redirect_step.ok) {
        std::string command = join_command(args.rest);
        std::vector<char> buffer(command.begin(), command.end());
        buffer.push_back('\0');
        STARTUPINFOEXA startup{};
        startup.StartupInfo.cb = static_cast<DWORD>(redirected ? sizeof(STARTUPINFOEXA) : sizeof(STARTUPINFOA));
        if (redirected) {
            startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            startup.StartupInfo.hStdInput = redirect.handles[0];
            startup.StartupInfo.hStdOutput = redirect.handles[1];
            startup.StartupInfo.hStdError = redirect.handles[2];
            startup.lpAttributeList = redirect.list;
        }
        const DWORD creation = CREATE_SUSPENDED | (redirected ? EXTENDED_STARTUPINFO_PRESENT : 0);
        PROCESS_INFORMATION process{};
        create_step.record(CreateProcessA(nullptr, buffer.data(), nullptr, nullptr, redirected ? TRUE : FALSE,
                                          creation, nullptr, nullptr, &startup.StartupInfo, &process));
        if (create_step.ok) {
            assign_step.record(AssignProcessToJobObject(job, process.hProcess));
            emit("launch_setup");
            if (assign_step.ok) resume_step.record(ResumeThread(process.hThread) != static_cast<DWORD>(-1));
            if (assign_step.ok && resume_step.ok) {
                WaitForSingleObject(process.hProcess, INFINITE);
                child_ran = GetExitCodeProcess(process.hProcess, &child_exit) != FALSE;
            } else {
                TerminateProcess(process.hProcess, 1);
                WaitForSingleObject(process.hProcess, 5000);
            }
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
        }
    }
    if (job) CloseHandle(job);
    emit("launch");
    return child_ran ? static_cast<int>(child_exit) : 125;
}

static int session_command(const Args& args) {
    const int dscp = parse_int(required(args, "--dscp"), 1, 63);
    const std::string& name = required(args, "--job-name");
    const std::string& stop_file = required(args, "--stop-file");
    const int max_seconds = parse_int(required(args, "--max-seconds"), 1, 3600);
    if (!args.rest.empty()) throw std::invalid_argument("unexpected arguments");
    Step job_step, kill_step, dscp_step, readback_step;
    NetRateControl readback{};
    SetLastError(ERROR_SUCCESS);
    HANDLE job = CreateJobObjectA(nullptr, name.c_str());
    job_step.record(job != nullptr && GetLastError() != ERROR_ALREADY_EXISTS);
    if (job_step.ok) configure_job(job, dscp, kill_step, dscp_step, readback_step, readback);
    const bool ready = job_step.ok && kill_step.ok && dscp_step.ok && readback_step.ok &&
        (readback.ControlFlags & (kNetRateEnable | kNetRateDscpTag)) == (kNetRateEnable | kNetRateDscpTag) &&
        readback.DscpTag == dscp;
    std::cout << "{\"kind\":\"session\",\"dscp\":" << dscp
              << ",\"job_created\":" << json_bool(job_step.ok) << ",\"job_error\":" << job_step.error
              << ",\"kill_on_close_set\":" << json_bool(kill_step.ok) << ",\"kill_on_close_error\":" << kill_step.error
              << ",\"dscp_set\":" << json_bool(dscp_step.ok) << ",\"dscp_error\":" << dscp_step.error
              << ",\"readback_ok\":" << json_bool(readback_step.ok) << ",\"readback_error\":" << readback_step.error
              << ",\"readback_flags\":" << readback.ControlFlags << ",\"readback_dscp\":" << unsigned(readback.DscpTag)
              << ",\"ready\":" << json_bool(ready) << "}" << std::endl;
    bool timed_out = false;
    if (ready) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(max_seconds);
        while (GetFileAttributesA(stop_file.c_str()) == INVALID_FILE_ATTRIBUTES) {
            if (std::chrono::steady_clock::now() >= deadline) {
                timed_out = true;
                break;
            }
            Sleep(20);
        }
    }
    if (job) CloseHandle(job);
    std::cout << "{\"kind\":\"session_end\",\"timed_out\":" << json_bool(timed_out) << "}" << std::endl;
    return ready && !timed_out ? 0 : 2;
}

static std::vector<std::string> split(const std::string& text, char separator) {
    std::vector<std::string> parts;
    size_t start = 0;
    for (;;) {
        const size_t end = text.find(separator, start);
        parts.push_back(text.substr(start, end == std::string::npos ? std::string::npos : end - start));
        if (end == std::string::npos) return parts;
        start = end + 1;
    }
}

static uint32_t required_ipv4(const Args& args, const char* name) {
    uint32_t address = 0;
    if (!parse_ipv4(required(args, name), address)) throw std::invalid_argument(std::string("invalid ") + name);
    return address;
}

static int owner_command(const Args& args) {
    const uint32_t local = required_ipv4(args, "--local");
    const uint32_t remote = required_ipv4(args, "--remote");
    const int local_port = parse_int(required(args, "--local-port"), 1, 65535);
    const int remote_port = parse_int(required(args, "--remote-port"), 1, 65535);
    const std::vector<std::string> jobs = split(required(args, "--jobs"), ',');
    if (!args.rest.empty()) throw std::invalid_argument("unexpected arguments");
    ULONG size = 0;
    DWORD result = GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    std::vector<uint8_t> buffer;
    for (int attempt = 0; attempt < 4 && result == ERROR_INSUFFICIENT_BUFFER; ++attempt) {
        buffer.resize(size_t(size) + 4096);
        size = static_cast<ULONG>(buffer.size());
        result = GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    }
    DWORD pid = 0;
    unsigned rows = 0;
    if (result == NO_ERROR && !buffer.empty()) {
        const auto* table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buffer.data());
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const MIB_TCPROW_OWNER_PID& row = table->table[i];
            if (table_address(row.dwLocalAddr) == local && table_port(row.dwLocalPort) == local_port &&
                table_address(row.dwRemoteAddr) == remote && table_port(row.dwRemotePort) == remote_port) {
                pid = row.dwOwningPid;
                ++rows;
            }
        }
    }
    const DWORD table_error = result == NO_ERROR && buffer.empty() ? ERROR_INSUFFICIENT_BUFFER : result;
    HANDLE process = nullptr;
    DWORD process_error = 0;
    if (rows == 1) {
        process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!process) process_error = GetLastError();
    }
    std::string results;
    for (const auto& name : jobs) {
        DWORD open_error = 0, query_error = 0;
        const char* in_job = "null";
        if (process) {
            HANDLE job = OpenJobObjectA(JOB_OBJECT_QUERY, FALSE, name.c_str());
            if (!job) {
                open_error = GetLastError();
            } else {
                BOOL member = FALSE;
                if (IsProcessInJob(process, job, &member)) in_job = json_bool(member != FALSE);
                else query_error = GetLastError();
                CloseHandle(job);
            }
        }
        if (!results.empty()) results += ',';
        results += std::string("{\"in_job\":") + in_job + ",\"open_error\":" + std::to_string(open_error) +
            ",\"query_error\":" + std::to_string(query_error) + "}";
    }
    if (process) CloseHandle(process);
    std::cout << "{\"kind\":\"owner\",\"table_error\":" << table_error << ",\"rows\":" << rows
              << ",\"found\":" << json_bool(rows == 1) << ",\"process_error\":" << process_error
              << ",\"jobs\":[" << results << "]}" << std::endl;
    return 0;
}

static int udp_send_command(const Args& args) {
    const uint32_t target = required_ipv4(args, "--target");
    const int port = parse_int(required(args, "--port"), 1, 65535);
    const int count = parse_int(required(args, "--count"), 1, 100);
    const int interval_ms = parse_int(required(args, "--interval-ms"), 0, 5000);
    if (!args.rest.empty()) throw std::invalid_argument("unexpected arguments");
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) throw std::runtime_error("WSAStartup");
    int sent = 0, local_port = 0, error = 0;
    const SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) {
        error = WSAGetLastError();
    } else {
        sockaddr_in local{};
        local.sin_family = AF_INET;
        local.sin_addr.s_addr = htonl(INADDR_ANY);
        sockaddr_in bound{};
        int bound_length = sizeof bound;
        if (bind(s, reinterpret_cast<const sockaddr*>(&local), sizeof local) == SOCKET_ERROR ||
            getsockname(s, reinterpret_cast<sockaddr*>(&bound), &bound_length) == SOCKET_ERROR) {
            error = WSAGetLastError();
        } else {
            local_port = ntohs(bound.sin_port);
            sockaddr_in destination{};
            destination.sin_family = AF_INET;
            destination.sin_port = htons(static_cast<u_short>(port));
            destination.sin_addr.s_addr = htonl(target);
            static const char payload[] = "gateinto-job-dscp-route";
            for (int i = 0; i < count; ++i) {
                if (i) Sleep(static_cast<DWORD>(interval_ms));
                const int result = sendto(s, payload, static_cast<int>(sizeof payload - 1), 0,
                                          reinterpret_cast<const sockaddr*>(&destination), sizeof destination);
                if (result == static_cast<int>(sizeof payload - 1)) ++sent;
                else error = WSAGetLastError();
            }
        }
        closesocket(s);
    }
    WSACleanup();
    std::cout << "{\"kind\":\"udp_send\",\"local_port\":" << local_port << ",\"sent\":" << sent
              << ",\"error\":" << error << "}" << std::endl;
    return sent == count ? 0 : 1;
}

class Engine {
    HANDLE handle = INVALID_HANDLE_VALUE;
    std::timed_mutex lock;
    FlowTable table{kFlowCapacity};
    Counters counters;
    DWORD last_error = 0;
    std::ofstream map_file;
    uint16_t listener_port = 0;
    int match_dscp = -1;
    bool contain = false;
    std::atomic<bool> done{false};

    void receive() {
        std::vector<uint8_t> buffer(WINDIVERT_MTU_MAX);
        const RecordSink sink = [this](const std::string& line) {
            map_file << line << '\n';
            map_file.flush();
            return static_cast<bool>(map_file);
        };
        for (;;) {
            WINDIVERT_ADDRESS address{};
            UINT length = 0;
            if (!WinDivertRecv(handle, buffer.data(), static_cast<UINT>(buffer.size()), &length, &address)) {
                const DWORD error = GetLastError();
                if (error == ERROR_NO_DATA) break;
                std::lock_guard<std::timed_mutex> guard(lock);
                ++counters.recv_errors;
                last_error = error;
                if (error == ERROR_INSUFFICIENT_BUFFER) continue;
                break;
            }
            Action action = Action::drop;
            {
                std::lock_guard<std::timed_mutex> guard(lock);
                action = process_packet(buffer.data(), length, listener_port, table, counters, sink, contain);
            }
            if (action == Action::drop) continue;
            address.Outbound = 0;
            if (!WinDivertHelperCalcChecksums(buffer.data(), length, &address, 0)) {
                std::lock_guard<std::timed_mutex> guard(lock);
                ++counters.checksum_errors;
                continue;
            }
            if (!WinDivertSend(handle, buffer.data(), length, nullptr, &address)) {
                const DWORD error = GetLastError();
                std::lock_guard<std::timed_mutex> guard(lock);
                ++counters.send_errors;
                last_error = error;
            }
        }
    }

public:
    int run(const Args& args) {
        listener_port = static_cast<uint16_t>(parse_int(required(args, "--listener-port"), 1, 65535));
        const std::string& stop_file = required(args, "--stop-file");
        const int max_seconds = parse_int(required(args, "--max-seconds"), 1, 3600);
        if (const std::string* match = value_or_null(args, "--match-dscp")) match_dscp = parse_int(*match, 1, 63);
        contain = args.flags.count("--contain") != 0;
        if (contain && match_dscp < 0) throw std::invalid_argument("--contain requires --match-dscp");
        map_file.open(required(args, "--map"), std::ios::trunc);
        if (!map_file) throw std::runtime_error("map output");
        DWORD open_error = 0, shutdown_error = 0;
        unsigned param_errors = 0;
        bool timed_out = false, stop_timeout = false;
        const std::string filter = engine_filter(listener_port, match_dscp, contain);
        handle = WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_NETWORK, 0, kDivertFlags);
        if (handle == INVALID_HANDLE_VALUE) {
            open_error = GetLastError();
            if (open_error == 0) open_error = ERROR_GEN_FAILURE;
        } else {
            const std::pair<WINDIVERT_PARAM, UINT64> params[] = {
                {WINDIVERT_PARAM_QUEUE_LENGTH, WINDIVERT_PARAM_QUEUE_LENGTH_MAX},
                {WINDIVERT_PARAM_QUEUE_TIME, WINDIVERT_PARAM_QUEUE_TIME_MAX},
                {WINDIVERT_PARAM_QUEUE_SIZE, WINDIVERT_PARAM_QUEUE_SIZE_MAX}};
            for (const auto& param : params)
                if (!WinDivertSetParam(handle, param.first, param.second)) ++param_errors;
            std::cout << "{\"kind\":\"ready\"}" << std::endl;
            std::thread receiver([this] {
                try {
                    receive();
                } catch (...) {
                    std::lock_guard<std::timed_mutex> guard(lock);
                    ++counters.recv_errors;
                    last_error = ERROR_GEN_FAILURE;
                }
                done = true;
            });
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(max_seconds);
            while (!done && GetFileAttributesA(stop_file.c_str()) == INVALID_FILE_ATTRIBUTES) {
                if (std::chrono::steady_clock::now() >= deadline) {
                    timed_out = true;
                    break;
                }
                Sleep(20);
            }
            if (!WinDivertShutdown(handle, WINDIVERT_SHUTDOWN_RECV)) shutdown_error = GetLastError();
            const auto stop_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
            while (!done && std::chrono::steady_clock::now() < stop_deadline) Sleep(10);
            if (done) {
                receiver.join();
                WinDivertClose(handle);
            } else {
                stop_timeout = true;
                receiver.detach();
            }
        }
        std::unique_lock<std::timed_mutex> guard(lock, std::defer_lock);
        if (!guard.try_lock_for(std::chrono::seconds(1))) stop_timeout = true;
        const Counters snapshot = counters;
        const DWORD last = last_error;
        const bool clean = !open_error && !shutdown_error && !timed_out && !stop_timeout && !snapshot.recv_errors &&
            !snapshot.checksum_errors && !snapshot.map_write_errors;
        std::cout << "{\"kind\":\"summary\"," << counters_json(snapshot) << ",\"open_error\":" << open_error
                  << ",\"param_errors\":" << param_errors << ",\"shutdown_error\":" << shutdown_error
                  << ",\"last_error\":" << last
                  << (match_dscp < 0 ? "" : ",\"match_dscp\":" + std::to_string(match_dscp))
                  << (contain ? "," + containment_json(snapshot) : "")
                  << ",\"timed_out\":" << json_bool(timed_out) << ",\"stop_timeout\":" << json_bool(stop_timeout)
                  << "}" << std::endl;
        const int code = clean ? 0 : 2;
        if (stop_timeout) TerminateProcess(GetCurrentProcess(), static_cast<UINT>(code));
        return code;
    }
};

static int dispatch(int argc, char** argv) {
    if (argc < 2) throw std::invalid_argument("missing command");
    const std::string command = argv[1];
    if (command == "self-test" && argc == 2) return windows_self_test();
    if (command == "env" && argc == 2) return env_command();
    if (command == "launch") return launch_command(parse_args(arguments(argc, argv, 2), {}));
    if (command == "session") return session_command(parse_args(arguments(argc, argv, 2), {}));
    if (command == "owner") return owner_command(parse_args(arguments(argc, argv, 2), {}));
    if (command == "udp-send") return udp_send_command(parse_args(arguments(argc, argv, 2), {}));
    if (command == "engine") {
        const Args args = parse_args(arguments(argc, argv, 2), {"--contain"});
        if (!args.rest.empty()) throw std::invalid_argument("unexpected arguments");
        Engine engine;
        return engine.run(args);
    }
    throw std::invalid_argument("unknown command");
}

}

int main(int argc, char** argv) {
    try {
        return job_dscp_route::dispatch(argc, argv);
    } catch (const std::exception& error) {
        std::cerr << "job-dscp-route error: " << error.what() << std::endl;
        return 2;
    } catch (...) {
        std::cerr << "job-dscp-route error" << std::endl;
        return 2;
    }
}
#endif
