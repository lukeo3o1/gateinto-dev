#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace job_dscp {

struct Packet {
    int version = 0;
    int protocol = -1;
    std::string src, dst;
    int sport = -1, dport = -1;
    int tos = 0;
    bool syn = false, ack = false, fin = false, rst = false;
};

struct Args {
    std::map<std::string, std::string> values;
    std::set<std::string> flags;
    std::vector<std::string> rest;
};

std::optional<Packet> parse_packet(const uint8_t* data, size_t length);
int dscp_of(int tos);
std::string json_string(const std::string& value);
std::string quote_arg(const std::string& value);
std::string join_command(const std::vector<std::string>& args);
Args parse_args(const std::vector<std::string>& args, const std::set<std::string>& flag_names);
std::string packet_json(const Packet& packet, const std::string& label, uint64_t seq, unsigned length,
                        bool loopback, bool outbound);
int parse_int(const std::string& value, int low, int high);
int spawn_depth(const Args& args);
std::vector<std::string> respawn_args(const std::vector<std::string>& args, int depth);
std::optional<std::string> option_value(const std::vector<std::string>& args, const std::string& name);
bool append_line(const std::string& path, const std::string& line);

int dscp_of(int tos) { return (tos & 0xFF) >> 2; }

static std::string ipv4_text(const uint8_t* a) {
    return std::to_string(a[0]) + "." + std::to_string(a[1]) + "." + std::to_string(a[2]) + "." +
        std::to_string(a[3]);
}

static std::string ipv6_text(const uint8_t* a) {
    static const char digits[] = "0123456789abcdef";
    std::string result;
    for (int group = 0; group < 8; ++group) {
        if (group) result += ':';
        const unsigned value = (unsigned(a[group * 2]) << 8) | a[group * 2 + 1];
        bool started = false;
        for (int shift = 12; shift >= 0; shift -= 4) {
            const unsigned nibble = (value >> shift) & 0xF;
            if (nibble || started || shift == 0) {
                result += digits[nibble];
                started = true;
            }
        }
    }
    return result;
}

static void parse_transport(Packet& packet, const uint8_t* data, size_t length) {
    if ((packet.protocol == 6 || packet.protocol == 17) && length >= 4) {
        packet.sport = (data[0] << 8) | data[1];
        packet.dport = (data[2] << 8) | data[3];
    }
    if (packet.protocol == 6 && length >= 14) {
        const uint8_t flags = data[13];
        packet.fin = flags & 0x01;
        packet.syn = flags & 0x02;
        packet.rst = flags & 0x04;
        packet.ack = flags & 0x10;
    }
}

std::optional<Packet> parse_packet(const uint8_t* data, size_t length) {
    if (length < 1) return std::nullopt;
    Packet packet;
    const int version = data[0] >> 4;
    if (version == 4) {
        const size_t header = size_t(data[0] & 0x0F) * 4;
        if (length < 20 || header < 20 || header > length) return std::nullopt;
        packet.version = 4;
        packet.tos = data[1];
        packet.protocol = data[9];
        packet.src = ipv4_text(data + 12);
        packet.dst = ipv4_text(data + 16);
        const unsigned fragment_offset = ((unsigned(data[6]) & 0x1F) << 8) | data[7];
        if (fragment_offset == 0) parse_transport(packet, data + header, length - header);
        return packet;
    }
    if (version == 6) {
        if (length < 40) return std::nullopt;
        packet.version = 6;
        packet.tos = ((data[0] & 0x0F) << 4) | (data[1] >> 4);
        packet.src = ipv6_text(data + 8);
        packet.dst = ipv6_text(data + 24);
        int next = data[6];
        size_t offset = 40;
        bool first_fragment = true;
        for (int hops = 0; hops < 8; ++hops) {
            if (next != 0 && next != 43 && next != 60 && next != 44) break;
            if (offset + 8 > length) { next = -1; break; }
            if (next == 44) {
                first_fragment = (((unsigned(data[offset + 2]) << 8) | data[offset + 3]) & 0xFFF8) == 0;
                next = data[offset];
                offset += 8;
            } else {
                const size_t size = (size_t(data[offset + 1]) + 1) * 8;
                next = data[offset];
                offset += size;
            }
        }
        packet.protocol = next;
        if (next >= 0 && offset <= length && first_fragment)
            parse_transport(packet, data + offset, length - offset);
        return packet;
    }
    return std::nullopt;
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

int spawn_depth(const Args& args) {
    const auto found = args.values.find("--spawn-depth");
    return found == args.values.end() ? 0 : parse_int(found->second, 0, 4);
}

std::vector<std::string> respawn_args(const std::vector<std::string>& args, int depth) {
    std::vector<std::string> result;
    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--spawn-depth" && i + 1 < args.size()) {
            if (depth > 1) {
                result.push_back(args[i]);
                result.push_back(std::to_string(depth - 1));
            }
            ++i;
        } else {
            result.push_back(args[i]);
        }
    }
    return result;
}

std::optional<std::string> option_value(const std::vector<std::string>& args, const std::string& name) {
    for (size_t i = 0; i + 1 < args.size(); ++i)
        if (args[i] == name && args[i + 1].compare(0, 2, "--") != 0) return args[i + 1];
    return std::nullopt;
}

bool append_line(const std::string& path, const std::string& line) {
    std::ofstream out(path, std::ios::app);
    out << line << '\n';
    out.flush();
    return static_cast<bool>(out);
}

static std::string json_port(int port) { return port < 0 ? "null" : std::to_string(port); }

static const char* json_bool(bool value) { return value ? "true" : "false"; }

std::string packet_json(const Packet& packet, const std::string& label, uint64_t seq, unsigned length,
                        bool loopback, bool outbound) {
    return "{\"kind\":\"packet\",\"label\":" + json_string(label) + ",\"seq\":" + std::to_string(seq) +
        ",\"v\":" + std::to_string(packet.version) + ",\"proto\":" + std::to_string(packet.protocol) +
        ",\"src\":" + json_string(packet.src) + ",\"dst\":" + json_string(packet.dst) +
        ",\"sport\":" + json_port(packet.sport) + ",\"dport\":" + json_port(packet.dport) +
        ",\"tos\":" + std::to_string(packet.tos) + ",\"dscp\":" + std::to_string(dscp_of(packet.tos)) +
        ",\"syn\":" + json_bool(packet.syn) + ",\"ack\":" + json_bool(packet.ack) +
        ",\"fin\":" + json_bool(packet.fin) + ",\"rst\":" + json_bool(packet.rst) +
        ",\"len\":" + std::to_string(length) + ",\"loopback\":" + json_bool(loopback) +
        ",\"outbound\":" + json_bool(outbound) + "}";
}

static void check(bool condition, const char* what) {
    if (!condition) throw std::runtime_error(what);
}

static std::vector<uint8_t> ipv4_tcp(uint8_t tos, uint8_t flags) {
    std::vector<uint8_t> p(40, 0);
    p[0] = 0x45; p[1] = tos; p[3] = 40; p[9] = 6;
    p[12] = 10; p[13] = 1; p[14] = 0; p[15] = 4;
    p[16] = 192; p[17] = 0; p[18] = 2; p[19] = 1;
    p[20] = 0xC3; p[21] = 0x50; p[22] = 0x01; p[23] = 0xBB;
    p[32] = 0x50; p[33] = flags;
    return p;
}

static std::vector<uint8_t> ipv6_udp(uint8_t traffic_class, bool hop_by_hop) {
    std::vector<uint8_t> p(40 + (hop_by_hop ? 8 : 0) + 8, 0);
    p[0] = uint8_t(0x60 | (traffic_class >> 4));
    p[1] = uint8_t((traffic_class & 0x0F) << 4);
    p[5] = uint8_t(p.size() - 40);
    p[6] = hop_by_hop ? 0 : 17;
    p[7] = 64;
    p[23] = 1;
    p[24] = 0x20; p[25] = 0x01; p[26] = 0x0d; p[27] = 0xb8; p[39] = 0x10;
    size_t at = 40;
    if (hop_by_hop) { p[40] = 17; at = 48; }
    p[at] = 0x04; p[at + 1] = 0xD2; p[at + 2] = 0x00; p[at + 3] = 0x35; p[at + 5] = 8;
    return p;
}

int self_test() {
    check(dscp_of(40) == 10 && dscp_of(43) == 10 && dscp_of(3) == 0 && dscp_of(255) == 63, "dscp ignores ECN");

    auto syn = ipv4_tcp(0x29, 0x02);
    auto parsed = parse_packet(syn.data(), syn.size());
    check(parsed && parsed->version == 4 && parsed->protocol == 6 && parsed->tos == 0x29, "ipv4 header");
    check(parsed->src == "10.1.0.4" && parsed->dst == "192.0.2.1", "ipv4 addresses");
    check(parsed->sport == 50000 && parsed->dport == 443, "tcp ports");
    check(parsed->syn && !parsed->ack && !parsed->fin && !parsed->rst, "tcp syn flags");
    auto fin_ack = ipv4_tcp(0, 0x11);
    parsed = parse_packet(fin_ack.data(), fin_ack.size());
    check(parsed && parsed->fin && parsed->ack && !parsed->syn, "tcp fin ack flags");
    parsed = parse_packet(syn.data(), 22);
    check(parsed && parsed->protocol == 6 && parsed->sport == -1 && parsed->tos == 0x29, "truncated transport");
    auto fragment = ipv4_tcp(0, 0x02);
    fragment[6] = 0x00; fragment[7] = 0x10;
    parsed = parse_packet(fragment.data(), fragment.size());
    check(parsed && parsed->sport == -1, "non-first fragment has no ports");

    auto v6 = ipv6_udp(0xB8, false);
    parsed = parse_packet(v6.data(), v6.size());
    check(parsed && parsed->version == 6 && parsed->tos == 0xB8 && parsed->protocol == 17, "ipv6 traffic class");
    check(parsed->src == "0:0:0:0:0:0:0:1" && parsed->dst == "2001:db8:0:0:0:0:0:10", "ipv6 addresses");
    check(parsed->sport == 1234 && parsed->dport == 53, "udp ports");
    auto v6ext = ipv6_udp(0x50, true);
    parsed = parse_packet(v6ext.data(), v6ext.size());
    check(parsed && parsed->protocol == 17 && parsed->sport == 1234 && parsed->tos == 0x50, "ipv6 extension");

    const uint8_t empty[1]{};
    check(!parse_packet(empty, 0), "empty packet");
    check(!parse_packet(syn.data(), 19), "short ipv4");
    auto bad_ihl = syn;
    bad_ihl[0] = 0x44;
    check(!parse_packet(bad_ihl.data(), bad_ihl.size()), "bad ihl");
    auto bad_version = syn;
    bad_version[0] = 0x75;
    check(!parse_packet(bad_version.data(), bad_version.size()), "bad version");
    check(!parse_packet(v6.data(), 39), "short ipv6");

    check(json_string("a\"\\\n\t\x01") == "\"a\\\"\\\\\\n\\t\\u0001\"", "json escaping");

    check(quote_arg("plain") == "plain", "plain argument");
    check(quote_arg("") == "\"\"", "empty argument");
    check(quote_arg("a b") == "\"a b\"", "space argument");
    check(quote_arg("C:\\dir with\\") == "\"C:\\dir with\\\\\"", "trailing backslash");
    check(quote_arg("say \"hi\"") == "\"say \\\"hi\\\"\"", "embedded quotes");
    check(quote_arg("a\\\\\"b") == "\"a\\\\\\\\\\\"b\"", "backslashes before quote");
    check(quote_arg("C:\\x\\y.exe") == "C:\\x\\y.exe", "unquoted backslashes");
    check(join_command({"a b", "c"}) == "\"a b\" c", "join command");

    auto args = parse_args({"--dscp", "10", "--flag", "--", "x", "--y"}, {"--flag"});
    check(args.values.at("--dscp") == "10" && args.flags.count("--flag") == 1, "options");
    check((args.rest == std::vector<std::string>{"x", "--y"}), "rest after separator");
    bool rejected = false;
    try { parse_args({"--dscp"}, {}); } catch (const std::invalid_argument&) { rejected = true; }
    check(rejected, "missing value");
    rejected = false;
    try { parse_args({"positional"}, {}); } catch (const std::invalid_argument&) { rejected = true; }
    check(rejected, "positional");
    rejected = false;
    try { parse_args({"--a", "1", "--a", "2"}, {}); } catch (const std::invalid_argument&) { rejected = true; }
    check(rejected, "duplicate option");

    check(parse_int("63", 0, 63) == 63, "int range");
    for (const char* bad : {"64", "-1", "", "1x", "99999999999"}) {
        rejected = false;
        try { parse_int(bad, 0, 63); } catch (const std::invalid_argument&) { rejected = true; }
        check(rejected, "int rejected");
    }

    check(spawn_depth(parse_args({"--role", "x"}, {})) == 0, "default spawn depth");
    check(spawn_depth(parse_args({"--spawn-depth", "2"}, {})) == 2, "spawn depth");
    for (const char* bad : {"5", "-1", "x"}) {
        rejected = false;
        try { spawn_depth(parse_args({"--spawn-depth", bad}, {})); } catch (const std::invalid_argument&) { rejected = true; }
        check(rejected, "spawn depth rejected");
    }
    check((respawn_args({"--role", "x", "--spawn-depth", "2", "--log", "l"}, 2) ==
           std::vector<std::string>{"--role", "x", "--spawn-depth", "1", "--log", "l"}), "respawn decrements depth");
    check((respawn_args({"--spawn-depth", "1", "--role", "x"}, 1) == std::vector<std::string>{"--role", "x"}),
          "last respawn sends");
    check(option_value({"--a", "1", "--log", "f"}, "--log") == std::optional<std::string>("f"), "option value");
    check(!option_value({"--a", "1"}, "--log") && !option_value({"--a", "--log"}, "--log"), "missing option value");
    const std::string log_file = (std::filesystem::temp_directory_path() / "job-dscp-self-test.log").string();
    std::remove(log_file.c_str());
    check(append_line(log_file, "one") && append_line(log_file, "two"), "append log");
    std::ifstream log_stream(log_file);
    std::string first_line, second_line;
    std::getline(log_stream, first_line);
    std::getline(log_stream, second_line);
    log_stream.close();
    std::remove(log_file.c_str());
    check(first_line == "one" && second_line == "two", "log lines appended");

    parsed = parse_packet(syn.data(), syn.size());
    check(packet_json(*parsed, "observe", 7, 40, false, true) ==
        "{\"kind\":\"packet\",\"label\":\"observe\",\"seq\":7,\"v\":4,\"proto\":6,\"src\":\"10.1.0.4\","
        "\"dst\":\"192.0.2.1\",\"sport\":50000,\"dport\":443,\"tos\":41,\"dscp\":10,\"syn\":true,\"ack\":false,"
        "\"fin\":false,\"rst\":false,\"len\":40,\"loopback\":false,\"outbound\":true}", "packet json");
    parsed = parse_packet(syn.data(), 22);
    check(packet_json(*parsed, "m", 0, 22, true, true).find("\"sport\":null,\"dport\":null") != std::string::npos,
        "missing ports are null");
    return 0;
}

}

#ifndef _WIN32
int main() {
    try {
        job_dscp::self_test();
        std::puts("job-dscp portable self-test passed");
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
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "windivert.h"
#include <atomic>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <mutex>
#include <thread>

#pragma comment(lib, "WinDivert.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Advapi32.lib")

namespace job_dscp {

constexpr UINT64 kCaptureFlags = WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY;
constexpr char kMarkedFilter[] = "outbound and ((ip and ip.TOS >= 4) or (ipv6 and ipv6.TrafficClass >= 4))";
constexpr DWORD kNetRateEnable = 0x1;
constexpr DWORD kNetRateDscpTag = 0x4;
constexpr UINT kPacketBuffer = 0xFFFF + 40;
constexpr uint64_t kRecordCap = 200000;

// Mirrors JOBOBJECT_NET_RATE_CONTROL_INFORMATION and JobObjectNetRateControlInformation (32) so the probe
// does not depend on which SDK header revision guards them.
struct NetRateControl {
    DWORD64 MaxBandwidth;
    DWORD ControlFlags;
    BYTE DscpTag;
};
static_assert(sizeof(NetRateControl) == 16, "JOBOBJECT_NET_RATE_CONTROL_INFORMATION layout");
const JOBOBJECTINFOCLASS kNetRateControlClass = static_cast<JOBOBJECTINFOCLASS>(32);

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

static void check_filter(const char* name, const char* filter, bool ipv6, std::vector<uint8_t> packet,
                         bool expected) {
    WINDIVERT_ADDRESS address{};
    address.Layer = WINDIVERT_LAYER_NETWORK;
    address.Outbound = 1;
    address.IPv6 = ipv6 ? 1 : 0;
    if (!WinDivertHelperCalcChecksums(packet.data(), static_cast<UINT>(packet.size()), &address, 0))
        throw std::runtime_error(std::string("WinDivert checksum helper: ") + name);
    SetLastError(ERROR_SUCCESS);
    const BOOL matched = WinDivertHelperEvalFilter(filter, packet.data(), static_cast<UINT>(packet.size()), &address);
    const DWORD error = GetLastError();
    if (bool(matched) != expected || (!matched && error != ERROR_SUCCESS))
        throw std::runtime_error(std::string("WinDivert filter evaluation: ") + name + " matched=" +
                                 std::to_string(matched) + " error=" + std::to_string(error));
}

static void compile_filter(const char* filter) {
    const char* error = nullptr;
    UINT position = 0;
    if (!WinDivertHelperCompileFilter(filter, WINDIVERT_LAYER_NETWORK, nullptr, 0, &error, &position))
        throw std::runtime_error(std::string("WinDivert filter compilation: ") + filter + ": " +
                                 (error ? error : "unknown") + " at " + std::to_string(position));
}

static int windows_self_test() {
    self_test();
    compile_filter(kMarkedFilter);
    compile_filter("outbound and ip and ip.DstAddr == 192.0.2.1 and tcp and tcp.DstPort == 443");
    compile_filter("outbound and ipv6 and ipv6.DstAddr == ::1 and udp and udp.DstPort == 5000");
    check_filter("ipv4 dscp 10", kMarkedFilter, false, ipv4_tcp(40, 0x02), true);
    check_filter("ipv4 dscp 63", kMarkedFilter, false, ipv4_tcp(0xFC, 0x02), true);
    check_filter("ipv4 ecn only", kMarkedFilter, false, ipv4_tcp(3, 0x02), false);
    check_filter("ipv4 unmarked", kMarkedFilter, false, ipv4_tcp(0, 0x02), false);
    check_filter("ipv6 dscp 46", kMarkedFilter, true, ipv6_udp(0xB8, false), true);
    check_filter("ipv6 ecn only", kMarkedFilter, true, ipv6_udp(0x03, false), false);
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
    bool connection_policy_api = false;
    if (const HMODULE fwpuclnt = LoadLibraryExW(L"fwpuclnt.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32)) {
        connection_policy_api = GetProcAddress(fwpuclnt, "FwpmConnectionPolicyAdd0") != nullptr;
        FreeLibrary(fwpuclnt);
    }
    BOOL in_job = FALSE;
    const bool in_job_ok = IsProcessInJob(GetCurrentProcess(), nullptr, &in_job) != FALSE;
    std::cout << "{\"kind\":\"env\",\"version_ok\":" << json_bool(version_ok)
              << ",\"os_major\":" << version.dwMajorVersion << ",\"os_minor\":" << version.dwMinorVersion
              << ",\"os_build\":" << version.dwBuildNumber << ",\"os_ubr\":" << (ubr_ok ? std::to_string(ubr) : "null")
              << ",\"product_type\":" << unsigned(version.wProductType)
              << ",\"elevated\":" << json_bool(elevated)
              << ",\"connection_policy_api\":" << json_bool(connection_policy_api)
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

static int launch_command(const Args& args) {
    const int dscp = parse_int(required(args, "--dscp"), 0, 63);
    if (args.rest.empty()) throw std::invalid_argument("missing child command line");
    Step job_step, kill_step, dscp_step, readback_step, create_step, assign_step, resume_step;
    NetRateControl readback{};
    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    job_step.record(job != nullptr);
    if (job) {
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
    bool child_ran = false;
    DWORD child_exit = 0;
    if (job && kill_step.ok) {
        std::string command = join_command(args.rest);
        std::vector<char> buffer(command.begin(), command.end());
        buffer.push_back('\0');
        STARTUPINFOA startup{};
        startup.cb = sizeof startup;
        PROCESS_INFORMATION process{};
        create_step.record(CreateProcessA(nullptr, buffer.data(), nullptr, nullptr, FALSE, CREATE_SUSPENDED,
                                          nullptr, nullptr, &startup, &process));
        if (create_step.ok) {
            assign_step.record(AssignProcessToJobObject(job, process.hProcess));
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
    std::cout << "{\"kind\":\"launch\",\"dscp\":" << dscp
              << ",\"job_created\":" << json_bool(job_step.ok) << ",\"job_error\":" << job_step.error
              << ",\"kill_on_close_set\":" << json_bool(kill_step.ok) << ",\"kill_on_close_error\":" << kill_step.error
              << ",\"dscp_set\":" << json_bool(dscp_step.ok) << ",\"dscp_error\":" << dscp_step.error
              << ",\"readback_ok\":" << json_bool(readback_step.ok) << ",\"readback_error\":" << readback_step.error
              << ",\"readback_flags\":" << readback.ControlFlags << ",\"readback_dscp\":" << unsigned(readback.DscpTag)
              << ",\"process_created\":" << json_bool(create_step.ok) << ",\"process_error\":" << create_step.error
              << ",\"assigned\":" << json_bool(assign_step.ok) << ",\"assign_error\":" << assign_step.error
              << ",\"resumed\":" << json_bool(resume_step.ok) << ",\"resume_error\":" << resume_step.error
              << ",\"child_ran\":" << json_bool(child_ran) << ",\"child_exit_code\":" << child_exit << "}" << std::endl;
    return child_ran ? static_cast<int>(child_exit) : 0;
}

struct Target {
    sockaddr_storage address{};
    int length = 0;
    int family = 0;
};

static Target resolve_target(const std::string& text, int port) {
    Target target;
    auto* v4 = reinterpret_cast<sockaddr_in*>(&target.address);
    auto* v6 = reinterpret_cast<sockaddr_in6*>(&target.address);
    if (inet_pton(AF_INET, text.c_str(), &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET;
        v4->sin_port = htons(static_cast<u_short>(port));
        target.length = sizeof(sockaddr_in);
        target.family = AF_INET;
    } else if (inet_pton(AF_INET6, text.c_str(), &v6->sin6_addr) == 1) {
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(static_cast<u_short>(port));
        target.length = sizeof(sockaddr_in6);
        target.family = AF_INET6;
    } else {
        throw std::invalid_argument("target must be a numeric address");
    }
    return target;
}

struct Attempt {
    int local_port = 0;
    const char* outcome = "socket_error";
    int error = 0;
};

static bool bind_any(SOCKET s, int family, Attempt& attempt) {
    sockaddr_storage local{};
    int length = 0;
    if (family == AF_INET) {
        auto* v4 = reinterpret_cast<sockaddr_in*>(&local);
        v4->sin_family = AF_INET;
        v4->sin_addr.s_addr = htonl(INADDR_ANY);
        length = sizeof(sockaddr_in);
    } else {
        reinterpret_cast<sockaddr_in6*>(&local)->sin6_family = AF_INET6;
        length = sizeof(sockaddr_in6);
    }
    if (bind(s, reinterpret_cast<sockaddr*>(&local), length) == SOCKET_ERROR) {
        attempt.outcome = "bind_error";
        attempt.error = WSAGetLastError();
        return false;
    }
    sockaddr_storage bound{};
    int bound_length = sizeof bound;
    if (getsockname(s, reinterpret_cast<sockaddr*>(&bound), &bound_length) == SOCKET_ERROR) {
        attempt.outcome = "getsockname_error";
        attempt.error = WSAGetLastError();
        return false;
    }
    attempt.local_port = ntohs(family == AF_INET ? reinterpret_cast<sockaddr_in*>(&bound)->sin_port
                                                 : reinterpret_cast<sockaddr_in6*>(&bound)->sin6_port);
    return true;
}

static timeval to_timeval(int milliseconds) {
    timeval value{};
    value.tv_sec = milliseconds / 1000;
    value.tv_usec = (milliseconds % 1000) * 1000;
    return value;
}

static void drain_after_shutdown(SOCKET s, int timeout_ms) {
    if (shutdown(s, SD_SEND) == SOCKET_ERROR) return;
    char buffer[512];
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    for (;;) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now()).count();
        if (left <= 0) return;
        fd_set readable;
        FD_ZERO(&readable);
        FD_SET(s, &readable);
        timeval wait = to_timeval(static_cast<int>(left));
        if (select(0, &readable, nullptr, nullptr, &wait) <= 0) return;
        if (recv(s, buffer, sizeof buffer, 0) <= 0) return;
    }
}

static Attempt tcp_attempt(const Target& target, int timeout_ms) {
    Attempt attempt;
    const SOCKET s = socket(target.family, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        attempt.error = WSAGetLastError();
        return attempt;
    }
    if (bind_any(s, target.family, attempt)) {
        u_long non_blocking = 1;
        if (ioctlsocket(s, FIONBIO, &non_blocking) == SOCKET_ERROR) {
            attempt.outcome = "ioctl_error";
            attempt.error = WSAGetLastError();
        } else if (connect(s, reinterpret_cast<const sockaddr*>(&target.address), target.length) == 0) {
            attempt.outcome = "connected";
        } else if (WSAGetLastError() != WSAEWOULDBLOCK) {
            attempt.error = WSAGetLastError();
            attempt.outcome = attempt.error == WSAECONNREFUSED ? "refused" : "connect_error";
        } else {
            fd_set writable, failed;
            FD_ZERO(&writable);
            FD_ZERO(&failed);
            FD_SET(s, &writable);
            FD_SET(s, &failed);
            timeval wait = to_timeval(timeout_ms);
            const int ready = select(0, nullptr, &writable, &failed, &wait);
            if (ready == 0) {
                attempt.outcome = "timeout";
            } else if (ready == SOCKET_ERROR) {
                attempt.outcome = "select_error";
                attempt.error = WSAGetLastError();
            } else {
                int socket_error = 0;
                int size = sizeof socket_error;
                if (getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&socket_error), &size) == SOCKET_ERROR)
                    socket_error = WSAGetLastError();
                if (FD_ISSET(s, &writable) && socket_error == 0) {
                    attempt.outcome = "connected";
                } else {
                    attempt.error = socket_error;
                    attempt.outcome = socket_error == WSAECONNREFUSED ? "refused" : "connect_error";
                }
            }
        }
        if (std::strcmp(attempt.outcome, "connected") == 0) drain_after_shutdown(s, timeout_ms);
    }
    closesocket(s);
    return attempt;
}

static Attempt udp_attempt(const Target& target) {
    Attempt attempt;
    const SOCKET s = socket(target.family, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) {
        attempt.error = WSAGetLastError();
        return attempt;
    }
    if (bind_any(s, target.family, attempt)) {
        static const char payload[] = "gateinto-job-dscp";
        const int sent = sendto(s, payload, static_cast<int>(sizeof payload - 1), 0,
                                reinterpret_cast<const sockaddr*>(&target.address), target.length);
        if (sent == static_cast<int>(sizeof payload - 1)) {
            attempt.outcome = "sent";
        } else {
            attempt.outcome = "send_error";
            attempt.error = sent == SOCKET_ERROR ? WSAGetLastError() : 0;
        }
    }
    closesocket(s);
    return attempt;
}

static int spawn_self(const std::vector<std::string>& args, int depth) {
    char path[MAX_PATH * 4];
    const DWORD length = GetModuleFileNameA(nullptr, path, static_cast<DWORD>(sizeof path));
    if (length == 0 || length >= sizeof path) throw std::runtime_error("module path");
    std::vector<std::string> child{path, "client"};
    for (const auto& arg : respawn_args(args, depth)) child.push_back(arg);
    std::string command = join_command(child);
    std::vector<char> buffer(command.begin(), command.end());
    buffer.push_back('\0');
    STARTUPINFOA startup{};
    startup.cb = sizeof startup;
    PROCESS_INFORMATION process{};
    if (!CreateProcessA(nullptr, buffer.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &startup, &process))
        throw std::runtime_error("spawn child failed with error " + std::to_string(GetLastError()));
    CloseHandle(process.hThread);
    WaitForSingleObject(process.hProcess, INFINITE);
    DWORD code = 2;
    if (!GetExitCodeProcess(process.hProcess, &code)) code = 2;
    CloseHandle(process.hProcess);
    if (code != 0) throw std::runtime_error("spawned child exited with " + std::to_string(code));
    return 0;
}

static int client_command(const std::vector<std::string>& raw) {
    const Args args = parse_args(raw, {});
    if (!args.rest.empty()) throw std::invalid_argument("unexpected arguments");
    const std::string& role = required(args, "--role");
    const std::string& proto = required(args, "--proto");
    if (proto != "tcp" && proto != "udp") throw std::invalid_argument("protocol");
    const int port = parse_int(required(args, "--port"), 1, 65535);
    const int count = parse_int(required(args, "--count"), 1, 100);
    const int timeout_ms = parse_int(required(args, "--timeout-ms"), 1, 60000);
    const std::string& out_path = required(args, "--out");
    const std::string& target_text = required(args, "--target");
    required(args, "--log");
    const int depth = spawn_depth(args);
    if (depth > 0) return spawn_self(raw, depth);
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) throw std::runtime_error("WSAStartup");
    const Target target = resolve_target(target_text, port);
    std::ofstream out(out_path, std::ios::app);
    if (!out) throw std::runtime_error("client output");
    for (int index = 0; index < count; ++index) {
        const Attempt attempt = proto == "tcp" ? tcp_attempt(target, timeout_ms) : udp_attempt(target);
        out << "{\"kind\":\"attempt\",\"role\":" << json_string(role) << ",\"proto\":" << json_string(proto)
            << ",\"index\":" << index << ",\"local_port\":" << attempt.local_port
            << ",\"outcome\":" << json_string(attempt.outcome) << ",\"error\":" << attempt.error << "}\n";
        out.flush();
        Sleep(100);
    }
    WSACleanup();
    if (!out) throw std::runtime_error("client output write");
    return 0;
}

static int logged_client_command(const std::vector<std::string>& raw) {
    try {
        return client_command(raw);
    } catch (const std::exception& error) {
        if (const auto log = option_value(raw, "--log")) append_line(*log, std::string("client error: ") + error.what());
        throw;
    }
}

class Sniffer {
    std::ofstream out;
    std::mutex lock;
    std::string label;
    HANDLE handle = INVALID_HANDLE_VALUE;
    std::atomic<bool> done{false};
    std::atomic<uint64_t> received{0}, parse_errors{0}, recv_errors{0}, records{0};
    std::atomic<DWORD> last_error{0};
    std::atomic<bool> truncated{false};

    void write(const std::string& line, bool flush) {
        std::lock_guard<std::mutex> guard(lock);
        out << line << '\n';
        if (flush) out.flush();
    }

    void receive() {
        std::vector<uint8_t> buffer(kPacketBuffer);
        uint64_t seq = 0;
        for (;;) {
            WINDIVERT_ADDRESS address{};
            UINT length = 0;
            if (!WinDivertRecv(handle, buffer.data(), kPacketBuffer, &length, &address)) {
                const DWORD error = GetLastError();
                if (error == ERROR_NO_DATA) break;
                ++recv_errors;
                last_error = error;
                if (error == ERROR_INSUFFICIENT_BUFFER) continue;
                break;
            }
            ++received;
            const auto packet = parse_packet(buffer.data(), length);
            if (!packet) {
                ++parse_errors;
                continue;
            }
            if (records >= kRecordCap) {
                truncated = true;
                continue;
            }
            write(packet_json(*packet, label, seq++, length, address.Loopback != 0, address.Outbound != 0), false);
            ++records;
        }
    }

public:
    int run(const Args& args) {
        const std::string& filter = required(args, "--filter");
        label = required(args, "--label");
        const std::string& stop_file = required(args, "--stop-file");
        const int max_seconds = parse_int(required(args, "--max-seconds"), 1, 3600);
        out.open(required(args, "--out"), std::ios::trunc);
        if (!out) throw std::runtime_error("sniffer output");
        DWORD open_error = 0, param_errors = 0, shutdown_error = 0;
        bool timed_out = false, stop_timeout = false;
        handle = WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_NETWORK, 0, kCaptureFlags);
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
            write("{\"kind\":\"ready\",\"label\":" + json_string(label) + "}", true);
            std::thread receiver([this] {
                try { receive(); } catch (...) { ++recv_errors; last_error = ERROR_GEN_FAILURE; }
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
        const bool clean = !open_error && !shutdown_error && !timed_out && !stop_timeout && !recv_errors &&
            !parse_errors && !truncated;
        std::string summary = "{\"kind\":\"summary\",\"label\":" + json_string(label) +
            ",\"received\":" + std::to_string(received.load()) + ",\"records\":" + std::to_string(records.load()) +
            ",\"parse_errors\":" + std::to_string(parse_errors.load()) +
            ",\"recv_errors\":" + std::to_string(recv_errors.load()) +
            ",\"last_error\":" + std::to_string(last_error.load()) + ",\"open_error\":" + std::to_string(open_error) +
            ",\"param_errors\":" + std::to_string(param_errors) + ",\"shutdown_error\":" + std::to_string(shutdown_error) +
            ",\"timed_out\":" + json_bool(timed_out) + ",\"stop_timeout\":" + json_bool(stop_timeout) +
            ",\"truncated\":" + json_bool(truncated.load()) + "}";
        write(summary, true);
        const int code = clean ? 0 : 2;
        if (stop_timeout) {
            std::lock_guard<std::mutex> guard(lock);
            out.flush();
            TerminateProcess(GetCurrentProcess(), static_cast<UINT>(code));
        }
        return code;
    }
};

static int dispatch(int argc, char** argv) {
    if (argc < 2) throw std::invalid_argument("missing command");
    const std::string command = argv[1];
    if (command == "self-test" && argc == 2) return windows_self_test();
    if (command == "env" && argc == 2) return env_command();
    if (command == "launch") return launch_command(parse_args(arguments(argc, argv, 2), {}));
    if (command == "client") return logged_client_command(arguments(argc, argv, 2));
    if (command == "sniff") {
        Sniffer sniffer;
        const Args args = parse_args(arguments(argc, argv, 2), {});
        if (!args.rest.empty()) throw std::invalid_argument("unexpected arguments");
        return sniffer.run(args);
    }
    throw std::invalid_argument("unknown command");
}

}

int main(int argc, char** argv) {
    try {
        return job_dscp::dispatch(argc, argv);
    } catch (const std::exception& error) {
        std::cerr << "job-dscp probe error: " << error.what() << std::endl;
        return 2;
    } catch (...) {
        std::cerr << "job-dscp probe error" << std::endl;
        return 2;
    }
}
#endif
