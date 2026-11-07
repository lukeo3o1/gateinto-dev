#include <cstdint>
#include <set>
#include <string>
#include <tuple>
#include <vector>

namespace ale {

struct Endpoint {
    uint64_t id = 0;
    uint32_t local = 0, remote = 0;
    uint16_t local_port = 0, remote_port = 0;
    uint8_t protocol = 0;
    std::string app_path;

    bool operator<(const Endpoint& other) const {
        return std::tie(id, local, remote, local_port, remote_port, protocol, app_path) <
            std::tie(other.id, other.local, other.remote, other.local_port, other.remote_port,
                     other.protocol, other.app_path);
    }
};

std::vector<Endpoint> completed_snapshot(const std::vector<Endpoint>& entries, bool complete,
                                       uint32_t target, uint16_t port, uint8_t protocol) {
    if (!complete) return {};
    std::set<Endpoint> distinct;
    for (const auto& entry : entries) {
        if (entry.id && entry.local && entry.remote == target && entry.local_port &&
            entry.remote_port == port && entry.protocol == protocol && !entry.app_path.empty())
            distinct.insert(entry);
    }
    return {distinct.begin(), distinct.end()};
}

}

#ifndef _WIN32
#include <cassert>
#include <iostream>

int main() {
    ale::Endpoint endpoint{1, 0x7f000001, 0x7f000001, 40001, 443, 6, "\\device\\lab\\app-a.exe"};
    assert(ale::completed_snapshot({endpoint}, false, 0x7f000001, 443, 6).empty());
    assert(ale::completed_snapshot({endpoint}, true, 0x7f000001, 443, 17).empty());
    assert(ale::completed_snapshot({endpoint}, true, 0x7f000002, 443, 6).empty());
    assert(ale::completed_snapshot({endpoint}, true, 0x7f000001, 8443, 6).empty());
    assert(ale::completed_snapshot({endpoint, endpoint}, true, 0x7f000001, 443, 6).size() == 1);
    auto incomplete = endpoint;
    incomplete.app_path.clear();
    assert(ale::completed_snapshot({incomplete}, true, 0x7f000001, 443, 6).empty());
    incomplete = endpoint;
    incomplete.local_port = 0;
    assert(ale::completed_snapshot({incomplete}, true, 0x7f000001, 443, 6).empty());
    incomplete = endpoint;
    incomplete.id = 0;
    assert(ale::completed_snapshot({incomplete}, true, 0x7f000001, 443, 6).empty());
    auto conflict = endpoint;
    conflict.app_path = "\\device\\lab\\app-b.exe";
    assert(ale::completed_snapshot({endpoint, conflict}, true, 0x7f000001, 443, 6).size() == 2);
    assert(ale::completed_snapshot({endpoint, conflict}, false, 0x7f000001, 443, 6).empty());
    std::cout << "ALE endpoint snapshot self-tests passed\n";
}
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
#include <mswsock.h>
#include <windows.h>
#include <fwpmu.h>
#include <fwpsu.h>
#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "ws2_32.lib")

namespace {

int64_t qpc() {
    LARGE_INTEGER value{};
    QueryPerformanceCounter(&value);
    return value.QuadPart;
}

std::string json(const std::string& value) {
    const char* digits = "0123456789abcdef";
    std::string result = "\"";
    for (unsigned char c : value) {
        if (c == '"' || c == '\\') { result += '\\'; result += static_cast<char>(c); }
        else if (c < 32) { result += "\\u00"; result += digits[c >> 4]; result += digits[c & 15]; }
        else result += static_cast<char>(c);
    }
    return result + '"';
}

class OutputLimit : public std::runtime_error {
public:
    OutputLimit() : std::runtime_error("ALE output record limit reached") {}
};

class Output {
    std::ofstream stream;
    unsigned lines = 0;
public:
    explicit Output(const std::string& path) : stream(path, std::ios::trunc) {
        if (!stream) throw std::runtime_error("cannot open ALE probe output");
    }
    void write(const std::string& line, bool terminal = false) {
        if (lines >= (terminal ? 65536u : 65528u)) throw OutputLimit();
        stream << line << '\n';
        stream.flush();
        if (!stream) throw std::runtime_error("ALE output write failed");
        ++lines;
    }
};

struct Options {
    std::string target, output, stop_file;
    uint16_t port = 0;
    uint8_t protocol = 6;
    unsigned seconds = 35, interval_ms = 5;
};

unsigned number(const std::string& value, unsigned minimum, unsigned maximum) {
    size_t consumed = 0;
    const auto result = std::stoul(value, &consumed);
    if (consumed != value.size() || result < minimum || result > maximum)
        throw std::runtime_error("numeric option out of range");
    return static_cast<unsigned>(result);
}

Options options(int argc, char** argv) {
    Options result;
    for (int i = 1; i < argc; i += 2) {
        if (i + 1 == argc) throw std::runtime_error("missing option value");
        const std::string key = argv[i], value = argv[i + 1];
        if (key == "--target") result.target = value;
        else if (key == "--port") result.port = static_cast<uint16_t>(number(value, 1, 65535));
        else if (key == "--protocol") {
            if (value != "tcp" && value != "udp") throw std::runtime_error("protocol must be tcp or udp");
            result.protocol = value == "tcp" ? 6 : 17;
        } else if (key == "--out") result.output = value;
        else if (key == "--stop-file") result.stop_file = value;
        else if (key == "--seconds") result.seconds = number(value, 1, 600);
        else if (key == "--interval-ms") result.interval_ms = number(value, 1, 1000);
        else throw std::runtime_error("unknown option: " + key);
    }
    if (result.target.empty() || !result.port || result.output.empty())
        throw std::runtime_error("required: --target IPv4 --port N --out PATH");
    return result;
}

struct Metric {
    uint64_t calls = 0;
    int64_t total = 0, maximum = 0;
    void add(int64_t ticks) {
        ++calls;
        total += ticks;
        maximum = (std::max)(maximum, ticks);
    }
    std::string json(int64_t frequency) const {
        const auto ms = [frequency](int64_t ticks) { return static_cast<double>(ticks) * 1000 / frequency; };
        std::ostringstream out;
        out << "{\"calls\":" << calls << ",\"total_ms\":" << ms(total)
            << ",\"max_ms\":" << ms(maximum) << "}";
        return out.str();
    }
};

struct Snapshot {
    uint64_t id = 0;
    bool complete = false;
    int64_t began = 0, observed = 0;
    int64_t create_ticks = 0, enum_ticks = 0, destroy_ticks = 0, decode_ticks = 0;
    unsigned returned = 0;
    std::vector<ale::Endpoint> endpoints;
};

class Probe {
    Options config;
    Output out;
    HMODULE library = nullptr;
    HANDLE engine = nullptr;
    HANDLE timer = nullptr;
    decltype(&FwpsAleEndpointCreateEnumHandle0) create_enum = nullptr;
    decltype(&FwpsAleEndpointEnum0) enum_entries = nullptr;
    decltype(&FwpsAleEndpointDestroyEnumHandle0) destroy_enum = nullptr;
    int64_t frequency = 0;
    uint32_t target = 0;
    bool available = false, truncated = false;
    unsigned errors = 0;
    uint64_t queries = 0, complete_snapshots = 0, incomplete_snapshots = 0, endpoint_records = 0;
    Metric create_metric, enum_metric, destroy_metric, decode_metric, query_metric;
    std::set<ale::Endpoint> seen;

    void error(const std::string& operation, DWORD code) {
        ++errors;
        out.write("{\"kind\":\"ale_error\",\"operation\":" + json(operation) +
                  ",\"code\":" + std::to_string(code) + "}", true);
    }

    void close() {
        if (engine) {
            const auto closed = FwpmEngineClose0(engine);
            engine = nullptr;
            if (closed) error("FwpmEngineClose0", closed);
        }
    }

    static std::string ip(uint32_t raw) {
        IN_ADDR address{};
        address.s_addr = htonl(raw);
        char buffer[INET_ADDRSTRLEN]{};
        if (!InetNtopA(AF_INET, &address, buffer, sizeof(buffer)))
            throw std::runtime_error("ALE IPv4 formatting failed");
        return buffer;
    }

    static std::string app_path(const FWP_BYTE_BLOB& blob) {
        if (!blob.data || blob.size == 0 || blob.size % sizeof(wchar_t) || blob.size > 65536) return {};
        std::vector<wchar_t> text(blob.size / sizeof(wchar_t));
        std::memcpy(text.data(), blob.data, blob.size);
        while (!text.empty() && text.back() == L'\0') text.pop_back();
        if (text.empty()) return {};
        const auto count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(),
            static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
        if (!count) throw std::runtime_error("ALE appId UTF-16 conversion failed");
        std::string result(static_cast<size_t>(count), '\0');
        if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()),
                               result.data(), count, nullptr, nullptr) != count)
            throw std::runtime_error("ALE appId conversion length differs");
        return result;
    }

    Snapshot query() {
        Snapshot snapshot;
        snapshot.id = ++queries;
        snapshot.began = qpc();
        FWP_V4_ADDR_AND_MASK remote{};
        remote.addr = target;
        remote.mask = 0xffffffff;
        FWPS_ALE_ENDPOINT_ENUM_TEMPLATE0 filter{};
        filter.remoteSubNet.type = FWP_V4_ADDR_MASK;
        filter.remoteSubNet.v4AddrMask = &remote;
        filter.ipProtocol.type = FWP_UINT8;
        filter.ipProtocol.uint8 = config.protocol;
        filter.remotePort.type = FWP_UINT16;
        filter.remotePort.uint16 = config.port;
        HANDLE handle = nullptr;
        int64_t began = qpc();
        const auto created = create_enum(engine, &filter, &handle);
        snapshot.create_ticks = qpc() - began;
        create_metric.add(snapshot.create_ticks);
        if (created) error("FwpsAleEndpointCreateEnumHandle0", created);
        else {
            const int64_t deadline = snapshot.began + frequency * 2;
            snapshot.complete = true;
            size_t copied_bytes = 0;
            try {
                for (unsigned batch = 0; batch < 64; ++batch) {
                    if (qpc() >= deadline) {
                        truncated = true;
                        error("ALE snapshot deadline", WAIT_TIMEOUT);
                        snapshot.complete = false;
                        break;
                    }
                    FWPS_ALE_ENDPOINT_PROPERTIES0** entries = nullptr;
                    UINT32 count = 0;
                    began = qpc();
                    const auto enumerated = enum_entries(engine, handle, 256, &entries, &count);
                    const auto duration = qpc() - began;
                    snapshot.enum_ticks += duration;
                    enum_metric.add(duration);
                    if (enumerated) {
                        if (entries) FwpmFreeMemory0(reinterpret_cast<void**>(&entries));
                        error("FwpsAleEndpointEnum0", enumerated);
                        snapshot.complete = false;
                        break;
                    }
                    began = qpc();
                    try {
                        if (count > 256 || (count && !entries)) throw std::runtime_error("ALE invalid endpoint array");
                        snapshot.returned += count;
                        for (UINT32 index = 0; index < count; ++index) {
                            const auto* native = entries[index];
                            if (!native) throw std::runtime_error("ALE null endpoint");
                            if (native->ipVersion != FWP_IP_VERSION_V4) continue;
                            copied_bytes += native->appId.size;
                            if (copied_bytes > 8 * 1024 * 1024) {
                                truncated = true;
                                throw std::runtime_error("ALE snapshot byte limit");
                            }
                            ale::Endpoint endpoint;
                            endpoint.id = native->endpointId;
                            endpoint.local = native->localV4Address;
                            endpoint.remote = native->remoteV4Address;
                            endpoint.local_port = native->localPort;
                            endpoint.remote_port = native->remotePort;
                            endpoint.protocol = native->ipProtocol;
                            endpoint.app_path = app_path(native->appId);
                            snapshot.endpoints.push_back(std::move(endpoint));
                        }
                    } catch (...) {
                        if (entries) FwpmFreeMemory0(reinterpret_cast<void**>(&entries));
                        throw;
                    }
                    if (entries) FwpmFreeMemory0(reinterpret_cast<void**>(&entries));
                    const auto decoded = qpc() - began;
                    snapshot.decode_ticks += decoded;
                    decode_metric.add(decoded);
                    if (count < 256) break;
                    if (batch == 63 || qpc() >= deadline) {
                        truncated = true;
                        error("FwpsAleEndpointEnum0_limit", ERROR_MORE_DATA);
                        snapshot.complete = false;
                        break;
                    }
                }
            } catch (...) {
                error("ALE snapshot decode", ERROR_INVALID_DATA);
                snapshot.complete = false;
            }
            began = qpc();
            const auto destroyed = destroy_enum(engine, handle);
            snapshot.destroy_ticks = qpc() - began;
            destroy_metric.add(snapshot.destroy_ticks);
            if (destroyed) { error("FwpsAleEndpointDestroyEnumHandle0", destroyed); snapshot.complete = false; }
        }
        began = qpc();
        snapshot.endpoints = ale::completed_snapshot(snapshot.endpoints, snapshot.complete,
                                                    target, config.port, config.protocol);
        const auto filtered = qpc() - began;
        snapshot.decode_ticks += filtered;
        decode_metric.add(filtered);
        snapshot.observed = qpc();
        if (snapshot.complete && snapshot.observed - snapshot.began >= frequency * 2) {
            truncated = true;
            error("ALE snapshot deadline", WAIT_TIMEOUT);
            snapshot.complete = false;
            snapshot.endpoints.clear();
        }
        query_metric.add(snapshot.observed - snapshot.began);
        if (snapshot.complete) ++complete_snapshots;
        else ++incomplete_snapshots;
        return snapshot;
    }

    void publish(const Snapshot& snapshot) {
        unsigned emitted = 0;
        for (const auto& endpoint : snapshot.endpoints) {
            std::ostringstream record;
            record << "{\"kind\":\"ale_endpoint\",\"snapshot_id\":" << snapshot.id
                << ",\"snapshot_complete\":true,\"endpoint_id\":" << endpoint.id
                << ",\"local_ip\":" << json(ip(endpoint.local)) << ",\"local_port\":" << endpoint.local_port
                << ",\"remote_ip\":" << json(ip(endpoint.remote)) << ",\"remote_port\":" << endpoint.remote_port
                << ",\"raw_local_v4\":" << endpoint.local << ",\"raw_remote_v4\":" << endpoint.remote
                << ",\"protocol\":" << unsigned(endpoint.protocol) << ",\"app_path\":" << json(endpoint.app_path)
                << ",\"query_start_qpc\":" << snapshot.began << ",\"observed_qpc\":" << snapshot.observed
                << ",\"recv_qpc\":" << snapshot.observed << "}";
            out.write(record.str());
            seen.insert(endpoint);
            ++emitted;
            ++endpoint_records;
        }
        const auto ms = [this](int64_t ticks) { return static_cast<double>(ticks) * 1000 / frequency; };
        std::ostringstream record;
        record << "{\"kind\":\"ale_snapshot\",\"snapshot_id\":" << snapshot.id
            << ",\"complete\":" << (snapshot.complete ? "true" : "false")
            << ",\"query_start_qpc\":" << snapshot.began << ",\"observed_qpc\":" << snapshot.observed
            << ",\"entries_returned\":" << snapshot.returned << ",\"emitted\":" << emitted
            << ",\"create_ms\":" << ms(snapshot.create_ticks) << ",\"enum_ms\":" << ms(snapshot.enum_ticks)
            << ",\"destroy_ms\":" << ms(snapshot.destroy_ticks) << ",\"decode_ms\":" << ms(snapshot.decode_ticks) << "}";
        out.write(record.str());
    }

public:
    explicit Probe(Options value) : config(std::move(value)), out(config.output) {
        LARGE_INTEGER counter{};
        QueryPerformanceFrequency(&counter);
        frequency = counter.QuadPart;
        IN_ADDR address{};
        if (InetPtonA(AF_INET, config.target.c_str(), &address) != 1)
            throw std::runtime_error("ALE probe requires an IPv4 target literal");
        target = ntohl(address.s_addr);
    }
    ~Probe() {
        if (engine) FwpmEngineClose0(engine);
        if (timer) CloseHandle(timer);
        if (library) FreeLibrary(library);
    }

    int run() {
        library = LoadLibraryExW(L"fwpuclnt.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (library) {
            create_enum = reinterpret_cast<decltype(create_enum)>(GetProcAddress(library, "FwpsAleEndpointCreateEnumHandle0"));
            enum_entries = reinterpret_cast<decltype(enum_entries)>(GetProcAddress(library, "FwpsAleEndpointEnum0"));
            destroy_enum = reinterpret_cast<decltype(destroy_enum)>(GetProcAddress(library, "FwpsAleEndpointDestroyEnumHandle0"));
        }
        available = create_enum && enum_entries && destroy_enum;
        if (!available) {
            out.write("{\"kind\":\"ale_unavailable\",\"code\":" +
                      std::to_string(library ? ERROR_PROC_NOT_FOUND : GetLastError()) + "}");
        } else {
            const auto opened = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &engine);
            if (opened) error("FwpmEngineOpen0", opened);
            else {
                timer = CreateWaitableTimerExW(nullptr, nullptr, 0x00000002, TIMER_ALL_ACCESS);
                out.write("{\"kind\":\"ready\",\"source\":\"ale_endpoint\",\"available\":true,\"qpc\":" +
                          std::to_string(qpc()) + ",\"qpc_frequency\":" + std::to_string(frequency) +
                          ",\"protocol\":" + std::to_string(config.protocol) + "}");
                const int64_t deadline = qpc() + frequency * config.seconds;
                try {
                    while (qpc() < deadline && !errors) {
                        if (!config.stop_file.empty() && GetFileAttributesA(config.stop_file.c_str()) != INVALID_FILE_ATTRIBUTES) break;
                        publish(query());
                        if (errors) break;
                        if (timer) {
                            LARGE_INTEGER due{};
                            due.QuadPart = -static_cast<int64_t>(config.interval_ms) * 10000;
                            if (!SetWaitableTimer(timer, &due, 0, nullptr, nullptr, FALSE) ||
                                WaitForSingleObject(timer, INFINITE) != WAIT_OBJECT_0) {
                                error("ALE waitable timer", GetLastError());
                                break;
                            }
                        } else Sleep(config.interval_ms);
                    }
                } catch (const OutputLimit&) {
                    truncated = true;
                    error("ALE output limit", ERROR_MORE_DATA);
                } catch (...) {
                    error("ALE probe", ERROR_INVALID_DATA);
                }
            }
        }
        close();
        const bool success = available && !errors && !truncated && complete_snapshots;
        std::ostringstream summary;
        summary << "{\"kind\":\"summary\",\"source\":\"ale_endpoint\",\"available\":" << (available ? "true" : "false")
            << ",\"success\":" << (success ? "true" : "false") << ",\"queries\":" << queries
            << ",\"complete_snapshots\":" << complete_snapshots << ",\"incomplete_snapshots\":" << incomplete_snapshots
            << ",\"endpoint_records\":" << endpoint_records << ",\"distinct_endpoints\":" << seen.size()
            << ",\"errors\":" << errors
            << ",\"truncated\":" << (truncated ? "true" : "false") << ",\"interval_ms\":" << config.interval_ms
            << ",\"timer\":" << json(timer ? "high_resolution" : "sleep")
            << ",\"phase_create\":" << create_metric.json(frequency)
            << ",\"phase_enum\":" << enum_metric.json(frequency)
            << ",\"phase_destroy\":" << destroy_metric.json(frequency)
            << ",\"phase_decode\":" << decode_metric.json(frequency)
            << ",\"query\":" << query_metric.json(frequency) << "}";
        out.write(summary.str(), true);
        return success ? 0 : available ? 3 : 2;
    }
};

}

int main(int argc, char** argv) {
    WSADATA winsock{};
    if (WSAStartup(MAKEWORD(2, 2), &winsock)) return 1;
    int result = 1;
    try {
        Probe probe(options(argc, argv));
        result = probe.run();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
    }
    WSACleanup();
    return result;
}
#endif
