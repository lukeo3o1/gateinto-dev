#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000006
#endif
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#endif
#include <iostream>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>

std::string json(const std::string&);
std::string xml_value(const std::string&, const std::string&);
std::string counts_json(const std::map<unsigned, unsigned long long>&);
std::string error_line_json(const std::string&, const std::string&, unsigned long);

struct CappedCounter {
    unsigned long long count = 0;
    unsigned long long cap;
    explicit CappedCounter(unsigned long long limit) : cap(limit) {}
    bool record();
};

class PollWindow {
public:
    PollWindow(unsigned long long floor, unsigned long long overlap, std::size_t capacity);
    unsigned long long begin() const;
    bool accept(unsigned long long timestamp, const std::string& identity);
    void finish(unsigned long long end);
    std::size_t size() const { return seen.size(); }
private:
    unsigned long long floor, overlap, horizon;
    std::size_t capacity;
    std::set<std::pair<unsigned long long, std::string>> seen;
};

int self_test() {
    if (json("a\n\"\\\t") != "\"a\\n\\\"\\\\\\t\"") throw std::runtime_error("JSON escaping");
    if (json(std::string(1, '\x01')) != "\"\\u0001\"") throw std::runtime_error("JSON control character");
    const std::string xml = "<Data Name='Application'>C:\\a&amp;b&lt;c&gt;.exe</Data><Data Name=\"ProcessID\">123</Data>";
    if (xml_value(xml, "Application") != "C:\\a&b<c>.exe") throw std::runtime_error("XML entities");
    if (xml_value(xml, "ProcessID") != "123") throw std::runtime_error("XML quote style");
    if (!xml_value(xml, "Missing").empty()) throw std::runtime_error("XML missing field");
    if (counts_json({}) != "{}") throw std::runtime_error("Empty type counts");
    if (counts_json({{3, 2}, {0, 1}}) != "{\"0\":1,\"3\":2}") throw std::runtime_error("Type counts");
    if (error_line_json("wfp_enum_error", "FwpmNetEventEnum3", 5) != "{\"kind\":\"wfp_enum_error\",\"operation\":\"FwpmNetEventEnum3\",\"code\":5}")
        throw std::runtime_error("Enumeration error line");
    CappedCounter capped(2);
    if (!capped.record() || !capped.record() || capped.record() || capped.record() || capped.count != 4)
        throw std::runtime_error("Capped counter");
    PollWindow window(1000, 100, 3);
    if (window.begin() != 1000) throw std::runtime_error("Poll window starts at floor");
    if (!window.accept(1010, "a") || window.accept(1010, "a")) throw std::runtime_error("Poll dedup");
    if (!window.accept(1010, "b") || !window.accept(1020, "a")) throw std::runtime_error("Poll distinct keys");
    if (window.begin() != 1000) throw std::runtime_error("Poll window floor with overlap");
    window.finish(1500);
    if (window.begin() != 1400) throw std::runtime_error("Poll window overlap");
    if (window.size() != 0) throw std::runtime_error("Poll prune before window");
    if (window.accept(1399, "c")) throw std::runtime_error("Poll rejects events before window");
    if (!window.accept(1450, "c") || window.accept(1450, "c")) throw std::runtime_error("Poll overlap dedup");
    window.finish(1460);
    if (window.begin() != 1400 || window.accept(1450, "c")) throw std::runtime_error("Poll keeps overlap keys");
    for (const char* id : {"d", "e", "f"}) window.accept(1455, id);
    if (window.size() != 3) throw std::runtime_error("Poll capacity");
    window.finish(1600);
    if (window.begin() != 1500) throw std::runtime_error("Poll horizon is monotonic");
    std::cout << "native-events helper self-tests passed\n";
    return 0;
}

#ifndef _WIN32
int main() { return self_test(); }
#endif

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
            if (c < 32) {
                result += "\\u00";
                result += digits[c >> 4];
                result += digits[c & 15];
            } else result += static_cast<char>(c);
        }
    }
    return result + '"';
}

std::string counts_json(const std::map<unsigned, unsigned long long>& counts) {
    std::string result = "{";
    for (const auto& entry : counts) {
        if (result.size() > 1) result += ',';
        result += "\"" + std::to_string(entry.first) + "\":" + std::to_string(entry.second);
    }
    return result + '}';
}

std::string error_line_json(const std::string& kind, const std::string& operation, unsigned long code) {
    return "{\"kind\":" + json(kind) + ",\"operation\":" + json(operation) + ",\"code\":" + std::to_string(code) + "}";
}

bool CappedCounter::record() { return ++count <= cap; }

PollWindow::PollWindow(unsigned long long start, unsigned long long margin, std::size_t limit)
    : floor(start), overlap(margin), horizon(start), capacity(limit) {}

unsigned long long PollWindow::begin() const {
    const auto start = horizon > overlap ? horizon - overlap : 0;
    return start > floor ? start : floor;
}

bool PollWindow::accept(unsigned long long timestamp, const std::string& identity) {
    if (timestamp < begin() || !seen.emplace(timestamp, identity).second) return false;
    if (seen.size() > capacity) seen.erase(seen.begin());
    return true;
}

void PollWindow::finish(unsigned long long end) {
    if (end > horizon) horizon = end;
    const auto start = begin();
    while (!seen.empty() && seen.begin()->first < start) seen.erase(seen.begin());
}

std::string xml_value(const std::string& xml, const std::string& name) {
    auto pos = xml.find("Name='" + name + "'");
    if (pos == std::string::npos) pos = xml.find("Name=\"" + name + "\"");
    if (pos == std::string::npos) return {};
    auto start = xml.find('>', pos);
    auto end = xml.find("</Data>", start);
    if (start == std::string::npos || end == std::string::npos) return {};
    std::string value = xml.substr(start + 1, end - start - 1);
    const std::pair<const char*, const char*> entities[] = {
        {"&lt;", "<"}, {"&gt;", ">"}, {"&quot;", "\""}, {"&apos;", "'"}, {"&amp;", "&"}
    };
    for (const auto& entity : entities) {
        std::size_t p = 0;
        while ((p = value.find(entity.first, p)) != std::string::npos) {
            value.replace(p, std::string(entity.first).size(), entity.second);
            p += std::string(entity.second).size();
        }
    }
    return value;
}

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fwpmu.h>
#include <winevt.h>
#include <sddl.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <fstream>
#include <iterator>
#include <limits>
#include <mutex>
#include <sstream>
#include <thread>
#include <vector>

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")

static unsigned long long qpc() {
    LARGE_INTEGER value{};
    QueryPerformanceCounter(&value);
    return static_cast<unsigned long long>(value.QuadPart);
}

static unsigned long long filetime(FILETIME value) {
    return (static_cast<unsigned long long>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
}

static unsigned long long utc_now() {
    FILETIME value{};
    GetSystemTimePreciseAsFileTime(&value);
    return filetime(value);
}

static std::string utf8(const wchar_t* value, int length) {
    if (!value || length <= 0) return {};
    int count = WideCharToMultiByte(CP_UTF8, 0, value, length, nullptr, 0, nullptr, nullptr);
    if (count <= 0) throw std::runtime_error("WideCharToMultiByte");
    std::string result(static_cast<std::size_t>(count), '\0');
    if (!WideCharToMultiByte(CP_UTF8, 0, value, length, result.data(), count, nullptr, nullptr))
        throw std::runtime_error("WideCharToMultiByte");
    return result;
}

static std::string blob_hex(const FWP_BYTE_BLOB& blob) {
    const char* digits = "0123456789abcdef";
    std::string result;
    result.reserve(static_cast<std::size_t>(blob.size) * 2);
    for (UINT32 i = 0; i < blob.size; ++i) {
        result += digits[blob.data[i] >> 4];
        result += digits[blob.data[i] & 15];
    }
    return result;
}

static std::string blob_path(const FWP_BYTE_BLOB& blob) {
    if (!blob.data || blob.size % sizeof(wchar_t)) return {};
    std::vector<wchar_t> text(blob.size / sizeof(wchar_t));
    std::memcpy(text.data(), blob.data, blob.size);
    while (!text.empty() && text.back() == L'\0') text.pop_back();
    return utf8(text.data(), static_cast<int>(text.size()));
}

static std::string sid_text(SID* sid) {
    LPWSTR text = nullptr;
    if (!sid || !ConvertSidToStringSidW(sid, &text)) return {};
    std::string result;
    try { result = utf8(text, static_cast<int>(wcslen(text))); }
    catch (...) { LocalFree(text); throw; }
    LocalFree(text);
    return result;
}

static FILETIME to_filetime(unsigned long long value) {
    FILETIME result{};
    result.dwLowDateTime = static_cast<DWORD>(value);
    result.dwHighDateTime = static_cast<DWORD>(value >> 32);
    return result;
}

template <typename Header>
static std::string address(const Header& header, bool local) {
    wchar_t text[INET6_ADDRSTRLEN]{};
    if (header.ipVersion == FWP_IP_VERSION_V4) {
        IN_ADDR addr{};
        addr.s_addr = htonl(local ? header.localAddrV4 : header.remoteAddrV4);
        if (!InetNtopW(AF_INET, &addr, text, INET6_ADDRSTRLEN)) return {};
    } else if (header.ipVersion == FWP_IP_VERSION_V6) {
        const auto& addr = local ? header.localAddrV6 : header.remoteAddrV6;
        if (!InetNtopW(AF_INET6, const_cast<UINT8*>(addr.byteArray16), text, INET6_ADDRSTRLEN)) return {};
    } else return {};
    return utf8(text, static_cast<int>(wcslen(text)));
}

struct Output {
    std::ofstream file;
    std::mutex mutex;
    std::condition_variable changed;
    std::deque<std::string> lines;
    std::atomic<unsigned long long> dropped{0};
    std::atomic<unsigned long long> errors{0};
    std::atomic<unsigned long long> wfp_count{0};
    std::atomic<unsigned long long> wfp_raw_count{0};
    std::mutex type_mutex;
    std::map<unsigned, unsigned long long> wfp_type_counts;
    unsigned long long enum_total = 0, enum_emitted = 0;
    CappedCounter enum_errors{5};
    bool enum_truncated = false;
    unsigned long long polls = 0, poll_max_qpc = 0;
    CappedCounter poll_errors{5};
    std::map<unsigned, unsigned long long> enum_type_counts;
    std::atomic<unsigned long long> security_count{0};
    bool stop = false;
    std::thread writer;

    explicit Output(const char* path) : file(path, std::ios::binary | std::ios::trunc) {
        if (!file) throw std::runtime_error("Cannot open output file");
        writer = std::thread([this] {
            std::unique_lock<std::mutex> lock(mutex);
            while (!stop || !lines.empty()) {
                changed.wait(lock, [this] { return stop || !lines.empty(); });
                while (!lines.empty()) {
                    auto line = std::move(lines.front());
                    lines.pop_front();
                    lock.unlock();
                    file << line << '\n';
                    file.flush();
                    if (!file) ++errors;
                    lock.lock();
                }
            }
        });
    }

    void push(std::string line) {
        std::lock_guard<std::mutex> lock(mutex);
        if (lines.size() >= 16384) { ++dropped; return; }
        lines.push_back(std::move(line));
        changed.notify_one();
    }

    void error(const char* operation, DWORD code) {
        ++errors;
        push("{\"kind\":\"error\",\"operation\":" + json(operation) +
             ",\"code\":" + std::to_string(code) + ",\"recv_qpc\":" + std::to_string(qpc()) + "}");
    }

    void enum_error(const char* operation, DWORD code) {
        if (enum_errors.record()) push(error_line_json("wfp_enum_error", operation, code));
    }

    void poll_error(const char* operation, DWORD code) {
        if (poll_errors.record()) push(error_line_json("wfp_poll_error", operation, code));
    }

    void count_type(unsigned type) {
        std::lock_guard<std::mutex> lock(type_mutex);
        ++wfp_type_counts[type];
    }

    std::string type_counts() {
        std::lock_guard<std::mutex> lock(type_mutex);
        return counts_json(wfp_type_counts);
    }

    void finish() {
        if (!writer.joinable()) return;
        {
            std::lock_guard<std::mutex> lock(mutex);
            stop = true;
        }
        changed.notify_one();
        writer.join();
    }

    ~Output() { finish(); }
};

template <typename Header>
static std::string identity(const Header& h) {
    std::string id = std::to_string(h.ipVersion) + ':' + std::to_string(h.ipProtocol) + ':' +
        std::to_string(h.localPort) + ':' + std::to_string(h.remotePort) + ':';
    if (h.ipVersion == FWP_IP_VERSION_V4) id += std::to_string(h.localAddrV4) + ':' + std::to_string(h.remoteAddrV4);
    else if (h.ipVersion == FWP_IP_VERSION_V6) {
        id.append(reinterpret_cast<const char*>(h.localAddrV6.byteArray16), 16);
        id.append(reinterpret_cast<const char*>(h.remoteAddrV6.byteArray16), 16);
    }
    id += ':';
    if (h.appId.data) id.append(reinterpret_cast<const char*>(h.appId.data), h.appId.size);
    return id;
}

template <typename Event>
static std::string wfp_line(const char* kind, const Event* event,
                            unsigned long long received, unsigned long long receipt_utc) {
    const auto& h = event->header;
    const auto flags = h.flags;
    const UINT32 required = FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET | FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET |
        FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET | FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET |
        FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET | FWPM_NET_EVENT_FLAG_APP_ID_SET |
        FWPM_NET_EVENT_FLAG_IP_VERSION_SET;
    const auto* allow = event->classifyAllow;
    const bool app_set = (flags & FWPM_NET_EVENT_FLAG_APP_ID_SET) && h.appId.data && h.appId.size;
    const auto path = app_set ? blob_path(h.appId) : std::string{};
    const auto local = (flags & FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET) ? address(h, true) : std::string{};
    const auto remote = (flags & FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET) ? address(h, false) : std::string{};
    const bool direction_known = allow && (allow->msFwpDirection == FWP_DIRECTION_OUTBOUND || allow->msFwpDirection == FWP_DIRECTION_INBOUND);
    const bool complete = (flags & required) == required && direction_known && !path.empty() && !local.empty() && !remote.empty();
    std::ostringstream s;
    s << "{\"kind\":" << json(kind) << ",\"recv_qpc\":" << received << ",\"receipt_filetime\":" << receipt_utc
      << ",\"event_filetime\":" << filetime(h.timeStamp) << ",\"flags\":" << flags
      << ",\"event_type\":" << event->type << ",\"pid\":null,\"app_path\":" << json(path)
      << ",\"app_id_hex\":" << json(app_set ? blob_hex(h.appId) : std::string{})
      << ",\"app_id_bytes\":" << (app_set ? h.appId.size : 0)
      << ",\"ip_version\":" << static_cast<int>(h.ipVersion)
      << ",\"protocol\":" << ((flags & FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET) ? std::to_string(h.ipProtocol) : "null")
      << ",\"local_ip\":" << json(local) << ",\"remote_ip\":" << json(remote)
      << ",\"local_port\":" << ((flags & FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET) ? std::to_string(h.localPort) : "null")
      << ",\"remote_port\":" << ((flags & FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET) ? std::to_string(h.remotePort) : "null")
      << ",\"scope_id\":" << ((flags & FWPM_NET_EVENT_FLAG_SCOPE_ID_SET) ? std::to_string(h.scopeId) : "null")
      << ",\"user_sid\":" << json((flags & FWPM_NET_EVENT_FLAG_USER_ID_SET) ? sid_text(h.userId) : std::string{})
      << ",\"direction\":" << json(!direction_known ? "unknown" : (allow->msFwpDirection == FWP_DIRECTION_OUTBOUND ? "outbound" : "inbound"))
      << ",\"complete\":" << (complete ? "true" : "false")
      << ",\"layer_id\":" << (allow ? std::to_string(allow->layerId) : "null")
      << ",\"filter_id\":" << (allow ? std::to_string(allow->filterId) : "null")
      << ",\"reauth_reason\":" << (allow ? std::to_string(allow->reauthReason) : "null")
      << ",\"is_loopback\":" << (allow && allow->isLoopback ? "true" : "false") << "}";
    return s.str();
}

template <typename Event>
static void CALLBACK net_event(void* context, const Event* event) noexcept {
    const auto received = qpc();
    const auto receipt_utc = utc_now();
    auto& out = *static_cast<Output*>(context);
    try {
        ++out.wfp_raw_count;
        if (!event) return;
        out.count_type(static_cast<unsigned>(event->type));
        if (event->type != FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW) return;
        ++out.wfp_count;
        out.push(wfp_line("wfp", event, received, receipt_utc));
    } catch (...) { out.error("net_event_callback", ERROR_INVALID_DATA); }
}

static std::string number(const std::string& input) {
    if (input.empty()) return "null";
    std::size_t consumed = 0;
    auto value = std::stoull(input, &consumed, input.size() > 2 && input.substr(0, 2) == "0x" ? 16 : 10);
    if (consumed != input.size()) throw std::runtime_error("Invalid event number");
    return std::to_string(value);
}

static unsigned long long event_time(const std::string& xml) {
    auto start = xml.find("SystemTime='");
    char quote = '\'';
    if (start == std::string::npos) { start = xml.find("SystemTime=\""); quote = '"'; }
    if (start == std::string::npos) return 0;
    start += 12;
    auto text = xml.substr(start, xml.find(quote, start) - start);
    unsigned year, month, day, hour, minute, second;
    if (sscanf_s(text.c_str(), "%u-%u-%uT%u:%u:%u", &year, &month, &day, &hour, &minute, &second) != 6) return 0;
    SYSTEMTIME st{};
    st.wYear = static_cast<WORD>(year); st.wMonth = static_cast<WORD>(month); st.wDay = static_cast<WORD>(day);
    st.wHour = static_cast<WORD>(hour); st.wMinute = static_cast<WORD>(minute); st.wSecond = static_cast<WORD>(second);
    FILETIME ft{};
    if (!SystemTimeToFileTime(&st, &ft)) return 0;
    unsigned long long fraction = 0;
    const auto dot = text.find('.');
    if (dot != std::string::npos) {
        for (std::size_t i = 0; i < 7; ++i) {
            const auto p = dot + i + 1;
            fraction = fraction * 10 + ((p < text.size() && text[p] >= '0' && text[p] <= '9') ? text[p] - '0' : 0);
        }
    }
    return filetime(ft) + fraction;
}

static DWORD WINAPI security_event(EVT_SUBSCRIBE_NOTIFY_ACTION action, void* context, EVT_HANDLE event) noexcept {
    const auto received = qpc();
    const auto receipt_utc = utc_now();
    auto& out = *static_cast<Output*>(context);
    try {
        if (action == EvtSubscribeActionError) {
            out.error("EvtSubscribeActionError", static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(event)));
            return ERROR_SUCCESS;
        }
        DWORD bytes = 0, properties = 0;
        if (!EvtRender(nullptr, event, EvtRenderEventXml, 0, nullptr, &bytes, &properties) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            out.error("EvtRender_size", GetLastError()); return ERROR_SUCCESS;
        }
        std::vector<wchar_t> buffer((bytes + sizeof(wchar_t) - 1) / sizeof(wchar_t));
        if (!EvtRender(nullptr, event, EvtRenderEventXml, bytes, buffer.data(), &bytes, &properties)) {
            out.error("EvtRender", GetLastError()); return ERROR_SUCCESS;
        }
        const auto xml = utf8(buffer.data(), static_cast<int>(wcslen(buffer.data())));
        const auto direction_token = xml_value(xml, "Direction");
        const bool outbound = direction_token == "%%14593";
        const bool inbound = direction_token == "%%14592";
        const auto app = xml_value(xml, "Application");
        const auto proto = number(xml_value(xml, "Protocol"));
        const auto source_ip = xml_value(xml, "SourceAddress"), dest_ip = xml_value(xml, "DestAddress");
        const auto source_port = number(xml_value(xml, "SourcePort")), dest_port = number(xml_value(xml, "DestPort"));
        const bool complete = (outbound || inbound) && !app.empty() && !source_ip.empty() && !dest_ip.empty() &&
            proto != "null" && source_port != "null" && dest_port != "null";
        std::ostringstream s;
        s << "{\"kind\":\"security5156\",\"recv_qpc\":" << received << ",\"receipt_filetime\":" << receipt_utc
          << ",\"event_filetime\":" << event_time(xml) << ",\"app_path\":" << json(app)
          << ",\"pid\":" << number(xml_value(xml, "ProcessID")) << ",\"protocol\":" << proto
          << ",\"direction\":" << json(outbound ? "outbound" : inbound ? "inbound" : "unknown")
          << ",\"local_ip\":" << json(outbound ? source_ip : dest_ip)
          << ",\"local_port\":" << (outbound ? source_port : dest_port)
          << ",\"remote_ip\":" << json(outbound ? dest_ip : source_ip)
          << ",\"remote_port\":" << (outbound ? dest_port : source_port)
          << ",\"layer_id\":" << number(xml_value(xml, "LayerRTID"))
          << ",\"filter_id\":" << number(xml_value(xml, "FilterRTID"))
          << ",\"complete\":" << (complete ? "true" : "false") << ",\"raw_xml\":" << json(xml) << "}";
        ++out.security_count;
        out.push(s.str());
    } catch (...) { out.error("security_event_callback", ERROR_INVALID_DATA); }
    return ERROR_SUCCESS;
}

struct Engine {
    HANDLE engine = nullptr;
    HANDLE subscription = nullptr;
    EVT_HANDLE security = nullptr;
    UINT32 old_collect = 0, old_keywords = 0;
    bool collect_changed = false, keywords_changed = false, enumerate_on_close = false;
    FILETIME start_time{};
    std::string api = "subscribe2";
    unsigned poll_interval_ms = 5, poll_overlap_ms = 1000;
    std::atomic<bool> poll_stop{false};
    std::thread poller;
    Output& out;

    explicit Engine(Output& output) : out(output) {}
    static void check(DWORD result, const char* operation) {
        if (result != ERROR_SUCCESS) throw std::runtime_error(std::string(operation) + ": " + std::to_string(result));
    }
    UINT32 get(FWPM_ENGINE_OPTION option) {
        FWP_VALUE0* value = nullptr;
        check(FwpmEngineGetOption0(engine, option, &value), "FwpmEngineGetOption0");
        if (!value) throw std::runtime_error("Null engine option");
        const UINT32 result = value->uint32;
        const bool valid = value->type == FWP_UINT32;
        FwpmFreeMemory0(reinterpret_cast<void**>(&value));
        if (!valid) throw std::runtime_error("Engine option is not UINT32");
        return result;
    }
    DWORD set(FWPM_ENGINE_OPTION option, UINT32 number) {
        FWP_VALUE0 value{}; value.type = FWP_UINT32; value.uint32 = number;
        return FwpmEngineSetOption0(engine, option, &value);
    }
    void start(const std::string& state_path) {
        GetSystemTimePreciseAsFileTime(&start_time);
        check(FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &engine), "FwpmEngineOpen0");
        old_collect = get(FWPM_ENGINE_COLLECT_NET_EVENTS);
        old_keywords = get(FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS);
        std::ofstream backup(state_path, std::ios::binary | std::ios::trunc);
        backup << "{\"version\":1,\"old_collect\":" << old_collect
               << ",\"old_keywords\":" << old_keywords << "}\n";
        backup.flush();
        if (!backup) throw std::runtime_error("Cannot persist BFE state before mutation");
        backup.close();
        if (old_collect != 1) {
            check(set(FWPM_ENGINE_COLLECT_NET_EVENTS, 1), "Set COLLECT_NET_EVENTS"); collect_changed = true;
        }
        if (!(old_keywords & FWPM_NET_EVENT_KEYWORD_CLASSIFY_ALLOW)) {
            check(set(FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS, old_keywords | FWPM_NET_EVENT_KEYWORD_CLASSIFY_ALLOW), "Set CLASSIFY_ALLOW keyword");
            keywords_changed = true;
        }
        const auto collect_after = get(FWPM_ENGINE_COLLECT_NET_EVENTS);
        const auto keywords_after = get(FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS);
        enumerate_on_close = true;
        FWPM_NET_EVENT_SUBSCRIPTION0 request{};
        if (api == "subscribe2")
            check(FwpmNetEventSubscribe2(engine, &request, net_event<FWPM_NET_EVENT3>, &out, &subscription), "FwpmNetEventSubscribe2");
        else if (api == "subscribe4")
            check(FwpmNetEventSubscribe4(engine, &request, net_event<FWPM_NET_EVENT5>, &out, &subscription), "FwpmNetEventSubscribe4");
        else poller = std::thread([this] { poll_loop(); });
        security = EvtSubscribe(nullptr, nullptr, L"Security", L"*[System[EventID=5156]]", nullptr, &out,
                                security_event, EvtSubscribeToFutureEvents | EvtSubscribeStrict);
        if (!security) throw std::runtime_error("EvtSubscribe: " + std::to_string(GetLastError()));
        LARGE_INTEGER frequency{}; QueryPerformanceFrequency(&frequency);
        out.push("{\"kind\":\"ready\",\"recv_qpc\":" + std::to_string(qpc()) +
            ",\"receipt_filetime\":" + std::to_string(utc_now()) + ",\"qpc_frequency\":" + std::to_string(frequency.QuadPart) +
            ",\"old_collect\":" + std::to_string(old_collect) + ",\"old_keywords\":" + std::to_string(old_keywords) + ",\"wfp_api\":" + json(api) +
            ",\"collect_after\":" + std::to_string(collect_after) + ",\"keywords_after\":" + std::to_string(keywords_after) + "}");
    }
    void restore_from(const std::string& path) {
        std::ifstream input(path, std::ios::binary);
        if (!input) throw std::runtime_error("Cannot read restore state");
        const std::string text{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
        const auto field = [&text](const std::string& key) {
            auto p = text.find("\"" + key + "\"");
            if (p == std::string::npos) throw std::runtime_error("Missing restore state field");
            p = text.find(':', p);
            if (p == std::string::npos) throw std::runtime_error("Invalid restore state");
            auto end = text.find_first_of(",}", p + 1);
            if (end == std::string::npos) throw std::runtime_error("Invalid restore state");
            const auto digits = text.substr(p + 1, end - p - 1);
            std::size_t consumed = 0;
            const auto value = std::stoull(digits, &consumed, 10);
            if (digits.find_first_not_of(" \t\r\n", consumed) != std::string::npos ||
                value > std::numeric_limits<UINT32>::max()) throw std::runtime_error("Invalid restore state value");
            return static_cast<UINT32>(value);
        };
        if (field("version") != 1) throw std::runtime_error("Unsupported restore state version");
        old_collect = field("old_collect");
        old_keywords = field("old_keywords");
        if (old_collect > 1) throw std::runtime_error("Invalid saved collect option");
        check(FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &engine), "FwpmEngineOpen0 restore");
        collect_changed = old_collect != 1;
        keywords_changed = !(old_keywords & FWPM_NET_EVENT_KEYWORD_CLASSIFY_ALLOW);
    }
    void restore(FWPM_ENGINE_OPTION option, UINT32 expected, UINT32 previous, const char* operation) noexcept {
        try {
            const auto current = get(option);
            if (current == previous) return;
            if (current != expected) { out.error(operation, ERROR_BUSY); return; }
            const auto result = set(option, previous);
            if (result) out.error(operation, result);
        } catch (...) { out.error(operation, ERROR_INVALID_DATA); }
    }
    bool poll_once(HANDLE session, PollWindow& window) {
        FWPM_NET_EVENT_ENUM_TEMPLATE0 range{};
        range.startTime = to_filetime(window.begin());
        GetSystemTimePreciseAsFileTime(&range.endTime);
        HANDLE handle = nullptr;
        const auto created = FwpmNetEventCreateEnumHandle0(session, &range, &handle);
        if (created) { out.poll_error("FwpmNetEventCreateEnumHandle0", created); return false; }
        bool complete = true;
        const UINT32 batch = 256;
        for (;;) {
            FWPM_NET_EVENT3** entries = nullptr;
            UINT32 count = 0;
            const auto result = FwpmNetEventEnum3(session, handle, batch, &entries, &count);
            if (result) { out.poll_error("FwpmNetEventEnum3", result); complete = false; break; }
            for (UINT32 i = 0; i < count; ++i) {
                try {
                    const auto* entry = entries[i];
                    if (!entry || entry->type != FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW) continue;
                    if (!window.accept(filetime(entry->header.timeStamp), identity(entry->header))) continue;
                    ++out.wfp_count;
                    out.push(wfp_line("wfp", entry, qpc(), utc_now()));
                } catch (...) { out.poll_error("FwpmNetEventEnum3_entry", ERROR_INVALID_DATA); }
            }
            if (entries) FwpmFreeMemory0(reinterpret_cast<void**>(&entries));
            if (count < batch) break;
        }
        const auto destroyed = FwpmNetEventDestroyEnumHandle0(session, handle);
        if (destroyed) out.poll_error("FwpmNetEventDestroyEnumHandle0", destroyed);
        if (complete) window.finish(filetime(range.endTime));
        return complete;
    }
    void poll_loop() noexcept {
        HANDLE session = nullptr;
        try {
            const auto opened = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &session);
            if (opened) { out.poll_error("FwpmEngineOpen0", opened); return; }
            PollWindow window(filetime(start_time), poll_overlap_ms * 10000ULL, 65536);
            while (!poll_stop) {
                const auto began = qpc();
                try { poll_once(session, window); }
                catch (...) { out.poll_error("poll_once", ERROR_INVALID_DATA); }
                ++out.polls;
                const auto elapsed = qpc() - began;
                if (elapsed > out.poll_max_qpc) out.poll_max_qpc = elapsed;
                std::this_thread::sleep_for(std::chrono::milliseconds(poll_interval_ms));
            }
        } catch (...) { out.poll_error("poll_loop", ERROR_INVALID_DATA); }
        if (session) {
            const auto closed = FwpmEngineClose0(session);
            if (closed) out.poll_error("FwpmEngineClose0", closed);
        }
    }
    void enumerate() noexcept {
        HANDLE handle = nullptr;
        try {
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
            FWPM_NET_EVENT_ENUM_TEMPLATE0 window{};
            window.startTime = start_time;
            GetSystemTimePreciseAsFileTime(&window.endTime);
            const auto created = FwpmNetEventCreateEnumHandle0(engine, &window, &handle);
            if (created) { out.enum_error("FwpmNetEventCreateEnumHandle0", created); return; }
            const UINT32 batch = 256;
            for (int batches = 0;; ++batches) {
                if (batches >= 64 || std::chrono::steady_clock::now() >= deadline) {
                    FWPM_NET_EVENT3** rest = nullptr;
                    UINT32 remaining = 0;
                    const auto probe = FwpmNetEventEnum3(engine, handle, 1, &rest, &remaining);
                    if (probe) out.enum_error("FwpmNetEventEnum3_probe", probe);
                    if (rest) FwpmFreeMemory0(reinterpret_cast<void**>(&rest));
                    out.enum_truncated = probe || remaining > 0;
                    break;
                }
                FWPM_NET_EVENT3** entries = nullptr;
                UINT32 count = 0;
                const auto result = FwpmNetEventEnum3(engine, handle, batch, &entries, &count);
                if (result) { out.enum_error("FwpmNetEventEnum3", result); break; }
                for (UINT32 i = 0; i < count; ++i) {
                    try {
                        ++out.enum_total;
                        if (!entries[i]) continue;
                        ++out.enum_type_counts[static_cast<unsigned>(entries[i]->type)];
                        if (entries[i]->type == FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW && out.enum_emitted < 200) {
                            ++out.enum_emitted;
                            out.push(wfp_line("wfp_enum", entries[i], qpc(), utc_now()));
                        }
                    } catch (...) { out.enum_error("FwpmNetEventEnum3_entry", ERROR_INVALID_DATA); }
                }
                if (entries) FwpmFreeMemory0(reinterpret_cast<void**>(&entries));
                if (count < batch) break;
            }
        } catch (...) { out.enum_error("net_event_enum", ERROR_INVALID_DATA); }
        if (handle) {
            const auto destroyed = FwpmNetEventDestroyEnumHandle0(engine, handle);
            if (destroyed) out.enum_error("FwpmNetEventDestroyEnumHandle0", destroyed);
        }
    }
    ~Engine() {
        poll_stop = true;
        if (poller.joinable()) poller.join();
        if (security) EvtClose(security);
        if (engine && enumerate_on_close) enumerate();
        if (subscription) {
            const auto result = FwpmNetEventUnsubscribe0(engine, subscription);
            if (result) out.error("FwpmNetEventUnsubscribe0", result);
        }
        if (engine) {
            if (keywords_changed) {
                restore(FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS, old_keywords | FWPM_NET_EVENT_KEYWORD_CLASSIFY_ALLOW,
                        old_keywords, "Restore MATCH_ANY_KEYWORDS");
            }
            if (collect_changed) {
                restore(FWPM_ENGINE_COLLECT_NET_EVENTS, 1, old_collect, "Restore COLLECT_NET_EVENTS");
            }
            const auto result = FwpmEngineClose0(engine);
            if (result) out.error("FwpmEngineClose0", result);
        }
    }
};

static std::atomic<bool> interrupted{false};

static BOOL WINAPI console_control(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT) {
        interrupted = true;
        return TRUE;
    }
    return FALSE;
}

struct Winsock {
    Winsock() {
        WSADATA data{};
        if (WSAStartup(MAKEWORD(2, 2), &data)) throw std::runtime_error("WSAStartup");
    }
    ~Winsock() { WSACleanup(); }
};

int main(int argc, char** argv) {
    try {
        int seconds = 30;
        int poll_interval = 5, poll_overlap = 1000;
        std::string output = "native-events.jsonl", stop_file, state_out, restore_state, api = "subscribe2";
        for (int i = 1; i < argc; ++i) {
            const std::string arg = argv[i];
            if (arg == "--self-test") return self_test();
            if (i + 1 >= argc) throw std::runtime_error("Usage: native-events --seconds N --out PATH [--stop-file PATH] [--state-out PATH] [--wfp-api subscribe2|subscribe4|poll] [--poll-interval-ms N] [--poll-overlap-ms N] | --restore-state PATH --out PATH | --self-test");
            if (arg == "--seconds") seconds = std::stoi(argv[++i]);
            else if (arg == "--out") output = argv[++i];
            else if (arg == "--stop-file") stop_file = argv[++i];
            else if (arg == "--state-out") state_out = argv[++i];
            else if (arg == "--restore-state") restore_state = argv[++i];
            else if (arg == "--wfp-api") api = argv[++i];
            else if (arg == "--poll-interval-ms") poll_interval = std::stoi(argv[++i]);
            else if (arg == "--poll-overlap-ms") poll_overlap = std::stoi(argv[++i]);
            else throw std::runtime_error("Unknown argument: " + arg);
        }
        if (seconds < 1 || seconds > 3600) throw std::runtime_error("seconds must be 1..3600");
        if (api != "subscribe2" && api != "subscribe4" && api != "poll") throw std::runtime_error("wfp-api must be subscribe2, subscribe4 or poll");
        if (poll_interval < 1 || poll_interval > 1000) throw std::runtime_error("poll-interval-ms must be 1..1000");
        if (poll_overlap < 0 || poll_overlap > 60000) throw std::runtime_error("poll-overlap-ms must be 0..60000");
        Output out(output.c_str());
        if (!restore_state.empty()) {
            {
                Engine engine(out);
                engine.restore_from(restore_state);
            }
            out.push("{\"kind\":\"restore_summary\",\"errors\":" + std::to_string(out.errors.load()) + "}");
            out.finish();
            return out.errors || out.dropped ? 2 : 0;
        }
        if (state_out.empty()) state_out = output + ".state.json";
        Winsock winsock;
        if (!SetConsoleCtrlHandler(console_control, TRUE)) throw std::runtime_error("SetConsoleCtrlHandler");
        {
            Engine engine(out);
            engine.api = api;
            engine.poll_interval_ms = static_cast<unsigned>(poll_interval);
            engine.poll_overlap_ms = static_cast<unsigned>(poll_overlap);
            engine.start(state_out);
            const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
            while (!interrupted && std::chrono::steady_clock::now() < until) {
                if (!stop_file.empty() && GetFileAttributesA(stop_file.c_str()) != INVALID_FILE_ATTRIBUTES) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }
        SetConsoleCtrlHandler(console_control, FALSE);
        LARGE_INTEGER frequency{};
        QueryPerformanceFrequency(&frequency);
        out.push("{\"kind\":\"summary\",\"recv_qpc\":" + std::to_string(qpc()) +
            ",\"wfp_api\":" + json(api) +
            ",\"wfp_count\":" + std::to_string(out.wfp_count.load()) +
            ",\"wfp_raw_count\":" + std::to_string(out.wfp_raw_count.load()) +
            ",\"wfp_type_counts\":" + out.type_counts() +
            ",\"wfp_enum_total\":" + std::to_string(out.enum_total) +
            ",\"wfp_enum_type_counts\":" + counts_json(out.enum_type_counts) +
            ",\"wfp_enum_emitted\":" + std::to_string(out.enum_emitted) +
            ",\"wfp_enum_errors\":" + std::to_string(out.enum_errors.count) +
            ",\"wfp_enum_truncated\":" + (out.enum_truncated ? "true" : "false") +
            ",\"wfp_polls\":" + std::to_string(out.polls) +
            ",\"wfp_poll_errors\":" + std::to_string(out.poll_errors.count) +
            ",\"wfp_poll_max_ms\":" + std::to_string(static_cast<double>(out.poll_max_qpc) * 1000.0 / static_cast<double>(frequency.QuadPart)) +
            ",\"security5156_count\":" + std::to_string(out.security_count.load()) +
            ",\"queue_dropped\":" + std::to_string(out.dropped.load()) +
            ",\"errors\":" + std::to_string(out.errors.load()) + "}");
        out.finish();
        return out.errors || out.dropped ? 2 : 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
#endif
