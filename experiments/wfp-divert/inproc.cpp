#include <algorithm>
#include <cmath>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace inproc {

enum class MatchOutcome { NoEvent, Matched, Ambiguous };
enum class PendingResolution { Retry, Matched, Ambiguous, Timeout, Discard };
enum class RestoreAction { AlreadyRestored, Restore, Conflict };

PendingResolution pending_resolution(MatchOutcome outcome, int64_t observed, int64_t deadline) {
    if (observed >= deadline) return PendingResolution::Timeout;
    if (outcome == MatchOutcome::Matched) return PendingResolution::Matched;
    if (outcome == MatchOutcome::Ambiguous) return PendingResolution::Ambiguous;
    return PendingResolution::Retry;
}

struct GenerationTag {
    int64_t generation;
    int64_t capture_qpc;
    bool operator==(const GenerationTag& other) const {
        return generation == other.generation && capture_qpc == other.capture_qpc;
    }
};

PendingResolution snapshot_resolution(MatchOutcome outcome, bool complete,
        GenerationTag requested, GenerationTag current, int64_t observed, int64_t deadline) {
    if (!complete || !(requested == current)) return PendingResolution::Discard;
    return pending_resolution(outcome, observed, deadline);
}

int64_t lookup_wakeup(bool query_busy, int64_t retry, int64_t deadline) {
    return query_busy || !retry ? deadline : (std::min)(retry, deadline);
}

class HandoffState {
    enum class Phase { Idle, Queued, Running, Ready, Stopped };
    Phase phase = Phase::Idle;
    bool transition(Phase expected, Phase next) {
        if (phase != expected) return false;
        phase = next;
        return true;
    }
public:
    bool submit() { return transition(Phase::Idle, Phase::Queued); }
    bool start() { return transition(Phase::Queued, Phase::Running); }
    bool finish() { return transition(Phase::Running, Phase::Ready); }
    bool consume() { return transition(Phase::Ready, Phase::Idle); }
    bool busy() const { return phase == Phase::Queued || phase == Phase::Running || phase == Phase::Ready; }
    bool ready() const { return phase == Phase::Ready; }
    void stop() { phase = Phase::Stopped; }
};

enum class EnumScope { Legacy, Destination };

enum ConditionMask : uint32_t {
    EventTypeCondition = 1u << 0,
    ProtocolCondition = 1u << 1,
    LocalPortCondition = 1u << 2,
    RemoteAddressCondition = 1u << 3,
    RemotePortCondition = 1u << 4,
};

struct QueryTuple {
    uint32_t remote_address;
    uint16_t local_port;
    uint16_t remote_port;
    uint8_t protocol;
};

struct DestinationShape {
    uint8_t protocol = 0;
    bool has_subjects = false;
    std::optional<uint32_t> remote_address;
    std::optional<uint16_t> remote_port;
    std::optional<uint16_t> local_port;
};

DestinationShape destination_shape(const std::vector<QueryTuple>& subjects, uint8_t protocol) {
    DestinationShape result;
    result.protocol = protocol;
    for (const auto& subject : subjects) {
        if (subject.protocol != protocol) continue;
        if (!result.has_subjects) {
            result.has_subjects = true;
            result.remote_address = subject.remote_address;
            result.remote_port = subject.remote_port;
            result.local_port = subject.local_port;
        } else {
            if (result.remote_address && *result.remote_address != subject.remote_address) result.remote_address.reset();
            if (result.remote_port && *result.remote_port != subject.remote_port) result.remote_port.reset();
            if (result.local_port && *result.local_port != subject.local_port) result.local_port.reset();
        }
    }
    return result;
}

std::vector<uint32_t> condition_keys(uint32_t mask) {
    std::vector<uint32_t> result;
    for (uint32_t key : {EventTypeCondition, ProtocolCondition, RemoteAddressCondition,
                         RemotePortCondition, LocalPortCondition})
        if (mask & key) result.push_back(key);
    return result;
}

std::vector<uint32_t> destination_profiles(const DestinationShape& shape) {
    if (!shape.has_subjects) return {};
    uint32_t mask = EventTypeCondition | ProtocolCondition;
    if (shape.remote_address) mask |= RemoteAddressCondition;
    if (shape.remote_port) mask |= RemotePortCondition;
    if (shape.local_port) mask |= LocalPortCondition;
    std::vector<uint32_t> result{mask};
    for (uint32_t key : {LocalPortCondition, RemotePortCondition, RemoteAddressCondition,
                         ProtocolCondition, EventTypeCondition}) {
        if (!(mask & key)) continue;
        mask &= ~key;
        result.push_back(mask);
    }
    return result;
}

struct FilterPattern {
    uint8_t protocol;
    int level;
    bool multiple_ports;
    EnumScope scope = EnumScope::Legacy;
    uint32_t condition_mask = 0;
    size_t condition_count = 0;
    bool operator<(const FilterPattern& other) const {
        if (scope != other.scope) return scope < other.scope;
        if (protocol != other.protocol) return protocol < other.protocol;
        if (level != other.level) return level < other.level;
        if (condition_mask != other.condition_mask) return condition_mask < other.condition_mask;
        if (scope == EnumScope::Destination && condition_count != other.condition_count)
            return condition_count < other.condition_count;
        return multiple_ports < other.multiple_ports;
    }
};

class FilterCapabilityCache {
    std::set<FilterPattern> unsupported;
public:
    bool enabled = true;
    bool skip(const FilterPattern& pattern) const { return enabled && unsupported.count(pattern) != 0; }
    static bool cacheable(uint32_t error) {
        return error == 0x80320002u || error == 0x8032002Au || error == 0x80320026u || error == 0x80320027u;
    }
    static bool fallback_allowed(uint32_t error) {
        return cacheable(error) || error == 0x80320035u || error == 87;
    }
    bool reject(const FilterPattern& pattern, uint32_t error) {
        return enabled && cacheable(error) && unsupported.insert(pattern).second;
    }
};

bool copy_budget_allows(size_t copied, size_t next) {
    constexpr size_t capacity = 8 * 1024 * 1024;
    return next <= 65536 && copied <= capacity && next <= capacity - copied;
}

RestoreAction restore_action(uint32_t previous, uint32_t expected, uint32_t current) {
    if (current == previous) return RestoreAction::AlreadyRestored;
    return current == expected ? RestoreAction::Restore : RestoreAction::Conflict;
}

struct EventRef {
    int64_t event_filetime = 0;
    uint32_t layer_id = 0;
    bool outbound = false;
    bool tuple_match = false;
    bool complete = false;
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
    return event.complete && !event.app_path.empty() && event.tuple_match && event.outbound &&
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
    event.complete = true;
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

    assert(match_generation({event_a(capture, 48, "")}, capture, config).outcome == MatchOutcome::NoEvent);
    EventRef incomplete = event_a(capture);
    incomplete.complete = false;
    assert(match_generation({incomplete}, capture, config).outcome == MatchOutcome::NoEvent);

    assert(pending_resolution(MatchOutcome::Matched, 1099, 1100) == PendingResolution::Matched);
    assert(pending_resolution(MatchOutcome::Matched, 1100, 1100) == PendingResolution::Timeout);
    assert(pending_resolution(MatchOutcome::Matched, 1115, 1100) == PendingResolution::Timeout);
    assert(pending_resolution(MatchOutcome::NoEvent, 1099, 1100) == PendingResolution::Retry);
    assert(pending_resolution(MatchOutcome::NoEvent, 1100, 1100) == PendingResolution::Timeout);
    assert(pending_resolution(MatchOutcome::Ambiguous, 1099, 1100) == PendingResolution::Ambiguous);

    GenerationTag requested{100, 1000};
    GenerationTag current{100, 1000};
    assert(snapshot_resolution(MatchOutcome::Matched, true, requested, current, 1101, 1100) == PendingResolution::Timeout);
    assert(snapshot_resolution(MatchOutcome::Matched, true, requested, GenerationTag{101, 1000}, 1099, 1100) == PendingResolution::Discard);
    assert(snapshot_resolution(MatchOutcome::Matched, true, requested, GenerationTag{100, 1001}, 1099, 1100) == PendingResolution::Discard);
    assert(snapshot_resolution(MatchOutcome::Matched, false, requested, current, 1099, 1100) == PendingResolution::Discard);
    assert(snapshot_resolution(MatchOutcome::Ambiguous, true, requested, current, 1099, 1100) == PendingResolution::Ambiguous);

    HandoffState handoff;
    assert(handoff.submit());
    assert(!handoff.submit());
    assert(handoff.start());
    assert(!handoff.submit());
    assert(handoff.finish());
    assert(!handoff.submit());
    assert(handoff.consume());
    assert(handoff.submit());
    handoff.stop();
    assert(!handoff.start());
    assert(!handoff.submit());
    assert(!handoff.finish());
    assert(!handoff.consume());

    assert(lookup_wakeup(true, 900, 1100) == 1100);
    assert(lookup_wakeup(true, 0, 1100) == 1100);
    assert(lookup_wakeup(true, 800, 1200) == 1200);
    assert(lookup_wakeup(false, 900, 1100) == 900);
    assert(lookup_wakeup(false, 1200, 1100) == 1100);

    FilterCapabilityCache capabilities;
    FilterPattern single{6, 2, false}, multi{6, 2, true};
    assert(!capabilities.skip(single));
    assert(capabilities.reject(single, 0x80320002u));
    assert(capabilities.skip(single));
    assert(!capabilities.skip(multi));
    assert(!capabilities.skip(FilterPattern{17, 2, false}));
    assert(!capabilities.reject(multi, 5));
    assert(!capabilities.reject(multi, 1722));
    assert(!capabilities.reject(multi, 0x80320035u));
    assert(!capabilities.skip(multi));
    assert(FilterCapabilityCache::fallback_allowed(0x80320035u));
    assert(FilterCapabilityCache::fallback_allowed(0x80320002u));
    assert(!FilterCapabilityCache::fallback_allowed(5));
    assert(!FilterCapabilityCache::fallback_allowed(1722));
    capabilities.enabled = false;
    assert(!capabilities.skip(single));
    assert(!capabilities.reject(multi, 0x8032002Au));

    const std::vector<QueryTuple> destinations{
        {0xCB007101u, 40000, 443, 6}, {0xCB007101u, 40001, 443, 6},
        {0xCB007102u, 41000, 8443, 17}};
    const auto common = destination_shape(destinations, 6);
    assert(common.has_subjects && common.protocol == 6);
    assert(common.remote_address && *common.remote_address == 0xCB007101u);
    assert(common.remote_port && *common.remote_port == 443);
    assert(!common.local_port);
    const auto common_profiles = destination_profiles(common);
    assert(common_profiles.front() == (EventTypeCondition | ProtocolCondition |
        RemoteAddressCondition | RemotePortCondition));
    assert(common_profiles.back() == 0);
    for (size_t i = 1; i < common_profiles.size(); ++i) {
        assert((common_profiles[i] & common_profiles[i - 1]) == common_profiles[i]);
        assert(common_profiles[i] != common_profiles[i - 1]);
    }
    for (uint32_t mask : common_profiles) {
        const auto keys = condition_keys(mask);
        assert(std::set<uint32_t>(keys.begin(), keys.end()).size() == keys.size());
        for (const auto& subject : destinations) {
            if (subject.protocol != common.protocol) continue;
            assert(!(mask & ProtocolCondition) || subject.protocol == common.protocol);
            assert(!(mask & RemoteAddressCondition) || subject.remote_address == *common.remote_address);
            assert(!(mask & RemotePortCondition) || subject.remote_port == *common.remote_port);
            assert(!(mask & LocalPortCondition) || subject.local_port == *common.local_port);
        }
    }
    const auto singleton = destination_shape({destinations.front()}, 6);
    assert(singleton.local_port && *singleton.local_port == 40000);
    assert(destination_profiles(singleton).front() == (EventTypeCondition | ProtocolCondition |
        RemoteAddressCondition | RemotePortCondition | LocalPortCondition));
    assert(destination_profiles(destination_shape({}, 6)).empty());
    assert(destination_profiles(destination_shape(destinations, 1)).empty());
    const auto different_address = destination_shape({destinations.front(),
        {0xCB007102u, 40001, 443, 6}}, 6);
    assert(!different_address.remote_address && different_address.remote_port && !different_address.local_port);
    assert(destination_profiles(different_address).front() ==
        (EventTypeCondition | ProtocolCondition | RemotePortCondition));
    const auto different_port = destination_shape({destinations.front(),
        {0xCB007101u, 40001, 8443, 6}}, 6);
    assert(different_port.remote_address && !different_port.remote_port && !different_port.local_port);
    assert(destination_profiles(different_port).front() ==
        (EventTypeCondition | ProtocolCondition | RemoteAddressCondition));
    const auto different_destination = destination_shape({destinations.front(),
        {0xCB007102u, 40001, 8443, 6}}, 6);
    assert(!different_destination.remote_address && !different_destination.remote_port && !different_destination.local_port);
    assert(destination_profiles(different_destination).front() == (EventTypeCondition | ProtocolCondition));
    const std::vector<std::vector<QueryTuple>> coverage_cases{
        destinations,
        {destinations.front(), {0xCB007102u, 40001, 443, 6}, destinations.front()},
        {destinations.front(), {0xCB007101u, 40001, 8443, 6}, destinations.front()},
        {destinations.front(), {0xCB007102u, 40001, 8443, 6}, destinations.front()},
        {destinations.front(), {0xCB007102u, 40000, 8443, 6}},
        {destinations.front(), destinations.front()}};
    for (const auto& subjects : coverage_cases) {
        for (uint8_t protocol : {uint8_t(6), uint8_t(17)}) {
            const auto shape = destination_shape(subjects, protocol);
            const auto profiles = destination_profiles(shape);
            for (uint32_t mask : profiles) {
                const auto keys = condition_keys(mask);
                assert(std::set<uint32_t>(keys.begin(), keys.end()).size() == keys.size());
                for (const auto& subject : subjects) {
                    if (subject.protocol != protocol) continue;
                    assert(!(mask & ProtocolCondition) || shape.protocol == subject.protocol);
                    assert(!(mask & RemoteAddressCondition) ||
                        (shape.remote_address && *shape.remote_address == subject.remote_address));
                    assert(!(mask & RemotePortCondition) ||
                        (shape.remote_port && *shape.remote_port == subject.remote_port));
                    assert(!(mask & LocalPortCondition) ||
                        (shape.local_port && *shape.local_port == subject.local_port));
                }
            }
        }
    }

    FilterCapabilityCache isolated;
    const FilterPattern legacy_shape{6, 2, false, EnumScope::Legacy,
        EventTypeCondition | ProtocolCondition | LocalPortCondition, 3};
    const FilterPattern destination_local{6, 2, false, EnumScope::Destination,
        EventTypeCondition | ProtocolCondition | LocalPortCondition, 3};
    const FilterPattern destination_remote{6, 2, false, EnumScope::Destination,
        EventTypeCondition | ProtocolCondition | RemotePortCondition, 3};
    const FilterPattern destination_multiple{6, 2, false, EnumScope::Destination,
        EventTypeCondition | ProtocolCondition | LocalPortCondition, 4};
    assert(isolated.reject(legacy_shape, 0x8032002Au));
    assert(!isolated.skip(destination_local));
    assert(isolated.reject(destination_local, 0x80320002u));
    assert(!isolated.skip(destination_remote));
    assert(!isolated.skip(destination_multiple));
    for (uint32_t error : {5u, 1722u, 87u, 0x80320035u}) {
        assert(!isolated.reject(destination_remote, error));
        assert(!isolated.skip(destination_remote));
    }
    FilterCapabilityCache coarse_legacy;
    const FilterPattern legacy_two_ports{6, 2, true, EnumScope::Legacy,
        EventTypeCondition | ProtocolCondition | LocalPortCondition, 4};
    const FilterPattern legacy_three_ports{6, 2, true, EnumScope::Legacy,
        EventTypeCondition | ProtocolCondition | LocalPortCondition, 5};
    assert(coarse_legacy.reject(legacy_two_ports, 0x8032002Au));
    assert(coarse_legacy.skip(legacy_three_ports));
    assert(!coarse_legacy.skip(legacy_shape));
    assert(!coarse_legacy.skip(destination_local));
    assert(!coarse_legacy.skip(destination_multiple));
    assert(coarse_legacy.reject(destination_local, 0x8032002Au));
    assert(!coarse_legacy.skip(destination_multiple));

    assert(copy_budget_allows(0, 65536));
    assert(!copy_budget_allows(0, 65537));
    assert(copy_budget_allows(8 * 1024 * 1024 - 65536, 65536));
    assert(!copy_budget_allows(8 * 1024 * 1024 - 1, 2));
    assert(!copy_budget_allows(static_cast<size_t>(-1), 1));

    assert(restore_action(0, 16, 0) == RestoreAction::AlreadyRestored);
    assert(restore_action(0, 16, 16) == RestoreAction::Restore);
    assert(restore_action(0, 16, 32) == RestoreAction::Conflict);

    assert(match_generation({event_a(capture, 44)}, capture, config).outcome == MatchOutcome::NoEvent);
    assert(match_generation({event_a(capture, 50)}, capture, config).outcome == MatchOutcome::Matched);

    assert(match_generation({event_a(capture - 6'000'000)}, capture, config).outcome == MatchOutcome::NoEvent);
    assert(match_generation({event_a(capture + 600'000)}, capture, config).outcome == MatchOutcome::NoEvent);
    assert(match_generation({event_a(capture + 400'000)}, capture, config).outcome == MatchOutcome::Matched);

    MatchConfig narrow = config;
    narrow.window_before = 5 * 10000;
    assert(match_generation({event_a(capture - 50'000)}, capture, narrow).outcome == MatchOutcome::Matched);
    assert(match_generation({event_a(capture - 50'001)}, capture, narrow).outcome == MatchOutcome::NoEvent);
    assert(match_generation({event_a(capture - 5'000'000)}, capture, config).outcome == MatchOutcome::Matched);
    assert(match_generation({event_a(capture - 5'000'001)}, capture, config).outcome == MatchOutcome::NoEvent);
    const std::vector<EventRef> fresh_and_stale{event_a(capture - 49'999),
        event_a(capture - 50'001, 48, "\\device\\lab\\app-b.exe")};
    assert(match_generation(fresh_and_stale, capture, config).outcome == MatchOutcome::Ambiguous);
    assert(match_generation(fresh_and_stale, capture, narrow).outcome == MatchOutcome::Matched);
    assert(match_generation({fresh_and_stale.back()}, capture, narrow).outcome == MatchOutcome::NoEvent);
    assert(match_generation({event_a(capture + 500'000)}, capture, narrow).outcome == MatchOutcome::Matched);
    assert(match_generation({event_a(capture + 500'001)}, capture, narrow).outcome == MatchOutcome::NoEvent);

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
    std::string lookup_mode = "inline";
    std::string enum_scope = "legacy";
    bool filter_cache = true;
    uint16_t port = 0;
    uint16_t udp_port = 0;
    uint16_t quic_port = 443;
    uint16_t listener_port = 0;
    int seconds = 35;
    int hold_ms = 1000;
    int window_before_ms = 500;
    int window_after_ms = 50;
    int leak_ms = 2000;
    int delay_ms = 0;
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
        else if (key == "--lookup-mode") result.lookup_mode = value;
        else if (key == "--enum-scope") result.enum_scope = value;
        else if (key == "--filter-cache") {
            if (value != "on" && value != "off") throw std::runtime_error("filter-cache must be on or off");
            result.filter_cache = value == "on";
        }
        else if (key == "--selected-app") result.selected_app = value;
        else if (key == "--seconds") result.seconds = static_cast<int>(number(value, 1, 600));
        else if (key == "--hold-ms") result.hold_ms = static_cast<int>(number(value, 1, 10000));
        else if (key == "--window-before-ms") result.window_before_ms = static_cast<int>(number(value, 0, 10000));
        else if (key == "--window-after-ms") result.window_after_ms = static_cast<int>(number(value, 0, 10000));
        else if (key == "--leak-ms") result.leak_ms = static_cast<int>(number(value, 0, 10000));
        else if (key == "--delay-ms") result.delay_ms = static_cast<int>(number(value, 0, 10000));
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
    if (result.lookup_mode != "inline" && result.lookup_mode != "async")
        throw std::runtime_error("lookup-mode must be inline or async");
    if (result.enum_scope != "legacy" && result.enum_scope != "destination")
        throw std::runtime_error("enum-scope must be legacy or destination");
    if (result.mode == "redirect" && !result.listener_port)
        throw std::runtime_error("redirect mode requires --listener-port");
    if (result.listener_port == result.port)
        throw std::runtime_error("listener and controlled target ports must differ");
    return result;
}

struct Bfe {
    HANDLE engine = nullptr;
    Log* log = nullptr;
    UINT32 old_collect = 0, old_keywords = 0;
    bool collect_changed = false, keywords_changed = false;
    unsigned errors = 0;

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
    void error(const char* operation, DWORD code) noexcept {
        ++errors;
        try {
            if (log) log->write("{\"kind\":\"error\",\"operation\":" + json(operation) +
                                ",\"code\":" + std::to_string(code) + "}");
        } catch (...) {}
    }
    void restore(FWPM_ENGINE_OPTION option, UINT32 expected, UINT32 previous, const char* operation) noexcept {
        try {
            const auto action = inproc::restore_action(previous, expected, get(option));
            if (action == inproc::RestoreAction::AlreadyRestored) return;
            if (action == inproc::RestoreAction::Conflict) { error(operation, ERROR_BUSY); return; }
            const auto result = set(option, previous);
            if (result) error(operation, result);
        } catch (...) { error(operation, ERROR_INVALID_DATA); }
    }
    void finish() noexcept {
        if (!engine) return;
        if (keywords_changed) restore(FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS,
            old_keywords | FWPM_NET_EVENT_KEYWORD_CLASSIFY_ALLOW, old_keywords, "Restore MATCH_ANY_KEYWORDS");
        if (collect_changed) restore(FWPM_ENGINE_COLLECT_NET_EVENTS, 1, old_collect, "Restore COLLECT_NET_EVENTS");
        const auto closed = FwpmEngineClose0(engine);
        if (closed) error("FwpmEngineClose0 BFE", closed);
        engine = nullptr;
    }
    ~Bfe() { finish(); }
};

struct PhaseMetric {
    uint64_t calls = 0;
    double total_ms = 0, max_ms = 0;
    void add(double ms) { ++calls; total_ms += ms; max_ms = (std::max)(max_ms, ms); }
    void merge(const PhaseMetric& other) {
        calls += other.calls; total_ms += other.total_ms; max_ms = (std::max)(max_ms, other.max_ms);
    }
};

struct QueryStats {
    std::set<std::string> filters;
    std::set<std::pair<uint32_t, size_t>> condition_shapes;
    unsigned calls = 0;
    unsigned errors = 0;
    std::vector<double> durations_ms;
    PhaseMetric create, enumerate, destroy, process;
    uint64_t events = 0;
    size_t copied_bytes = 0;
    uint64_t cache_hits = 0, cache_misses = 0, cache_rejections = 0;
    double busy_ms = 0;
    double cpu_ms = 0;
    unsigned cpu_samples = 0, cpu_errors = 0;
    DWORD cpu_error_code = ERROR_SUCCESS;
};

struct Lookup : QueryStats {
    std::string filter;
    unsigned queries = 0, completed = 0, cancelled = 0, backpressure = 0;
    unsigned stale_subjects = 0, incomplete_results = 0;
    size_t max_subjects = 0;
    std::vector<double> apply_ms;
};

struct QuerySubject {
    Tuple tuple;
    inproc::GenerationTag tag;
    uint64_t capture_filetime;
};

struct QueryRequest {
    uint64_t id = 0;
    std::vector<QuerySubject> subjects;
};

struct QueryResult {
    QueryRequest request;
    std::map<Tuple, std::vector<inproc::EventRef>> events;
    bool complete = false;
    QueryStats stats;
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
    WINDIVERT_ADDRESS first_address{};
    unsigned lookup_calls = 0;
    SOCKET reservation = INVALID_SOCKET;
    uint16_t alias = 0;
    bool leak_selected = false;
    bool rst_sent = false;
    std::string drop_reason = "selected_quic";
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
    std::atomic<bool> lookup_worker_error{false};
    std::thread receiver;
    std::thread lookup_thread;
    std::mutex mutex;
    std::condition_variable wake;
    std::condition_variable query_wake;
    std::deque<Packet> input;
    inproc::HandoffState query_handoff;
    std::optional<QueryRequest> query_request;
    std::optional<QueryResult> query_result;
    bool lookup_stopping = false;
    inproc::FilterCapabilityCache filter_capabilities;
    int64_t engine_started_qpc = 0;

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
    int64_t next_leak_check_qpc = 0;

    static constexpr size_t MAX_BYTES = 8 * 1024 * 1024;
    static constexpr size_t MAX_FLOWS = 4096;

    uint64_t to_filetime_from_qpc(int64_t capture) const {
        return anchor_filetime + static_cast<uint64_t>((capture - anchor_qpc) * 10'000'000 / frequency);
    }

    bool send(Packet& packet, const char* reason) {
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
        return success;
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
        if (send(packet, "forward")) record_added(held, flow.action, packet.address.Timestamp);
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
        if (tuple.protocol != IPPROTO_TCP) return;
        unsigned char buffer[40]{};
        WINDIVERT_IPHDR* ip_header = reinterpret_cast<WINDIVERT_IPHDR*>(buffer);
        WINDIVERT_TCPHDR* tcp = reinterpret_cast<WINDIVERT_TCPHDR*>(buffer + 20);
        ip_header->Version = 4;
        ip_header->HdrLength = 5;
        ip_header->Length = htons(40);
        ip_header->TTL = 64;
        ip_header->Protocol = IPPROTO_TCP;
        tcp->HdrLength = 5;
        tcp->Rst = 1;
        tcp->Window = 0;
        const int64_t send_qpc = qpc();
        for (bool reverse_direction : {true, false}) {
            ip_header->SrcAddr = reverse_direction ? tuple.remote : tuple.local;
            ip_header->DstAddr = reverse_direction ? tuple.local : tuple.remote;
            tcp->SrcPort = htons(reverse_direction ? tuple.remote_port : tuple.local_port);
            tcp->DstPort = htons(reverse_direction ? tuple.local_port : tuple.remote_port);
            tcp->SeqNum = htonl(reverse_direction ? flow.last_ack : flow.last_seq);
            tcp->AckNum = htonl(reverse_direction ? flow.last_seq : flow.last_ack);
            tcp->Ack = 1;
            Packet packet;
            packet.bytes.assign(buffer, buffer + 40);
            packet.address = flow.first_address;
            packet.address.Outbound = reverse_direction && !flow.outbound_loopback ? 0 : 1;
            if (!WinDivertHelperCalcChecksums(packet.bytes.data(), 40, &packet.address, 0)) {
                fatal_send = true;
                log.write("{\"kind\":\"error\",\"operation\":\"rst_checksums\"}");
                return;
            }
            if (!send(packet, reverse_direction ? "rst_client" : "rst_remote")) return;
        }
        flow.rst_sent = true;
        flow.action = "drop";
        flow.drop_reason = "leak_reset";
        ++rst_count;
        log.write("{\"kind\":\"rst\"," + fields(tuple) + ",\"generation\":" +
                  std::to_string(flow.generation) + ",\"send_qpc\":" + std::to_string(send_qpc) +
                  ",\"directions\":2,\"qpc\":" + std::to_string(qpc()) + "}");
    }

    double elapsed_ms(int64_t began) const {
        return static_cast<double>(qpc() - began) * 1000.0 / static_cast<double>(frequency);
    }

    void lookup_error(QueryStats& stats, const char* operation, DWORD code) {
        ++stats.errors;
        log.write("{\"kind\":\"error\",\"operation\":" + json(operation) +
                  ",\"code\":" + std::to_string(code) + "}");
    }

    bool enumerate(uint8_t protocol, const std::vector<uint16_t>& ports,
                   const inproc::DestinationShape& destination, uint64_t window_start, QueryResult& result) {
        auto& stats = result.stats;
        if (!session) { lookup_error(stats, "lookup_session", ERROR_INVALID_HANDLE); return false; }
        const bool destination_scope = config.enum_scope == "destination";
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
        FWPM_FILTER_CONDITION0 remote_address_condition{};
        remote_address_condition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        remote_address_condition.matchType = FWP_MATCH_EQUAL;
        remote_address_condition.conditionValue.type = FWP_UINT32;
        remote_address_condition.conditionValue.uint32 = destination.remote_address.value_or(0);
        FWPM_FILTER_CONDITION0 remote_port_condition{};
        remote_port_condition.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        remote_port_condition.matchType = FWP_MATCH_EQUAL;
        remote_port_condition.conditionValue.type = FWP_UINT16;
        remote_port_condition.conditionValue.uint16 = destination.remote_port.value_or(0);
        std::vector<FWPM_FILTER_CONDITION0> port_conditions;
        if (!destination_scope) {
            for (uint16_t port : ports) {
                FWPM_FILTER_CONDITION0 condition{};
                condition.fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
                condition.matchType = FWP_MATCH_EQUAL;
                condition.conditionValue.type = FWP_UINT16;
                condition.conditionValue.uint16 = port;
                port_conditions.push_back(condition);
            }
        }

        auto build = [&](int level, uint32_t mask) {
            conditions.clear();
            if (!destination_scope) {
                if (level >= 0) conditions.push_back(type_condition);
                if (level >= 1) conditions.push_back(protocol_condition);
                if (level >= 2) for (const auto& c : port_conditions) conditions.push_back(c);
                return;
            }
            for (uint32_t key : inproc::condition_keys(mask)) {
                switch (key) {
                case inproc::EventTypeCondition: conditions.push_back(type_condition); break;
                case inproc::ProtocolCondition: conditions.push_back(protocol_condition); break;
                case inproc::RemoteAddressCondition: conditions.push_back(remote_address_condition); break;
                case inproc::RemotePortCondition: conditions.push_back(remote_port_condition); break;
                case inproc::LocalPortCondition:
                    FWPM_FILTER_CONDITION0 condition{};
                    condition.fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
                    condition.matchType = FWP_MATCH_EQUAL;
                    condition.conditionValue.type = FWP_UINT16;
                    condition.conditionValue.uint16 = destination.local_port.value();
                    conditions.push_back(condition);
                    break;
                }
            }
        };

        auto name = [&](int level, uint32_t mask) {
            if (!destination_scope)
                return std::string(level >= 2 ? "type+protocol+local_port" : level == 1 ? "type+protocol" :
                    level == 0 ? "type" : "time_window_only");
            std::string result;
            for (uint32_t key : inproc::condition_keys(mask)) {
                if (!result.empty()) result += "+";
                switch (key) {
                case inproc::EventTypeCondition: result += "type"; break;
                case inproc::ProtocolCondition: result += "protocol"; break;
                case inproc::RemoteAddressCondition: result += "remote_address"; break;
                case inproc::RemotePortCondition: result += "remote_port"; break;
                case inproc::LocalPortCondition: result += "local_port"; break;
                }
            }
            return result.empty() ? std::string("time_window_only") : result;
        };

        std::vector<std::pair<int, uint32_t>> profiles;
        if (destination_scope) {
            const auto masks = inproc::destination_profiles(destination);
            for (size_t i = 0; i < masks.size(); ++i)
                profiles.emplace_back(static_cast<int>(masks.size() - i) - 2, masks[i]);
        } else {
            for (int level = port_conditions.empty() ? 1 : 2; level >= -1; --level) {
                uint32_t mask = 0;
                if (level >= 0) mask |= inproc::EventTypeCondition;
                if (level >= 1) mask |= inproc::ProtocolCondition;
                if (level >= 2) mask |= inproc::LocalPortCondition;
                profiles.emplace_back(level, mask);
            }
        }
        if (profiles.empty()) { lookup_error(stats, "lookup_empty_subjects", ERROR_INVALID_DATA); return false; }

        FWPM_NET_EVENT_ENUM_TEMPLATE0 range{};
        range.startTime = to_filetime(window_start);
        GetSystemTimePreciseAsFileTime(&range.endTime);

        struct EnumGuard {
            HANDLE session;
            HANDLE handle = nullptr;
            ~EnumGuard() { if (handle) FwpmNetEventDestroyEnumHandle0(session, handle); }
        } guard{session};
        std::string chosen;
        for (const auto& profile : profiles) {
            const int level = profile.first;
            const uint32_t mask = profile.second;
            build(level, mask);
            const inproc::FilterPattern pattern{protocol, level, !destination_scope && ports.size() > 1,
                destination_scope ? inproc::EnumScope::Destination : inproc::EnumScope::Legacy,
                mask, conditions.size()};
            if (mask && filter_capabilities.skip(pattern)) {
                ++stats.cache_hits;
                continue;
            }
            if (config.filter_cache && mask) ++stats.cache_misses;
            range.numFilterConditions = static_cast<UINT32>(conditions.size());
            range.filterCondition = conditions.empty() ? nullptr : conditions.data();
            const auto began = qpc();
            const auto created = FwpmNetEventCreateEnumHandle0(session, &range, &guard.handle);
            stats.create.add(elapsed_ms(began));
            if (!created) {
                chosen = name(level, mask);
                stats.condition_shapes.emplace(mask, conditions.size());
                break;
            }
            if (!mask || !inproc::FilterCapabilityCache::fallback_allowed(created)) {
                lookup_error(stats, "FwpmNetEventCreateEnumHandle0", created);
                return false;
            }
            const bool learned = filter_capabilities.reject(pattern, created);
            if (learned) ++stats.cache_rejections;
            log.write("{\"kind\":\"enum_filter_fallback\",\"level\":" + std::to_string(level) +
                      ",\"enum_scope\":" + json(config.enum_scope) +
                      ",\"protocol\":" + std::to_string(protocol) +
                      ",\"condition_mask\":" + std::to_string(mask) +
                      ",\"condition_count\":" + std::to_string(conditions.size()) +
                      ",\"filter\":" + json(name(level, mask)) +
                      ",\"multiple_ports\":" + (ports.size() > 1 ? "true" : "false") +
                      ",\"cached\":" + (learned ? "true" : "false") +
                      ",\"code\":" + std::to_string(created) + "}");
        }
        stats.filters.insert(chosen);

        const UINT32 batch = 256;
        const int64_t enumeration_deadline = qpc() + frequency * 2;
        unsigned batches = 0;
        bool complete = true;
        for (;;) {
            struct EntriesGuard {
                FWPM_NET_EVENT3** value = nullptr;
                ~EntriesGuard() { if (value) FwpmFreeMemory0(reinterpret_cast<void**>(&value)); }
            } entries;
            UINT32 count = 0;
            const auto began = qpc();
            const auto enumerated = FwpmNetEventEnum3(session, guard.handle, batch, &entries.value, &count);
            stats.enumerate.add(elapsed_ms(began));
            if (enumerated) {
                lookup_error(stats, "FwpmNetEventEnum3", enumerated);
                complete = false;
                break;
            }
            if (count && !entries.value) {
                lookup_error(stats, "FwpmNetEventEnum3_null_entries", ERROR_INVALID_DATA);
                complete = false;
                break;
            }
            const auto process_began = qpc();
            stats.events += count;
            for (UINT32 i = 0; i < count; ++i) {
                const auto* entry = entries.value[i];
                if (!entry || entry->type != FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW) continue;
                const auto& header = entry->header;
                const auto* allow = entry->classifyAllow;
                inproc::EventRef ref;
                ref.event_filetime = static_cast<int64_t>(filetime(header.timeStamp));
                ref.layer_id = allow ? allow->layerId : 0;
                ref.outbound = allow && allow->msFwpDirection == FWP_DIRECTION_OUTBOUND;
                if (header.flags & FWPM_NET_EVENT_FLAG_APP_ID_SET) {
                    if (!inproc::copy_budget_allows(stats.copied_bytes, header.appId.size))
                        throw std::runtime_error("native event snapshot byte limit");
                    stats.copied_bytes += header.appId.size;
                    ref.app_path = lower(blob_path(header.appId));
                }
                const UINT32 required = FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET | FWPM_NET_EVENT_FLAG_IP_VERSION_SET |
                    FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET | FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET |
                    FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET | FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET |
                    FWPM_NET_EVENT_FLAG_APP_ID_SET;
                ref.complete = (header.flags & required) == required && !ref.app_path.empty();
                ref.tuple_match = header.ipVersion == FWP_IP_VERSION_V4;
                ref.raw_local_addr = header.localAddrV4;
                ref.raw_remote_addr = header.remoteAddrV4;
                ref.match_local_port = static_cast<uint16_t>(header.localPort);
                ref.match_remote_port = static_cast<uint16_t>(header.remotePort);
                ref.match_protocol = static_cast<uint8_t>(header.ipProtocol);
                ref.ip_version = header.ipVersion;
                if (ref.ip_version != FWP_IP_VERSION_V4) continue;
                Tuple key{htonl(ref.raw_local_addr), htonl(ref.raw_remote_addr),
                    ref.match_local_port, ref.match_remote_port, ref.match_protocol};
                result.events[key].push_back(std::move(ref));
            }
            stats.process.add(elapsed_ms(process_began));
            if (count < batch) break;
            if (++batches >= 64 || qpc() >= enumeration_deadline) {
                lookup_error(stats, "FwpmNetEventEnum3_limit", ERROR_MORE_DATA);
                complete = false;
                break;
            }
        }
        const auto destroy_began = qpc();
        const auto destroyed = FwpmNetEventDestroyEnumHandle0(session, guard.handle);
        guard.handle = nullptr;
        stats.destroy.add(elapsed_ms(destroy_began));
        if (destroyed) { lookup_error(stats, "FwpmNetEventDestroyEnumHandle0", destroyed); complete = false; }
        return complete;
    }

    inproc::MatchResult match(const Flow& flow, const std::vector<inproc::EventRef>& events, int64_t observed) {
        inproc::MatchConfig match_config;
        match_config.window_before = static_cast<int64_t>(config.window_before_ms) * 10000;
        match_config.window_after = static_cast<int64_t>(config.window_after_ms) * 10000;
        match_config.ale_connect_v4 = ALE_AUTH_CONNECT_V4;
        match_config.ale_connect_v6 = ALE_AUTH_CONNECT_V6;
        auto result = inproc::match_generation(events, static_cast<int64_t>(flow.capture_filetime), match_config);
        if (result.outcome == inproc::MatchOutcome::Matched && result.app_path == selected_app &&
            observed < flow.capture_qpc + frequency * config.delay_ms / 1000)
            return {};
        return result;
    }

    void log_ownership(const Tuple& tuple, const Flow& flow, const inproc::MatchResult& result, uint64_t query_id) {
        log.write("{\"kind\":\"ownership\"," + fields(tuple) + ",\"generation\":" +
                  std::to_string(flow.generation) + ",\"app_path\":" + json(result.app_path) +
                  ",\"event_filetime\":" + std::to_string(result.event_filetime) +
                  ",\"capture_qpc\":" + std::to_string(flow.capture_qpc) +
                  ",\"query_id\":" + std::to_string(query_id) +
                  ",\"qpc\":" + std::to_string(qpc()) + "}");
    }

    QueryResult execute_query(QueryRequest request) {
        QueryResult result;
        result.request = std::move(request);
        const int64_t began = qpc();
        auto thread_cpu = [](uint64_t& ticks) {
            FILETIME created{}, exited{}, kernel{}, user{};
            if (!GetThreadTimes(GetCurrentThread(), &created, &exited, &kernel, &user)) return false;
            ticks = filetime(kernel) + filetime(user);
            return true;
        };
        uint64_t cpu_before = 0, cpu_after = 0;
        const bool cpu_before_valid = thread_cpu(cpu_before);
        const DWORD cpu_before_error = cpu_before_valid ? ERROR_SUCCESS : GetLastError();
        bool complete = true;
        try {
            std::vector<inproc::QueryTuple> subjects;
            if (config.enum_scope == "destination") {
                subjects.reserve(result.request.subjects.size());
                for (const auto& subject : result.request.subjects)
                    subjects.push_back({ntohl(subject.tuple.remote), subject.tuple.local_port,
                        subject.tuple.remote_port, subject.tuple.protocol});
            }
            for (uint8_t protocol : {uint8_t(6), uint8_t(17)}) {
                std::vector<uint16_t> ports;
                uint64_t window_start = utc_now();
                for (const auto& subject : result.request.subjects) {
                    if (subject.tuple.protocol != protocol) continue;
                    ports.push_back(subject.tuple.local_port);
                    window_start = (std::min)(window_start, subject.capture_filetime);
                }
                if (ports.empty()) continue;
                window_start -= static_cast<uint64_t>(config.window_before_ms) * 10000;
                const int64_t query_began = qpc();
                ++result.stats.calls;
                complete = enumerate(protocol, inproc::pending_ports(ports),
                    inproc::destination_shape(subjects, protocol), window_start, result);
                result.stats.durations_ms.push_back(elapsed_ms(query_began));
                if (!complete) break;
            }
        } catch (const std::exception& error) {
            lookup_error(result.stats, "lookup_exception", ERROR_GEN_FAILURE);
            log.write("{\"kind\":\"error\",\"operation\":\"lookup_exception_detail\",\"message\":" + json(error.what()) + "}");
            complete = false;
        } catch (...) {
            lookup_error(result.stats, "lookup_exception", ERROR_GEN_FAILURE);
            complete = false;
        }
        result.complete = complete;
        if (!complete) result.events.clear();
        const bool cpu_after_valid = thread_cpu(cpu_after);
        if (cpu_before_valid && cpu_after_valid && cpu_after >= cpu_before) {
            result.stats.cpu_ms = static_cast<double>(cpu_after - cpu_before) / 10000.0;
            result.stats.cpu_samples = 1;
        } else {
            ++result.stats.cpu_errors;
            result.stats.cpu_error_code = !cpu_before_valid ? cpu_before_error :
                !cpu_after_valid ? GetLastError() : ERROR_INVALID_DATA;
        }
        result.stats.busy_ms = elapsed_ms(began);
        return result;
    }

    void merge_query_stats(const QueryResult& result) {
        const auto& stats = result.stats;
        ++lookup.completed;
        lookup.calls += stats.calls;
        lookup.errors += stats.errors;
        lookup.durations_ms.insert(lookup.durations_ms.end(), stats.durations_ms.begin(), stats.durations_ms.end());
        lookup.create.merge(stats.create);
        lookup.enumerate.merge(stats.enumerate);
        lookup.destroy.merge(stats.destroy);
        lookup.process.merge(stats.process);
        lookup.events += stats.events;
        lookup.cache_hits += stats.cache_hits;
        lookup.cache_misses += stats.cache_misses;
        lookup.cache_rejections += stats.cache_rejections;
        lookup.busy_ms += stats.busy_ms;
        lookup.cpu_ms += stats.cpu_ms;
        lookup.cpu_samples += stats.cpu_samples;
        lookup.cpu_errors += stats.cpu_errors;
        if (stats.cpu_errors) lookup.cpu_error_code = stats.cpu_error_code;
        lookup.condition_shapes.insert(stats.condition_shapes.begin(), stats.condition_shapes.end());
        for (const auto& filter : stats.filters) {
            if (!lookup.filters.insert(filter).second) continue;
            if (!lookup.filter.empty()) lookup.filter += "|";
            lookup.filter += filter;
        }
    }

    void apply_query(QueryResult result, bool apply = true) {
        merge_query_stats(result);
        if (!result.complete) { ++lookup.incomplete_results; return; }
        if (!apply) return;
        const int64_t began = qpc();
        for (const auto& subject : result.request.subjects) {
            auto found = flows.find(subject.tuple);
            if (found == flows.end()) { ++lookup.stale_subjects; continue; }
            Flow& flow = *found->second;
            const inproc::GenerationTag current{flow.generation, flow.capture_qpc};
            if (!(subject.tag == current)) { ++lookup.stale_subjects; continue; }
            auto evidence = result.events.find(subject.tuple);
            const std::vector<inproc::EventRef> empty;
            auto outcome = match(flow, evidence == result.events.end() ? empty : evidence->second, qpc());
            const int64_t observed = qpc();
            if (flow.action == "pending") {
                const auto resolution = inproc::snapshot_resolution(outcome.outcome, result.complete,
                    subject.tag, current, observed, flow.deadline_qpc);
                if (resolution == inproc::PendingResolution::Discard) { ++lookup.stale_subjects; continue; }
                if (resolution == inproc::PendingResolution::Timeout) {
                    decide(subject.tuple, flow, "direct", "timeout");
                    continue;
                }
                if (resolution == inproc::PendingResolution::Retry) {
                    flow.backoff_ms = flow.backoff_ms == 0 ? 1 : (std::min)(flow.backoff_ms * 2, 8);
                    flow.next_retry_qpc = (std::min)(observed + frequency * flow.backoff_ms / 1000, flow.deadline_qpc);
                    continue;
                }
                if (resolution == inproc::PendingResolution::Ambiguous) {
                    decide(subject.tuple, flow, "direct", "ambiguous");
                    continue;
                }
                log_ownership(subject.tuple, flow, outcome, result.request.id);
                if (outcome.app_path != selected_app) {
                    decide(subject.tuple, flow, "direct", "other_app");
                } else if (flow.protocol == 17) {
                    decide(subject.tuple, flow, subject.tuple.remote_port == config.quic_port ? "drop_quic" : "direct",
                           subject.tuple.remote_port == config.quic_port ? "selected_quic" : "selected_udp_direct");
                } else {
                    decide(subject.tuple, flow, config.mode == "redirect" ? "proxy" : "direct", "selected");
                }
                continue;
            }
            auto watch = std::find_if(leak_watch.begin(), leak_watch.end(), [&](const auto& item) {
                return item.first == subject.tuple && observed < item.second;
            });
            if (watch == leak_watch.end() || outcome.outcome != inproc::MatchOutcome::Matched) continue;
            log_ownership(subject.tuple, flow, outcome, result.request.id);
            if (outcome.app_path == selected_app && !flow.leak_selected) {
                flow.leak_selected = true;
                ++leaked;
                log.write("{\"kind\":\"leaked\"," + fields(subject.tuple) + ",\"generation\":" +
                    std::to_string(flow.generation) + ",\"qpc\":" + std::to_string(qpc()) + "}");
                if (config.send_rst && !flow.rst_sent) send_rst(subject.tuple, flow);
            }
            leak_watch.erase(watch);
        }
        lookup.apply_ms.push_back(elapsed_ms(began));
    }

    void lookup_loop() {
        for (;;) {
            QueryRequest request;
            {
                std::unique_lock<std::mutex> lock(mutex);
                query_wake.wait(lock, [&] { return lookup_stopping || query_request.has_value(); });
                if (lookup_stopping) return;
                if (!query_handoff.start()) return;
                request = std::move(*query_request);
                query_request.reset();
            }
            QueryResult result = execute_query(std::move(request));
            {
                std::lock_guard<std::mutex> lock(mutex);
                query_result = std::move(result);
                query_handoff.finish();
            }
            wake.notify_one();
        }
    }

    void consume_query(bool apply = true) {
        std::optional<QueryResult> result;
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (!query_handoff.ready()) return;
            result = std::move(query_result);
            query_result.reset();
            query_handoff.consume();
        }
        apply_query(std::move(*result), apply);
    }

    void stop_lookup() {
        {
            std::lock_guard<std::mutex> lock(mutex);
            lookup_stopping = true;
        }
        query_wake.notify_all();
        if (lookup_thread.joinable()) lookup_thread.join();
        consume_query(false);
        std::lock_guard<std::mutex> lock(mutex);
        if (query_request) { ++lookup.cancelled; query_request.reset(); }
        query_handoff.stop();
    }

    void resolve_pending(int64_t now) {
        consume_query();
        now = qpc();
        bool pending_due = false;
        for (auto& entry : flows) {
            Flow& flow = *entry.second;
            if (flow.action != "pending") continue;
            if (now >= flow.deadline_qpc) decide(entry.first, flow, "direct", "timeout");
            else if (flow.next_retry_qpc <= now) pending_due = true;
        }
        leak_watch.erase(std::remove_if(leak_watch.begin(), leak_watch.end(),
            [&](const auto& item) { return now >= item.second; }), leak_watch.end());
        const bool leaks_due = !leak_watch.empty() && now >= next_leak_check_qpc;
        if ((!pending_due && !leaks_due) || lookup.errors || lookup_stopping) return;
        if (config.lookup_mode == "async") {
            std::lock_guard<std::mutex> lock(mutex);
            if (query_handoff.busy()) { ++lookup.backpressure; return; }
        }
        QueryRequest request;
        std::set<Tuple> watched_tuples;
        if (leaks_due) for (const auto& watch : leak_watch) watched_tuples.insert(watch.first);
        for (const auto& entry : flows) {
            const Flow& flow = *entry.second;
            const bool watched = watched_tuples.count(entry.first) != 0;
            if (!(pending_due && flow.action == "pending") && !watched) continue;
            request.subjects.push_back({entry.first, {flow.generation, flow.capture_qpc}, flow.capture_filetime});
        }
        if (request.subjects.empty()) return;
        if (config.lookup_mode == "async") {
            std::lock_guard<std::mutex> lock(mutex);
            if (!query_handoff.submit()) { ++lookup.backpressure; return; }
        }
        request.id = ++lookup.queries;
        lookup.max_subjects = (std::max)(lookup.max_subjects, request.subjects.size());
        for (const auto& subject : request.subjects) {
            Flow& flow = *flows.at(subject.tuple);
            if (flow.action == "pending") ++flow.lookup_calls;
        }
        if (leaks_due) next_leak_check_qpc = now + frequency * 8 / 1000;
        if (config.lookup_mode == "async") {
            {
                std::lock_guard<std::mutex> lock(mutex);
                query_request = std::move(request);
            }
            query_wake.notify_one();
        } else {
            apply_query(execute_query(std::move(request)));
        }
    }

    void decide(const Tuple& tuple, Flow& flow, std::string action, const char* reason) {
        if (action == "proxy" && !reserve(tuple, flow)) {
            fatal_send = true;
            action = "direct";
            reason = "alias_failure";
            log.write("{\"kind\":\"error\",\"operation\":\"reserve_alias_direct\"}");
        }
        const int64_t now = qpc();
        if (now >= flow.deadline_qpc && std::string(reason) != "pending_capacity") {
            action = "direct";
            reason = "timeout";
            if (flow.alias) {
                aliases.erase({tuple.local, flow.alias});
                closesocket(flow.reservation);
                flow.reservation = INVALID_SOCKET;
                flow.alias = 0;
            }
        }
        decision_latency_ms.push_back(static_cast<double>(now - flow.capture_qpc) * 1000.0 / static_cast<double>(frequency));
        lookups_per_flow.push_back(static_cast<double>(flow.lookup_calls));
        if (action == "drop_quic") {
            flow.action = "drop";
            ++quic_drops;
            while (!flow.held.empty()) {
                log_decision(tuple, flow, "drop", "selected_quic", now);
                flow.held.pop_front();
            }
            return;
        }
        flow.action = action;
        if (flow.action == "proxy") ++decided_proxy;
        else {
            ++decided_direct;
            if (std::string(reason) == "timeout") {
                ++unattributed;
                if (tuple.protocol == IPPROTO_TCP && config.leak_ms) {
                    leak_watch.emplace_back(tuple, now + frequency * config.leak_ms / 1000);
                    next_leak_check_qpc = now;
                }
            }
        }
        log_decision(tuple, flow, flow.action, reason, now);
        flush(flow, tuple);
    }

    void log_decision(const Tuple& tuple, Flow& flow, const std::string& action, const std::string& reason,
                      int64_t now = 0) {
        if (!now) now = qpc();
        log.write("{\"kind\":\"decision\"," + fields(tuple) + ",\"generation\":" +
                  std::to_string(flow.generation) + ",\"action\":" + json(action) +
                  ",\"reason\":" + json(reason) + ",\"qpc\":" + std::to_string(now) +
                  ",\"capture_qpc\":" + std::to_string(flow.capture_qpc) +
                  ",\"deadline_qpc\":" + std::to_string(flow.deadline_qpc) + "}");
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
            flow->deadline_qpc = flow->capture_qpc + frequency * config.hold_ms / 1000;
            flow->protocol = tuple.protocol;
            flow->first_address = packet.address;
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
            const unsigned headers = static_cast<unsigned>(parsed.ip_header->HdrLength + parsed.tcp->HdrLength) * 4;
            const unsigned length = ntohs(parsed.ip_header->Length);
            const unsigned payload = length >= headers ? length - headers : 0;
            flow.last_seq = ntohl(parsed.tcp->SeqNum) + payload + (parsed.tcp->Syn ? 1 : 0) + (parsed.tcp->Fin ? 1 : 0);
            flow.last_ack = ntohl(parsed.tcp->AckNum);
            if (parsed.tcp->Syn && !parsed.tcp->Ack && flow.action == "proxy" &&
                flow.saw_syn && parsed.tcp->SeqNum != flow.syn_sequence) {
                log_decision(tuple, flow, "drop", "ambiguous_reuse_of_proxy_tuple");
                reuse_disrupted = true;
                return;
            }
        }
        if (flow.action == "drop") {
            log_decision(tuple, flow, "drop", flow.drop_reason);
            return;
        }
        if (flow.action != "pending") {
            forward(packet, tuple, flow, false);
            return;
        }
        if (flow.held.size() >= 256) {
            decide(tuple, flow, "direct", "pending_capacity");
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
            consider(inproc::lookup_wakeup(query_handoff.busy(), flow.next_retry_qpc, flow.deadline_qpc));
        }
        for (const auto& watch : leak_watch)
            consider(inproc::lookup_wakeup(query_handoff.busy(), next_leak_check_qpc, watch.second));
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
        filter_capabilities.enabled = config.filter_cache;
        bfe.log = &log;
    }

    ~Engine() {
        stopping = true;
        wake.notify_all();
        if (divert != INVALID_HANDLE_VALUE) WinDivertShutdown(divert, WINDIVERT_SHUTDOWN_RECV);
        if (receiver.joinable()) receiver.join();
        stop_lookup();
        if (divert != INVALID_HANDLE_VALUE) WinDivertClose(divert);
        if (session) FwpmEngineClose0(session);
    }

    int run() {
        bfe.start(config.state_out);
        if (FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &session))
            throw std::runtime_error("FwpmEngineOpen0 lookup session");

        anchor_qpc = qpc();
        anchor_filetime = utc_now();
        engine_started_qpc = anchor_qpc;

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
                  ",\"mode\":" + json(config.mode) + ",\"lookup_mode\":" + json(config.lookup_mode) +
                  ",\"enum_scope\":" + json(config.enum_scope) +
                  ",\"filter_cache\":" + (config.filter_cache ? "true" : "false") +
                  ",\"hold_ms\":" + std::to_string(config.hold_ms) + "}");

        if (config.lookup_mode == "async") lookup_thread = std::thread([this] {
            try { lookup_loop(); }
            catch (const std::exception& error) {
                lookup_worker_error = true;
                log.write("{\"kind\":\"error\",\"operation\":\"lookup_worker_exception\",\"message\":" + json(error.what()) + "}");
            } catch (...) {
                lookup_worker_error = true;
                log.write("{\"kind\":\"error\",\"operation\":\"lookup_worker_exception\"}");
            }
            wake.notify_one();
        });
        receiver = std::thread([this] { receive(); });
        const int64_t end = qpc() + frequency * config.seconds;

        while (qpc() < end && !receive_error && !fatal_send && !lookup.errors && !lookup_worker_error) {
            if (!config.stop_file.empty() &&
                GetFileAttributesA(config.stop_file.c_str()) != INVALID_FILE_ATTRIBUTES) break;
            std::deque<Packet> batch;
            {
                std::unique_lock<std::mutex> lock(mutex);
                if (input.empty() && !query_handoff.ready() && !lookup_worker_error && !receive_error) {
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
        }

        stopping = true;
        WinDivertShutdown(divert, WINDIVERT_SHUTDOWN_RECV);
        wake.notify_all();
        if (receiver.joinable()) receiver.join();
        stop_lookup();
        {
            std::deque<Packet> batch;
            { std::lock_guard<std::mutex> lock(mutex); batch.swap(input); }
            for (auto& packet : batch) handle(std::move(packet));
        }
        for (auto& entry : flows) {
            Flow& flow = *entry.second;
            if (flow.action == "pending") { flow.action = "direct"; ++unattributed; }
            flush(flow, entry.first);
        }

        bfe.finish();
        write_summary();
        if (receive_error)
            log.write("{\"kind\":\"error\",\"operation\":\"receive\",\"code\":" +
                      std::to_string(receive_error.load()) + "}");
        log.write("{\"kind\":\"complete\",\"qpc\":" + std::to_string(qpc()) +
                  ",\"flows\":" + std::to_string(flows.size()) +
                  ",\"success\":" + (success() ? "true" : "false") + "}");
        return success() ? 0 : 3;
    }

    bool success() const { return !receive_error && !fatal_send && !lookup.errors && !lookup_worker_error && !bfe.errors; }

    void write_summary() {
        auto dist = [](const std::vector<double>& values) {
            auto d = inproc::distribution(values);
            std::ostringstream out;
            out << "{\"count\":" << d.count << ",\"p50\":" << d.p50 << ",\"p95\":" << d.p95
                << ",\"max\":" << d.max << "}";
            return out.str();
        };
        auto phase = [](const PhaseMetric& metric) {
            std::ostringstream out;
            out << "{\"calls\":" << metric.calls << ",\"total_ms\":" << metric.total_ms
                << ",\"max_ms\":" << metric.max_ms << "}";
            return out.str();
        };
        const double runtime_ms = elapsed_ms(engine_started_qpc);
        std::ostringstream shapes;
        shapes << "[";
        for (const auto& shape : lookup.condition_shapes) {
            if (shape != *lookup.condition_shapes.begin()) shapes << ",";
            shapes << "{\"mask\":" << shape.first << ",\"count\":" << shape.second << "}";
        }
        shapes << "]";
        std::ostringstream out;
        out << "{\"engine\":\"inproc\",\"mode\":" << json(config.mode)
            << ",\"topology\":\"single-host-local\""
            << ",\"selected_app\":" << json(selected_app)
            << ",\"first_packet_decision_latency_ms\":" << dist(decision_latency_ms)
            << ",\"lookup_calls\":" << lookup.calls
            << ",\"lookup_errors\":" << lookup.errors
            << ",\"lookup_worker_error\":" << (lookup_worker_error ? "true" : "false")
            << ",\"lookup_mode\":" << json(config.lookup_mode)
            << ",\"enum_scope\":" << json(config.enum_scope)
            << ",\"filter_cache\":" << (config.filter_cache ? "true" : "false")
            << ",\"lookup_query_count\":" << lookup.queries
            << ",\"lookup_query_completed\":" << lookup.completed
            << ",\"lookup_query_cancelled\":" << lookup.cancelled
            << ",\"lookup_query_backpressure\":" << lookup.backpressure
            << ",\"lookup_query_max_subjects\":" << lookup.max_subjects
            << ",\"lookup_stale_subjects\":" << lookup.stale_subjects
            << ",\"lookup_incomplete_results\":" << lookup.incomplete_results
            << ",\"lookup_query_busy_ms\":" << lookup.busy_ms
            << ",\"lookup_query_cpu_ms\":" << lookup.cpu_ms
            << ",\"lookup_query_cpu_valid\":" << (lookup.cpu_samples && !lookup.cpu_errors ? "true" : "false")
            << ",\"lookup_query_cpu_samples\":" << lookup.cpu_samples
            << ",\"lookup_query_cpu_errors\":" << lookup.cpu_errors
            << ",\"lookup_query_cpu_error_code\":" << lookup.cpu_error_code
            << ",\"lookup_runtime_ms\":" << runtime_ms
            << ",\"lookup_busy_share\":" << (runtime_ms > 0 ? lookup.busy_ms / runtime_ms : 0)
            << ",\"lookup_create\":" << phase(lookup.create)
            << ",\"lookup_enum\":" << phase(lookup.enumerate)
            << ",\"lookup_destroy\":" << phase(lookup.destroy)
            << ",\"lookup_process\":" << phase(lookup.process)
            << ",\"lookup_result_apply_ms\":" << dist(lookup.apply_ms)
            << ",\"lookup_returned_events\":" << lookup.events
            << ",\"filter_cache_hits\":" << lookup.cache_hits
            << ",\"filter_cache_misses\":" << lookup.cache_misses
            << ",\"filter_cache_rejections\":" << lookup.cache_rejections
            << ",\"bfe_errors\":" << bfe.errors
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
            << ",\"enum_condition_shapes\":" << shapes.str()
            << ",\"window_before_ms\":" << config.window_before_ms
            << ",\"window_after_ms\":" << config.window_after_ms
            << ",\"send_rst\":" << (config.send_rst ? "true" : "false")
            << ",\"delay_ms\":" << config.delay_ms
            << ",\"success\":" << (success() ? "true" : "false") << "}";
        summary_file << out.str() << '\n';
        summary_file.flush();
        log.write("{\"kind\":\"summary\",\"enum_filter\":" + json(lookup.filter.empty() ? "none" : lookup.filter) +
                  ",\"lookup_mode\":" + json(config.lookup_mode) +
                  ",\"enum_scope\":" + json(config.enum_scope) +
                  ",\"enum_condition_shapes\":" + shapes.str() +
                  ",\"filter_cache\":" + (config.filter_cache ? "true" : "false") +
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
