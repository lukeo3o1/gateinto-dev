#pragma once
#include <cstdint>
#include <map>
#include <limits>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <tuple>

namespace socket_owner {

struct Tuple {
    uint32_t local = 0, remote = 0;
    uint16_t local_port = 0, remote_port = 0;
    uint8_t protocol = 6;
    bool operator<(const Tuple& other) const {
        return std::tie(local, remote, local_port, remote_port, protocol) <
            std::tie(other.local, other.remote, other.local_port, other.remote_port, other.protocol);
    }
    bool operator==(const Tuple& other) const { return !(*this < other) && !(other < *this); }
};

struct Tag {
    int64_t generation = 0, capture = 0;
    bool operator==(const Tag& other) const { return generation == other.generation && capture == other.capture; }
};

enum class Kind { Connect, Close, Identity };
enum class Verdict { Missing, Matched, Closed, Ambiguous, Stale, Invalid, Poisoned };

inline bool forwarding_allowed(bool proxy, Verdict verdict) {
    return verdict == Verdict::Matched || (!proxy && verdict == Verdict::Missing);
}

inline bool teardown_only(bool syn, bool ack, bool fin, bool rst, size_t payload) {
    return !syn && !payload && (ack || fin || rst);
}

struct Event {
    Kind kind = Kind::Connect;
    Tuple tuple;
    uint64_t endpoint = 0, parent = 0, creation = 0;
    uint32_t pid = 0;
    int64_t occurred = 0, received = 0, ready = 0;
    bool ipv4 = false, creation_guard_valid = false;
    std::string path;
};

struct Match {
    Verdict verdict = Verdict::Missing;
    Event event;
};

inline bool route_allowed(bool pending, Tag requested, Tag current, int64_t now, int64_t deadline, Verdict verdict) {
    return pending && requested == current && now < deadline && verdict == Verdict::Matched;
}

class History {
    struct Entry {
        Event connect, identity;
        bool connected = false, resolved = false, closed = false, conflict = false, admitted = false;
        int64_t closed_qpc = 0;
        std::optional<Tag> bound;
    };
    std::map<Tuple, Entry> entries;
    std::map<uint64_t, Tuple> endpoints;
    std::map<uint64_t, int64_t> closed_endpoints;
    size_t capacity, byte_capacity, bytes = 0;
    bool poisoned = false;
public:
    explicit History(size_t limit = 4096, size_t byte_limit = 8 * 1024 * 1024) : capacity(limit), byte_capacity(byte_limit) {}
    bool apply(const Event&);
    Match match(const Tuple&, Tag, Tag, int64_t, bool historical = false);
    Match forwarding(const Tuple&, Tag, int64_t, int64_t packet_qpc, bool teardown, int64_t grace);
    void invalidate(const Tuple&);
    void poison() { poisoned = true; }
    bool failed() const { return poisoned; }
    size_t size() const { return entries.size(); }
};

inline bool History::apply(const Event& event) {
    if (poisoned) return false;
    if (!event.endpoint) return true;
    if (event.kind == Kind::Close) {
        if (!closed_endpoints.count(event.endpoint) && closed_endpoints.size() >= capacity) { poison(); return false; }
        closed_endpoints.emplace(event.endpoint, event.occurred);
        const auto known = endpoints.find(event.endpoint);
        if (known != endpoints.end()) {
            auto& entry = entries.at(known->second);
            entry.closed = true;
            entry.closed_qpc = closed_endpoints.at(event.endpoint);
        }
        return true;
    }
    if (event.kind == Kind::Identity) {
        auto found = entries.find(event.tuple);
        if (found == entries.end()) return true;
        auto& entry = found->second;
        const auto& connect = entry.connect;
        if (!entry.connected || connect.endpoint != event.endpoint || connect.pid != event.pid ||
            connect.occurred != event.occurred) return true;
        if (entry.resolved) {
            if (entry.identity.creation != event.creation || entry.identity.path != event.path) entry.conflict = true;
            return true;
        }
        if (event.path.size() > byte_capacity - bytes) { poison(); return false; }
        bytes += event.path.size();
        entry.identity = event;
        entry.resolved = true;
        return true;
    }
    auto found = entries.find(event.tuple);
    if (found == entries.end()) {
        if (entries.size() >= capacity) { poison(); return false; }
        found = entries.emplace(event.tuple, Entry{}).first;
    }
    auto& entry = found->second;
    const auto known = endpoints.find(event.endpoint);
    if (known != endpoints.end() && !(known->second == event.tuple)) {
        entries.at(known->second).conflict = entry.conflict = true;
        return true;
    }
    if (known == endpoints.end()) {
        if (endpoints.size() >= capacity) { poison(); return false; }
        endpoints.emplace(event.endpoint, event.tuple);
    }
    if (entry.connected) {
        if (entry.connect.endpoint != event.endpoint || entry.connect.pid != event.pid ||
            entry.connect.occurred != event.occurred) entry.conflict = true;
    } else {
        entry.connect = event;
        entry.connected = true;
        entry.closed = closed_endpoints.count(event.endpoint) != 0;
        if (entry.closed) entry.closed_qpc = closed_endpoints.at(event.endpoint);
    }
    return true;
}

inline Match History::match(const Tuple& tuple, Tag requested, Tag current, int64_t lookback, bool historical) {
    if (poisoned) return {Verdict::Poisoned, {}};
    if (!(requested == current)) return {Verdict::Stale, {}};
    auto found = entries.find(tuple);
    if (found == entries.end()) return {};
    auto& entry = found->second;
    if (entry.conflict) return {Verdict::Ambiguous, {}};
    if (entry.closed && (!historical || entry.closed_qpc <= requested.capture)) return {Verdict::Closed, {}};
    const auto& connect = entry.connect;
    if (!entry.connected) return {};
    if (connect.occurred <= 0 || connect.occurred > requested.capture ||
        requested.capture - connect.occurred > lookback || (entry.bound && !(*entry.bound == requested)))
        return {Verdict::Stale, {}};
    entry.bound = requested;
    if (!entry.resolved) return {};
    const auto& identity = entry.identity;
    if (!identity.ipv4 || identity.tuple.protocol != 6 || !identity.tuple.local || !identity.tuple.remote ||
        !identity.tuple.local_port || !identity.tuple.remote_port || !identity.pid || !identity.endpoint ||
        !identity.creation || !identity.creation_guard_valid || identity.path.empty() ||
        identity.received < identity.occurred || identity.ready < identity.received)
        return {Verdict::Invalid, {}};
    if (!historical) entry.admitted = true;
    return {Verdict::Matched, identity};
}

inline Match History::forwarding(const Tuple& tuple, Tag tag, int64_t lookback, int64_t packet_qpc, bool teardown, int64_t grace) {
    auto result = match(tuple, tag, tag, lookback, true);
    if (result.verdict != Verdict::Matched) return result;
    const auto& entry = entries.at(tuple);
    if (packet_qpc < tag.capture) return {Verdict::Stale, {}};
    if (entry.closed && (!entry.admitted || (packet_qpc > entry.closed_qpc &&
        (!teardown || packet_qpc - entry.closed_qpc > grace))))
        return {Verdict::Closed, {}};
    return result;
}

inline void History::invalidate(const Tuple& tuple) {
    auto found = entries.find(tuple);
    if (found != entries.end()) found->second.conflict = true;
    else {
        if (entries.size() >= capacity) { poison(); return; }
        entries[tuple].conflict = true;
    }
}

inline int64_t checked_time_add(int64_t left, int64_t right) {
    if ((right > 0 && left > std::numeric_limits<int64_t>::max() - right) ||
        (right < 0 && left < std::numeric_limits<int64_t>::min() - right)) throw std::overflow_error("Socket time overflow");
    return left + right;
}

inline int64_t scale_time(int64_t delta, int64_t frequency, bool round_up) {
    constexpr int64_t units = 10'000'000;
    const auto whole = delta / frequency;
    if (whole > std::numeric_limits<int64_t>::max() / units || whole < std::numeric_limits<int64_t>::min() / units)
        throw std::overflow_error("Socket QPC overflow");
    const auto remainder = delta % frequency * units;
    auto fraction = remainder / frequency;
    if (round_up && remainder % frequency > 0) ++fraction;
    if (!round_up && remainder % frequency < 0) --fraction;
    return checked_time_add(whole * units, fraction);
}

inline bool creation_precedes(uint64_t creation, int64_t event, int64_t before, int64_t after,
                              uint64_t utc, int64_t frequency) {
    if (!creation || event < 0 || before < 0 || after < before || frequency <= 0 ||
        frequency > std::numeric_limits<int64_t>::max() / 10'000'000 ||
        utc > uint64_t(std::numeric_limits<int64_t>::max())) return false;
    const auto lower = checked_time_add(static_cast<int64_t>(utc), scale_time(event - after, frequency, false));
    return lower >= 0 && creation <= static_cast<uint64_t>(lower);
}

}
