#pragma once
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <map>
#include <limits>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <tuple>

namespace socket_owner {

template <class Mutex>
class RevisionWake {
    Mutex& mutex;
    std::condition_variable& wake;
    std::atomic<uint64_t> version{0};
public:
    RevisionWake(Mutex& guard, std::condition_variable& event) : mutex(guard), wake(event) {}
    uint64_t revision() const { return version.load(); }
    void changed() {
        { std::lock_guard<Mutex> lock(mutex); ++version; }
        wake.notify_one();
    }
};

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
enum class ConnectChange { New, ExactDuplicate, Timestamp, Process, Endpoint, Tuple, Invalid };
enum class CloseRelation { Unknown, Original, OtherKnown, Quarantined };

inline int64_t wakeup(int64_t now, int64_t retry, int64_t deadline) {
    return retry > now && retry < deadline ? retry : deadline;
}

inline bool forwarding_allowed(bool proxy, Verdict verdict) {
    return verdict == Verdict::Matched || (!proxy && verdict == Verdict::Missing);
}

inline bool teardown_only(bool syn, bool ack, bool fin, bool rst, size_t payload) {
    return !syn && !payload && (ack || fin || rst);
}

inline bool initial_syn_rejected(bool quarantined, bool progress, bool saw_syn, bool same_sequence, bool unusable) {
    return quarantined || progress || (saw_syn && !same_sequence) || unusable;
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

struct ConnectContext {
    bool bound = false, after_capture = false, same_endpoint = false, same_pid = false, parent_matches = false;
    bool injection_known = false, after_injection_start = false, after_injection_success = false, received_after_injection = false;
};

inline bool route_allowed(bool pending, Tag requested, Tag current, int64_t now, int64_t deadline, Verdict verdict) {
    return pending && requested == current && now < deadline && verdict == Verdict::Matched;
}

class History {
    struct Entry {
        Event connect, identity;
        bool connected = false, resolved = false, closed = false, conflict = false, admitted = false, quarantined = false;
        int64_t closed_qpc = 0;
        int64_t injection_started = 0, injection_succeeded = 0;
        std::optional<Tag> bound;
    };
    std::map<Tuple, Entry> entries;
    std::map<uint64_t, Tuple> endpoints;
    std::map<uint64_t, int64_t> closed_endpoints;
    std::set<std::pair<Tuple, uint64_t>> quarantine;
    std::set<uint64_t> quarantine_endpoints;
    uint64_t quarantine_count = 0;
    size_t capacity, byte_capacity, bytes = 0;
    bool poisoned = false;
public:
    explicit History(size_t limit = 4096, size_t byte_limit = 8 * 1024 * 1024) : capacity(limit), byte_capacity(byte_limit) {}
    bool apply(const Event&);
    ConnectChange classify(const Event&) const;
    CloseRelation close_relation(uint64_t endpoint) const;
    ConnectContext context(const Event&) const;
    void injected(const Tuple&, Tag, int64_t started, int64_t succeeded);
    Match match(const Tuple&, Tag, Tag, int64_t, bool historical = false);
    Match forwarding(const Tuple&, Tag, int64_t, int64_t packet_qpc, bool teardown, int64_t grace, bool initial_syn = false);
    void invalidate(const Tuple&);
    void poison() { poisoned = true; }
    bool failed() const { return poisoned; }
    size_t size() const { return entries.size(); }
    uint64_t quarantined_count() const { return quarantine_count; }
    size_t quarantined_pairs() const { return quarantine.size(); }
    size_t quarantined_endpoints() const { return quarantine_endpoints.size(); }
    bool reject_initial_syn(const Tuple& tuple) const {
        const auto found = entries.find(tuple);
        return found != entries.end() && found->second.quarantined;
    }
};

inline ConnectChange History::classify(const Event& event) const {
    if (!event.endpoint || !event.pid) return ConnectChange::Invalid;
    const auto known = endpoints.find(event.endpoint);
    if (known != endpoints.end() && !(known->second == event.tuple)) return ConnectChange::Tuple;
    const auto found = entries.find(event.tuple);
    if (found == entries.end() || !found->second.connected) return ConnectChange::New;
    const auto& first = found->second.connect;
    if (first.endpoint != event.endpoint) return ConnectChange::Endpoint;
    if (first.pid != event.pid) return ConnectChange::Process;
    if (first.occurred != event.occurred) return ConnectChange::Timestamp;
    return ConnectChange::ExactDuplicate;
}

inline CloseRelation History::close_relation(uint64_t endpoint) const {
    const auto known = endpoints.find(endpoint);
    if (known == endpoints.end()) return quarantine_endpoints.count(endpoint) ? CloseRelation::Quarantined : CloseRelation::Unknown;
    return entries.at(known->second).connect.endpoint == endpoint ? CloseRelation::Original : CloseRelation::OtherKnown;
}

inline ConnectContext History::context(const Event& event) const {
    ConnectContext result;
    const auto found = entries.find(event.tuple);
    if (found == entries.end()) return result;
    const auto& entry = found->second;
    if (!entry.bound) return result;
    result.bound = true;
    result.after_capture = event.occurred > entry.bound->capture;
    result.same_endpoint = entry.connect.endpoint == event.endpoint;
    result.same_pid = entry.connect.pid == event.pid;
    result.parent_matches = entry.connect.endpoint == event.parent;
    result.injection_known = entry.injection_succeeded != 0;
    result.after_injection_start = entry.injection_started && event.occurred >= entry.injection_started;
    result.after_injection_success = entry.injection_succeeded && event.occurred >= entry.injection_succeeded;
    result.received_after_injection = entry.injection_succeeded && event.received >= entry.injection_succeeded;
    return result;
}

inline void History::injected(const Tuple& tuple, Tag tag, int64_t started, int64_t succeeded) {
    auto found = entries.find(tuple);
    if (found == entries.end() || !found->second.bound || !(*found->second.bound == tag)) return;
    auto& entry = found->second;
    if (!entry.admitted || entry.closed || entry.conflict || started < tag.capture || succeeded < started) return;
    if (!entry.injection_succeeded) { entry.injection_started = started; entry.injection_succeeded = succeeded; }
}

inline bool History::apply(const Event& event) {
    if (poisoned) return false;
    if (!event.endpoint) return true;
    if (event.kind == Kind::Close) {
        if (quarantine_endpoints.count(event.endpoint) && !endpoints.count(event.endpoint)) return true;
        if (!closed_endpoints.count(event.endpoint) && closed_endpoints.size() >= capacity) { poison(); return false; }
        closed_endpoints.emplace(event.endpoint, event.occurred);
        const auto known = endpoints.find(event.endpoint);
        if (known != endpoints.end()) {
            auto& entry = entries.at(known->second);
            if (entry.connect.endpoint == event.endpoint) {
                entry.closed = true;
                entry.closed_qpc = closed_endpoints.at(event.endpoint);
            }
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
    const bool later_connect = entry.connected && entry.resolved && entry.admitted && entry.bound &&
        !entry.closed && !entry.conflict && entry.connect.endpoint != event.endpoint &&
        entry.injection_started && entry.injection_succeeded >= entry.injection_started &&
        event.occurred > entry.bound->capture && event.occurred > entry.injection_started &&
        event.received >= event.occurred;
    if (later_connect) {
        const auto key = std::make_pair(event.tuple, event.endpoint);
        if (!quarantine.count(key) && quarantine.size() >= capacity) { poison(); return false; }
        quarantine.insert(key);
        quarantine_endpoints.insert(event.endpoint);
        entry.quarantined = true;
        ++quarantine_count;
        return true;
    }
    if (quarantine_endpoints.count(event.endpoint)) {
        entry.conflict = true;
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

inline Match History::forwarding(const Tuple& tuple, Tag tag, int64_t lookback, int64_t packet_qpc, bool teardown, int64_t grace,
                                 bool initial_syn) {
    auto result = match(tuple, tag, tag, lookback, true);
    if (result.verdict != Verdict::Matched) return result;
    if (initial_syn && reject_initial_syn(tuple)) return {Verdict::Ambiguous, {}};
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
