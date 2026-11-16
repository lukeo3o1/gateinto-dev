use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use super::packet::{FIN, RST, Segment};

pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs((2 * 60 + 4) * 60);
pub const LINGER: Duration = Duration::from_secs(120);
pub(super) const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

type Key = (Ipv4Addr, u16);

struct Flow {
    remote_port: u16,
    initial_sequence: u32,
    last_seen: Instant,
    fin_out: bool,
    fin_in: bool,
    ended_at: Option<Instant>,
}

impl Flow {
    fn new(segment: &Segment, now: Instant) -> Self {
        Self {
            remote_port: segment.destination_port,
            initial_sequence: segment.sequence,
            last_seen: now,
            fin_out: false,
            fin_in: false,
            ended_at: None,
        }
    }

    fn live(&self, now: Instant, idle_timeout: Duration) -> bool {
        let lingered = self
            .ended_at
            .is_some_and(|ended| now.saturating_duration_since(ended) >= LINGER);
        !lingered && now.saturating_duration_since(self.last_seen) < idle_timeout
    }

    fn seen(&mut self, segment: &Segment, outbound: bool, now: Instant) {
        self.last_seen = now;
        if segment.has(FIN) {
            if outbound {
                self.fin_out = true;
            } else {
                self.fin_in = true;
            }
        }
        if self.ended_at.is_none() && (segment.has(RST) || (self.fin_out && self.fin_in)) {
            self.ended_at = Some(now);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Admission {
    Created,
    Retransmit,
    Continued,
    Orphan,
    Collision,
    Full,
}

pub(super) struct Flows {
    flows: HashMap<Key, Flow>,
    capacity: usize,
    idle_timeout: Duration,
    last_sweep: Option<Instant>,
}

impl Flows {
    pub(super) fn new(capacity: usize, idle_timeout: Duration) -> Self {
        Self {
            flows: HashMap::new(),
            capacity,
            idle_timeout,
            last_sweep: None,
        }
    }

    pub(super) fn client(&mut self, segment: &Segment, now: Instant) -> Admission {
        let key = (segment.destination, segment.source_port);
        let syn = segment.is_pure_syn();
        let Some(flow) = self.live(key, now) else {
            return if syn {
                self.create(key, segment, now)
            } else {
                Admission::Orphan
            };
        };
        let admission = if syn && flow.ended_at.is_some() {
            Admission::Created
        } else if flow.remote_port != segment.destination_port {
            return Admission::Collision;
        } else if !syn {
            Admission::Continued
        } else if segment.sequence == flow.initial_sequence {
            Admission::Retransmit
        } else {
            Admission::Created
        };
        if admission == Admission::Created {
            *flow = Flow::new(segment, now);
        } else {
            flow.seen(segment, true, now);
        }
        admission
    }

    pub(super) fn reply(&mut self, segment: &Segment, now: Instant) -> Option<u16> {
        let flow = self.live((segment.destination, segment.destination_port), now)?;
        flow.seen(segment, false, now);
        Some(flow.remote_port)
    }

    fn live(&mut self, key: Key, now: Instant) -> Option<&mut Flow> {
        let idle_timeout = self.idle_timeout;
        if self
            .flows
            .get(&key)
            .is_some_and(|flow| !flow.live(now, idle_timeout))
        {
            self.flows.remove(&key);
        }
        self.flows.get_mut(&key)
    }

    fn create(&mut self, key: Key, segment: &Segment, now: Instant) -> Admission {
        let swept_lately = self
            .last_sweep
            .is_some_and(|last| now.saturating_duration_since(last) < SWEEP_INTERVAL);
        if self.flows.len() >= self.capacity && !swept_lately {
            let idle_timeout = self.idle_timeout;
            self.flows.retain(|_, flow| flow.live(now, idle_timeout));
            self.last_sweep = Some(now);
        }
        if self.flows.len() >= self.capacity {
            return Admission::Full;
        }
        self.flows.insert(key, Flow::new(segment, now));
        Admission::Created
    }
}
