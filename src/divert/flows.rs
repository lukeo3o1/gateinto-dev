use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use super::packet::{ACK, FIN, RST, SYN, Segment};

pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs((2 * 60 + 4) * 60);
pub const LINGER: Duration = Duration::from_secs(120);
pub(super) const OPENING_TIMEOUT: Duration = Duration::from_secs(4 * 60);
pub(super) const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

type Key = (Ipv4Addr, Ipv4Addr, u16);

#[derive(Clone, Copy)]
struct Syn {
    sequence: u32,
    payload_len: u32,
}

impl Syn {
    fn from_segment(segment: &Segment) -> Self {
        Self {
            sequence: segment.sequence,
            payload_len: segment.payload_len,
        }
    }

    fn acknowledged_by(self, segment: &Segment) -> bool {
        // A SYN takes one sequence number. TCP Fast Open may acknowledge its data too.
        segment.has(ACK)
            && (1..=1 + self.payload_len)
                .contains(&segment.acknowledgment.wrapping_sub(self.sequence))
    }
}

enum Phase {
    Opening {
        started: Instant,
        reply: Option<Syn>,
    },
    Established,
    Ended(Instant),
}

struct Flow {
    remote_port: u16,
    initial: Syn,
    last_seen: Instant,
    fin_out: bool,
    fin_in: bool,
    phase: Phase,
}

impl Flow {
    fn new(segment: &Segment, now: Instant) -> Self {
        Self {
            remote_port: segment.destination_port,
            initial: Syn::from_segment(segment),
            last_seen: now,
            fin_out: false,
            fin_in: false,
            phase: Phase::Opening {
                started: now,
                reply: None,
            },
        }
    }

    fn live(&self, now: Instant, idle_timeout: Duration) -> bool {
        let retained = match self.phase {
            Phase::Opening { started, .. } => {
                now.saturating_duration_since(started) < OPENING_TIMEOUT
            }
            Phase::Established => true,
            Phase::Ended(ended) => now.saturating_duration_since(ended) < LINGER,
        };
        retained && now.saturating_duration_since(self.last_seen) < idle_timeout
    }

    fn seen(&mut self, segment: &Segment, outbound: bool, now: Instant, injected: bool) {
        self.last_seen = now;
        match &mut self.phase {
            Phase::Opening {
                reply: Some(syn), ..
            } if injected
                && outbound
                && !segment.has(SYN | RST)
                && syn.acknowledged_by(segment) =>
            {
                self.phase = Phase::Established;
            }
            Phase::Opening { reply, .. }
                if injected
                    && !outbound
                    && segment.has(SYN)
                    && !segment.has(FIN | RST)
                    && self.initial.acknowledged_by(segment) =>
            {
                *reply = Some(Syn::from_segment(segment));
            }
            _ => {}
        }
        if segment.has(FIN) {
            if outbound {
                self.fin_out = true;
            } else {
                self.fin_in = true;
            }
        }
        if !matches!(self.phase, Phase::Ended(_))
            && (segment.has(RST) || (self.fin_out && self.fin_in))
        {
            self.phase = Phase::Ended(now);
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

    pub(super) fn client(
        &mut self,
        segment: &Segment,
        now: Instant,
        reflect: impl FnOnce() -> bool,
    ) -> Admission {
        let key = (segment.source, segment.destination, segment.source_port);
        let syn = segment.is_pure_syn();
        let Some(flow) = self.live(key, now) else {
            if !syn {
                return Admission::Orphan;
            }
            let admission = self.create(key, segment, now);
            if admission == Admission::Created {
                reflect();
            }
            return admission;
        };
        let admission = if syn && matches!(flow.phase, Phase::Ended(_)) {
            Admission::Created
        } else if flow.remote_port != segment.destination_port {
            return Admission::Collision;
        } else if !syn {
            Admission::Continued
        } else if segment.sequence == flow.initial.sequence {
            Admission::Retransmit
        } else {
            Admission::Created
        };
        let injected = reflect();
        if admission == Admission::Created {
            *flow = Flow::new(segment, now);
        } else {
            flow.seen(segment, true, now, injected);
        }
        admission
    }

    pub(super) fn reply(
        &mut self,
        segment: &Segment,
        now: Instant,
        restore: impl FnOnce(u16) -> bool,
    ) -> bool {
        let key = (
            segment.source,
            segment.destination,
            segment.destination_port,
        );
        let Some(flow) = self.live(key, now) else {
            return false;
        };
        let injected = restore(flow.remote_port);
        flow.seen(segment, false, now, injected);
        true
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
