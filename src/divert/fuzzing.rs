use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::num::NonZeroU16;
use std::time::{Duration, Instant};

use super::packet::{self, ECN, IP_HEADER, Packet};
use super::{Counters, DEFAULT_IDLE_TIMEOUT, Direction, Engine, Verdict};

pub const LISTENER: NonZeroU16 = NonZeroU16::new(8443).unwrap();
const CAPACITY: usize = 4;

pub struct Checker {
    listener: u16,
    remote_ports: HashMap<(Ipv4Addr, u16), u16>,
}

impl Checker {
    pub fn new(listener: NonZeroU16) -> Self {
        Self {
            listener: listener.get(),
            remote_ports: HashMap::new(),
        }
    }

    pub fn check(&mut self, before: &[u8], after: &[u8], verdict: Verdict) {
        if verdict == Verdict::Drop {
            assert!(before == after, "a dropped packet was changed");
            return;
        }
        assert!(
            matches!(packet::parse(after), Packet::Tcp(_)),
            "an injected packet is not IPv4 TCP without IPv4 options"
        );
        assert!(
            packet::checksums_valid(after),
            "an injected packet has a wrong checksum"
        );
        let source = address(before, 12);
        let destination = address(before, 16);
        let source_port = port(before, IP_HEADER);
        let destination_port = port(before, IP_HEADER + 2);
        assert!(
            (address(after, 12), address(after, 16)) == (destination, source),
            "the addresses of an injected packet are not swapped"
        );
        if source_port == self.listener {
            let remote_port = self.remote_ports.get(&(destination, destination_port));
            assert!(
                remote_port == Some(&port(after, IP_HEADER)),
                "a restored reply does not come from the remote port of its flow"
            );
            assert!(
                port(after, IP_HEADER + 2) == destination_port,
                "a restored reply changed its destination port"
            );
        } else {
            assert!(
                port(after, IP_HEADER) == source_port,
                "a reflected packet changed its source port"
            );
            assert!(
                port(after, IP_HEADER + 2) == self.listener,
                "a reflected packet is not addressed to the listener"
            );
            assert!(after[1] & !ECN == 0, "a reflected packet kept its DSCP");
            self.remote_ports
                .insert((destination, source_port), destination_port);
        }
    }
}

fn address(packet: &[u8], at: usize) -> Ipv4Addr {
    Ipv4Addr::new(packet[at], packet[at + 1], packet[at + 2], packet[at + 3])
}

fn port(packet: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([packet[at], packet[at + 1]])
}

pub fn run(data: &[u8]) -> Counters {
    let mut engine = Engine::new(LISTENER, CAPACITY, DEFAULT_IDLE_TIMEOUT);
    let mut checker = Checker::new(LISTENER);
    let mut now = Instant::now();
    let mut rest = data;
    while let [control, length, tail @ ..] = rest {
        let (bytes, next) = tail.split_at(usize::from(*length).min(tail.len()));
        let step = Duration::from_secs(u64::from(control >> 1).pow(2));
        now = now.checked_add(step).unwrap_or(now);
        let direction = if control & 1 == 0 {
            Direction::Outbound
        } else {
            Direction::Inbound
        };
        let mut packet = bytes.to_vec();
        let verdict = engine.process(&mut packet, direction, now);
        checker.check(bytes, &packet, verdict);
        rest = next;
    }
    engine.counters()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::divert::packet::{ACK, FIN, SYN, UDP};
    use crate::divert::testing::{CLIENT, REMOTE, TAGGED, TestPacket};

    fn input(steps: &[(u8, TestPacket)]) -> Vec<u8> {
        let mut input = Vec::new();
        for (control, packet) in steps {
            let bytes = packet.build();
            input.push(*control);
            input.push(bytes.len() as u8);
            input.extend_from_slice(&bytes);
        }
        input
    }

    #[test]
    fn a_connection_in_the_input_is_translated_both_ways_and_ends() {
        let counters = run(&input(&[
            (0, TestPacket::client(SYN)),
            (0, TestPacket::reply(SYN | ACK)),
            (2, TestPacket::client(ACK)),
            (0, TestPacket::client(FIN | ACK)),
            (0, TestPacket::reply(FIN | ACK)),
            (0, TestPacket::client(ACK)),
            (22, TestPacket::client(ACK)),
            (1, TestPacket::client(ACK)),
            (
                0,
                TestPacket {
                    protocol: UDP,
                    ..TestPacket::client(0)
                },
            ),
        ]));
        assert_eq!(
            counters,
            Counters {
                captured: 9,
                new_flows: 1,
                reflected: 4,
                replies_restored: 2,
                orphans_dropped: 1,
                inbound_dropped: 1,
                contained_udp: 1,
                ..Counters::default()
            }
        );
    }

    #[test]
    fn a_truncated_input_ends_with_a_short_packet() {
        let mut data = input(&[(0, TestPacket::client(SYN))]);
        data.truncate(data.len() - 2);
        assert_eq!(run(&data).malformed_dropped, 1);
        assert_eq!(run(&[0]), Counters::default());
        assert_eq!(run(&[]), Counters::default());
    }

    #[test]
    #[should_panic(expected = "a reflected packet kept its DSCP")]
    fn the_checker_refuses_a_reflected_packet_that_kept_its_dscp() {
        let before = TestPacket::client(SYN).build();
        let after = TestPacket {
            source: REMOTE,
            destination: CLIENT,
            destination_port: LISTENER.get(),
            ..TestPacket::client(SYN)
        }
        .build();
        assert_eq!(after[1], TAGGED);
        Checker::new(LISTENER).check(&before, &after, Verdict::InjectInbound);
    }

    #[test]
    #[should_panic(expected = "a restored reply does not come from the remote port of its flow")]
    fn the_checker_refuses_a_reply_without_a_flow() {
        let before = TestPacket::reply(ACK).build();
        let after = TestPacket {
            source: REMOTE,
            destination: CLIENT,
            source_port: 443,
            ..TestPacket::reply(ACK)
        }
        .build();
        Checker::new(LISTENER).check(&before, &after, Verdict::InjectInbound);
    }

    #[test]
    #[should_panic(expected = "a dropped packet was changed")]
    fn the_checker_refuses_a_changed_dropped_packet() {
        Checker::new(LISTENER).check(&[1], &[2], Verdict::Drop);
    }
}
