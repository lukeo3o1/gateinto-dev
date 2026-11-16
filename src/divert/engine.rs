use std::num::NonZeroU16;
use std::time::{Duration, Instant};

use super::flows::{Admission, Flows};
use super::packet::{self, Packet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Outbound,
    Inbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    InjectInbound,
    Drop,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    pub captured: u64,
    pub new_flows: u64,
    pub reflected: u64,
    pub replies_restored: u64,
    pub syn_retransmits: u64,
    pub orphans_dropped: u64,
    pub key_collisions: u64,
    pub unknown_replies_dropped: u64,
    pub fragments_dropped: u64,
    pub malformed_dropped: u64,
    pub options_dropped: u64,
    pub table_full: u64,
    pub contained_udp: u64,
    pub contained_other: u64,
    pub contained_ipv6: u64,
    pub inbound_dropped: u64,
}

pub struct Engine {
    listener_port: u16,
    flows: Flows,
    counters: Counters,
}

impl Engine {
    pub fn new(listener_port: NonZeroU16, capacity: usize, idle_timeout: Duration) -> Self {
        Self {
            listener_port: listener_port.get(),
            flows: Flows::new(capacity, idle_timeout),
            counters: Counters::default(),
        }
    }

    pub fn process(&mut self, packet: &mut [u8], direction: Direction, now: Instant) -> Verdict {
        let counters = &mut self.counters;
        counters.captured += 1;
        if direction == Direction::Inbound {
            return dropped(&mut counters.inbound_dropped);
        }
        let segment = match packet::parse(packet) {
            Packet::Tcp(segment) => segment,
            Packet::Udp => return dropped(&mut counters.contained_udp),
            Packet::Other => return dropped(&mut counters.contained_other),
            Packet::Ipv6 => return dropped(&mut counters.contained_ipv6),
            Packet::Fragment => return dropped(&mut counters.fragments_dropped),
            Packet::Options => return dropped(&mut counters.options_dropped),
            Packet::Malformed => return dropped(&mut counters.malformed_dropped),
        };
        if segment.source_port == self.listener_port {
            let Some(remote_port) = self.flows.reply(&segment, now) else {
                return dropped(&mut counters.unknown_replies_dropped);
            };
            packet::restore(packet, &segment, remote_port);
            counters.replies_restored += 1;
            return Verdict::InjectInbound;
        }
        match self.flows.client(&segment, now) {
            Admission::Created => counters.new_flows += 1,
            Admission::Retransmit => counters.syn_retransmits += 1,
            Admission::Continued => {}
            Admission::Orphan => return dropped(&mut counters.orphans_dropped),
            Admission::Collision => return dropped(&mut counters.key_collisions),
            Admission::Full => return dropped(&mut counters.table_full),
        }
        packet::reflect(packet, &segment, self.listener_port);
        counters.reflected += 1;
        Verdict::InjectInbound
    }

    pub fn counters(&self) -> Counters {
        self.counters
    }
}

fn dropped(counter: &mut u64) -> Verdict {
    *counter += 1;
    Verdict::Drop
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::divert::flows::SWEEP_INTERVAL;
    use crate::divert::fuzzing::Checker;
    use crate::divert::packet::{ACK, FIN, RST, SYN, TCP, UDP, checksums_valid};
    use crate::divert::testing::{
        CLIENT, LISTENER, LOCAL_PORT, REMOTE, REMOTE_PORT, TAGGED, TestPacket,
    };
    use crate::divert::{DEFAULT_IDLE_TIMEOUT, LINGER};

    const IDLE: Duration = Duration::from_secs(600);
    const OTHER_PORT: u16 = 80;

    struct Harness {
        engine: Engine,
        start: Instant,
        now: Duration,
    }

    impl Harness {
        fn new(capacity: usize) -> Self {
            Self {
                engine: Engine::new(LISTENER, capacity, IDLE),
                start: Instant::now(),
                now: Duration::ZERO,
            }
        }

        fn at(&mut self, now: Duration) -> &mut Self {
            self.now = now;
            self
        }

        fn process(&mut self, packet: &mut [u8], direction: Direction) -> Verdict {
            self.engine
                .process(packet, direction, self.start + self.now)
        }

        fn send(&mut self, packet: TestPacket) -> (Verdict, Vec<u8>) {
            let mut bytes = packet.build();
            let verdict = self.process(&mut bytes, Direction::Outbound);
            (verdict, bytes)
        }

        fn verdict(&mut self, packet: TestPacket) -> Verdict {
            self.send(packet).0
        }

        fn counters(&self) -> Counters {
            self.engine.counters()
        }
    }

    fn syn(sequence: u32) -> TestPacket {
        TestPacket {
            sequence,
            ..TestPacket::client(SYN)
        }
    }

    fn to_port(port: u16, packet: TestPacket) -> TestPacket {
        TestPacket {
            destination_port: port,
            ..packet
        }
    }

    fn header(packet: &[u8]) -> (Ipv4Addr, Ipv4Addr, u16, u16, u8) {
        let octets = |at: usize| Ipv4Addr::from(<[u8; 4]>::try_from(&packet[at..at + 4]).unwrap());
        let port = |at: usize| u16::from_be_bytes([packet[at], packet[at + 1]]);
        (octets(12), octets(16), port(20), port(22), packet[1])
    }

    const INJECT: Verdict = Verdict::InjectInbound;
    const DROP: Verdict = Verdict::Drop;

    #[test]
    fn a_tagged_syn_starts_a_flow_and_is_reflected_to_the_listener() {
        let mut harness = Harness::new(8);
        let (verdict, packet) = harness.send(TestPacket {
            tos: TAGGED | 0x01,
            ..syn(7)
        });
        assert_eq!(verdict, INJECT);
        assert!(checksums_valid(&packet));
        assert_eq!(
            header(&packet),
            (REMOTE, CLIENT, LOCAL_PORT, LISTENER.get(), 0x01)
        );
        assert_eq!(
            harness.counters(),
            Counters {
                captured: 1,
                new_flows: 1,
                reflected: 1,
                ..Counters::default()
            }
        );
    }

    #[test]
    fn a_listener_reply_is_restored_to_come_from_the_remote_port() {
        let mut harness = Harness::new(8);
        harness.verdict(syn(7));
        let (verdict, packet) = harness.send(TestPacket::reply(SYN | ACK));
        assert_eq!(verdict, INJECT);
        assert!(checksums_valid(&packet));
        assert_eq!(
            header(&packet),
            (REMOTE, CLIENT, REMOTE_PORT, LOCAL_PORT, 0)
        );
        let (verdict, packet) = harness.send(TestPacket::client(ACK));
        assert_eq!(verdict, INJECT);
        assert_eq!(header(&packet).3, LISTENER.get());
        assert_eq!(
            harness.counters(),
            Counters {
                captured: 3,
                new_flows: 1,
                reflected: 2,
                replies_restored: 1,
                ..Counters::default()
            }
        );
    }

    #[test]
    fn a_reply_without_a_flow_is_dropped() {
        let mut harness = Harness::new(8);
        harness.verdict(syn(7));
        let other_client = TestPacket {
            destination_port: LOCAL_PORT + 1,
            ..TestPacket::reply(SYN | ACK)
        };
        let other_remote = TestPacket {
            destination: Ipv4Addr::new(192, 0, 2, 1),
            ..TestPacket::reply(SYN | ACK)
        };
        assert_eq!(harness.verdict(other_client), DROP);
        assert_eq!(harness.verdict(other_remote), DROP);
        assert_eq!(harness.counters().unknown_replies_dropped, 2);
        assert_eq!(harness.counters().replies_restored, 0);
    }

    #[test]
    fn inbound_packets_are_dropped_whatever_they_are() {
        let mut harness = Harness::new(8);
        harness.verdict(syn(7));
        for packet in [TestPacket::reply(ACK), syn(8), TestPacket::client(ACK)] {
            let mut bytes = packet.build();
            let original = bytes.clone();
            assert_eq!(harness.process(&mut bytes, Direction::Inbound), DROP);
            assert_eq!(bytes, original);
        }
        let mut empty = [];
        assert_eq!(harness.process(&mut empty, Direction::Inbound), DROP);
        assert_eq!(harness.counters().inbound_dropped, 4);
        assert_eq!(harness.counters().captured, 5);
    }

    #[test]
    fn tagged_udp_other_protocols_and_ipv6_are_contained() {
        let mut ipv6 = vec![0; 60];
        ipv6[0] = 0x60 | (TAGGED >> 4);
        ipv6[6] = TCP;
        let udp = TestPacket {
            protocol: UDP,
            ..TestPacket::client(0)
        };
        let icmp = TestPacket {
            protocol: 1,
            ..TestPacket::client(0)
        };
        let mut harness = Harness::new(8);
        for mut packet in [udp.build(), udp.build(), icmp.build(), ipv6] {
            assert_eq!(harness.process(&mut packet, Direction::Outbound), DROP);
        }
        assert_eq!(
            harness.counters(),
            Counters {
                captured: 4,
                contained_udp: 2,
                contained_other: 1,
                contained_ipv6: 1,
                ..Counters::default()
            }
        );
    }

    #[test]
    fn fragments_and_malformed_packets_are_dropped() {
        let mut harness = Harness::new(8);
        let fragment = TestPacket {
            fragment: 0x2000,
            ..syn(7)
        };
        assert_eq!(harness.verdict(fragment), DROP);
        let mut truncated = syn(7).build();
        truncated.pop();
        assert_eq!(harness.process(&mut truncated, Direction::Outbound), DROP);
        assert_eq!(
            harness.counters(),
            Counters {
                captured: 2,
                fragments_dropped: 1,
                malformed_dropped: 1,
                ..Counters::default()
            }
        );
    }

    #[test]
    fn every_prefix_of_a_valid_packet_is_dropped_as_malformed() {
        let mut harness = Harness::new(8);
        harness.verdict(syn(7));
        for packet in [
            TestPacket {
                ip_options: 8,
                tcp_options: 8,
                payload: 9,
                ..TestPacket::client(ACK)
            },
            TestPacket::reply(ACK),
        ] {
            let bytes = packet.build();
            for length in 0..bytes.len() {
                let mut prefix = bytes[..length].to_vec();
                assert_eq!(
                    harness.process(&mut prefix, Direction::Outbound),
                    DROP,
                    "{length}"
                );
                assert_eq!(prefix, bytes[..length], "{length}");
            }
        }
        let counters = harness.counters();
        assert_eq!(counters.malformed_dropped, counters.captured - 1);
    }

    #[test]
    fn arbitrary_bytes_never_panic_and_only_inject_translated_packets() {
        let mut harness = Harness::new(4);
        let mut checker = Checker::new(LISTENER);
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let templates = [
            syn(7).build(),
            TestPacket::client(ACK).build(),
            TestPacket::reply(SYN | ACK).build(),
            TestPacket::client(FIN | ACK).build(),
            TestPacket::reply(RST).build(),
        ];
        let mut injected = 0;
        for round in 0..20_000 {
            if next() % 50 == 0 {
                let step = Duration::from_secs(next() % 400);
                let now = harness.now + step;
                harness.at(now);
            }
            let template = &templates[(next() % templates.len() as u64) as usize];
            let length = (next() % 80) as usize;
            let mut bytes: Vec<u8> = (0..length).map(|_| next() as u8).collect();
            if round % 4 != 0 {
                bytes = template.clone();
                for _ in 0..next() % 3 {
                    let at = (next() % bytes.len() as u64) as usize;
                    bytes[at] = next() as u8;
                }
            }
            let direction = if round % 7 == 0 {
                Direction::Inbound
            } else {
                Direction::Outbound
            };
            let before = bytes.clone();
            let verdict = harness.process(&mut bytes, direction);
            checker.check(&before, &bytes, verdict);
            injected += u64::from(verdict == INJECT);
        }
        let counters = harness.counters();
        assert_eq!(counters.captured, 20_000);
        assert_eq!(injected, counters.reflected + counters.replies_restored);
        assert!(counters.reflected > 100 && counters.replies_restored > 100);
    }

    #[test]
    fn tcp_packets_with_ipv4_options_are_dropped_unchanged_in_both_directions_of_a_flow() {
        let mut harness = Harness::new(8);
        harness.verdict(syn(7));
        for packet in [
            TestPacket::client(ACK),
            TestPacket::reply(ACK),
            syn(9),
            TestPacket {
                source_port: LOCAL_PORT + 1,
                ..syn(9)
            },
        ] {
            let mut bytes = TestPacket {
                ip_options: 4,
                ..packet
            }
            .build();
            let original = bytes.clone();
            assert_eq!(harness.process(&mut bytes, Direction::Outbound), DROP);
            assert_eq!(bytes, original);
        }
        let udp = TestPacket {
            protocol: UDP,
            ip_options: 8,
            ..TestPacket::client(0)
        };
        assert_eq!(harness.verdict(udp), DROP);
        assert_eq!(
            harness.counters(),
            Counters {
                captured: 6,
                new_flows: 1,
                reflected: 1,
                options_dropped: 4,
                contained_udp: 1,
                ..Counters::default()
            }
        );
    }

    #[test]
    fn the_same_syn_after_a_flow_ended_starts_a_new_flow_that_outlives_the_old_linger() {
        let mut harness = Harness::new(8);
        harness.verdict(syn(7));
        harness.verdict(TestPacket::client(RST));
        harness.at(Duration::from_secs(1));
        assert_eq!(harness.verdict(syn(7)), INJECT);
        let counters = harness.counters();
        assert_eq!((counters.new_flows, counters.syn_retransmits), (2, 0));
        harness.at(LINGER + Duration::from_secs(1));
        assert_eq!(harness.verdict(TestPacket::client(ACK)), INJECT);
        let (verdict, packet) = harness.send(TestPacket::reply(ACK));
        assert_eq!(verdict, INJECT);
        assert_eq!(header(&packet).2, REMOTE_PORT);
    }

    #[test]
    fn a_tagged_packet_from_the_listener_port_takes_the_reply_path() {
        let from_listener = TestPacket {
            source_port: LISTENER.get(),
            tos: TAGGED,
            ..syn(7)
        };
        let mut harness = Harness::new(8);
        assert_eq!(harness.verdict(from_listener), DROP);
        assert_eq!(harness.counters().unknown_replies_dropped, 1);
        assert_eq!(harness.counters().new_flows, 0);
        harness.verdict(TestPacket {
            source_port: REMOTE_PORT,
            ..syn(7)
        });
        let (verdict, packet) = harness.send(from_listener);
        assert_eq!(verdict, INJECT);
        assert_eq!(
            header(&packet),
            (REMOTE, CLIENT, REMOTE_PORT, REMOTE_PORT, TAGGED)
        );
        let counters = harness.counters();
        assert_eq!((counters.replies_restored, counters.reflected), (1, 1));
    }

    #[test]
    fn listener_syn_ack_and_reset_are_translated_during_the_linger_without_extending_it() {
        let mut harness = Harness::new(8);
        harness.verdict(syn(7));
        harness.verdict(TestPacket::client(FIN | ACK));
        harness.verdict(TestPacket::reply(FIN | ACK));
        harness.at(LINGER - Duration::from_secs(2));
        assert_eq!(harness.verdict(TestPacket::reply(SYN | ACK)), INJECT);
        harness.at(LINGER - Duration::from_secs(1));
        assert_eq!(harness.verdict(TestPacket::reply(RST)), INJECT);
        harness.at(LINGER);
        assert_eq!(harness.verdict(TestPacket::reply(ACK)), DROP);
        assert_eq!(harness.verdict(TestPacket::client(ACK)), DROP);
        let counters = harness.counters();
        assert_eq!(counters.replies_restored, 3);
        assert_eq!(counters.unknown_replies_dropped, 1);
        assert_eq!(counters.orphans_dropped, 1);
    }

    #[test]
    fn a_non_syn_packet_of_an_unknown_flow_is_an_orphan() {
        let mut harness = Harness::new(8);
        for flags in [ACK, SYN | ACK, RST, FIN | ACK, 0] {
            assert_eq!(
                harness.verdict(TestPacket::client(flags)),
                DROP,
                "{flags:#x}"
            );
        }
        assert_eq!(
            harness.counters(),
            Counters {
                captured: 5,
                orphans_dropped: 5,
                ..Counters::default()
            }
        );
    }

    #[test]
    fn a_repeated_syn_is_a_retransmit_and_a_new_sequence_number_a_new_flow() {
        let mut harness = Harness::new(8);
        for sequence in [7, 7, 9, 9, 7] {
            assert_eq!(harness.verdict(syn(sequence)), INJECT, "{sequence}");
        }
        let counters = harness.counters();
        assert_eq!(counters.new_flows, 3);
        assert_eq!(counters.syn_retransmits, 2);
        assert_eq!(counters.reflected, 5);
    }

    #[test]
    fn flows_are_keyed_by_remote_address_and_local_port() {
        let mut harness = Harness::new(8);
        let other_remote = Ipv4Addr::new(192, 0, 2, 1);
        harness.verdict(syn(7));
        harness.verdict(TestPacket {
            destination: other_remote,
            ..to_port(OTHER_PORT, syn(7))
        });
        harness.verdict(TestPacket {
            source_port: LOCAL_PORT + 1,
            ..to_port(OTHER_PORT, syn(7))
        });
        assert_eq!(harness.counters().new_flows, 3);
        for (destination, port, original) in [
            (REMOTE, LOCAL_PORT, REMOTE_PORT),
            (other_remote, LOCAL_PORT, OTHER_PORT),
            (REMOTE, LOCAL_PORT + 1, OTHER_PORT),
        ] {
            let (verdict, packet) = harness.send(TestPacket {
                destination,
                destination_port: port,
                ..TestPacket::reply(ACK)
            });
            assert_eq!(verdict, INJECT);
            assert_eq!(header(&packet).2, original);
        }
    }

    #[test]
    fn another_remote_port_on_a_live_flow_is_a_key_collision() {
        let mut harness = Harness::new(8);
        harness.verdict(syn(7));
        assert_eq!(harness.verdict(to_port(OTHER_PORT, syn(9))), DROP);
        assert_eq!(
            harness.verdict(to_port(OTHER_PORT, TestPacket::client(ACK))),
            DROP
        );
        let (verdict, packet) = harness.send(TestPacket::reply(ACK));
        assert_eq!(verdict, INJECT);
        assert_eq!(header(&packet).2, REMOTE_PORT);
        let counters = harness.counters();
        assert_eq!(counters.key_collisions, 2);
        assert_eq!(counters.new_flows, 1);
    }

    #[test]
    fn a_syn_replaces_a_flow_ended_by_a_reset_or_by_fins_both_ways() {
        let client_reset = [TestPacket::client(RST | ACK)].to_vec();
        let listener_reset = [TestPacket::reply(RST)].to_vec();
        let fins = [TestPacket::client(FIN | ACK), TestPacket::reply(FIN | ACK)].to_vec();
        let fins_reversed = [TestPacket::reply(FIN | ACK), TestPacket::client(FIN | ACK)].to_vec();
        for (name, ending) in [
            ("client reset", client_reset),
            ("listener reset", listener_reset),
            ("fins", fins),
            ("fins reversed", fins_reversed),
        ] {
            let mut harness = Harness::new(8);
            harness.verdict(syn(7));
            for packet in ending {
                assert_eq!(harness.verdict(packet), INJECT, "{name}");
            }
            harness.at(Duration::from_secs(1));
            assert_eq!(
                harness.verdict(to_port(OTHER_PORT, syn(9))),
                INJECT,
                "{name}"
            );
            let (verdict, packet) = harness.send(TestPacket::reply(SYN | ACK));
            assert_eq!(verdict, INJECT, "{name}");
            assert_eq!(header(&packet).2, OTHER_PORT, "{name}");
            let counters = harness.counters();
            assert_eq!(counters.new_flows, 2, "{name}");
            assert_eq!(counters.key_collisions, 0, "{name}");
        }
    }

    #[test]
    fn a_fin_in_one_direction_does_not_end_a_flow() {
        for fin in [TestPacket::client(FIN | ACK), TestPacket::reply(FIN | ACK)] {
            let mut harness = Harness::new(8);
            harness.verdict(syn(7));
            harness.verdict(fin);
            harness.verdict(fin);
            assert_eq!(harness.verdict(to_port(OTHER_PORT, syn(9))), DROP);
            assert_eq!(harness.counters().key_collisions, 1);
        }
    }

    #[test]
    fn an_ended_flow_translates_its_last_packets_until_the_linger_is_over() {
        let mut harness = Harness::new(8);
        harness.verdict(syn(7));
        harness.at(Duration::from_secs(10));
        harness.verdict(TestPacket::client(FIN | ACK));
        harness.verdict(TestPacket::reply(FIN | ACK));
        harness.at(Duration::from_secs(10) + LINGER - Duration::from_secs(1));
        assert_eq!(harness.verdict(TestPacket::client(ACK)), INJECT);
        assert_eq!(harness.verdict(TestPacket::reply(ACK)), INJECT);
        harness.at(Duration::from_secs(10) + LINGER);
        assert_eq!(harness.verdict(TestPacket::client(ACK)), DROP);
        assert_eq!(harness.verdict(TestPacket::reply(ACK)), DROP);
        let counters = harness.counters();
        assert_eq!(counters.reflected, 3);
        assert_eq!(counters.replies_restored, 2);
        assert_eq!(counters.orphans_dropped, 1);
        assert_eq!(counters.unknown_replies_dropped, 1);
    }

    #[test]
    fn an_idle_flow_expires_and_activity_keeps_it_alive() {
        let mut harness = Harness::new(8);
        harness.verdict(syn(7));
        harness.at(IDLE - Duration::from_secs(1));
        assert_eq!(harness.verdict(TestPacket::reply(ACK)), INJECT);
        harness.at(2 * IDLE - Duration::from_secs(2));
        assert_eq!(harness.verdict(TestPacket::client(ACK)), INJECT);
        harness.at(3 * IDLE - Duration::from_secs(2));
        assert_eq!(harness.verdict(TestPacket::reply(ACK)), DROP);
        assert_eq!(harness.verdict(TestPacket::client(ACK)), DROP);
        assert_eq!(harness.verdict(to_port(OTHER_PORT, syn(9))), INJECT);
        let counters = harness.counters();
        assert_eq!(counters.unknown_replies_dropped, 1);
        assert_eq!(counters.orphans_dropped, 1);
        assert_eq!(counters.new_flows, 2);
        assert_eq!(counters.key_collisions, 0);
    }

    #[test]
    fn a_full_table_evicts_only_expired_or_lingered_flows() {
        let flow = |local_port: u16| TestPacket {
            source_port: local_port,
            ..syn(7)
        };
        let mut harness = Harness::new(2);
        harness.verdict(flow(1));
        harness.verdict(flow(2));
        assert_eq!(harness.verdict(flow(3)), DROP);
        harness.verdict(TestPacket {
            source_port: 1,
            ..TestPacket::client(RST)
        });
        assert_eq!(harness.verdict(flow(3)), DROP);
        harness.at(LINGER);
        assert_eq!(harness.verdict(flow(3)), INJECT);
        assert_eq!(harness.verdict(flow(4)), DROP);
        harness.at(IDLE);
        assert_eq!(harness.verdict(flow(4)), INJECT);
        assert_eq!(harness.verdict(flow(5)), DROP);
        let counters = harness.counters();
        assert_eq!(counters.table_full, 4);
        assert_eq!(counters.new_flows, 4);
    }

    #[test]
    fn a_full_table_is_swept_at_most_once_per_interval() {
        let flow = |local_port: u16| TestPacket {
            source_port: local_port,
            ..syn(7)
        };
        let half = SWEEP_INTERVAL / 2;
        let mut harness = Harness::new(1);
        harness.verdict(flow(1));
        harness.at(IDLE - half);
        assert_eq!(harness.verdict(flow(2)), DROP);
        harness.at(IDLE);
        assert_eq!(harness.verdict(flow(2)), DROP);
        harness.at(IDLE + half);
        assert_eq!(harness.verdict(flow(2)), INJECT);
        let counters = harness.counters();
        assert_eq!((counters.table_full, counters.new_flows), (2, 2));
        assert_eq!(SWEEP_INTERVAL, Duration::from_secs(1));
    }

    #[test]
    fn the_default_idle_timeout_is_two_hours_and_four_minutes() {
        assert_eq!(DEFAULT_IDLE_TIMEOUT, Duration::from_secs(7_440));
        assert_eq!(LINGER, Duration::from_secs(120));
    }
}
