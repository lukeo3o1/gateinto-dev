use std::net::Ipv4Addr;

pub(super) const TCP: u8 = 6;
pub(super) const UDP: u8 = 17;
pub(super) const FIN: u8 = 0x01;
pub(super) const SYN: u8 = 0x02;
pub(super) const RST: u8 = 0x04;
pub(super) const ACK: u8 = 0x10;
pub(super) const ECN: u8 = 0x03;
pub(super) const IP_HEADER: usize = 20;

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[derive(Clone, Copy)]
pub(super) enum Packet {
    Tcp(Segment),
    Udp,
    Other,
    Ipv6,
    Fragment,
    Options,
    Malformed,
}

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[derive(Clone, Copy)]
pub(super) struct Segment {
    total: usize,
    pub(super) source: Ipv4Addr,
    pub(super) destination: Ipv4Addr,
    pub(super) source_port: u16,
    pub(super) destination_port: u16,
    pub(super) flags: u8,
    pub(super) sequence: u32,
}

impl Segment {
    pub(super) fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }

    pub(super) fn is_pure_syn(&self) -> bool {
        self.flags & (SYN | ACK | RST | FIN) == SYN
    }
}

pub(super) fn parse(bytes: &[u8]) -> Packet {
    match bytes.first().map(|byte| byte >> 4) {
        Some(4) => parse_ipv4(bytes).unwrap_or(Packet::Malformed),
        Some(6) => Packet::Ipv6,
        _ => Packet::Malformed,
    }
}

fn parse_ipv4(bytes: &[u8]) -> Option<Packet> {
    let header = bytes.get(..IP_HEADER)?;
    let ip_header = usize::from(header[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([header[2], header[3]]));
    if ip_header < IP_HEADER || total < ip_header || total > bytes.len() {
        return None;
    }
    match header[9] {
        TCP => {}
        UDP => return Some(Packet::Udp),
        _ => return Some(Packet::Other),
    }
    if u16::from_be_bytes([header[6], header[7]]) & 0x3fff != 0 {
        return Some(Packet::Fragment);
    }
    if ip_header != IP_HEADER {
        return Some(Packet::Options);
    }
    let tcp = bytes.get(IP_HEADER..total)?.get(..20)?;
    let data_offset = usize::from(tcp[12] >> 4) * 4;
    if data_offset < 20 || IP_HEADER + data_offset > total {
        return None;
    }
    Some(Packet::Tcp(Segment {
        total,
        source: address(&header[12..16]),
        destination: address(&header[16..20]),
        source_port: u16::from_be_bytes([tcp[0], tcp[1]]),
        destination_port: u16::from_be_bytes([tcp[2], tcp[3]]),
        flags: tcp[13],
        sequence: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
    }))
}

fn address(octets: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3])
}

pub(super) fn reflect(packet: &mut [u8], segment: &Segment, listener_port: u16) {
    swap_addresses(packet, segment);
    packet[IP_HEADER + 2..IP_HEADER + 4].copy_from_slice(&listener_port.to_be_bytes());
    packet[1] &= ECN;
    fill_checksums(packet, IP_HEADER, segment.total);
}

pub(super) fn restore(packet: &mut [u8], segment: &Segment, remote_port: u16) {
    swap_addresses(packet, segment);
    packet[IP_HEADER..IP_HEADER + 2].copy_from_slice(&remote_port.to_be_bytes());
    fill_checksums(packet, IP_HEADER, segment.total);
}

fn swap_addresses(packet: &mut [u8], segment: &Segment) {
    packet[12..16].copy_from_slice(&segment.destination.octets());
    packet[16..20].copy_from_slice(&segment.source.octets());
}

pub(super) fn fill_checksums(packet: &mut [u8], ip_header: usize, total: usize) {
    packet[10..12].fill(0);
    let header = checksum(&packet[..ip_header], 0);
    packet[10..12].copy_from_slice(&header.to_be_bytes());
    let tcp = ip_header + 16..ip_header + 18;
    packet[tcp.clone()].fill(0);
    let segment = checksum(
        &packet[ip_header..total],
        pseudo_header(packet, ip_header, total),
    );
    packet[tcp].copy_from_slice(&segment.to_be_bytes());
}

fn pseudo_header(packet: &[u8], ip_header: usize, total: usize) -> u64 {
    sum(&packet[12..20]) + u64::from(TCP) + (total - ip_header) as u64
}

fn sum(data: &[u8]) -> u64 {
    let (pairs, rest) = data.as_chunks::<2>();
    let odd = rest.first().map_or(0, |&byte| u64::from(byte) << 8);
    pairs
        .iter()
        .map(|&pair| u64::from(u16::from_be_bytes(pair)))
        .sum::<u64>()
        + odd
}

fn checksum(data: &[u8], initial: u64) -> u16 {
    let mut total = initial + sum(data);
    while total > 0xffff {
        total = (total & 0xffff) + (total >> 16);
    }
    !(total as u16)
}

#[cfg(any(test, fuzzing))]
pub(super) fn checksums_valid(packet: &[u8]) -> bool {
    let Packet::Tcp(segment) = parse(packet) else {
        return false;
    };
    let tcp = &packet[IP_HEADER..segment.total];
    checksum(&packet[..IP_HEADER], 0) == 0
        && checksum(tcp, pseudo_header(packet, IP_HEADER, segment.total)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::divert::testing::{
        CLIENT, LISTENER, LOCAL_PORT, REMOTE, REMOTE_PORT, TAGGED, TestPacket,
    };

    fn segment(packet: &[u8]) -> Segment {
        match parse(packet) {
            Packet::Tcp(segment) => segment,
            other => panic!("not a TCP segment: {other:?}"),
        }
    }

    fn ports(packet: &[u8]) -> (u16, u16) {
        let tcp = &packet[IP_HEADER..];
        (
            u16::from_be_bytes([tcp[0], tcp[1]]),
            u16::from_be_bytes([tcp[2], tcp[3]]),
        )
    }

    fn addresses(packet: &[u8]) -> (Ipv4Addr, Ipv4Addr) {
        let octets = |at: usize| Ipv4Addr::from(<[u8; 4]>::try_from(&packet[at..at + 4]).unwrap());
        (octets(12), octets(16))
    }

    const ODD_PAYLOAD: [u8; 43] = [
        0x45, 0x00, 0x00, 0x2b, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x32, 0x35, 0xc0, 0x00, 0x02,
        0x0a, 0xc6, 0x33, 0x64, 0x14, 0xc0, 0x00, 0x01, 0xbb, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x77, 0x88, 0x50, 0x18, 0x01, 0xf6, 0x2a, 0x0e, 0x00, 0x00, 0x61, 0x62, 0x63,
    ];
    const EVEN_PAYLOAD_WITH_OPTIONS: [u8; 58] = [
        0x45, 0x00, 0x00, 0x3a, 0x00, 0x01, 0x40, 0x00, 0x80, 0x06, 0x0e, 0x6b, 0xc0, 0x00, 0x02,
        0x0a, 0xc6, 0x33, 0x64, 0x14, 0xc0, 0x01, 0x00, 0x50, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00,
        0x00, 0x00, 0x80, 0x02, 0xfa, 0xf0, 0xe5, 0xe4, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01,
        0x03, 0x03, 0x08, 0x01, 0x01, 0x04, 0x02, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x21,
    ];
    const ODD_PAYLOAD_WITH_OPTIONS_AND_ECN: [u8; 61] = [
        0x45, 0xae, 0x00, 0x3d, 0xbe, 0xef, 0x00, 0x00, 0x39, 0x06, 0xd5, 0xcb, 0xc6, 0x33, 0x64,
        0x14, 0xc0, 0x00, 0x02, 0x0a, 0x01, 0xbb, 0xc0, 0x00, 0x01, 0x02, 0x03, 0x04, 0xa0, 0xb0,
        0xc0, 0xd0, 0x80, 0x10, 0x04, 0x00, 0xa4, 0x77, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x47, 0x61, 0x74, 0x65, 0x69, 0x6e, 0x74, 0x6f,
        0x21,
    ];

    #[test]
    fn checksums_match_independently_computed_packets() {
        for (name, expected) in [
            ("odd payload", &ODD_PAYLOAD[..]),
            ("even payload with options", &EVEN_PAYLOAD_WITH_OPTIONS[..]),
            (
                "odd payload with options",
                &ODD_PAYLOAD_WITH_OPTIONS_AND_ECN[..],
            ),
        ] {
            let mut packet = expected.to_vec();
            packet[10..12].fill(0);
            packet[IP_HEADER + 16..IP_HEADER + 18].fill(0);
            fill_checksums(&mut packet, IP_HEADER, expected.len());
            assert_eq!(packet, expected, "{name}");
            assert!(checksums_valid(expected), "{name}");
        }
    }

    #[test]
    fn the_header_checksum_matches_a_known_ipv4_header() {
        let header = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(checksum(&header, 0), 0xb861);
    }

    #[test]
    fn a_tcp_segment_with_options_is_parsed() {
        let packet = TestPacket {
            tcp_options: 12,
            payload: 5,
            flags: SYN | ACK,
            ..TestPacket::client(0)
        }
        .build();
        let parsed = segment(&packet);
        assert_eq!(parsed.total, packet.len());
        assert_eq!(parsed.source, CLIENT);
        assert_eq!(parsed.destination, REMOTE);
        assert_eq!(parsed.source_port, LOCAL_PORT);
        assert_eq!(parsed.destination_port, REMOTE_PORT);
        assert_eq!(parsed.flags, SYN | ACK);
        assert_eq!(parsed.sequence, 0x0102_0304);
        assert!(checksums_valid(&packet));
    }

    #[test]
    fn a_tcp_packet_with_ipv4_options_is_refused_and_other_kinds_are_kept() {
        let with_options = |ip_options: usize, packet: TestPacket| {
            TestPacket {
                ip_options,
                ..packet
            }
            .build()
        };
        for (name, packet, expected) in [
            (
                "tcp, 4 bytes",
                with_options(4, TestPacket::client(SYN)),
                Packet::Options,
            ),
            (
                "tcp, 40 bytes",
                with_options(40, TestPacket::reply(ACK)),
                Packet::Options,
            ),
            (
                "udp",
                with_options(
                    8,
                    TestPacket {
                        protocol: UDP,
                        ..TestPacket::client(0)
                    },
                ),
                Packet::Udp,
            ),
            (
                "icmp",
                with_options(
                    8,
                    TestPacket {
                        protocol: 1,
                        ..TestPacket::client(0)
                    },
                ),
                Packet::Other,
            ),
            (
                "fragment",
                with_options(
                    8,
                    TestPacket {
                        fragment: 0x2000,
                        ..TestPacket::client(SYN)
                    },
                ),
                Packet::Fragment,
            ),
        ] {
            assert_eq!(parse(&packet), expected, "{name}");
        }
    }

    #[test]
    fn bytes_after_the_total_length_are_not_part_of_the_segment() {
        let mut packet = TestPacket::client(SYN).build();
        let total = packet.len();
        packet.extend_from_slice(&[0xff; 3]);
        assert_eq!(segment(&packet).total, total);
        assert!(checksums_valid(&packet));
    }

    #[test]
    fn only_a_pure_syn_is_a_pure_syn() {
        for (flags, pure) in [
            (SYN, true),
            (SYN | 0x08, true),
            (SYN | ACK, false),
            (SYN | RST, false),
            (SYN | FIN, false),
            (ACK, false),
        ] {
            let packet = TestPacket::client(flags).build();
            assert_eq!(segment(&packet).is_pure_syn(), pure, "{flags:#x}");
        }
    }

    #[test]
    fn malformed_headers_are_refused() {
        let valid = TestPacket::client(SYN).build();
        let changed = |at: usize, value: u8| {
            let mut packet = valid.clone();
            packet[at] = value;
            packet
        };
        let mut short_total = valid.clone();
        short_total[2..4].copy_from_slice(&39u16.to_be_bytes());
        let mut tiny_total = valid.clone();
        tiny_total[2..4].copy_from_slice(&19u16.to_be_bytes());
        let mut long_total = valid.clone();
        long_total[2..4].copy_from_slice(&41u16.to_be_bytes());
        for (name, packet) in [
            ("empty", Vec::new()),
            ("short header", valid[..19].to_vec()),
            ("version 5", changed(0, 0x55)),
            ("version 0", changed(0, 0x05)),
            ("ihl below 5", changed(0, 0x44)),
            ("ihl beyond the packet", changed(0, 0x4f)),
            ("total length below the tcp header", short_total),
            ("total length below the ip header", tiny_total),
            ("total length beyond the packet", long_total),
            ("tcp data offset below 5", changed(32, 0x40)),
            ("tcp data offset beyond the total length", changed(32, 0x60)),
        ] {
            assert_eq!(parse(&packet), Packet::Malformed, "{name}");
        }
    }

    #[test]
    fn every_strict_prefix_of_a_segment_is_malformed() {
        let packet = TestPacket {
            ip_options: 4,
            tcp_options: 4,
            payload: 3,
            ..TestPacket::client(SYN)
        }
        .build();
        for length in 0..packet.len() {
            assert_eq!(parse(&packet[..length]), Packet::Malformed, "{length}");
        }
    }

    #[test]
    fn fragments_are_recognised_and_dont_fragment_is_not_one() {
        for (fragment, expected) in [
            (0x2000, Packet::Fragment),
            (0x0001, Packet::Fragment),
            (0x4001, Packet::Fragment),
            (0x1fff, Packet::Fragment),
        ] {
            let packet = TestPacket {
                fragment,
                ..TestPacket::client(SYN)
            }
            .build();
            assert_eq!(parse(&packet), expected, "{fragment:#x}");
        }
        for fragment in [0x0000, 0x4000, 0x8000] {
            let packet = TestPacket {
                fragment,
                ..TestPacket::client(SYN)
            }
            .build();
            assert!(matches!(parse(&packet), Packet::Tcp(_)), "{fragment:#x}");
        }
    }

    #[test]
    fn other_protocols_and_ipv6_are_told_apart() {
        for (protocol, expected) in [(UDP, Packet::Udp), (1, Packet::Other), (47, Packet::Other)] {
            let packet = TestPacket {
                protocol,
                ..TestPacket::client(0)
            }
            .build();
            assert_eq!(parse(&packet), expected, "{protocol}");
        }
        let mut ipv6 = vec![0; 60];
        ipv6[0] = 0x60 | (TAGGED >> 4);
        ipv6[6] = TCP;
        assert_eq!(parse(&ipv6), Packet::Ipv6);
    }

    #[test]
    fn reflecting_turns_a_client_packet_into_a_valid_one_to_the_listener() {
        for (tcp_options, payload, tos) in [
            (0, 0, TAGGED),
            (0, 1, TAGGED | 0x01),
            (4, 7, TAGGED | 0x02),
            (12, 100, TAGGED | 0x03),
            (40, 1_301, 0xff),
        ] {
            let mut packet = TestPacket {
                tcp_options,
                payload,
                tos,
                ..TestPacket::client(ACK)
            }
            .build();
            let original = packet.clone();
            packet[10..12].copy_from_slice(&[0xde, 0xad]);
            packet[IP_HEADER + 16..IP_HEADER + 18].copy_from_slice(&[0xbe, 0xef]);
            let parsed = segment(&packet);
            reflect(&mut packet, &parsed, LISTENER.get());
            let case = (tcp_options, payload, tos);
            assert!(checksums_valid(&packet), "{case:?}");
            assert_eq!(packet[1], tos & 0x03, "{case:?}");
            assert_eq!(addresses(&packet), (REMOTE, CLIENT), "{case:?}");
            assert_eq!(ports(&packet), (LOCAL_PORT, LISTENER.get()), "{case:?}");
            assert_eq!(
                packet[IP_HEADER + 4..IP_HEADER + 16],
                original[IP_HEADER + 4..IP_HEADER + 16],
                "{case:?}"
            );
            assert_eq!(
                packet[IP_HEADER + 18..],
                original[IP_HEADER + 18..],
                "{case:?}"
            );
        }
    }

    #[test]
    fn restoring_turns_a_listener_reply_into_a_valid_one_from_the_remote() {
        for (tcp_options, payload) in [(0, 0), (4, 1), (0, 33)] {
            let mut packet = TestPacket {
                tcp_options,
                payload,
                tos: 0x02,
                ..TestPacket::reply(SYN | ACK)
            }
            .build();
            packet[10..12].copy_from_slice(&[0, 0]);
            packet[IP_HEADER + 16..IP_HEADER + 18].copy_from_slice(&[0, 0]);
            let parsed = segment(&packet);
            restore(&mut packet, &parsed, REMOTE_PORT);
            let case = (tcp_options, payload);
            assert!(checksums_valid(&packet), "{case:?}");
            assert_eq!(packet[1], 0x02, "{case:?}");
            assert_eq!(addresses(&packet), (REMOTE, CLIENT), "{case:?}");
            assert_eq!(ports(&packet), (REMOTE_PORT, LOCAL_PORT), "{case:?}");
        }
    }

    #[test]
    fn a_changed_byte_breaks_the_checksums() {
        let packet = TestPacket {
            payload: 3,
            ..TestPacket::client(ACK)
        }
        .build();
        assert!(checksums_valid(&packet));
        for at in [1, 15, 21, 42] {
            let mut changed = packet.clone();
            changed[at] ^= 0x10;
            assert!(!checksums_valid(&changed), "{at}");
        }
    }
}
