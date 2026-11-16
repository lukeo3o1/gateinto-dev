use std::net::Ipv4Addr;

pub(super) const TCP: u8 = 6;
pub(super) const UDP: u8 = 17;
pub(super) const FIN: u8 = 0x01;
pub(super) const SYN: u8 = 0x02;
pub(super) const RST: u8 = 0x04;
pub(super) const ACK: u8 = 0x10;
const ECN: u8 = 0x03;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Packet {
    Tcp(Segment),
    Udp,
    Other,
    Ipv6,
    Fragment,
    Malformed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Segment {
    ip_header: usize,
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
    let header = bytes.get(..20)?;
    let ip_header = usize::from(header[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([header[2], header[3]]));
    if ip_header < 20 || total < ip_header || total > bytes.len() {
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
    let tcp = bytes.get(ip_header..total)?.get(..20)?;
    let data_offset = usize::from(tcp[12] >> 4) * 4;
    if data_offset < 20 || ip_header + data_offset > total {
        return None;
    }
    Some(Packet::Tcp(Segment {
        ip_header,
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
    let tcp = segment.ip_header;
    packet[tcp + 2..tcp + 4].copy_from_slice(&listener_port.to_be_bytes());
    packet[1] &= ECN;
    fill_checksums(packet, segment.ip_header, segment.total);
}

pub(super) fn restore(packet: &mut [u8], segment: &Segment, remote_port: u16) {
    swap_addresses(packet, segment);
    let tcp = segment.ip_header;
    packet[tcp..tcp + 2].copy_from_slice(&remote_port.to_be_bytes());
    fill_checksums(packet, segment.ip_header, segment.total);
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
    let chunks = data.chunks_exact(2);
    let odd = chunks
        .remainder()
        .first()
        .map_or(0, |&byte| u64::from(byte) << 8);
    chunks
        .map(|pair| u64::from(u16::from_be_bytes([pair[0], pair[1]])))
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

#[cfg(test)]
pub(super) fn checksums_valid(packet: &[u8]) -> bool {
    let Packet::Tcp(segment) = parse(packet) else {
        return false;
    };
    let tcp = &packet[segment.ip_header..segment.total];
    checksum(&packet[..segment.ip_header], 0) == 0
        && checksum(tcp, pseudo_header(packet, segment.ip_header, segment.total)) == 0
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

    fn ports(packet: &[u8], ip_header: usize) -> (u16, u16) {
        let tcp = &packet[ip_header..];
        (
            u16::from_be_bytes([tcp[0], tcp[1]]),
            u16::from_be_bytes([tcp[2], tcp[3]]),
        )
    }

    fn addresses(packet: &[u8]) -> (Ipv4Addr, Ipv4Addr) {
        let octets = |at: usize| Ipv4Addr::from(<[u8; 4]>::try_from(&packet[at..at + 4]).unwrap());
        (octets(12), octets(16))
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
            ip_options: 8,
            tcp_options: 12,
            payload: 5,
            flags: SYN | ACK,
            ..TestPacket::client(0)
        }
        .build();
        let parsed = segment(&packet);
        assert_eq!(parsed.ip_header, 28);
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
        for (ip_options, tcp_options, payload, tos) in [
            (0, 0, 0, TAGGED),
            (0, 0, 1, TAGGED | 0x01),
            (4, 0, 7, TAGGED | 0x02),
            (0, 12, 100, TAGGED | 0x03),
            (40, 40, 1_301, 0xff),
        ] {
            let mut packet = TestPacket {
                ip_options,
                tcp_options,
                payload,
                tos,
                ..TestPacket::client(ACK)
            }
            .build();
            let original = packet.clone();
            let ip_header = 20 + ip_options;
            packet[10..12].copy_from_slice(&[0xde, 0xad]);
            packet[ip_header + 16..ip_header + 18].copy_from_slice(&[0xbe, 0xef]);
            let parsed = segment(&packet);
            reflect(&mut packet, &parsed, LISTENER);
            let case = (ip_options, tcp_options, payload, tos);
            assert!(checksums_valid(&packet), "{case:?}");
            assert_eq!(packet[1], tos & 0x03, "{case:?}");
            assert_eq!(addresses(&packet), (REMOTE, CLIENT), "{case:?}");
            assert_eq!(
                ports(&packet, ip_header),
                (LOCAL_PORT, LISTENER),
                "{case:?}"
            );
            assert_eq!(
                packet[ip_header + 4..ip_header + 16],
                original[ip_header + 4..ip_header + 16],
                "{case:?}"
            );
            assert_eq!(
                packet[ip_header + 18..],
                original[ip_header + 18..],
                "{case:?}"
            );
        }
    }

    #[test]
    fn restoring_turns_a_listener_reply_into_a_valid_one_from_the_remote() {
        for (ip_options, tcp_options, payload) in [(0, 0, 0), (0, 4, 1), (8, 0, 33)] {
            let mut packet = TestPacket {
                ip_options,
                tcp_options,
                payload,
                tos: 0x02,
                ..TestPacket::reply(SYN | ACK)
            }
            .build();
            let ip_header = 20 + ip_options;
            packet[10..12].copy_from_slice(&[0, 0]);
            packet[ip_header + 16..ip_header + 18].copy_from_slice(&[0, 0]);
            let parsed = segment(&packet);
            restore(&mut packet, &parsed, REMOTE_PORT);
            let case = (ip_options, tcp_options, payload);
            assert!(checksums_valid(&packet), "{case:?}");
            assert_eq!(packet[1], 0x02, "{case:?}");
            assert_eq!(addresses(&packet), (REMOTE, CLIENT), "{case:?}");
            assert_eq!(
                ports(&packet, ip_header),
                (REMOTE_PORT, LOCAL_PORT),
                "{case:?}"
            );
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
