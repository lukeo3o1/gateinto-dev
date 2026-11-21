use std::net::Ipv4Addr;
use std::num::NonZeroU16;

use super::packet::{TCP, fill_checksums};

pub(super) const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
pub(super) const REMOTE: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);
pub(super) const LOCAL_PORT: u16 = 50_000;
pub(super) const REMOTE_PORT: u16 = 443;
pub(super) const LISTENER: NonZeroU16 = NonZeroU16::new(8443).unwrap();
pub(super) const TAGGED: u8 = 43 << 2;

#[derive(Debug, Clone, Copy)]
pub(super) struct TestPacket {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub source_port: u16,
    pub destination_port: u16,
    pub tos: u8,
    pub flags: u8,
    pub sequence: u32,
    pub protocol: u8,
    pub fragment: u16,
    pub ip_options: usize,
    pub tcp_options: usize,
    pub payload: usize,
}

impl TestPacket {
    pub fn client(flags: u8) -> Self {
        Self {
            source: CLIENT,
            destination: REMOTE,
            source_port: LOCAL_PORT,
            destination_port: REMOTE_PORT,
            tos: TAGGED,
            flags,
            sequence: 0x0102_0304,
            protocol: TCP,
            fragment: 0x4000,
            ip_options: 0,
            tcp_options: 0,
            payload: 0,
        }
    }

    pub fn reply(flags: u8) -> Self {
        Self {
            source: CLIENT,
            destination: REMOTE,
            source_port: LISTENER.get(),
            destination_port: LOCAL_PORT,
            tos: 0,
            ..Self::client(flags)
        }
    }

    pub fn build(&self) -> Vec<u8> {
        let ip_header = 20 + self.ip_options;
        let transport = if self.protocol == TCP {
            20 + self.tcp_options
        } else {
            8
        };
        let total = ip_header + transport + self.payload;
        let mut packet = vec![0; total];
        packet[0] = 0x40 | (ip_header / 4) as u8;
        packet[1] = self.tos;
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        packet[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        packet[6..8].copy_from_slice(&self.fragment.to_be_bytes());
        packet[8] = 128;
        packet[9] = self.protocol;
        packet[12..16].copy_from_slice(&self.source.octets());
        packet[16..20].copy_from_slice(&self.destination.octets());
        packet[20..ip_header].fill(1);
        let header = &mut packet[ip_header..];
        header[0..2].copy_from_slice(&self.source_port.to_be_bytes());
        header[2..4].copy_from_slice(&self.destination_port.to_be_bytes());
        if self.protocol == TCP {
            header[4..8].copy_from_slice(&self.sequence.to_be_bytes());
            header[12] = ((transport / 4) as u8) << 4;
            header[13] = self.flags;
            header[14..16].copy_from_slice(&0xFAF0u16.to_be_bytes());
            header[20..transport].fill(1);
        }
        for (index, byte) in header[transport..].iter_mut().enumerate() {
            *byte = b'a' + (index % 26) as u8;
        }
        if self.protocol == TCP {
            fill_checksums(&mut packet, ip_header, total);
        }
        packet
    }
}
