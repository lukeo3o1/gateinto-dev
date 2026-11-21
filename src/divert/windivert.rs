use std::io;

use super::Direction;
use super::pump::RecvError;

const OUTBOUND_BIT: u32 = 17;
const IP_CHECKSUM_BIT: u32 = 21;
const TCP_CHECKSUM_BIT: u32 = 22;
const ERROR_NO_DATA: i32 = 232;

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct Address {
    timestamp: i64,
    bits: u32,
    reserved: u32,
    data: [u64; 8],
}

const _: () = assert!(size_of::<Address>() == 80);

impl Address {
    pub(super) const fn zeroed() -> Self {
        Self {
            timestamp: 0,
            bits: 0,
            reserved: 0,
            data: [0; 8],
        }
    }

    pub(super) fn direction(&self) -> Direction {
        match self.bits & 1 << OUTBOUND_BIT {
            0 => Direction::Inbound,
            _ => Direction::Outbound,
        }
    }

    pub(super) fn inbound(&self) -> Self {
        Self {
            bits: self.bits & !(1 << OUTBOUND_BIT) | 1 << IP_CHECKSUM_BIT | 1 << TCP_CHECKSUM_BIT,
            ..*self
        }
    }
}

pub(super) fn recv_error(error: io::Error) -> RecvError {
    match error.raw_os_error() {
        Some(ERROR_NO_DATA) => RecvError::Shutdown,
        _ => RecvError::Failed(error),
    }
}

pub(crate) struct PinnedFile {
    pub(crate) name: &'static str,
    pub(crate) sha256: [u8; 32],
}

const LIBRARY: &str = "WinDivert.dll";
const DRIVER_64: PinnedFile = PinnedFile {
    name: "WinDivert64.sys",
    sha256: sha256("8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2"),
};

pub(super) const X86_64: &[PinnedFile] = &[
    PinnedFile {
        name: LIBRARY,
        sha256: sha256("c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2"),
    },
    DRIVER_64,
];

pub(super) const X86: &[PinnedFile] = &[
    PinnedFile {
        name: LIBRARY,
        sha256: sha256("a321649090c21aaa7529ce5d019d242b1d5f2a2aff04bc3224db409641604a83"),
    },
    PinnedFile {
        name: "WinDivert32.sys",
        sha256: sha256("2f43f4251be4d72dd56c91bf6cce475d379eb9ba6c4dda2be3022ea633d5e807"),
    },
    DRIVER_64,
];

pub(crate) const FILES: &[PinnedFile] = if cfg!(target_arch = "x86_64") {
    X86_64
} else if cfg!(target_arch = "x86") {
    X86
} else {
    &[]
};

const fn sha256(hex: &str) -> [u8; 32] {
    let hex = hex.as_bytes();
    assert!(hex.len() == 64, "a SHA-256 digest has 64 hex digits");
    let mut digest = [0; 32];
    let mut at = 0;
    while at < 32 {
        digest[at] = nibble(hex[2 * at]) << 4 | nibble(hex[2 * at + 1]);
        at += 1;
    }
    digest
}

const fn nibble(digit: u8) -> u8 {
    match digit {
        b'0'..=b'9' => digit - b'0',
        b'a'..=b'f' => digit - b'a' + 10,
        _ => panic!("not a lowercase hex digit"),
    }
}

#[cfg(test)]
mod packaging;

#[cfg(test)]
mod tests {
    use std::io;
    use std::mem::{align_of, offset_of, size_of};

    use super::*;

    #[test]
    fn the_address_has_the_layout_of_windivert_address() {
        assert_eq!(size_of::<Address>(), 80);
        assert_eq!(align_of::<Address>(), 8);
        assert_eq!(offset_of!(Address, timestamp), 0);
        assert_eq!(offset_of!(Address, bits), 8);
        assert_eq!(offset_of!(Address, reserved), 12);
        assert_eq!(offset_of!(Address, data), 16);
    }

    fn with_bits(bits: u32) -> Address {
        Address {
            timestamp: -7,
            bits,
            reserved: 0x0102_0304,
            data: [0x1111_2222_3333_4444, 5, 6, 7, 8, 9, 10, u64::MAX],
        }
    }

    const OUTBOUND: u32 = 1 << 17;
    const IP_CHECKSUM: u32 = 1 << 21;
    const TCP_CHECKSUM: u32 = 1 << 22;

    #[test]
    fn the_direction_is_the_outbound_bit() {
        assert_eq!(with_bits(OUTBOUND).direction(), Direction::Outbound);
        assert_eq!(with_bits(u32::MAX).direction(), Direction::Outbound);
        assert_eq!(with_bits(0).direction(), Direction::Inbound);
        assert_eq!(with_bits(!OUTBOUND).direction(), Direction::Inbound);
        assert_eq!(Address::zeroed().direction(), Direction::Inbound);
    }

    #[test]
    fn an_inbound_copy_clears_outbound_and_claims_valid_ip_and_tcp_checksums() {
        for bits in [
            OUTBOUND,
            u32::MAX,
            0,
            0xAB | 0xCD << 8 | OUTBOUND | 1 << 18 | 1 << 20 | 1 << 23 | 0x5A << 24,
        ] {
            let received = with_bits(bits);
            let inbound = received.inbound();
            assert_eq!(
                inbound.bits,
                (bits & !OUTBOUND) | IP_CHECKSUM | TCP_CHECKSUM,
                "{bits:#x}"
            );
            assert_eq!(inbound.direction(), Direction::Inbound);
            assert_eq!(
                (inbound.timestamp, inbound.reserved, inbound.data),
                (received.timestamp, received.reserved, received.data)
            );
        }
    }

    #[test]
    fn a_zeroed_address_is_all_zero() {
        let zeroed = Address::zeroed();
        assert_eq!(
            (zeroed.timestamp, zeroed.bits, zeroed.reserved, zeroed.data),
            (0, 0, 0, [0; 8])
        );
    }

    #[test]
    fn no_data_after_a_shutdown_ends_the_loop_and_other_errors_fail() {
        assert!(matches!(
            recv_error(io::Error::from_raw_os_error(232)),
            RecvError::Shutdown
        ));
        for code in [5, 6, 122, 995] {
            let RecvError::Failed(error) = recv_error(io::Error::from_raw_os_error(code)) else {
                panic!("{code} ended the loop normally");
            };
            assert_eq!(error.raw_os_error(), Some(code));
        }
        assert!(matches!(
            recv_error(io::Error::other("no code")),
            RecvError::Failed(_)
        ));
    }

    #[test]
    fn a_digest_is_read_from_64_lowercase_hex_digits() {
        let mut expected = [0; 32];
        expected[0] = 0x01;
        expected[1] = 0xab;
        expected[31] = 0xf0;
        assert_eq!(
            sha256("01ab0000000000000000000000000000000000000000000000000000000000f0"),
            expected
        );
    }

    #[test]
    #[should_panic(expected = "not a lowercase hex digit")]
    fn a_digest_with_an_upper_case_digit_is_refused() {
        sha256("01AB0000000000000000000000000000000000000000000000000000000000f0");
    }

    #[test]
    #[should_panic(expected = "a SHA-256 digest has 64 hex digits")]
    fn a_digest_of_another_length_is_refused() {
        sha256("01ab");
    }

    fn named(files: &[PinnedFile]) -> Vec<(&str, [u8; 32])> {
        files.iter().map(|file| (file.name, file.sha256)).collect()
    }

    const DRIVER_64: &str = "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2";

    #[test]
    fn the_pinned_files_are_those_of_windivert_2_2_2_with_the_library_first() {
        assert_eq!(
            named(X86_64),
            [
                (
                    "WinDivert.dll",
                    sha256("c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2")
                ),
                ("WinDivert64.sys", sha256(DRIVER_64)),
            ]
        );
        assert_eq!(
            named(X86),
            [
                (
                    "WinDivert.dll",
                    sha256("a321649090c21aaa7529ce5d019d242b1d5f2a2aff04bc3224db409641604a83")
                ),
                (
                    "WinDivert32.sys",
                    sha256("2f43f4251be4d72dd56c91bf6cce475d379eb9ba6c4dda2be3022ea633d5e807")
                ),
                ("WinDivert64.sys", sha256(DRIVER_64)),
            ]
        );
        let expected: &[PinnedFile] = if cfg!(target_arch = "x86_64") {
            X86_64
        } else if cfg!(target_arch = "x86") {
            X86
        } else {
            &[]
        };
        assert_eq!(named(FILES), named(expected));
    }
}
