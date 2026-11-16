use std::error::Error;
use std::fmt;

mod engine;
mod flows;
mod packet;
#[cfg(test)]
mod testing;

pub use engine::{Counters, Direction, Engine, Verdict};
pub use flows::{DEFAULT_IDLE_TIMEOUT, LINGER};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Dscp(u8);

impl Dscp {
    pub const DEFAULT: Self = Self(43);

    pub fn new(value: u8) -> Result<Self, InvalidDscp> {
        match value {
            1..=63 => Ok(Self(value)),
            _ => Err(InvalidDscp),
        }
    }

    pub fn value(self) -> u8 {
        self.0
    }
}

impl Default for Dscp {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl fmt::Display for Dscp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidDscp;

impl fmt::Display for InvalidDscp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a DSCP value must be between 1 and 63")
    }
}

impl Error for InvalidDscp {}

pub fn filter(listener_port: u16, dscp: Dscp) -> String {
    let low = u16::from(dscp.0) << 2;
    let high = low + 3;
    let port = listener_port;
    format!(
        "(outbound and !loopback and ((ip and ((ip.TOS >= {low} and ip.TOS <= {high}) \
         or (tcp and tcp.SrcPort == {port}))) or (ipv6 and ipv6.TrafficClass >= {low} \
         and ipv6.TrafficClass <= {high}))) or (inbound and !loopback and tcp and \
         tcp.DstPort == {port})"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dscp_is_one_to_sixty_three_and_defaults_to_forty_three() {
        for value in [1, 43, 63] {
            assert_eq!(Dscp::new(value).unwrap().value(), value);
        }
        for value in [0, 64, 255] {
            assert_eq!(Dscp::new(value), Err(InvalidDscp), "{value}");
        }
        assert_eq!(Dscp::default(), Dscp::new(43).unwrap());
        assert_eq!(Dscp::DEFAULT.to_string(), "43");
        assert_eq!(
            InvalidDscp.to_string(),
            "a DSCP value must be between 1 and 63"
        );
    }

    #[test]
    fn the_filter_captures_the_tagged_packets_and_the_listener_traffic() {
        assert_eq!(
            filter(8443, Dscp::DEFAULT),
            "(outbound and !loopback and ((ip and ((ip.TOS >= 172 and ip.TOS <= 175) \
             or (tcp and tcp.SrcPort == 8443))) or (ipv6 and ipv6.TrafficClass >= 172 \
             and ipv6.TrafficClass <= 175))) or (inbound and !loopback and tcp and \
             tcp.DstPort == 8443)"
        );
    }

    #[test]
    fn the_filter_matches_every_ecn_value_of_the_lowest_and_highest_dscp() {
        for (dscp, low, high) in [(1, 4, 7), (63, 252, 255)] {
            let filter = filter(1, Dscp::new(dscp).unwrap());
            assert!(
                filter.contains(&format!("(ip.TOS >= {low} and ip.TOS <= {high})")),
                "{filter}"
            );
            assert!(
                filter.contains(&format!(
                    "ipv6.TrafficClass >= {low} and ipv6.TrafficClass <= {high}"
                )),
                "{filter}"
            );
        }
    }
}
