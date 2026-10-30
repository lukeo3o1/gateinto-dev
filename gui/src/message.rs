pub const APP: u32 = 0x8000;
pub const AGENT: u32 = APP;
pub const TRAY: u32 = APP + 1;
pub const REVEAL: u32 = APP + 2;
pub const EXIT: u32 = APP + 3;

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [u32; 4] = [AGENT, TRAY, REVEAL, EXIT];

    #[test]
    fn app_messages_are_pairwise_distinct() {
        for (i, a) in ALL.iter().enumerate() {
            for b in &ALL[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn app_messages_stay_in_the_application_range() {
        for message in ALL {
            assert!((0x8000..0xC000).contains(&message), "{message:#x}");
        }
    }
}
