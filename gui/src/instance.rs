use std::time::Duration;

pub const ATTEMPTS: u32 = 10;
pub const PAUSE: Duration = Duration::from_millis(100);

pub fn mutex_name(sid: &str, demo: bool) -> String {
    let suffix = if demo { ".Demo" } else { "" };
    format!(r"Local\Gateinto.App.{sid}{suffix}")
}

pub fn descriptor(sid: &str) -> String {
    format!("O:{sid}D:P(A;;GA;;;{sid})")
}

pub fn running(owner: Option<&str>, sid: &str) -> bool {
    owner == Some(sid)
}

pub fn class(demo: bool) -> &'static str {
    if demo {
        "GateintoDemoWindow"
    } else {
        "GateintoWindow"
    }
}

pub fn approval_class(demo: bool) -> &'static str {
    if demo {
        "GateintoDemoApprovalWindow"
    } else {
        "GateintoApprovalWindow"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SID: &str = "S-1-5-21-1004336348-1177238915-682003330-1001";

    #[test]
    fn the_mutex_is_named_per_user_in_the_session_namespace() {
        assert_eq!(
            mutex_name(SID, false),
            r"Local\Gateinto.App.S-1-5-21-1004336348-1177238915-682003330-1001"
        );
        assert_ne!(
            mutex_name(SID, false),
            mutex_name("S-1-5-21-1-2-3-1002", false)
        );
    }

    #[test]
    fn the_demo_has_its_own_mutex() {
        assert_eq!(
            mutex_name(SID, true),
            r"Local\Gateinto.App.S-1-5-21-1004336348-1177238915-682003330-1001.Demo"
        );
    }

    #[test]
    fn the_mutex_is_owned_by_and_only_granted_to_the_user() {
        assert_eq!(descriptor(SID), format!("O:{SID}D:P(A;;GA;;;{SID})"));
    }

    #[test]
    fn only_a_mutex_owned_by_the_user_means_an_instance_is_running() {
        assert!(running(Some(SID), SID));
        assert!(!running(Some("S-1-5-21-1-2-3-1002"), SID));
        assert!(!running(None, SID));
    }

    #[test]
    fn the_demo_window_has_its_own_class() {
        assert_eq!(class(false), "GateintoWindow");
        assert_eq!(class(true), "GateintoDemoWindow");
    }

    #[test]
    fn the_approval_window_has_its_own_class_apart_from_the_main_window() {
        assert_eq!(approval_class(false), "GateintoApprovalWindow");
        assert_eq!(approval_class(true), "GateintoDemoApprovalWindow");
        for demo in [false, true] {
            for other in [false, true] {
                assert_ne!(approval_class(demo), class(other));
            }
        }
    }
}
