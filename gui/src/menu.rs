use std::borrow::Cow;

use gateinto::link::Known;

use crate::agent::AgentState;

use crate::gateways;
use crate::hit::Zone;
use crate::icons::{self, Icon};
use crate::layout::Rect;

pub const NO_GATEWAYS: &str = "No gateways";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Popup {
    Picker,
    Session(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Choice {
    Launch(usize),
    Portal(u64),
    Details,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub icon: Icon,
    pub label: Cow<'static, str>,
    pub choice: Option<Choice>,
}

pub fn picker(listing: &Result<Known, String>) -> Vec<Entry> {
    let entries: Vec<Entry> = listing.as_ref().map_or(Vec::new(), |known| {
        known
            .gateways
            .iter()
            .enumerate()
            .map(|(row, gateway)| Entry {
                icon: icons::GATEWAYS,
                label: gateways::label(gateway).into(),
                choice: Some(Choice::Launch(row)),
            })
            .collect()
    });
    if entries.is_empty() {
        return vec![Entry {
            icon: icons::GATEWAYS,
            label: NO_GATEWAYS.into(),
            choice: None,
        }];
    }
    entries
}

pub fn session(listing: &Result<Known, String>, state: &AgentState, id: u64) -> Vec<Entry> {
    let portal = portal(listing, state, id).map(|_| Entry {
        icon: icons::EXTERNAL,
        label: "Open portal page".into(),
        choice: Some(Choice::Portal(id)),
    });
    let details = Entry {
        icon: icons::GATEWAYS,
        label: "Gateway details".into(),
        choice: Some(Choice::Details),
    };
    portal.into_iter().chain([details]).collect()
}

pub fn portal<'a>(
    listing: &'a Result<Known, String>,
    state: &AgentState,
    id: u64,
) -> Option<&'a str> {
    let AgentState::Running(sessions) = state else {
        return None;
    };
    let session = sessions.iter().find(|session| session.id == id)?;
    listing
        .as_ref()
        .ok()?
        .gateways
        .iter()
        .find(|gateway| gateway.name.as_str() == session.gateway)?
        .portal_url
        .as_ref()
        .map(|url| url.as_str())
        .filter(|url| https(url))
}

pub fn https(url: &str) -> bool {
    const SCHEME: &str = "https://";
    url.len() > SCHEME.len()
        && url
            .get(..SCHEME.len())
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case(SCHEME))
}

pub fn dismisses(zone: Zone) -> bool {
    !matches!(zone, Zone::Entry(_) | Zone::Menu)
}

pub fn place(anchor: Rect, (w, h): (i32, i32), bounds: Rect, gap: i32) -> Rect {
    let x = (anchor.right() - w).min(bounds.right() - w).max(bounds.x);
    let below = anchor.bottom() + gap;
    let (under, over) = (bounds.bottom() - below, anchor.y - gap - bounds.y);
    if h > under && (h <= over || over > under) {
        let h = h.min(over);
        Rect::new(x, anchor.y - gap - h, w, h)
    } else {
        Rect::new(x, below, w, h.min(under))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wheel {
    Menu,
    Page,
}

pub fn wheel(open: bool, zone: Zone, in_content: bool) -> Option<Wheel> {
    if open {
        (!dismisses(zone)).then_some(Wheel::Menu)
    } else {
        in_content.then_some(Wheel::Page)
    }
}

#[cfg(test)]
mod tests {
    use gateinto::ipc::{SessionAuth, SessionInfo, SessionKind, SessionRoute};
    use gateinto::link::{KnownGateway, Source};

    use super::*;

    const PROFILE: &str = "g-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd";

    fn gateway(name: &str, host: &str) -> KnownGateway {
        KnownGateway {
            name: name.parse().unwrap(),
            host: Some(host.to_owned()),
            port: Some(443),
            portal_url: None,
            source: Source::Linked,
        }
    }

    fn known(gateways: Vec<KnownGateway>) -> Result<Known, String> {
        Ok(Known {
            gateways,
            ..Known::default()
        })
    }

    fn launch(label: &str, row: usize) -> Entry {
        Entry {
            icon: icons::GATEWAYS,
            label: label.to_owned().into(),
            choice: Some(Choice::Launch(row)),
        }
    }

    #[test]
    fn the_picker_lists_gateways_by_host_never_by_profile_hash() {
        let listing = known(vec![
            gateway("office", "proxy.example.com"),
            gateway(PROFILE, "edge.example.net"),
        ]);
        assert_eq!(
            picker(&listing),
            [launch("office", 0), launch("edge.example.net", 1)]
        );
    }

    #[test]
    fn without_gateways_the_picker_has_one_disabled_item() {
        let none = Entry {
            icon: icons::GATEWAYS,
            label: NO_GATEWAYS.into(),
            choice: None,
        };
        assert_eq!(picker(&known(vec![])), std::slice::from_ref(&none));
        assert_eq!(picker(&Err("broken".to_owned())), [none]);
    }

    fn session_info(id: u64, gateway: &str) -> SessionInfo {
        SessionInfo {
            id,
            kind: SessionKind::Browser,
            gateway: gateway.to_owned(),
            upstream: "proxy.example.com:443".to_owned(),
            listen: "127.0.0.1:8080".parse().unwrap(),
            route: SessionRoute::All,
            auth: SessionAuth::OsUser,
            started: 0,
            tunnels: 0,
            browser: None,
        }
    }

    fn with_portal(name: &str, portal: &str) -> KnownGateway {
        KnownGateway {
            portal_url: Some(portal.parse().unwrap()),
            ..gateway(name, "proxy.example.com")
        }
    }

    fn details() -> Entry {
        Entry {
            icon: icons::GATEWAYS,
            label: "Gateway details".into(),
            choice: Some(Choice::Details),
        }
    }

    fn running() -> AgentState {
        AgentState::Running(vec![session_info(3, "office"), session_info(4, "lab")])
    }

    #[test]
    fn a_session_menu_opens_its_gateway_portal_and_details() {
        let listing = known(vec![
            gateway("lab", "lab.example.com"),
            with_portal("office", "https://portal.example.com/start"),
        ]);
        let portal = Entry {
            icon: icons::EXTERNAL,
            label: "Open portal page".into(),
            choice: Some(Choice::Portal(3)),
        };
        assert_eq!(session(&listing, &running(), 3), [portal, details()]);
        assert_eq!(
            super::portal(&listing, &running(), 3),
            Some("https://portal.example.com/start")
        );
    }

    #[test]
    fn without_a_known_portal_the_session_menu_only_has_details() {
        let listing = known(vec![gateway("lab", "lab.example.com")]);
        assert_eq!(session(&listing, &running(), 4), [details()]);
        assert_eq!(super::portal(&listing, &running(), 4), None);
        let elsewhere = known(vec![with_portal("lab", "https://lab.example.com/")]);
        assert_eq!(super::portal(&elsewhere, &running(), 3), None);
        assert_eq!(super::portal(&elsewhere, &running(), 9), None);
        assert_eq!(super::portal(&elsewhere, &AgentState::Stopped, 4), None);
        assert_eq!(
            session(&Err("broken".to_owned()), &running(), 4),
            [details()]
        );
    }

    #[test]
    fn only_https_addresses_count_as_portals() {
        assert!(https("https://portal.example.com/"));
        assert!(https("HTTPS://portal.example.com/"));
        for url in [
            "http://portal.example.com/",
            "file:///C:/Windows/notepad.exe",
            "javascript:alert(1)",
            "C:\\Windows\\notepad.exe",
            "https:",
            "",
        ] {
            assert!(!https(url), "{url}");
        }
    }

    #[test]
    fn clicks_outside_the_menu_dismiss_it() {
        assert!(!dismisses(Zone::Entry(0)));
        assert!(!dismisses(Zone::Menu));
        for zone in [
            Zone::Client,
            Zone::Picker,
            Zone::StopAgent,
            Zone::Revoke(1),
            Zone::More(1),
            Zone::Nav(crate::nav::Page::Gateways),
        ] {
            assert!(dismisses(zone), "{zone:?}");
        }
    }

    const BOUNDS: Rect = Rect::new(0, 0, 1040, 680);

    #[test]
    fn a_menu_hangs_under_its_anchor_right_aligned() {
        let anchor = Rect::new(711, 110, 143, 32);
        assert_eq!(
            place(anchor, (200, 76), BOUNDS, 6),
            Rect::new(654, 148, 200, 76)
        );
    }

    #[test]
    fn a_menu_flips_above_when_it_would_leave_the_window() {
        let anchor = Rect::new(964, 600, 32, 32);
        assert_eq!(
            place(anchor, (200, 110), BOUNDS, 6),
            Rect::new(796, 484, 200, 110)
        );
    }

    #[test]
    fn a_tall_menu_is_clamped_to_the_roomier_side() {
        let anchor = Rect::new(711, 110, 143, 32);
        assert_eq!(
            place(anchor, (200, 800), BOUNDS, 6),
            Rect::new(654, 148, 200, 532)
        );
        let anchor = Rect::new(964, 600, 32, 32);
        assert_eq!(
            place(anchor, (200, 800), BOUNDS, 6),
            Rect::new(796, 0, 200, 594)
        );
    }

    #[test]
    fn the_wheel_scrolls_an_open_menu_and_never_the_page_under_it() {
        assert_eq!(wheel(true, Zone::Entry(2), true), Some(Wheel::Menu));
        assert_eq!(wheel(true, Zone::Menu, true), Some(Wheel::Menu));
        assert_eq!(wheel(true, Zone::Revoke(1), true), None);
        assert_eq!(wheel(true, Zone::Client, false), None);
        assert_eq!(wheel(false, Zone::Revoke(1), true), Some(Wheel::Page));
        assert_eq!(wheel(false, Zone::Caption, false), None);
    }

    #[test]
    fn a_menu_stays_inside_the_window_horizontally() {
        let anchor = Rect::new(10, 100, 32, 32);
        assert_eq!(
            place(anchor, (200, 76), BOUNDS, 6),
            Rect::new(0, 138, 200, 76)
        );
    }
}
