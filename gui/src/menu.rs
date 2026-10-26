use std::borrow::Cow;

use gateinto::link::Known;

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

pub fn session() -> Vec<Entry> {
    vec![Entry {
        icon: icons::GATEWAYS,
        label: "Gateway details".into(),
        choice: Some(Choice::Details),
    }]
}

pub fn dismisses(zone: Zone) -> bool {
    !matches!(zone, Zone::Entry(_) | Zone::Menu)
}

pub fn place(anchor: Rect, (w, h): (i32, i32), bounds: Rect, gap: i32) -> Rect {
    let x = (anchor.right() - w).min(bounds.right() - w).max(bounds.x);
    let below = anchor.bottom() + gap;
    let y = if below + h > bounds.bottom() && anchor.y - gap - h >= bounds.y {
        anchor.y - gap - h
    } else {
        below
    };
    Rect::new(x, y, w, h)
}

#[cfg(test)]
mod tests {
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

    #[test]
    fn a_session_menu_leads_to_the_gateway_details() {
        assert_eq!(
            session(),
            [Entry {
                icon: icons::GATEWAYS,
                label: "Gateway details".into(),
                choice: Some(Choice::Details),
            }]
        );
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
    fn a_menu_stays_inside_the_window_horizontally() {
        let anchor = Rect::new(10, 100, 32, 32);
        assert_eq!(
            place(anchor, (200, 76), BOUNDS, 6),
            Rect::new(0, 138, 200, 76)
        );
    }
}
