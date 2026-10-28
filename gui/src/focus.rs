use crate::hit::Zone;
use crate::layout::Rect;
use crate::pointer::{self, Action};
use crate::scale::Scale;
use crate::scene::Op;
use crate::theme::Theme;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stop {
    pub rect: Rect,
    pub zone: Zone,
    pub scrolls: bool,
    pub clip: Rect,
}

impl Stop {
    fn seen(&self) -> bool {
        let (r, c) = (self.rect, self.clip);
        r.x.max(c.x) < r.right().min(c.right()) && r.y.max(c.y) < r.bottom().min(c.bottom())
    }

    fn whole(&self) -> bool {
        let (r, c) = (self.rect, self.clip);
        r.x >= c.x && r.y >= c.y && r.right() <= c.right() && r.bottom() <= c.bottom()
    }
}

pub fn stops(rail: &[Stop], order: &[Stop]) -> (Vec<Stop>, bool) {
    let actionable = |s: &&Stop| pointer::action(s.zone).is_some() && (s.scrolls || s.seen());
    match order
        .iter()
        .position(|s| matches!(s.zone, Zone::Menu | Zone::Dialog))
    {
        Some(end) => (
            order[..end].iter().filter(actionable).copied().collect(),
            true,
        ),
        None => (
            rail.iter()
                .chain(order.iter().filter(actionable))
                .copied()
                .collect(),
            false,
        ),
    }
}

fn group(zone: Zone) -> Option<u8> {
    match zone {
        Zone::Nav(_) => Some(0),
        Zone::LogFilter(_) => Some(1),
        Zone::Theme(_) => Some(2),
        Zone::Entry(_) => Some(3),
        _ => None,
    }
}

fn same(a: Zone, b: Zone) -> bool {
    a == b || matches!((a, b), (Zone::TogglePassword(_), Zone::TogglePassword(_)))
}

fn step(len: usize, at: usize, forward: bool) -> usize {
    if forward {
        (at + 1) % len
    } else {
        (at + len - 1) % len
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Focus {
    zone: Option<Zone>,
    visible: bool,
    opener: Option<Zone>,
    trapped: bool,
}

impl Focus {
    pub fn zone(&self) -> Option<Zone> {
        self.zone
    }

    pub fn ring(&self) -> Option<Zone> {
        self.zone.filter(|_| self.visible)
    }

    pub fn action(&self, stops: &[Stop]) -> Option<Action> {
        let zone = self.ring()?;
        stops
            .iter()
            .find(|s| s.zone == zone && s.seen())
            .and_then(|s| pointer::action(s.zone))
    }

    pub fn tab(&mut self, stops: &[Stop], back: bool) -> Option<Zone> {
        if stops.is_empty() {
            return None;
        }
        let at = self
            .zone
            .and_then(|z| stops.iter().position(|s| s.zone == z));
        let next = match at {
            Some(i) => step(stops.len(), i, !back),
            None if back => stops.len() - 1,
            None => 0,
        };
        self.visible = true;
        self.zone = Some(stops[next].zone);
        self.zone
    }

    pub fn clicked(&mut self, zone: Zone, stops: &[Stop]) {
        self.visible = false;
        if stops.iter().any(|s| s.zone == zone) {
            self.zone = Some(zone);
        }
    }

    pub fn arrow(&mut self, stops: &[Stop], forward: bool) -> Option<Zone> {
        let next = match self.zone {
            None if self.trapped => {
                let mut menu = stops.iter().filter(|s| matches!(s.zone, Zone::Entry(_)));
                if forward {
                    menu.next()
                } else {
                    menu.next_back()
                }?
                .zone
            }
            None => return None,
            Some(zone) => {
                let kind = group(zone)?;
                let peers: Vec<Zone> = stops
                    .iter()
                    .map(|s| s.zone)
                    .filter(|&z| group(z) == Some(kind))
                    .collect();
                let at = peers.iter().position(|&z| z == zone)?;
                peers[step(peers.len(), at, forward)]
            }
        };
        self.visible = true;
        self.zone = Some(next);
        self.zone
    }

    pub fn sync(&mut self, stops: &[Stop], trapped: bool) {
        let first = stops.first().map(|s| s.zone).filter(|_| self.visible);
        if trapped && !self.trapped {
            self.opener = self.zone;
            self.zone = first;
        } else if !trapped && self.trapped {
            self.zone = self.opener.take();
        }
        self.trapped = trapped;
        self.zone = self
            .zone
            .and_then(|z| stops.iter().map(|s| s.zone).find(|&s| same(s, z)))
            .or(if trapped { first } else { None });
        if self.zone.is_none() && !trapped {
            self.visible = false;
        }
    }
}

pub fn outline(stop: &Stop, s: Scale, t: &Theme) -> Vec<Op> {
    let ring = ring(stop.rect, s, t);
    if !stop.seen() {
        Vec::new()
    } else if stop.scrolls || !stop.whole() {
        vec![Op::Clip(stop.clip), ring, Op::Unclip]
    } else {
        vec![ring]
    }
}

fn ring(rect: Rect, s: Scale, t: &Theme) -> Op {
    let d = s.px(2.5);
    Op::Ring(
        Rect::new(rect.x - d, rect.y - d, rect.w + 2 * d, rect.h + 2 * d),
        s.pxf(6.0),
        s.pxf(2.0),
        t.focus,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::Field;
    use crate::log::Filter;
    use crate::nav::Page;
    use crate::scale::Scale;
    use crate::theme::{Choice, Theme};

    fn stop(zone: Zone) -> Stop {
        Stop {
            rect: Rect::new(10, 10, 20, 20),
            zone,
            scrolls: false,
            clip: Rect::new(0, 0, 1000, 1000),
        }
    }

    fn at(zone: Zone, rect: Rect, scrolls: bool) -> Stop {
        Stop {
            rect,
            zone,
            scrolls,
            clip: Rect::new(0, 100, 200, 100),
        }
    }

    fn zones(stops: &[Stop]) -> Vec<Zone> {
        stops.iter().map(|s| s.zone).collect()
    }

    fn page() -> Vec<Stop> {
        vec![
            stop(Zone::OpenConfig),
            stop(Zone::Theme(Choice::System)),
            stop(Zone::Theme(Choice::Light)),
            stop(Zone::Theme(Choice::Dark)),
            stop(Zone::SignIn),
        ]
    }

    fn rail() -> Vec<Stop> {
        Page::ALL.map(|p| stop(Zone::Nav(p))).to_vec()
    }

    #[test]
    fn the_rail_comes_before_the_actionable_content() {
        let mut order = page();
        order.insert(0, stop(Zone::Client));
        let (found, trapped) = stops(&rail(), &order);
        assert!(!trapped);
        assert_eq!(
            zones(&found),
            [
                Zone::Nav(Page::Sessions),
                Zone::Nav(Page::Gateways),
                Zone::Nav(Page::Device),
                Zone::Nav(Page::Log),
                Zone::Nav(Page::Settings),
                Zone::OpenConfig,
                Zone::Theme(Choice::System),
                Zone::Theme(Choice::Light),
                Zone::Theme(Choice::Dark),
                Zone::SignIn,
            ]
        );
    }

    #[test]
    fn an_open_dialog_or_menu_traps_the_stops() {
        let order = vec![
            stop(Zone::CopyCredential(Field::Password)),
            stop(Zone::CloseDialog),
            stop(Zone::Dialog),
        ];
        let (found, trapped) = stops(&rail(), &order);
        assert!(trapped);
        assert_eq!(
            zones(&found),
            [Zone::CopyCredential(Field::Password), Zone::CloseDialog]
        );
        let order = vec![
            stop(Zone::Entry(0)),
            stop(Zone::Entry(2)),
            stop(Zone::Menu),
            stop(Zone::More(4)),
        ];
        let (found, trapped) = stops(&rail(), &order);
        assert!(trapped);
        assert_eq!(zones(&found), [Zone::Entry(0), Zone::Entry(2)]);
    }

    #[test]
    fn tab_walks_forward_and_back_with_wrap_and_shows_the_ring() {
        let stops = page();
        let mut f = Focus::default();
        assert_eq!(f.ring(), None);
        assert_eq!(f.tab(&stops, false), Some(Zone::OpenConfig));
        assert_eq!(f.ring(), Some(Zone::OpenConfig));
        assert_eq!(f.tab(&stops, false), Some(Zone::Theme(Choice::System)));
        assert_eq!(f.tab(&stops, true), Some(Zone::OpenConfig));
        assert_eq!(f.tab(&stops, true), Some(Zone::SignIn));
        assert_eq!(f.tab(&stops, false), Some(Zone::OpenConfig));
        let mut f = Focus::default();
        assert_eq!(f.tab(&stops, true), Some(Zone::SignIn));
        assert_eq!(Focus::default().tab(&[], false), None);
    }

    #[test]
    fn a_click_hides_the_ring_and_moves_the_focus_to_a_stop() {
        let stops = page();
        let mut f = Focus::default();
        f.tab(&stops, false);
        f.clicked(Zone::SignIn, &stops);
        assert_eq!(f.ring(), None);
        assert_eq!(f.zone(), Some(Zone::SignIn));
        f.clicked(Zone::Client, &stops);
        assert_eq!(f.zone(), Some(Zone::SignIn));
        assert_eq!(f.tab(&stops, false), Some(Zone::OpenConfig));
        assert_eq!(f.ring(), Some(Zone::OpenConfig));
    }

    #[test]
    fn arrows_move_within_a_group_only() {
        let mut stops = rail();
        stops.extend(page());
        stops.push(stop(Zone::LogFilter(Filter::All)));
        stops.push(stop(Zone::LogFilter(Filter::Warnings)));
        let mut f = Focus::default();
        assert_eq!(f.arrow(&stops, true), None);
        f.tab(&stops, false);
        assert_eq!(f.arrow(&stops, true), Some(Zone::Nav(Page::Gateways)));
        assert_eq!(f.arrow(&stops, false), Some(Zone::Nav(Page::Sessions)));
        assert_eq!(f.arrow(&stops, false), Some(Zone::Nav(Page::Settings)));
        assert_eq!(f.arrow(&stops, true), Some(Zone::Nav(Page::Sessions)));
        f.clicked(Zone::Theme(Choice::Dark), &stops);
        assert_eq!(f.arrow(&stops, true), Some(Zone::Theme(Choice::System)));
        assert_eq!(f.ring(), Some(Zone::Theme(Choice::System)));
        assert_eq!(f.arrow(&stops, false), Some(Zone::Theme(Choice::Dark)));
        f.clicked(Zone::OpenConfig, &stops);
        assert_eq!(f.arrow(&stops, true), None);
        assert_eq!(f.zone(), Some(Zone::OpenConfig));
        f.clicked(Zone::LogFilter(Filter::All), &stops);
        assert_eq!(
            f.arrow(&stops, true),
            Some(Zone::LogFilter(Filter::Warnings))
        );
    }

    #[test]
    fn arrows_enter_an_open_menu() {
        let menu = [stop(Zone::Entry(1)), stop(Zone::Entry(3))];
        let mut f = Focus::default();
        f.sync(&menu, true);
        assert_eq!(f.zone(), None);
        assert_eq!(f.arrow(&menu, true), Some(Zone::Entry(1)));
        let mut f = Focus::default();
        f.sync(&menu, true);
        assert_eq!(f.arrow(&menu, false), Some(Zone::Entry(3)));
        assert_eq!(f.arrow(&menu, false), Some(Zone::Entry(1)));
    }

    #[test]
    fn a_dialog_takes_the_focus_and_gives_it_back_to_the_opener() {
        let stops = page();
        let dialog = [stop(Zone::CopyId), stop(Zone::CloseDialog)];
        let mut f = Focus::default();
        f.tab(&stops, false);
        f.sync(&dialog, true);
        assert_eq!(f.zone(), Some(Zone::CopyId));
        assert_eq!(f.tab(&dialog, false), Some(Zone::CloseDialog));
        assert_eq!(f.tab(&dialog, false), Some(Zone::CopyId));
        f.sync(&stops, false);
        assert_eq!(f.zone(), Some(Zone::OpenConfig));
        assert_eq!(f.ring(), Some(Zone::OpenConfig));
    }

    #[test]
    fn a_dialog_opened_by_mouse_waits_for_a_key() {
        let stops = page();
        let dialog = [stop(Zone::CopyId), stop(Zone::CloseDialog)];
        let mut f = Focus::default();
        f.clicked(Zone::SignIn, &stops);
        f.sync(&dialog, true);
        assert_eq!(f.zone(), None);
        assert_eq!(f.tab(&dialog, false), Some(Zone::CopyId));
        f.sync(&stops, false);
        assert_eq!(f.zone(), Some(Zone::SignIn));
    }

    #[test]
    fn a_menu_that_opens_a_dialog_still_returns_to_the_opener() {
        let page = [stop(Zone::More(4)), stop(Zone::Revoke(4))];
        let menu = [stop(Zone::Entry(0)), stop(Zone::Entry(1))];
        let dialog = [stop(Zone::CloseDialog)];
        let mut f = Focus::default();
        f.tab(&page, false);
        f.sync(&menu, true);
        assert_eq!(f.zone(), Some(Zone::Entry(0)));
        f.arrow(&menu, true);
        f.sync(&dialog, true);
        assert_eq!(f.zone(), Some(Zone::CloseDialog));
        f.sync(&page, false);
        assert_eq!(f.zone(), Some(Zone::More(4)));
    }

    #[test]
    fn a_vanished_stop_drops_the_focus() {
        let mut f = Focus::default();
        f.tab(&[stop(Zone::Revoke(4))], false);
        f.sync(&[stop(Zone::Revoke(5))], false);
        assert_eq!(f.zone(), None);
        assert_eq!(f.ring(), None);
    }

    #[test]
    fn the_password_toggle_keeps_the_focus_when_it_flips() {
        let mut f = Focus::default();
        f.tab(&[stop(Zone::TogglePassword(false))], false);
        f.sync(&[stop(Zone::TogglePassword(true))], false);
        assert_eq!(f.zone(), Some(Zone::TogglePassword(true)));
    }

    #[test]
    fn the_ring_surrounds_its_target_with_a_gap() {
        let s = Scale { dpi: 144 };
        let t = Theme::DARK;
        assert_eq!(
            ring(Rect::new(100, 50, 40, 30), s, &t),
            Op::Ring(Rect::new(96, 46, 48, 38), 9.0, 3.0, t.focus)
        );
    }

    #[test]
    fn keys_activate_actionable_stops() {
        let stops = [stop(Zone::Theme(Choice::Dark))];
        let mut f = Focus::default();
        assert_eq!(f.action(&stops), None);
        f.tab(&stops, false);
        assert_eq!(f.action(&stops), Some(Action::Theme(Choice::Dark)));
        f.clicked(Zone::Theme(Choice::Dark), &stops);
        assert_eq!(f.action(&stops), None);
    }

    #[test]
    fn stops_outside_their_view_are_skipped_unless_they_scroll() {
        let order = vec![
            at(
                Zone::CopyCredential(Field::Username),
                Rect::new(10, 190, 20, 20),
                false,
            ),
            at(
                Zone::CopyCredential(Field::Password),
                Rect::new(10, 200, 20, 20),
                false,
            ),
            at(Zone::Revoke(1), Rect::new(10, 300, 20, 20), true),
            stop(Zone::CloseDialog),
            stop(Zone::Dialog),
        ];
        let (found, _) = stops(&rail(), &order);
        assert_eq!(
            zones(&found),
            [
                Zone::CopyCredential(Field::Username),
                Zone::Revoke(1),
                Zone::CloseDialog
            ]
        );
    }

    #[test]
    fn keys_never_activate_a_stop_scrolled_out_of_view() {
        let shown = [at(Zone::Revoke(4), Rect::new(10, 120, 20, 20), true)];
        let mut f = Focus::default();
        f.tab(&shown, false);
        assert_eq!(f.action(&shown), Some(Action::Revoke(4)));
        let gone = [at(Zone::Revoke(4), Rect::new(10, 40, 20, 20), true)];
        f.sync(&gone, false);
        assert_eq!(f.zone(), Some(Zone::Revoke(4)));
        assert_eq!(f.action(&gone), None);
    }

    #[test]
    fn the_ring_is_clipped_to_the_view_of_a_scrolling_or_cut_stop() {
        let s = Scale { dpi: 96 };
        let t = Theme::DARK;
        let view = Rect::new(0, 100, 200, 100);
        let inside = Rect::new(10, 120, 20, 20);
        let cut = Rect::new(10, 190, 20, 20);
        assert_eq!(
            outline(&stop(Zone::SignIn), s, &t),
            [ring(stop(Zone::SignIn).rect, s, &t)]
        );
        let clipped = |r: Rect| vec![Op::Clip(view), ring(r, s, &t), Op::Unclip];
        assert_eq!(
            outline(&at(Zone::Revoke(1), inside, true), s, &t),
            clipped(inside)
        );
        assert_eq!(outline(&at(Zone::CopyId, cut, false), s, &t), clipped(cut));
        let below = Rect::new(10, 201, 20, 20);
        assert_eq!(outline(&at(Zone::Revoke(1), below, true), s, &t), []);
    }
}
