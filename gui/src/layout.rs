use crate::model::{self, Session};
use crate::scale::Scale;
use crate::style::Control;

pub const DESIGN_WIDTH: f32 = 1040.0;
pub const DESIGN_HEIGHT: f32 = 640.0;
pub const NAV_WIDTH: f32 = 232.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Font {
    Nav,
    Title,
    Subtitle,
    Button,
    CardTitle,
    Small,
    Mono,
    CardButton,
    DeviceTitle,
    Link,
}

pub trait Measure {
    fn width(&self, font: Font, text: &str) -> i32;
    fn line_height(&self, font: Font) -> i32;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

impl Rect {
    pub const fn new(x: i32, y: i32, w: i32, h: i32) -> Self {
        Self { x, y, w, h }
    }

    pub const fn right(self) -> i32 {
        self.x + self.w
    }

    pub const fn bottom(self) -> i32 {
        self.y + self.h
    }

    pub const fn translate(self, dx: i32, dy: i32) -> Self {
        Self::new(self.x + dx, self.y + dy, self.w, self.h)
    }

    pub const fn inflate(self, dx: i32, dy: i32) -> Self {
        Self::new(self.x - dx, self.y - dy, self.w + 2 * dx, self.h + 2 * dy)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NavItem {
    pub frame: Rect,
    pub indicator: Rect,
    pub icon: Rect,
    pub label: Rect,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Card {
    pub frame: Rect,
    pub tile: Rect,
    pub icon: Rect,
    pub title: Rect,
    pub tag: Rect,
    pub detail: Vec<Rect>,
    pub badges: [Rect; 2],
    pub credentials: Option<Rect>,
    pub revoke: Rect,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceCard {
    pub frame: Rect,
    pub icon: Rect,
    pub title: Rect,
    pub fingerprint: Rect,
    pub details: Rect,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layout {
    pub nav: [NavItem; 4],
    pub panel: Rect,
    pub title: Rect,
    pub subtitle: Rect,
    pub open_log: Rect,
    pub new_session: Rect,
    pub plus: Rect,
    pub new_session_label: Rect,
    pub cards: Vec<Card>,
    pub device: DeviceCard,
}

impl Layout {
    pub fn controls(&self) -> Vec<Control> {
        let nav = (0..self.nav.len()).map(Control::Nav);
        let header = [Control::OpenLog, Control::NewSession];
        let cards = self.cards.iter().enumerate().flat_map(|(i, card)| {
            let credentials = card.credentials.map(|_| Control::Credentials(i));
            credentials.into_iter().chain([Control::Revoke(i)])
        });
        nav.chain(header)
            .chain(cards)
            .chain([Control::Details])
            .collect()
    }

    pub fn bounds(&self, control: Control, s: Scale) -> Option<Rect> {
        match control {
            Control::Nav(i) => self.nav.get(i).map(|item| item.frame),
            Control::OpenLog => Some(self.open_log),
            Control::NewSession => Some(self.new_session),
            Control::Credentials(i) => self.cards.get(i).and_then(|card| card.credentials),
            Control::Revoke(i) => self.cards.get(i).map(|card| card.revoke),
            Control::Details => Some(self.device.details.inflate(s.px(4.0), s.px(2.0))),
        }
    }
}

pub fn min_client_size(s: Scale) -> (i32, i32) {
    (s.px(DESIGN_WIDTH), s.px(DESIGN_HEIGHT))
}

pub fn flow(widths: &[i32], avail: i32, gap: i32) -> Vec<(usize, i32)> {
    let mut line = 0;
    let mut end = 0;
    widths
        .iter()
        .enumerate()
        .map(|(i, &w)| {
            let x = if i == 0 { 0 } else { end + gap };
            if i > 0 && x + w > avail {
                line += 1;
                end = w;
                (line, 0)
            } else {
                end = x + w;
                (line, x)
            }
        })
        .collect()
}

fn centered(top: i32, span: i32, size: i32) -> i32 {
    top + (span - size) / 2
}

fn nav_item(frame: Rect, s: Scale) -> NavItem {
    let icon = Rect::new(
        frame.x + s.px(12.0),
        centered(frame.y, frame.h, s.px(18.0)),
        s.px(18.0),
        s.px(18.0),
    );
    let label_x = icon.right() + s.px(12.0);
    NavItem {
        frame,
        indicator: Rect::new(frame.x, frame.y + s.px(12.0), s.px(3.0), s.px(16.0)),
        icon,
        label: Rect::new(
            label_x,
            frame.y,
            frame.right() - s.px(12.0) - label_x,
            frame.h,
        ),
    }
}

fn nav(height: i32, s: Scale) -> [NavItem; 4] {
    let x = s.px(8.0);
    let w = s.px(NAV_WIDTH) - 2 * x;
    let h = s.px(40.0);
    let step = h + s.px(4.0);
    let top = s.px(8.0);
    let settings = height - s.px(16.0) - h;
    [top, top + step, top + 2 * step, settings].map(|y| nav_item(Rect::new(x, y, w, h), s))
}

struct Content {
    left: i32,
    top: i32,
    right: i32,
}

fn card(y: i32, c: &Content, s: Scale, m: &dyn Measure, session: &Session) -> Card {
    let bw = s.hairline();
    let left = c.left + bw + s.px(16.0);
    let right = c.right - bw - s.px(16.0);
    let actions_x = right - s.px(196.0);

    let badge_h = m.line_height(Font::Small) + 2 * s.px(2.0);
    let badge_w = |t: &str| m.width(Font::Small, t) + 2 * s.px(8.0);
    let widths = [badge_w(session.auth), badge_w(session.route)];
    let badges_x = actions_x - s.px(16.0) - widths[0] - s.px(6.0) - widths[1];

    let col_x = left + s.px(40.0) + s.px(16.0);
    let col_w = badges_x - s.px(16.0) - col_x;
    let row_h = m
        .line_height(Font::CardTitle)
        .max(m.line_height(Font::Small));
    let line_h = m.line_height(Font::Small).max(m.line_height(Font::Mono));
    let parts = session.detail();
    let part_w: Vec<i32> = parts
        .iter()
        .map(|&(t, mono)| m.width(if mono { Font::Mono } else { Font::Small }, t))
        .collect();
    let placed = flow(&part_w, col_w, s.px(6.0));
    let lines = placed.last().map_or(0, |p| p.0 as i32 + 1);
    let detail_h = lines * line_h + (lines - 1).max(0) * s.px(6.0);
    let col_h = row_h + s.px(4.0) + detail_h;

    let button_h = s.px(30.0);
    let content_h = s.px(40.0).max(col_h).max(badge_h).max(button_h);
    let content_y = y + bw + s.px(14.0);
    let mid = |h: i32| centered(content_y, content_h, h);

    let tile = Rect::new(left, mid(s.px(40.0)), s.px(40.0), s.px(40.0));
    let icon_size = s.px(20.0);
    let icon = Rect::new(
        centered(tile.x, tile.w, icon_size),
        centered(tile.y, tile.h, icon_size),
        icon_size,
        icon_size,
    );

    let col_y = mid(col_h);
    let title = Rect::new(col_x, col_y, m.width(Font::CardTitle, session.title), row_h);
    let tag_text = session.tag();
    let tag = Rect::new(
        title.right() + s.px(8.0),
        col_y,
        m.width(Font::Small, &tag_text),
        row_h,
    );
    let detail_y = col_y + row_h + s.px(4.0);
    let detail = placed
        .iter()
        .zip(&part_w)
        .map(|(&(line, x), &w)| {
            Rect::new(
                col_x + x,
                detail_y + line as i32 * (line_h + s.px(6.0)),
                w,
                line_h,
            )
        })
        .collect();

    let badge_y = mid(badge_h);
    let badges = [
        Rect::new(badges_x, badge_y, widths[0], badge_h),
        Rect::new(
            badges_x + widths[0] + s.px(6.0),
            badge_y,
            widths[1],
            badge_h,
        ),
    ];

    let button_w = |t: &str| m.width(Font::CardButton, t) + 2 * s.px(12.0) + 2 * bw;
    let button_y = mid(button_h);
    let revoke_w = button_w(model::REVOKE);
    let revoke = Rect::new(right - revoke_w, button_y, revoke_w, button_h);
    let credentials = session.credentials.then(|| {
        let w = button_w(model::CREDENTIALS);
        Rect::new(revoke.x - s.px(6.0) - w, button_y, w, button_h)
    });

    Card {
        frame: Rect::new(
            c.left,
            y,
            c.right - c.left,
            2 * bw + 2 * s.px(14.0) + content_h,
        ),
        tile,
        icon,
        title,
        tag,
        detail,
        badges,
        credentials,
        revoke,
    }
}

fn device_card(bottom: i32, c: &Content, s: Scale, m: &dyn Measure) -> DeviceCard {
    let bw = s.hairline();
    let left = c.left + bw + s.px(16.0);
    let right = c.right - bw - s.px(16.0);
    let title_h = m.line_height(Font::DeviceTitle);
    let col_h = title_h + s.px(2.0) + m.line_height(Font::Mono);
    let link_h = m.line_height(Font::Link);
    let content_h = s.px(20.0).max(col_h).max(link_h);
    let h = 2 * bw + 2 * s.px(14.0) + content_h;
    let y = bottom - h;
    let content_y = y + bw + s.px(14.0);
    let mid = |size: i32| centered(content_y, content_h, size);

    let icon = Rect::new(left, mid(s.px(20.0)), s.px(20.0), s.px(20.0));
    let col_x = icon.right() + s.px(14.0);
    let col_y = mid(col_h);
    let link_w = m.width(Font::Link, model::DETAILS);
    DeviceCard {
        frame: Rect::new(c.left, y, c.right - c.left, h),
        icon,
        title: Rect::new(
            col_x,
            col_y,
            m.width(Font::DeviceTitle, model::DEVICE_KEY),
            title_h,
        ),
        fingerprint: Rect::new(
            col_x,
            col_y + title_h + s.px(2.0),
            m.width(Font::Mono, model::FINGERPRINT),
            m.line_height(Font::Mono),
        ),
        details: Rect::new(right - link_w, mid(link_h), link_w, link_h),
    }
}

pub fn compute(width: i32, height: i32, s: Scale, m: &dyn Measure, sessions: &[Session]) -> Layout {
    let bw = s.hairline();
    let panel = Rect::new(s.px(NAV_WIDTH), 0, width - s.px(NAV_WIDTH), height);
    let c = Content {
        left: panel.x + bw + s.px(36.0),
        top: panel.y + bw + s.px(28.0),
        right: width - s.px(36.0),
    };

    let title_h = m.line_height(Font::Title);
    let subtitle_h = m.line_height(Font::Subtitle);
    let column_h = title_h + s.px(4.0) + subtitle_h;
    let button_h = s.px(32.0);
    let header_bottom = c.top + column_h.max(button_h);
    let button_y = header_bottom - button_h;

    let new_label_w = m.width(Font::Button, model::NEW_SESSION);
    let new_w = s.px(16.0) + s.px(14.0) + s.px(8.0) + new_label_w + s.px(16.0);
    let new_session = Rect::new(c.right - new_w, button_y, new_w, button_h);
    let plus = Rect::new(
        new_session.x + s.px(16.0),
        centered(button_y, button_h, s.px(14.0)),
        s.px(14.0),
        s.px(14.0),
    );
    let new_session_label = Rect::new(plus.right() + s.px(8.0), button_y, new_label_w, button_h);
    let open_w = m.width(Font::Button, model::OPEN_LOG) + 2 * s.px(16.0) + 2 * bw;
    let open_log = Rect::new(
        new_session.x - s.px(16.0) - open_w,
        button_y,
        open_w,
        button_h,
    );

    let text_w = open_log.x - s.px(16.0) - c.left;
    let title = Rect::new(c.left, header_bottom - column_h, text_w, title_h);
    let subtitle = Rect::new(c.left, title.bottom() + s.px(4.0), text_w, subtitle_h);

    let mut y = header_bottom + s.px(20.0);
    let cards = sessions
        .iter()
        .map(|session| {
            let card = card(y, &c, s, m, session);
            y = card.frame.bottom() + s.px(6.0);
            card
        })
        .collect();

    Layout {
        nav: nav(height, s),
        panel,
        title,
        subtitle,
        open_log,
        new_session,
        plus,
        new_session_label,
        cards,
        device: device_card(height - s.px(28.0), &c, s, m),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SESSIONS;

    struct Fake;

    impl Measure for Fake {
        fn width(&self, _: Font, text: &str) -> i32 {
            7 * text.chars().count() as i32
        }

        fn line_height(&self, font: Font) -> i32 {
            match font {
                Font::Title => 37,
                Font::Subtitle | Font::CardButton | Font::DeviceTitle | Font::Link => 17,
                Font::Small | Font::Mono => 16,
                Font::Nav | Font::Button | Font::CardTitle => 19,
            }
        }
    }

    #[test]
    fn controls_are_listed_in_tab_order() {
        let l = at(96, 1040, 640);
        assert_eq!(
            l.controls(),
            vec![
                Control::Nav(0),
                Control::Nav(1),
                Control::Nav(2),
                Control::Nav(3),
                Control::OpenLog,
                Control::NewSession,
                Control::Credentials(0),
                Control::Revoke(0),
                Control::Revoke(1),
                Control::Revoke(2),
                Control::Details,
            ]
        );
    }

    #[test]
    fn control_bounds_come_from_the_layout() {
        let s = Scale::new(96);
        let l = at(96, 1040, 640);
        assert_eq!(l.bounds(Control::Nav(2), s), Some(l.nav[2].frame));
        assert_eq!(l.bounds(Control::OpenLog, s), Some(l.open_log));
        assert_eq!(l.bounds(Control::NewSession, s), Some(l.new_session));
        assert_eq!(l.bounds(Control::Credentials(0), s), l.cards[0].credentials);
        assert_eq!(l.bounds(Control::Credentials(1), s), None);
        assert_eq!(l.bounds(Control::Revoke(2), s), Some(l.cards[2].revoke));
        assert_eq!(l.bounds(Control::Revoke(3), s), None);
        assert_eq!(l.bounds(Control::Nav(4), s), None);
    }

    #[test]
    fn the_details_link_gets_a_larger_hit_area() {
        let l = at(144, 1560, 960);
        assert_eq!(
            l.bounds(Control::Details, Scale::new(144)),
            Some(l.device.details.inflate(6, 3))
        );
    }

    #[test]
    fn translate_moves_without_resizing() {
        assert_eq!(
            Rect::new(10, 20, 30, 40).translate(-4, 6),
            Rect::new(6, 26, 30, 40)
        );
    }

    fn at(dpi: u32, w: i32, h: i32) -> Layout {
        compute(w, h, Scale::new(dpi), &Fake, &SESSIONS)
    }

    #[test]
    fn min_client_size_is_the_design_size() {
        assert_eq!(min_client_size(Scale::new(96)), (1040, 640));
        assert_eq!(min_client_size(Scale::new(144)), (1560, 960));
    }

    #[test]
    fn flow_wraps_items_that_overflow_the_line() {
        assert_eq!(
            flow(&[182, 7, 98, 7, 77], 197, 6),
            vec![(0, 0), (0, 188), (1, 0), (1, 104), (1, 117)]
        );
    }

    #[test]
    fn flow_keeps_an_oversized_first_item_on_its_line() {
        assert_eq!(flow(&[300, 10], 100, 6), vec![(0, 0), (1, 0)]);
    }

    #[test]
    fn flow_fits_everything_on_one_line_when_wide_enough() {
        assert_eq!(flow(&[10, 20, 30], 100, 6), vec![(0, 0), (0, 16), (0, 42)]);
    }

    #[test]
    fn nav_items_stack_with_settings_pinned_to_the_bottom() {
        let l = at(96, 1040, 640);
        let frames: Vec<Rect> = l.nav.iter().map(|n| n.frame).collect();
        assert_eq!(
            frames,
            vec![
                Rect::new(8, 8, 216, 40),
                Rect::new(8, 52, 216, 40),
                Rect::new(8, 96, 216, 40),
                Rect::new(8, 584, 216, 40),
            ]
        );
        assert_eq!(l.nav[0].indicator, Rect::new(8, 20, 3, 16));
        assert_eq!(l.nav[0].icon, Rect::new(20, 19, 18, 18));
        assert_eq!(l.nav[0].label, Rect::new(50, 8, 162, 40));
    }

    #[test]
    fn panel_fills_the_area_right_of_the_nav() {
        assert_eq!(at(96, 1040, 640).panel, Rect::new(232, 0, 808, 640));
    }

    #[test]
    fn header_buttons_are_right_aligned_and_bottom_aligned_with_the_subtitle() {
        let l = at(96, 1040, 640);
        assert_eq!(l.title, Rect::new(269, 29, 426, 37));
        assert_eq!(l.subtitle, Rect::new(269, 70, 426, 17));
        assert_eq!(l.new_session, Rect::new(817, 55, 187, 32));
        assert_eq!(l.open_log, Rect::new(711, 55, 90, 32));
        assert_eq!(l.plus, Rect::new(833, 64, 14, 14));
        assert_eq!(l.new_session_label, Rect::new(855, 55, 133, 32));
    }

    #[test]
    fn first_card_wraps_its_detail_line() {
        let l = at(96, 1040, 640);
        let c = &l.cards[0];
        assert_eq!(c.frame, Rect::new(269, 107, 735, 91));
        assert_eq!(c.tile, Rect::new(286, 132, 40, 40));
        assert_eq!(c.icon, Rect::new(296, 142, 20, 20));
        assert_eq!(c.title, Rect::new(342, 122, 98, 19));
        assert_eq!(c.tag, Rect::new(448, 122, 14, 19));
        assert_eq!(
            c.detail,
            vec![
                Rect::new(342, 145, 182, 16),
                Rect::new(530, 145, 7, 16),
                Rect::new(342, 167, 98, 16),
                Rect::new(446, 167, 7, 16),
                Rect::new(459, 167, 77, 16),
            ]
        );
        assert_eq!(
            c.badges,
            [Rect::new(555, 142, 149, 20), Rect::new(710, 142, 65, 20)]
        );
        assert_eq!(c.revoke, Rect::new(919, 137, 68, 30));
        assert_eq!(c.credentials, Some(Rect::new(810, 137, 103, 30)));
    }

    #[test]
    fn cards_stack_with_a_gap_and_only_the_first_has_credentials() {
        let l = at(96, 1040, 640);
        assert_eq!(l.cards.len(), 3);
        assert_eq!(l.cards[1].frame.y, 107 + 91 + 6);
        assert_eq!(l.cards[2].frame.y, l.cards[1].frame.bottom() + 6);
        assert!(l.cards[1].credentials.is_none());
        assert!(l.cards[2].credentials.is_none());
        assert_eq!(l.cards[2].revoke.right(), 987);
    }

    #[test]
    fn device_card_sits_on_the_bottom_padding() {
        let d = at(96, 1040, 640).device;
        assert_eq!(d.frame, Rect::new(269, 547, 735, 65));
        assert_eq!(d.icon, Rect::new(286, 569, 20, 20));
        assert_eq!(d.title, Rect::new(320, 562, 238, 17));
        assert_eq!(d.fingerprint, Rect::new(320, 581, 175, 16));
        assert_eq!(d.details, Rect::new(938, 571, 49, 17));
    }

    #[test]
    fn widening_the_window_stretches_cards_and_keeps_buttons_right_aligned() {
        let l = at(96, 1400, 800);
        assert_eq!(l.panel, Rect::new(232, 0, 1168, 800));
        assert_eq!(l.new_session.right(), 1364);
        assert_eq!(l.cards[0].frame.w, 1095);
        assert_eq!(l.cards[0].revoke.right(), 1347);
        assert_eq!(l.device.frame.y, 800 - 28 - 65);
        assert_eq!(l.nav[3].frame.y, 800 - 16 - 40);
    }

    #[test]
    fn a_wide_card_keeps_the_detail_line_on_one_row() {
        let c = &at(96, 1400, 800).cards[0];
        assert!(c.detail.iter().all(|r| r.y == c.detail[0].y));
        assert_eq!(c.frame.h, 2 + 28 + 40);
    }

    #[test]
    fn scales_dip_constants_at_150_percent() {
        let l = at(144, 1560, 960);
        assert_eq!(l.nav[0].frame, Rect::new(12, 12, 324, 60));
        assert_eq!(l.nav[0].indicator, Rect::new(12, 30, 5, 24));
        assert_eq!(l.panel, Rect::new(348, 0, 1212, 960));
        assert_eq!(l.title.x, 348 + 1 + 54);
        assert_eq!(l.title.y, 1 + 42);
        assert_eq!(l.new_session.right(), 1560 - 54);
        assert_eq!(l.new_session.h, 48);
        assert_eq!(l.cards[0].tile.w, 60);
        assert_eq!(l.cards[0].revoke.h, 45);
        assert_eq!(l.device.frame.bottom(), 960 - 42);
    }
}
