use std::borrow::Cow;

use crate::focus::Stop;
use crate::fonts::{Font, Measure};
use crate::gateways::START;
use crate::hit::Zone;
use crate::icons::{self, Icon};
use crate::layout::{Layout, Rect};
use crate::menu::Popup;
use crate::nav::Page as NavPage;
use crate::pointer::Look;
use crate::scale::Scale;
use crate::scene::{Op, View, stroke};
use crate::scroll::{self, Pane};
use crate::sessions::{EMPTY, Eyes, Kind, Launch, Page, Row};
use crate::theme::{Rgb, Theme};

pub mod device;
pub mod dialog;
pub mod gateways;
pub mod log;
pub mod menu;
pub mod settings;
pub mod tray;

#[derive(Debug, Default, PartialEq)]
pub struct Board {
    pub ops: Vec<Op>,
    pub targets: Vec<(Rect, Zone)>,
    pub order: Vec<Stop>,
    pub pane: Option<Pane>,
    pub anchor: Option<Rect>,
    pub popup: Option<Pane>,
}

const STOP_LABEL: &str = "Stop agent";
const REVOKE_TIP: &str = "Revoke session";
const MORE_TIP: &str = "More";

pub fn tips(targets: &[(Rect, Zone)]) -> Vec<(Rect, &'static str)> {
    if targets.iter().any(|&(_, zone)| zone == Zone::Menu) {
        return Vec::new();
    }
    targets
        .iter()
        .filter_map(|&(r, zone)| match zone {
            Zone::Revoke(_) => Some((r, REVOKE_TIP)),
            Zone::More(_) => Some((r, MORE_TIP)),
            Zone::TogglePassword(false) => Some((r, "Show password")),
            Zone::TogglePassword(true) => Some((r, "Hide password")),
            _ => None,
        })
        .collect()
}

struct Columns {
    session: Rect,
    gateway: Rect,
    uptime: Rect,
    activity: Rect,
    actions: Rect,
}

struct Painter<'a, M> {
    s: Scale,
    t: &'a Theme,
    v: &'a View,
    m: &'a M,
    clip: Rect,
    hidden: bool,
    board: Board,
}

pub fn board(l: &Layout, s: Scale, t: &Theme, v: &View, page: &Page, m: &impl Measure) -> Board {
    if v.nav.selected() != NavPage::Sessions {
        return Board::default();
    }
    let mut p = Painter::new(l, s, t, v, m);
    let card = p.status(l.content, page);
    if let Some(rows) = &page.rows {
        let heading = Rect::new(card.x, card.bottom() + s.px(18.0), card.w, s.px(20.0));
        p.text(Font::Heading, "Sessions", heading, t.text);
        p.table(
            Rect::new(card.x, heading.bottom() + s.px(18.0), card.w, 0),
            rows,
        );
    }
    p.finish()
}

fn inset(r: Rect, d: i32) -> Rect {
    Rect::new(r.x + d, r.y + d, r.w - 2 * d, r.h - 2 * d)
}

impl<'a, M: Measure> Painter<'a, M> {
    fn new(l: &Layout, s: Scale, t: &'a Theme, v: &'a View, m: &'a M) -> Self {
        Self::within(l.content, s, t, v, m)
    }

    fn within(clip: Rect, s: Scale, t: &'a Theme, v: &'a View, m: &'a M) -> Self {
        let mut p = Self {
            s,
            t,
            v,
            m,
            clip,
            hidden: false,
            board: Board::default(),
        };
        p.push(Op::Clip(clip));
        p
    }

    fn finish(mut self) -> Board {
        if self.board.pane.is_some() {
            self.push(Op::Unclip);
        }
        self.push(Op::Unclip);
        if let Some(pane) = self.board.pane {
            self.thumb(pane);
        }
        self.board
    }

    fn scroll(&mut self, view: Rect, content: i32) -> i32 {
        let page = self.v.nav.selected();
        let pane = Pane::new(view, content, self.v.scroll.get(page));
        self.board.pane = Some(pane);
        self.push(Op::Clip(view));
        self.clip = view;
        pane.offset
    }

    fn thumb(&mut self, pane: Pane) {
        let s = self.s;
        let view = pane.view;
        let track = Rect::new(view.right() + s.px(12.0), view.y, s.px(4.0), view.h);
        if let Some(r) = scroll::thumb(track, pane.content, pane.offset, s.px(24.0)) {
            self.push(Op::Round(r, s.pxf(2.0), self.t.eyes_idle));
        }
    }

    fn push(&mut self, op: Op) {
        if !self.hidden {
            self.board.ops.push(op);
        }
    }

    fn unseen(&mut self, draw: impl FnOnce(&mut Self)) {
        self.hidden = true;
        draw(self);
        self.hidden = false;
    }

    fn text(&mut self, font: Font, text: impl Into<Cow<'static, str>>, r: Rect, c: Rgb) {
        self.push(Op::Text(font, text.into(), r, c));
    }

    fn icon(&mut self, icon: Icon, centre: Rect, size: f32, c: Rgb) {
        let px = self.s.px(size);
        let r = Rect::new(
            centre.x + (centre.w - px) / 2,
            centre.y + (centre.h - px) / 2,
            px,
            px,
        );
        self.push(Op::Icon(icon, r, stroke(self.s, &icon, size), c));
    }

    fn framed(&mut self, r: Rect, radius: f32, fill: Rgb) {
        let edge = self.s.hairline();
        let radius = self.s.pxf(radius);
        self.push(Op::Round(r, radius, self.t.border));
        self.push(Op::Round(inset(r, edge), radius - edge as f32, fill));
    }

    fn target(&mut self, r: Rect, zone: Zone) {
        let scrolls = [self.board.pane, self.board.popup]
            .iter()
            .flatten()
            .any(|pane| pane.view == self.clip);
        self.board.order.push(Stop {
            rect: r,
            zone,
            scrolls,
            clip: self.clip,
        });
        let top = r.y.max(self.clip.y);
        let bottom = r.bottom().min(self.clip.bottom());
        if bottom > top && !self.hidden {
            self.board
                .targets
                .push((Rect::new(r.x, top, r.w, bottom - top), zone));
        }
    }

    fn status(&mut self, content: Rect, page: &Page) -> Rect {
        let (s, t) = (self.s, self.t);
        let status = &page.status;
        let card = Rect::new(content.x, content.y, content.w, s.px(92.0));
        self.framed(card, 12.0, t.card);
        let logo = s.px(56.0);
        let eyes = match status.eyes {
            Eyes::Lit => Some(t.accent),
            Eyes::Dim => Some(t.eyes_idle),
            Eyes::Closed => None,
        };
        let logo = Rect::new(card.x + s.px(20.0), card.y + s.px(18.0), logo, logo);
        self.push(Op::Logo(logo, eyes));
        let x = logo.right() + s.px(16.0);
        let mut right = card.right() - s.px(20.0);
        let button = status.stop.then(|| self.button(card, right, STOP_LABEL));
        if let Some(button) = button {
            right = button.x - s.px(16.0);
        }
        let pick = (status.launch != Launch::Hidden).then(|| self.button(card, right, START));
        if let Some(pick) = pick {
            right = pick.x - s.px(16.0);
        }
        let (title, sub) = (s.px(28.0), s.px(18.0));
        let top = card.y + (card.h - title - s.px(2.0) - sub) / 2;
        let w = right - x;
        self.text(
            Font::Status,
            status.title,
            Rect::new(x, top, w, title),
            t.text,
        );
        let subtitle = Rect::new(x, top + title + s.px(2.0), w, sub);
        self.text(Font::Body, status.subtitle.clone(), subtitle, t.muted);
        if let Some(pick) = pick {
            let ready = status.launch == Launch::Ready;
            self.start(pick, START, Zone::Picker, ready);
            if ready && self.v.popup == Some(Popup::Picker) {
                self.board.anchor = Some(pick);
            }
        }
        if let Some(button) = button {
            self.stop(button);
        }
        card
    }

    fn button(&self, card: Rect, right: i32, label: &str) -> Rect {
        let s = self.s;
        let text = self.m.width(Font::BodyStrong, label);
        let w = s.px(14.0) + s.px(16.0) + s.px(8.0) + text + s.px(14.0);
        let h = s.px(32.0);
        Rect::new(right - w, card.y + (card.h - h) / 2, w, h)
    }

    fn start(&mut self, button: Rect, label: &'static str, zone: Zone, enabled: bool) {
        let (s, t) = (self.s, self.t);
        let (fill, glyph, ink) = match (enabled, self.v.pointer.look(zone)) {
            (false, _) => (t.tile, t.eyes_idle, t.eyes_idle),
            (true, Look::Rest) => (t.button, t.button_glyph, t.button_text),
            (true, Look::Hover) => (t.button_hover, t.button_glyph, t.button_text),
            (true, Look::Pressed) => (t.button_pressed, t.button_glyph, t.button_text),
        };
        self.push(Op::Round(button, s.pxf(6.0), fill));
        let icon = Rect::new(button.x + s.px(14.0), button.y, s.px(16.0), button.h);
        self.icon(icons::PLUS, icon, 16.0, glyph);
        let x = icon.right() + s.px(8.0);
        let text = Rect::new(x, button.y, button.right() - s.px(14.0) - x, button.h);
        self.text(Font::BodyStrong, label, text, ink);
        if enabled {
            self.target(button, zone);
        }
    }

    fn stop(&mut self, button: Rect) {
        self.outlined(button, icons::STOP, STOP_LABEL, Zone::StopAgent);
    }

    fn outlined(&mut self, button: Rect, icon: Icon, label: &'static str, zone: Zone) {
        let (s, t) = (self.s, self.t);
        let fill = match self.v.pointer.look(zone) {
            Look::Rest => t.card,
            Look::Hover => t.caption_hover,
            Look::Pressed => t.caption_pressed,
        };
        self.framed(button, 6.0, fill);
        let glyph = Rect::new(button.x + s.px(14.0), button.y, s.px(16.0), button.h);
        self.icon(icon, glyph, 16.0, t.text);
        let x = glyph.right() + s.px(8.0);
        let text = Rect::new(x, button.y, button.right() - s.px(14.0) - x, button.h);
        self.text(Font::BodyStrong, label, text, t.text);
        self.target(button, zone);
    }

    fn columns(&self, row: Rect) -> Columns {
        let s = self.s;
        let gap = s.px(16.0);
        let right = row.right() - s.px(16.0);
        let column = |right: i32, w: f32| Rect::new(right - s.px(w), row.y, s.px(w), row.h);
        let actions = column(right, 64.0);
        let activity = column(actions.x - gap, 70.0);
        let uptime = column(activity.x - gap, 80.0);
        let gateway = column(uptime.x - gap, 210.0);
        let x = row.x + s.px(72.0);
        Columns {
            session: Rect::new(x, row.y, (gateway.x - gap - x).max(0), row.h),
            gateway,
            uptime,
            activity,
            actions,
        }
    }

    fn rule(&mut self, table: Rect, bottom: i32) {
        let edge = self.s.hairline();
        let line = Rect::new(table.x + edge, bottom - edge, table.w - 2 * edge, edge);
        self.push(Op::Fill(line, self.t.border));
    }

    fn table(&mut self, top: Rect, rows: &[Row]) {
        let (s, t) = (self.s, self.t);
        let (header_h, row_h) = (s.px(36.0), s.px(60.0));
        let lines = rows.len().max(1) as i32;
        let height = header_h + lines * row_h;
        let view = Rect::new(top.x, top.y, top.w, (self.clip.bottom() - top.y).max(0));
        let offset = self.scroll(view, height);
        let table = Rect::new(top.x, top.y - offset, top.w, height);
        self.framed(table, 10.0, t.card);
        let header = Rect::new(table.x, table.y, table.w, header_h);
        let c = self.columns(header);
        for (label, col) in [
            ("Session", c.session),
            ("Gateway", c.gateway),
            ("Uptime", c.uptime),
            ("Activity", c.activity),
        ] {
            self.text(Font::Small, label, col, t.muted);
        }
        self.rule(table, header.bottom());
        if rows.is_empty() {
            let pad = s.px(16.0);
            let r = Rect::new(table.x + pad, header.bottom(), table.w - 2 * pad, row_h);
            self.text(Font::Body, EMPTY, r, t.muted);
            return;
        }
        for (i, row) in rows.iter().enumerate() {
            let r = Rect::new(table.x, header.bottom() + i as i32 * row_h, table.w, row_h);
            if r.bottom() <= view.y || r.y >= view.bottom() {
                self.unseen(|p| p.row(r, row));
                continue;
            }
            self.row(r, row);
            if i + 1 < rows.len() {
                self.rule(table, r.bottom());
            }
        }
    }

    fn row(&mut self, r: Rect, row: &Row) {
        let (s, t) = (self.s, self.t);
        let c = self.columns(r);
        let tile = s.px(40.0);
        let tile = Rect::new(r.x + s.px(16.0), r.y + (r.h - tile) / 2, tile, tile);
        self.push(Op::Round(tile, s.pxf(10.0), t.tile));
        let icon = match row.kind {
            Kind::Browser => icons::GLOBE,
            Kind::Device => icons::DEVICE,
        };
        self.icon(icon, tile, 20.0, t.text);

        let line1 = |col: Rect| Rect::new(col.x, r.y + s.px(11.0), col.w, s.px(20.0));
        let line2 = |col: Rect| Rect::new(col.x, r.y + s.px(31.0), col.w, s.px(18.0));

        let first = line1(c.session);
        let w = self.m.width(Font::BodyStrong, row.title).min(first.w);
        self.text(Font::BodyStrong, row.title, Rect { w, ..first }, t.text);
        let number = Rect::new(first.x + w, first.y, first.w - w, first.h);
        self.text(Font::Small, row.number.clone(), number, t.muted);
        self.text(Font::Small, row.auth, line2(c.session), t.muted);

        let first = line1(c.gateway);
        let (pill_pad, pill_gap) = (s.px(7.0), s.px(6.0));
        let pill_w = self.m.width(Font::Pill, row.route) + 2 * pill_pad;
        let room = (first.w - pill_gap - pill_w).max(0);
        let w = self.m.width(Font::BodyStrong, &row.gateway).min(room);
        self.text(
            Font::BodyStrong,
            row.gateway.clone(),
            Rect { w, ..first },
            t.text,
        );
        let pill_h = s.px(16.0);
        let x = first.x + w + pill_gap;
        let pill = Rect::new(
            x,
            first.y + (first.h - pill_h) / 2,
            pill_w.min(first.right() - x),
            pill_h,
        );
        self.push(Op::Round(pill, s.pxf(8.0), t.tile));
        let route = Rect::new(pill.x + pill_pad, pill.y, pill.w - 2 * pill_pad, pill.h);
        self.text(Font::Pill, row.route, route, t.pill_text);
        self.text(Font::Mono, row.address.clone(), line2(c.gateway), t.muted);

        self.text(Font::Body, row.uptime.clone(), c.uptime, t.text);

        let (dot_w, dot_h, dot_gap) = (s.px(5.0), s.px(7.0), s.px(4.0));
        let dot = if row.active { t.accent } else { t.eyes_idle };
        let radius = s.pxf(3.0).min(dot_w as f32 / 2.0);
        let y = r.y + (r.h - dot_h) / 2;
        for i in 0..2 {
            let x = c.activity.x + i * (dot_w + dot_gap);
            self.push(Op::Round(Rect::new(x, y, dot_w, dot_h), radius, dot));
        }
        let x = c.activity.x + 2 * dot_w + dot_gap + s.px(8.0);
        let label = if row.active { "Active" } else { "Idle" };
        let state = Rect::new(x, r.y, c.activity.right() - x, r.h);
        self.text(Font::Small, label, state, t.muted);

        let size = s.px(32.0);
        let y = c.actions.y + (c.actions.h - size) / 2;
        self.revoke(Rect::new(c.actions.x, y, size, size), row.id);
        self.more(Rect::new(c.actions.right() - size, y, size, size), row.id);
    }

    fn more(&mut self, button: Rect, id: u64) {
        let (s, t) = (self.s, self.t);
        let zone = Zone::More(id);
        let (fill, ink) = match self.v.pointer.look(zone) {
            Look::Rest => (None, t.muted),
            Look::Hover => (Some(t.caption_hover), t.text),
            Look::Pressed => (Some(t.caption_pressed), t.text),
        };
        if let Some(fill) = fill {
            self.push(Op::Round(button, s.pxf(6.0), fill));
        }
        self.icon(icons::MORE, button, 18.0, ink);
        let before = self.board.targets.len();
        self.target(button, zone);
        if self.board.targets.len() > before && self.v.popup == Some(Popup::Session(id)) {
            self.board.anchor = Some(button);
        }
    }

    fn revoke(&mut self, button: Rect, id: u64) {
        let (s, t) = (self.s, self.t);
        let zone = Zone::Revoke(id);
        let (fill, ink) = match self.v.pointer.look(zone) {
            Look::Rest => (None, t.muted),
            Look::Hover => (Some(t.revoke_hover), t.revoke_glyph),
            Look::Pressed => (Some(t.revoke_pressed), t.revoke_glyph),
        };
        if let Some(fill) = fill {
            self.push(Op::Round(button, s.pxf(6.0), fill));
        }
        self.icon(icons::POWER, button, 18.0, ink);
        self.target(button, zone);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fonts::Font;
    use crate::icons;
    use crate::menu::Popup;
    use crate::nav::{Nav, Page as NavPage};
    use crate::scroll::Pane;
    use crate::sessions::{EMPTY, Eyes, Kind, Launch, Row, Status};

    const T: Theme = Theme::LIGHT;
    const S: Scale = Scale { dpi: 96 };
    const STOP: Rect = Rect::new(870, 110, 122, 32);
    pub(super) const PICK: Rect = Rect::new(711, 110, 143, 32);
    const FIRST_ROW: i32 = 264;

    pub(super) struct Chars;

    impl Measure for Chars {
        fn width(&self, _font: Font, text: &str) -> i32 {
            7 * text.chars().count() as i32
        }
    }

    pub(super) fn layout() -> Layout {
        Layout::new(1040, 680, S, true)
    }

    #[test]
    fn revoke_and_more_buttons_get_their_own_tips() {
        let a = Rect::new(1, 2, 3, 4);
        let b = Rect::new(5, 6, 7, 8);
        let targets = [
            (a, Zone::StopAgent),
            (b, Zone::Revoke(9)),
            (a, Zone::More(9)),
            (a, Zone::Revoke(3)),
        ];
        assert_eq!(
            tips(&targets),
            [(b, "Revoke session"), (a, "More"), (a, "Revoke session")]
        );
    }

    #[test]
    fn the_password_toggle_says_what_it_does() {
        let r = Rect::new(1, 2, 3, 4);
        let targets = [
            (r, Zone::TogglePassword(false)),
            (r, Zone::TogglePassword(true)),
        ];
        assert_eq!(tips(&targets), [(r, "Show password"), (r, "Hide password")]);
    }

    #[test]
    fn an_open_menu_hides_the_tips() {
        let r = Rect::new(1, 2, 3, 4);
        let targets = [(r, Zone::Entry(0)), (r, Zone::Menu), (r, Zone::Revoke(9))];
        assert_eq!(tips(&targets), []);
    }

    fn running(rows: Vec<Row>) -> Page {
        let active = rows.iter().any(|r| r.active);
        Page {
            status: Status {
                title: if active { "Relaying" } else { "Idle" },
                subtitle: "Agent running on loopback only · 1 session · 1 active".to_owned(),
                eyes: if active { Eyes::Lit } else { Eyes::Dim },
                stop: true,
                launch: Launch::Ready,
            },
            rows: Some(rows),
        }
    }

    fn stopped() -> Page {
        Page {
            status: Status {
                title: "Stopped",
                subtitle: "The agent is not running".to_owned(),
                eyes: Eyes::Closed,
                stop: false,
                launch: Launch::Hidden,
            },
            rows: None,
        }
    }

    fn row(id: u64) -> Row {
        Row {
            id,
            kind: Kind::Browser,
            title: "Chrome",
            number: format!(" #{id}"),
            auth: "OS user",
            gateway: "edge.example".to_owned(),
            route: "All",
            address: "edge.example".to_owned(),
            uptime: "5 min".to_owned(),
            active: true,
        }
    }

    fn draw_with(page: &Page, v: &View) -> Board {
        board(&layout(), S, &T, v, page, &Chars)
    }

    fn draw(page: &Page) -> Board {
        draw_with(page, &View::default())
    }

    pub(super) fn inside(ops: &[Op], r: Rect) -> Vec<Op> {
        let within = |o: Rect| {
            o.x >= r.x && o.y >= r.y && o.right() <= r.right() && o.bottom() <= r.bottom()
        };
        ops.iter()
            .filter(|op| match op {
                Op::Fill(o, _)
                | Op::Shade(o, ..)
                | Op::Round(o, ..)
                | Op::Icon(_, o, ..)
                | Op::Text(_, _, o, _)
                | Op::Logo(o, _)
                | Op::Ring(o, ..) => within(*o),
                Op::Clip(_) | Op::Unclip => false,
            })
            .cloned()
            .collect()
    }

    pub(super) fn text(font: Font, s: &str, r: Rect, c: crate::theme::Rgb) -> Op {
        Op::Text(font, s.to_owned().into(), r, c)
    }

    #[test]
    fn other_pages_draw_nothing() {
        let mut nav = Nav::default();
        nav.select(NavPage::Gateways);
        let v = View {
            nav,
            ..View::default()
        };
        assert_eq!(draw_with(&running(vec![row(1)]), &v), Board::default());
    }

    #[test]
    fn the_status_card_shows_the_logo_title_and_subtitle_inside_the_content_clip() {
        let l = layout();
        let ops = draw(&running(vec![row(1)])).ops;
        assert_eq!(ops.first(), Some(&Op::Clip(l.content)));
        assert_eq!(ops.last(), Some(&Op::Unclip));
        assert_eq!(
            ops[1..6],
            [
                Op::Round(Rect::new(248, 80, 764, 92), 12.0, T.border),
                Op::Round(Rect::new(249, 81, 762, 90), 11.0, T.card),
                Op::Logo(Rect::new(268, 98, 56, 56), Some(T.accent)),
                text(
                    Font::Status,
                    "Relaying",
                    Rect::new(340, 102, 355, 28),
                    T.text
                ),
                text(
                    Font::Body,
                    "Agent running on loopback only · 1 session · 1 active",
                    Rect::new(340, 132, 355, 18),
                    T.muted
                ),
            ]
        );
    }

    #[test]
    fn the_logo_eyes_follow_the_status() {
        let logo = |page: &Page| {
            draw(page)
                .ops
                .into_iter()
                .find_map(|op| match op {
                    Op::Logo(_, eyes) => Some(eyes),
                    _ => None,
                })
                .unwrap()
        };
        assert_eq!(logo(&running(vec![row(1)])), Some(T.accent));
        let mut idle = row(1);
        idle.active = false;
        assert_eq!(logo(&running(vec![idle])), Some(T.eyes_idle));
        assert_eq!(logo(&stopped()), None);
    }

    #[test]
    fn a_stopped_agent_has_a_wide_subtitle_and_no_button_heading_or_table() {
        let b = draw(&stopped());
        assert!(b.targets.is_empty());
        assert_eq!(
            b.ops[4..],
            [
                text(
                    Font::Status,
                    "Stopped",
                    Rect::new(340, 102, 652, 28),
                    T.text
                ),
                text(
                    Font::Body,
                    "The agent is not running",
                    Rect::new(340, 132, 652, 18),
                    T.muted
                ),
                Op::Unclip,
            ]
        );
    }

    #[test]
    fn the_stop_button_has_a_border_icon_and_label() {
        let b = draw(&running(vec![]));
        assert_eq!(b.targets, [(PICK, Zone::Picker), (STOP, Zone::StopAgent)]);
        assert_eq!(
            inside(&b.ops, STOP),
            [
                Op::Round(STOP, 6.0, T.border),
                Op::Round(Rect::new(871, 111, 120, 30), 5.0, T.card),
                Op::Icon(icons::STOP, Rect::new(884, 118, 16, 16), 1.0, T.text),
                text(
                    Font::BodyStrong,
                    "Stop agent",
                    Rect::new(908, 110, 70, 32),
                    T.text
                ),
            ]
        );
    }

    fn busy() -> Page {
        let mut page = running(vec![]);
        page.status.launch = Launch::Busy;
        page
    }

    #[test]
    fn the_start_browser_button_sits_left_of_stop_agent() {
        let b = draw(&running(vec![]));
        assert_eq!(
            inside(&b.ops, PICK),
            [
                Op::Round(PICK, 6.0, T.button),
                Op::Icon(icons::PLUS, Rect::new(725, 118, 16, 16), 1.0, T.accent),
                text(
                    Font::BodyStrong,
                    "Start browser",
                    Rect::new(749, 110, 91, 32),
                    T.button_text
                ),
            ]
        );
    }

    #[test]
    fn the_start_browser_button_is_disabled_while_a_launch_is_in_flight() {
        let b = draw(&busy());
        assert_eq!(b.targets, [(STOP, Zone::StopAgent)]);
        assert_eq!(
            inside(&b.ops, PICK),
            [
                Op::Round(PICK, 6.0, T.tile),
                Op::Icon(icons::PLUS, Rect::new(725, 118, 16, 16), 1.0, T.eyes_idle),
                text(
                    Font::BodyStrong,
                    "Start browser",
                    Rect::new(749, 110, 91, 32),
                    T.eyes_idle
                ),
            ]
        );
    }

    #[test]
    fn the_start_browser_button_tints_on_hover_and_press() {
        let fill = |v: &View| inside(&draw_with(&running(vec![]), v).ops, PICK)[0].clone();
        let mut v = View::default();
        v.pointer.moved(Zone::Picker);
        assert_eq!(fill(&v), Op::Round(PICK, 6.0, T.button_hover));
        v.pointer.down(Zone::Picker);
        assert_eq!(fill(&v), Op::Round(PICK, 6.0, T.button_pressed));
    }

    #[test]
    fn an_open_picker_hangs_from_an_enabled_start_browser_button() {
        let open = View {
            popup: Some(Popup::Picker),
            ..View::default()
        };
        assert_eq!(draw_with(&running(vec![]), &open).anchor, Some(PICK));
        assert_eq!(draw(&running(vec![])).anchor, None);
        assert_eq!(draw_with(&busy(), &open).anchor, None);
        assert_eq!(draw_with(&stopped(), &open).anchor, None);
    }

    #[test]
    fn the_stop_button_tints_on_hover_and_press() {
        let fill = |v: &View| inside(&draw_with(&running(vec![]), v).ops, STOP)[1].clone();
        let mut v = View::default();
        v.pointer.moved(Zone::StopAgent);
        assert_eq!(
            fill(&v),
            Op::Round(Rect::new(871, 111, 120, 30), 5.0, T.caption_hover)
        );
        v.pointer.down(Zone::StopAgent);
        assert_eq!(
            fill(&v),
            Op::Round(Rect::new(871, 111, 120, 30), 5.0, T.caption_pressed)
        );
    }

    #[test]
    fn the_table_has_a_heading_and_column_headers() {
        let ops = draw(&running(vec![row(1)])).ops;
        assert!(ops.contains(&text(
            Font::Heading,
            "Sessions",
            Rect::new(248, 190, 764, 20),
            T.text
        )));
        let header = Rect::new(248, 228, 764, 36);
        assert_eq!(
            inside(&ops, header),
            [
                text(
                    Font::Small,
                    "Session",
                    Rect::new(320, 228, 188, 36),
                    T.muted
                ),
                text(
                    Font::Small,
                    "Gateway",
                    Rect::new(524, 228, 210, 36),
                    T.muted
                ),
                text(Font::Small, "Uptime", Rect::new(750, 228, 80, 36), T.muted),
                text(
                    Font::Small,
                    "Activity",
                    Rect::new(846, 228, 70, 36),
                    T.muted
                ),
                Op::Fill(Rect::new(249, 263, 762, 1), T.border),
            ]
        );
        let card = Rect::new(248, 228, 764, 96);
        assert!(ops.contains(&Op::Round(card, 10.0, T.border)));
        assert!(ops.contains(&Op::Round(Rect::new(249, 229, 762, 94), 9.0, T.card)));
    }

    #[test]
    fn a_row_shows_its_session_gateway_uptime_activity_and_revoke_button() {
        let ops = draw(&running(vec![row(12)])).ops;
        let y = FIRST_ROW;
        assert_eq!(
            inside(&ops, Rect::new(248, y, 764, 60)),
            [
                Op::Round(Rect::new(264, y + 10, 40, 40), 10.0, T.tile),
                Op::Icon(icons::GLOBE, Rect::new(274, y + 20, 20, 20), 1.0, T.text),
                text(
                    Font::BodyStrong,
                    "Chrome",
                    Rect::new(320, y + 11, 42, 20),
                    T.text
                ),
                text(
                    Font::Small,
                    " #12",
                    Rect::new(362, y + 11, 146, 20),
                    T.muted
                ),
                text(
                    Font::Small,
                    "OS user",
                    Rect::new(320, y + 31, 188, 18),
                    T.muted
                ),
                text(
                    Font::BodyStrong,
                    "edge.example",
                    Rect::new(524, y + 11, 84, 20),
                    T.text
                ),
                Op::Round(Rect::new(614, y + 13, 35, 16), 8.0, T.tile),
                text(
                    Font::Pill,
                    "All",
                    Rect::new(621, y + 13, 21, 16),
                    T.pill_text
                ),
                text(
                    Font::Mono,
                    "edge.example",
                    Rect::new(524, y + 31, 210, 18),
                    T.muted
                ),
                text(Font::Body, "5 min", Rect::new(750, y, 80, 60), T.text),
                Op::Round(Rect::new(846, y + 26, 5, 7), 2.5, T.accent),
                Op::Round(Rect::new(855, y + 26, 5, 7), 2.5, T.accent),
                text(Font::Small, "Active", Rect::new(868, y, 48, 60), T.muted),
                Op::Icon(icons::POWER, Rect::new(939, y + 21, 18, 18), 1.0, T.muted),
                Op::Icon(icons::MORE, Rect::new(971, y + 21, 18, 18), 1.0, T.muted),
            ]
        );
    }

    #[test]
    fn device_rows_use_the_device_icon_and_idle_rows_grey_pills() {
        let mut device = row(3);
        device.kind = Kind::Device;
        device.active = false;
        let ops = draw(&running(vec![device])).ops;
        let row = inside(&ops, Rect::new(248, FIRST_ROW, 764, 60));
        assert!(matches!(row[1], Op::Icon(icon, ..) if icon == icons::DEVICE));
        assert_eq!(
            row[10],
            Op::Round(Rect::new(846, FIRST_ROW + 26, 5, 7), 2.5, T.eyes_idle)
        );
        assert_eq!(
            row[12],
            text(
                Font::Small,
                "Idle",
                Rect::new(868, FIRST_ROW, 48, 60),
                T.muted
            )
        );
    }

    #[test]
    fn rows_are_separated_but_the_last_has_no_border() {
        let ops = draw(&running(vec![row(1), row(2)])).ops;
        let border = |y| Op::Fill(Rect::new(249, y, 762, 1), T.border);
        assert!(ops.contains(&border(FIRST_ROW + 59)));
        assert!(!ops.contains(&border(FIRST_ROW + 119)));
    }

    #[test]
    fn every_row_has_a_revoke_target_that_tints_red() {
        let b = draw(&running(vec![row(1), row(2)]));
        let button = |i: i32| Rect::new(932, FIRST_ROW + 60 * i + 14, 32, 32);
        let more = |i: i32| Rect::new(964, FIRST_ROW + 60 * i + 14, 32, 32);
        assert_eq!(
            b.targets,
            [
                (PICK, Zone::Picker),
                (STOP, Zone::StopAgent),
                (button(0), Zone::Revoke(1)),
                (more(0), Zone::More(1)),
                (button(1), Zone::Revoke(2)),
                (more(1), Zone::More(2)),
            ]
        );
        let mut v = View::default();
        v.pointer.moved(Zone::Revoke(2));
        let glyph = Op::Icon(
            icons::POWER,
            Rect::new(939, FIRST_ROW + 81, 18, 18),
            1.0,
            T.revoke_glyph,
        );
        let page = running(vec![row(1), row(2)]);
        assert_eq!(
            inside(&draw_with(&page, &v).ops, button(1)),
            [Op::Round(button(1), 6.0, T.revoke_hover), glyph.clone()]
        );
        v.pointer.down(Zone::Revoke(2));
        assert_eq!(
            inside(&draw_with(&page, &v).ops, button(1)),
            [Op::Round(button(1), 6.0, T.revoke_pressed), glyph]
        );
    }

    #[test]
    fn every_row_has_a_more_button_that_tints_on_hover_and_press() {
        let page = running(vec![row(1), row(2)]);
        let more = Rect::new(964, FIRST_ROW + 74, 32, 32);
        let glyph = |c| Op::Icon(icons::MORE, Rect::new(971, FIRST_ROW + 81, 18, 18), 1.0, c);
        let mut v = View::default();
        v.pointer.moved(Zone::More(2));
        assert_eq!(
            inside(&draw_with(&page, &v).ops, more),
            [Op::Round(more, 6.0, T.caption_hover), glyph(T.text)]
        );
        v.pointer.down(Zone::More(2));
        assert_eq!(
            inside(&draw_with(&page, &v).ops, more),
            [Op::Round(more, 6.0, T.caption_pressed), glyph(T.text)]
        );
    }

    #[test]
    fn an_open_session_menu_hangs_from_its_more_button() {
        let page = running(vec![row(1), row(2)]);
        let open = |id| View {
            popup: Some(Popup::Session(id)),
            ..View::default()
        };
        assert_eq!(
            draw_with(&page, &open(2)).anchor,
            Some(Rect::new(964, FIRST_ROW + 74, 32, 32))
        );
        assert_eq!(draw_with(&page, &open(7)).anchor, None);
        assert_eq!(draw_with(&stopped(), &open(2)).anchor, None);
    }

    #[test]
    fn a_session_menu_closes_when_its_row_scrolls_out_of_view() {
        let page = running((1..=9).map(row).collect());
        let mut v = scrolled(148);
        v.popup = Some(Popup::Session(1));
        assert_eq!(draw_with(&page, &v).anchor, None);
        v.popup = Some(Popup::Session(9));
        assert_eq!(
            draw_with(&page, &v).anchor,
            Some(Rect::new(964, 610, 32, 32))
        );
    }

    #[test]
    fn an_empty_list_says_how_to_start_a_session() {
        let ops = draw(&running(vec![])).ops;
        assert_eq!(
            inside(&ops, Rect::new(248, FIRST_ROW, 764, 60)),
            [text(
                Font::Body,
                EMPTY,
                Rect::new(264, FIRST_ROW, 732, 60),
                T.muted
            )]
        );
        assert!(ops.contains(&Op::Round(Rect::new(248, 228, 764, 96), 10.0, T.border)));
    }

    #[test]
    fn long_text_is_given_only_its_column() {
        let mut long = row(1);
        long.gateway = "a-very-long-gateway-name.example.com".to_owned();
        let ops = draw(&running(vec![long])).ops;
        let row = inside(&ops, Rect::new(248, FIRST_ROW, 764, 60));
        assert_eq!(
            row[5],
            text(
                Font::BodyStrong,
                "a-very-long-gateway-name.example.com",
                Rect::new(524, FIRST_ROW + 11, 169, 20),
                T.text
            )
        );
        assert_eq!(
            row[6],
            Op::Round(Rect::new(699, FIRST_ROW + 13, 35, 16), 8.0, T.tile)
        );
    }

    #[test]
    fn the_focus_order_keeps_rows_outside_the_view() {
        let rows = (1..=9).map(row).collect();
        let b = draw(&running(rows));
        let zones: Vec<_> = b.order.iter().map(|stop| stop.zone).collect();
        let buttons: Vec<_> = (1..=9)
            .flat_map(|id| [Zone::Revoke(id), Zone::More(id)])
            .collect();
        assert_eq!(zones[..2], [Zone::Picker, Zone::StopAgent]);
        assert_eq!(zones[2..], buttons[..]);
        assert!(!b.order[0].scrolls);
        let last = b.order.last().unwrap();
        assert!(last.scrolls);
        assert_eq!(Some(last.clip), b.pane.map(|pane| pane.view));
        assert_eq!(last.rect, Rect::new(964, 638 + 2 * 60, 32, 32));
        assert_eq!(b.targets.len(), 16);
    }

    #[test]
    fn rows_below_the_content_are_clipped_and_lose_their_targets() {
        let rows = (1..=9).map(row).collect();
        let b = draw(&running(rows));
        let ids: Vec<_> = b.targets.iter().map(|(_, z)| *z).collect();
        let buttons: Vec<_> = (1..=7)
            .flat_map(|id| [Zone::Revoke(id), Zone::More(id)])
            .collect();
        assert_eq!(ids[2..], buttons[..]);
        assert_eq!(b.targets[14].0, Rect::new(932, 638, 32, 18));
        assert_eq!(b.targets[15].0, Rect::new(964, 638, 32, 18));
        assert!(
            !b.ops
                .iter()
                .any(|op| matches!(op, Op::Text(_, s, ..) if s == " #8"))
        );
    }

    fn scrolled(offset: i32) -> View {
        let mut v = View::default();
        v.scroll.set(NavPage::Sessions, offset);
        v
    }

    const TABLE_VIEW: Rect = Rect::new(248, 228, 764, 428);

    #[test]
    fn the_table_scrolls_in_a_viewport_under_the_heading() {
        let page = running((1..=9).map(row).collect());
        let b = draw(&page);
        assert_eq!(b.pane, Some(Pane::new(TABLE_VIEW, 576, 0)));
        assert!(b.ops.contains(&Op::Clip(TABLE_VIEW)));
        let b = draw_with(&page, &scrolled(120));
        assert_eq!(b.pane, Some(Pane::new(TABLE_VIEW, 576, 120)));
        assert!(
            b.ops
                .contains(&Op::Round(Rect::new(248, 108, 764, 576), 10.0, T.border))
        );
        assert!(
            !b.ops
                .iter()
                .any(|op| matches!(op, Op::Text(_, s, ..) if s == " #1"))
        );
        assert_eq!(
            b.targets[2..6],
            [
                (Rect::new(932, 228, 32, 22), Zone::Revoke(2)),
                (Rect::new(964, 228, 32, 22), Zone::More(2)),
                (Rect::new(932, 278, 32, 32), Zone::Revoke(3)),
                (Rect::new(964, 278, 32, 32), Zone::More(3)),
            ]
        );
    }

    #[test]
    fn the_offset_is_clamped_to_the_table() {
        let b = draw_with(&running((1..=9).map(row).collect()), &scrolled(10_000));
        assert_eq!(b.pane.map(|p| p.offset), Some(148));
        let b = draw_with(&running(vec![row(1)]), &scrolled(50));
        assert_eq!(b.pane.map(|p| p.offset), Some(0));
        assert_eq!(draw_with(&stopped(), &scrolled(50)).pane, None);
    }

    #[test]
    fn an_overflowing_table_gets_a_thin_scrollbar_in_the_gutter() {
        let page = running((1..=9).map(row).collect());
        let thumb = |v: &View| draw_with(&page, v).ops.last().cloned();
        assert_eq!(
            thumb(&View::default()),
            Some(Op::Round(Rect::new(1024, 228, 4, 318), 2.0, T.eyes_idle))
        );
        assert_eq!(
            thumb(&scrolled(148)),
            Some(Op::Round(Rect::new(1024, 338, 4, 318), 2.0, T.eyes_idle))
        );
        assert_eq!(draw(&running(vec![row(1)])).ops.last(), Some(&Op::Unclip));
    }

    #[test]
    fn sizes_scale_with_dpi() {
        let s = Scale::new(192);
        let l = Layout::new(2080, 1360, s, true);
        let b = board(&l, s, &T, &View::default(), &running(vec![row(1)]), &Chars);
        assert_eq!(
            b.ops[1],
            Op::Round(Rect::new(496, 160, 1528, 184), 24.0, T.border)
        );
        assert_eq!(
            b.ops[2],
            Op::Round(Rect::new(498, 162, 1524, 180), 22.0, T.card)
        );
        assert_eq!(
            b.ops[3],
            Op::Logo(Rect::new(536, 196, 112, 112), Some(T.accent))
        );
        assert_eq!(b.targets[2].0.w, 64);
    }
}
