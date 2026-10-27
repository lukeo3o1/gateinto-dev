use std::borrow::Cow;

use super::{Board, Painter};
use crate::credentials::{Field, HINT, Page, SUBTITLE};
use crate::fonts::{Font, Measure};
use crate::hit::Zone;
use crate::icons::{self, Icon};
use crate::layout::{Layout, Rect};
use crate::pointer::Look;
use crate::scale::Scale;
use crate::scene::{Op, View};
use crate::theme::{Rgb, Theme};

pub const SHADE: f32 = 0.32;
const TITLE: &str = "Session credentials";
const REVOKE: &str = "Revoke session";
const CLOSE: &str = "Close";

pub fn wrap(m: &impl Measure, font: Font, text: &str, width: i32) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && m.width(font, &format!("{line} {word}")) > width {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

pub struct Modal<'a, M> {
    p: Painter<'a, M>,
    panel: Rect,
    inside: Rect,
    footer: Rect,
    inner: Rect,
}

fn client(l: &Layout) -> Rect {
    Rect::new(0, 0, l.caption_row.right(), l.rail.h)
}

fn width(l: &Layout, s: Scale) -> i32 {
    s.px(520.0).min(l.content.w) - 2 * s.px(24.0)
}

impl<'a, M: Measure> Modal<'a, M> {
    pub fn open(l: &Layout, s: Scale, t: &'a Theme, v: &'a View, m: &'a M, body: i32) -> Self {
        let mut p = Painter::within(client(l), s, t, v, m);
        p.push(Op::Shade(client(l), t.text, SHADE));
        let (top, gap, footer_h) = (s.px(20.0), s.px(16.0), s.px(56.0));
        let w = s.px(520.0).min(l.content.w);
        let area_y = l.caption_row.bottom();
        let area_h = l.rail.h - area_y - s.px(16.0);
        let h = (top + body + gap + footer_h).min(area_h);
        let panel = Rect::new(
            l.content.x + (l.content.w - w) / 2,
            area_y + (area_h - h) / 2,
            w,
            h,
        );
        p.framed(panel, 10.0, t.bg);
        let edge = s.hairline();
        let inside = Rect::new(
            panel.x + edge,
            panel.y + edge,
            panel.w - 2 * edge,
            panel.h - 2 * edge,
        );
        let footer = Rect::new(inside.x, inside.bottom() - footer_h, inside.w, footer_h);
        p.push(Op::Clip(inside));
        let body_area = Rect::new(inside.x, inside.y, inside.w, footer.y - inside.y);
        p.push(Op::Clip(body_area));
        p.clip = body_area;
        let pad = (w - width(l, s)) / 2;
        let inner = Rect::new(panel.x + pad, panel.y + top, w - 2 * pad, body);
        Self {
            p,
            panel,
            inside,
            footer,
            inner,
        }
    }

    fn close(mut self, board: &mut Board, buttons: impl FnOnce(&mut Painter<'a, M>, Rect)) {
        let (s, t, footer) = (self.p.s, self.p.t, self.footer);
        self.p.push(Op::Unclip);
        self.p.clip = self.inside;
        self.p.push(Op::Fill(footer, t.card));
        let rule = Rect::new(footer.x, footer.y, footer.w, s.hairline());
        self.p.push(Op::Fill(rule, t.border));
        buttons(&mut self.p, footer);
        self.p.target(self.panel, Zone::Dialog);
        self.p.push(Op::Unclip);
        self.p.push(Op::Unclip);
        board.ops.append(&mut self.p.board.ops);
        board.targets = self.p.board.targets;
        board.anchor = None;
        board.popup = None;
    }
}

const ROW: f32 = 34.0;
const LABEL: f32 = 18.0;
const GAP: f32 = 12.0;
const CARD: f32 = 52.0;
const COPY_W: f32 = 96.0;

pub fn credentials(
    board: &mut Board,
    l: &Layout,
    s: Scale,
    t: &Theme,
    v: &View,
    page: &Page,
    m: &impl Measure,
) {
    let w = width(l, s);
    let subtitle = wrap(m, Font::Body, SUBTITLE, w);
    let pad = s.px(10.0);
    let glyph = s.px(16.0);
    let warning = wrap(m, Font::Small, &page.warning, w - 3 * pad - glyph);
    let (line, small) = (s.px(18.0), s.px(16.0));
    let notice = 2 * pad + warning.len() as i32 * small;
    let (gap, label, row) = (s.px(GAP), s.px(LABEL), s.px(ROW));
    let body = s.px(28.0)
        + s.px(2.0)
        + subtitle.len() as i32 * line
        + gap
        + s.px(CARD)
        + gap
        + label
        + s.px(4.0)
        + row
        + gap
        + label
        + s.px(4.0)
        + row
        + s.px(4.0)
        + small
        + gap
        + notice;
    let mut modal = Modal::open(l, s, t, v, m, body);
    let inner = modal.inner;
    let p = &mut modal.p;
    let x = inner.x;
    p.text(
        Font::Title,
        TITLE,
        Rect::new(x, inner.y, w, s.px(28.0)),
        t.text,
    );
    let mut y = inner.y + s.px(30.0);
    for text in subtitle {
        p.text(Font::Body, text, Rect::new(x, y, w, line), t.muted);
        y += line;
    }
    y += gap;
    p.session(Rect::new(x, y, w, s.px(CARD)), page);
    y += s.px(CARD) + gap;

    p.text(
        Font::BodyStrong,
        "Username",
        Rect::new(x, y, w, label),
        t.text,
    );
    y += label + s.px(4.0);
    let copy_w = s.px(COPY_W);
    let field = Rect::new(x, y, w - copy_w - s.px(8.0), row);
    match page.note {
        Some(note) => p.field(field, note, Font::Small, t.muted),
        None => p.field(field, page.username.to_owned(), Font::Mono, t.text),
    }
    let copied = |f| page.copied == Some(f);
    let copy = Rect::new(field.right() + s.px(8.0), y, copy_w, row);
    p.copy_button(copy, Field::Username, copied(Field::Username), page.ready);
    y += row + gap;

    p.text(
        Font::BodyStrong,
        "Password",
        Rect::new(x, y, w, label),
        t.text,
    );
    y += label + s.px(4.0);
    let field = Rect::new(x, y, w - copy_w - row - 2 * s.px(8.0), row);
    p.field(field, page.password.to_owned(), Font::Mono, t.text);
    let toggle = Rect::new(field.right() + s.px(8.0), y, row, row);
    let eye = if page.revealed {
        icons::EYE_OFF
    } else {
        icons::EYE
    };
    p.square(toggle, eye, Zone::TogglePassword(page.revealed), page.ready);
    let copy = Rect::new(toggle.right() + s.px(8.0), y, copy_w, row);
    p.copy_button(copy, Field::Password, copied(Field::Password), page.ready);
    y += row + s.px(4.0);
    p.text(Font::Small, HINT, Rect::new(x, y, w, small), t.muted);
    y += small + gap;

    let r = Rect::new(x, y, w, notice);
    p.push(Op::Round(r, s.pxf(8.0), t.notice));
    let icon = Rect::new(x + pad, y + pad, glyph, small);
    p.icon(icons::LOCK, icon, 14.0, t.notice_text);
    let tx = icon.right() + pad;
    for (i, text) in warning.into_iter().enumerate() {
        let r = Rect::new(tx, y + pad + i as i32 * small, r.right() - pad - tx, small);
        p.text(Font::Small, text, r, t.notice_text);
    }

    modal.close(board, |p, footer| {
        p.footer_buttons(footer, Zone::RevokeCredentials, Zone::CloseDialog)
    });
}

impl<M: Measure> Painter<'_, M> {
    fn session(&mut self, r: Rect, page: &Page) {
        let (s, t) = (self.s, self.t);
        self.framed(r, 8.0, t.card);
        let tile = s.px(32.0);
        let tile = Rect::new(r.x + s.px(10.0), r.y + (r.h - tile) / 2, tile, tile);
        self.push(Op::Round(tile, s.pxf(8.0), t.tile));
        self.icon(icons::GLOBE, tile, 16.0, t.text);
        let x = tile.right() + s.px(12.0);
        let w = r.right() - s.px(12.0) - x;
        let top = r.y + (r.h - s.px(34.0)) / 2;
        let session = page.session.clone();
        self.text(
            Font::BodyStrong,
            session,
            Rect::new(x, top, w, s.px(18.0)),
            t.text,
        );
        let detail = Rect::new(x, top + s.px(18.0), w, s.px(16.0));
        self.text(Font::Small, page.detail.clone(), detail, t.muted);
    }

    fn primary(&mut self, button: Rect, label: &'static str, zone: Zone) {
        let (s, t) = (self.s, self.t);
        let fill = match self.v.pointer.look(zone) {
            Look::Rest => t.button,
            Look::Hover => t.button_hover,
            Look::Pressed => t.button_pressed,
        };
        self.push(Op::Round(button, s.pxf(6.0), fill));
        let pad = s.px(14.0);
        let text = Rect::new(button.x + pad, button.y, button.w - 2 * pad, button.h);
        self.text(Font::BodyStrong, label, text, t.button_text);
        self.target(button, zone);
    }

    fn square(&mut self, button: Rect, icon: Icon, zone: Zone, enabled: bool) {
        let t = self.t;
        let (fill, ink) = match (enabled, self.v.pointer.look(zone)) {
            (false, _) => (t.card, t.eyes_idle),
            (true, Look::Rest) => (t.card, t.text),
            (true, Look::Hover) => (t.caption_hover, t.text),
            (true, Look::Pressed) => (t.caption_pressed, t.text),
        };
        self.framed(button, 6.0, fill);
        self.icon(icon, button, 16.0, ink);
        if enabled {
            self.target(button, zone);
        }
    }

    fn copy_button(&mut self, button: Rect, field: Field, copied: bool, enabled: bool) {
        let label = if copied { "Copied" } else { "Copy" };
        if enabled {
            self.outlined(button, icons::COPY, label, Zone::CopyCredential(field));
            return;
        }
        let (s, t) = (self.s, self.t);
        self.framed(button, 6.0, t.card);
        let glyph = Rect::new(button.x + s.px(14.0), button.y, s.px(16.0), button.h);
        self.icon(icons::COPY, glyph, 16.0, t.eyes_idle);
        let x = glyph.right() + s.px(8.0);
        let text = Rect::new(x, button.y, button.right() - s.px(14.0) - x, button.h);
        self.text(Font::BodyStrong, label, text, t.eyes_idle);
    }

    fn field(&mut self, r: Rect, value: impl Into<Cow<'static, str>>, font: Font, ink: Rgb) {
        let s = self.s;
        self.framed(r, 6.0, self.t.field);
        let pad = s.px(10.0);
        self.text(
            font,
            value,
            Rect::new(r.x + pad, r.y, r.w - 2 * pad, r.h),
            ink,
        );
    }

    fn footer_buttons(&mut self, footer: Rect, revoke: Zone, close: Zone) {
        let s = self.s;
        let h = s.px(32.0);
        let y = footer.y + (footer.h - h) / 2;
        let pad = s.px(14.0);
        let close_w = 2 * pad + self.m.width(Font::BodyStrong, CLOSE);
        let close_r = Rect::new(footer.right() - s.px(24.0) - close_w, y, close_w, h);
        let revoke_w = 2 * pad + s.px(24.0) + self.m.width(Font::BodyStrong, REVOKE);
        let revoke_r = Rect::new(close_r.x - s.px(8.0) - revoke_w, y, revoke_w, h);
        self.outlined(revoke_r, icons::POWER, REVOKE, revoke);
        self.primary(close_r, CLOSE, close);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board::tests::{Chars, layout};
    use crate::credentials::{Field, MASK, Page, UNAVAILABLE, WAITING};
    use crate::hit::Zone;
    use crate::layout::Rect;
    use crate::scale::Scale;
    use crate::scene::{Op, View};
    use crate::theme::Theme;

    const T: Theme = Theme::LIGHT;
    const S: Scale = Scale { dpi: 96 };
    const PASSWORD: &str = "abcd-efgh-jkmn";

    fn page(password: &'static str, note: Option<&'static str>) -> Page<'static> {
        let ready = note.is_none();
        Page {
            session: "Chrome #3".to_owned(),
            detail: "office · proxy.example.com · sign-in dialog names 127.0.0.1:49210".to_owned(),
            username: if ready { "gateinto" } else { "" },
            password: if ready { password } else { "" },
            revealed: password == PASSWORD,
            ready,
            copied: None,
            note,
            warning: "Enter these only in the browser's proxy sign-in dialog that names \
                      127.0.0.1:49210. Never enter them in a website's sign-in page or dialog."
                .to_owned(),
        }
    }

    fn draw(page: &Page) -> Board {
        let mut board = Board {
            targets: vec![(Rect::new(900, 300, 32, 32), Zone::Revoke(3))],
            ..Board::default()
        };
        credentials(&mut board, &layout(), S, &T, &View::default(), page, &Chars);
        board
    }

    fn texts(board: &Board) -> Vec<String> {
        board
            .ops
            .iter()
            .filter_map(|op| match op {
                Op::Text(_, text, ..) => Some(text.to_string()),
                _ => None,
            })
            .collect()
    }

    fn zones(board: &Board) -> Vec<Zone> {
        board.targets.iter().map(|&(_, zone)| zone).collect()
    }

    #[test]
    fn lines_wrap_greedily_at_spaces() {
        assert_eq!(
            wrap(&Chars, Font::Small, "aa bb cc dd", 7 * 5),
            ["aa bb", "cc dd"]
        );
        assert_eq!(
            wrap(&Chars, Font::Small, "abcdefgh ij", 7 * 4),
            ["abcdefgh", "ij"]
        );
        assert_eq!(wrap(&Chars, Font::Small, "", 70), Vec::<String>::new());
    }

    #[test]
    fn the_dialog_shades_the_window_and_takes_over_the_targets() {
        let board = draw(&page(MASK, None));
        assert_eq!(
            board.ops[1],
            Op::Shade(Rect::new(0, 0, 1040, 680), T.text, SHADE)
        );
        assert_eq!(
            zones(&board),
            [
                Zone::CopyCredential(Field::Username),
                Zone::TogglePassword(false),
                Zone::CopyCredential(Field::Password),
                Zone::RevokeCredentials,
                Zone::CloseDialog,
                Zone::Dialog,
            ]
        );
        let panel = board.targets.last().unwrap().0;
        assert_eq!(panel.w, 520);
        assert_eq!(panel.x, 248 + (764 - 520) / 2);
        for &(r, _) in &board.targets {
            assert!(r.x >= panel.x && r.right() <= panel.right(), "{r:?}");
            assert!(r.y >= panel.y && r.bottom() <= panel.bottom(), "{r:?}");
        }
        assert_eq!(board.anchor, None);
    }

    #[test]
    fn the_password_is_drawn_masked_unless_revealed() {
        let masked = texts(&draw(&page(MASK, None)));
        assert!(masked.iter().any(|t| t == MASK));
        assert!(!masked.iter().any(|t| t.contains(PASSWORD)));
        assert!(masked.iter().any(|t| t == "gateinto"));
        let shown = draw(&page(PASSWORD, None));
        assert!(texts(&shown).iter().any(|t| t == PASSWORD));
        assert!(zones(&shown).contains(&Zone::TogglePassword(true)));
    }

    #[test]
    fn the_dialog_carries_its_labels_hint_and_warning() {
        let all = texts(&draw(&page(MASK, None))).join("\n");
        for part in [
            "Session credentials",
            "Chrome #3",
            "sign-in dialog names 127.0.0.1:49210",
            "Username",
            "Password",
            "Type it exactly, including the hyphens.",
            "Never enter them",
            "Revoke session",
            "Close",
            "Copy",
        ] {
            assert!(all.contains(part), "{part}");
        }
    }

    #[test]
    fn a_copied_field_says_so() {
        let mut copied = page(MASK, None);
        copied.copied = Some(Field::Password);
        let texts = texts(&draw(&copied));
        assert_eq!(texts.iter().filter(|t| *t == "Copied").count(), 1);
        assert_eq!(texts.iter().filter(|t| *t == "Copy").count(), 1);
    }

    #[test]
    fn without_credentials_only_the_note_and_the_footer_remain() {
        for note in [WAITING, UNAVAILABLE] {
            let board = draw(&page("", Some(note)));
            assert!(texts(&board).iter().any(|t| t == note));
            assert_eq!(
                zones(&board),
                [Zone::RevokeCredentials, Zone::CloseDialog, Zone::Dialog]
            );
        }
    }

    #[test]
    fn the_whole_dialog_fits_a_window_of_the_minimum_size() {
        let (w, h) = crate::layout::Layout::min_size(S);
        let l = crate::layout::Layout::new(w, h, S, true);
        let mut board = Board::default();
        let page = page(MASK, None);
        credentials(&mut board, &l, S, &T, &View::default(), &page, &Chars);
        let panel = board.targets.last().unwrap().0;
        assert!(
            panel.y >= l.caption_row.bottom() && panel.bottom() <= h,
            "{panel:?}"
        );
        assert!(panel.x >= l.content.x && panel.right() <= l.content.right());
        let field = board.targets[2].0;
        let footer = board.targets[3].0;
        assert_eq!(board.targets[2].1, Zone::CopyCredential(Field::Password));
        assert!(field.bottom() + 100 < footer.y, "{field:?} {footer:?}");
    }
}
