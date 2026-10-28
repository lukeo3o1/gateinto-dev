use super::settings::card_height;
use super::{Board, Painter};
use crate::device::{Computer, Gateway, KeyCard, Page, USED_WITH};
use crate::fonts::{Font, Measure};
use crate::gateways::EMPTY;
use crate::hit::Zone;
use crate::icons;
use crate::layout::{Layout, Rect};
use crate::nav::Page as NavPage;
use crate::scale::Scale;
use crate::scene::View;
use crate::theme::Theme;

pub fn board(l: &Layout, s: Scale, t: &Theme, v: &View, page: &Page, m: &impl Measure) -> Board {
    if v.nav.selected() != NavPage::Device {
        return Board::default();
    }
    let content = l.content;
    let header = Rect::new(
        content.x,
        l.title.y,
        content.w,
        content.bottom() - l.title.y,
    );
    let mut p = Painter::within(header, s, t, v, m);
    let line = Rect::new(content.x, content.y, content.w, s.px(18.0));
    let ink = if page.failed { t.warning } else { t.muted };
    p.text(Font::Body, page.subtitle.clone(), line, ink);

    let gap = s.px(14.0);
    let top = line.bottom() + gap;
    let view = Rect::new(content.x, top, content.w, (content.bottom() - top).max(0));
    let note = s.px(20.0);
    let key_note = if page.key.note.is_some() { note } else { 0 };
    let key_h = card_height(s, page.key.rows.len() as i32) + key_note;
    let computer_h = page.computer.as_ref().map(|c| {
        let account = if c.account.is_some() { note } else { 0 };
        card_height(s, c.rows.len() as i32) + account
    });
    let listed = page.gateways.as_ref().map_or(1, |g| g.len().max(1)) as i32;
    let gateways_h = card_height(s, listed);
    let total = key_h + computer_h.map_or(0, |h| h + gap) + gap + gateways_h;
    let offset = p.scroll(view, total);
    let mut card = Rect::new(content.x, top - offset, content.w, key_h);
    p.key(card, &page.key);
    if let (Some(computer), Some(h)) = (&page.computer, computer_h) {
        card = Rect::new(card.x, card.bottom() + gap, card.w, h);
        p.computer(card, computer);
    }
    card = Rect::new(card.x, card.bottom() + gap, card.w, gateways_h);
    p.gateways(card, &page.gateways);
    p.finish()
}

impl<M: Measure> Painter<'_, M> {
    fn note(&mut self, heading: Rect, note: String, alert: bool) -> Rect {
        let (s, t) = (self.s, self.t);
        let r = Rect::new(heading.x, heading.bottom(), heading.w, s.px(20.0));
        let ink = if alert { t.warning } else { t.muted };
        self.text(Font::Small, note, r, ink);
        Rect::new(heading.x, heading.y + r.h, heading.w, heading.h)
    }

    fn key(&mut self, card: Rect, key: &KeyCard) {
        let heading = self.section(card, key.title);
        if let Some(label) = key.copy {
            let button = self.button(heading, heading.right(), label);
            self.outlined(button, icons::COPY, label, Zone::CopyId);
        }
        let above = match &key.note {
            Some(note) => self.note(heading, note.clone(), key.alert),
            None => heading,
        };
        for (i, (label, value)) in key.rows.iter().enumerate() {
            let row = self.line(above, i as i32);
            let font = if *label == crate::device::DEVICE_ID {
                Font::Mono
            } else {
                Font::Body
            };
            self.pair(row, label, value.clone(), font);
        }
    }

    fn computer(&mut self, card: Rect, computer: &Computer) {
        let mut above = self.section(card, computer.name.clone());
        if let Some(account) = &computer.account {
            above = self.note(above, account.clone(), false);
        }
        for (i, (label, value)) in computer.rows.iter().enumerate() {
            let row = self.line(above, i as i32);
            self.pair(row, label, value.clone(), Font::Body);
        }
    }

    fn gateways(&mut self, card: Rect, gateways: &Result<Vec<Gateway>, String>) {
        let t = self.t;
        let heading = self.section(card, USED_WITH);
        match gateways {
            Ok(list) if list.is_empty() => {
                let row = self.line(heading, 0);
                self.text(Font::Body, EMPTY, row, t.muted);
            }
            Ok(list) => {
                for (i, gateway) in list.iter().enumerate() {
                    let row = self.line(heading, i as i32);
                    self.used(row, gateway);
                }
            }
            Err(error) => {
                let row = self.line(heading, 0);
                self.text(Font::Body, error.clone(), row, t.warning);
            }
        }
    }

    fn used(&mut self, row: Rect, gateway: &Gateway) {
        let (s, t) = (self.s, self.t);
        let w = self.m.width(Font::Mono, &gateway.address).min(row.w / 2);
        let address = Rect::new(row.right() - w, row.y, w, row.h);
        let (label, note) = (s.px(18.0), s.px(16.0));
        let y = row.y + (row.h - label - s.px(2.0) - note) / 2;
        let left = (address.x - s.px(16.0) - row.x).max(0);
        let name = Rect::new(row.x, y, left, label);
        self.text(Font::Body, gateway.label.clone(), name, t.text);
        let below = Rect::new(row.x, name.bottom() + s.px(2.0), left, note);
        self.text(Font::Small, gateway.source, below, t.muted);
        self.text(Font::Mono, gateway.address.clone(), address, t.muted);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board::tests::{Chars, inside, layout, text};
    use crate::device::{Computer, Gateway, KeyCard, SUBTITLE, USED_WITH};
    use crate::fonts::Font;
    use crate::gateways::EMPTY;
    use crate::hit::Zone;
    use crate::icons;
    use crate::layout::Rect;
    use crate::nav::{Nav, Page as NavPage};
    use crate::scene::{Op, stroke};
    use crate::scroll::Pane;

    const T: Theme = Theme::LIGHT;
    const S: Scale = Scale { dpi: 96 };
    const COPY_BUTTON: Rect = Rect::new(842, 122, 150, 32);
    const KEY: Rect = Rect::new(248, 112, 764, 252);
    const COMPUTER: Rect = Rect::new(248, 378, 764, 208);
    const GATEWAYS: Rect = Rect::new(248, 600, 764, 100);

    fn id() -> String {
        "ab".repeat(32)
    }

    fn page() -> Page {
        Page {
            subtitle: SUBTITLE.to_owned(),
            failed: false,
            key: KeyCard {
                title: "Hardware key",
                note: Some("Kept in this PC's TPM".to_owned()),
                alert: false,
                rows: vec![
                    (
                        "Storage",
                        "TPM (Microsoft Platform Crypto Provider)".to_owned(),
                    ),
                    ("Algorithm", "ECDSA P-256".to_owned()),
                    ("Key name", "Gateinto Device".to_owned()),
                    ("Device ID", id()),
                ],
                copy: Some("Copy device ID"),
            },
            computer: Some(Computer {
                name: "DESK-7".to_owned(),
                account: Some("Signed in as CORP\\ana".to_owned()),
                rows: vec![
                    ("System", "Windows 11 Pro \u{b7} x64".to_owned()),
                    ("Gateinto", "0.1.0".to_owned()),
                    ("Agent", "Loopback only".to_owned()),
                ],
            }),
            gateways: Ok(vec![Gateway {
                label: "Office".to_owned(),
                address: "proxy.example.com:443".to_owned(),
                source: "Config file",
            }]),
        }
    }

    fn reading() -> Page {
        Page {
            key: KeyCard {
                title: "Device key",
                note: Some("Reading the device key\u{2026}".to_owned()),
                alert: false,
                rows: Vec::new(),
                copy: None,
            },
            computer: None,
            ..page()
        }
    }

    fn view() -> View {
        let mut nav = Nav::default();
        nav.select(NavPage::Device);
        View {
            nav,
            ..View::default()
        }
    }

    fn draw_with(page: &Page, v: &View) -> Board {
        board(&layout(), S, &T, v, page, &Chars)
    }

    fn draw(page: &Page) -> Board {
        draw_with(page, &view())
    }

    #[test]
    fn other_pages_draw_nothing() {
        assert_eq!(draw_with(&page(), &View::default()), Board::default());
    }

    #[test]
    fn the_subtitle_sits_under_the_title_and_the_cards_scroll_below() {
        let b = draw(&page());
        assert_eq!(
            b.ops[..3],
            [
                Op::Clip(Rect::new(248, 44, 764, 612)),
                text(Font::Body, SUBTITLE, Rect::new(248, 80, 764, 18), T.muted),
                Op::Clip(Rect::new(248, 112, 764, 544)),
            ]
        );
        assert_eq!(
            b.pane,
            Some(Pane::new(Rect::new(248, 112, 764, 544), 588, 0))
        );
    }

    #[test]
    fn a_failure_replaces_the_subtitle_as_a_warning() {
        let mut p = page();
        p.subtitle = "Could not reach the agent".to_owned();
        p.failed = true;
        assert_eq!(
            draw(&p).ops[1],
            text(
                Font::Body,
                "Could not reach the agent",
                Rect::new(248, 80, 764, 18),
                T.warning
            )
        );
    }

    #[test]
    fn the_key_card_has_a_copy_button_a_note_and_the_key_rows() {
        let ops = draw(&page()).ops;
        let card = inside(&ops, KEY);
        assert_eq!(
            card[..12],
            [
                Op::Round(KEY, 12.0, T.border),
                Op::Round(Rect::new(249, 113, 762, 250), 11.0, T.card),
                text(
                    Font::Heading,
                    "Hardware key",
                    Rect::new(268, 116, 724, 44),
                    T.text
                ),
                Op::Round(COPY_BUTTON, 6.0, T.border),
                Op::Round(Rect::new(843, 123, 148, 30), 5.0, T.card),
                Op::Icon(
                    icons::COPY,
                    Rect::new(856, 130, 16, 16),
                    stroke(S, &icons::COPY, 16.0),
                    T.text
                ),
                text(
                    Font::BodyStrong,
                    "Copy device ID",
                    Rect::new(880, 122, 98, 32),
                    T.text
                ),
                text(
                    Font::Small,
                    "Kept in this PC's TPM",
                    Rect::new(268, 160, 724, 20),
                    T.muted
                ),
                Op::Fill(Rect::new(268, 180, 724, 1), T.border),
                text(Font::Body, "Storage", Rect::new(268, 180, 49, 44), T.text),
                text(
                    Font::Body,
                    "TPM (Microsoft Platform Crypto Provider)",
                    Rect::new(712, 180, 280, 44),
                    T.muted
                ),
                Op::Fill(Rect::new(268, 224, 724, 1), T.border),
            ]
        );
        assert_eq!(
            card[card.len() - 3..],
            [
                Op::Fill(Rect::new(268, 312, 724, 1), T.border),
                text(Font::Body, "Device ID", Rect::new(268, 312, 63, 44), T.text),
                text(Font::Mono, id(), Rect::new(544, 312, 448, 44), T.muted),
            ]
        );
        assert_eq!(card.len(), 8 + 4 * 3);
    }

    #[test]
    fn a_key_without_a_note_lists_its_rows_under_the_heading() {
        let mut p = page();
        p.key.note = None;
        let b = draw(&p);
        let key = Rect::new(248, 112, 764, 232);
        let card = inside(&b.ops, key);
        assert_eq!(card[0], Op::Round(key, 12.0, T.border));
        assert_eq!(card[7], Op::Fill(Rect::new(268, 160, 724, 1), T.border));
        assert!(
            !card
                .iter()
                .any(|op| matches!(op, Op::Text(Font::Small, ..)))
        );
        assert_eq!(b.pane.map(|p| p.content), Some(232 + 14 + 208 + 14 + 100));
    }

    #[test]
    fn an_alert_note_is_a_warning() {
        let mut p = page();
        p.key.alert = true;
        let ops = draw(&p).ops;
        assert!(ops.contains(&text(
            Font::Small,
            "Kept in this PC's TPM",
            Rect::new(268, 160, 724, 20),
            T.warning
        )));
    }

    #[test]
    fn the_copy_button_is_the_only_target_and_tints_on_hover() {
        assert_eq!(draw(&page()).targets, [(COPY_BUTTON, Zone::CopyId)]);
        let mut v = view();
        v.pointer.moved(Zone::CopyId);
        assert!(draw_with(&page(), &v).ops.contains(&Op::Round(
            Rect::new(843, 123, 148, 30),
            5.0,
            T.caption_hover
        )));
    }

    #[test]
    fn a_copied_button_narrows_to_its_label() {
        let mut p = page();
        p.key.copy = Some("Copied");
        let b = draw(&p);
        assert_eq!(b.targets, [(Rect::new(898, 122, 94, 32), Zone::CopyId)]);
    }

    #[test]
    fn without_a_key_there_is_no_button_and_the_card_is_short() {
        let b = draw(&reading());
        assert!(b.targets.is_empty());
        let card = inside(&b.ops, Rect::new(248, 112, 764, 76));
        assert_eq!(
            card,
            [
                Op::Round(Rect::new(248, 112, 764, 76), 12.0, T.border),
                Op::Round(Rect::new(249, 113, 762, 74), 11.0, T.card),
                text(
                    Font::Heading,
                    "Device key",
                    Rect::new(268, 116, 724, 44),
                    T.text
                ),
                text(
                    Font::Small,
                    "Reading the device key\u{2026}",
                    Rect::new(268, 160, 724, 20),
                    T.muted
                ),
            ]
        );
        assert!(
            b.ops
                .contains(&Op::Round(Rect::new(248, 202, 764, 100), 12.0, T.border))
        );
        assert_eq!(b.pane.map(|p| p.content), Some(76 + 14 + 100));
    }

    #[test]
    fn the_computer_card_names_the_pc_and_its_account() {
        let ops = draw(&page()).ops;
        let card = inside(&ops, COMPUTER);
        assert_eq!(
            card[..7],
            [
                Op::Round(COMPUTER, 12.0, T.border),
                Op::Round(Rect::new(249, 379, 762, 206), 11.0, T.card),
                text(
                    Font::Heading,
                    "DESK-7",
                    Rect::new(268, 382, 724, 44),
                    T.text
                ),
                text(
                    Font::Small,
                    "Signed in as CORP\\ana",
                    Rect::new(268, 426, 724, 20),
                    T.muted
                ),
                Op::Fill(Rect::new(268, 446, 724, 1), T.border),
                text(Font::Body, "System", Rect::new(268, 446, 42, 44), T.text),
                text(
                    Font::Body,
                    "Windows 11 Pro \u{b7} x64",
                    Rect::new(852, 446, 140, 44),
                    T.muted
                ),
            ]
        );
        assert_eq!(
            card[card.len() - 2..],
            [
                text(Font::Body, "Agent", Rect::new(268, 534, 35, 44), T.text),
                text(
                    Font::Body,
                    "Loopback only",
                    Rect::new(901, 534, 91, 44),
                    T.muted
                ),
            ]
        );
    }

    #[test]
    fn an_unknown_account_drops_its_line() {
        let mut p = page();
        if let Some(c) = p.computer.as_mut() {
            c.account = None;
        }
        let b = draw(&p);
        let card = inside(&b.ops, Rect::new(248, 378, 764, 188));
        assert_eq!(card[3], Op::Fill(Rect::new(268, 426, 724, 1), T.border));
        assert_eq!(b.pane.map(|p| p.content), Some(252 + 14 + 188 + 14 + 100));
    }

    #[test]
    fn the_gateways_card_lists_each_gateway_with_its_source_and_address() {
        let ops = draw(&page()).ops;
        assert_eq!(
            inside(&ops, GATEWAYS),
            [
                Op::Round(GATEWAYS, 12.0, T.border),
                Op::Round(Rect::new(249, 601, 762, 98), 11.0, T.card),
                text(
                    Font::Heading,
                    USED_WITH,
                    Rect::new(268, 604, 724, 44),
                    T.text
                ),
                Op::Fill(Rect::new(268, 648, 724, 1), T.border),
                text(Font::Body, "Office", Rect::new(268, 652, 561, 18), T.text),
                text(
                    Font::Small,
                    "Config file",
                    Rect::new(268, 672, 561, 16),
                    T.muted
                ),
                text(
                    Font::Mono,
                    "proxy.example.com:443",
                    Rect::new(845, 648, 147, 44),
                    T.muted
                ),
            ]
        );
    }

    #[test]
    fn no_gateways_or_an_error_show_one_line() {
        let mut p = page();
        p.gateways = Ok(Vec::new());
        assert!(draw(&p).ops.contains(&text(
            Font::Body,
            EMPTY,
            Rect::new(268, 648, 724, 44),
            T.muted
        )));
        p.gateways = Err("config file c.toml: broken".to_owned());
        assert!(draw(&p).ops.contains(&text(
            Font::Body,
            "config file c.toml: broken",
            Rect::new(268, 648, 724, 44),
            T.warning
        )));
    }

    #[test]
    fn scrolling_moves_the_cards_and_the_copy_target() {
        let short = Layout::new(1040, 400, S, true);
        let mut v = view();
        v.scroll.set(NavPage::Device, 20);
        let b = board(&short, S, &T, &v, &page(), &Chars);
        assert_eq!(b.pane.map(|p| p.offset), Some(20));
        assert!(
            b.ops
                .contains(&Op::Round(Rect::new(248, 92, 764, 252), 12.0, T.border))
        );
        assert_eq!(b.targets, [(Rect::new(842, 112, 150, 22), Zone::CopyId)]);
    }
}
