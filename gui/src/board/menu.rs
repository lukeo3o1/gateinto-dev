use super::{Board, Painter};
use crate::fonts::{Font, Measure};
use crate::hit::Zone;
use crate::layout::{Layout, Rect};
use crate::menu::{Entry, place};
use crate::pointer::Look;
use crate::scale::Scale;
use crate::scene::{Op, View};
use crate::scroll::{self, Pane};
use crate::theme::Theme;

pub fn overlay(
    board: &mut Board,
    l: &Layout,
    s: Scale,
    t: &Theme,
    v: &View,
    entries: &[Entry],
    m: &impl Measure,
) {
    let Some(anchor) = board.anchor else {
        return;
    };
    let mut p = Painter::new(l, s, t, v, m);
    let (pad, line) = (s.px(4.0), s.px(34.0));
    let content = entries.len() as i32 * line;
    let panel = place(
        anchor,
        (s.px(200.0), 2 * pad + content),
        l.content,
        s.px(6.0),
    );
    p.framed(panel, 8.0, t.card);
    let view = Rect::new(panel.x, panel.y + pad, panel.w, panel.h - 2 * pad);
    let (mut offset, mut width) = (0, panel.w - 2 * pad);
    let pane = (content > view.h).then(|| Pane::new(view, content, v.popup_scroll));
    if let Some(pane) = pane {
        p.board.popup = Some(pane);
        offset = pane.offset;
        width -= s.px(8.0);
        p.push(Op::Clip(view));
        p.clip = view;
    }
    for (i, entry) in entries.iter().enumerate() {
        let item = Rect::new(view.x + pad, view.y + i as i32 * line - offset, width, line);
        if item.bottom() > view.y && item.y < view.bottom() {
            p.item(item, i, entry);
        } else {
            p.unseen(|p| p.item(item, i, entry));
        }
    }
    if let Some(pane) = pane {
        p.push(Op::Unclip);
        p.clip = l.content;
        let track = Rect::new(view.x + pad + width + s.px(2.0), view.y, s.px(4.0), view.h);
        if let Some(r) = scroll::thumb(track, pane.content, pane.offset, s.px(24.0)) {
            p.push(Op::Round(r, s.pxf(2.0), t.eyes_idle));
        }
    }
    board.popup = pane;
    p.target(panel, Zone::Menu);
    p.push(Op::Unclip);
    board.ops.append(&mut p.board.ops);
    p.board.targets.append(&mut board.targets);
    board.targets = p.board.targets;
    p.board.order.append(&mut board.order);
    board.order = p.board.order;
}

impl<M: Measure> Painter<'_, M> {
    fn item(&mut self, item: Rect, index: usize, entry: &Entry) {
        let (s, t) = (self.s, self.t);
        let zone = Zone::Entry(index);
        let enabled = entry.choice.is_some();
        if enabled && self.v.pointer.look(zone) != Look::Rest {
            self.push(Op::Round(item, s.pxf(5.0), t.tile));
        }
        let (glyph, ink) = if enabled {
            (t.muted, t.text)
        } else {
            (t.eyes_idle, t.eyes_idle)
        };
        let icon = Rect::new(item.x + s.px(10.0), item.y, s.px(16.0), item.h);
        self.icon(entry.icon, icon, 16.0, glyph);
        let x = icon.right() + s.px(10.0);
        let label = Rect::new(x, item.y, item.right() - s.px(10.0) - x, item.h);
        self.text(Font::Body, entry.label.clone(), label, ink);
        if enabled {
            self.target(item, zone);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board::tests::{Chars, PICK, layout, text};
    use crate::fonts::Font;
    use crate::hit::Zone;
    use crate::icons;
    use crate::layout::Rect;
    use crate::menu::{Choice, NO_GATEWAYS};
    use crate::scene::{Op, stroke};
    use crate::scroll::Pane;

    const T: Theme = Theme::LIGHT;
    const S: Scale = Scale { dpi: 96 };

    fn entry(label: &'static str, choice: Option<Choice>) -> Entry {
        Entry {
            icon: icons::GATEWAYS,
            label: label.into(),
            choice,
        }
    }

    fn anchored() -> Board {
        Board {
            targets: vec![(PICK, Zone::Picker)],
            anchor: Some(PICK),
            ..Board::default()
        }
    }

    fn item(i: i32) -> Rect {
        Rect::new(658, 152 + 34 * i, 192, 34)
    }

    fn glyph(i: i32, c: crate::theme::Rgb) -> Op {
        let r = Rect::new(668, 161 + 34 * i, 16, 16);
        Op::Icon(icons::GATEWAYS, r, stroke(S, &icons::GATEWAYS, 16.0), c)
    }

    fn draw(v: &View, entries: &[Entry]) -> Board {
        let mut b = anchored();
        overlay(&mut b, &layout(), S, &T, v, entries, &Chars);
        b
    }

    #[test]
    fn the_menu_is_a_bordered_card_of_items_under_its_anchor() {
        let entries = [
            entry("office", Some(Choice::Launch(0))),
            entry("edge.example.net", Some(Choice::Launch(1))),
        ];
        let b = draw(&View::default(), &entries);
        let l = layout();
        let panel = Rect::new(654, 148, 200, 76);
        assert_eq!(
            b.ops,
            [
                Op::Clip(l.content),
                Op::Round(panel, 8.0, T.border),
                Op::Round(Rect::new(655, 149, 198, 74), 7.0, T.card),
                glyph(0, T.muted),
                text(Font::Body, "office", Rect::new(694, 152, 146, 34), T.text),
                glyph(1, T.muted),
                text(
                    Font::Body,
                    "edge.example.net",
                    Rect::new(694, 186, 146, 34),
                    T.text
                ),
                Op::Unclip,
            ]
        );
        assert_eq!(
            b.targets,
            [
                (item(0), Zone::Entry(0)),
                (item(1), Zone::Entry(1)),
                (panel, Zone::Menu),
                (PICK, Zone::Picker),
            ]
        );
        assert_eq!(b.popup, None);
    }

    fn many(n: usize) -> Vec<Entry> {
        (0..n)
            .map(|i| entry("office", Some(Choice::Launch(i))))
            .collect()
    }

    const VIEW: Rect = Rect::new(654, 152, 200, 500);

    fn row(i: i32, offset: i32) -> Rect {
        Rect::new(658, 152 + 34 * i - offset, 184, 34)
    }

    #[test]
    fn a_long_menu_is_clamped_to_the_content_and_scrolls() {
        let b = draw(&View::default(), &many(20));
        let panel = Rect::new(654, 148, 200, 508);
        assert_eq!(b.popup, Some(Pane::new(VIEW, 680, 0)));
        assert_eq!(b.ops[1], Op::Round(panel, 8.0, T.border));
        assert_eq!(b.ops[3], Op::Clip(VIEW));
        let thumb = Op::Round(Rect::new(844, 152, 4, 367), 2.0, T.eyes_idle);
        assert_eq!(b.ops[b.ops.len() - 3..], [Op::Unclip, thumb, Op::Unclip]);
        let entries: Vec<_> = b.targets.iter().take(16).copied().collect();
        assert_eq!(entries[0], (row(0, 0), Zone::Entry(0)));
        assert_eq!(entries[14], (Rect::new(658, 628, 184, 24), Zone::Entry(14)));
        assert_eq!(entries[15], (panel, Zone::Menu));
    }

    #[test]
    fn a_scrolled_menu_shifts_its_items_and_clamps_the_offset() {
        let v = View {
            popup_scroll: 102,
            ..View::default()
        };
        let b = draw(&v, &many(20));
        assert_eq!(b.popup.map(|p| p.offset), Some(102));
        assert_eq!(b.targets[0], (row(3, 102), Zone::Entry(3)));
        let v = View {
            popup_scroll: 10_000,
            ..View::default()
        };
        let b = draw(&v, &many(20));
        assert_eq!(b.popup.map(|p| p.offset), Some(180));
        assert_eq!(b.targets[14], (row(19, 180), Zone::Entry(19)));
    }

    #[test]
    fn the_focus_order_holds_every_entry_of_a_long_menu() {
        let b = draw(&View::default(), &many(20));
        let zones: Vec<_> = b.order.iter().map(|stop| stop.zone).collect();
        let mut expected: Vec<_> = (0..20).map(Zone::Entry).collect();
        expected.push(Zone::Menu);
        assert_eq!(zones, expected);
        assert_eq!(b.order[19].rect, row(19, 0));
        assert!(b.order[19].scrolls);
        assert!(!b.order[20].scrolls);
    }

    #[test]
    fn a_hovered_item_is_tinted() {
        let entries = [
            entry("office", Some(Choice::Launch(0))),
            entry("lab", Some(Choice::Launch(1))),
        ];
        let mut v = View::default();
        v.pointer.moved(Zone::Entry(1));
        let ops = draw(&v, &entries).ops;
        let at = ops.iter().position(|op| *op == glyph(1, T.muted)).unwrap();
        assert_eq!(ops[at - 1], Op::Round(item(1), 5.0, T.tile));
        assert!(!ops.contains(&Op::Round(item(0), 5.0, T.tile)));
    }

    #[test]
    fn a_disabled_item_is_greyed_and_not_a_target() {
        let b = draw(&View::default(), &[entry(NO_GATEWAYS.english(), None)]);
        let panel = Rect::new(654, 148, 200, 42);
        assert_eq!(
            b.ops[3..5],
            [
                glyph(0, T.eyes_idle),
                text(
                    Font::Body,
                    NO_GATEWAYS,
                    Rect::new(694, 152, 146, 34),
                    T.eyes_idle
                ),
            ]
        );
        assert_eq!(b.targets, [(panel, Zone::Menu), (PICK, Zone::Picker)]);
    }

    #[test]
    fn without_an_anchor_nothing_is_drawn() {
        let mut b = Board::default();
        let entries = [entry("office", Some(Choice::Launch(0)))];
        overlay(&mut b, &layout(), S, &T, &View::default(), &entries, &Chars);
        assert_eq!(b, Board::default());
    }
}
