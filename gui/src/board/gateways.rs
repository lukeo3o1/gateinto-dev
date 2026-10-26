use super::{Board, Painter};
use crate::fonts::{Font, Measure};
use crate::gateways::{EMPTY, FOOTNOTE, Page, Row, START};
use crate::hit::Zone;
use crate::icons;
use crate::layout::{Layout, Rect};
use crate::nav::Page as NavPage;
use crate::scale::Scale;
use crate::scene::{Op, View};
use crate::theme::Theme;

pub fn board(l: &Layout, s: Scale, t: &Theme, v: &View, page: &Page, m: &impl Measure) -> Board {
    if v.nav.selected() != NavPage::Gateways {
        return Board::default();
    }
    let mut p = Painter::new(l, s, t, v, m);
    let content = l.content;
    let subtitle = Rect::new(content.x, content.y, content.w, s.px(18.0));
    p.text(Font::Body, page.subtitle.clone(), subtitle, t.muted);
    let top = subtitle.bottom() + s.px(18.0);
    let mut bottom = content.bottom();
    if page.footnote {
        let foot = Rect::new(content.x, bottom - s.px(18.0), content.w, s.px(18.0));
        p.footnote(foot);
        bottom = foot.y - s.px(18.0);
    }
    if page.empty {
        p.text(
            Font::Body,
            EMPTY,
            Rect::new(content.x, top, content.w, s.px(20.0)),
            t.muted,
        );
    }
    if !page.rows.is_empty() {
        let (h, gap) = (s.px(72.0), s.px(10.0));
        let view = Rect::new(content.x, top, content.w, (bottom - top).max(0));
        let offset = p.scroll(view, page.rows.len() as i32 * (h + gap) - gap);
        for (i, row) in page.rows.iter().enumerate() {
            let card = Rect::new(content.x, top - offset + i as i32 * (h + gap), content.w, h);
            if card.bottom() <= view.y {
                continue;
            }
            if card.y >= view.bottom() {
                break;
            }
            p.gateway(card, row, (i, page.launch));
        }
    }
    p.finish()
}

impl<M: Measure> Painter<'_, M> {
    fn footnote(&mut self, r: Rect) {
        let (s, t) = (self.s, self.t);
        let glyph = Rect::new(r.x, r.y, s.px(14.0), r.h);
        self.icon(icons::LOCK, glyph, 14.0, t.muted);
        let x = glyph.right() + s.px(6.0);
        let text = Rect::new(x, r.y, r.right() - x, r.h);
        self.text(Font::Small, FOOTNOTE, text, t.muted);
    }

    fn gateway(&mut self, card: Rect, row: &Row, (index, launch): (usize, bool)) {
        let (s, t) = (self.s, self.t);
        self.framed(card, 10.0, t.card);
        let pad = s.px(20.0);
        let tile = s.px(40.0);
        let tile = Rect::new(card.x + pad, card.y + (card.h - tile) / 2, tile, tile);
        self.push(Op::Round(tile, s.pxf(10.0), t.tile));
        self.icon(icons::GATEWAYS, tile, 20.0, t.text);

        let gap = s.px(16.0);
        let right = card.right() - pad;
        let button = self.button(card, right, START);
        let sessions = Rect::new(button.x - gap - s.px(120.0), card.y, s.px(120.0), card.h);
        let x = tile.right() + gap;
        let w = (sessions.x - gap - x).max(0);
        let line = s.px(20.0);
        let top = card.y + (card.h - line - s.px(18.0)) / 2;
        let lock = if row.config {
            s.px(8.0) + s.px(14.0)
        } else {
            0
        };
        let name_w = self
            .m
            .width(Font::Heading, &row.label)
            .min((w - lock).max(0));
        let name = Rect::new(x, top, name_w, line);
        self.text(Font::Heading, row.label.clone(), name, t.text);
        if row.config {
            let glyph = Rect::new(name.right() + s.px(8.0), top, s.px(14.0), line);
            self.icon(icons::LOCK, glyph, 14.0, t.muted);
        }
        let address = Rect::new(x, top + line, w, s.px(18.0));
        self.text(Font::Mono, row.address.clone(), address, t.muted);

        self.eyes(sessions, row);
        self.start(button, START, Zone::StartBrowser(index), launch);
    }

    fn eyes(&mut self, col: Rect, row: &Row) {
        let (s, t) = (self.s, self.t);
        let (dot_w, dot_h, dot_gap) = (s.px(5.0), s.px(7.0), s.px(6.0));
        let dot = if row.lit { t.accent } else { t.eyes_idle };
        let radius = s.pxf(3.0).min(dot_w as f32 / 2.0);
        let y = col.y + (col.h - dot_h) / 2;
        for i in 0..2 {
            let x = col.x + i * (dot_w + dot_gap);
            self.push(Op::Round(Rect::new(x, y, dot_w, dot_h), radius, dot));
        }
        let x = col.x + 2 * (dot_w + dot_gap) + s.px(4.0);
        let label = Rect::new(x, col.y, col.right() - x, col.h);
        self.text(Font::Small, row.sessions.clone(), label, t.muted);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board::tests::{Chars, inside, layout, text};
    use crate::fonts::Font;
    use crate::gateways::{EMPTY, FOOTNOTE, Row, START, SUBTITLE};
    use crate::hit::Zone;
    use crate::icons;
    use crate::nav::{Nav, Page as NavPage};
    use crate::scene::Op;
    use crate::scroll::Pane;
    use crate::theme::Theme;

    const T: Theme = Theme::LIGHT;
    const S: Scale = Scale { dpi: 96 };
    const FIRST: i32 = 116;

    fn row(name: &str, config: bool) -> Row {
        Row {
            label: name.to_owned(),
            address: "proxy.example.com".to_owned(),
            sessions: "1 session".to_owned(),
            lit: false,
            config,
        }
    }

    fn listed(rows: Vec<Row>) -> Page {
        Page {
            subtitle: SUBTITLE.to_owned(),
            footnote: rows.iter().any(|r| r.config),
            empty: rows.is_empty(),
            launch: true,
            rows,
        }
    }

    fn view() -> View {
        let mut nav = Nav::default();
        nav.select(NavPage::Gateways);
        View {
            nav,
            ..View::default()
        }
    }

    fn draw(page: &Page) -> Board {
        board(&layout(), S, &T, &view(), page, &Chars)
    }

    #[test]
    fn other_pages_draw_nothing() {
        let page = listed(vec![row("office", true)]);
        let b = board(&layout(), S, &T, &View::default(), &page, &Chars);
        assert_eq!(b, Board::default());
    }

    #[test]
    fn the_subtitle_sits_under_the_title_inside_the_content_clip() {
        let l = layout();
        let ops = draw(&listed(vec![])).ops;
        assert_eq!(ops.first(), Some(&Op::Clip(l.content)));
        assert_eq!(ops.last(), Some(&Op::Unclip));
        assert_eq!(
            ops[1],
            text(Font::Body, SUBTITLE, Rect::new(248, 80, 764, 18), T.muted)
        );
    }

    #[test]
    fn no_gateways_shows_the_empty_text_and_no_footnote() {
        let ops = draw(&listed(vec![])).ops;
        assert_eq!(
            ops[1..],
            [
                text(Font::Body, SUBTITLE, Rect::new(248, 80, 764, 18), T.muted),
                text(Font::Body, EMPTY, Rect::new(248, FIRST, 764, 20), T.muted),
                Op::Unclip,
            ]
        );
    }

    #[test]
    fn a_load_error_shows_only_the_error() {
        let page = Page {
            subtitle: "config file c.toml: broken".to_owned(),
            rows: Vec::new(),
            empty: false,
            footnote: false,
            launch: false,
        };
        assert_eq!(
            draw(&page).ops[1..],
            [
                text(
                    Font::Body,
                    "config file c.toml: broken",
                    Rect::new(248, 80, 764, 18),
                    T.muted
                ),
                Op::Unclip,
            ]
        );
    }

    #[test]
    fn a_row_is_a_card_with_tile_name_lock_address_and_sessions() {
        let ops = draw(&listed(vec![row("office", true)])).ops;
        let y = FIRST;
        assert_eq!(
            inside(&ops, Rect::new(248, y, 764, 72)),
            [
                Op::Round(Rect::new(248, y, 764, 72), 10.0, T.border),
                Op::Round(Rect::new(249, y + 1, 762, 70), 9.0, T.card),
                Op::Round(Rect::new(268, y + 16, 40, 40), 10.0, T.tile),
                Op::Icon(icons::GATEWAYS, Rect::new(278, y + 26, 20, 20), 1.0, T.text),
                text(
                    Font::Heading,
                    "office",
                    Rect::new(324, y + 17, 42, 20),
                    T.text
                ),
                Op::Icon(icons::LOCK, Rect::new(374, y + 20, 14, 14), 1.0, T.muted),
                text(
                    Font::Mono,
                    "proxy.example.com",
                    Rect::new(324, y + 37, 373, 18),
                    T.muted
                ),
                Op::Round(Rect::new(713, y + 32, 5, 7), 2.5, T.eyes_idle),
                Op::Round(Rect::new(724, y + 32, 5, 7), 2.5, T.eyes_idle),
                text(Font::Small, "1 session", Rect::new(739, y, 94, 72), T.muted),
                Op::Round(Rect::new(849, y + 20, 143, 32), 6.0, T.button),
                Op::Icon(icons::PLUS, Rect::new(863, y + 28, 16, 16), 1.0, T.accent),
                text(
                    Font::BodyStrong,
                    START,
                    Rect::new(887, y + 20, 91, 32),
                    T.button_text
                ),
            ]
        );
    }

    fn button(ops: &[Op]) -> Vec<Op> {
        inside(ops, Rect::new(849, FIRST + 20, 143, 32))
    }

    #[test]
    fn each_start_browser_button_targets_its_row() {
        let b = draw(&listed(vec![row("office", true), row("home", false)]));
        assert_eq!(
            b.targets,
            [
                (Rect::new(849, FIRST + 20, 143, 32), Zone::StartBrowser(0)),
                (Rect::new(849, FIRST + 102, 143, 32), Zone::StartBrowser(1)),
            ]
        );
    }

    #[test]
    fn the_start_browser_button_follows_the_pointer() {
        let page = listed(vec![row("office", true)]);
        let mut v = view();
        v.pointer.moved(Zone::StartBrowser(0));
        let hover = board(&layout(), S, &T, &v, &page, &Chars).ops;
        assert_eq!(
            button(&hover)[0],
            Op::Round(Rect::new(849, FIRST + 20, 143, 32), 6.0, T.button_hover)
        );
        v.pointer.down(Zone::StartBrowser(0));
        let pressed = board(&layout(), S, &T, &v, &page, &Chars).ops;
        assert_eq!(
            button(&pressed)[0],
            Op::Round(Rect::new(849, FIRST + 20, 143, 32), 6.0, T.button_pressed)
        );
    }

    #[test]
    fn without_a_running_agent_the_button_is_disabled() {
        let mut page = listed(vec![row("office", true)]);
        page.launch = false;
        let mut v = view();
        v.pointer.moved(Zone::StartBrowser(0));
        let b = board(&layout(), S, &T, &v, &page, &Chars);
        assert!(b.targets.is_empty());
        assert_eq!(
            button(&b.ops),
            [
                Op::Round(Rect::new(849, FIRST + 20, 143, 32), 6.0, T.tile),
                Op::Icon(
                    icons::PLUS,
                    Rect::new(863, FIRST + 28, 16, 16),
                    1.0,
                    T.eyes_idle
                ),
                text(
                    Font::BodyStrong,
                    START,
                    Rect::new(887, FIRST + 20, 91, 32),
                    T.eyes_idle
                ),
            ]
        );
    }

    #[test]
    fn linked_rows_have_no_lock_and_lit_rows_amber_eyes() {
        let mut linked = row("edge.example", false);
        linked.lit = true;
        let ops = draw(&listed(vec![linked])).ops;
        let card = inside(&ops, Rect::new(248, FIRST, 764, 72));
        assert!(
            !card
                .iter()
                .any(|op| matches!(op, Op::Icon(i, ..) if *i == icons::LOCK))
        );
        assert!(card.contains(&Op::Round(Rect::new(713, FIRST + 32, 5, 7), 2.5, T.accent)));
        assert!(
            !ops.iter()
                .any(|op| matches!(op, Op::Text(_, s, ..) if s == FOOTNOTE))
        );
    }

    #[test]
    fn a_long_name_leaves_room_for_its_lock() {
        let ops = draw(&listed(vec![row(&"n".repeat(100), true)])).ops;
        let card = inside(&ops, Rect::new(248, FIRST, 764, 72));
        assert!(matches!(&card[4], Op::Text(Font::Heading, _, r, _) if r.w == 351));
        assert_eq!(
            card[5],
            Op::Icon(
                icons::LOCK,
                Rect::new(683, FIRST + 20, 14, 14),
                1.0,
                T.muted
            )
        );
    }

    #[test]
    fn config_gateways_get_a_footnote_at_the_bottom() {
        let ops = draw(&listed(vec![row("office", true)])).ops;
        let foot = Rect::new(248, 638, 764, 18);
        assert_eq!(
            inside(&ops, foot),
            [
                Op::Icon(icons::LOCK, Rect::new(248, 640, 14, 14), 1.0, T.muted),
                text(Font::Small, FOOTNOTE, Rect::new(268, 638, 744, 18), T.muted),
            ]
        );
    }

    fn nine(config: bool) -> Page {
        listed((0..9).map(|i| row(&format!("g{i}"), config)).collect())
    }

    fn scrolled(offset: i32) -> View {
        let mut v = view();
        v.scroll.set(NavPage::Gateways, offset);
        v
    }

    fn cards(v: &View) -> Vec<i32> {
        board(&layout(), S, &T, v, &nine(false), &Chars)
            .ops
            .iter()
            .filter_map(|op| match op {
                Op::Round(r, _, c) if *c == T.border => Some(r.y),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn cards_scroll_between_the_subtitle_and_the_footnote() {
        let pane = |page: &Page| board(&layout(), S, &T, &view(), page, &Chars).pane;
        let open = Rect::new(248, FIRST, 764, 540);
        assert_eq!(pane(&nine(false)), Some(Pane::new(open, 728, 0)));
        let above = Rect::new(248, FIRST, 764, 504);
        assert_eq!(pane(&nine(true)), Some(Pane::new(above, 728, 0)));
        assert_eq!(pane(&listed(vec![])), None);
        let ops = draw(&nine(true)).ops;
        assert!(ops.contains(&Op::Clip(above)));
    }

    #[test]
    fn only_cards_in_the_viewport_are_drawn() {
        assert_eq!(cards(&view()), [116, 198, 280, 362, 444, 526, 608]);
        assert_eq!(cards(&scrolled(100)), [98, 180, 262, 344, 426, 508, 590]);
    }

    #[test]
    fn scrolled_targets_are_clipped_to_the_viewport() {
        let b = board(&layout(), S, &T, &scrolled(110), &nine(false), &Chars);
        assert_eq!(
            b.targets[..2],
            [
                (Rect::new(849, FIRST, 143, 24), Zone::StartBrowser(1)),
                (Rect::new(849, 190, 143, 32), Zone::StartBrowser(2)),
            ]
        );
    }

    #[test]
    fn the_offset_is_clamped_and_shown_by_a_thumb() {
        let b = board(&layout(), S, &T, &scrolled(10_000), &nine(false), &Chars);
        assert_eq!(b.pane.map(|p| p.offset), Some(188));
        assert_eq!(
            b.ops.last(),
            Some(&Op::Round(Rect::new(1024, 256, 4, 400), 2.0, T.eyes_idle))
        );
    }
}
