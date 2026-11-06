use super::{Board, PILL_GAP, Painter};
use crate::fonts::{Font, Measure};
use crate::gateways::{ADD, EMPTY, FOOTNOTE, Page, Row, START};
use crate::hit::Zone;
use crate::i18n::tr;
use crate::icons;
use crate::layout::{Layout, Rect};
use crate::nav::Page as NavPage;
use crate::pointer::Look;
use crate::scale::Scale;
use crate::scene::{Op, View};
use crate::theme::Theme;

const MIN_NAME: f32 = 80.0;

pub fn board(l: &Layout, s: Scale, t: &Theme, v: &View, page: &Page, m: &impl Measure) -> Board {
    if v.nav.selected() != NavPage::Gateways {
        return Board::default();
    }
    let mut p = Painter::new(l, s, t, v, m);
    let content = l.content;
    let header = Rect::new(content.x, content.y, content.w, s.px(32.0));
    let add = p.button(header, header.right(), tr(ADD));
    let subtitle = Rect::new(
        content.x,
        content.y + (header.h - s.px(18.0)) / 2,
        add.x - s.px(16.0) - content.x,
        s.px(18.0),
    );
    p.text(Font::Body, page.subtitle.clone(), subtitle, t.muted);
    p.outlined(add, icons::PLUS, tr(ADD), Zone::AddGateway);
    let top = header.bottom() + s.px(12.0);
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
            if card.bottom() <= view.y || card.y >= view.bottom() {
                p.unseen(|p| p.gateway(card, row, i, page));
                continue;
            }
            p.gateway(card, row, i, page);
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

    fn gateway(&mut self, card: Rect, row: &Row, index: usize, page: &Page) {
        let (s, t) = (self.s, self.t);
        self.framed(card, 10.0, t.card);
        let pad = s.px(20.0);
        let tile = s.px(40.0);
        let tile = Rect::new(card.x + pad, card.y + (card.h - tile) / 2, tile, tile);
        self.push(Op::Round(tile, s.pxf(10.0), t.tile));
        self.icon(icons::GATEWAYS, tile, 20.0, t.text);

        let gap = s.px(16.0);
        let right = card.right() - pad;
        let button = self.button(card, right, tr(START));
        let side = s.px(32.0);
        let terminal = Rect::new(button.x - s.px(8.0) - side, button.y, side, side);
        let before = if page.terminal { terminal.x } else { button.x };
        let x = tile.right() + gap;
        let full = s.px(120.0);
        let dots = s.px(16.0);
        let width = if before - gap - full - gap - x < s.px(MIN_NAME) {
            dots
        } else {
            full
        };
        let sessions = Rect::new(before - gap - width, card.y, width, card.h);
        let w = (sessions.x - gap - x).max(0);
        let line = s.px(20.0);
        let top = card.y + (card.h - line - s.px(18.0)) / 2;
        let lock = if row.config {
            s.px(8.0) + s.px(14.0)
        } else {
            0
        };
        let pill_gap = s.px(PILL_GAP);
        let room = w - lock - pill_gap - self.pill_w(row.route);
        let name_w = self.m.width(Font::Heading, &row.label).min(room.max(0));
        let name = Rect::new(x, top, name_w, line);
        self.text(Font::Heading, row.label.clone(), name, t.text);
        if row.config {
            let glyph = Rect::new(name.right() + s.px(8.0), top, s.px(14.0), line);
            self.icon(icons::LOCK, glyph, 14.0, t.muted);
        }
        let first = Rect::new(x, top, w, line);
        self.pill(name.right() + lock + pill_gap, first, row.route);
        let address_w = self.m.width(Font::Mono, &row.address).min(w);
        let address = Rect::new(x, top + line, address_w, s.px(18.0));
        self.text(Font::Mono, row.address.clone(), address, t.muted);

        self.eyes(sessions, row);
        if page.terminal && row.config {
            self.terminal(terminal, Zone::OpenTerminal(index), page.launch);
        }
        self.start(
            button,
            icons::PLUS,
            tr(START),
            Zone::StartBrowser(index),
            page.launch,
        );
        self.target(card, Zone::GatewayCard(index));
    }

    fn terminal(&mut self, button: Rect, zone: Zone, enabled: bool) {
        let (s, t) = (self.s, self.t);
        let glyph = Rect::new(button.x + s.px(8.0), button.y, s.px(16.0), button.h);
        if !enabled {
            self.push(Op::Round(button, s.pxf(6.0), t.tile));
            self.icon(icons::TERMINAL, glyph, 16.0, t.eyes_idle);
            return;
        }
        let fill = match self.v.pointer.look(zone) {
            Look::Rest => t.card,
            Look::Hover => t.caption_hover,
            Look::Pressed => t.caption_pressed,
        };
        self.framed(button, 6.0, fill);
        self.icon(icons::TERMINAL, glyph, 16.0, t.text);
        self.target(button, zone);
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
        if x < col.right() {
            let label = Rect::new(x, col.y, col.right() - x, col.h);
            self.text(Font::Small, row.sessions.clone(), label, t.muted);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board::tests::{Chars, inside, layout, text};
    use crate::fonts::Font;
    use crate::gateways::{ADD, EMPTY, FOOTNOTE, Row, START, SUBTITLE};
    use crate::hit::Zone;
    use crate::i18n::{Language, Text, speaking};
    use crate::icons;
    use crate::nav::{Nav, Page as NavPage};
    use crate::scene::Op;
    use crate::scroll::Pane;
    use crate::theme::Theme;

    const T: Theme = Theme::LIGHT;
    const S: Scale = Scale { dpi: 96 };
    const FIRST: i32 = 124;
    const SUBTITLED: Rect = Rect::new(248, 87, 619, 18);
    const ADDING: (Rect, Zone) = (Rect::new(883, 80, 129, 32), Zone::AddGateway);

    fn row(name: &str, config: bool) -> Row {
        Row {
            label: name.to_owned(),
            address: "proxy.example.com".to_owned(),
            route: "Mixed",
            sessions: "1 session".to_owned(),
            lit: false,
            config,
        }
    }

    fn listed(rows: Vec<Row>) -> Page {
        Page {
            subtitle: SUBTITLE.english().to_owned(),
            footnote: rows.iter().any(|r| r.config),
            empty: rows.is_empty(),
            launch: true,
            terminal: false,
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

    fn add_button() -> [Op; 4] {
        [
            Op::Round(Rect::new(883, 80, 129, 32), 6.0, T.border),
            Op::Round(Rect::new(884, 81, 127, 30), 5.0, T.card),
            Op::Icon(icons::PLUS, Rect::new(897, 88, 16, 16), 1.0, T.text),
            text(Font::BodyStrong, ADD, Rect::new(921, 80, 77, 32), T.text),
        ]
    }

    fn draw(page: &Page) -> Board {
        board(&layout(), S, &T, &view(), page, &Chars)
    }

    #[test]
    fn an_add_gateway_button_sits_beside_the_subtitle() {
        for page in [listed(vec![]), listed(vec![row("office", true)])] {
            let b = draw(&page);
            assert_eq!(b.targets[0], ADDING);
            assert_eq!(b.ops[2..6], add_button());
        }
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
        assert_eq!(ops[1], text(Font::Body, SUBTITLE, SUBTITLED, T.muted));
    }

    #[test]
    fn no_gateways_shows_the_empty_text_and_no_footnote() {
        let ops = draw(&listed(vec![])).ops;
        assert_eq!(ops[1], text(Font::Body, SUBTITLE, SUBTITLED, T.muted));
        assert_eq!(
            ops[6..],
            [
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
            terminal: false,
        };
        let ops = draw(&page).ops;
        assert_eq!(
            ops[1],
            text(Font::Body, "config file c.toml: broken", SUBTITLED, T.muted)
        );
        assert_eq!(ops[2..6], add_button());
        assert_eq!(ops[6..], [Op::Unclip]);
    }

    #[test]
    fn a_row_is_a_card_with_tile_name_lock_route_pill_address_and_sessions() {
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
                Op::Round(Rect::new(394, y + 19, 49, 16), 8.0, T.tile),
                text(
                    Font::Pill,
                    "Mixed",
                    Rect::new(401, y + 19, 35, 16),
                    T.pill_text
                ),
                text(
                    Font::Mono,
                    "proxy.example.com",
                    Rect::new(324, y + 37, 119, 18),
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
                ADDING,
                (Rect::new(849, FIRST + 20, 143, 32), Zone::StartBrowser(0)),
                (Rect::new(248, FIRST, 764, 72), Zone::GatewayCard(0)),
                (Rect::new(849, FIRST + 102, 143, 32), Zone::StartBrowser(1)),
                (Rect::new(248, FIRST + 82, 764, 72), Zone::GatewayCard(1)),
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
        assert_eq!(
            b.targets,
            [
                ADDING,
                (Rect::new(248, FIRST, 764, 72), Zone::GatewayCard(0))
            ]
        );
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

    fn terminals(rows: Vec<Row>) -> Page {
        Page {
            terminal: true,
            ..listed(rows)
        }
    }

    const TERMINAL: Rect = Rect::new(809, FIRST + 20, 32, 32);

    #[test]
    fn a_running_agent_offers_a_terminal_beside_start_browser_on_config_rows() {
        let page = terminals(vec![row("office", true), row("home", false)]);
        let b = draw(&page);
        assert_eq!(
            b.targets,
            [
                ADDING,
                (TERMINAL, Zone::OpenTerminal(0)),
                (Rect::new(849, FIRST + 20, 143, 32), Zone::StartBrowser(0)),
                (Rect::new(248, FIRST, 764, 72), Zone::GatewayCard(0)),
                (Rect::new(849, FIRST + 102, 143, 32), Zone::StartBrowser(1)),
                (Rect::new(248, FIRST + 82, 764, 72), Zone::GatewayCard(1)),
            ]
        );
        assert_eq!(
            inside(&b.ops, TERMINAL),
            [
                Op::Round(TERMINAL, 6.0, T.border),
                Op::Round(Rect::new(810, FIRST + 21, 30, 30), 5.0, T.card),
                Op::Icon(
                    icons::TERMINAL,
                    Rect::new(817, FIRST + 28, 16, 16),
                    1.0,
                    T.text
                ),
            ]
        );
        let linked = Rect {
            y: TERMINAL.y + 82,
            ..TERMINAL
        };
        assert_eq!(inside(&b.ops, linked), []);
        for y in [FIRST, FIRST + 82] {
            assert!(
                b.ops
                    .contains(&Op::Round(Rect::new(673, y + 32, 5, 7), 2.5, T.eyes_idle))
            );
            assert!(b.ops.contains(&text(
                Font::Small,
                "1 session",
                Rect::new(699, y, 94, 72),
                T.muted
            )));
        }
        assert_eq!(
            crate::board::tips(&b.targets),
            [(TERMINAL, "Open terminal")]
        );
    }

    #[test]
    fn a_stopped_agent_offers_no_terminal() {
        let page = listed(vec![row("office", true)]);
        let b = draw(&page);
        assert!(
            !b.targets
                .iter()
                .any(|(_, z)| matches!(z, Zone::OpenTerminal(_)))
        );
        assert_eq!(inside(&b.ops, TERMINAL), []);
    }

    #[test]
    fn a_pending_launch_disables_the_terminal_button() {
        let mut page = terminals(vec![row("office", true)]);
        page.launch = false;
        let mut v = view();
        v.pointer.moved(Zone::OpenTerminal(0));
        let b = board(&layout(), S, &T, &v, &page, &Chars);
        assert_eq!(
            b.targets,
            [
                ADDING,
                (Rect::new(248, FIRST, 764, 72), Zone::GatewayCard(0))
            ]
        );
        assert_eq!(
            inside(&b.ops, TERMINAL),
            [
                Op::Round(TERMINAL, 6.0, T.tile),
                Op::Icon(
                    icons::TERMINAL,
                    Rect::new(817, FIRST + 28, 16, 16),
                    1.0,
                    T.eyes_idle
                ),
            ]
        );
    }

    #[test]
    fn the_terminal_button_follows_the_pointer() {
        let page = terminals(vec![row("office", true)]);
        let mut v = view();
        v.pointer.moved(Zone::OpenTerminal(0));
        let hover = board(&layout(), S, &T, &v, &page, &Chars).ops;
        assert_eq!(
            inside(&hover, TERMINAL)[1],
            Op::Round(Rect::new(810, FIRST + 21, 30, 30), 5.0, T.caption_hover)
        );
        v.pointer.down(Zone::OpenTerminal(0));
        let pressed = board(&layout(), S, &T, &v, &page, &Chars).ops;
        assert_eq!(
            inside(&pressed, TERMINAL)[1],
            Op::Round(Rect::new(810, FIRST + 21, 30, 30), 5.0, T.caption_pressed)
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
                .any(|op| matches!(op, Op::Text(_, s, ..) if s == FOOTNOTE.english()))
        );
    }

    #[test]
    fn without_a_lock_the_pill_follows_the_name() {
        let mut all = row("edge", false);
        all.route = "All";
        let ops = draw(&listed(vec![all])).ops;
        let card = inside(&ops, Rect::new(248, FIRST, 764, 72));
        assert_eq!(
            card[4..7],
            [
                text(
                    Font::Heading,
                    "edge",
                    Rect::new(324, FIRST + 17, 28, 20),
                    T.text
                ),
                Op::Round(Rect::new(358, FIRST + 19, 35, 16), 8.0, T.tile),
                text(
                    Font::Pill,
                    "All",
                    Rect::new(365, FIRST + 19, 21, 16),
                    T.pill_text
                ),
            ]
        );
    }

    #[test]
    fn a_long_address_takes_the_whole_second_line() {
        let mut long = row("office", true);
        long.address = "a".repeat(100);
        let ops = draw(&listed(vec![long])).ops;
        let card = inside(&ops, Rect::new(248, FIRST, 764, 72));
        assert!(matches!(&card[8], Op::Text(Font::Mono, _, r, _) if r.x == 324 && r.w == 373));
        assert!(
            !card
                .iter()
                .any(|op| matches!(op, Op::Text(Font::Small, s, ..) if s.contains("Route")))
        );
    }

    #[test]
    fn a_long_name_leaves_room_for_its_lock_and_pill() {
        let ops = draw(&listed(vec![row(&"n".repeat(100), true)])).ops;
        let card = inside(&ops, Rect::new(248, FIRST, 764, 72));
        assert!(matches!(&card[4], Op::Text(Font::Heading, _, r, _) if r.w == 296));
        assert_eq!(
            card[5],
            Op::Icon(
                icons::LOCK,
                Rect::new(628, FIRST + 20, 14, 14),
                1.0,
                T.muted
            )
        );
        assert_eq!(
            card[6],
            Op::Round(Rect::new(648, FIRST + 19, 49, 16), 8.0, T.tile)
        );
    }

    #[test]
    fn the_pill_stays_inside_the_card_at_the_minimum_window_in_both_languages() {
        let (w, h) = crate::layout::Layout::min_size(S);
        let l = crate::layout::Layout::new(w, h, S, true);
        for language in [Language::English, Language::Chinese] {
            let _speaking = speaking(language);
            for route in [Text::Mixed, Text::All] {
                for (config, terminal) in
                    [(true, false), (false, false), (true, true), (false, true)]
                {
                    let mut long = row(&"n".repeat(100), config);
                    long.route = tr(route);
                    let page = Page {
                        terminal,
                        ..listed(vec![long])
                    };
                    let b = board(&l, S, &T, &view(), &page, &Chars);
                    let card = b.targets.last().unwrap().0;
                    let start = b.targets[b.targets.len() - 2].0;
                    let start = if terminal {
                        Rect::new(start.x - 40, start.y, 32, 32)
                    } else {
                        start
                    };
                    let pill = b
                        .ops
                        .iter()
                        .find_map(|op| match op {
                            Op::Round(r, _, c) if *c == T.tile && r.h == 16 => Some(*r),
                            _ => None,
                        })
                        .unwrap();
                    let word = b.ops.iter().find_map(|op| match op {
                        Op::Text(Font::Pill, s, _, _) => Some(s.to_string()),
                        _ => None,
                    });
                    let name = b
                        .ops
                        .iter()
                        .find_map(|op| match op {
                            Op::Text(Font::Heading, _, r, _) => Some(*r),
                            _ => None,
                        })
                        .unwrap();
                    assert_eq!(word.as_deref(), Some(tr(route)));
                    assert!(name.w > 0 && name.right() < pill.x, "{name:?} {pill:?}");
                    assert!(
                        pill.x >= card.x && pill.right() < start.x,
                        "{pill:?} {start:?}"
                    );
                    assert_eq!(pill.w, Chars.width(Font::Pill, tr(route)) + 14);
                }
            }
        }
    }

    #[test]
    fn at_the_minimum_window_the_terminal_button_leaves_only_the_session_dots() {
        let (w, h) = crate::layout::Layout::min_size(S);
        let l = crate::layout::Layout::new(w, h, S, true);
        for terminal in [false, true] {
            let page = Page {
                terminal,
                ..listed(vec![row("office", true)])
            };
            let b = board(&l, S, &T, &view(), &page, &Chars);
            let label = b
                .ops
                .iter()
                .any(|op| matches!(op, Op::Text(Font::Small, s, ..) if s == "1 session"));
            let dots = b
                .ops
                .iter()
                .filter(|op| matches!(op, Op::Round(r, _, c) if *c == T.eyes_idle && r.h == 7))
                .count();
            assert_eq!((label, dots), (!terminal, 2));
        }
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
                Op::Round(r, _, c) if *c == T.border && r.x == 248 => Some(r.y),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn cards_scroll_between_the_subtitle_and_the_footnote() {
        let pane = |page: &Page| board(&layout(), S, &T, &view(), page, &Chars).pane;
        let open = Rect::new(248, FIRST, 764, 532);
        assert_eq!(pane(&nine(false)), Some(Pane::new(open, 728, 0)));
        let above = Rect::new(248, FIRST, 764, 496);
        assert_eq!(pane(&nine(true)), Some(Pane::new(above, 728, 0)));
        assert_eq!(pane(&listed(vec![])), None);
        let ops = draw(&nine(true)).ops;
        assert!(ops.contains(&Op::Clip(above)));
    }

    #[test]
    fn only_cards_in_the_viewport_are_drawn() {
        assert_eq!(cards(&view()), [124, 206, 288, 370, 452, 534, 616]);
        assert_eq!(cards(&scrolled(100)), [106, 188, 270, 352, 434, 516, 598]);
    }

    #[test]
    fn scrolled_targets_are_clipped_to_the_viewport() {
        let b = board(&layout(), S, &T, &scrolled(110), &nine(false), &Chars);
        assert_eq!(
            b.targets[..4],
            [
                ADDING,
                (Rect::new(849, FIRST, 143, 24), Zone::StartBrowser(1)),
                (Rect::new(248, FIRST, 764, 44), Zone::GatewayCard(1)),
                (Rect::new(849, 198, 143, 32), Zone::StartBrowser(2)),
            ]
        );
    }

    #[test]
    fn the_offset_is_clamped_and_shown_by_a_thumb() {
        let b = board(&layout(), S, &T, &scrolled(10_000), &nine(false), &Chars);
        assert_eq!(b.pane.map(|p| p.offset), Some(196));
        assert_eq!(
            b.ops.last(),
            Some(&Op::Round(Rect::new(1024, 268, 4, 388), 2.0, T.eyes_idle))
        );
    }
}
