use super::{Board, Painter};
use crate::fonts::{Font, Measure};
use crate::hit::Zone;
use crate::i18n::{Text, fill, tr};
use crate::icons::{self, Icon};
use crate::layout::Rect;
use crate::pointer::Look;
use crate::scale::Scale;
use crate::scene::{Op, View};
use crate::sessions::Launch;
use crate::theme::Theme;
use crate::tray::{ADD, Flyout, LABEL, OPEN, Row, START_AGENT, STOP};

pub fn flyout(frame: Rect, s: Scale, t: &Theme, v: &View, f: &Flyout, m: &impl Measure) -> Board {
    let mut p = Painter::within(frame, s, t, v, m);
    let edge = s.hairline();
    p.push(Op::Fill(frame, t.border));
    p.push(Op::Fill(
        Rect::new(
            frame.x + edge,
            frame.y + edge,
            frame.w - 2 * edge,
            frame.h - 2 * edge,
        ),
        t.bg,
    ));
    let pad = s.px(18.0);
    let logo = Rect::new(frame.x + pad, frame.y + pad, s.px(48.0), s.px(48.0));
    p.push(Op::Logo(logo, f.logo));
    let x = logo.right() + s.px(14.0);
    let w = frame.right() - pad - x;
    let (title, sub, gap) = (s.px(23.0), s.px(16.0), s.px(3.0));
    let top = logo.y + (logo.h - title - gap - sub) / 2;
    p.text(Font::Lead, f.title, Rect::new(x, top, w, title), t.text);
    let subtitle = Rect::new(x, top + title + gap, w, sub);
    p.text(Font::Small, f.subtitle.clone(), subtitle, t.muted);

    let line = Rect::new(frame.x + pad, 0, frame.w - 2 * pad, 0);
    let mut y = logo.bottom() + s.px(14.0);
    if let Some(notice) = &f.notice {
        let r = Rect::new(line.x, y, line.w, s.px(18.0));
        p.text(Font::Small, notice.clone(), r, t.notice_text);
        y = r.bottom() + s.px(6.0);
    }
    let label = Rect::new(line.x, y, line.w, s.px(24.0));
    p.text(Font::Small, tr(LABEL), label, t.muted);
    y = label.bottom() + s.px(6.0);

    let mut actions = vec![
        (icons::SESSIONS, tr(OPEN), Zone::OpenMain, true),
        (icons::GATEWAYS, tr(ADD), Zone::AddGateway, true),
    ];
    if f.stop {
        actions.push((icons::STOP, tr(STOP), Zone::StopAgent, true));
    }
    if f.start != Launch::Hidden {
        let ready = f.start == Launch::Ready;
        actions.push((icons::POWER, tr(START_AGENT), Zone::StartAgent, ready));
    }
    let (item, inner) = (s.px(36.0), s.px(8.0));
    let area = frame.bottom() - (2 * inner + actions.len() as i32 * item);

    let (row_h, row_gap) = (s.px(55.0), s.px(6.0));
    let list = Rect::new(frame.x + s.px(14.0), y, frame.w - 2 * s.px(14.0), 0);
    if let Some(empty) = &f.empty {
        p.text(
            Font::Body,
            empty.clone(),
            Rect::new(line.x, y, line.w, s.px(20.0)),
            t.muted,
        );
    }
    let (shown, more) = fit(f.rows.len(), area - inner - y, row_h, row_gap);
    for (i, row) in f.rows.iter().take(shown).enumerate() {
        let r = Rect::new(list.x, y + i as i32 * (row_h + row_gap), list.w, row_h);
        p.flyout_row(r, row, i, f.launch);
    }
    if more > 0 {
        let r = Rect::new(line.x, y + shown as i32 * (row_h + row_gap), line.w, row_h);
        p.text(Font::Small, fill(Text::MoreInApp, &[&more]), r, t.muted);
    }

    p.push(Op::Fill(Rect::new(frame.x, area, frame.w, edge), t.border));
    for (i, (icon, label, zone, enabled)) in actions.into_iter().enumerate() {
        let r = Rect::new(
            frame.x + inner,
            area + inner + i as i32 * item,
            frame.w - 2 * inner,
            item,
        );
        p.action(r, icon, label, zone, enabled);
    }
    p.finish()
}

pub fn fit(rows: usize, room: i32, row: i32, gap: i32) -> (usize, usize) {
    let slots = if room < row {
        0
    } else {
        ((room + gap) / (row + gap)) as usize
    };
    if rows <= slots {
        (rows, 0)
    } else {
        let shown = slots.saturating_sub(1);
        (shown, rows - shown)
    }
}

impl<M: Measure> Painter<'_, M> {
    fn flyout_row(&mut self, r: Rect, row: &Row, index: usize, launch: bool) {
        let (s, t) = (self.s, self.t);
        let zone = Zone::StartBrowser(index);
        let look = if launch {
            self.v.pointer.look(zone)
        } else {
            Look::Rest
        };
        let (fill, button) = match (launch, look) {
            (false, _) => (t.card, t.tile),
            (true, Look::Rest) => (t.card, t.button),
            (true, Look::Hover) => (t.caption_hover, t.button_hover),
            (true, Look::Pressed) => (t.caption_pressed, t.button_pressed),
        };
        self.push(Op::Round(r, s.pxf(8.0), fill));

        let (dot_w, dot_h) = (s.px(5.0), s.px(7.0));
        let dot = if row.lit { t.accent } else { t.eyes_idle };
        let radius = s.pxf(3.0).min(dot_w as f32 / 2.0);
        let dot_y = r.y + (r.h - dot_h) / 2;
        let dot_x = r.x + s.px(12.0);
        for x in [dot_x, dot_x + s.px(9.0)] {
            self.push(Op::Round(Rect::new(x, dot_y, dot_w, dot_h), radius, dot));
        }

        let size = s.px(30.0);
        let plus = Rect::new(
            r.right() - s.px(12.0) - size,
            r.y + (r.h - size) / 2,
            size,
            size,
        );
        let gap = s.px(12.0);
        let mut right = plus.x - gap;
        let x = r.x + s.px(38.0);
        let count = (!row.open.is_empty()).then(|| {
            let w = self.m.width(Font::Pill, &row.open);
            right -= w + gap;
            Rect::new(right + gap, r.y, w, r.h)
        });
        let w = (right - x).max(0);
        let (name_h, address_h, between) = (s.px(18.0), s.px(15.0), s.px(2.0));
        let top = r.y + (r.h - name_h - between - address_h) / 2;
        self.text(
            Font::BodyStrong,
            row.name.clone(),
            Rect::new(x, top, w, name_h),
            t.text,
        );
        let address = Rect::new(x, top + name_h + between, w, address_h);
        self.text(Font::Mono, row.address.clone(), address, t.muted);
        if let Some(count) = count {
            self.text(Font::Pill, row.open.clone(), count, t.muted);
        }
        self.push(Op::Round(plus, s.pxf(6.0), button));
        let ink = if launch { t.button_text } else { t.muted };
        self.icon(icons::PLUS, plus, 16.0, ink);
        if launch {
            self.target(r, zone);
        }
    }

    fn action(&mut self, r: Rect, icon: Icon, label: &'static str, zone: Zone, enabled: bool) {
        let (s, t) = (self.s, self.t);
        let look = if enabled {
            self.v.pointer.look(zone)
        } else {
            Look::Rest
        };
        let fill = match look {
            Look::Rest => None,
            Look::Hover => Some(t.caption_hover),
            Look::Pressed => Some(t.caption_pressed),
        };
        let (glyph_ink, ink) = if enabled {
            (t.muted, t.text)
        } else {
            (t.eyes_idle, t.eyes_idle)
        };
        if let Some(fill) = fill {
            self.push(Op::Round(r, s.pxf(6.0), fill));
        }
        let glyph = Rect::new(r.x + s.px(10.0), r.y, s.px(16.0), r.h);
        self.icon(icon, glyph, 16.0, glyph_ink);
        let x = glyph.right() + s.px(10.0);
        self.text(
            Font::Body,
            label,
            Rect::new(x, r.y, r.right() - s.px(10.0) - x, r.h),
            ink,
        );
        if enabled {
            self.target(r, zone);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board::tests::{Chars, text};
    use crate::logo::State;
    use crate::sessions::Launch;
    use crate::tray::{ADD, LABEL, NO_GATEWAYS, OPEN, Row, START_AGENT, STOP};

    const T: Theme = Theme::DARK;
    const S: Scale = Scale { dpi: 96 };
    const SIZE: Rect = Rect::new(0, 0, 360, 520);

    fn row(name: &str, open: &str, lit: bool) -> Row {
        Row {
            name: name.to_owned(),
            address: "proxy.example.com".to_owned(),
            open: open.to_owned(),
            lit,
        }
    }

    fn relaying(rows: Vec<Row>) -> Flyout {
        Flyout {
            title: "Relaying",
            subtitle: "2 sessions · 1 with traffic".to_owned(),
            logo: State::Relaying,
            stop: true,
            start: Launch::Hidden,
            launch: true,
            rows,
            empty: None,
            notice: None,
        }
    }

    fn draw(f: &Flyout) -> Board {
        flyout(SIZE, S, &T, &View::default(), f, &Chars)
    }

    fn texts(board: &Board) -> Vec<&str> {
        board
            .ops
            .iter()
            .filter_map(|op| match op {
                Op::Text(_, s, ..) => Some(s.as_ref()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn the_header_shows_the_logo_status_and_label() {
        let ops = draw(&relaying(Vec::new())).ops;
        assert_eq!(
            ops[..7],
            [
                Op::Clip(SIZE),
                Op::Fill(SIZE, T.border),
                Op::Fill(Rect::new(1, 1, 358, 518), T.bg),
                Op::Logo(Rect::new(18, 18, 48, 48), State::Relaying),
                text(Font::Lead, "Relaying", Rect::new(80, 21, 262, 23), T.text),
                text(
                    Font::Small,
                    "2 sessions · 1 with traffic",
                    Rect::new(80, 47, 262, 16),
                    T.muted
                ),
                text(Font::Small, LABEL, Rect::new(18, 80, 324, 24), T.muted),
            ]
        );
        assert_eq!(ops.last(), Some(&Op::Unclip));
    }

    #[test]
    fn the_flyout_paints_with_the_theme_it_is_given() {
        let l = Theme::LIGHT;
        let f = relaying(vec![row("Office", "2 open", true)]);
        let ops = flyout(SIZE, S, &l, &View::default(), &f, &Chars).ops;
        assert_eq!(
            ops[1..3],
            [
                Op::Fill(SIZE, l.border),
                Op::Fill(Rect::new(1, 1, 358, 518), l.bg),
            ]
        );
        assert!(ops.contains(&Op::Round(Rect::new(14, 110, 332, 55), 8.0, l.card)));
        assert!(ops.contains(&text(
            Font::Lead,
            "Relaying",
            Rect::new(80, 21, 262, 23),
            l.text
        )));
        assert!(
            !ops.iter()
                .any(|op| matches!(op, Op::Text(.., c) if *c == T.text))
        );
    }

    #[test]
    fn the_logo_follows_the_status() {
        let mut f = relaying(Vec::new());
        for state in [State::Idle, State::Stopped, State::Attention] {
            f.logo = state;
            let logo = Op::Logo(Rect::new(18, 18, 48, 48), state);
            assert!(draw(&f).ops.contains(&logo));
        }
    }

    #[test]
    fn rows_and_actions_are_targets() {
        let board = draw(&relaying(vec![
            row("office", "1 open", true),
            row("lab", "", false),
        ]));
        assert_eq!(
            board.targets,
            [
                (Rect::new(14, 110, 332, 55), Zone::StartBrowser(0)),
                (Rect::new(14, 171, 332, 55), Zone::StartBrowser(1)),
                (Rect::new(8, 404, 344, 36), Zone::OpenMain),
                (Rect::new(8, 440, 344, 36), Zone::AddGateway),
                (Rect::new(8, 476, 344, 36), Zone::StopAgent),
            ]
        );
        assert_eq!(
            texts(&board)[3..],
            [
                "office",
                "proxy.example.com",
                "1 open",
                "lab",
                "proxy.example.com",
                OPEN.english(),
                ADD.english(),
                STOP.english()
            ]
        );
        assert!(
            board
                .ops
                .contains(&Op::Fill(Rect::new(0, 396, 360, 1), T.border))
        );
    }

    #[test]
    fn a_row_shows_its_eyes_name_address_count_and_plus() {
        let ops = draw(&relaying(vec![row("office", "1 open", true)])).ops;
        let r = Rect::new(14, 110, 332, 55);
        assert!(ops.contains(&Op::Round(r, 8.0, T.card)));
        assert!(ops.contains(&Op::Round(Rect::new(26, 134, 5, 7), 2.5, T.accent)));
        assert!(ops.contains(&Op::Round(Rect::new(35, 134, 5, 7), 2.5, T.accent)));
        assert!(ops.contains(&text(
            Font::BodyStrong,
            "office",
            Rect::new(52, 120, 186, 18),
            T.text
        )));
        assert!(ops.contains(&text(
            Font::Mono,
            "proxy.example.com",
            Rect::new(52, 140, 186, 15),
            T.muted
        )));
        assert!(ops.contains(&text(
            Font::Pill,
            "1 open",
            Rect::new(250, 110, 42, 55),
            T.muted
        )));
        assert!(ops.contains(&Op::Round(Rect::new(304, 122, 30, 30), 6.0, T.button)));
        assert!(ops.iter().any(|op| matches!(op, Op::Icon(icon, _, _, c) if *icon == icons::PLUS && *c == T.button_text)));
    }

    #[test]
    fn idle_rows_use_grey_eyes_and_no_count() {
        let ops = draw(&relaying(vec![row("lab", "", false)])).ops;
        assert!(ops.contains(&Op::Round(Rect::new(26, 134, 5, 7), 2.5, T.eyes_idle)));
        assert!(ops.contains(&text(
            Font::BodyStrong,
            "lab",
            Rect::new(52, 120, 240, 18),
            T.text
        )));
    }

    #[test]
    fn rows_cannot_launch_while_the_agent_cannot() {
        let mut f = relaying(vec![row("office", "", false)]);
        f.launch = false;
        f.stop = false;
        let board = draw(&f);
        assert_eq!(
            board.targets,
            [
                (Rect::new(8, 440, 344, 36), Zone::OpenMain),
                (Rect::new(8, 476, 344, 36), Zone::AddGateway),
            ]
        );
        assert!(
            board
                .ops
                .contains(&Op::Round(Rect::new(304, 122, 30, 30), 6.0, T.tile))
        );
        assert!(!texts(&board).contains(&STOP.english()));
    }

    fn stopped(start: Launch) -> Flyout {
        Flyout {
            title: "Stopped",
            stop: false,
            start,
            launch: false,
            ..relaying(Vec::new())
        }
    }

    #[test]
    fn a_stopped_agent_offers_to_start_where_stop_would_be() {
        let board = draw(&stopped(Launch::Ready));
        let r = Rect::new(8, 476, 344, 36);
        assert_eq!(
            board.targets,
            [
                (Rect::new(8, 404, 344, 36), Zone::OpenMain),
                (Rect::new(8, 440, 344, 36), Zone::AddGateway),
                (r, Zone::StartAgent),
            ]
        );
        assert_eq!(
            crate::board::tests::inside(&board.ops, r),
            [
                Op::Icon(icons::POWER, Rect::new(18, 486, 16, 16), 1.0, T.muted),
                text(Font::Body, START_AGENT, Rect::new(44, 476, 298, 36), T.text),
            ]
        );
        assert!(!texts(&board).contains(&STOP.english()));
    }

    #[test]
    fn a_start_in_flight_greys_out_start_agent() {
        let mut v = View::default();
        v.pointer.moved(Zone::StartAgent);
        let board = flyout(SIZE, S, &T, &v, &stopped(Launch::Busy), &Chars);
        let r = Rect::new(8, 476, 344, 36);
        assert!(!board.targets.iter().any(|&(_, z)| z == Zone::StartAgent));
        assert_eq!(
            crate::board::tests::inside(&board.ops, r),
            [
                Op::Icon(icons::POWER, Rect::new(18, 486, 16, 16), 1.0, T.eyes_idle),
                text(
                    Font::Body,
                    START_AGENT,
                    Rect::new(44, 476, 298, 36),
                    T.eyes_idle
                ),
            ]
        );
    }

    #[test]
    fn hovering_a_row_lights_it_and_its_button() {
        let mut v = View::default();
        v.pointer.moved(Zone::StartBrowser(0));
        let ops = flyout(
            SIZE,
            S,
            &T,
            &v,
            &relaying(vec![row("office", "", false)]),
            &Chars,
        )
        .ops;
        assert!(ops.contains(&Op::Round(
            Rect::new(14, 110, 332, 55),
            8.0,
            T.caption_hover
        )));
        assert!(ops.contains(&Op::Round(Rect::new(304, 122, 30, 30), 6.0, T.button_hover)));
        v.pointer.moved(Zone::OpenMain);
        let ops = flyout(SIZE, S, &T, &v, &relaying(Vec::new()), &Chars).ops;
        assert!(ops.contains(&Op::Round(Rect::new(8, 404, 344, 36), 6.0, T.caption_hover)));
    }

    #[test]
    fn rows_that_do_not_fit_are_counted() {
        assert_eq!(fit(3, 278, 55, 6), (3, 0));
        assert_eq!(fit(4, 278, 55, 6), (4, 0));
        assert_eq!(fit(10, 278, 55, 6), (3, 7));
        assert_eq!(fit(2, 40, 55, 6), (0, 2));
        let rows = (0..10).map(|i| row(&format!("g{i}"), "", false)).collect();
        let board = draw(&relaying(rows));
        let starts = board
            .targets
            .iter()
            .filter(|(_, z)| matches!(z, Zone::StartBrowser(_)))
            .count();
        assert_eq!(starts, 3);
        assert!(board.ops.contains(&text(
            Font::Small,
            "7 more in Gateinto",
            Rect::new(18, 293, 324, 55),
            T.muted
        )));
    }

    #[test]
    fn an_empty_list_says_why() {
        let mut f = relaying(Vec::new());
        f.empty = Some(NO_GATEWAYS.english().to_owned());
        assert!(draw(&f).ops.contains(&text(
            Font::Body,
            NO_GATEWAYS,
            Rect::new(18, 110, 324, 20),
            T.muted
        )));
    }

    #[test]
    fn the_notice_sits_under_the_header_and_pushes_the_rows_down() {
        let mut f = relaying(vec![row("office", "", false)]);
        f.notice = Some("Gateway refused".to_owned());
        let board = draw(&f);
        assert!(board.ops.contains(&text(
            Font::Small,
            "Gateway refused",
            Rect::new(18, 80, 324, 18),
            T.notice_text
        )));
        assert_eq!(
            board.targets[0],
            (Rect::new(14, 134, 332, 55), Zone::StartBrowser(0))
        );
    }

    #[test]
    fn the_flyout_speaks_chinese() {
        let _zh = crate::i18n::speaking(crate::i18n::Language::Chinese);
        let rows = (0..10).map(|i| row(&format!("g{i}"), "", false)).collect();
        let board = draw(&relaying(rows));
        let texts = texts(&board);
        for expected in [
            "啟動瀏覽器工作階段",
            "開啟 Gateinto",
            "新增閘道…",
            "停止代理程式",
            "Gateinto 中還有 7 個",
        ] {
            assert!(texts.contains(&expected), "{expected} in {texts:?}");
        }
    }
}
