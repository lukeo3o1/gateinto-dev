use super::{Board, Painter};
use crate::fonts::{Font, Measure};
use crate::hit::Zone;
use crate::icons::{self, Icon};
use crate::layout::Rect;
use crate::pointer::Look;
use crate::scale::Scale;
use crate::scene::{Op, View};
use crate::sessions::Eyes;
use crate::theme::Theme;
use crate::tray::{ADD, Flyout, LABEL, OPEN, Row, STOP};

const T: &Theme = &Theme::FLYOUT;

pub fn flyout(frame: Rect, s: Scale, v: &View, f: &Flyout, m: &impl Measure) -> Board {
    let mut p = Painter::within(frame, s, T, v, m);
    let edge = s.hairline();
    p.push(Op::Fill(frame, T.border));
    p.push(Op::Fill(
        Rect::new(
            frame.x + edge,
            frame.y + edge,
            frame.w - 2 * edge,
            frame.h - 2 * edge,
        ),
        T.bg,
    ));
    let pad = s.px(18.0);
    let logo = Rect::new(frame.x + pad, frame.y + pad, s.px(48.0), s.px(48.0));
    let eyes = match f.eyes {
        Eyes::Lit => Some(T.accent),
        Eyes::Dim => Some(T.eyes_idle),
        Eyes::Closed => None,
    };
    p.push(Op::Logo(logo, eyes));
    let x = logo.right() + s.px(14.0);
    let w = frame.right() - pad - x;
    let (title, sub, gap) = (s.px(23.0), s.px(16.0), s.px(3.0));
    let top = logo.y + (logo.h - title - gap - sub) / 2;
    p.text(Font::Lead, f.title, Rect::new(x, top, w, title), T.text);
    let subtitle = Rect::new(x, top + title + gap, w, sub);
    p.text(Font::Small, f.subtitle.clone(), subtitle, T.muted);

    let line = Rect::new(frame.x + pad, 0, frame.w - 2 * pad, 0);
    let mut y = logo.bottom() + s.px(14.0);
    if let Some(notice) = &f.notice {
        let r = Rect::new(line.x, y, line.w, s.px(18.0));
        p.text(Font::Small, notice.clone(), r, T.notice_text);
        y = r.bottom() + s.px(6.0);
    }
    let label = Rect::new(line.x, y, line.w, s.px(24.0));
    p.text(Font::Small, LABEL, label, T.muted);
    y = label.bottom() + s.px(6.0);

    let mut actions = vec![
        (icons::SESSIONS, OPEN, Zone::OpenMain),
        (icons::GATEWAYS, ADD, Zone::AddGateway),
    ];
    if f.stop {
        actions.push((icons::STOP, STOP, Zone::StopAgent));
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
            T.muted,
        );
    }
    let (shown, more) = fit(f.rows.len(), area - inner - y, row_h, row_gap);
    for (i, row) in f.rows.iter().take(shown).enumerate() {
        let r = Rect::new(list.x, y + i as i32 * (row_h + row_gap), list.w, row_h);
        p.flyout_row(r, row, i, f.launch);
    }
    if more > 0 {
        let r = Rect::new(line.x, y + shown as i32 * (row_h + row_gap), line.w, row_h);
        p.text(Font::Small, format!("{more} more in Gateinto"), r, T.muted);
    }

    p.push(Op::Fill(Rect::new(frame.x, area, frame.w, edge), T.border));
    for (i, (icon, label, zone)) in actions.into_iter().enumerate() {
        let r = Rect::new(
            frame.x + inner,
            area + inner + i as i32 * item,
            frame.w - 2 * inner,
            item,
        );
        p.action(r, icon, label, zone);
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
        let s = self.s;
        let zone = Zone::StartBrowser(index);
        let look = if launch {
            self.v.pointer.look(zone)
        } else {
            Look::Rest
        };
        let (fill, button) = match (launch, look) {
            (false, _) => (T.card, T.tile),
            (true, Look::Rest) => (T.card, T.button),
            (true, Look::Hover) => (T.caption_hover, T.button_hover),
            (true, Look::Pressed) => (T.caption_pressed, T.button_pressed),
        };
        self.push(Op::Round(r, s.pxf(8.0), fill));

        let (dot_w, dot_h) = (s.px(5.0), s.px(7.0));
        let dot = if row.lit { T.accent } else { T.eyes_idle };
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
            T.text,
        );
        let address = Rect::new(x, top + name_h + between, w, address_h);
        self.text(Font::Mono, row.address.clone(), address, T.muted);
        if let Some(count) = count {
            self.text(Font::Pill, row.open.clone(), count, T.muted);
        }
        self.push(Op::Round(plus, s.pxf(6.0), button));
        let ink = if launch { T.button_text } else { T.muted };
        self.icon(icons::PLUS, plus, 16.0, ink);
        if launch {
            self.target(r, zone);
        }
    }

    fn action(&mut self, r: Rect, icon: Icon, label: &'static str, zone: Zone) {
        let s = self.s;
        let fill = match self.v.pointer.look(zone) {
            Look::Rest => None,
            Look::Hover => Some(T.caption_hover),
            Look::Pressed => Some(T.caption_pressed),
        };
        if let Some(fill) = fill {
            self.push(Op::Round(r, s.pxf(6.0), fill));
        }
        let glyph = Rect::new(r.x + s.px(10.0), r.y, s.px(16.0), r.h);
        self.icon(icon, glyph, 16.0, T.muted);
        let x = glyph.right() + s.px(10.0);
        self.text(
            Font::Body,
            label,
            Rect::new(x, r.y, r.right() - s.px(10.0) - x, r.h),
            T.text,
        );
        self.target(r, zone);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board::tests::{Chars, text};
    use crate::sessions::Eyes;
    use crate::tray::{ADD, LABEL, NO_GATEWAYS, OPEN, Row, STOP};

    const T: Theme = Theme::FLYOUT;
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
            eyes: Eyes::Lit,
            stop: true,
            launch: true,
            rows,
            empty: None,
            notice: None,
        }
    }

    fn draw(f: &Flyout) -> Board {
        flyout(SIZE, S, &View::default(), f, &Chars)
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
                Op::Logo(Rect::new(18, 18, 48, 48), Some(T.accent)),
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
    fn the_logo_eyes_follow_the_status() {
        let mut f = relaying(Vec::new());
        f.eyes = Eyes::Dim;
        assert!(
            draw(&f)
                .ops
                .contains(&Op::Logo(Rect::new(18, 18, 48, 48), Some(T.eyes_idle)))
        );
        f.eyes = Eyes::Closed;
        assert!(
            draw(&f)
                .ops
                .contains(&Op::Logo(Rect::new(18, 18, 48, 48), None))
        );
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
                OPEN,
                ADD,
                STOP
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
        assert!(!texts(&board).contains(&STOP));
    }

    #[test]
    fn hovering_a_row_lights_it_and_its_button() {
        let mut v = View::default();
        v.pointer.moved(Zone::StartBrowser(0));
        let ops = flyout(
            SIZE,
            S,
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
        let ops = flyout(SIZE, S, &v, &relaying(Vec::new()), &Chars).ops;
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
        f.empty = Some(NO_GATEWAYS.to_owned());
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
}
