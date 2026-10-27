use gateinto::ipc::LogLevel;

use super::{Board, Painter, inset};
use crate::fonts::{Font, Measure};
use crate::hit::Zone;
use crate::icons;
use crate::layout::{Layout, Rect};
use crate::log::{Body, Filter, Page, Row};
use crate::nav::Page as NavPage;
use crate::pointer::Look;
use crate::scale::Scale;
use crate::scene::{Op, View};
use crate::theme::{Rgb, Theme};

const FILTERS: [(Filter, &str); 2] = [(Filter::All, "All"), (Filter::Warnings, "Warnings")];
const WIDEST_TIME: &str = "00:00:00";
const WIDEST_LEVEL: &str = "ERROR";

pub fn board(l: &Layout, s: Scale, t: &Theme, v: &View, page: &Page, m: &impl Measure) -> Board {
    if v.nav.selected() != NavPage::Log {
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
    let ink = if page.alert { t.warning } else { t.muted };
    p.text(Font::Body, page.subtitle.clone(), line, ink);

    let gap = s.px(14.0);
    let tools = Rect::new(content.x, line.bottom() + gap, content.w, s.px(32.0));
    p.filters(tools, page.filter);
    if let Some(label) = page.copy {
        let button = p.button(tools, tools.right(), label);
        p.outlined(button, icons::COPY, label, Zone::CopyLog);
    }

    let top = tools.bottom() + gap;
    let view = Rect::new(content.x, top, content.w, (content.bottom() - top).max(0));
    let (pad, row_h) = (s.px(8.0), s.px(24.0));
    let total = match &page.body {
        Body::Rows(rows) => 2 * pad + rows.len() as i32 * row_h,
        Body::Empty(_) => s.px(56.0),
    };
    let offset = p.scroll(view, total);
    let card = Rect::new(content.x, top - offset, content.w, total);
    p.framed(card, 10.0, t.card);
    let side = s.px(16.0);
    match &page.body {
        Body::Rows(rows) => {
            let inner = Rect::new(card.x + side, card.y + pad, card.w - 2 * side, row_h);
            let columns = Columns::new(&p, inner, rows);
            for (i, row) in rows.iter().enumerate() {
                let r = Rect::new(inner.x, inner.y + i as i32 * row_h, inner.w, row_h);
                if r.bottom() <= view.y {
                    continue;
                }
                if r.y >= view.bottom() {
                    break;
                }
                p.entry(&columns, r, row);
            }
        }
        Body::Empty(why) => {
            let r = Rect::new(card.x + side, card.y, card.w - 2 * side, card.h);
            p.text(Font::Body, why.clone(), r, t.muted);
        }
    }
    p.finish()
}

struct Columns {
    time: i32,
    level: i32,
    scope: i32,
    gap: i32,
}

impl Columns {
    fn new<M: Measure>(p: &Painter<'_, M>, inner: Rect, rows: &[Row]) -> Self {
        let widest = rows
            .iter()
            .map(|row| p.m.width(Font::Mono, &row.scope))
            .max()
            .unwrap_or(0);
        Self {
            time: p.m.width(Font::Mono, WIDEST_TIME),
            level: p.m.width(Font::Mono, WIDEST_LEVEL),
            scope: widest.min(inner.w / 4),
            gap: p.s.px(12.0),
        }
    }
}

fn level_ink(t: &Theme, level: LogLevel) -> Rgb {
    match level {
        LogLevel::Warn => t.warning,
        LogLevel::Error => t.revoke_glyph,
        LogLevel::Info | LogLevel::Unknown => t.muted,
    }
}

impl<M: Measure> Painter<'_, M> {
    fn filters(&mut self, tools: Rect, chosen: Filter) {
        let (s, t) = (self.s, self.t);
        let pad = s.px(14.0);
        let mut x = tools.x;
        let parts = FILTERS.map(|(filter, label)| {
            let w = self
                .m
                .width(Font::Body, label)
                .max(self.m.width(Font::BodyStrong, label));
            let part = Rect::new(x, tools.y, w + 2 * pad, tools.h);
            x = part.right();
            (filter, label, part)
        });
        self.framed(
            Rect::new(tools.x, tools.y, x - tools.x, tools.h),
            6.0,
            t.card,
        );
        for (filter, _, part) in parts {
            let fill = match (
                filter == chosen,
                self.v.pointer.look(Zone::LogFilter(filter)),
            ) {
                (true, _) => Some(t.tile),
                (false, Look::Rest) => None,
                (false, Look::Hover) => Some(t.caption_hover),
                (false, Look::Pressed) => Some(t.caption_pressed),
            };
            if let Some(fill) = fill {
                self.push(Op::Round(inset(part, s.px(3.0)), s.pxf(4.0), fill));
            }
        }
        for (filter, label, part) in parts {
            let (font, ink) = if filter == chosen {
                (Font::BodyStrong, t.text)
            } else {
                (Font::Body, t.muted)
            };
            let text = Rect::new(part.x + pad, part.y, part.w - 2 * pad, part.h);
            self.text(font, label, text, ink);
            self.target(part, Zone::LogFilter(filter));
        }
    }

    fn entry(&mut self, c: &Columns, r: Rect, row: &Row) {
        let t = self.t;
        let time = Rect::new(r.x, r.y, c.time, r.h);
        self.text(Font::Mono, row.time.clone(), time, t.muted);
        let level = Rect::new(time.right() + c.gap, r.y, c.level, r.h);
        self.text(Font::Mono, row.label(), level, level_ink(t, row.level));
        let scope = Rect::new(level.right() + c.gap, r.y, c.scope, r.h);
        self.text(Font::Mono, row.scope.clone(), scope, t.muted);
        let x = scope.right() + c.gap;
        let message = Rect::new(x, r.y, (r.right() - x).max(0), r.h);
        self.text(Font::Mono, row.message.clone(), message, t.text);
    }
}

#[cfg(test)]
mod tests {
    use gateinto::ipc::LogLevel;

    use super::*;
    use crate::board::tests::{Chars, inside, layout, text};
    use crate::fonts::Font;
    use crate::hit::Zone;
    use crate::icons;
    use crate::layout::{Layout, Rect};
    use crate::log::{Body, COPIED, COPY, Filter, Row, STOPPED, SUBTITLE};
    use crate::nav::{Nav, Page as NavPage};
    use crate::scene::{Op, stroke};
    use crate::scroll::Pane;

    const T: Theme = Theme::LIGHT;
    const S: Scale = Scale { dpi: 96 };
    const ALL: Rect = Rect::new(248, 112, 49, 32);
    const WARNINGS: Rect = Rect::new(297, 112, 84, 32);
    const COPY_BUTTON: Rect = Rect::new(932, 112, 80, 32);
    const LIST: Rect = Rect::new(248, 158, 764, 498);

    fn row(level: LogLevel, scope: &str, message: &str) -> Row {
        Row {
            time: "09:41:07".to_owned(),
            level,
            scope: scope.to_owned(),
            message: message.to_owned(),
        }
    }

    fn rows() -> Vec<Row> {
        vec![
            row(LogLevel::Info, "agent", "listening on 127.0.0.1:8080"),
            row(LogLevel::Warn, "session 4", "tunnel closed early"),
            row(LogLevel::Error, "proxy", "gateway refused the tunnel"),
        ]
    }

    fn page(body: Body) -> Page {
        let copy = matches!(body, Body::Rows(_)).then_some(COPY);
        Page {
            subtitle: SUBTITLE.to_owned(),
            alert: false,
            filter: Filter::All,
            copy,
            body,
        }
    }

    fn view() -> View {
        let mut nav = Nav::default();
        nav.select(NavPage::Log);
        View {
            nav,
            ..View::default()
        }
    }

    fn draw_on(l: &Layout, page: &Page, v: &View) -> Board {
        board(l, S, &T, v, page, &Chars)
    }

    fn draw_with(page: &Page, v: &View) -> Board {
        draw_on(&layout(), page, v)
    }

    fn draw(page: &Page) -> Board {
        draw_with(page, &view())
    }

    #[test]
    fn other_pages_draw_nothing() {
        assert_eq!(
            draw_with(&page(Body::Rows(rows())), &View::default()),
            Board::default()
        );
    }

    #[test]
    fn the_subtitle_sits_under_the_title_and_the_lines_scroll_below_the_tools() {
        let b = draw(&page(Body::Rows(rows())));
        assert_eq!(
            b.ops[..2],
            [
                Op::Clip(Rect::new(248, 44, 764, 612)),
                text(Font::Body, SUBTITLE, Rect::new(248, 80, 764, 18), T.muted),
            ]
        );
        assert!(b.ops.contains(&Op::Clip(LIST)));
        assert_eq!(b.pane, Some(Pane::new(LIST, 8 + 3 * 24 + 8, 0)));
    }

    #[test]
    fn a_problem_replaces_the_subtitle_as_a_warning() {
        let mut p = page(Body::Rows(rows()));
        p.subtitle = "Could not copy the log".to_owned();
        p.alert = true;
        assert_eq!(
            draw(&p).ops[1],
            text(
                Font::Body,
                "Could not copy the log",
                Rect::new(248, 80, 764, 18),
                T.warning
            )
        );
    }

    #[test]
    fn the_filter_is_a_two_part_toggle_marking_the_chosen_part() {
        let ops = draw(&page(Body::Rows(rows()))).ops;
        let toggle = Rect::new(248, 112, 133, 32);
        assert_eq!(
            inside(&ops, toggle),
            [
                Op::Round(toggle, 6.0, T.border),
                Op::Round(Rect::new(249, 113, 131, 30), 5.0, T.card),
                Op::Round(Rect::new(251, 115, 43, 26), 4.0, T.tile),
                text(Font::BodyStrong, "All", Rect::new(262, 112, 21, 32), T.text),
                text(Font::Body, "Warnings", Rect::new(311, 112, 56, 32), T.muted),
            ]
        );
        let mut p = page(Body::Rows(rows()));
        p.filter = Filter::Warnings;
        let ops = draw(&p).ops;
        let marked = inside(&ops, toggle);
        assert_eq!(
            marked[2],
            Op::Round(Rect::new(300, 115, 78, 26), 4.0, T.tile)
        );
        assert_eq!(
            marked[3..],
            [
                text(Font::Body, "All", Rect::new(262, 112, 21, 32), T.muted),
                text(
                    Font::BodyStrong,
                    "Warnings",
                    Rect::new(311, 112, 56, 32),
                    T.text
                ),
            ]
        );
    }

    #[test]
    fn hovering_the_other_filter_tints_it() {
        let mut v = view();
        v.pointer.moved(Zone::LogFilter(Filter::Warnings));
        let ops = draw_with(&page(Body::Rows(rows())), &v).ops;
        assert!(ops.contains(&Op::Round(
            Rect::new(300, 115, 78, 26),
            4.0,
            T.caption_hover
        )));
    }

    #[test]
    fn the_filters_and_the_copy_button_are_the_targets() {
        assert_eq!(
            draw(&page(Body::Rows(rows()))).targets,
            [
                (ALL, Zone::LogFilter(Filter::All)),
                (WARNINGS, Zone::LogFilter(Filter::Warnings)),
                (COPY_BUTTON, Zone::CopyLog),
            ]
        );
    }

    #[test]
    fn the_copy_button_is_outlined_and_says_when_it_copied() {
        let ops = draw(&page(Body::Rows(rows()))).ops;
        assert_eq!(
            inside(&ops, COPY_BUTTON),
            [
                Op::Round(COPY_BUTTON, 6.0, T.border),
                Op::Round(Rect::new(933, 113, 78, 30), 5.0, T.card),
                Op::Icon(
                    icons::COPY,
                    Rect::new(946, 120, 16, 16),
                    stroke(S, &icons::COPY, 16.0),
                    T.text
                ),
                text(Font::BodyStrong, COPY, Rect::new(970, 112, 28, 32), T.text),
            ]
        );
        let mut p = page(Body::Rows(rows()));
        p.copy = Some(COPIED);
        let copied = draw(&p);
        assert_eq!(
            copied.targets.last(),
            Some(&(Rect::new(918, 112, 94, 32), Zone::CopyLog))
        );
    }

    #[test]
    fn each_line_shows_time_level_scope_and_message_in_mono() {
        let ops = draw(&page(Body::Rows(rows()))).ops;
        let card = Rect::new(248, 158, 764, 88);
        let lines = inside(&ops, card);
        assert_eq!(
            lines[..6],
            [
                Op::Round(card, 10.0, T.border),
                Op::Round(Rect::new(249, 159, 762, 86), 9.0, T.card),
                text(Font::Mono, "09:41:07", Rect::new(264, 166, 56, 24), T.muted),
                text(Font::Mono, "INFO", Rect::new(332, 166, 35, 24), T.muted),
                text(Font::Mono, "agent", Rect::new(379, 166, 63, 24), T.muted),
                text(
                    Font::Mono,
                    "listening on 127.0.0.1:8080",
                    Rect::new(454, 166, 542, 24),
                    T.text
                ),
            ]
        );
        assert!(lines.contains(&text(
            Font::Mono,
            "WARN",
            Rect::new(332, 190, 35, 24),
            T.warning
        )));
        assert!(lines.contains(&text(
            Font::Mono,
            "ERROR",
            Rect::new(332, 214, 35, 24),
            T.revoke_glyph
        )));
        assert_eq!(lines.len(), 2 + 3 * 4);
    }

    #[test]
    fn long_scopes_leave_room_for_the_message() {
        let wide = "s".repeat(400);
        let ops = draw(&page(Body::Rows(vec![row(LogLevel::Info, &wide, "m")]))).ops;
        assert!(ops.contains(&text(
            Font::Mono,
            &wide,
            Rect::new(379, 166, 183, 24),
            T.muted
        )));
        assert!(ops.contains(&text(Font::Mono, "m", Rect::new(574, 166, 422, 24), T.text)));
    }

    #[test]
    fn only_the_lines_in_view_are_drawn_and_the_last_screen_can_be_reached() {
        let many: Vec<Row> = (0..100)
            .map(|n| row(LogLevel::Info, "agent", &format!("line {n}")))
            .collect();
        let p = page(Body::Rows(many));
        let messages = |b: &Board| -> Vec<String> {
            b.ops
                .iter()
                .filter_map(|op| match op {
                    Op::Text(Font::Mono, s, _, ink) if *ink == T.text => Some(s.to_string()),
                    _ => None,
                })
                .collect()
        };
        let top = draw(&p);
        assert_eq!(top.pane.map(|pane| pane.content), Some(8 + 100 * 24 + 8));
        let shown = messages(&top);
        assert_eq!(shown.first().map(String::as_str), Some("line 0"));
        assert_eq!(shown.len(), 21);
        let mut v = view();
        v.scroll.set(NavPage::Log, i32::MAX);
        let bottom = draw_with(&p, &v);
        assert!(bottom.pane.is_some_and(|pane| pane.at_bottom()));
        let shown = messages(&bottom);
        assert_eq!(shown.last().map(String::as_str), Some("line 99"));
        assert!(shown.len() <= 22);
    }

    #[test]
    fn without_lines_the_page_says_why_and_offers_nothing_to_copy() {
        let b = draw(&page(Body::Empty(STOPPED.to_owned())));
        let card = Rect::new(248, 158, 764, 56);
        assert_eq!(
            inside(&b.ops, card),
            [
                Op::Round(card, 10.0, T.border),
                Op::Round(Rect::new(249, 159, 762, 54), 9.0, T.card),
                text(Font::Body, STOPPED, Rect::new(264, 158, 732, 56), T.muted),
            ]
        );
        assert_eq!(
            b.targets,
            [
                (ALL, Zone::LogFilter(Filter::All)),
                (WARNINGS, Zone::LogFilter(Filter::Warnings)),
            ]
        );
    }

    #[test]
    fn a_short_window_scrolls_the_lines_under_the_tools() {
        let l = Layout::new(1040, 300, S, true);
        let b = draw_on(
            &l,
            &page(Body::Rows(rows().into_iter().cycle().take(12).collect())),
            &view(),
        );
        let pane = b.pane.expect("a scrolling pane");
        assert_eq!(pane.view.y, 158);
        assert!(pane.content > pane.view.h);
    }
}
