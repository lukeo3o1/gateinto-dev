use super::{Board, Painter};
use crate::fonts::{Font, Measure};
use crate::hit::Zone;
use crate::icons;
use crate::layout::{Layout, Rect};
use crate::nav::Page as NavPage;
use crate::pointer::Look;
use crate::scale::Scale;
use crate::scene::{Op, View};
use crate::settings::{AGENT, APP, FROM_CONFIG, OPEN, Page, SIGN_IN, SIGN_IN_NOTE, THEME};
use crate::theme::{Choice, Theme};

pub fn board(l: &Layout, s: Scale, t: &Theme, v: &View, page: &Page, m: &impl Measure) -> Board {
    if v.nav.selected() != NavPage::Settings {
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
    let height = s.px(32.0);
    let button = p.button(
        Rect::new(line.x, line.bottom() - height, line.w, height),
        content.right(),
        OPEN,
    );
    p.outlined(button, icons::LOG, OPEN, Zone::OpenConfig);
    let line = Rect::new(line.x, line.y, button.x - s.px(16.0) - line.x, line.h);
    let font = if page.failed { Font::Body } else { Font::Mono };
    p.text(font, page.line.clone(), line, t.muted);

    let gap = s.px(14.0);
    let top = line.bottom() + gap;
    let view = Rect::new(content.x, top, content.w, (content.bottom() - top).max(0));
    let rows = page.agent.as_ref().map_or(1, Vec::len) as i32;
    let app_h = card_height(s, 2);
    let agent_h = card_height(s, rows);
    let offset = p.scroll(view, app_h + gap + agent_h);
    let app = Rect::new(content.x, top - offset, content.w, app_h);
    p.app(app, page);
    let agent = Rect::new(content.x, app.bottom() + gap, content.w, agent_h);
    p.agent(agent, &page.agent);
    p.finish()
}

pub(super) fn card_height(s: Scale, rows: i32) -> i32 {
    s.px(4.0) + s.px(44.0) + rows * s.px(44.0) + s.px(8.0)
}

impl<M: Measure> Painter<'_, M> {
    pub(super) fn section(
        &mut self,
        card: Rect,
        title: impl Into<std::borrow::Cow<'static, str>>,
    ) -> Rect {
        let (s, t) = (self.s, self.t);
        self.framed(card, 12.0, t.card);
        let pad = s.px(20.0);
        let heading = Rect::new(
            card.x + pad,
            card.y + s.px(4.0),
            card.w - 2 * pad,
            s.px(44.0),
        );
        self.text(Font::Heading, title, heading, t.text);
        heading
    }

    pub(super) fn line(&mut self, heading: Rect, i: i32) -> Rect {
        let s = self.s;
        let h = s.px(44.0);
        let row = Rect::new(heading.x, heading.bottom() + i * h, heading.w, h);
        let edge = Rect::new(row.x, row.y, row.w, s.hairline());
        self.push(Op::Fill(edge, self.t.border));
        row
    }

    fn app(&mut self, card: Rect, page: &Page) {
        let (s, t) = (self.s, self.t);
        let heading = self.section(card, APP);
        let row = self.line(heading, 0);
        self.theme(row, page.theme);
        let row = self.line(heading, 1);
        let (w, h) = (s.px(40.0), s.px(22.0));
        let switch = Rect::new(row.right() - w, row.y + (row.h - h) / 2, w, h);
        let x = switch.x - s.px(16.0);
        let (label, note) = (s.px(18.0), s.px(16.0));
        let y = row.y + (row.h - label - s.px(2.0) - note) / 2;
        let text = Rect::new(row.x, y, x - row.x, label);
        self.text(Font::Body, SIGN_IN, text, t.text);
        let below = Rect::new(row.x, text.bottom() + s.px(2.0), text.w, note);
        self.text(Font::Small, SIGN_IN_NOTE, below, t.muted);
        self.switch(switch, page.sign_in);
    }

    fn theme(&mut self, row: Rect, chosen: Choice) {
        let (s, t) = (self.s, self.t);
        let (inset, gap, pad, h) = (s.px(3.0), s.px(2.0), s.px(12.0), s.px(26.0));
        let widths = Choice::ALL.map(|c| {
            let label = c.name();
            let w = self.m.width(Font::Small, label);
            w.max(self.m.width(Font::SmallStrong, label)) + 2 * pad
        });
        let inner: i32 = widths.iter().sum::<i32>() + gap * (widths.len() as i32 - 1);
        let (gw, gh) = (inner + 2 * inset, h + 2 * inset);
        let group = Rect::new(row.right() - gw, row.y + (row.h - gh) / 2, gw, gh);
        let label = Rect::new(row.x, row.y, group.x - s.px(16.0) - row.x, row.h);
        self.text(Font::Body, THEME, label, t.text);
        self.push(Op::Round(group, s.pxf(7.0), t.tile));
        let mut x = group.x + inset;
        for (choice, w) in Choice::ALL.into_iter().zip(widths) {
            let part = Rect::new(x, group.y + inset, w, h);
            x = part.right() + gap;
            let zone = Zone::Theme(choice);
            let fill = match (choice == chosen, self.v.pointer.look(zone)) {
                (true, _) => Some(t.card),
                (false, Look::Rest) => None,
                (false, Look::Hover) => Some(t.caption_pressed),
                (false, Look::Pressed) => Some(t.border),
            };
            if let Some(fill) = fill {
                self.push(Op::Round(part, s.pxf(5.0), fill));
            }
            let (font, ink) = if choice == chosen {
                (Font::SmallStrong, t.text)
            } else {
                (Font::Small, t.muted)
            };
            let text = Rect::new(part.x + pad, part.y, part.w - 2 * pad, part.h);
            self.text(font, choice.name(), text, ink);
            self.target(part, zone);
        }
    }

    fn switch(&mut self, track: Rect, on: bool) {
        let (s, t) = (self.s, self.t);
        let (knob, inset) = (s.px(16.0), s.px(3.0));
        let (fill, dot, x) = if on {
            (t.button, t.button_glyph, track.right() - inset - knob)
        } else {
            (t.border, t.knob, track.x + inset)
        };
        self.push(Op::Round(track, track.h as f32 / 2.0, fill));
        let y = track.y + (track.h - knob) / 2;
        self.push(Op::Round(
            Rect::new(x, y, knob, knob),
            knob as f32 / 2.0,
            dot,
        ));
        self.target(track, Zone::SignIn);
    }

    pub(super) fn pair(&mut self, row: Rect, label: &'static str, value: String, font: Font) {
        let (s, t) = (self.s, self.t);
        let lw = self.m.width(Font::Body, label).min(row.w);
        self.text(
            Font::Body,
            label,
            Rect::new(row.x, row.y, lw, row.h),
            t.text,
        );
        let vw = self.m.width(font, &value);
        let x = (row.right() - vw).max(row.x + lw + s.px(16.0));
        let value_r = Rect::new(x, row.y, (row.right() - x).max(0), row.h);
        self.text(font, value, value_r, t.muted);
    }

    fn agent(&mut self, card: Rect, agent: &Result<Vec<(&'static str, String)>, String>) {
        let (s, t) = (self.s, self.t);
        let heading = self.section(card, AGENT);
        let w = self.m.width(Font::Small, FROM_CONFIG).min(heading.w);
        let source = Rect::new(heading.right() - w, heading.y, w, heading.h);
        let glyph = s.px(13.0);
        let glyph = Rect::new(source.x - s.px(6.0) - glyph, heading.y, glyph, heading.h);
        self.icon(icons::LOCK, glyph, 13.0, t.muted);
        self.text(Font::Small, FROM_CONFIG, source, t.muted);
        match agent {
            Ok(rows) => {
                for (i, (label, value)) in rows.iter().enumerate() {
                    let row = self.line(heading, i as i32);
                    self.pair(row, label, value.clone(), Font::Body);
                }
            }
            Err(error) => {
                let row = self.line(heading, 0);
                self.text(Font::Body, error.clone(), row, t.muted);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board::tests::{Chars, inside, layout, text};
    use crate::fonts::Font;
    use crate::hit::Zone;
    use crate::icons;
    use crate::layout::Rect;
    use crate::nav::{Nav, Page as NavPage};
    use crate::scene::{Op, stroke};
    use crate::scroll::Pane;
    use crate::settings::{AGENT, APP, FROM_CONFIG, OPEN, SIGN_IN, SIGN_IN_NOTE, THEME};
    use crate::theme::Choice;

    const T: Theme = Theme::LIGHT;
    const S: Scale = Scale { dpi: 96 };
    const BUTTON: Rect = Rect::new(848, 66, 164, 32);
    const SWITCH: Rect = Rect::new(952, 215, 40, 22);
    const AGENT_Y: i32 = 270;
    const SYSTEM: Rect = Rect::new(808, 169, 66, 26);
    const LIGHT: Rect = Rect::new(876, 169, 59, 26);
    const DARK: Rect = Rect::new(937, 169, 52, 26);

    fn page(sign_in: bool) -> Page {
        Page {
            line: "%APPDATA%\\Gateinto\\config.toml".to_owned(),
            failed: false,
            agent: Ok(vec![
                ("Browser", "chrome.exe".to_owned()),
                ("Concurrent tunnels", "64".to_owned()),
                ("Connect timeout", "10 s".to_owned()),
                ("Idle timeout", "300 s".to_owned()),
                ("Request header limit", "16 KB".to_owned()),
            ]),
            sign_in,
            theme: Choice::System,
        }
    }

    fn view() -> View {
        let mut nav = Nav::default();
        nav.select(NavPage::Settings);
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
        let b = draw_with(&page(true), &View::default());
        assert_eq!(b, Board::default());
    }

    #[test]
    fn the_header_shows_the_path_and_an_open_button_beside_the_title() {
        let ops = draw(&page(true)).ops;
        assert_eq!(ops[0], Op::Clip(Rect::new(248, 44, 764, 612)));
        assert_eq!(
            ops[1..8],
            [
                Op::Round(BUTTON, 6.0, T.border),
                Op::Round(Rect::new(849, 67, 162, 30), 5.0, T.card),
                Op::Icon(icons::LOG, Rect::new(862, 74, 16, 16), 1.0, T.text),
                text(Font::BodyStrong, OPEN, Rect::new(886, 66, 112, 32), T.text),
                text(
                    Font::Mono,
                    "%APPDATA%\\Gateinto\\config.toml",
                    Rect::new(248, 80, 584, 18),
                    T.muted
                ),
                Op::Clip(Rect::new(248, 112, 764, 544)),
                Op::Round(Rect::new(248, 112, 764, 144), 12.0, T.border),
            ]
        );
    }

    #[test]
    fn a_failure_replaces_the_path_in_body_text() {
        let mut p = page(true);
        p.line = "Could not open the config file".to_owned();
        p.failed = true;
        let ops = draw(&p).ops;
        assert_eq!(
            ops[5],
            text(
                Font::Body,
                "Could not open the config file",
                Rect::new(248, 80, 584, 18),
                T.muted
            )
        );
    }

    #[test]
    fn the_open_button_tints_on_hover_and_press() {
        let mut v = view();
        v.pointer.moved(Zone::OpenConfig);
        let hover = draw_with(&page(true), &v).ops;
        assert_eq!(
            hover[2],
            Op::Round(Rect::new(849, 67, 162, 30), 5.0, T.caption_hover)
        );
        v.pointer.down(Zone::OpenConfig);
        let pressed = draw_with(&page(true), &v).ops;
        assert_eq!(
            pressed[2],
            Op::Round(Rect::new(849, 67, 162, 30), 5.0, T.caption_pressed)
        );
    }

    #[test]
    fn the_app_card_has_the_theme_row_then_the_sign_in_switch_on() {
        let ops = draw(&page(true)).ops;
        let card = inside(&ops, Rect::new(248, 112, 764, 144));
        assert_eq!(
            card[..5],
            [
                Op::Round(Rect::new(248, 112, 764, 144), 12.0, T.border),
                Op::Round(Rect::new(249, 113, 762, 142), 11.0, T.card),
                text(Font::Heading, APP, Rect::new(268, 116, 724, 44), T.text),
                Op::Fill(Rect::new(268, 160, 724, 1), T.border),
                text(Font::Body, THEME, Rect::new(268, 160, 521, 44), T.text),
            ]
        );
        assert_eq!(
            card[card.len() - 5..],
            [
                Op::Fill(Rect::new(268, 204, 724, 1), T.border),
                text(Font::Body, SIGN_IN, Rect::new(268, 208, 668, 18), T.text),
                text(
                    Font::Small,
                    SIGN_IN_NOTE,
                    Rect::new(268, 228, 668, 16),
                    T.muted
                ),
                Op::Round(SWITCH, 11.0, T.button),
                Op::Round(Rect::new(973, 218, 16, 16), 8.0, T.button_glyph),
            ]
        );
    }

    #[test]
    fn the_theme_control_marks_the_chosen_part() {
        let ops = draw(&page(true)).ops;
        assert_eq!(
            inside(&ops, Rect::new(805, 166, 187, 32)),
            [
                Op::Round(Rect::new(805, 166, 187, 32), 7.0, T.tile),
                Op::Round(SYSTEM, 5.0, T.card),
                text(
                    Font::SmallStrong,
                    "System",
                    Rect::new(820, 169, 42, 26),
                    T.text
                ),
                text(Font::Small, "Light", Rect::new(888, 169, 35, 26), T.muted),
                text(Font::Small, "Dark", Rect::new(949, 169, 28, 26), T.muted),
            ]
        );
        let mut p = page(true);
        p.theme = Choice::Dark;
        let ops = draw(&p).ops;
        assert!(ops.contains(&Op::Round(DARK, 5.0, T.card)));
        assert!(!ops.contains(&Op::Round(SYSTEM, 5.0, T.card)));
        assert!(ops.contains(&text(
            Font::SmallStrong,
            "Dark",
            Rect::new(949, 169, 28, 26),
            T.text
        )));
    }

    #[test]
    fn theme_parts_tint_on_hover_and_press() {
        let mut v = view();
        v.pointer.moved(Zone::Theme(Choice::Light));
        let ops = draw_with(&page(true), &v).ops;
        assert!(ops.contains(&Op::Round(LIGHT, 5.0, T.caption_pressed)));
        v.pointer.down(Zone::Theme(Choice::Light));
        let ops = draw_with(&page(true), &v).ops;
        assert!(ops.contains(&Op::Round(LIGHT, 5.0, T.border)));
    }

    #[test]
    fn the_switch_off_shows_its_knob_on_the_left() {
        let ops = draw(&page(false)).ops;
        assert_eq!(
            inside(&ops, SWITCH),
            [
                Op::Round(SWITCH, 11.0, T.border),
                Op::Round(Rect::new(955, 218, 16, 16), 8.0, T.knob),
            ]
        );
    }

    #[test]
    fn the_switch_knob_stands_out_in_both_themes() {
        for t in [Theme::LIGHT, Theme::DARK] {
            assert_ne!(t.button_glyph, t.button);
            assert_ne!(t.knob, t.border);
        }
    }

    #[test]
    fn the_button_the_theme_parts_and_the_switch_are_targets() {
        assert_eq!(
            draw(&page(false)).targets,
            [
                (BUTTON, Zone::OpenConfig),
                (SYSTEM, Zone::Theme(Choice::System)),
                (LIGHT, Zone::Theme(Choice::Light)),
                (DARK, Zone::Theme(Choice::Dark)),
                (SWITCH, Zone::SignIn),
            ]
        );
    }

    #[test]
    fn the_agent_card_lists_the_config_values_right_aligned() {
        let ops = draw(&page(true)).ops;
        let y = AGENT_Y;
        let card = inside(&ops, Rect::new(248, y, 764, 276));
        assert_eq!(
            card[..7],
            [
                Op::Round(Rect::new(248, y, 764, 276), 12.0, T.border),
                Op::Round(Rect::new(249, y + 1, 762, 274), 11.0, T.card),
                text(Font::Heading, AGENT, Rect::new(268, y + 4, 724, 44), T.text),
                Op::Icon(
                    icons::LOCK,
                    Rect::new(833, y + 19, 13, 13),
                    stroke(S, &icons::LOCK, 13.0),
                    T.muted
                ),
                text(
                    Font::Small,
                    FROM_CONFIG,
                    Rect::new(852, y + 4, 140, 44),
                    T.muted
                ),
                Op::Fill(Rect::new(268, y + 48, 724, 1), T.border),
                text(
                    Font::Body,
                    "Browser",
                    Rect::new(268, y + 48, 49, 44),
                    T.text
                ),
            ]
        );
        assert_eq!(
            card[7],
            text(
                Font::Body,
                "chrome.exe",
                Rect::new(922, y + 48, 70, 44),
                T.muted
            )
        );
        let last = y + 48 + 4 * 44;
        assert_eq!(
            card[card.len() - 3..],
            [
                Op::Fill(Rect::new(268, last, 724, 1), T.border),
                text(
                    Font::Body,
                    "Request header limit",
                    Rect::new(268, last, 140, 44),
                    T.text
                ),
                text(Font::Body, "16 KB", Rect::new(957, last, 35, 44), T.muted),
            ]
        );
        assert_eq!(card.len(), 5 + 5 * 3);
    }

    #[test]
    fn a_long_value_keeps_clear_of_its_label() {
        let mut p = page(true);
        p.agent = Ok(vec![("Browser", "b".repeat(200))]);
        let ops = draw(&p).ops;
        assert!(ops.contains(&text(
            Font::Body,
            &"b".repeat(200),
            Rect::new(333, AGENT_Y + 48, 659, 44),
            T.muted
        )));
    }

    #[test]
    fn a_config_error_shows_one_line_instead_of_values() {
        let mut p = page(true);
        p.agent = Err("config file c.toml: broken".to_owned());
        let ops = draw(&p).ops;
        let y = AGENT_Y;
        let card = inside(&ops, Rect::new(248, y, 764, 100));
        assert_eq!(
            card[card.len() - 2..],
            [
                Op::Fill(Rect::new(268, y + 48, 724, 1), T.border),
                text(
                    Font::Body,
                    "config file c.toml: broken",
                    Rect::new(268, y + 48, 724, 44),
                    T.muted
                ),
            ]
        );
        assert!(ops.contains(&Op::Round(Rect::new(248, y, 764, 100), 12.0, T.border)));
        assert_eq!(draw(&p).pane.map(|p| p.content), Some(258));
    }

    #[test]
    fn the_cards_scroll_under_the_header() {
        let b = draw(&page(true));
        assert_eq!(
            b.pane,
            Some(Pane::new(Rect::new(248, 112, 764, 544), 434, 0))
        );
        let short = Layout::new(1040, 400, S, true);
        let mut v = view();
        v.scroll.set(NavPage::Settings, 50);
        let b = board(&short, S, &T, &v, &page(true), &Chars);
        let pane = b.pane.unwrap();
        assert_eq!(pane.offset, 50);
        assert!(
            b.ops
                .contains(&Op::Round(Rect::new(248, 62, 764, 144), 12.0, T.border))
        );
        assert_eq!(b.targets[0], (BUTTON, Zone::OpenConfig));
        assert_eq!(b.targets[4], (Rect::new(952, 165, 40, 22), Zone::SignIn));
    }
}
