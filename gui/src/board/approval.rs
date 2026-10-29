use std::borrow::Cow;

use super::dialog::wrap;
use super::{Board, Painter};
use crate::approval::Button;
use crate::focus::{self, Stop};
use crate::fonts::{Font, Measure};
use crate::hit::Zone;
use crate::i18n::{Text, fill, tr};
use crate::layout::Rect;
use crate::pointer::Look;
use crate::scale::Scale;
use crate::scene::{Op, View};
use crate::theme::{Rgb, Theme};

const WIDTH: f32 = 460.0;
const PAD: f32 = 24.0;
const LINE: f32 = 20.0;
const FOOTER: f32 = 64.0;
const BUTTON: f32 = 32.0;
const GAP: f32 = 8.0;
const MIN: f32 = 96.0;
const SIDES: f32 = 28.0;

pub struct Sheet<'a> {
    pub notice: &'a str,
    pub countdown: Option<u64>,
    pub hover: Option<Button>,
    pub pressed: Option<Button>,
}

impl Sheet<'_> {
    fn look(&self, button: Button) -> Look {
        match self.pressed {
            Some(pressed) if pressed == button && self.hover == Some(button) => Look::Pressed,
            Some(_) => Look::Rest,
            None if self.hover == Some(button) => Look::Hover,
            None => Look::Rest,
        }
    }
}

pub fn width(s: Scale) -> i32 {
    s.px(WIDTH)
}

pub fn lines(m: &impl Measure, notice: &str, width: i32) -> Vec<String> {
    notice
        .split('\n')
        .flat_map(|paragraph| match wrap(m, Font::Body, paragraph, width) {
            lines if lines.is_empty() => vec![String::new()],
            lines => lines,
        })
        .collect()
}

pub fn height(s: Scale, m: &impl Measure, notice: &str) -> i32 {
    let count = lines(m, notice, width(s) - 2 * s.px(PAD)).len() as i32;
    2 * s.px(PAD) + count * s.px(LINE) + s.px(FOOTER)
}

pub fn button(zone: Zone) -> Option<Button> {
    match zone {
        Zone::DenyLink => Some(Button::Deny),
        Zone::AllowLink => Some(Button::Allow),
        _ => None,
    }
}

pub fn approval(frame: Rect, s: Scale, t: &Theme, sheet: &Sheet, m: &impl Measure) -> Board {
    let view = View::default();
    let mut p = Painter::within(frame, s, t, &view, m);
    p.push(Op::Fill(frame, t.bg));
    let pad = s.px(PAD);
    let width = frame.w - 2 * pad;
    for (i, line) in lines(m, sheet.notice, width).into_iter().enumerate() {
        let y = frame.y + pad + i as i32 * s.px(LINE);
        p.text(
            Font::Body,
            line,
            Rect::new(frame.x + pad, y, width, s.px(LINE)),
            t.text,
        );
    }

    let footer = Rect::new(
        frame.x,
        frame.bottom() - s.px(FOOTER),
        frame.w,
        s.px(FOOTER),
    );
    p.push(Op::Fill(footer, t.card));
    p.push(Op::Fill(
        Rect::new(footer.x, footer.y, footer.w, s.hairline()),
        t.border,
    ));
    let h = s.px(BUTTON);
    let y = footer.y + (footer.h - h) / 2;
    let deny_label = tr(Text::Deny);
    let deny_w = p.button_width(&[deny_label]);
    let deny = Rect::new(footer.right() - pad - deny_w, y, deny_w, h);
    let allow_w = p.button_width(&[tr(Text::Allow), &fill(Text::AllowIn, &[&1])]);
    let allow = Rect::new(deny.x - s.px(GAP) - allow_w, y, allow_w, h);
    match sheet.countdown {
        Some(left) => {
            p.framed(allow, 6.0, t.tile);
            p.label(allow, fill(Text::AllowIn, &[&left]), t.eyes_idle);
        }
        None => {
            let fill = match sheet.look(Button::Allow) {
                Look::Rest => t.card,
                Look::Hover => t.caption_hover,
                Look::Pressed => t.caption_pressed,
            };
            p.framed(allow, 6.0, fill);
            p.label(allow, tr(Text::Allow), t.text);
            p.target(allow, Zone::AllowLink);
        }
    }

    let fill = match sheet.look(Button::Deny) {
        Look::Rest => t.button,
        Look::Hover => t.button_hover,
        Look::Pressed => t.button_pressed,
    };
    p.push(Op::Round(deny, s.pxf(6.0), fill));
    p.label(deny, deny_label, t.button_text);
    p.target(deny, Zone::DenyLink);
    let stop = Stop {
        rect: deny,
        zone: Zone::DenyLink,
        scrolls: false,
        clip: frame,
    };
    for op in focus::outline(&stop, s, t) {
        p.push(op);
    }
    p.finish()
}

impl<M: Measure> Painter<'_, M> {
    fn button_width(&self, labels: &[&str]) -> i32 {
        let text = labels
            .iter()
            .map(|label| self.m.width(Font::BodyStrong, label))
            .max()
            .unwrap_or(0);
        (self.s.px(SIDES) + text).max(self.s.px(MIN))
    }

    fn label(&mut self, r: Rect, label: impl Into<Cow<'static, str>>, ink: Rgb) {
        let label = label.into();
        let x = r.x + (r.w - self.m.width(Font::BodyStrong, &label)).max(0) / 2;
        self.text(
            Font::BodyStrong,
            label,
            Rect::new(x, r.y, r.right() - x, r.h),
            ink,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board::tests::{Chars, text};
    use crate::focus::{self, Stop};
    use crate::fonts::Font;
    use crate::hit::Zone;
    use crate::layout::Rect;
    use crate::scale::Scale;
    use crate::scene::Op;
    use crate::theme::Theme;

    const T: Theme = Theme::LIGHT;
    const S: Scale = Scale { dpi: 96 };
    const NOTICE: &str = "first\n\nsecond";
    const FRAME: Rect = Rect::new(0, 0, 460, 172);
    const DENY: Rect = Rect::new(340, 124, 96, 32);
    const ALLOW: Rect = Rect::new(236, 124, 96, 32);

    fn sheet(countdown: Option<u64>) -> Sheet<'static> {
        Sheet {
            notice: NOTICE,
            countdown,
            hover: None,
            pressed: None,
        }
    }

    fn draw(sheet: &Sheet) -> Board {
        approval(FRAME, S, &T, sheet, &Chars)
    }

    fn texts(board: &Board) -> Vec<String> {
        board
            .ops
            .iter()
            .filter_map(|op| match op {
                Op::Text(_, s, ..) => Some(s.to_string()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn paragraphs_keep_their_breaks_and_wrap_within_the_width() {
        let lines = lines(&Chars, "one two three\n\nfour", 70);

        assert_eq!(lines, ["one two", "three", "", "four"]);
    }

    #[test]
    fn the_height_fits_every_line_and_the_footer() {
        assert_eq!(width(S), 460);
        assert_eq!(height(S, &Chars, NOTICE), 172);
    }

    #[test]
    fn the_notice_is_drawn_line_by_line() {
        let ops = draw(&sheet(None)).ops;

        assert!(ops.contains(&text(
            Font::Body,
            "first",
            Rect::new(24, 24, 412, 20),
            T.text
        )));
        assert!(ops.contains(&text(
            Font::Body,
            "second",
            Rect::new(24, 64, 412, 20),
            T.text
        )));
    }

    #[test]
    fn a_disarmed_allow_shows_its_countdown_and_takes_no_clicks() {
        let board = draw(&sheet(Some(1)));

        assert_eq!(board.targets, [(DENY, Zone::DenyLink)]);
        assert!(board.ops.contains(&text(
            Font::BodyStrong,
            "Allow (1)",
            Rect::new(ALLOW.x + 16, ALLOW.y, 80, 32),
            T.eyes_idle
        )));
    }

    #[test]
    fn an_armed_allow_takes_clicks() {
        let board = draw(&sheet(None));

        assert_eq!(
            board.targets,
            [(ALLOW, Zone::AllowLink), (DENY, Zone::DenyLink)]
        );
        assert!(board.ops.contains(&text(
            Font::BodyStrong,
            "Allow",
            Rect::new(ALLOW.x + 30, ALLOW.y, 66, 32),
            T.text
        )));
    }

    #[test]
    fn deny_is_the_focused_primary_button() {
        let ops = draw(&sheet(None)).ops;
        let ring = focus::outline(
            &Stop {
                rect: DENY,
                zone: Zone::DenyLink,
                scrolls: false,
                clip: FRAME,
            },
            S,
            &T,
        );

        assert!(ops.contains(&Op::Round(DENY, 6.0, T.button)));
        assert!(ops.contains(&text(
            Font::BodyStrong,
            "Deny",
            Rect::new(DENY.x + 34, DENY.y, 62, 32),
            T.button_text
        )));
        assert!(ring.iter().all(|op| ops.contains(op)));
        assert!(!ring.is_empty());
    }

    #[test]
    fn buttons_tint_on_hover_and_only_press_while_the_pointer_stays() {
        let mut s = sheet(None);
        s.hover = Some(Button::Deny);
        assert!(draw(&s).ops.contains(&Op::Round(DENY, 6.0, T.button_hover)));

        s.pressed = Some(Button::Deny);
        assert!(
            draw(&s)
                .ops
                .contains(&Op::Round(DENY, 6.0, T.button_pressed))
        );

        s.hover = Some(Button::Allow);
        let ops = draw(&s).ops;
        assert!(ops.contains(&Op::Round(DENY, 6.0, T.button)));
        assert!(ops.contains(&Op::Round(Rect::new(237, 125, 94, 30), 5.0, T.card)));

        s.pressed = Some(Button::Allow);
        let ops = draw(&s).ops;
        assert!(ops.contains(&Op::Round(
            Rect::new(237, 125, 94, 30),
            5.0,
            T.caption_pressed
        )));
    }

    #[test]
    fn zones_name_their_buttons() {
        assert_eq!(button(Zone::DenyLink), Some(Button::Deny));
        assert_eq!(button(Zone::AllowLink), Some(Button::Allow));
        assert_eq!(button(Zone::Client), None);
    }

    #[test]
    fn the_buttons_speak_chinese() {
        let _zh = crate::i18n::speaking(crate::i18n::Language::Chinese);

        let armed = texts(&draw(&sheet(None)));
        let disarmed = texts(&draw(&sheet(Some(1))));

        assert!(armed.contains(&"允許".to_owned()));
        assert!(armed.contains(&"拒絕".to_owned()));
        assert!(disarmed.contains(&"允許（1）".to_owned()));
    }
}
