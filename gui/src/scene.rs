use std::borrow::Cow;

use crate::fonts::Font;
use crate::hit::Zone;
use crate::icons::{self, Icon};
use crate::layout::{Layout, Rect};
use crate::logo::State;
use crate::menu::Popup;
use crate::nav::Nav;
use crate::pointer::{Look, Pointer};
use crate::scale::Scale;
use crate::scroll::Offsets;
use crate::theme::{Rgb, Theme};

#[derive(Clone, Debug, PartialEq)]
pub enum Op {
    Fill(Rect, Rgb),
    Shade(Rect, Rgb, f32),
    Round(Rect, f32, Rgb),
    Icon(Icon, Rect, f32, Rgb),
    Text(Font, Cow<'static, str>, Rect, Rgb),
    Logo(Rect, State),
    Ring(Rect, f32, f32, Rgb),
    Clip(Rect),
    Unclip,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct View {
    pub nav: Nav,
    pub pointer: Pointer,
    pub maximized: bool,
    pub scroll: Offsets,
    pub popup: Option<Popup>,
    pub popup_scroll: i32,
    pub logo: State,
    pub demo: bool,
}

pub const BANNER: &str = "Demo";
pub const BANNER_NOTE: &str = "Sample data only";

const RAIL_ICON: f32 = 20.0;
const CAPTION_GLYPH: f32 = 10.0;

pub fn stroke(s: Scale, icon: &Icon, size: f32) -> f32 {
    s.stroke(icon.stroke * size / icon.view)
}

pub fn scene(l: &Layout, s: Scale, t: &Theme, v: &View) -> Vec<Op> {
    let mut ops = vec![
        Op::Fill(Rect::new(0, 0, l.caption_row.right(), l.rail.h), t.bg),
        Op::Fill(l.rail, t.rail),
        Op::Fill(l.rail_edge, t.rail_edge),
        Op::Logo(l.logo, v.logo),
        Op::Text(Font::Brand, "Gateinto".into(), l.brand_text, t.rail_on),
    ];
    for item in l.nav {
        let selected = v.nav.selected() == item.page;
        if selected {
            ops.push(Op::Round(item.frame, s.pxf(6.0), t.rail_selected));
            ops.push(Op::Round(item.bar, s.pxf(1.5), t.accent));
        } else if v.pointer.look(Zone::Nav(item.page)) != Look::Rest {
            ops.push(Op::Round(item.frame, s.pxf(6.0), t.rail_hover));
        }
        let icon = icons::rail_icon(item.page);
        let (font, ink, glyph) = if selected {
            (Font::ItemSelected, t.rail_on, t.rail_icon)
        } else {
            (Font::Item, t.rail_text, t.rail_text)
        };
        ops.push(Op::Icon(
            icon,
            item.icon,
            stroke(s, &icon, RAIL_ICON),
            glyph,
        ));
        ops.push(Op::Text(font, item.page.label().into(), item.label, ink));
    }
    if v.demo {
        let b = l.banner;
        ops.push(Op::Round(b.card, s.pxf(6.0), t.notice));
        ops.push(Op::Text(
            Font::SmallStrong,
            BANNER.into(),
            b.title,
            t.notice_text,
        ));
        ops.push(Op::Text(
            Font::Small,
            BANNER_NOTE.into(),
            b.note,
            t.notice_text,
        ));
    }
    if let Some(b) = l.buttons {
        let maximize = if v.maximized {
            icons::RESTORE
        } else {
            icons::MAXIMIZE
        };
        for (zone, rect, icon) in [
            (Zone::Minimize, b.minimize, icons::MINIMIZE),
            (Zone::Maximize, b.maximize, maximize),
            (Zone::Close, b.close, icons::CLOSE),
        ] {
            let close = zone == Zone::Close;
            let fill = match (v.pointer.look(zone), close) {
                (Look::Rest, _) => None,
                (Look::Hover, false) => Some(t.caption_hover),
                (Look::Pressed, false) => Some(t.caption_pressed),
                (Look::Hover, true) => Some(t.close_hover),
                (Look::Pressed, true) => Some(t.close_pressed),
            };
            if let Some(fill) = fill {
                ops.push(Op::Fill(rect, fill));
            }
            let ink = if close && fill.is_some() {
                t.close_glyph_hover
            } else {
                t.caption
            };
            ops.push(Op::Icon(
                icon,
                b.glyph(rect),
                stroke(s, &icon, CAPTION_GLYPH),
                ink,
            ));
        }
    }
    ops.push(Op::Text(
        Font::Title,
        v.nav.selected().title().into(),
        l.title,
        t.text,
    ));
    ops
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nav::Page;

    const T: Theme = Theme::LIGHT;
    const S: Scale = Scale { dpi: 96 };

    fn layout(caption_buttons: bool) -> Layout {
        Layout::new(1040, 680, S, caption_buttons)
    }

    fn draw(v: &View) -> Vec<Op> {
        scene(&layout(true), S, &T, v)
    }

    fn at(page: Page) -> View {
        let mut nav = Nav::default();
        nav.select(page);
        View {
            nav,
            ..View::default()
        }
    }

    fn inside(ops: &[Op], r: Rect) -> Vec<Op> {
        let within = |o: Rect| {
            o.x >= r.x && o.y >= r.y && o.right() <= r.right() && o.bottom() <= r.bottom()
        };
        ops.iter()
            .filter(|op| match op {
                Op::Fill(o, _)
                | Op::Shade(o, ..)
                | Op::Round(o, ..)
                | Op::Icon(_, o, ..)
                | Op::Text(_, _, o, _)
                | Op::Logo(o, _)
                | Op::Ring(o, ..) => within(*o),
                Op::Clip(_) | Op::Unclip => false,
            })
            .cloned()
            .collect()
    }

    #[test]
    fn paints_background_rail_and_brand_first() {
        let l = layout(true);
        let ops = draw(&View::default());
        assert_eq!(
            ops[..5],
            [
                Op::Fill(Rect::new(0, 0, 1040, 680), T.bg),
                Op::Fill(l.rail, T.rail),
                Op::Fill(l.rail_edge, T.rail_edge),
                Op::Logo(l.logo, State::Idle),
                Op::Text(Font::Brand, "Gateinto".into(), l.brand_text, T.rail_on),
            ]
        );
    }

    #[test]
    fn the_brand_logo_follows_the_agent_state() {
        let l = layout(true);
        for logo in [State::Stopped, State::Relaying, State::Attention] {
            let v = View {
                logo,
                ..View::default()
            };
            assert_eq!(draw(&v)[3], Op::Logo(l.logo, logo));
        }
        assert_eq!(draw(&View::default())[3], Op::Logo(l.logo, State::Idle));
    }

    #[test]
    fn only_the_demo_draws_its_banner() {
        let b = layout(true).banner;
        let demo = View {
            demo: true,
            ..View::default()
        };
        assert_eq!(
            inside(&draw(&demo), b.card),
            [
                Op::Round(b.card, 6.0, T.notice),
                Op::Text(Font::SmallStrong, BANNER.into(), b.title, T.notice_text),
                Op::Text(Font::Small, BANNER_NOTE.into(), b.note, T.notice_text),
            ]
        );
        assert!(inside(&draw(&View::default()), b.card).is_empty());
    }

    #[test]
    fn selected_item_is_raised_with_an_accent_bar() {
        let item = layout(true).item(Page::Gateways);
        let ops = inside(&draw(&at(Page::Gateways)), item.frame);
        assert_eq!(
            ops,
            [
                Op::Round(item.frame, 6.0, T.rail_selected),
                Op::Round(item.bar, 1.5, T.accent),
                Op::Icon(icons::GATEWAYS, item.icon, 1.0, T.rail_icon),
                Op::Text(Font::ItemSelected, "Gateways".into(), item.label, T.rail_on),
            ]
        );
    }

    #[test]
    fn resting_items_are_flat_and_hovered_items_tint() {
        let item = layout(true).item(Page::Log);
        let rest = inside(&draw(&View::default()), item.frame);
        assert_eq!(
            rest,
            [
                Op::Icon(icons::LOG, item.icon, 1.0, T.rail_text),
                Op::Text(Font::Item, "Log".into(), item.label, T.rail_text),
            ]
        );
        let mut v = View::default();
        v.pointer.moved(Zone::Nav(Page::Log));
        let hovered = inside(&draw(&v), item.frame);
        assert_eq!(hovered[0], Op::Round(item.frame, 6.0, T.rail_hover));
        assert_eq!(hovered[1..], rest[..]);
    }

    #[test]
    fn caption_buttons_rest_hover_and_press() {
        let b = layout(true).buttons.unwrap();
        let ops = draw(&View::default());
        assert_eq!(
            inside(&ops, b.minimize),
            [Op::Icon(
                icons::MINIMIZE,
                b.glyph(b.minimize),
                1.0,
                T.caption
            )]
        );
        let mut v = View::default();
        v.pointer.moved(Zone::Maximize);
        assert_eq!(
            inside(&draw(&v), b.maximize),
            [
                Op::Fill(b.maximize, T.caption_hover),
                Op::Icon(icons::MAXIMIZE, b.glyph(b.maximize), 1.0, T.caption),
            ]
        );
        v.pointer.down(Zone::Minimize);
        assert_eq!(
            inside(&draw(&v), b.minimize)[0],
            Op::Fill(b.minimize, T.caption_pressed)
        );
    }

    #[test]
    fn close_turns_red_with_a_white_glyph() {
        let b = layout(true).buttons.unwrap();
        let mut v = View::default();
        v.pointer.moved(Zone::Close);
        let glyph = Op::Icon(icons::CLOSE, b.glyph(b.close), 1.0, T.close_glyph_hover);
        assert_eq!(
            inside(&draw(&v), b.close),
            [Op::Fill(b.close, T.close_hover), glyph.clone()]
        );
        v.pointer.down(Zone::Close);
        assert_eq!(
            inside(&draw(&v), b.close),
            [Op::Fill(b.close, T.close_pressed), glyph]
        );
    }

    #[test]
    fn maximized_windows_show_the_restore_glyph() {
        let b = layout(true).buttons.unwrap();
        let v = View {
            maximized: true,
            ..View::default()
        };
        assert_eq!(
            inside(&draw(&v), b.maximize),
            [Op::Icon(
                icons::RESTORE,
                b.glyph(b.maximize),
                1.0,
                T.caption
            )]
        );
    }

    #[test]
    fn system_frame_draws_no_caption_glyphs() {
        let ops = scene(&layout(false), S, &T, &View::default());
        assert!(!ops.iter().any(|op| matches!(
            op,
            Op::Icon(icon, ..) if [icons::MINIMIZE, icons::MAXIMIZE, icons::CLOSE].contains(icon)
        )));
    }

    #[test]
    fn page_title_names_the_selected_page_last() {
        let l = layout(true);
        let ops = draw(&at(Page::Device));
        assert_eq!(
            ops.last(),
            Some(&Op::Text(
                Font::Title,
                "This device".into(),
                l.title,
                T.text
            ))
        );
    }

    #[test]
    fn strokes_and_radii_scale_with_dpi() {
        let s = Scale::new(192);
        let l = Layout::new(2080, 1360, s, true);
        let item = l.item(Page::Sessions);
        let ops = inside(&scene(&l, s, &T, &View::default()), item.frame);
        assert_eq!(ops[0], Op::Round(item.frame, 12.0, T.rail_selected));
        assert_eq!(ops[1], Op::Round(item.bar, 3.0, T.accent));
        assert_eq!(
            ops[2],
            Op::Icon(icons::SESSIONS, item.icon, 3.0, T.rail_icon)
        );
    }
}
