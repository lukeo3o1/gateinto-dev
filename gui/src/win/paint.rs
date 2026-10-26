use super::d2d::Canvas;
use super::text::{Align, Fonts};
use crate::color::{self, Rgb};
use crate::geom::RectF;
use crate::icons::{self, Icon};
use crate::layout::{Font, Layout, Rect};
use crate::model::{self, Session, SessionKind};
use crate::scale::Scale;
use crate::style::{self, Control, State};

const NAV_ICONS: [Icon; 4] = [
    icons::SESSIONS,
    icons::GATEWAYS,
    icons::IDENTITY,
    icons::SETTINGS,
];

pub struct Ctx<'a> {
    pub fonts: &'a Fonts,
    pub s: Scale,
    pub layout: &'a Layout,
    pub sessions: &'a [Session],
}

impl Ctx<'_> {
    fn dip(&self, v: f32) -> f32 {
        self.s.pxf(v)
    }

    fn hairline(&self) -> f32 {
        self.s.hairline() as f32
    }

    fn icon_stroke(&self) -> f32 {
        self.s.stroke(icons::STROKE)
    }

    fn symbol(&self, g: &Canvas, icon: &Icon, box_dip: f32, r: Rect, c: Rgb) {
        if !g.glyph(self.fonts, icon.glyph, box_dip, r, c) {
            g.icon(icon, r, self.icon_stroke(), c);
        }
    }
}

const LEFT: Align = Align {
    center: false,
    ellipsis: false,
};
const CLIPPED: Align = Align {
    center: false,
    ellipsis: true,
};
const CENTER: Align = Align {
    center: true,
    ellipsis: false,
};

pub fn scene(g: &Canvas, w: i32, h: i32, ctx: &Ctx) {
    let l = ctx.layout;
    let f = ctx.fonts;
    let bw = ctx.hairline();
    g.fill_rect(Rect::new(0, 0, w, h), color::WINDOW);
    let panel = RectF::from(l.panel);
    let radius = ctx.dip(8.0);
    g.fill_top_left_round(panel, radius, color::STROKE);
    let inner = RectF {
        x: panel.x + bw,
        y: panel.y + bw,
        w: panel.w - bw,
        h: panel.h - bw,
    };
    g.fill_top_left_round(inner, radius - bw, color::PANEL);

    g.text(f, Font::Title, model::TITLE, l.title, color::TEXT, CLIPPED);
    g.text(
        f,
        Font::Subtitle,
        model::SUBTITLE,
        l.subtitle,
        color::TEXT_SECONDARY,
        CLIPPED,
    );

    for (card, session) in l.cards.iter().zip(ctx.sessions) {
        g.bordered_round(card.frame, ctx.dip(6.0), bw, color::STROKE, color::CARD);
        g.fill_round(card.tile, ctx.dip(8.0), color::TILE);
        let icon = match session.kind {
            SessionKind::Device => icons::DEVICE,
            SessionKind::Browser => icons::BROWSER,
        };
        ctx.symbol(g, &icon, 20.0, card.icon, color::ACCENT);
        let pill = ctx.dip(10.0);
        g.fill_round(card.badges[0], pill, color::BADGE_OK_BG);
        g.fill_round(card.badges[1], pill, color::BADGE_BG);

        g.text(
            f,
            Font::CardTitle,
            session.title,
            card.title,
            color::TEXT,
            LEFT,
        );
        g.text(
            f,
            Font::Small,
            &session.tag(),
            card.tag,
            color::TEXT_SECONDARY,
            LEFT,
        );
        for (&(part, mono), &r) in session.detail().iter().zip(&card.detail) {
            let font = if mono { Font::Mono } else { Font::Small };
            g.text(f, font, part, r, color::TEXT_SECONDARY, LEFT);
        }
        let badges = [
            (session.auth, color::BADGE_OK_FG),
            (session.route, color::BADGE_FG),
        ];
        for ((label, fg), &r) in badges.into_iter().zip(&card.badges) {
            g.text(f, Font::Small, label, r, fg, CENTER);
        }
    }

    let device = &l.device;
    g.bordered_round(device.frame, ctx.dip(6.0), bw, color::STROKE, color::CARD);
    ctx.symbol(g, &icons::SHIELD, 20.0, device.icon, color::SHIELD);
    g.text(
        f,
        Font::DeviceTitle,
        model::DEVICE_KEY,
        device.title,
        color::TEXT,
        LEFT,
    );
    g.text(
        f,
        Font::Mono,
        model::FINGERPRINT,
        device.fingerprint,
        color::TEXT_SECONDARY,
        LEFT,
    );
}

fn surface(g: &Canvas, local: Rect, radius: f32, look: style::Look, bw: f32) {
    g.fill_rect(local, look.surface);
    match (look.border, look.fill) {
        (Some(border), Some(fill)) => g.bordered_round(local, radius, bw, border, fill),
        (None, Some(fill)) => g.fill_round(local, radius, fill),
        _ => {}
    }
}

pub fn control(g: &Canvas, bounds: Rect, control: Control, state: State, ctx: &Ctx) {
    let l = ctx.layout;
    let f = ctx.fonts;
    let (dx, dy) = (-bounds.x, -bounds.y);
    let local = Rect::new(0, 0, bounds.w, bounds.h);
    let look = style::look(control, state);
    let radius = match control {
        Control::Nav(_) => ctx.dip(6.0),
        Control::Details => ctx.dip(2.0),
        _ => ctx.dip(4.0),
    };

    surface(g, local, radius, look, ctx.hairline());
    match control {
        Control::Nav(i) => {
            let item = &l.nav[i];
            if i == model::SELECTED_NAV {
                let bar = item.indicator.translate(dx, dy);
                g.fill_round(bar, ctx.dip(2.0), color::ACCENT);
            }
            let icon = item.icon.translate(dx, dy);
            ctx.symbol(g, &NAV_ICONS[i], 18.0, icon, color::TEXT);
        }
        Control::NewSession => {
            ctx.symbol(g, &icons::PLUS, 14.0, l.plus.translate(dx, dy), look.text)
        }
        _ => {}
    }
    if state.focused {
        g.stroke_round(local, radius, ctx.s.stroke(2.0), color::FOCUS);
    }

    let text = control.label();
    match control {
        Control::Nav(i) => {
            let r = l.nav[i].label.translate(dx, dy);
            g.text(f, Font::Nav, text, r, look.text, CLIPPED);
        }
        Control::OpenLog => g.text(f, Font::Button, text, local, look.text, CENTER),
        Control::NewSession => {
            let r = l.new_session_label.translate(dx, dy);
            g.text(f, Font::Button, text, r, look.text, LEFT);
        }
        Control::Credentials(_) | Control::Revoke(_) => {
            g.text(f, Font::CardButton, text, local, look.text, CENTER);
        }
        Control::Details => {
            let r = l.device.details.translate(dx, dy);
            g.text(f, Font::Link, text, r, look.text, LEFT);
        }
    }
}
