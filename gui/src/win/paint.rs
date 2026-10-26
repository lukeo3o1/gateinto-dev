use windows_sys::Win32::Graphics::Gdi::HDC;

use super::gdi::{self, Align, Fonts};
use super::gdip::{Graphics, Path, RectF};
use crate::color;
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
}

fn rect_path(r: Rect) -> Path {
    Path::round_rect(r.into(), 0.0)
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

pub fn scene(dc: HDC, w: i32, h: i32, ctx: &Ctx) {
    let l = ctx.layout;
    let bw = ctx.hairline();
    if let Some(g) = Graphics::new(dc) {
        g.fill(&rect_path(Rect::new(0, 0, w, h)), color::WINDOW);
        let panel = RectF::from(l.panel);
        let radius = ctx.dip(8.0);
        g.fill(&Path::top_left_round(panel, radius), color::STROKE);
        let inner = RectF {
            x: panel.x + bw,
            y: panel.y + bw,
            w: panel.w - bw,
            h: panel.h - bw,
        };
        g.fill(&Path::top_left_round(inner, radius - bw), color::PANEL);

        for (card, session) in l.cards.iter().zip(ctx.sessions) {
            g.bordered_round(
                card.frame.into(),
                ctx.dip(6.0),
                bw,
                color::STROKE,
                color::CARD,
            );
            g.fill_round(card.tile.into(), ctx.dip(8.0), color::TILE);
            let icon = match session.kind {
                SessionKind::Device => icons::DEVICE,
                SessionKind::Browser => icons::BROWSER,
            };
            g.icon(&icon, card.icon, color::ACCENT);
            let pill = ctx.dip(10.0);
            g.fill_round(card.badges[0].into(), pill, color::BADGE_OK_BG);
            g.fill_round(card.badges[1].into(), pill, color::BADGE_BG);
        }

        let device = &l.device;
        g.bordered_round(
            device.frame.into(),
            ctx.dip(6.0),
            bw,
            color::STROKE,
            color::CARD,
        );
        g.icon(&icons::SHIELD, device.icon, color::SHIELD);
    }

    let f = ctx.fonts;
    gdi::text(
        dc,
        f,
        Font::Title,
        model::TITLE,
        l.title,
        color::TEXT,
        CLIPPED,
    );
    gdi::text(
        dc,
        f,
        Font::Subtitle,
        model::SUBTITLE,
        l.subtitle,
        color::TEXT_SECONDARY,
        CLIPPED,
    );

    for (card, session) in l.cards.iter().zip(ctx.sessions) {
        gdi::text(
            dc,
            f,
            Font::CardTitle,
            session.title,
            card.title,
            color::TEXT,
            LEFT,
        );
        gdi::text(
            dc,
            f,
            Font::Small,
            &session.tag(),
            card.tag,
            color::TEXT_SECONDARY,
            LEFT,
        );
        for (&(part, mono), &r) in session.detail().iter().zip(&card.detail) {
            let font = if mono { Font::Mono } else { Font::Small };
            gdi::text(dc, f, font, part, r, color::TEXT_SECONDARY, LEFT);
        }
        let badges = [
            (session.auth, color::BADGE_OK_FG),
            (session.route, color::BADGE_FG),
        ];
        for ((label, fg), &r) in badges.into_iter().zip(&card.badges) {
            gdi::text(dc, f, Font::Small, label, r, fg, CENTER);
        }
    }

    let device = &l.device;
    gdi::text(
        dc,
        f,
        Font::DeviceTitle,
        model::DEVICE_KEY,
        device.title,
        color::TEXT,
        LEFT,
    );
    gdi::text(
        dc,
        f,
        Font::Mono,
        model::FINGERPRINT,
        device.fingerprint,
        color::TEXT_SECONDARY,
        LEFT,
    );
}

fn surface(g: &Graphics, local: Rect, radius: f32, look: style::Look, bw: f32) {
    g.fill(&rect_path(local), look.surface);
    match (look.border, look.fill) {
        (Some(border), Some(fill)) => g.bordered_round(local.into(), radius, bw, border, fill),
        (None, Some(fill)) => g.fill_round(local.into(), radius, fill),
        _ => {}
    }
}

fn focus_ring(g: &Graphics, local: Rect, radius: f32, width: f32) {
    let ring = RectF::from(local).inset(width / 2.0);
    g.stroke(
        &Path::round_rect(ring, radius - width / 2.0),
        color::FOCUS,
        width,
    );
}

pub fn control(dc: HDC, bounds: Rect, control: Control, state: State, ctx: &Ctx) {
    let l = ctx.layout;
    let (dx, dy) = (-bounds.x, -bounds.y);
    let local = Rect::new(0, 0, bounds.w, bounds.h);
    let look = style::look(control, state);
    let radius = match control {
        Control::Nav(_) => ctx.dip(6.0),
        Control::Details => ctx.dip(2.0),
        _ => ctx.dip(4.0),
    };

    if let Some(g) = Graphics::new(dc) {
        surface(&g, local, radius, look, ctx.hairline());
        match control {
            Control::Nav(i) => {
                let item = &l.nav[i];
                if i == model::SELECTED_NAV {
                    let bar = item.indicator.translate(dx, dy);
                    g.fill_round(bar.into(), ctx.dip(2.0), color::ACCENT);
                }
                g.icon(&NAV_ICONS[i], item.icon.translate(dx, dy), color::TEXT);
            }
            Control::NewSession => g.icon(&icons::PLUS, l.plus.translate(dx, dy), look.text),
            _ => {}
        }
        if state.focused {
            focus_ring(&g, local, radius, ctx.dip(2.0).round().max(1.0));
        }
    }

    let f = ctx.fonts;
    let text = control.label();
    match control {
        Control::Nav(i) => {
            let r = l.nav[i].label.translate(dx, dy);
            gdi::text(dc, f, Font::Nav, text, r, look.text, CLIPPED);
        }
        Control::OpenLog => gdi::text(dc, f, Font::Button, text, local, look.text, CENTER),
        Control::NewSession => {
            let r = l.new_session_label.translate(dx, dy);
            gdi::text(dc, f, Font::Button, text, r, look.text, LEFT);
        }
        Control::Credentials(_) | Control::Revoke(_) => {
            gdi::text(dc, f, Font::CardButton, text, local, look.text, CENTER);
        }
        Control::Details => {
            let r = l.device.details.translate(dx, dy);
            gdi::text(dc, f, Font::Link, text, r, look.text, LEFT);
        }
    }
}
