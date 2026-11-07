use std::borrow::Cow;

use super::{CLOSE, GAP, Modal, width, wrap};
use crate::board::{Board, Painter};
use crate::fonts::{Font, Measure};
use crate::hit::Zone;
use crate::i18n::{Text, tr};
use crate::layout::{Layout, Rect};
use crate::scale::Scale;
use crate::scene::{Op, View};
use crate::theme::{Rgb, Theme};
use crate::verification::{self, NO_QR, Page, Qr, RETRY};

const TITLE: Text = Text::VerificationTitle;
const QR_SIDE: f32 = 164.0;
pub const LIGHT: Rgb = Rgb(0xffffff);
pub const DARK: Rgb = Rgb(0x000000);

enum Item<'q> {
    Text(Font, Cow<'static, str>, Rgb, i32),
    Gap(i32),
    Qr(&'q Qr, i32),
}

impl Item<'_> {
    fn height(&self) -> i32 {
        match self {
            Item::Text(.., h) | Item::Gap(h) | Item::Qr(_, h) => *h,
        }
    }
}

pub fn module(s: Scale, qr: &Qr) -> i32 {
    let span = i32::try_from(verification::span(qr)).unwrap_or(i32::MAX);
    (s.px(QR_SIDE) / span).max(1)
}

fn lines(
    items: &mut Vec<Item<'_>>,
    m: &impl Measure,
    font: Font,
    text: &str,
    w: i32,
    h: i32,
    ink: Rgb,
) {
    for line in wrap(m, font, text, w) {
        items.push(Item::Text(font, line.into(), ink, h));
    }
}

fn items<'q>(page: &Page<'q>, s: Scale, t: &Theme, m: &impl Measure, w: i32) -> Vec<Item<'q>> {
    let (gap, line, small) = (s.px(GAP), s.px(18.0), s.px(16.0));
    let mut items = Vec::new();
    if let Some(status) = page.status {
        items.push(Item::Text(
            Font::Title,
            tr(TITLE).into(),
            t.text,
            s.px(30.0),
        ));
        lines(
            &mut items,
            m,
            Font::BodyStrong,
            &page.gateway,
            w,
            line,
            t.text,
        );
        items.push(Item::Gap(gap));
        lines(&mut items, m, Font::Body, status, w, line, t.muted);
        return items;
    }
    lines(
        &mut items,
        m,
        Font::Origin,
        page.origin,
        w,
        s.px(24.0),
        t.text,
    );
    if let Some(note) = page.note {
        lines(&mut items, m, Font::Small, note, w, small, t.muted);
    }
    items.push(Item::Gap(gap));
    lines(
        &mut items,
        m,
        Font::BodyStrong,
        &page.gateway,
        w,
        line,
        t.text,
    );
    lines(&mut items, m, Font::Body, &page.targets, w, line, t.muted);
    items.push(Item::Gap(gap));
    lines(&mut items, m, Font::Mono, page.url, w, line, t.text);
    items.push(Item::Gap(gap));
    let label = tr(Text::PairingCode);
    items.push(Item::Text(Font::BodyStrong, label.into(), t.text, line));
    lines(
        &mut items,
        m,
        Font::Origin,
        page.code,
        w,
        s.px(24.0),
        t.text,
    );
    items.push(Item::Text(
        Font::Small,
        page.countdown.clone().into(),
        t.muted,
        small,
    ));
    items.push(Item::Gap(gap));
    match page.qr {
        Some(qr) => {
            let span = i32::try_from(verification::span(qr)).unwrap_or(i32::MAX);
            items.push(Item::Qr(qr, module(s, qr).saturating_mul(span)));
        }
        None => items.push(Item::Text(Font::Small, tr(NO_QR).into(), t.muted, small)),
    }
    items.push(Item::Gap(gap));
    lines(&mut items, m, Font::Body, tr(RETRY), w, line, t.text);
    items
}

impl<M: Measure> Painter<'_, M> {
    fn qr(&mut self, x: i32, y: i32, qr: &Qr) {
        let px = module(self.s, qr);
        let span = i32::try_from(verification::span(qr)).unwrap_or(i32::MAX);
        let side = px.saturating_mul(span);
        self.push(Op::Fill(Rect::new(x, y, side, side), LIGHT));
        for run in verification::runs(qr).iter() {
            let at = |v: usize| i32::try_from(v).unwrap_or(i32::MAX).saturating_mul(px);
            let r = Rect::new(x + at(run.x), y + at(run.y), at(run.len), px);
            self.push(Op::Fill(r, DARK));
        }
    }
}

pub fn board(
    board: &mut Board,
    l: &Layout,
    s: Scale,
    t: &Theme,
    v: &View,
    page: &Page,
    m: &impl Measure,
) {
    let w = width(l, s);
    let items = items(page, s, t, m, w);
    let body = items.iter().map(Item::height).sum();
    let mut modal = Modal::open(l, s, t, v, m, body);
    let inner = modal.inner;
    let p = &mut modal.p;
    let mut y = inner.y;
    for item in items {
        let h = item.height();
        match item {
            Item::Text(font, text, ink, h) => p.text(font, text, Rect::new(inner.x, y, w, h), ink),
            Item::Qr(qr, _) => p.qr(inner.x, y, qr),
            Item::Gap(_) => {}
        }
        y += h;
    }
    let ready = page.ready;
    let copy = tr(if page.copied {
        Text::Copied
    } else {
        Text::CopyLink
    });
    modal.close(board, |p, footer| {
        let close = p.close_rect(footer);
        if ready {
            let dismiss = p.footer_rect(footer, close.x - s.px(8.0), tr(Text::Dismiss));
            let copy_r = p.footer_rect(footer, dismiss.x - s.px(8.0), copy);
            let open_label = tr(Text::OpenVerification);
            let open_w = p.footer_rect(footer, 0, open_label).w;
            let open = p.footer_rect(footer, footer.x + s.px(24.0) + open_w, open_label);
            p.plain(open, open_label, Zone::OpenVerification);
            p.plain(copy_r, copy, Zone::CopyLink);
            p.plain(dismiss, tr(Text::Dismiss), Zone::DismissVerification);
        }
        p.primary(close, tr(CLOSE), Zone::CloseDialog);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board::tests::{Chars, layout};
    use crate::verification::{Encoder, UNAVAILABLE};

    const T: Theme = Theme::LIGHT;
    const S: Scale = Scale { dpi: 96 };
    const URL: &str = "https://verify.example/device?code=BCDF-GHJK";

    fn page(qr: Option<&Qr>) -> Page<'_> {
        Page {
            origin: "https://verify.example",
            note: Some(tr(Text::DifferentOrigin)),
            gateway: "office".to_owned(),
            targets: "intranet.example".to_owned(),
            url: URL,
            code: "BCDF-GHJK",
            countdown: "Expires in 9:59".to_owned(),
            qr,
            status: None,
            ready: true,
            copied: false,
        }
    }

    fn draw(page: &Page) -> Board {
        let mut b = Board::default();
        board(&mut b, &layout(), S, &T, &View::default(), page, &Chars);
        b
    }

    fn texts(b: &Board) -> Vec<(Font, String)> {
        b.ops
            .iter()
            .filter_map(|op| match op {
                Op::Text(font, text, ..) => Some((*font, text.to_string())),
                _ => None,
            })
            .collect()
    }

    fn zones(b: &Board) -> Vec<Zone> {
        b.targets.iter().map(|&(_, zone)| zone).collect()
    }

    #[test]
    fn the_origin_comes_first_and_largest_then_the_rest_in_order() {
        let qr = Encoder::default().encode(URL);
        let b = draw(&page(qr.as_ref()));
        let texts = texts(&b);
        assert_eq!(
            texts[0],
            (Font::Origin, "https://verify.example".to_owned())
        );
        let size = |font: Font| font.spec().size;
        assert!(
            texts[1..]
                .iter()
                .all(|(f, _)| size(*f) <= size(Font::Origin))
        );
        let order: Vec<&str> = texts.iter().map(|(_, text)| text.as_str()).collect();
        assert_eq!(
            order,
            [
                "https://verify.example",
                tr(Text::DifferentOrigin),
                "office",
                "intranet.example",
                URL,
                tr(Text::PairingCode),
                "BCDF-GHJK",
                "Expires in 9:59",
                tr(RETRY),
                tr(Text::OpenVerification),
                tr(Text::CopyLink),
                tr(Text::Dismiss),
                tr(CLOSE),
            ]
        );
        assert!(texts.contains(&(Font::Origin, "BCDF-GHJK".to_owned())));
        assert!(texts.contains(&(Font::Mono, URL.to_owned())));
    }

    #[test]
    fn a_shown_verification_offers_open_copy_dismiss_and_close() {
        let b = draw(&page(None));
        assert_eq!(
            zones(&b),
            [
                Zone::OpenVerification,
                Zone::CopyLink,
                Zone::DismissVerification,
                Zone::CloseDialog,
                Zone::Dialog,
            ]
        );
    }

    #[test]
    fn a_copied_link_says_so() {
        let mut shown = page(None);
        shown.copied = true;
        let b = draw(&shown);
        assert!(texts(&b).iter().any(|(_, t)| t == tr(Text::Copied)));
        assert!(!texts(&b).iter().any(|(_, t)| t == tr(Text::CopyLink)));
    }

    #[test]
    fn waiting_or_unavailable_shows_only_the_status_and_close() {
        let mut waiting = page(None);
        waiting.status = Some(tr(UNAVAILABLE));
        waiting.ready = false;
        waiting.origin = "";
        waiting.url = "";
        waiting.code = "";
        let b = draw(&waiting);
        let order: Vec<String> = texts(&b).into_iter().map(|(_, t)| t).collect();
        assert_eq!(order[..2], [tr(TITLE), "office"]);
        assert_eq!(order[2..order.len() - 1].join(" "), tr(UNAVAILABLE));
        assert_eq!(order[order.len() - 1], tr(CLOSE));
        assert_eq!(zones(&b), [Zone::CloseDialog, Zone::Dialog]);
    }

    #[test]
    fn without_a_qr_code_a_fixed_text_says_so() {
        let b = draw(&page(None));
        assert!(texts(&b).iter().any(|(_, t)| t == tr(NO_QR)));
        assert!(
            !b.ops
                .iter()
                .any(|op| matches!(op, Op::Fill(_, c) if *c == DARK))
        );
    }

    #[test]
    fn modules_are_drawn_as_rects_inside_a_light_quiet_zone() {
        let qr = Encoder::default().encode(URL).unwrap();
        let b = draw(&page(Some(&qr)));
        let px = module(S, &qr);
        let span = i32::try_from(verification::span(&qr)).unwrap();
        assert_eq!(px, 164 / span);
        let back = b
            .ops
            .iter()
            .find_map(|op| match op {
                Op::Fill(r, c) if *c == LIGHT && r.w == r.h => Some(*r),
                _ => None,
            })
            .unwrap();
        assert_eq!((back.w, back.h), (px * span, px * span));
        let dark: Vec<Rect> = b
            .ops
            .iter()
            .filter_map(|op| match op {
                Op::Fill(r, c) if *c == DARK => Some(*r),
                _ => None,
            })
            .collect();
        let runs = verification::runs(&qr);
        assert_eq!(dark.len(), runs.len());
        let quiet = i32::try_from(verification::QUIET).unwrap();
        assert_eq!(
            dark[0],
            Rect::new(back.x + quiet * px, back.y + quiet * px, 7 * px, px)
        );
        for (r, run) in dark.iter().zip(runs.iter()) {
            assert_eq!(r.x, back.x + px * i32::try_from(run.x).unwrap());
            assert_eq!(r.y, back.y + px * i32::try_from(run.y).unwrap());
            assert_eq!(r.w, px * i32::try_from(run.len).unwrap());
            assert!(r.right() <= back.right() - quiet * px);
            assert!(r.bottom() <= back.bottom() - quiet * px);
        }
    }

    #[test]
    fn a_large_code_still_gets_at_least_one_pixel_per_module() {
        let long = format!("https://verify.example/{}", "a".repeat(2000));
        let qr = Encoder::default().encode(&long).unwrap();
        assert!(module(S, &qr) >= 1);
    }

    #[test]
    fn a_wiped_frame_keeps_no_link_code_or_modules() {
        let qr = Encoder::default().encode(URL).unwrap();
        let mut b = draw(&page(Some(&qr)));
        crate::scene::wipe(&mut b.ops);
        assert!(b.ops.iter().all(|op| match op {
            Op::Text(_, text, ..) => !text.contains("BCDF") && !text.contains("verify.example"),
            Op::Fill(r, _) => *r == Rect::default(),
            _ => true,
        }));
    }
}
