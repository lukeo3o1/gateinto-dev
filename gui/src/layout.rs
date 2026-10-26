use crate::nav::Page;
use crate::scale::Scale;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

impl Rect {
    pub const fn new(x: i32, y: i32, w: i32, h: i32) -> Self {
        Self { x, y, w, h }
    }

    pub const fn right(self) -> i32 {
        self.x + self.w
    }

    pub const fn bottom(self) -> i32 {
        self.y + self.h
    }

    pub const fn contains(self, x: i32, y: i32) -> bool {
        x >= self.x && x < self.right() && y >= self.y && y < self.bottom()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NavItem {
    pub page: Page,
    pub frame: Rect,
    pub icon: Rect,
    pub label: Rect,
    pub bar: Rect,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaptionButtons {
    pub minimize: Rect,
    pub maximize: Rect,
    pub close: Rect,
    glyph: i32,
}

impl CaptionButtons {
    pub fn glyph(&self, button: Rect) -> Rect {
        Rect::new(
            button.x + (button.w - self.glyph) / 2,
            button.y + (button.h - self.glyph) / 2,
            self.glyph,
            self.glyph,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    pub rail: Rect,
    pub rail_edge: Rect,
    pub brand: Rect,
    pub logo: Rect,
    pub brand_text: Rect,
    pub nav: [NavItem; 5],
    pub caption_row: Rect,
    pub buttons: Option<CaptionButtons>,
    pub title: Rect,
}

impl Layout {
    pub fn new(width: i32, height: i32, s: Scale, caption_buttons: bool) -> Self {
        let rail = Rect::new(0, 0, s.px(220.0), height);
        let edge = s.hairline();
        let inner = rail.w - edge;
        let brand = Rect::new(0, 0, inner, s.px(56.0));
        let logo_size = s.px(28.0);
        let text_x = s.px(54.0);

        let gutter = s.px(10.0);
        let item_h = s.px(40.0);
        let nav = std::array::from_fn(|i| {
            let page = Page::ALL[i];
            let y = if page.at_bottom() {
                height - s.px(14.0) - item_h * (Page::ALL.len() - i) as i32
            } else {
                s.px(64.0 + 44.0 * i as f32)
            };
            let frame = Rect::new(gutter, y, inner - 2 * gutter, item_h);
            let icon = s.px(20.0);
            let label_x = s.px(44.0);
            NavItem {
                page,
                frame,
                icon: Rect::new(
                    frame.x + s.px(12.0),
                    frame.y + (frame.h - icon) / 2,
                    icon,
                    icon,
                ),
                label: Rect::new(
                    frame.x + label_x,
                    frame.y,
                    frame.w - label_x - s.px(12.0),
                    frame.h,
                ),
                bar: Rect::new(frame.x, frame.y + s.px(11.0), s.px(3.0), s.px(18.0)),
            }
        });

        let content_w = width - rail.w;
        let caption_row = Rect::new(rail.w, 0, content_w, s.px(40.0));
        let button = |i: i32| {
            let w = s.px(46.0);
            Rect::new(width - w * i, 0, w, caption_row.h)
        };
        let pad = s.px(28.0);
        Self {
            rail,
            rail_edge: Rect::new(inner, 0, edge, height),
            brand,
            logo: Rect::new(s.px(16.0), (brand.h - logo_size) / 2, logo_size, logo_size),
            brand_text: Rect::new(text_x, 0, inner - text_x - gutter, brand.h),
            nav,
            caption_row,
            buttons: caption_buttons.then(|| CaptionButtons {
                minimize: button(3),
                maximize: button(2),
                close: button(1),
                glyph: s.px(10.0),
            }),
            title: Rect::new(
                rail.w + pad,
                caption_row.h + s.px(4.0),
                content_w - 2 * pad,
                s.px(32.0),
            ),
        }
    }

    pub fn item(&self, page: Page) -> NavItem {
        self.nav[page as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(dpi: u32) -> Layout {
        Layout::new(1040, 680, Scale::new(dpi), true)
    }

    #[test]
    fn rect_edges_and_containment() {
        let r = Rect::new(10, 20, 30, 40);
        assert_eq!((r.right(), r.bottom()), (40, 60));
        assert!(r.contains(10, 20));
        assert!(r.contains(39, 59));
        assert!(!r.contains(40, 30));
        assert!(!r.contains(20, 60));
        assert!(!r.contains(9, 30));
    }

    #[test]
    fn rail_spans_the_left_edge_with_a_hairline_border() {
        let l = at(96);
        assert_eq!(l.rail, Rect::new(0, 0, 220, 680));
        assert_eq!(l.rail_edge, Rect::new(219, 0, 1, 680));
        assert_eq!(l.brand, Rect::new(0, 0, 219, 56));
        assert_eq!(l.logo, Rect::new(16, 14, 28, 28));
        assert_eq!(l.brand_text, Rect::new(54, 0, 155, 56));
    }

    #[test]
    fn top_items_stack_under_the_brand_and_the_rest_sit_at_the_bottom() {
        let l = at(96);
        let frames: Vec<_> = l.nav.iter().map(|i| (i.page, i.frame)).collect();
        assert_eq!(
            frames,
            [
                (Page::Sessions, Rect::new(10, 64, 199, 40)),
                (Page::Gateways, Rect::new(10, 108, 199, 40)),
                (Page::Device, Rect::new(10, 152, 199, 40)),
                (Page::Log, Rect::new(10, 586, 199, 40)),
                (Page::Settings, Rect::new(10, 626, 199, 40)),
            ]
        );
    }

    #[test]
    fn item_parts() {
        let item = at(96).item(Page::Gateways);
        assert_eq!(item.icon, Rect::new(22, 118, 20, 20));
        assert_eq!(item.label, Rect::new(54, 108, 143, 40));
        assert_eq!(item.bar, Rect::new(10, 119, 3, 18));
    }

    #[test]
    fn caption_buttons_sit_at_the_top_right() {
        let l = at(96);
        assert_eq!(l.caption_row, Rect::new(220, 0, 820, 40));
        let b = l.buttons.unwrap();
        assert_eq!(b.minimize, Rect::new(902, 0, 46, 40));
        assert_eq!(b.maximize, Rect::new(948, 0, 46, 40));
        assert_eq!(b.close, Rect::new(994, 0, 46, 40));
        assert_eq!(b.glyph(b.close), Rect::new(1012, 15, 10, 10));
    }

    #[test]
    fn no_caption_buttons_with_the_system_frame() {
        assert_eq!(Layout::new(1040, 680, Scale::new(96), false).buttons, None);
    }

    #[test]
    fn page_title_sits_under_the_caption_row() {
        assert_eq!(at(96).title, Rect::new(248, 44, 764, 32));
    }

    #[test]
    fn scales_every_offset_from_design_units() {
        let l = Layout::new(1560, 1020, Scale::new(144), true);
        assert_eq!(l.rail, Rect::new(0, 0, 330, 1020));
        assert_eq!(l.rail_edge, Rect::new(329, 0, 1, 1020));
        assert_eq!(l.item(Page::Device).frame, Rect::new(15, 228, 299, 60));
        assert_eq!(l.item(Page::Settings).frame, Rect::new(15, 939, 299, 60));
        assert_eq!(l.buttons.unwrap().close, Rect::new(1491, 0, 69, 60));
        assert_eq!(l.title, Rect::new(372, 66, 1146, 48));
    }
}
