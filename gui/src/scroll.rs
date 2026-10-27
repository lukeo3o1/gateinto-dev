use crate::layout::Rect;
use crate::nav::Page;

pub const WHEEL_DELTA: i32 = 120;
pub const PAGE_SCROLL: u32 = u32::MAX;

pub fn clamp(offset: i32, content: i32, view: i32) -> i32 {
    offset.clamp(0, (content - view).max(0))
}

pub fn step(delta: i32, lines: u32, line: i32, page: i32) -> i32 {
    let unit = match lines {
        0 => return 0,
        PAGE_SCROLL => i64::from(page),
        n => i64::from(n) * i64::from(line),
    };
    let px = -i64::from(delta) * unit / i64::from(WHEEL_DELTA);
    px.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
}

pub fn thumb(track: Rect, content: i32, offset: i32, min: i32) -> Option<Rect> {
    if content <= track.h {
        return None;
    }
    let offset = i64::from(clamp(offset, content, track.h));
    let (view, content) = (i64::from(track.h), i64::from(content));
    let h = (view * view / content).max(i64::from(min)).min(view);
    let travel = (view - h) * offset / (content - view);
    Some(Rect::new(
        track.x,
        track.y + travel as i32,
        track.w,
        h as i32,
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pane {
    pub view: Rect,
    pub content: i32,
    pub offset: i32,
}

impl Pane {
    pub fn new(view: Rect, content: i32, offset: i32) -> Self {
        Self {
            view,
            content,
            offset: clamp(offset, content, view.h),
        }
    }

    pub fn scrolled(&self, delta: i32, lines: u32, line: i32) -> i32 {
        let moved = self
            .offset
            .saturating_add(step(delta, lines, line, self.view.h));
        clamp(moved, self.content, self.view.h)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Offsets {
    sessions: i32,
    gateways: i32,
    settings: i32,
}

impl Offsets {
    fn slot(&mut self, page: Page) -> Option<&mut i32> {
        match page {
            Page::Sessions => Some(&mut self.sessions),
            Page::Gateways => Some(&mut self.gateways),
            Page::Settings => Some(&mut self.settings),
            _ => None,
        }
    }

    pub fn get(mut self, page: Page) -> i32 {
        self.slot(page).map_or(0, |offset| *offset)
    }

    pub fn set(&mut self, page: Page, offset: i32) -> bool {
        self.slot(page)
            .is_some_and(|slot| std::mem::replace(slot, offset) != offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offsets_stay_between_the_top_and_the_last_screen() {
        assert_eq!(clamp(-5, 500, 200), 0);
        assert_eq!(clamp(120, 500, 200), 120);
        assert_eq!(clamp(400, 500, 200), 300);
        assert_eq!(clamp(50, 150, 200), 0);
    }

    #[test]
    fn a_notch_down_scrolls_the_configured_lines() {
        assert_eq!(step(-WHEEL_DELTA, 3, 20, 400), 60);
        assert_eq!(step(WHEEL_DELTA, 3, 20, 400), -60);
        assert_eq!(step(-2 * WHEEL_DELTA, 1, 20, 400), 40);
    }

    #[test]
    fn partial_notches_scroll_proportionally() {
        assert_eq!(step(-WHEEL_DELTA / 4, 3, 20, 400), 15);
    }

    #[test]
    fn page_scroll_moves_a_whole_view_and_zero_lines_nothing() {
        assert_eq!(step(-WHEEL_DELTA, PAGE_SCROLL, 20, 400), 400);
        assert_eq!(step(WHEEL_DELTA, PAGE_SCROLL, 20, 400), -400);
        assert_eq!(step(-WHEEL_DELTA, 0, 20, 400), 0);
    }

    #[test]
    fn huge_settings_do_not_overflow() {
        assert_eq!(step(i32::from(i16::MIN), u32::MAX - 1, 20, 400), i32::MAX);
    }

    #[test]
    fn the_thumb_shows_the_visible_share_and_position() {
        let track = Rect::new(10, 100, 4, 200);
        assert_eq!(thumb(track, 200, 0, 24), None);
        assert_eq!(thumb(track, 400, 0, 24), Some(Rect::new(10, 100, 4, 100)));
        assert_eq!(thumb(track, 400, 200, 24), Some(Rect::new(10, 200, 4, 100)));
        assert_eq!(thumb(track, 400, 100, 24), Some(Rect::new(10, 150, 4, 100)));
    }

    #[test]
    fn a_pane_keeps_its_offset_in_range() {
        let view = Rect::new(0, 100, 50, 200);
        assert_eq!(Pane::new(view, 500, 900).offset, 300);
        assert_eq!(Pane::new(view, 100, 40).offset, 0);
    }

    #[test]
    fn a_pane_scrolls_by_the_wheel_within_its_content() {
        let pane = Pane::new(Rect::new(0, 100, 50, 200), 500, 280);
        assert_eq!(pane.scrolled(-WHEEL_DELTA, 3, 20), 300);
        assert_eq!(pane.scrolled(WHEEL_DELTA, 3, 20), 220);
        assert_eq!(pane.scrolled(WHEEL_DELTA, PAGE_SCROLL, 20), 80);
        let top = Pane::new(Rect::new(0, 100, 50, 200), 500, 0);
        assert_eq!(top.scrolled(i32::from(i16::MAX), u32::MAX - 1, 20), 0);
    }

    #[test]
    fn each_scrolling_page_keeps_its_own_offset() {
        let mut o = Offsets::default();
        assert!(o.set(Page::Gateways, 40));
        assert!(!o.set(Page::Gateways, 40));
        assert_eq!(o.get(Page::Gateways), 40);
        assert_eq!(o.get(Page::Sessions), 0);
        assert!(o.set(Page::Sessions, 7));
        assert_eq!(o.get(Page::Sessions), 7);
        assert!(o.set(Page::Settings, 9));
        assert_eq!(o.get(Page::Settings), 9);
        assert_eq!(o.get(Page::Gateways), 40);
        assert!(!o.set(Page::Log, 3));
        assert_eq!(o.get(Page::Log), 0);
    }

    #[test]
    fn the_thumb_never_gets_too_small_to_see() {
        let track = Rect::new(10, 100, 4, 200);
        assert_eq!(
            thumb(track, 100_000, 99_800, 24),
            Some(Rect::new(10, 276, 4, 24))
        );
    }
}
