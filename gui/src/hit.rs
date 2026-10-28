use crate::add::Input;
use crate::credentials::Field;
use crate::layout::{Layout, Rect};
use crate::log::Filter;
use crate::nav::Page;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Zone {
    Top,
    TopLeft,
    TopRight,
    Caption,
    Minimize,
    Maximize,
    Close,
    Nav(Page),
    StopAgent,
    Revoke(u64),
    More(u64),
    StartBrowser(usize),
    GatewayCard(usize),
    Picker,
    Entry(usize),
    OpenConfig,
    SignIn,
    CopyId,
    CopyLog,
    LogFilter(Filter),
    Menu,
    Dialog,
    CopyCredential(Field),
    TogglePassword(bool),
    RevokeCredentials,
    CloseDialog,
    AddGateway,
    AddField(Input),
    ConfirmAdd,
    OpenMain,
    Client,
}

pub fn find(targets: &[(Rect, Zone)], x: i32, y: i32) -> Zone {
    targets
        .iter()
        .find(|(r, _)| r.contains(x, y))
        .map_or(Zone::Client, |&(_, zone)| zone)
}

pub fn hit(l: &Layout, x: i32, y: i32, resize: i32, targets: &[(Rect, Zone)]) -> Zone {
    let width = l.caption_row.right();
    if y < resize {
        return if x < resize {
            Zone::TopLeft
        } else if x >= width - resize {
            Zone::TopRight
        } else {
            Zone::Top
        };
    }
    if let Some(b) = l.buttons {
        for (rect, zone) in [
            (b.minimize, Zone::Minimize),
            (b.maximize, Zone::Maximize),
            (b.close, Zone::Close),
        ] {
            if rect.contains(x, y) {
                return zone;
            }
        }
    }
    if let Some(item) = l.nav.iter().find(|i| i.frame.contains(x, y)) {
        return Zone::Nav(item.page);
    }
    let zone = find(targets, x, y);
    if zone != Zone::Client {
        return zone;
    }
    if l.caption_row.contains(x, y) || (x < l.rail.right() && y < l.brand.bottom()) {
        return Zone::Caption;
    }
    Zone::Client
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scale::Scale;

    const RESIZE: i32 = 6;

    fn shell() -> Layout {
        Layout::new(1040, 680, Scale::new(96), true)
    }

    #[test]
    fn top_band_resizes_and_its_ends_resize_diagonally() {
        let l = shell();
        assert_eq!(hit(&l, 500, 0, RESIZE, &[]), Zone::Top);
        assert_eq!(hit(&l, 500, 5, RESIZE, &[]), Zone::Top);
        assert_eq!(hit(&l, 2, 2, RESIZE, &[]), Zone::TopLeft);
        assert_eq!(hit(&l, 1038, 2, RESIZE, &[]), Zone::TopRight);
        assert_eq!(hit(&l, 1000, 2, RESIZE, &[]), Zone::Top);
        assert_eq!(hit(&l, 500, 6, RESIZE, &[]), Zone::Caption);
    }

    #[test]
    fn no_top_band_without_a_resize_border() {
        assert_eq!(hit(&shell(), 500, 0, 0, &[]), Zone::Caption);
        assert_eq!(hit(&shell(), 1000, 0, 0, &[]), Zone::Close);
    }

    #[test]
    fn caption_buttons() {
        let l = shell();
        assert_eq!(hit(&l, 902, 20, RESIZE, &[]), Zone::Minimize);
        assert_eq!(hit(&l, 947, 39, RESIZE, &[]), Zone::Minimize);
        assert_eq!(hit(&l, 948, 20, RESIZE, &[]), Zone::Maximize);
        assert_eq!(hit(&l, 994, 20, RESIZE, &[]), Zone::Close);
        assert_eq!(hit(&l, 1039, 39, RESIZE, &[]), Zone::Close);
        assert_eq!(hit(&l, 901, 20, RESIZE, &[]), Zone::Caption);
        assert_eq!(hit(&l, 1000, 40, RESIZE, &[]), Zone::Client);
    }

    #[test]
    fn brand_header_and_caption_row_drag_the_window() {
        let l = shell();
        assert_eq!(hit(&l, 100, 20, RESIZE, &[]), Zone::Caption);
        assert_eq!(hit(&l, 100, 55, RESIZE, &[]), Zone::Caption);
        assert_eq!(hit(&l, 219, 50, RESIZE, &[]), Zone::Caption);
        assert_eq!(hit(&l, 600, 39, RESIZE, &[]), Zone::Caption);
        assert_eq!(hit(&l, 600, 40, RESIZE, &[]), Zone::Client);
    }

    #[test]
    fn rail_items_are_client_targets() {
        let l = shell();
        assert_eq!(hit(&l, 100, 80, RESIZE, &[]), Zone::Nav(Page::Sessions));
        assert_eq!(hit(&l, 10, 152, RESIZE, &[]), Zone::Nav(Page::Device));
        assert_eq!(hit(&l, 100, 600, RESIZE, &[]), Zone::Nav(Page::Log));
        assert_eq!(hit(&l, 100, 665, RESIZE, &[]), Zone::Nav(Page::Settings));
        assert_eq!(hit(&l, 100, 300, RESIZE, &[]), Zone::Client);
        assert_eq!(hit(&l, 100, 106, RESIZE, &[]), Zone::Client);
        assert_eq!(hit(&l, 600, 300, RESIZE, &[]), Zone::Client);
    }

    #[test]
    fn page_targets_are_hit_inside_their_rects() {
        let l = shell();
        let targets = [
            (Rect::new(900, 100, 100, 32), Zone::StopAgent),
            (Rect::new(960, 300, 32, 32), Zone::Revoke(7)),
            (Rect::new(700, 400, 130, 32), Zone::StartBrowser(1)),
        ];
        let at = |x, y| hit(&l, x, y, RESIZE, &targets);
        assert_eq!(at(900, 100), Zone::StopAgent);
        assert_eq!(at(999, 131), Zone::StopAgent);
        assert_eq!(at(1000, 100), Zone::Client);
        assert_eq!(at(975, 315), Zone::Revoke(7));
        assert_eq!(at(975, 332), Zone::Client);
        assert_eq!(at(829, 431), Zone::StartBrowser(1));
    }

    #[test]
    fn the_system_frame_leaves_the_content_top_to_the_client() {
        let l = Layout::new(1040, 680, Scale::new(96), false);
        assert_eq!(hit(&l, 1000, 20, 0, &[]), Zone::Client);
        assert_eq!(hit(&l, 600, 0, 0, &[]), Zone::Client);
    }

    #[test]
    fn find_picks_the_first_target_or_the_client() {
        let targets = [
            (Rect::new(0, 0, 10, 10), Zone::OpenMain),
            (Rect::new(0, 0, 20, 20), Zone::StartBrowser(0)),
        ];
        assert_eq!(find(&targets, 5, 5), Zone::OpenMain);
        assert_eq!(find(&targets, 15, 15), Zone::StartBrowser(0));
        assert_eq!(find(&targets, 25, 5), Zone::Client);
    }
}
