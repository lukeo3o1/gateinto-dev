#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Frame {
    Custom,
    System,
}

impl Frame {
    pub fn choose(os_major: u32, composition: bool) -> Self {
        if os_major >= 10 && composition {
            Frame::Custom
        } else {
            Frame::System
        }
    }

    pub fn draws_caption(self) -> bool {
        self == Frame::Custom
    }

    pub fn client_top(original_top: i32, maximized: bool, frame_y: i32) -> i32 {
        if maximized {
            original_top + frame_y
        } else {
            original_top
        }
    }

    pub fn outer_size(self, [left, top, right, bottom]: [i32; 4]) -> (i32, i32) {
        let top = if self.draws_caption() { 0 } else { top };
        (right - left, bottom - top)
    }

    pub fn top_resize_band(self, maximized: bool, frame_y: i32) -> i32 {
        if self.draws_caption() && !maximized {
            frame_y
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_frame_needs_windows_10_and_composition() {
        assert_eq!(Frame::choose(10, true), Frame::Custom);
        assert_eq!(Frame::choose(11, true), Frame::Custom);
        assert_eq!(Frame::choose(10, false), Frame::System);
        assert_eq!(Frame::choose(6, true), Frame::System);
        assert_eq!(Frame::choose(6, false), Frame::System);
    }

    #[test]
    fn only_the_custom_frame_draws_caption_buttons() {
        assert!(Frame::Custom.draws_caption());
        assert!(!Frame::System.draws_caption());
    }

    #[test]
    fn client_keeps_the_top_edge_unless_maximized() {
        assert_eq!(Frame::client_top(100, false, 8), 100);
        assert_eq!(Frame::client_top(-8, true, 8), 0);
    }

    #[test]
    fn top_resize_band_only_on_a_restored_custom_frame() {
        assert_eq!(Frame::Custom.top_resize_band(false, 8), 8);
        assert_eq!(Frame::Custom.top_resize_band(true, 8), 0);
        assert_eq!(Frame::System.top_resize_band(false, 8), 0);
    }

    #[test]
    fn outer_size_drops_the_caption_of_a_custom_frame() {
        let adjusted = [-8, -31, 1048, 688];
        assert_eq!(Frame::System.outer_size(adjusted), (1056, 719));
        assert_eq!(Frame::Custom.outer_size(adjusted), (1056, 688));
    }
}
