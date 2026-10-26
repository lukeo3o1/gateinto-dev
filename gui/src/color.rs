#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rgb(pub u32);

impl Rgb {
    pub const fn argb(self) -> u32 {
        0xff00_0000 | self.0
    }

    pub const fn colorref(self) -> u32 {
        ((self.0 & 0xff) << 16) | (self.0 & 0xff00) | ((self.0 >> 16) & 0xff)
    }
}

pub const WINDOW: Rgb = Rgb(0xf3f3f3);
pub const PANEL: Rgb = Rgb(0xf9f9f9);
pub const STROKE: Rgb = Rgb(0xe5e5e5);
pub const CONTROL_STROKE: Rgb = Rgb(0xe0e0e0);
pub const CARD: Rgb = Rgb(0xffffff);
pub const TEXT: Rgb = Rgb(0x1a1a1a);
pub const TEXT_SECONDARY: Rgb = Rgb(0x5c5c5c);
pub const ACCENT: Rgb = Rgb(0x005fb8);
pub const ACCENT_HOVER: Rgb = Rgb(0x1a6fbf);
pub const ACCENT_PRESSED: Rgb = Rgb(0x3c7fc4);
pub const ON_ACCENT: Rgb = Rgb(0xffffff);
pub const NAV_SELECTED: Rgb = Rgb(0xe9e9e9);
pub const NAV_SELECTED_HOVER: Rgb = Rgb(0xe4e4e4);
pub const NAV_HOVER: Rgb = Rgb(0xeaeaea);
pub const NAV_PRESSED: Rgb = Rgb(0xededed);
pub const TILE: Rgb = Rgb(0xeef4fb);
pub const BADGE_OK_BG: Rgb = Rgb(0xe6f2e6);
pub const BADGE_OK_FG: Rgb = Rgb(0x0f5c13);
pub const BADGE_BG: Rgb = Rgb(0xf0f0f0);
pub const BADGE_FG: Rgb = Rgb(0x3d3d3d);
pub const BUTTON: Rgb = Rgb(0xffffff);
pub const BUTTON_SUBTLE: Rgb = Rgb(0xfbfbfb);
pub const BUTTON_HOVER: Rgb = Rgb(0xf6f6f6);
pub const BUTTON_PRESSED: Rgb = Rgb(0xf0f0f0);
pub const TEXT_PRESSED: Rgb = Rgb(0x5c5c5c);
pub const DANGER: Rgb = Rgb(0xa4262c);
pub const SHIELD: Rgb = Rgb(0x0f5c13);
pub const LINK_HOVER: Rgb = Rgb(0x004a8f);
pub const FOCUS: Rgb = Rgb(0x1a1a1a);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argb_is_opaque() {
        assert_eq!(Rgb(0x005fb8).argb(), 0xff005fb8);
    }

    #[test]
    fn colorref_swaps_red_and_blue() {
        assert_eq!(Rgb(0x005fb8).colorref(), 0x00b85f00);
        assert_eq!(Rgb(0xa4262c).colorref(), 0x002c26a4);
    }
}
