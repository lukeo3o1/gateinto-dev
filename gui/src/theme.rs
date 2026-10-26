#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rgb(pub u32);

impl Rgb {
    pub fn channels(self) -> [f32; 4] {
        let c = |shift: u32| ((self.0 >> shift) & 0xff) as f32 / 255.0;
        [c(16), c(8), c(0), 1.0]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Theme {
    pub bg: Rgb,
    pub text: Rgb,
    pub rail: Rgb,
    pub rail_edge: Rgb,
    pub rail_hover: Rgb,
    pub rail_selected: Rgb,
    pub rail_text: Rgb,
    pub rail_on: Rgb,
    pub rail_icon: Rgb,
    pub accent: Rgb,
    pub caption: Rgb,
    pub caption_hover: Rgb,
    pub caption_pressed: Rgb,
    pub close_hover: Rgb,
    pub close_pressed: Rgb,
    pub close_glyph_hover: Rgb,
}

impl Theme {
    pub const LIGHT: Theme = Theme {
        bg: Rgb(0xf4f3f0),
        text: Rgb(0x1d1f24),
        rail: Rgb(0xebe9e4),
        rail_edge: Rgb(0xe0ddd6),
        rail_hover: Rgb(0xe3e1db),
        rail_selected: Rgb(0xffffff),
        rail_text: Rgb(0x3d4049),
        rail_on: Rgb(0x1d1f24),
        rail_icon: Rgb(0x262b36),
        accent: Rgb(0xffc94a),
        caption: Rgb(0x1d1f24),
        caption_hover: Rgb(0xe6e5e1),
        caption_pressed: Rgb(0xdad9d5),
        close_hover: Rgb(0xc42b1c),
        close_pressed: Rgb(0xc84031),
        close_glyph_hover: Rgb(0xffffff),
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channels_are_unit_floats() {
        assert_eq!(Rgb(0xff0033).channels(), [1.0, 0.0, 0.2, 1.0]);
    }

    #[test]
    fn light_theme_uses_the_board_palette() {
        let t = Theme::LIGHT;
        assert_eq!(t.bg, Rgb(0xf4f3f0));
        assert_eq!(t.text, Rgb(0x1d1f24));
        assert_eq!(t.rail, Rgb(0xebe9e4));
        assert_eq!(t.rail_edge, Rgb(0xe0ddd6));
        assert_eq!(t.rail_selected, Rgb(0xffffff));
        assert_eq!(t.rail_text, Rgb(0x3d4049));
        assert_eq!(t.rail_on, Rgb(0x1d1f24));
        assert_eq!(t.rail_icon, Rgb(0x262b36));
        assert_eq!(t.caption, Rgb(0x1d1f24));
        assert_eq!(t.accent, Rgb(0xffc94a));
        assert_eq!(t.close_hover, Rgb(0xc42b1c));
    }

    #[test]
    fn hover_fills_differ_from_what_they_cover() {
        let t = Theme::LIGHT;
        assert_ne!(t.rail_hover, t.rail);
        assert_ne!(t.rail_hover, t.rail_selected);
        assert_ne!(t.caption_hover, t.bg);
        assert_ne!(t.close_glyph_hover, t.close_hover);
    }
}
