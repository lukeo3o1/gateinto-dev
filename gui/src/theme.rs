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
    pub card: Rgb,
    pub border: Rgb,
    pub muted: Rgb,
    pub tile: Rgb,
    pub pill_text: Rgb,
    pub eyes_idle: Rgb,
    pub revoke_hover: Rgb,
    pub revoke_pressed: Rgb,
    pub revoke_glyph: Rgb,
    pub warning: Rgb,
    pub button: Rgb,
    pub button_hover: Rgb,
    pub button_pressed: Rgb,
    pub button_text: Rgb,
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
        card: Rgb(0xffffff),
        border: Rgb(0xe4e2dc),
        muted: Rgb(0x5f636d),
        tile: Rgb(0xefeee9),
        pill_text: Rgb(0x3d4049),
        eyes_idle: Rgb(0x9aa1b1),
        revoke_hover: Rgb(0xfde7e5),
        revoke_pressed: Rgb(0xfad4d0),
        revoke_glyph: Rgb(0xc42b1c),
        warning: Rgb(0x9a5b00),
        button: Rgb(0x262b36),
        button_hover: Rgb(0x353b48),
        button_pressed: Rgb(0x1b1f27),
        button_text: Rgb(0xffffff),
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
    fn sessions_page_uses_the_board_palette() {
        let t = Theme::LIGHT;
        assert_eq!(t.card, Rgb(0xffffff));
        assert_eq!(t.border, Rgb(0xe4e2dc));
        assert_eq!(t.muted, Rgb(0x5f636d));
        assert_eq!(t.tile, Rgb(0xefeee9));
        assert_eq!(t.pill_text, Rgb(0x3d4049));
        assert_eq!(t.eyes_idle, Rgb(0x9aa1b1));
        assert_eq!(t.revoke_hover, Rgb(0xfde7e5));
        assert_eq!(t.revoke_glyph, Rgb(0xc42b1c));
    }

    #[test]
    fn gateways_page_uses_the_board_palette() {
        let t = Theme::LIGHT;
        assert_eq!(t.button, Rgb(0x262b36));
        assert_eq!(t.button_text, Rgb(0xffffff));
        assert_ne!(t.button_hover, t.button);
        assert_ne!(t.button_pressed, t.button_hover);
        assert_ne!(t.button_pressed, t.button);
    }

    #[test]
    fn device_warnings_are_amber_and_readable_on_cards() {
        let t = Theme::LIGHT;
        assert_eq!(t.warning, Rgb(0x9a5b00));
    }

    #[test]
    fn hover_fills_differ_from_what_they_cover() {
        let t = Theme::LIGHT;
        assert_ne!(t.rail_hover, t.rail);
        assert_ne!(t.rail_hover, t.rail_selected);
        assert_ne!(t.caption_hover, t.bg);
        assert_ne!(t.close_glyph_hover, t.close_hover);
        assert_ne!(t.revoke_pressed, t.revoke_hover);
        assert_ne!(t.revoke_hover, t.card);
    }
}
