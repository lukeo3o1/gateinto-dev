#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rgb(pub u32);

impl Rgb {
    pub fn channels(self) -> [f32; 4] {
        let c = |shift: u32| ((self.0 >> shift) & 0xff) as f32 / 255.0;
        [c(16), c(8), c(0), 1.0]
    }

    #[cfg(test)]
    fn luminance(self) -> f64 {
        let linear = |c: f32| {
            let c = f64::from(c);
            if c <= 0.04045 {
                c / 12.92
            } else {
                ((c + 0.055) / 1.055).powf(2.4)
            }
        };
        let [r, g, b, _] = self.channels();
        0.2126 * linear(r) + 0.7152 * linear(g) + 0.0722 * linear(b)
    }
}

#[cfg(test)]
pub fn contrast(a: Rgb, b: Rgb) -> f64 {
    let (a, b) = (a.luminance(), b.luminance());
    (a.max(b) + 0.05) / (a.min(b) + 0.05)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Choice {
    #[default]
    System,
    Light,
    Dark,
}

impl Choice {
    pub const ALL: [Choice; 3] = [Choice::System, Choice::Light, Choice::Dark];

    pub fn name(self) -> &'static str {
        match self {
            Choice::System => "System",
            Choice::Light => "Light",
            Choice::Dark => "Dark",
        }
    }

    pub fn parse(value: Option<&str>) -> Choice {
        Choice::ALL
            .into_iter()
            .find(|c| Some(c.name()) == value)
            .unwrap_or_default()
    }

    pub fn dark(self, light_apps: bool) -> bool {
        match self {
            Choice::System => !light_apps,
            Choice::Light => false,
            Choice::Dark => true,
        }
    }
}

pub const PERSONALIZE: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize";
pub const APPS_USE_LIGHT: &str = "AppsUseLightTheme";
pub const KEY: &str = "Software\\Gateinto\\App";
pub const VALUE: &str = "Theme";

const DARK_EXPLORER: u32 = 17763;
const APP_MODE: u32 = 18362;
const DOCUMENTED_ATTRIBUTE: u32 = 18985;

pub fn light_apps(value: Option<u32>) -> bool {
    value != Some(0)
}

pub fn immersive_attribute(build: u32) -> Option<u32> {
    match build {
        DOCUMENTED_ATTRIBUTE.. => Some(20),
        DARK_EXPLORER.. => Some(19),
        _ => None,
    }
}

pub fn dark_controls(build: u32) -> bool {
    build >= DARK_EXPLORER
}

pub fn menu_mode(choice: Choice, build: u32) -> Option<u32> {
    (build >= APP_MODE).then_some(match choice {
        Choice::System => 1,
        Choice::Dark => 2,
        Choice::Light => 3,
    })
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
    pub button_glyph: Rgb,
    pub field: Rgb,
    pub notice: Rgb,
    pub notice_text: Rgb,
    pub focus: Rgb,
    pub knob: Rgb,
    pub scrim: Rgb,
}

impl Theme {
    pub fn of(dark: bool) -> &'static Theme {
        if dark { &Theme::DARK } else { &Theme::LIGHT }
    }

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
        button_glyph: Rgb(0xffc94a),
        field: Rgb(0xfbfbfa),
        notice: Rgb(0xfff4d6),
        notice_text: Rgb(0x7a5000),
        focus: Rgb(0x262b36),
        knob: Rgb(0xffffff),
        scrim: Rgb(0x1d1f24),
    };

    pub const DARK: Theme = Theme {
        bg: Rgb(0x17191e),
        text: Rgb(0xe8e9ec),
        rail: Rgb(0x0f1115),
        rail_edge: Rgb(0x0f1115),
        rail_hover: Rgb(0x1b1e25),
        rail_selected: Rgb(0x232731),
        rail_text: Rgb(0xc9cdd6),
        rail_on: Rgb(0xffffff),
        rail_icon: Rgb(0xffc94a),
        accent: Rgb(0xffc94a),
        caption: Rgb(0xe8e9ec),
        caption_hover: Rgb(0x2a2e37),
        caption_pressed: Rgb(0x343944),
        close_hover: Rgb(0xc42b1c),
        close_pressed: Rgb(0xc84031),
        close_glyph_hover: Rgb(0xffffff),
        card: Rgb(0x20232a),
        border: Rgb(0x2e323c),
        muted: Rgb(0x9aa0ad),
        tile: Rgb(0x2a2e37),
        pill_text: Rgb(0xc9cdd6),
        eyes_idle: Rgb(0x9aa1b1),
        revoke_hover: Rgb(0x3a2020),
        revoke_pressed: Rgb(0x4a2826),
        revoke_glyph: Rgb(0xff8a80),
        warning: Rgb(0xffc94a),
        button: Rgb(0xffc94a),
        button_hover: Rgb(0xffd56e),
        button_pressed: Rgb(0xe6b43f),
        button_text: Rgb(0x1d1f24),
        button_glyph: Rgb(0x1d1f24),
        field: Rgb(0x1a1c22),
        notice: Rgb(0x2a2619),
        notice_text: Rgb(0xffc94a),
        focus: Rgb(0xffc94a),
        knob: Rgb(0xc9cdd6),
        scrim: Rgb(0x000000),
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
    fn the_dark_theme_uses_the_dark_board_palette() {
        let t = Theme::DARK;
        assert_eq!(t.bg, Rgb(0x17191e));
        assert_eq!(t.rail, Rgb(0x0f1115));
        assert_eq!(t.rail_selected, Rgb(0x232731));
        assert_eq!(t.rail_text, Rgb(0xc9cdd6));
        assert_eq!(t.rail_on, Rgb(0xffffff));
        assert_eq!(t.rail_icon, Rgb(0xffc94a));
        assert_eq!(t.caption, Rgb(0xe8e9ec));
        assert_eq!(t.tile, Rgb(0x2a2e37));
        assert_eq!(t.pill_text, Rgb(0xc9cdd6));
        assert_eq!(t.caption_hover, Rgb(0x2a2e37));
        assert_eq!(t.revoke_hover, Rgb(0x3a2020));
        assert_eq!(t.revoke_glyph, Rgb(0xff8a80));
        assert_eq!(t.button_glyph, Rgb(0x1d1f24));
        assert_eq!(t.focus, Rgb(0xffc94a));
    }

    #[test]
    fn dialogs_darken_what_lies_behind_them() {
        assert_eq!(Theme::LIGHT.scrim, Rgb(0x1d1f24));
        assert_eq!(Theme::DARK.scrim, Rgb(0x000000));
    }

    #[test]
    fn the_light_start_button_keeps_its_amber_glyph() {
        assert_eq!(Theme::LIGHT.button_glyph, Rgb(0xffc94a));
        assert_eq!(Theme::LIGHT.focus, Rgb(0x262b36));
    }

    #[test]
    fn the_tray_flyout_uses_the_dark_palette() {
        let t = Theme::DARK;
        assert_eq!(t.bg, Rgb(0x17191e));
        assert_eq!(t.border, Rgb(0x2e323c));
        assert_eq!(t.text, Rgb(0xe8e9ec));
        assert_eq!(t.muted, Rgb(0x9aa0ad));
        assert_eq!(t.card, Rgb(0x20232a));
        assert_eq!(t.accent, Rgb(0xffc94a));
        assert_eq!(t.eyes_idle, Rgb(0x9aa1b1));
        assert_eq!(t.button, Rgb(0xffc94a));
        assert_eq!(t.button_text, Rgb(0x1d1f24));
        assert_ne!(t.caption_hover, t.card);
        assert_ne!(t.caption_hover, t.bg);
        assert_ne!(t.caption_pressed, t.caption_hover);
        assert_ne!(t.button_hover, t.button);
        assert_ne!(t.button_pressed, t.button_hover);
    }

    #[test]
    fn device_warnings_use_the_amber_ink() {
        let t = Theme::LIGHT;
        assert_eq!(t.warning, Rgb(0x9a5b00));
    }

    #[test]
    fn hover_fills_differ_from_what_they_cover() {
        for t in [Theme::LIGHT, Theme::DARK] {
            assert_ne!(t.rail_hover, t.rail);
            assert_ne!(t.rail_hover, t.rail_selected);
            assert_ne!(t.caption_hover, t.bg);
            assert_ne!(t.caption_hover, t.card);
            assert_ne!(t.caption_pressed, t.caption_hover);
            assert_ne!(t.close_glyph_hover, t.close_hover);
            assert_ne!(t.revoke_pressed, t.revoke_hover);
            assert_ne!(t.revoke_hover, t.card);
        }
    }

    #[test]
    fn contrast_follows_the_wcag_formula() {
        assert!((contrast(Rgb(0x000000), Rgb(0xffffff)) - 21.0).abs() < 0.01);
        assert!((contrast(Rgb(0x777777), Rgb(0xffffff)) - 4.48).abs() < 0.01);
        assert_eq!(contrast(Rgb(0x123456), Rgb(0x123456)), 1.0);
    }

    #[test]
    fn text_meets_wcag_aa_in_both_themes() {
        for t in [Theme::LIGHT, Theme::DARK] {
            for (ink, under) in [
                (t.text, t.bg),
                (t.text, t.card),
                (t.text, t.field),
                (t.text, t.tile),
                (t.muted, t.bg),
                (t.muted, t.card),
                (t.rail_text, t.rail),
                (t.rail_text, t.rail_hover),
                (t.rail_on, t.rail_selected),
                (t.caption, t.caption_hover),
                (t.pill_text, t.tile),
                (t.button_text, t.button),
                (t.button_text, t.button_hover),
                (t.warning, t.card),
                (t.revoke_glyph, t.card),
                (t.notice_text, t.notice),
            ] {
                assert!(contrast(ink, under) >= 4.5, "{ink:?} on {under:?}");
            }
        }
    }

    #[test]
    fn the_focus_ring_stands_out_in_both_themes() {
        for t in [Theme::LIGHT, Theme::DARK] {
            for under in [t.bg, t.card, t.rail] {
                assert!(contrast(t.focus, under) >= 3.0, "{under:?}");
            }
        }
    }

    #[test]
    fn an_unknown_or_missing_choice_follows_the_system() {
        assert_eq!(Choice::parse(None), Choice::System);
        assert_eq!(Choice::parse(Some("")), Choice::System);
        assert_eq!(Choice::parse(Some("Sepia")), Choice::System);
        assert_eq!(Choice::parse(Some("System")), Choice::System);
        assert_eq!(Choice::parse(Some("Light")), Choice::Light);
        assert_eq!(Choice::parse(Some("Dark")), Choice::Dark);
        assert_eq!(Choice::default(), Choice::System);
    }

    #[test]
    fn choices_round_trip_through_their_names() {
        for c in Choice::ALL {
            assert_eq!(Choice::parse(Some(c.name())), c);
        }
        assert_eq!(Choice::ALL.map(Choice::name), ["System", "Light", "Dark"]);
    }

    #[test]
    fn the_system_choice_follows_the_app_mode() {
        assert!(!Choice::System.dark(true));
        assert!(Choice::System.dark(false));
        assert!(!Choice::Light.dark(false));
        assert!(Choice::Dark.dark(true));
        assert_eq!(Theme::of(false), &Theme::LIGHT);
        assert_eq!(Theme::of(true), &Theme::DARK);
    }

    #[test]
    fn a_missing_app_mode_reads_as_light() {
        assert!(light_apps(None));
        assert!(light_apps(Some(1)));
        assert!(!light_apps(Some(0)));
    }

    #[test]
    fn the_dark_title_bar_attribute_depends_on_the_build() {
        assert_eq!(immersive_attribute(7601), None);
        assert_eq!(immersive_attribute(17762), None);
        assert_eq!(immersive_attribute(17763), Some(19));
        assert_eq!(immersive_attribute(18984), Some(19));
        assert_eq!(immersive_attribute(18985), Some(20));
        assert_eq!(immersive_attribute(22631), Some(20));
    }

    #[test]
    fn menus_follow_the_choice_only_where_the_app_mode_exists() {
        assert_eq!(menu_mode(Choice::System, 18361), None);
        assert_eq!(menu_mode(Choice::System, 18362), Some(1));
        assert_eq!(menu_mode(Choice::Dark, 19045), Some(2));
        assert_eq!(menu_mode(Choice::Light, 22631), Some(3));
    }

    #[test]
    fn dark_tooltips_need_the_dark_explorer_theme() {
        assert!(!dark_controls(17762));
        assert!(dark_controls(17763));
    }
}
