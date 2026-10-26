use std::ffi::OsStr;

use crate::fonts;

pub const ICON_FAMILIES: &[&str] = &["Segoe Fluent Icons", "Segoe MDL2 Assets"];
pub const NATURAL_SIZES: [f32; 7] = [16.0, 20.0, 24.0, 32.0, 40.0, 48.0, 64.0];
pub const FORCE_DRAWN: &str = "GATEINTO_GUI_DRAWN_ICONS";

pub fn icon_family<S: AsRef<str>>(installed: &[S]) -> Option<&'static str> {
    fonts::first_installed(installed, ICON_FAMILIES)
}

pub fn drawn_forced(value: Option<&OsStr>) -> bool {
    value == Some(OsStr::new("1"))
}

pub fn size_for(box_dip: f32) -> f32 {
    NATURAL_SIZES
        .into_iter()
        .rfind(|&size| size <= box_dip)
        .unwrap_or(NATURAL_SIZES[0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::icons;

    #[test]
    fn prefers_fluent_icons_then_mdl2_assets() {
        let both = ["Segoe MDL2 Assets", "Segoe Fluent Icons"];
        assert_eq!(icon_family(&both), Some("Segoe Fluent Icons"));
        let windows10 = ["Segoe UI", "segoe mdl2 assets"];
        assert_eq!(icon_family(&windows10), Some("Segoe MDL2 Assets"));
    }

    #[test]
    fn falls_back_to_drawn_icons_without_an_icon_font() {
        let windows7 = ["Segoe UI", "Segoe UI Symbol", "Consolas"];
        assert_eq!(icon_family(&windows7), None);
    }

    #[test]
    fn only_one_forces_the_drawn_icons() {
        assert!(drawn_forced(Some(OsStr::new("1"))));
        assert!(!drawn_forced(Some(OsStr::new("0"))));
        assert!(!drawn_forced(Some(OsStr::new(""))));
        assert!(!drawn_forced(None));
    }

    #[test]
    fn glyphs_use_the_largest_natural_size_that_fits_the_box() {
        assert_eq!(size_for(18.0), 16.0);
        assert_eq!(size_for(20.0), 20.0);
        assert_eq!(size_for(30.0), 24.0);
    }

    #[test]
    fn boxes_below_the_smallest_natural_size_use_it_anyway() {
        assert_eq!(size_for(14.0), 16.0);
    }

    #[test]
    fn icons_map_to_codepoints_shared_by_both_icon_fonts() {
        let table = [
            (icons::SESSIONS, '\u{E737}'),
            (icons::GATEWAYS, '\u{E774}'),
            (icons::IDENTITY, '\u{E72E}'),
            (icons::SETTINGS, '\u{E713}'),
            (icons::DEVICE, '\u{E7F4}'),
            (icons::BROWSER, '\u{E909}'),
            (icons::SHIELD, '\u{EA18}'),
            (icons::PLUS, '\u{E710}'),
        ];
        for (icon, glyph) in table {
            assert_eq!(icon.glyph, glyph);
        }
    }
}
