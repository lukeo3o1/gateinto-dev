use crate::layout::Font;

pub const ALL: [Font; 10] = [
    Font::Nav,
    Font::Title,
    Font::Subtitle,
    Font::Button,
    Font::CardTitle,
    Font::Small,
    Font::Mono,
    Font::CardButton,
    Font::DeviceTitle,
    Font::Link,
];

pub const UI_FAMILIES: &[&str] = &["Segoe UI Variable Text", "Segoe UI"];
pub const MONO_FAMILIES: &[&str] = &["Cascadia Mono", "Consolas"];

pub fn choose_family<'a, S: AsRef<str>>(installed: &[S], preferred: &[&'a str]) -> &'a str {
    preferred
        .iter()
        .copied()
        .find(|want| {
            installed
                .iter()
                .any(|have| have.as_ref().eq_ignore_ascii_case(want))
        })
        .or(preferred.last().copied())
        .unwrap_or_default()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Spec {
    pub size: u16,
    pub weight: u16,
    pub mono: bool,
    pub underline: bool,
}

pub fn spec(font: Font) -> Spec {
    let (size, weight) = match font {
        Font::Title => (28, 600),
        Font::CardTitle => (14, 600),
        Font::DeviceTitle => (13, 600),
        Font::Nav | Font::Button => (14, 400),
        Font::Subtitle | Font::CardButton | Font::Link => (13, 400),
        Font::Small | Font::Mono => (12, 400),
    };
    Spec {
        size,
        weight,
        mono: font == Font::Mono,
        underline: font == Font::Link,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specs_follow_the_mockup() {
        let s = |size, weight, mono, underline| Spec {
            size,
            weight,
            mono,
            underline,
        };
        assert_eq!(spec(Font::Nav), s(14, 400, false, false));
        assert_eq!(spec(Font::Title), s(28, 600, false, false));
        assert_eq!(spec(Font::Subtitle), s(13, 400, false, false));
        assert_eq!(spec(Font::Button), s(14, 400, false, false));
        assert_eq!(spec(Font::CardTitle), s(14, 600, false, false));
        assert_eq!(spec(Font::Small), s(12, 400, false, false));
        assert_eq!(spec(Font::Mono), s(12, 400, true, false));
        assert_eq!(spec(Font::CardButton), s(13, 400, false, false));
        assert_eq!(spec(Font::DeviceTitle), s(13, 600, false, false));
        assert_eq!(spec(Font::Link), s(13, 400, false, true));
    }

    #[test]
    fn every_font_is_listed_once() {
        let seen: std::collections::HashSet<Font> = ALL.into_iter().collect();
        assert_eq!(seen.len(), ALL.len());
    }

    #[test]
    fn prefers_the_first_installed_family() {
        let installed = ["Arial", "Segoe UI", "Segoe UI Variable Text"];
        assert_eq!(
            choose_family(&installed, UI_FAMILIES),
            "Segoe UI Variable Text"
        );
    }

    #[test]
    fn falls_back_to_the_next_installed_family() {
        let installed = ["Arial", "Segoe UI", "Consolas"];
        assert_eq!(choose_family(&installed, UI_FAMILIES), "Segoe UI");
        assert_eq!(choose_family(&installed, MONO_FAMILIES), "Consolas");
    }

    #[test]
    fn matches_family_names_case_insensitively() {
        let installed = vec![String::from("cascadia mono")];
        assert_eq!(choose_family(&installed, MONO_FAMILIES), "Cascadia Mono");
    }

    #[test]
    fn uses_the_last_preference_when_none_is_installed() {
        let installed: [&str; 0] = [];
        assert_eq!(choose_family(&installed, UI_FAMILIES), "Segoe UI");
        assert_eq!(choose_family(&installed, MONO_FAMILIES), "Consolas");
    }
}
