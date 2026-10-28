#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Font {
    Brand,
    Item,
    ItemSelected,
    Title,
    Status,
    Heading,
    Body,
    BodyStrong,
    Small,
    Pill,
    Mono,
    Lead,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Spec {
    pub size: u16,
    pub weight: u16,
}

impl Font {
    pub const ALL: [Font; 12] = [
        Font::Brand,
        Font::Item,
        Font::ItemSelected,
        Font::Title,
        Font::Status,
        Font::Heading,
        Font::Body,
        Font::BodyStrong,
        Font::Small,
        Font::Pill,
        Font::Mono,
        Font::Lead,
    ];

    pub fn spec(self) -> Spec {
        let (size, weight) = match self {
            Font::Brand => (16, 600),
            Font::Item => (14, 400),
            Font::ItemSelected => (14, 600),
            Font::Title => (24, 600),
            Font::Status => (20, 600),
            Font::Heading => (15, 600),
            Font::Body => (13, 400),
            Font::BodyStrong => (13, 600),
            Font::Small => (12, 400),
            Font::Pill => (11, 400),
            Font::Mono => (12, 400),
            Font::Lead => (17, 600),
        };
        Spec { size, weight }
    }

    pub fn families(self) -> &'static [&'static str] {
        match self {
            Font::Mono => MONO_FAMILIES,
            _ => UI_FAMILIES,
        }
    }
}

pub trait Measure {
    fn width(&self, font: Font, text: &str) -> i32;
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specs_follow_the_board() {
        let s = |size, weight| Spec { size, weight };
        assert_eq!(Font::Brand.spec(), s(16, 600));
        assert_eq!(Font::Item.spec(), s(14, 400));
        assert_eq!(Font::ItemSelected.spec(), s(14, 600));
        assert_eq!(Font::Title.spec(), s(24, 600));
        assert_eq!(Font::Status.spec(), s(20, 600));
        assert_eq!(Font::Heading.spec(), s(15, 600));
        assert_eq!(Font::Body.spec(), s(13, 400));
        assert_eq!(Font::BodyStrong.spec(), s(13, 600));
        assert_eq!(Font::Small.spec(), s(12, 400));
        assert_eq!(Font::Pill.spec(), s(11, 400));
        assert_eq!(Font::Mono.spec(), s(12, 400));
        assert_eq!(Font::Lead.spec(), s(17, 600));
    }

    #[test]
    fn only_mono_uses_the_monospaced_families() {
        for font in Font::ALL {
            let want = if font == Font::Mono {
                MONO_FAMILIES
            } else {
                UI_FAMILIES
            };
            assert_eq!(font.families(), want);
        }
        assert_eq!(MONO_FAMILIES, ["Cascadia Mono", "Consolas"]);
    }

    #[test]
    fn all_lists_every_font_at_its_index() {
        for (i, font) in Font::ALL.into_iter().enumerate() {
            assert_eq!(font as usize, i);
        }
    }

    #[test]
    fn prefers_the_first_installed_family_ignoring_case() {
        assert_eq!(
            choose_family(&["segoe ui", "SEGOE UI VARIABLE TEXT"], UI_FAMILIES),
            "Segoe UI Variable Text"
        );
        assert_eq!(choose_family(&["Segoe UI"], UI_FAMILIES), "Segoe UI");
    }

    #[test]
    fn falls_back_to_the_last_preference() {
        assert_eq!(choose_family::<&str>(&[], UI_FAMILIES), "Segoe UI");
    }
}
