#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Font {
    Brand,
    Item,
    ItemSelected,
    Title,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Spec {
    pub size: u16,
    pub weight: u16,
}

impl Font {
    pub const ALL: [Font; 4] = [Font::Brand, Font::Item, Font::ItemSelected, Font::Title];

    pub fn spec(self) -> Spec {
        let (size, weight) = match self {
            Font::Brand => (16, 600),
            Font::Item => (14, 400),
            Font::ItemSelected => (14, 600),
            Font::Title => (24, 600),
        };
        Spec { size, weight }
    }
}

pub const UI_FAMILIES: &[&str] = &["Segoe UI Variable Text", "Segoe UI"];

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
