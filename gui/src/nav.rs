use crate::i18n::{Text, tr};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Page {
    #[default]
    Sessions,
    Gateways,
    Device,
    Log,
    Settings,
}

impl Page {
    pub const ALL: [Page; 5] = [
        Page::Sessions,
        Page::Gateways,
        Page::Device,
        Page::Log,
        Page::Settings,
    ];

    pub fn label(self) -> &'static str {
        tr(match self {
            Page::Sessions => Text::Sessions,
            Page::Gateways => Text::Gateways,
            Page::Device => Text::Device,
            Page::Log => Text::Log,
            Page::Settings => Text::Settings,
        })
    }

    pub fn title(self) -> &'static str {
        match self {
            Page::Device => tr(Text::ThisDevice),
            other => other.label(),
        }
    }

    pub fn at_bottom(self) -> bool {
        matches!(self, Page::Log | Page::Settings)
    }
}

// AltGr arrives as Ctrl+Alt, so a held Alt keeps AltGr digits out.
pub fn shortcut(key: u16, ctrl: bool, alt: bool) -> Option<Page> {
    if !ctrl || alt {
        return None;
    }
    let i = key.checked_sub(u16::from(b'1'))?;
    Page::ALL.get(usize::from(i)).copied()
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Nav {
    selected: Page,
}

impl Nav {
    pub fn selected(self) -> Page {
        self.selected
    }

    pub fn select(&mut self, page: Page) -> bool {
        let changed = self.selected != page;
        self.selected = page;
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctrl_digits_pick_pages_but_altgr_digits_do_not() {
        assert_eq!(shortcut(u16::from(b'1'), true, false), Some(Page::Sessions));
        assert_eq!(shortcut(u16::from(b'5'), true, false), Some(Page::Settings));
        assert_eq!(shortcut(u16::from(b'6'), true, false), None);
        assert_eq!(shortcut(u16::from(b'0'), true, false), None);
        assert_eq!(shortcut(u16::from(b'2'), false, false), None);
        assert_eq!(shortcut(u16::from(b'2'), true, true), None);
    }

    #[test]
    fn rail_order_matches_the_board() {
        assert_eq!(
            Page::ALL,
            [
                Page::Sessions,
                Page::Gateways,
                Page::Device,
                Page::Log,
                Page::Settings
            ]
        );
    }

    #[test]
    fn labels_and_titles() {
        let labels: Vec<_> = Page::ALL.iter().map(|p| p.label()).collect();
        assert_eq!(
            labels,
            ["Sessions", "Gateways", "Device", "Log", "Settings"]
        );
        let titles: Vec<_> = Page::ALL.iter().map(|p| p.title()).collect();
        assert_eq!(
            titles,
            ["Sessions", "Gateways", "This device", "Log", "Settings"]
        );
    }

    #[test]
    fn log_and_settings_sit_at_the_bottom() {
        let bottom: Vec<_> = Page::ALL.into_iter().filter(|p| p.at_bottom()).collect();
        assert_eq!(bottom, [Page::Log, Page::Settings]);
    }

    #[test]
    fn starts_on_sessions_and_select_reports_changes() {
        let mut nav = Nav::default();
        assert_eq!(nav.selected(), Page::Sessions);
        assert!(nav.select(Page::Device));
        assert_eq!(nav.selected(), Page::Device);
        assert!(!nav.select(Page::Device));
    }
}
