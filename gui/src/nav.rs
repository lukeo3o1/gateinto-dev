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
        match self {
            Page::Sessions => "Sessions",
            Page::Gateways => "Gateways",
            Page::Device => "Device",
            Page::Log => "Log",
            Page::Settings => "Settings",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Page::Device => "This device",
            other => other.label(),
        }
    }

    pub fn at_bottom(self) -> bool {
        matches!(self, Page::Log | Page::Settings)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyKind {
    Hardware,
    Software,
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
