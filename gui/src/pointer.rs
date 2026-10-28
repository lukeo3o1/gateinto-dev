use crate::add::Input;
use crate::credentials::Field;
use crate::hit::Zone;
use crate::log::Filter;
use crate::nav::Page;
use crate::theme::Choice;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Select(Page),
    Minimize,
    ToggleMaximize,
    Close,
    StopAgent,
    Revoke(u64),
    More(u64),
    StartBrowser(usize),
    GatewayDetails(usize),
    OpenPicker,
    Choose(usize),
    OpenConfig,
    ToggleSignIn,
    Theme(Choice),
    CopyId,
    CopyLog,
    Filter(Filter),
    CopyCredential(Field),
    TogglePassword,
    RevokeCredentials,
    CloseDialog,
    AddGateway,
    Focus(Input),
    ConfirmAdd,
    OpenMain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Look {
    Rest,
    Hover,
    Pressed,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pointer {
    hover: Option<Zone>,
    pressed: Option<Zone>,
}

// A stray click must not discard values typed into the add gateway form.
pub fn outside_click_closes(adding: bool) -> bool {
    !adding
}

fn action(zone: Zone) -> Option<Action> {
    match zone {
        Zone::Nav(page) => Some(Action::Select(page)),
        Zone::Minimize => Some(Action::Minimize),
        Zone::Maximize => Some(Action::ToggleMaximize),
        Zone::Close => Some(Action::Close),
        Zone::StopAgent => Some(Action::StopAgent),
        Zone::Revoke(id) => Some(Action::Revoke(id)),
        Zone::More(id) => Some(Action::More(id)),
        Zone::StartBrowser(row) => Some(Action::StartBrowser(row)),
        Zone::GatewayCard(row) => Some(Action::GatewayDetails(row)),
        Zone::Picker => Some(Action::OpenPicker),
        Zone::Entry(i) => Some(Action::Choose(i)),
        Zone::OpenConfig => Some(Action::OpenConfig),
        Zone::SignIn => Some(Action::ToggleSignIn),
        Zone::Theme(choice) => Some(Action::Theme(choice)),
        Zone::CopyId => Some(Action::CopyId),
        Zone::CopyLog => Some(Action::CopyLog),
        Zone::LogFilter(filter) => Some(Action::Filter(filter)),
        Zone::CopyCredential(field) => Some(Action::CopyCredential(field)),
        Zone::TogglePassword(_) => Some(Action::TogglePassword),
        Zone::RevokeCredentials => Some(Action::RevokeCredentials),
        Zone::CloseDialog => Some(Action::CloseDialog),
        Zone::AddGateway => Some(Action::AddGateway),
        Zone::AddField(input) => Some(Action::Focus(input)),
        Zone::ConfirmAdd => Some(Action::ConfirmAdd),
        Zone::OpenMain => Some(Action::OpenMain),
        _ => None,
    }
}

impl Pointer {
    pub fn look(&self, zone: Zone) -> Look {
        let hovered = self.hover == Some(zone);
        match self.pressed {
            Some(p) if p == zone && hovered => Look::Pressed,
            Some(_) => Look::Rest,
            None if hovered => Look::Hover,
            None => Look::Rest,
        }
    }

    pub fn moved(&mut self, zone: Zone) -> bool {
        let next = action(zone).map(|_| zone);
        std::mem::replace(&mut self.hover, next) != next
    }

    pub fn down(&mut self, zone: Zone) -> bool {
        if action(zone).is_none() {
            return false;
        }
        self.hover = Some(zone);
        self.pressed = Some(zone);
        true
    }

    pub fn up(&mut self, zone: Zone) -> Option<Action> {
        if self.pressed.take()? != zone {
            return None;
        }
        action(zone)
    }

    pub fn cancel(&mut self) -> bool {
        self.pressed.take().is_some()
    }

    pub fn sessions_changed(&mut self) -> bool {
        matches!(self.pressed, Some(Zone::Revoke(_) | Zone::More(_))) && self.cancel()
    }

    pub fn gateways_changed(&mut self) -> bool {
        matches!(
            self.pressed,
            Some(Zone::StartBrowser(_) | Zone::GatewayCard(_))
        ) && self.cancel()
    }

    pub fn entries_changed(&mut self) -> bool {
        matches!(self.pressed, Some(Zone::Entry(_))) && self.cancel()
    }

    pub fn left(&mut self) -> bool {
        let changed = self.hover.is_some() || self.pressed.is_some();
        *self = Self::default();
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SETTINGS: Zone = Zone::Nav(Page::Settings);

    #[test]
    fn hovers_only_interactive_zones() {
        let mut p = Pointer::default();
        assert!(p.moved(Zone::Close));
        assert_eq!(p.look(Zone::Close), Look::Hover);
        assert!(!p.moved(Zone::Close));
        assert!(p.moved(Zone::Caption));
        assert_eq!(p.look(Zone::Close), Look::Rest);
        assert!(!p.moved(Zone::Client));
        assert!(!p.moved(Zone::Top));
    }

    #[test]
    fn click_on_the_same_target_acts() {
        let mut p = Pointer::default();
        p.moved(SETTINGS);
        assert!(p.down(SETTINGS));
        assert_eq!(p.look(SETTINGS), Look::Pressed);
        assert_eq!(p.up(SETTINGS), Some(Action::Select(Page::Settings)));
        assert_eq!(p.look(SETTINGS), Look::Hover);
    }

    #[test]
    fn caption_buttons_map_to_window_actions() {
        for (zone, action) in [
            (Zone::Minimize, Action::Minimize),
            (Zone::Maximize, Action::ToggleMaximize),
            (Zone::Close, Action::Close),
        ] {
            let mut p = Pointer::default();
            p.down(zone);
            assert_eq!(p.up(zone), Some(action));
        }
    }

    #[test]
    fn the_tray_flyout_opens_the_main_window() {
        let mut p = Pointer::default();
        p.down(Zone::OpenMain);
        assert_eq!(p.up(Zone::OpenMain), Some(Action::OpenMain));
    }

    #[test]
    fn releasing_elsewhere_cancels() {
        let mut p = Pointer::default();
        p.down(Zone::Close);
        p.moved(Zone::Maximize);
        assert_eq!(p.look(Zone::Close), Look::Rest);
        assert_eq!(p.look(Zone::Maximize), Look::Rest);
        p.moved(Zone::Close);
        assert_eq!(p.look(Zone::Close), Look::Pressed);
        assert_eq!(p.up(Zone::Maximize), None);
        assert_eq!(p.up(Zone::Close), None);
    }

    #[test]
    fn pressing_a_passive_zone_does_nothing() {
        let mut p = Pointer::default();
        assert!(!p.down(Zone::Caption));
        assert_eq!(p.up(Zone::Caption), None);
    }

    #[test]
    fn page_buttons_stop_the_agent_and_revoke_a_session() {
        let mut p = Pointer::default();
        p.down(Zone::StopAgent);
        assert_eq!(p.up(Zone::StopAgent), Some(Action::StopAgent));
        p.down(Zone::Revoke(4));
        assert_eq!(p.up(Zone::Revoke(4)), Some(Action::Revoke(4)));
        assert!(p.moved(Zone::Revoke(9)));
        assert_eq!(p.look(Zone::Revoke(9)), Look::Hover);
    }

    #[test]
    fn a_revoke_moved_under_by_a_new_list_does_not_act() {
        let mut p = Pointer::default();
        p.down(Zone::Revoke(4));
        p.moved(Zone::Revoke(5));
        assert_eq!(p.up(Zone::Revoke(5)), None);
    }

    #[test]
    fn a_changed_session_list_drops_a_pressed_revoke() {
        let mut p = Pointer::default();
        p.down(Zone::Revoke(4));
        assert!(p.sessions_changed());
        assert_eq!(p.look(Zone::Revoke(4)), Look::Hover);
        assert_eq!(p.up(Zone::Revoke(4)), None);
        p.down(Zone::StopAgent);
        assert!(!p.sessions_changed());
        assert_eq!(p.up(Zone::StopAgent), Some(Action::StopAgent));
    }

    #[test]
    fn a_start_browser_button_starts_its_gateway() {
        let mut p = Pointer::default();
        p.down(Zone::StartBrowser(2));
        assert_eq!(p.up(Zone::StartBrowser(2)), Some(Action::StartBrowser(2)));
        p.down(Zone::StartBrowser(1));
        assert_eq!(p.up(Zone::StartBrowser(0)), None);
    }

    #[test]
    fn a_changed_gateway_list_drops_a_pressed_start_browser() {
        let mut p = Pointer::default();
        p.down(Zone::StartBrowser(1));
        assert!(!p.sessions_changed());
        assert!(p.gateways_changed());
        assert_eq!(p.look(Zone::StartBrowser(1)), Look::Hover);
        assert_eq!(p.up(Zone::StartBrowser(1)), None);
        p.down(Zone::Revoke(4));
        assert!(!p.gateways_changed());
        assert_eq!(p.up(Zone::Revoke(4)), Some(Action::Revoke(4)));
    }

    #[test]
    fn a_gateway_card_opens_its_details_until_the_list_changes() {
        let mut p = Pointer::default();
        assert!(p.moved(Zone::GatewayCard(1)));
        p.down(Zone::GatewayCard(1));
        assert_eq!(p.up(Zone::GatewayCard(1)), Some(Action::GatewayDetails(1)));
        p.down(Zone::GatewayCard(1));
        assert!(p.gateways_changed());
        assert_eq!(p.up(Zone::GatewayCard(1)), None);
    }

    #[test]
    fn the_picker_button_opens_and_menu_entries_choose() {
        let mut p = Pointer::default();
        p.down(Zone::Picker);
        assert_eq!(p.up(Zone::Picker), Some(Action::OpenPicker));
        assert!(p.moved(Zone::Entry(1)));
        assert_eq!(p.look(Zone::Entry(1)), Look::Hover);
        p.down(Zone::Entry(1));
        assert_eq!(p.up(Zone::Entry(1)), Some(Action::Choose(1)));
        assert!(p.moved(Zone::Menu));
        assert_eq!(p.look(Zone::Entry(1)), Look::Rest);
        assert!(!p.moved(Zone::Menu));
        assert!(!p.down(Zone::Menu));
    }

    #[test]
    fn a_more_button_opens_its_session_menu() {
        let mut p = Pointer::default();
        assert!(p.moved(Zone::More(3)));
        assert_eq!(p.look(Zone::More(3)), Look::Hover);
        p.down(Zone::More(3));
        assert_eq!(p.up(Zone::More(3)), Some(Action::More(3)));
        p.down(Zone::More(3));
        assert_eq!(p.up(Zone::More(4)), None);
    }

    #[test]
    fn a_changed_session_list_drops_a_pressed_more_button() {
        let mut p = Pointer::default();
        p.down(Zone::More(3));
        assert!(!p.gateways_changed());
        assert!(p.sessions_changed());
        assert_eq!(p.up(Zone::More(3)), None);
    }

    #[test]
    fn changed_menu_entries_drop_a_pressed_entry() {
        let mut p = Pointer::default();
        p.down(Zone::Entry(0));
        assert!(!p.sessions_changed());
        assert!(!p.gateways_changed());
        assert!(p.entries_changed());
        assert_eq!(p.up(Zone::Entry(0)), None);
        p.down(Zone::More(3));
        assert!(!p.entries_changed());
        assert_eq!(p.up(Zone::More(3)), Some(Action::More(3)));
    }

    #[test]
    fn settings_buttons_open_the_config_and_toggle_sign_in() {
        let mut p = Pointer::default();
        assert!(p.moved(Zone::OpenConfig));
        assert!(p.down(Zone::OpenConfig));
        assert_eq!(p.up(Zone::OpenConfig), Some(Action::OpenConfig));
        assert!(p.down(Zone::SignIn));
        assert_eq!(p.up(Zone::SignIn), Some(Action::ToggleSignIn));
    }

    #[test]
    fn the_device_page_copies_its_id() {
        let mut p = Pointer::default();
        assert!(p.down(Zone::CopyId));
        assert_eq!(p.up(Zone::CopyId), Some(Action::CopyId));
    }

    #[test]
    fn the_log_page_copies_its_lines_and_switches_its_filter() {
        let mut p = Pointer::default();
        assert!(p.down(Zone::CopyLog));
        assert_eq!(p.up(Zone::CopyLog), Some(Action::CopyLog));
        let warnings = Zone::LogFilter(Filter::Warnings);
        assert!(p.moved(warnings));
        assert_eq!(p.look(warnings), Look::Hover);
        assert!(p.down(warnings));
        assert_eq!(p.up(warnings), Some(Action::Filter(Filter::Warnings)));
    }

    #[test]
    fn the_credentials_dialog_copies_toggles_revokes_and_closes() {
        let mut p = Pointer::default();
        for (zone, action) in [
            (
                Zone::CopyCredential(Field::Password),
                Action::CopyCredential(Field::Password),
            ),
            (Zone::TogglePassword(true), Action::TogglePassword),
            (Zone::RevokeCredentials, Action::RevokeCredentials),
            (Zone::CloseDialog, Action::CloseDialog),
        ] {
            assert!(p.down(zone));
            assert_eq!(p.up(zone), Some(action));
        }
        assert!(!p.down(Zone::Dialog));
    }

    #[test]
    fn leaving_clears_hover_and_press() {
        let mut p = Pointer::default();
        p.moved(Zone::Close);
        p.down(Zone::Close);
        assert!(p.left());
        assert_eq!(p.look(Zone::Close), Look::Rest);
        assert_eq!(p.up(Zone::Close), None);
        assert!(!p.left());
    }

    #[test]
    fn losing_capture_cancels_the_press_but_keeps_the_hover() {
        let mut p = Pointer::default();
        p.moved(SETTINGS);
        p.down(SETTINGS);
        assert!(p.cancel());
        assert_eq!(p.look(SETTINGS), Look::Hover);
        assert_eq!(p.up(SETTINGS), None);
        assert!(!p.cancel());
        assert_eq!(p.look(SETTINGS), Look::Hover);
    }

    #[test]
    fn the_add_gateway_zones_act() {
        for (zone, action) in [
            (Zone::AddGateway, Action::AddGateway),
            (Zone::AddField(Input::Name), Action::Focus(Input::Name)),
            (Zone::ConfirmAdd, Action::ConfirmAdd),
        ] {
            let mut p = Pointer::default();
            assert!(p.down(zone));
            assert_eq!(p.up(zone), Some(action));
        }
    }

    #[test]
    fn an_outside_click_closes_every_dialog_but_add_gateway() {
        assert!(outside_click_closes(false));
        assert!(!outside_click_closes(true));
    }

    #[test]
    fn a_theme_part_chooses_its_theme() {
        let mut p = Pointer::default();
        let zone = Zone::Theme(Choice::Dark);
        assert!(p.moved(zone));
        assert!(p.down(zone));
        assert_eq!(p.up(zone), Some(Action::Theme(Choice::Dark)));
    }
}
