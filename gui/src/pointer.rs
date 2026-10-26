use crate::hit::Zone;
use crate::nav::Page;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Select(Page),
    Minimize,
    ToggleMaximize,
    Close,
    StopAgent,
    Revoke(u64),
    StartBrowser(usize),
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

fn action(zone: Zone) -> Option<Action> {
    match zone {
        Zone::Nav(page) => Some(Action::Select(page)),
        Zone::Minimize => Some(Action::Minimize),
        Zone::Maximize => Some(Action::ToggleMaximize),
        Zone::Close => Some(Action::Close),
        Zone::StopAgent => Some(Action::StopAgent),
        Zone::Revoke(id) => Some(Action::Revoke(id)),
        Zone::StartBrowser(row) => Some(Action::StartBrowser(row)),
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
        matches!(self.pressed, Some(Zone::Revoke(_))) && self.cancel()
    }

    pub fn gateways_changed(&mut self) -> bool {
        matches!(self.pressed, Some(Zone::StartBrowser(_))) && self.cancel()
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
}
