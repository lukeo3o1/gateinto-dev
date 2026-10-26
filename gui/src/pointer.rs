use crate::hit::Zone;
use crate::nav::Page;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Select(Page),
    Minimize,
    ToggleMaximize,
    Close,
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
    fn leaving_clears_hover_and_press() {
        let mut p = Pointer::default();
        p.moved(Zone::Close);
        p.down(Zone::Close);
        assert!(p.left());
        assert_eq!(p.look(Zone::Close), Look::Rest);
        assert_eq!(p.up(Zone::Close), None);
        assert!(!p.left());
    }
}
