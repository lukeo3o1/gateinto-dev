use crate::color::{self, Rgb};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control {
    Nav(usize),
    OpenLog,
    NewSession,
    Credentials(usize),
    Revoke(usize),
    Details,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct State {
    pub hover: bool,
    pub pressed: bool,
    pub focused: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Look {
    pub surface: Rgb,
    pub fill: Option<Rgb>,
    pub border: Option<Rgb>,
    pub text: Rgb,
}

const SLOTS: u16 = 100;

impl Control {
    pub fn id(self) -> u16 {
        match self {
            Self::Nav(i) => SLOTS + i as u16,
            Self::OpenLog => 2 * SLOTS,
            Self::NewSession => 2 * SLOTS + 1,
            Self::Credentials(i) => 3 * SLOTS + i as u16,
            Self::Revoke(i) => 4 * SLOTS + i as u16,
            Self::Details => 5 * SLOTS,
        }
    }

    pub fn from_id(id: u16) -> Option<Self> {
        let i = usize::from(id % SLOTS);
        match (id / SLOTS, id % SLOTS) {
            (1, _) => Some(Self::Nav(i)),
            (2, 0) => Some(Self::OpenLog),
            (2, 1) => Some(Self::NewSession),
            (3, _) => Some(Self::Credentials(i)),
            (4, _) => Some(Self::Revoke(i)),
            (5, 0) => Some(Self::Details),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        use crate::model;
        match self {
            Self::Nav(i) => model::NAV.get(i).copied().unwrap_or_default(),
            Self::OpenLog => model::OPEN_LOG,
            Self::NewSession => model::NEW_SESSION,
            Self::Credentials(_) => model::CREDENTIALS,
            Self::Revoke(_) => model::REVOKE,
            Self::Details => model::DETAILS,
        }
    }

    pub fn is_active(self) -> bool {
        self != Self::Nav(crate::model::SELECTED_NAV)
    }
}

fn pick(state: State, rest: Rgb, hover: Rgb, pressed: Rgb) -> Rgb {
    if state.pressed {
        pressed
    } else if state.hover {
        hover
    } else {
        rest
    }
}

pub fn look(control: Control, state: State) -> Look {
    let text_on_button = pick(state, color::TEXT, color::TEXT, color::TEXT_PRESSED);
    match control {
        Control::Nav(i) if i == crate::model::SELECTED_NAV => Look {
            surface: color::WINDOW,
            fill: Some(pick(
                state,
                color::NAV_SELECTED,
                color::NAV_SELECTED_HOVER,
                color::NAV_SELECTED_HOVER,
            )),
            border: None,
            text: color::TEXT,
        },
        Control::Nav(_) => Look {
            surface: color::WINDOW,
            fill: (state.hover || state.pressed)
                .then(|| pick(state, color::WINDOW, color::NAV_HOVER, color::NAV_PRESSED)),
            border: None,
            text: color::TEXT,
        },
        Control::OpenLog => Look {
            surface: color::PANEL,
            fill: Some(pick(
                state,
                color::BUTTON,
                color::BUTTON_HOVER,
                color::BUTTON_PRESSED,
            )),
            border: Some(color::CONTROL_STROKE),
            text: text_on_button,
        },
        Control::NewSession => Look {
            surface: color::PANEL,
            fill: Some(pick(
                state,
                color::ACCENT,
                color::ACCENT_HOVER,
                color::ACCENT_PRESSED,
            )),
            border: None,
            text: color::ON_ACCENT,
        },
        Control::Credentials(_) | Control::Revoke(_) => Look {
            surface: color::CARD,
            fill: Some(pick(
                state,
                color::BUTTON_SUBTLE,
                color::BUTTON_HOVER,
                color::BUTTON_PRESSED,
            )),
            border: Some(color::CONTROL_STROKE),
            text: match control {
                Control::Revoke(_) => color::DANGER,
                _ => text_on_button,
            },
        },
        Control::Details => Look {
            surface: color::CARD,
            fill: None,
            border: None,
            text: pick(state, color::ACCENT, color::LINK_HOVER, color::LINK_HOVER),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Control; 10] = [
        Control::Nav(0),
        Control::Nav(3),
        Control::OpenLog,
        Control::NewSession,
        Control::Credentials(0),
        Control::Credentials(2),
        Control::Revoke(0),
        Control::Revoke(2),
        Control::Details,
        Control::Nav(1),
    ];

    const HOVER: State = State {
        hover: true,
        pressed: false,
        focused: false,
    };
    const PRESSED: State = State {
        hover: true,
        pressed: true,
        focused: false,
    };

    #[test]
    fn labels_come_from_the_model() {
        assert_eq!(Control::Nav(2).label(), "Device identity");
        assert_eq!(Control::Nav(9).label(), "");
        assert_eq!(Control::OpenLog.label(), "Open log");
        assert_eq!(Control::NewSession.label(), "New browser session");
        assert_eq!(Control::Credentials(0).label(), "Credentials");
        assert_eq!(Control::Revoke(2).label(), "Revoke");
        assert_eq!(Control::Details.label(), "Details");
    }

    #[test]
    fn ids_round_trip() {
        for control in ALL {
            assert_eq!(Control::from_id(control.id()), Some(control));
        }
    }

    #[test]
    fn ids_are_distinct_and_nonzero() {
        let mut ids: Vec<u16> = ALL.iter().map(|c| c.id()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), ALL.len());
        assert!(ids.iter().all(|&id| id > 2));
    }

    #[test]
    fn unknown_ids_are_rejected() {
        assert_eq!(Control::from_id(0), None);
        assert_eq!(Control::from_id(1), None);
        assert_eq!(Control::from_id(999), None);
    }

    #[test]
    fn the_selected_nav_item_does_nothing() {
        assert!(!Control::Nav(crate::model::SELECTED_NAV).is_active());
        assert!(Control::Nav(1).is_active());
        assert!(Control::Revoke(0).is_active());
    }

    #[test]
    fn selected_nav_has_a_pill_that_darkens_on_hover() {
        let rest = look(Control::Nav(0), State::default());
        assert_eq!(rest.surface, color::WINDOW);
        assert_eq!(rest.fill, Some(color::NAV_SELECTED));
        assert_eq!(
            look(Control::Nav(0), HOVER).fill,
            Some(color::NAV_SELECTED_HOVER)
        );
    }

    #[test]
    fn other_nav_items_are_transparent_until_hovered() {
        assert_eq!(look(Control::Nav(1), State::default()).fill, None);
        assert_eq!(look(Control::Nav(1), HOVER).fill, Some(color::NAV_HOVER));
        assert_eq!(
            look(Control::Nav(1), PRESSED).fill,
            Some(color::NAV_PRESSED)
        );
    }

    #[test]
    fn open_log_is_a_bordered_white_button_on_the_panel() {
        let rest = look(Control::OpenLog, State::default());
        assert_eq!(rest.surface, color::PANEL);
        assert_eq!(rest.fill, Some(color::BUTTON));
        assert_eq!(rest.border, Some(color::CONTROL_STROKE));
        assert_eq!(rest.text, color::TEXT);
        assert_eq!(
            look(Control::OpenLog, HOVER).fill,
            Some(color::BUTTON_HOVER)
        );
        let pressed = look(Control::OpenLog, PRESSED);
        assert_eq!(pressed.fill, Some(color::BUTTON_PRESSED));
        assert_eq!(pressed.text, color::TEXT_PRESSED);
    }

    #[test]
    fn new_session_is_an_accent_button() {
        let rest = look(Control::NewSession, State::default());
        assert_eq!(rest.fill, Some(color::ACCENT));
        assert_eq!(rest.border, None);
        assert_eq!(rest.text, color::ON_ACCENT);
        assert_eq!(
            look(Control::NewSession, HOVER).fill,
            Some(color::ACCENT_HOVER)
        );
        assert_eq!(
            look(Control::NewSession, PRESSED).fill,
            Some(color::ACCENT_PRESSED)
        );
    }

    #[test]
    fn card_buttons_are_subtle_on_white_and_revoke_is_red() {
        let credentials = look(Control::Credentials(0), State::default());
        assert_eq!(credentials.surface, color::CARD);
        assert_eq!(credentials.fill, Some(color::BUTTON_SUBTLE));
        assert_eq!(credentials.text, color::TEXT);
        let revoke = look(Control::Revoke(1), State::default());
        assert_eq!(revoke.fill, Some(color::BUTTON_SUBTLE));
        assert_eq!(revoke.text, color::DANGER);
        assert_eq!(
            look(Control::Revoke(1), HOVER).fill,
            Some(color::BUTTON_HOVER)
        );
    }

    #[test]
    fn details_is_a_link_that_darkens_on_hover() {
        let rest = look(Control::Details, State::default());
        assert_eq!(rest.surface, color::CARD);
        assert_eq!(rest.fill, None);
        assert_eq!(rest.border, None);
        assert_eq!(rest.text, color::ACCENT);
        assert_eq!(look(Control::Details, HOVER).text, color::LINK_HOVER);
    }
}
