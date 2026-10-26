pub struct FocusCue {
    visible: bool,
}

impl FocusCue {
    pub fn new(always: bool) -> Self {
        Self { visible: always }
    }

    pub fn visible(&self) -> bool {
        self.visible
    }

    pub fn reveal(&mut self) -> bool {
        !std::mem::replace(&mut self.visible, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hidden_until_keyboard_is_used() {
        let cue = FocusCue::new(false);
        assert!(!cue.visible());
    }

    #[test]
    fn visible_from_start_when_the_system_always_shows_cues() {
        assert!(FocusCue::new(true).visible());
    }

    #[test]
    fn first_reveal_reports_a_change_and_later_ones_do_not() {
        let mut cue = FocusCue::new(false);
        assert!(cue.reveal());
        assert!(cue.visible());
        assert!(!cue.reveal());
    }

    #[test]
    fn reveal_reports_no_change_when_already_visible() {
        assert!(!FocusCue::new(true).reveal());
    }
}
