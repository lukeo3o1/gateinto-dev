use std::time::Duration;

pub const ARMING: Duration = Duration::from_secs(1);
pub const TIMEOUT: Duration = Duration::from_secs(100);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    Allow,
    Deny,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Button {
    Deny,
    Allow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    Enter,
    Space,
    Escape,
}

#[derive(Debug)]
pub struct Dialog {
    ticket: u64,
    opened: Duration,
    armed: Duration,
    pressed: Option<Button>,
}

impl Dialog {
    pub fn open(ticket: u64, now: Duration) -> Self {
        Self {
            ticket,
            opened: now,
            armed: now + ARMING,
            pressed: None,
        }
    }

    pub fn ticket(&self) -> u64 {
        self.ticket
    }

    pub fn rearm(&mut self, now: Duration) {
        self.armed = now + ARMING;
        self.pressed = None;
    }

    pub fn armed(&self, now: Duration) -> bool {
        now >= self.armed
    }

    pub fn countdown(&self, now: Duration) -> Option<u64> {
        let left = self.armed.checked_sub(now).filter(|left| !left.is_zero())?;
        Some(left.as_millis().div_ceil(1_000) as u64)
    }

    pub fn expired(&self, now: Duration) -> bool {
        now >= self.opened + TIMEOUT
    }

    pub fn pressed(&self) -> Option<Button> {
        self.pressed
    }

    pub fn press(&mut self, button: Option<Button>, now: Duration) {
        self.pressed = button.filter(|button| *button == Button::Deny || self.armed(now));
    }

    pub fn release(&mut self, button: Option<Button>, now: Duration) -> Option<Answer> {
        let pressed = self.pressed.take()?;
        match button? {
            released if released != pressed => None,
            Button::Deny => Some(Answer::Deny),
            Button::Allow => self.armed(now).then_some(Answer::Allow),
        }
    }

    pub fn key(&mut self, key: Key) -> Answer {
        self.pressed = None;
        match key {
            Key::Enter | Key::Space | Key::Escape => Answer::Deny,
        }
    }
}

#[derive(Debug)]
pub struct Desk<T> {
    issued: u64,
    open: Option<(u64, T)>,
}

impl<T> Default for Desk<T> {
    fn default() -> Self {
        Self {
            issued: 0,
            open: None,
        }
    }
}

impl<T> Desk<T> {
    pub fn open(&mut self, value: T) -> (u64, Option<T>) {
        self.issued += 1;
        let superseded = self.open.replace((self.issued, value));
        (self.issued, superseded.map(|(_, value)| value))
    }

    pub fn holds(&self, ticket: u64) -> bool {
        self.open.as_ref().is_some_and(|(open, _)| *open == ticket)
    }

    pub fn take(&mut self, ticket: u64) -> Option<T> {
        if !self.holds(ticket) {
            return None;
        }
        self.close()
    }

    pub fn close(&mut self) -> Option<T> {
        self.open.take().map(|(_, value)| value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(value: u64) -> Duration {
        Duration::from_millis(value)
    }

    #[test]
    fn allow_is_disabled_until_the_arming_delay_passes() {
        let dialog = Dialog::open(7, ms(5_000));

        assert_eq!(dialog.ticket(), 7);
        assert!(!dialog.armed(ms(5_000)));
        assert!(!dialog.armed(ms(5_999)));
        assert!(dialog.armed(ms(6_000)));
    }

    #[test]
    fn countdown_shows_whole_seconds_left_until_armed() {
        let dialog = Dialog::open(1, ms(0));

        assert_eq!(dialog.countdown(ms(0)), Some(1));
        assert_eq!(dialog.countdown(ms(999)), Some(1));
        assert_eq!(dialog.countdown(ms(1_000)), None);
    }

    #[test]
    fn rearming_restarts_the_delay() {
        let mut dialog = Dialog::open(1, ms(0));
        dialog.rearm(ms(3_000));

        assert!(!dialog.armed(ms(3_500)));
        assert_eq!(dialog.countdown(ms(3_500)), Some(1));
        assert!(dialog.armed(ms(4_000)));
    }

    #[test]
    fn allow_needs_press_and_release_on_the_armed_allow_button() {
        let mut dialog = Dialog::open(1, ms(0));
        dialog.press(Some(Button::Allow), ms(1_000));

        assert_eq!(
            dialog.release(Some(Button::Allow), ms(1_100)),
            Some(Answer::Allow)
        );
    }

    #[test]
    fn the_pressed_button_is_kept_until_release() {
        let mut dialog = Dialog::open(1, ms(0));
        dialog.press(Some(Button::Deny), ms(100));
        assert_eq!(dialog.pressed(), Some(Button::Deny));

        dialog.release(None, ms(200));
        assert_eq!(dialog.pressed(), None);

        dialog.press(Some(Button::Allow), ms(300));
        assert_eq!(dialog.pressed(), None);
    }

    #[test]
    fn a_press_while_disarmed_never_allows() {
        let mut dialog = Dialog::open(1, ms(0));
        dialog.press(Some(Button::Allow), ms(900));

        assert_eq!(dialog.release(Some(Button::Allow), ms(1_100)), None);
    }

    #[test]
    fn a_release_off_the_pressed_button_answers_nothing() {
        let mut dialog = Dialog::open(1, ms(0));
        dialog.press(Some(Button::Allow), ms(2_000));
        assert_eq!(dialog.release(None, ms(2_100)), None);
        assert_eq!(dialog.release(Some(Button::Allow), ms(2_200)), None);

        dialog.press(None, ms(2_300));
        assert_eq!(dialog.release(Some(Button::Allow), ms(2_400)), None);

        dialog.press(Some(Button::Deny), ms(2_500));
        assert_eq!(dialog.release(Some(Button::Allow), ms(2_600)), None);
    }

    #[test]
    fn rearming_between_press_and_release_drops_the_press() {
        let mut dialog = Dialog::open(1, ms(0));
        dialog.press(Some(Button::Allow), ms(2_000));
        dialog.rearm(ms(2_050));

        assert_eq!(dialog.release(Some(Button::Allow), ms(3_100)), None);
    }

    #[test]
    fn deny_click_answers_deny_even_while_disarmed() {
        let mut dialog = Dialog::open(1, ms(0));
        dialog.press(Some(Button::Deny), ms(100));

        assert_eq!(
            dialog.release(Some(Button::Deny), ms(200)),
            Some(Answer::Deny)
        );
    }

    #[test]
    fn keys_never_allow() {
        for key in [Key::Enter, Key::Space, Key::Escape] {
            let mut dialog = Dialog::open(1, ms(0));
            dialog.press(Some(Button::Allow), ms(5_000));

            assert_eq!(dialog.key(key), Answer::Deny);
        }
    }

    #[test]
    fn the_dialog_expires_after_the_timeout() {
        let mut dialog = Dialog::open(1, ms(1_000));
        dialog.rearm(ms(90_000));

        assert!(!dialog.expired(ms(100_999)));
        assert!(dialog.expired(ms(101_000)));
    }

    #[test]
    fn the_timeout_is_shorter_than_the_agent_confirm_expiry() {
        assert!(TIMEOUT < Duration::from_secs(120));
    }

    #[test]
    fn desk_issues_fresh_tickets_and_supersedes_the_open_one() {
        let mut desk = Desk::default();
        let (first, superseded) = desk.open("first");
        assert_eq!(superseded, None);

        let (second, superseded) = desk.open("second");
        assert_ne!(first, second);
        assert_eq!(superseded, Some("first"));
    }

    #[test]
    fn desk_drops_answers_for_stale_tickets() {
        let mut desk = Desk::default();
        let (first, _) = desk.open("first");
        let (second, _) = desk.open("second");

        assert!(!desk.holds(first));
        assert!(desk.holds(second));
        assert_eq!(desk.take(first), None);
        assert_eq!(desk.take(second), Some("second"));
        assert!(!desk.holds(second));
        assert_eq!(desk.take(second), None);
    }

    #[test]
    fn desk_close_hands_back_the_open_value() {
        let mut desk = Desk::default();
        let (ticket, _) = desk.open("open");

        assert_eq!(desk.close(), Some("open"));
        assert_eq!(desk.close(), None);
        assert_eq!(desk.take(ticket), None);
    }
}
