use std::path::PathBuf;

use gateinto::config::{DisplayName, GatewayName, PortalUrl};
use gateinto::link::store::{LinkedStore, StoreError};
use gateinto::link::{
    self, ALL_TRAFFIC, Decision, IDENTITY, Known, LOCAL_ADDRESS, LinkError, LinkedGateway,
    MIXED_WARNING, Resolution, TRUST,
};
use gateinto::proxy::Route;
use gateinto::uri::{LaunchAuth, LaunchRequest, UriError};

use crate::gateways;
use crate::i18n::{Language, Text, chinese_disclosure, current, fill, tr};
use crate::naming;

pub const TITLE: Text = Text::AddGateway;
pub const ADDRESS_HINT: Text = Text::AddressHint;
pub const NAME_HINT: Text = Text::NameHint;
pub const PORTAL_HINT: Text = Text::PortalHint;
pub const NO_FOLDER: Text = Text::NoFolder;
const DAMAGED: Text = Text::Damaged;
const UNSTORABLE: Text = Text::Unstorable;
const UNAVAILABLE: Text = Text::StoreUnavailable;
const TAKEN: Text = Text::Taken;
const FULL: Text = Text::Full;
const NOT_SAVED: Text = Text::NotSaved;
const UNLISTED: Text = Text::Unlisted;
const UNUSABLE: Text = Text::Unusable;
// The longest DNS name, a colon and a five digit port.
const MAX_ADDRESS: usize = 253 + 1 + 5;
const MAX_TYPED_NAME: usize = 4 * DisplayName::MAX_LEN;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Input {
    #[default]
    Address,
    Name,
    Portal,
}

fn saved_len(name: &str) -> usize {
    let words = name.split_whitespace().map(|word| word.chars().count() + 1);
    words.sum::<usize>().saturating_sub(1)
}

impl Input {
    fn fits(self, field: &str, c: char) -> bool {
        match self {
            Self::Address => field.len() + c.len_utf8() <= MAX_ADDRESS,
            Self::Name => {
                field.chars().count() < MAX_TYPED_NAME
                    && saved_len(&format!("{field}{c}")) <= DisplayName::MAX_LEN
            }
            Self::Portal => field.len() + c.len_utf8() <= PortalUrl::MAX_LEN,
        }
    }

    fn takes(self, c: char) -> bool {
        !c.is_control() && (self == Self::Name || !c.is_whitespace())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message(Text, String);

impl Message {
    fn with(text: Text, arg: impl std::fmt::Display) -> Self {
        Self(text, arg.to_string())
    }

    pub fn text(&self) -> String {
        fill(self.0, &[&self.1])
    }
}

impl From<Text> for Message {
    fn from(text: Text) -> Self {
        Self(text, String::new())
    }
}

#[derive(Debug, Default)]
pub struct Form {
    address: String,
    name: String,
    portal: String,
    focus: Input,
    route: Route,
    failure: Option<Message>,
}

impl Form {
    pub fn value(&self, input: Input) -> &str {
        match input {
            Input::Address => &self.address,
            Input::Name => &self.name,
            Input::Portal => &self.portal,
        }
    }

    fn field(&mut self) -> &mut String {
        self.failure = None;
        match self.focus {
            Input::Address => &mut self.address,
            Input::Name => &mut self.name,
            Input::Portal => &mut self.portal,
        }
    }

    pub fn select(&mut self, input: Input) {
        self.focus = input;
    }

    pub fn choose(&mut self, route: Route) {
        self.failure = None;
        self.route = route;
    }

    pub fn type_text(&mut self, text: &str) {
        let input = self.focus;
        let field = self.field();
        for c in text.chars().filter(|&c| input.takes(c)) {
            if !input.fits(field, c) {
                break;
            }
            field.push(c);
        }
    }

    pub fn erase(&mut self) {
        self.field().pop();
    }

    pub fn selected(&self) -> Input {
        self.focus
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Keyed {
    Changed,
    Submit,
    Paste,
    Ignored,
}

pub fn keyed(form: &mut Form, field: Option<Input>, c: char) -> Keyed {
    if c == '\r' {
        return Keyed::Submit;
    }
    let Some(field) = field else {
        return Keyed::Ignored;
    };
    form.select(field);
    match c {
        '\u{8}' => {
            form.erase();
            Keyed::Changed
        }
        '\u{16}' => Keyed::Paste,
        c if c.is_control() => Keyed::Ignored,
        c => {
            form.type_text(c.encode_utf8(&mut [0; 4]));
            Keyed::Changed
        }
    }
}

#[derive(Debug, Default)]
pub struct Units {
    high: Option<u16>,
}

impl Units {
    pub fn push(&mut self, unit: u16) -> Option<char> {
        let high = self.high.take();
        if (0xD800..0xDC00).contains(&unit) {
            self.high = Some(unit);
            return None;
        }
        match high {
            Some(high) if (0xDC00..0xE000).contains(&unit) => {
                char::decode_utf16([high, unit]).next()?.ok()
            }
            _ => char::from_u32(u32::from(unit)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ready {
    pub gateway: LinkedGateway,
    pub local: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Incomplete,
    Invalid(Option<Input>, Message),
    Ready(Ready),
}

fn optional(text: &str) -> Option<&str> {
    Some(text).filter(|text| !text.is_empty())
}

fn field_error(error: UriError) -> Verdict {
    let (input, message) = match error {
        UriError::InvalidValue("gateway") => (Input::Address, Text::EnterHost),
        UriError::ReservedGateway => (Input::Address, Text::ReservedHost),
        UriError::InvalidValue("portal") => (Input::Portal, Text::EnterHttps),
        _ => return Verdict::Invalid(None, UNUSABLE.into()),
    };
    Verdict::Invalid(Some(input), message.into())
}

fn shown(known: &Known, name: &GatewayName) -> String {
    known
        .gateways
        .iter()
        .find(|gateway| &gateway.name == name)
        .map_or_else(|| name.to_string(), gateways::label)
}

fn link_error(known: &Known, error: LinkError) -> Verdict {
    let (input, message) = match error {
        LinkError::KnownGateway { existing, .. } => (
            Some(Input::Address),
            Message::with(Text::AlreadySetUp, shown(known, &existing)),
        ),
        LinkError::Damaged { .. } => (None, DAMAGED.into()),
        LinkError::Unstorable { .. } => (Some(Input::Address), UNSTORABLE.into()),
        LinkError::StoreUnavailable(_) => (None, UNAVAILABLE.into()),
        _ => (None, UNUSABLE.into()),
    };
    Verdict::Invalid(input, message)
}

fn display_name(form: &Form, known: &Known) -> Result<Option<DisplayName>, Message> {
    if form.name.trim().is_empty() {
        return Ok(None);
    }
    let name = DisplayName::normalize(&form.name)
        .map_err(|_| Message::with(Text::NameRule, DisplayName::MAX_LEN))?;
    let wanted = name.as_str().to_lowercase();
    match known
        .gateways
        .iter()
        .map(gateways::label)
        .find(|shown| shown.to_lowercase() == wanted)
    {
        Some(shown) => Err(Message::with(Text::NameUsed, shown)),
        None => Ok(Some(name)),
    }
}

fn fields(form: &Form, profile: Option<&str>) -> Result<LaunchRequest, UriError> {
    LaunchRequest::from_fields(
        profile,
        LaunchAuth::SessionCredentials.as_str(),
        None,
        Some(&form.address),
        optional(&form.portal),
    )
}

pub fn check(form: &Form, listing: &Result<Known, String>) -> Verdict {
    if form.address.is_empty() {
        return Verdict::Incomplete;
    }
    let known = match listing {
        Ok(known) => known,
        Err(_) => return Verdict::Invalid(None, UNLISTED.into()),
    };
    let host = match fields(form, None) {
        Ok(request) => request
            .gateway
            .map_or_else(String::new, |gateway| gateway.host()),
        Err(error) => return field_error(error),
    };
    let display = match display_name(form, known) {
        Ok(display) => display,
        Err(message) => return Verdict::Invalid(Some(Input::Name), message),
    };
    let taken: Vec<&str> = known
        .gateways
        .iter()
        .map(|gateway| gateway.name.as_str())
        .chain(
            known
                .invalid
                .iter()
                .filter_map(|entry| entry.name.as_ref().map(|name| name.as_str())),
        )
        .collect();
    let typed = display.as_ref().map_or("", DisplayName::as_str);
    let name = naming::identifier(typed, &host, &taken);
    let request = match fields(form, Some(name.as_str())) {
        Ok(request) => request,
        Err(error) => return field_error(error),
    };
    match link::resolve(&request, known, &mut Decision::Defer, 0) {
        Ok(Resolution::Confirm(confirmation)) => match display {
            None => Verdict::Incomplete,
            Some(display) => match damaged_name(known, &display) {
                Some(held) => {
                    Verdict::Invalid(Some(Input::Name), Message::with(Text::NameUsed, held))
                }
                None => Verdict::Ready(Ready {
                    local: confirmation.gateway.is_local(),
                    gateway: LinkedGateway {
                        name: confirmation.profile,
                        display_name: Some(display),
                        address: confirmation.gateway,
                        portal_url: confirmation.portal,
                        approved_at: None,
                        route: form.route,
                    },
                }),
            },
        },
        Ok(Resolution::Launch(launch)) => Verdict::Invalid(
            Some(Input::Address),
            Message::with(Text::AlreadySetUp, shown(known, &launch.profile)),
        ),
        Err(error) => link_error(known, error),
    }
}

fn damaged_name<'a>(known: &'a Known, display: &DisplayName) -> Option<&'a str> {
    let wanted = display.as_str().to_lowercase();
    known
        .invalid
        .iter()
        .filter_map(|entry| entry.name.as_ref())
        .map(GatewayName::as_str)
        .find(|name| name.to_lowercase() == wanted)
}

pub fn disclosure(route: Route) -> String {
    if current() == Language::Chinese {
        return chinese_disclosure(route);
    }
    match route {
        Route::Mixed => {
            format!("{IDENTITY} and the traffic routed to it. {MIXED_WARNING} Add it {TRUST}")
        }
        Route::Gateway => format!("{IDENTITY} and {ALL_TRAFFIC} Add it {TRUST}"),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Hint,
    Error,
    Warning,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    pub input: Input,
    pub label: &'static str,
    pub value: &'a str,
    pub note: String,
    pub tone: Tone,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sheet<'a> {
    pub entries: [Entry<'a>; 3],
    pub focus: Input,
    pub route: Route,
    pub notice: Option<(String, Tone)>,
    pub ready: bool,
}

pub fn sheet<'a>(form: &'a Form, listing: &Result<Known, String>) -> Sheet<'a> {
    let verdict = check(form, listing);
    let entry = |input, label: Text, hint: Text| {
        let (note, tone) = match &verdict {
            Verdict::Invalid(Some(wrong), message) if *wrong == input => {
                (message.text(), Tone::Error)
            }
            Verdict::Ready(ready) if ready.local && input == Input::Address => {
                (LOCAL_ADDRESS.to_owned(), Tone::Warning)
            }
            _ => (tr(hint).to_owned(), Tone::Hint),
        };
        Entry {
            input,
            label: tr(label),
            value: form.value(input),
            note,
            tone,
        }
    };
    let entries = [
        entry(Input::Address, Text::GatewayAddress, ADDRESS_HINT),
        entry(Input::Name, Text::Name, NAME_HINT),
        entry(Input::Portal, Text::PortalPage, PORTAL_HINT),
    ];
    let general = match &verdict {
        Verdict::Invalid(None, message) => Some(message),
        _ => None,
    };
    let notice = form
        .failure
        .as_ref()
        .or(general)
        .map(|message| (message.text(), Tone::Error))
        .or_else(|| Some((disclosure(form.route), Tone::Warning)));
    Sheet {
        entries,
        focus: form.focus,
        route: form.route,
        notice,
        ready: form.failure.is_none() && matches!(verdict, Verdict::Ready(_)),
    }
}

fn accepted(form: &mut Form, listing: &Result<Known, String>) -> Option<Ready> {
    match check(form, listing) {
        Verdict::Ready(ready) => Some(ready),
        Verdict::Invalid(_, message) => {
            form.failure = Some(message);
            None
        }
        Verdict::Incomplete => None,
    }
}

pub fn rehearse(form: &mut Form, listing: &Result<Known, String>) -> bool {
    accepted(form, listing).is_some()
}

pub fn commit(
    form: &mut Form,
    listing: &Result<Known, String>,
    dir: Option<PathBuf>,
    now: u64,
) -> bool {
    let Some(ready) = accepted(form, listing) else {
        return false;
    };
    let Some(dir) = dir else {
        form.failure = Some(NO_FOLDER.into());
        return false;
    };
    let gateway = LinkedGateway {
        approved_at: Some(now),
        ..ready.gateway
    };
    match LinkedStore::new(dir).add(&gateway) {
        Ok(_) => true,
        Err(error) => {
            let message = match error {
                StoreError::Exists(_) | StoreError::AddressTaken(_) => TAKEN,
                StoreError::Full => FULL,
                _ => NOT_SAVED,
            };
            form.failure = Some(message.into());
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};

    use gateinto::config::ConfigFile;
    use gateinto::link::store::InvalidEntry;
    use gateinto::link::{KnownGateway, Source};

    use super::*;
    use crate::gateways::catalog;

    const PROFILE: &str = "g-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd";

    fn known(gateways: Vec<KnownGateway>) -> Result<Known, String> {
        Ok(Known {
            gateways,
            ..Known::default()
        })
    }

    fn office() -> KnownGateway {
        KnownGateway {
            name: "office".parse().unwrap(),
            display_name: None,
            host: Some("proxy.example.com".to_owned()),
            port: Some(443),
            portal_url: None,
            route: gateinto::proxy::Route::Gateway,
            source: Source::Config,
        }
    }

    fn form(address: &str, name: &str, portal: &str) -> Form {
        let mut form = Form::default();
        form.type_text(address);
        form.select(Input::Name);
        form.type_text(name);
        form.select(Input::Portal);
        form.type_text(portal);
        form
    }

    fn error(form: &Form, listing: &Result<Known, String>) -> (Option<Input>, String) {
        match check(form, listing) {
            Verdict::Invalid(input, message) => (input, message.text()),
            other => panic!("expected an error, got {other:?}"),
        }
    }

    fn ready(form: &Form, listing: &Result<Known, String>) -> Ready {
        match check(form, listing) {
            Verdict::Ready(ready) => ready,
            other => panic!("expected a ready gateway, got {other:?}"),
        }
    }

    fn scratch() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("gateinto-gui-add-{}-{n}", std::process::id()))
    }

    #[test]
    fn typing_fills_the_focused_field_and_drops_spaces_and_control_characters() {
        let mut form = Form::default();
        assert_eq!(form.focus, Input::Address);
        form.type_text(" proxy.example.com\r\n");
        form.select(Input::Portal);
        form.type_text("https://portal\t.example/");
        assert_eq!(form.value(Input::Address), "proxy.example.com");
        assert_eq!(form.value(Input::Name), "");
        assert_eq!(form.value(Input::Portal), "https://portal.example/");
        form.erase();
        assert_eq!(form.value(Input::Portal), "https://portal.example");
    }

    #[test]
    fn the_name_keeps_spaces_and_chinese_but_drops_control_characters() {
        let mut form = Form::default();
        form.select(Input::Name);
        form.type_text("台北 Office\r\n");
        assert_eq!(form.value(Input::Name), "台北 Office");
    }

    #[test]
    fn each_field_stops_at_its_limit() {
        for (input, limit) in [(Input::Address, 259), (Input::Portal, PortalUrl::MAX_LEN)] {
            let mut form = Form::default();
            form.select(input);
            form.type_text(&"a".repeat(limit + 10));
            assert_eq!(form.value(input).len(), limit);
        }
        let mut form = Form::default();
        form.select(Input::Name);
        form.type_text(&"台".repeat(DisplayName::MAX_LEN + 6));
        assert_eq!(
            form.value(Input::Name).chars().count(),
            DisplayName::MAX_LEN
        );
    }

    #[test]
    fn the_name_limit_counts_the_name_as_it_will_be_saved() {
        let spaced = format!("{}a", "ab  ".repeat(21));
        let mut form = Form::default();
        form.select(Input::Name);
        form.type_text(&format!("  {spaced}"));
        assert_eq!(form.value(Input::Name), format!("  {spaced}"));
        let saved = display_name(&form, &Known::default()).unwrap().unwrap();
        assert_eq!(saved.as_str().chars().count(), DisplayName::MAX_LEN);
        form.type_text("  x");
        assert_eq!(form.value(Input::Name), format!("  {spaced}  "));
        let mut blank = Form::default();
        blank.select(Input::Name);
        blank.type_text(&" ".repeat(1000));
        assert_eq!(blank.value(Input::Name).len(), 4 * DisplayName::MAX_LEN);
    }

    #[test]
    fn a_limit_never_splits_a_character() {
        let mut form = Form::default();
        form.type_text("ab");
        form.type_text(&"\u{e9}".repeat(200));
        assert_eq!(form.value(Input::Address).len(), MAX_ADDRESS - 1);
        form.type_text("c");
        assert_eq!(form.value(Input::Address).len(), MAX_ADDRESS);
        form.type_text("d");
        assert_eq!(form.value(Input::Address).len(), MAX_ADDRESS);
    }

    #[test]
    fn the_selected_field_is_reported() {
        let mut form = Form::default();
        assert_eq!(form.selected(), Input::Address);
        form.select(Input::Portal);
        assert_eq!(form.selected(), Input::Portal);
    }

    #[test]
    fn an_empty_address_is_incomplete() {
        assert_eq!(
            check(&form("", "lab", ""), &known(vec![])),
            Verdict::Incomplete
        );
    }

    #[test]
    fn an_empty_or_blank_name_is_incomplete() {
        for name in ["", "   "] {
            assert_eq!(
                check(&form("proxy.example.net", name, ""), &known(vec![])),
                Verdict::Incomplete
            );
        }
    }

    #[test]
    fn a_display_name_is_kept_and_an_identifier_is_generated_from_it() {
        let ready = ready(
            &form("proxy.example.net", "  Head   Office ", ""),
            &known(vec![]),
        );
        assert_eq!(
            ready.gateway.display_name.as_ref().map(DisplayName::as_str),
            Some("Head Office")
        );
        assert_eq!(ready.gateway.name.as_str(), "head-office");
        assert_eq!(ready.gateway.address.to_string(), "proxy.example.net:443");
        assert_eq!(ready.gateway.portal_url, None);
        assert_eq!(ready.gateway.approved_at, None);
        assert!(!ready.local);
    }

    #[test]
    fn a_chinese_display_name_gets_an_identifier_from_the_host() {
        let ready = ready(&form("proxy.example.net", "台北辦公室", ""), &known(vec![]));
        assert_eq!(
            ready.gateway.display_name.as_ref().map(DisplayName::as_str),
            Some("台北辦公室")
        );
        assert_eq!(ready.gateway.name.as_str(), "proxy-example-net");
    }

    #[test]
    fn a_taken_identifier_gets_the_next_free_number() {
        let mut lab = office();
        lab.name = "lab".parse().unwrap();
        lab.display_name = Some("Old lab".parse().unwrap());
        let listing = Ok(Known {
            gateways: vec![lab],
            invalid: vec![InvalidEntry {
                file: PathBuf::from("/secret/lab-2.gateway"),
                name: Some("LAB-2".parse().unwrap()),
                addresses: Vec::new(),
                reason: "bad".to_owned(),
            }],
            ..Known::default()
        });
        let ready = ready(&form("proxy.example.net", "Lab", ""), &listing);
        assert_eq!(ready.gateway.name.as_str(), "lab-3");
    }

    #[test]
    fn a_named_gateway_keeps_its_port_and_portal() {
        let form = form(
            "proxy.example.net:8443",
            "lab",
            "https://portal.example.net/",
        );
        let ready = ready(&form, &known(vec![office()]));
        assert_eq!(ready.gateway.name.as_str(), "lab");
        assert_eq!(ready.gateway.address.to_string(), "proxy.example.net:8443");
        assert_eq!(
            ready.gateway.portal_url.map(|url| url.to_string()),
            Some("https://portal.example.net/".to_owned())
        );
    }

    #[test]
    fn a_local_address_is_flagged() {
        assert!(ready(&form("192.168.1.10", "lab", ""), &known(vec![])).local);
    }

    #[test]
    fn each_field_reports_its_own_error() {
        let none = known(vec![]);
        assert_eq!(
            error(&form("proxy..example", "", ""), &none).0,
            Some(Input::Address)
        );
        assert_eq!(
            error(&form("con.example", "", ""), &none).0,
            Some(Input::Address)
        );
        assert_eq!(
            error(&form("proxy.example.net", "a\u{202E}b", ""), &none),
            (
                Some(Input::Name),
                "Use at most 64 characters, without control or text direction characters."
                    .to_owned()
            )
        );
        assert_eq!(
            error(
                &form("proxy.example.net", "lab", "http://portal.example/"),
                &none
            )
            .0,
            Some(Input::Portal)
        );
    }

    #[test]
    fn an_address_already_set_up_names_its_gateway() {
        let listing = known(vec![office()]);
        assert_eq!(
            error(&form("PROXY.example.com", "", ""), &listing),
            (
                Some(Input::Address),
                "Already set up as \"office\".".to_owned()
            )
        );
        assert_eq!(
            error(&form("proxy.example.com:443", "lab", ""), &listing),
            (
                Some(Input::Address),
                "Already set up as \"office\".".to_owned()
            )
        );
    }

    #[test]
    fn an_address_set_up_without_a_name_is_named_by_its_host() {
        let mut linked = office();
        linked.name = PROFILE.parse().unwrap();
        linked.source = Source::Linked;
        assert_eq!(
            error(&form("proxy.example.com", "lab", ""), &known(vec![linked])),
            (
                Some(Input::Address),
                "Already set up as \"proxy.example.com\".".to_owned()
            )
        );
    }

    #[test]
    fn a_name_shown_for_another_gateway_is_refused_ignoring_letter_case() {
        let listing = known(vec![office()]);
        for typed in ["office", "Office"] {
            assert_eq!(
                error(&form("proxy.example.net", typed, ""), &listing),
                (
                    Some(Input::Name),
                    "\"office\" is already used by another gateway.".to_owned()
                )
            );
        }
        let mut head = office();
        head.display_name = Some("Head Office".parse().unwrap());
        assert_eq!(
            error(
                &form("proxy.example.net", "head  office", ""),
                &known(vec![head])
            ),
            (
                Some(Input::Name),
                "\"Head Office\" is already used by another gateway.".to_owned()
            )
        );
    }

    #[test]
    fn an_unreadable_listing_blocks_adding() {
        let failed: Result<Known, String> = Err("config.toml: password = hunter2".to_owned());
        assert_eq!(
            error(&form("proxy.example.net", "", ""), &failed),
            (None, "The gateway list cannot be read.".to_owned())
        );
    }

    #[test]
    fn an_address_shared_by_several_gateways_names_one_of_them() {
        let mut home = office();
        home.name = "home".parse().unwrap();
        let listing = known(vec![office(), home]);
        assert_eq!(
            error(&form("proxy.example.com", "Lab", ""), &listing).0,
            Some(Input::Address)
        );
    }

    #[test]
    fn a_name_held_by_a_damaged_entry_elsewhere_is_refused() {
        let listing = Ok(Known {
            invalid: vec![InvalidEntry {
                file: PathBuf::from("/secret/lab.gateway"),
                name: Some("lab".parse().unwrap()),
                addresses: vec!["proxy.example.org:443".parse().unwrap()],
                reason: "bad".to_owned(),
            }],
            ..Known::default()
        });
        assert_eq!(
            error(&form("proxy.example.net", "LAB", ""), &listing),
            (
                Some(Input::Name),
                "\"lab\" is already used by another gateway.".to_owned()
            )
        );
    }

    #[test]
    fn a_damaged_entry_is_reported_without_link_wording() {
        let listing = Ok(Known {
            invalid: vec![InvalidEntry {
                file: PathBuf::from("/secret/lab.gateway"),
                name: Some("lab".parse().unwrap()),
                addresses: vec!["proxy.example.net:443".parse().unwrap()],
                reason: "bad".to_owned(),
            }],
            ..Known::default()
        });
        assert_eq!(
            error(&form("proxy.example.net", "lab", ""), &listing),
            (None, DAMAGED.english().to_owned())
        );
    }

    #[test]
    fn an_address_too_long_to_store_is_refused_on_the_address() {
        let host = format!("{}example", "a.".repeat(123));
        assert_eq!(
            error(&form(&host, "lab", ""), &known(vec![])),
            (Some(Input::Address), UNSTORABLE.english().to_owned())
        );
    }

    #[test]
    fn unexpected_errors_get_fixed_wording() {
        let unavailable = Ok(Known {
            unavailable: Some("denied".to_owned()),
            ..Known::default()
        });
        assert_eq!(
            error(&form("proxy.example.net", "lab", ""), &unavailable),
            (None, UNAVAILABLE.english().to_owned())
        );
        assert_eq!(
            field_error(UriError::TooLong),
            Verdict::Invalid(None, UNUSABLE.into())
        );
        for text in [DAMAGED, UNSTORABLE, UNAVAILABLE, UNUSABLE] {
            for word in ["link", "launch", "URI", "profile"] {
                assert!(!text.english().contains(word), "{text}");
            }
        }
    }

    fn notes(sheet: &Sheet) -> Vec<(String, Tone)> {
        sheet
            .entries
            .iter()
            .map(|entry| (entry.note.clone(), entry.tone))
            .collect()
    }

    fn hint(text: Text) -> (String, Tone) {
        (text.english().to_owned(), Tone::Hint)
    }

    #[test]
    fn an_empty_sheet_labels_every_field_with_its_hint_and_cannot_add() {
        let form = Form::default();
        let sheet = sheet(&form, &known(vec![]));
        let labels: Vec<_> = sheet
            .entries
            .iter()
            .map(|e| (e.input, e.label, e.value))
            .collect();
        assert_eq!(
            labels,
            [
                (Input::Address, "Gateway address", ""),
                (Input::Name, "Name", ""),
                (Input::Portal, "Portal page", ""),
            ]
        );
        assert_eq!(
            notes(&sheet),
            [hint(ADDRESS_HINT), hint(NAME_HINT), hint(PORTAL_HINT)]
        );
        assert_eq!(sheet.route, Route::Mixed);
        assert_eq!(
            sheet.notice,
            Some((disclosure(Route::Mixed), Tone::Warning))
        );
        assert!(!sheet.ready);
    }

    #[test]
    fn the_route_starts_as_mixed_and_choosing_all_changes_the_disclosure() {
        let mut form = form("proxy.example.net", "Lab", "");
        assert_eq!(ready(&form, &known(vec![])).gateway.route, Route::Mixed);
        form.failure = Some(FULL.into());
        form.choose(Route::Gateway);
        assert_eq!(form.failure, None);
        assert_eq!(ready(&form, &known(vec![])).gateway.route, Route::Gateway);
        let sheet = sheet(&form, &known(vec![]));
        assert_eq!(sheet.route, Route::Gateway);
        assert_eq!(
            sheet.notice,
            Some((disclosure(Route::Gateway), Tone::Warning))
        );
    }

    #[test]
    fn a_field_error_replaces_only_that_hint() {
        let form = form("proxy.example.net", "a\u{202E}b", "");
        let sheet = sheet(&form, &known(vec![]));
        assert_eq!(sheet.entries[1].value, "a\u{202E}b");
        assert_eq!(sheet.entries[1].tone, Tone::Error);
        assert_eq!(sheet.entries[0].note, ADDRESS_HINT.english());
        assert_eq!(sheet.entries[2].note, PORTAL_HINT.english());
        assert!(!sheet.ready);
    }

    #[test]
    fn a_ready_local_gateway_warns_under_its_address() {
        let form = form("127.0.0.1:3128", "Local", "");
        let sheet = sheet(&form, &known(vec![]));
        assert!(sheet.ready);
        assert_eq!(sheet.entries[0].clone().note, gateinto::link::LOCAL_ADDRESS);
        assert_eq!(sheet.entries[0].tone, Tone::Warning);
    }

    #[test]
    fn every_add_shows_the_identity_and_trust_disclosure() {
        let form = form("proxy.example.net", "Lab", "");
        let sheet = sheet(&form, &known(vec![]));
        assert!(sheet.ready);
        assert_eq!(
            sheet.notice,
            Some((disclosure(Route::Mixed), Tone::Warning))
        );
    }

    #[test]
    fn a_general_error_or_failure_takes_the_notice_and_blocks_adding() {
        let mut form = form("proxy.example.net", "", "");
        let failed: Result<Known, String> = Err("bad".to_owned());
        let sheet_failed = sheet(&form, &failed);
        assert!(!sheet_failed.ready);
        assert_eq!(
            sheet_failed.notice,
            Some(("The gateway list cannot be read.".to_owned(), Tone::Error))
        );
        form.failure = Some(FULL.into());
        let sheet = sheet(&form, &known(vec![]));
        assert!(!sheet.ready);
        assert_eq!(sheet.notice, Some((FULL.english().to_owned(), Tone::Error)));
    }

    #[test]
    fn the_form_and_its_disclosure_speak_chinese() {
        let mut stuck = lab();
        assert!(!commit(&mut stuck, &known(vec![]), None, 1));
        let _zh = crate::i18n::speaking(crate::i18n::Language::Chinese);
        let blank = Form::default();
        let sheet = sheet(&blank, &known(vec![]));
        let labels: Vec<_> = sheet
            .entries
            .iter()
            .map(|e| (e.label, e.note.as_str()))
            .collect();
        assert_eq!(
            labels,
            [
                ("閘道位址", "主機名稱或 IP 位址。預設連接埠為 443。"),
                ("名稱", "顯示在應用程式中，可包含空格。"),
                ("入口網頁", "選填。瀏覽器最先開啟的 https:// 網頁。"),
            ]
        );
        assert_eq!(
            sheet.notice,
            Some((disclosure(Route::Mixed), Tone::Warning))
        );
        assert_eq!(
            disclosure(Route::Mixed),
            "閘道將能看到此裝置的身分（其用戶端憑證，若已安裝）以及轉送給它的流量。\
             警告：在混合模式下，網站可能會被直接連線，而不經過閘道，\
             這會向它們暴露您的本機 DNS 查詢與 IP 位址，並繞過閘道的政策。\
             只有在您信任營運此閘道的組織時才新增。"
        );
        assert_eq!(
            disclosure(Route::Gateway),
            "閘道將能看到此裝置的身分（其用戶端憑證，若已安裝）以及\
             隔離瀏覽器的所有流量：每個連線都會經過閘道。\
             只有在您信任營運此閘道的組織時才新增。"
        );
        assert_eq!(
            error(
                &form("proxy.example.net", "office", ""),
                &known(vec![office()])
            ),
            (Some(Input::Name), "「office」已被其他閘道使用。".to_owned())
        );
        assert_eq!(
            super::sheet(&stuck, &known(vec![])).notice,
            Some(("這台裝置沒有存放新增閘道的資料夾。".to_owned(), Tone::Error))
        );
    }

    #[test]
    fn the_disclosure_reuses_the_link_identity_route_and_trust_wording() {
        assert_eq!(
            disclosure(Route::Mixed),
            "The gateway will see this device's identity (its client certificate, if one is \
             installed) and the traffic routed to it. Warning: in mixed mode, sites may be \
             reached directly instead of through the gateway, which exposes your local DNS \
             lookups and your IP address to them and bypasses the gateway's policy. Add it \
             only if you trust the organisation that runs this gateway."
        );
        assert_eq!(
            disclosure(Route::Gateway),
            "The gateway will see this device's identity (its client certificate, if one is \
             installed) and all traffic of the isolated browser: every connection goes \
             through the gateway. Add it only if you trust the organisation that runs this \
             gateway."
        );
        for route in [Route::Mixed, Route::Gateway] {
            assert!(disclosure(route).starts_with(gateinto::link::IDENTITY));
            assert!(disclosure(route).ends_with(gateinto::link::TRUST));
        }
        assert!(disclosure(Route::Mixed).contains(gateinto::link::MIXED_WARNING));
        assert!(disclosure(Route::Gateway).contains(gateinto::link::ALL_TRAFFIC));
    }

    #[test]
    fn editing_clears_a_failure() {
        let mut form = form("proxy.example.net", "lab", "");
        form.failure = Some(FULL.into());
        form.erase();
        assert_eq!(form.failure, None);
        form.failure = Some(FULL.into());
        form.type_text("x");
        assert_eq!(form.failure, None);
    }

    #[test]
    fn committing_stores_the_gateway_with_its_approval_time_and_chosen_route() {
        let dir = scratch();
        let mut first = form(
            "proxy.example.net:8443",
            "lab",
            "https://portal.example.net/",
        );
        let listing = Ok(catalog(&ConfigFile::default(), Some(dir.clone())));
        assert!(commit(&mut first, &listing, Some(dir.clone()), 42));
        let stored = LinkedStore::new(dir.clone()).load().unwrap();
        assert_eq!(stored.gateways.len(), 1);
        assert_eq!(stored.gateways[0].name.as_str(), "lab");
        assert_eq!(
            stored.gateways[0]
                .display_name
                .as_ref()
                .map(DisplayName::as_str),
            Some("lab")
        );
        assert_eq!(
            stored.gateways[0].address.to_string(),
            "proxy.example.net:8443"
        );
        assert_eq!(stored.gateways[0].approved_at, Some(42));
        assert_eq!(stored.gateways[0].route, Route::Mixed);
        let again = Ok(catalog(&ConfigFile::default(), Some(dir.clone())));
        let mut twin = form("proxy.example.org", "lab", "");
        assert!(!commit(&mut twin, &again, Some(dir.clone()), 43));
        assert_eq!(
            twin.failure.as_ref().map(Message::text).as_deref(),
            Some("\"lab\" is already used by another gateway.")
        );
        assert_eq!(
            LinkedStore::new(dir.clone()).load().unwrap().gateways.len(),
            1
        );
        let mut all = form("proxy.example.org", "Edge", "");
        all.choose(Route::Gateway);
        assert!(commit(&mut all, &again, Some(dir.clone()), 44));
        let stored = LinkedStore::new(dir.clone()).load().unwrap();
        let edge = stored.gateways.iter().find(|g| g.name.as_str() == "edge");
        assert_eq!(edge.map(|g| g.route), Some(Route::Gateway));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rehearsing_checks_the_form_like_committing_but_stores_nothing() {
        let listing = Ok(Known::default());
        let mut ready = lab();
        assert!(rehearse(&mut ready, &listing));
        assert_eq!(ready.failure, None);
        let mut incomplete = form("", "", "");
        assert!(!rehearse(&mut incomplete, &listing));
        assert_eq!(incomplete.failure, None);
        let mut wrong = form("proxy.example.net", "lab", "http://portal.example.net/");
        assert!(!rehearse(&mut wrong, &listing));
        assert!(wrong.failure.is_some());
    }

    fn lab() -> Form {
        form("proxy.example.net", "lab", "")
    }

    fn other(name: &str, host: &str) -> LinkedGateway {
        LinkedGateway {
            name: name.parse().unwrap(),
            display_name: None,
            address: host.parse().unwrap(),
            portal_url: None,
            approved_at: None,
            route: gateinto::proxy::Route::Gateway,
        }
    }

    fn stored(dir: &Path) -> Vec<String> {
        let loaded = LinkedStore::new(dir.to_owned()).load().unwrap();
        assert!(loaded.invalid.is_empty());
        loaded
            .gateways
            .iter()
            .map(|gateway| format!("{} {}", gateway.name, gateway.address))
            .collect()
    }

    #[test]
    fn committing_after_the_store_became_unusable_writes_nothing() {
        let dir = scratch();
        let listing = Ok(catalog(&ConfigFile::default(), Some(dir.clone())));
        std::fs::write(&dir, b"").unwrap();
        let mut form = lab();
        assert!(!commit(&mut form, &listing, Some(dir.clone()), 1));
        assert_eq!(form.failure, Some(NOT_SAVED.into()));
        assert!(std::fs::read(&dir).unwrap().is_empty());
        std::fs::remove_file(dir).unwrap();
    }

    #[test]
    fn committing_a_name_another_writer_just_added_writes_nothing() {
        let dir = scratch();
        let listing = Ok(catalog(&ConfigFile::default(), Some(dir.clone())));
        let store = LinkedStore::new(dir.clone());
        store.add(&other("lab", "proxy.example.org")).unwrap();
        let mut form = lab();
        assert!(!commit(&mut form, &listing, Some(dir.clone()), 1));
        assert_eq!(form.failure, Some(TAKEN.into()));
        assert_eq!(stored(&dir), ["lab proxy.example.org:443"]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn committing_an_address_another_writer_just_added_writes_nothing() {
        let dir = scratch();
        let listing = Ok(catalog(&ConfigFile::default(), Some(dir.clone())));
        let store = LinkedStore::new(dir.clone());
        store.add(&other("edge", "proxy.example.net")).unwrap();
        let mut form = lab();
        assert!(!commit(&mut form, &listing, Some(dir.clone()), 1));
        assert_eq!(form.failure, Some(TAKEN.into()));
        assert_eq!(stored(&dir), ["edge proxy.example.net:443"]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn store_failures_get_fixed_wording() {
        for text in [TAKEN, FULL, NOT_SAVED] {
            for word in ["link", "gateinto"] {
                assert!(!text.english().contains(word), "{text}");
            }
        }
    }

    #[test]
    fn committing_without_a_store_folder_writes_nothing() {
        let mut form = form("proxy.example.net", "lab", "");
        assert!(!commit(&mut form, &known(vec![]), None, 1));
        assert_eq!(form.failure, Some(NO_FOLDER.into()));
    }

    #[test]
    fn committing_an_incomplete_form_writes_nothing() {
        let dir = scratch();
        let mut form = Form::default();
        assert!(!commit(&mut form, &known(vec![]), Some(dir.clone()), 1));
        assert!(!dir.exists());
    }

    #[test]
    fn keys_edit_the_form_and_ask_for_submit_or_paste() {
        let mut typed = Form::default();
        assert_eq!(keyed(&mut typed, Some(Input::Address), 'a'), Keyed::Changed);
        assert_eq!(keyed(&mut typed, Some(Input::Address), 'b'), Keyed::Changed);
        assert_eq!(
            keyed(&mut typed, Some(Input::Address), '\u{8}'),
            Keyed::Changed
        );
        assert_eq!(typed.value(Input::Address), "a");
        assert_eq!(keyed(&mut typed, Some(Input::Address), '\r'), Keyed::Submit);
        assert_eq!(
            keyed(&mut typed, Some(Input::Address), '\u{16}'),
            Keyed::Paste
        );
        for ignored in ['\t', '\u{1b}', '\u{7f}', '\n'] {
            assert_eq!(
                keyed(&mut typed, Some(Input::Address), ignored),
                Keyed::Ignored
            );
        }
        assert_eq!(typed.value(Input::Address), "a");
    }

    #[test]
    fn keys_edit_only_the_field_that_holds_the_focus() {
        let mut form = Form::default();
        assert_eq!(keyed(&mut form, Some(Input::Name), 'n'), Keyed::Changed);
        assert_eq!(form.selected(), Input::Name);
        assert_eq!(keyed(&mut form, None, 'x'), Keyed::Ignored);
        assert_eq!(keyed(&mut form, None, '\u{8}'), Keyed::Ignored);
        assert_eq!(keyed(&mut form, None, '\u{16}'), Keyed::Ignored);
        assert_eq!(keyed(&mut form, None, '\r'), Keyed::Submit);
        assert_eq!(form.value(Input::Name), "n");
        assert_eq!(form.value(Input::Address), "");
    }

    #[test]
    fn utf16_units_join_into_characters() {
        let mut units = Units::default();
        assert_eq!(units.push(0x61), Some('a'));
        assert_eq!(units.push(0xD83D), None);
        assert_eq!(units.push(0xDE00), Some('\u{1F600}'));
        assert_eq!(units.push(0xDE00), None);
        assert_eq!(units.push(0xD83D), None);
        assert_eq!(units.push(0x62), Some('b'));
    }
}
