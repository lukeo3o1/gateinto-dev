use std::path::PathBuf;

use gateinto::config::GatewayName;
use gateinto::link::store::LinkedStore;
use gateinto::link::{
    self, Decision, Known, LOCAL_ADDRESS, LinkError, LinkedGateway, MIXED_TRAFFIC, Resolution,
};
use gateinto::proxy::Route;
use gateinto::uri::{LaunchAuth, LaunchRequest, UriError};

use crate::gateways;

pub const TITLE: &str = "Add gateway";
pub const ADDRESS_HINT: &str = "Host name or IP address. Port 443 is the default.";
pub const NAME_HINT: &str = "Shown in lists. Leave empty to use the host name.";
pub const PORTAL_HINT: &str = "Optional. An https:// page the browser opens first.";
pub const ROUTES: [(Route, &str, &str); 2] = [
    (
        Route::Gateway,
        "Gateway",
        "Every site goes through the gateway",
    ),
    (
        Route::Mixed,
        "Mixed",
        "Sites the gateway serves go through it; others connect directly",
    ),
];
pub const NO_FOLDER: &str = "This device has no folder for added gateways.";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Input {
    #[default]
    Address,
    Name,
    Portal,
}

impl Input {
    fn limit(self) -> usize {
        match self {
            Self::Address => 261,
            Self::Name => 64,
            Self::Portal => 2048,
        }
    }
}

#[derive(Debug, Default)]
pub struct Form {
    address: String,
    name: String,
    portal: String,
    route: Route,
    focus: Input,
    failure: Option<String>,
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

    pub fn focus(&self) -> Input {
        self.focus
    }

    pub fn route(&self) -> Route {
        self.route
    }

    pub fn select(&mut self, input: Input) {
        self.focus = input;
    }

    pub fn choose(&mut self, route: Route) {
        self.failure = None;
        self.route = route;
    }

    pub fn type_text(&mut self, text: &str) {
        let limit = self.focus.limit();
        let field = self.field();
        let room = limit.saturating_sub(field.chars().count());
        field.extend(
            text.chars()
                .filter(|c| !c.is_control() && !c.is_whitespace())
                .take(room),
        );
    }

    pub fn erase(&mut self) {
        self.field().pop();
    }

    pub fn next(&mut self, back: bool) {
        self.focus = match (self.focus, back) {
            (Input::Address, false) | (Input::Portal, true) => Input::Name,
            (Input::Name, false) | (Input::Address, true) => Input::Portal,
            (Input::Portal, false) | (Input::Name, true) => Input::Address,
        };
    }

    pub fn failure(&self) -> Option<&str> {
        self.failure.as_deref()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Keyed {
    Changed,
    Submit,
    Paste,
    Ignored,
}

pub fn keyed(form: &mut Form, c: char) -> Keyed {
    match c {
        '\u{8}' => {
            form.erase();
            Keyed::Changed
        }
        '\r' => Keyed::Submit,
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
    pub route: Route,
    pub local: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Incomplete,
    Invalid(Option<Input>, String),
    Ready(Ready),
}

fn optional(text: &str) -> Option<&str> {
    Some(text).filter(|text| !text.is_empty())
}

fn field_error(error: UriError) -> Verdict {
    let (input, message) = match error {
        UriError::InvalidValue("gateway") => (
            Input::Address,
            "Enter a host name or IP address, with an optional :port.",
        ),
        UriError::ReservedGateway => (
            Input::Address,
            "The host may not start with a Windows device name such as CON or NUL.",
        ),
        UriError::InvalidValue("profile") => (
            Input::Name,
            "Use letters, digits, _ or -, not starting with -.",
        ),
        UriError::InvalidValue("portal") => (Input::Portal, "Enter an https:// address."),
        other => return Verdict::Invalid(None, other.to_string()),
    };
    Verdict::Invalid(Some(input), message.to_owned())
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
            format!("Already set up as \"{}\".", shown(known, &existing)),
        ),
        LinkError::GatewayMismatch(name) | LinkError::ProfileCollision(name) => (
            Some(Input::Name),
            format!("\"{name}\" is already used by another gateway."),
        ),
        LinkError::LookAlikeProfile { existing, .. } => (
            Some(Input::Name),
            format!("Too close to \"{existing}\": names may not differ only in letter case."),
        ),
        other => (None, other.to_string()),
    };
    Verdict::Invalid(input, message)
}

pub fn check(form: &Form, listing: &Result<Known, String>) -> Verdict {
    if form.address.is_empty() {
        return Verdict::Incomplete;
    }
    let known = match listing {
        Ok(known) => known,
        Err(error) => {
            return Verdict::Invalid(None, format!("The gateway list cannot be read: {error}"));
        }
    };
    let request = match LaunchRequest::from_fields(
        optional(&form.name),
        LaunchAuth::SessionCredentials.as_str(),
        None,
        Some(&form.address),
        optional(&form.portal),
    ) {
        Ok(request) => LaunchRequest {
            route: form.route,
            ..request
        },
        Err(error) => return field_error(error),
    };
    match link::resolve(&request, known, &mut Decision::Defer, 0) {
        Ok(Resolution::Confirm(confirmation)) => Verdict::Ready(Ready {
            local: confirmation.gateway.is_local(),
            route: confirmation.route,
            gateway: LinkedGateway {
                name: confirmation.profile,
                address: confirmation.gateway,
                portal_url: confirmation.portal,
                approved_at: None,
            },
        }),
        Ok(Resolution::Launch(launch)) => Verdict::Invalid(
            Some(Input::Address),
            format!("Already set up as \"{}\".", shown(known, &launch.profile)),
        ),
        Err(error) => link_error(known, error),
    }
}

pub fn disclosure(route: Route) -> Option<String> {
    match route {
        Route::Gateway => None,
        Route::Mixed => Some(format!(
            "The gateway will see this device's identity and {MIXED_TRAFFIC}."
        )),
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
    let entry = |input, label, hint: &str| {
        let (note, tone) = match &verdict {
            Verdict::Invalid(Some(wrong), message) if *wrong == input => {
                (message.clone(), Tone::Error)
            }
            Verdict::Ready(ready) if ready.local && input == Input::Address => {
                (LOCAL_ADDRESS.to_owned(), Tone::Warning)
            }
            _ => (hint.to_owned(), Tone::Hint),
        };
        Entry {
            input,
            label,
            value: form.value(input),
            note,
            tone,
        }
    };
    let entries = [
        entry(Input::Address, "Gateway address", ADDRESS_HINT),
        entry(Input::Name, "Name", NAME_HINT),
        entry(Input::Portal, "Portal page", PORTAL_HINT),
    ];
    let general = match &verdict {
        Verdict::Invalid(None, message) => Some(message.clone()),
        _ => None,
    };
    let notice = form
        .failure
        .clone()
        .or(general)
        .map(|message| (message, Tone::Error))
        .or_else(|| disclosure(form.route).map(|text| (text, Tone::Warning)));
    Sheet {
        entries,
        focus: form.focus,
        route: form.route,
        notice,
        ready: form.failure.is_none() && matches!(verdict, Verdict::Ready(_)),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Added {
    pub name: GatewayName,
    pub route: Route,
}

pub fn commit(
    form: &mut Form,
    listing: &Result<Known, String>,
    dir: Option<PathBuf>,
    now: u64,
) -> Option<Added> {
    let ready = match check(form, listing) {
        Verdict::Ready(ready) => ready,
        Verdict::Invalid(_, message) => {
            form.failure = Some(message);
            return None;
        }
        Verdict::Incomplete => return None,
    };
    let Some(dir) = dir else {
        form.failure = Some(NO_FOLDER.to_owned());
        return None;
    };
    let gateway = LinkedGateway {
        approved_at: Some(now),
        ..ready.gateway
    };
    match LinkedStore::new(dir).add(&gateway) {
        Ok(_) => Some(Added {
            name: gateway.name,
            route: ready.route,
        }),
        Err(error) => {
            form.failure = Some(format!("The gateway was not added: {error}"));
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use gateinto::config::ConfigFile;
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
            host: Some("proxy.example.com".to_owned()),
            port: Some(443),
            portal_url: None,
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
            Verdict::Invalid(input, message) => (input, message),
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
        assert_eq!(form.focus(), Input::Address);
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
    fn a_name_stops_at_sixty_four_characters() {
        let mut form = Form::default();
        form.select(Input::Name);
        form.type_text(&"a".repeat(80));
        assert_eq!(form.value(Input::Name).len(), 64);
    }

    #[test]
    fn tab_cycles_the_fields_both_ways() {
        let mut form = Form::default();
        form.next(false);
        assert_eq!(form.focus(), Input::Name);
        form.next(false);
        assert_eq!(form.focus(), Input::Portal);
        form.next(false);
        assert_eq!(form.focus(), Input::Address);
        form.next(true);
        assert_eq!(form.focus(), Input::Portal);
    }

    #[test]
    fn an_empty_address_is_incomplete() {
        assert_eq!(
            check(&form("", "lab", ""), &known(vec![])),
            Verdict::Incomplete
        );
    }

    #[test]
    fn an_empty_name_proposes_the_generated_name_shown_by_host() {
        let ready = ready(&form("proxy.example.net", "", ""), &known(vec![]));
        assert!(ready.gateway.name.as_str().starts_with("g-"));
        assert_eq!(ready.gateway.address.to_string(), "proxy.example.net:443");
        assert_eq!(ready.gateway.portal_url, None);
        assert_eq!(ready.gateway.approved_at, None);
        assert_eq!(ready.route, Route::Gateway);
        assert!(!ready.local);
    }

    #[test]
    fn a_named_gateway_keeps_its_port_portal_and_route() {
        let mut form = form(
            "proxy.example.net:8443",
            "lab",
            "https://portal.example.net/",
        );
        form.choose(Route::Mixed);
        let ready = ready(&form, &known(vec![office()]));
        assert_eq!(ready.gateway.name.as_str(), "lab");
        assert_eq!(ready.gateway.address.to_string(), "proxy.example.net:8443");
        assert_eq!(
            ready.gateway.portal_url.map(|url| url.to_string()),
            Some("https://portal.example.net/".to_owned())
        );
        assert_eq!(ready.route, Route::Mixed);
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
            error(&form("proxy.example.net", "a.b", ""), &none).0,
            Some(Input::Name)
        );
        assert_eq!(
            error(&form("proxy.example.net", "-lab", ""), &none).0,
            Some(Input::Name)
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
    fn a_taken_or_look_alike_name_is_refused() {
        let listing = known(vec![office()]);
        assert_eq!(
            error(&form("proxy.example.net", "office", ""), &listing),
            (
                Some(Input::Name),
                "\"office\" is already used by another gateway.".to_owned()
            )
        );
        assert_eq!(
            error(&form("proxy.example.net", "Office", ""), &listing),
            (
                Some(Input::Name),
                "Too close to \"office\": names may not differ only in letter case.".to_owned()
            )
        );
    }

    #[test]
    fn an_unreadable_listing_blocks_adding() {
        let failed: Result<Known, String> = Err("config.toml: bad".to_owned());
        assert_eq!(
            error(&form("proxy.example.net", "", ""), &failed),
            (
                None,
                "The gateway list cannot be read: config.toml: bad".to_owned()
            )
        );
        let unavailable = Ok(Known {
            unavailable: Some("denied".to_owned()),
            ..Known::default()
        });
        assert_eq!(
            error(&form("proxy.example.net", "lab", ""), &unavailable).0,
            None
        );
    }

    fn notes(sheet: &Sheet) -> Vec<(String, Tone)> {
        sheet
            .entries
            .iter()
            .map(|entry| (entry.note.clone(), entry.tone))
            .collect()
    }

    fn hint(text: &str) -> (String, Tone) {
        (text.to_owned(), Tone::Hint)
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
        assert_eq!(sheet.notice, None);
        assert_eq!(sheet.route, Route::Gateway);
        assert!(!sheet.ready);
    }

    #[test]
    fn a_field_error_replaces_only_that_hint() {
        let form = form("proxy.example.net", "a.b", "");
        let sheet = sheet(&form, &known(vec![]));
        assert_eq!(sheet.entries[1].value, "a.b");
        assert_eq!(sheet.entries[1].tone, Tone::Error);
        assert_eq!(sheet.entries[0].note, ADDRESS_HINT);
        assert_eq!(sheet.entries[2].note, PORTAL_HINT);
        assert!(!sheet.ready);
    }

    #[test]
    fn a_ready_local_gateway_warns_under_its_address() {
        let form = form("127.0.0.1:3128", "", "");
        let sheet = sheet(&form, &known(vec![]));
        assert!(sheet.ready);
        assert_eq!(sheet.entries[0].clone().note, gateinto::link::LOCAL_ADDRESS);
        assert_eq!(sheet.entries[0].tone, Tone::Warning);
    }

    #[test]
    fn mixed_shows_its_disclosure_while_add_is_possible() {
        let mut form = form("proxy.example.net", "", "");
        form.choose(Route::Mixed);
        let sheet = sheet(&form, &known(vec![]));
        assert!(sheet.ready);
        assert_eq!(sheet.route, Route::Mixed);
        assert_eq!(
            sheet.notice,
            Some((disclosure(Route::Mixed).unwrap(), Tone::Warning))
        );
    }

    #[test]
    fn a_general_error_or_failure_takes_the_notice_and_blocks_adding() {
        let mut form = form("proxy.example.net", "", "");
        form.choose(Route::Mixed);
        let failed: Result<Known, String> = Err("bad".to_owned());
        let sheet_failed = sheet(&form, &failed);
        assert!(!sheet_failed.ready);
        assert_eq!(
            sheet_failed.notice,
            Some((
                "The gateway list cannot be read: bad".to_owned(),
                Tone::Error
            ))
        );
        form.failure = Some("The gateway was not added: full".to_owned());
        let sheet = sheet(&form, &known(vec![]));
        assert!(!sheet.ready);
        assert_eq!(
            sheet.notice,
            Some(("The gateway was not added: full".to_owned(), Tone::Error))
        );
    }

    #[test]
    fn only_mixed_discloses_direct_connections() {
        assert_eq!(disclosure(Route::Gateway), None);
        let text = disclosure(Route::Mixed).unwrap();
        assert!(text.contains(MIXED_TRAFFIC));
        assert!(text.contains("exposing your IP address and local DNS lookups"));
    }

    #[test]
    fn editing_clears_a_failure() {
        let mut form = form("proxy.example.net", "lab", "");
        form.failure = Some("x".to_owned());
        form.erase();
        assert_eq!(form.failure(), None);
        form.failure = Some("x".to_owned());
        form.choose(Route::Mixed);
        assert_eq!(form.failure(), None);
    }

    #[test]
    fn committing_stores_the_gateway_with_its_approval_time() {
        let dir = scratch();
        let mut first = form(
            "proxy.example.net:8443",
            "lab",
            "https://portal.example.net/",
        );
        first.choose(Route::Mixed);
        let listing = Ok(catalog(&ConfigFile::default(), Some(dir.clone())));
        let added = commit(&mut first, &listing, Some(dir.clone()), 42);
        assert_eq!(
            added,
            Some(Added {
                name: "lab".parse().unwrap(),
                route: Route::Mixed,
            })
        );
        let stored = LinkedStore::new(dir.clone()).load().unwrap();
        assert_eq!(stored.gateways.len(), 1);
        assert_eq!(stored.gateways[0].name.as_str(), "lab");
        assert_eq!(
            stored.gateways[0].address.to_string(),
            "proxy.example.net:8443"
        );
        assert_eq!(stored.gateways[0].approved_at, Some(42));
        let again = Ok(catalog(&ConfigFile::default(), Some(dir.clone())));
        let mut twin = form("proxy.example.org", "lab", "");
        assert_eq!(commit(&mut twin, &again, Some(dir.clone()), 43), None);
        assert_eq!(
            twin.failure(),
            Some("\"lab\" is already used by another gateway.")
        );
        assert_eq!(
            LinkedStore::new(dir.clone()).load().unwrap().gateways.len(),
            1
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn committing_without_a_store_folder_writes_nothing() {
        let mut form = form("proxy.example.net", "lab", "");
        assert_eq!(commit(&mut form, &known(vec![]), None, 1), None);
        assert_eq!(form.failure(), Some(NO_FOLDER));
    }

    #[test]
    fn committing_an_incomplete_form_writes_nothing() {
        let dir = scratch();
        let mut form = Form::default();
        assert_eq!(
            commit(&mut form, &known(vec![]), Some(dir.clone()), 1),
            None
        );
        assert!(!dir.exists());
    }

    #[test]
    fn keys_edit_the_form_and_ask_for_submit_or_paste() {
        let mut typed = Form::default();
        assert_eq!(keyed(&mut typed, 'a'), Keyed::Changed);
        assert_eq!(keyed(&mut typed, 'b'), Keyed::Changed);
        assert_eq!(keyed(&mut typed, '\u{8}'), Keyed::Changed);
        assert_eq!(typed.value(Input::Address), "a");
        assert_eq!(keyed(&mut typed, '\r'), Keyed::Submit);
        assert_eq!(keyed(&mut typed, '\u{16}'), Keyed::Paste);
        for ignored in ['\t', '\u{1b}', '\u{7f}', '\n'] {
            assert_eq!(keyed(&mut typed, ignored), Keyed::Ignored);
        }
        assert_eq!(typed.value(Input::Address), "a");
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
