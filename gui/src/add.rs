use std::path::PathBuf;

use gateinto::config::{GatewayName, PortalUrl};
use gateinto::link::store::{LinkedStore, StoreError};
use gateinto::link::{
    self, Decision, IDENTITY, Known, LOCAL_ADDRESS, LinkError, LinkedGateway, Resolution, TRUST,
};
use gateinto::uri::{LaunchAuth, LaunchRequest, UriError};

use crate::gateways;

pub const TITLE: &str = "Add gateway";
pub const ADDRESS_HINT: &str = "Host name or IP address. Port 443 is the default.";
pub const NAME_HINT: &str = "Shown in lists. Leave empty to use the host name.";
pub const PORTAL_HINT: &str = "Optional. An https:// page the browser opens first.";
pub const NO_FOLDER: &str = "This device has no folder for added gateways.";
const AMBIGUOUS: &str = "Several gateways use this address. Enter the name of the one you mean.";
const DAMAGED: &str = "A damaged gateway entry on this device uses this name or address. \
     Fix or remove it, then try again.";
const UNSTORABLE: &str = "This address is too long to store on this device.";
const UNAVAILABLE: &str =
    "The gateways added on this device cannot be read, so no gateway can be added now.";
const TAKEN: &str =
    "Another gateway with this name or address was just added. Nothing was changed.";
const FULL: &str = "This device holds as many added gateways as it can. Remove one first.";
const NOT_SAVED: &str = "The gateway could not be saved on this device.";
const UNLISTED: &str = "The gateway list cannot be read.";
const UNUSABLE: &str = "These values cannot be used for a gateway.";
// The longest DNS name, a colon and a five digit port.
const MAX_ADDRESS: usize = 253 + 1 + 5;

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
            Self::Address => MAX_ADDRESS,
            Self::Name => GatewayName::MAX_LEN,
            Self::Portal => PortalUrl::MAX_LEN,
        }
    }
}

#[derive(Debug, Default)]
pub struct Form {
    address: String,
    name: String,
    portal: String,
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

    pub fn select(&mut self, input: Input) {
        self.focus = input;
    }

    pub fn type_text(&mut self, text: &str) {
        let limit = self.focus.limit();
        let field = self.field();
        for c in text
            .chars()
            .filter(|c| !c.is_control() && !c.is_whitespace())
        {
            if field.len() + c.len_utf8() > limit {
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
        _ => return Verdict::Invalid(None, UNUSABLE.to_owned()),
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
        LinkError::AmbiguousGateway(_) => (Some(Input::Name), AMBIGUOUS.to_owned()),
        LinkError::Damaged { .. } => (None, DAMAGED.to_owned()),
        LinkError::Unstorable { .. } => (Some(Input::Address), UNSTORABLE.to_owned()),
        LinkError::StoreUnavailable(_) => (None, UNAVAILABLE.to_owned()),
        _ => (None, UNUSABLE.to_owned()),
    };
    Verdict::Invalid(input, message)
}

pub fn check(form: &Form, listing: &Result<Known, String>) -> Verdict {
    if form.address.is_empty() {
        return Verdict::Incomplete;
    }
    let known = match listing {
        Ok(known) => known,
        Err(_) => return Verdict::Invalid(None, UNLISTED.to_owned()),
    };
    let request = match LaunchRequest::from_fields(
        optional(&form.name),
        LaunchAuth::SessionCredentials.as_str(),
        None,
        Some(&form.address),
        optional(&form.portal),
    ) {
        Ok(request) => request,
        Err(error) => return field_error(error),
    };
    match link::resolve(&request, known, &mut Decision::Defer, 0) {
        Ok(Resolution::Confirm(confirmation)) => Verdict::Ready(Ready {
            local: confirmation.gateway.is_local(),
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

pub fn disclosure() -> String {
    format!("{IDENTITY} and the browser traffic routed to it. Add it {TRUST}")
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
        .or_else(|| Some((disclosure(), Tone::Warning)));
    Sheet {
        entries,
        focus: form.focus,
        notice,
        ready: form.failure.is_none() && matches!(verdict, Verdict::Ready(_)),
    }
}

pub fn commit(
    form: &mut Form,
    listing: &Result<Known, String>,
    dir: Option<PathBuf>,
    now: u64,
) -> bool {
    let ready = match check(form, listing) {
        Verdict::Ready(ready) => ready,
        Verdict::Invalid(_, message) => {
            form.failure = Some(message);
            return false;
        }
        Verdict::Incomplete => return false,
    };
    let Some(dir) = dir else {
        form.failure = Some(NO_FOLDER.to_owned());
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
            form.failure = Some(message.to_owned());
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
    fn each_field_stops_at_its_byte_limit() {
        for (input, limit) in [
            (Input::Address, 259),
            (Input::Name, GatewayName::MAX_LEN),
            (Input::Portal, PortalUrl::MAX_LEN),
        ] {
            let mut form = Form::default();
            form.select(input);
            form.type_text(&"a".repeat(limit + 10));
            assert_eq!(form.value(input).len(), limit);
        }
    }

    #[test]
    fn a_limit_never_splits_a_character() {
        let mut form = Form::default();
        form.select(Input::Name);
        form.type_text("a");
        form.type_text(&"\u{e9}".repeat(40));
        assert_eq!(form.value(Input::Name).len(), GatewayName::MAX_LEN - 1);
        form.type_text("b");
        assert_eq!(form.value(Input::Name).len(), GatewayName::MAX_LEN);
        form.type_text("c");
        assert_eq!(form.value(Input::Name).len(), GatewayName::MAX_LEN);
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
    fn an_empty_name_proposes_the_generated_name_shown_by_host() {
        let ready = ready(&form("proxy.example.net", "", ""), &known(vec![]));
        assert!(ready.gateway.name.as_str().starts_with("g-"));
        assert_eq!(ready.gateway.address.to_string(), "proxy.example.net:443");
        assert_eq!(ready.gateway.portal_url, None);
        assert_eq!(ready.gateway.approved_at, None);
        assert!(!ready.local);
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
        let failed: Result<Known, String> = Err("config.toml: password = hunter2".to_owned());
        assert_eq!(
            error(&form("proxy.example.net", "", ""), &failed),
            (None, "The gateway list cannot be read.".to_owned())
        );
    }

    #[test]
    fn an_address_shared_by_several_gateways_asks_for_a_name() {
        let mut home = office();
        home.name = "home".parse().unwrap();
        let listing = known(vec![office(), home]);
        assert_eq!(
            error(&form("proxy.example.com", "", ""), &listing),
            (Some(Input::Name), AMBIGUOUS.to_owned())
        );
    }

    #[test]
    fn a_damaged_entry_is_reported_without_link_wording() {
        let listing = Ok(Known {
            invalid: vec![InvalidEntry {
                file: PathBuf::from("/secret/lab.gateway"),
                name: Some("lab".parse().unwrap()),
                addresses: Vec::new(),
                reason: "bad".to_owned(),
            }],
            ..Known::default()
        });
        assert_eq!(
            error(&form("proxy.example.net", "lab", ""), &listing),
            (None, DAMAGED.to_owned())
        );
    }

    #[test]
    fn an_address_too_long_to_store_is_refused_on_the_address() {
        let host = format!("{}example", "a.".repeat(123));
        assert_eq!(
            error(&form(&host, "lab", ""), &known(vec![])),
            (Some(Input::Address), UNSTORABLE.to_owned())
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
            (None, UNAVAILABLE.to_owned())
        );
        assert_eq!(
            field_error(UriError::TooLong),
            Verdict::Invalid(None, UNUSABLE.to_owned())
        );
        for text in [AMBIGUOUS, DAMAGED, UNSTORABLE, UNAVAILABLE, UNUSABLE] {
            for word in ["link", "launch", "URI", "profile"] {
                assert!(!text.contains(word), "{text}");
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
        assert_eq!(sheet.notice, Some((disclosure(), Tone::Warning)));
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
    fn every_add_shows_the_identity_and_trust_disclosure() {
        let form = form("proxy.example.net", "", "");
        let sheet = sheet(&form, &known(vec![]));
        assert!(sheet.ready);
        assert_eq!(sheet.notice, Some((disclosure(), Tone::Warning)));
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
        form.failure = Some("The gateway was not added: full".to_owned());
        let sheet = sheet(&form, &known(vec![]));
        assert!(!sheet.ready);
        assert_eq!(
            sheet.notice,
            Some(("The gateway was not added: full".to_owned(), Tone::Error))
        );
    }

    #[test]
    fn the_disclosure_reuses_the_link_identity_and_trust_wording() {
        assert_eq!(
            disclosure(),
            "The gateway will see this device's identity (its client certificate, if one is \
             installed) and the browser traffic routed to it. Add it only if you trust the \
             organisation that runs this gateway."
        );
        assert!(disclosure().starts_with(gateinto::link::IDENTITY));
        assert!(disclosure().ends_with(gateinto::link::TRUST));
    }

    #[test]
    fn editing_clears_a_failure() {
        let mut form = form("proxy.example.net", "lab", "");
        form.failure = Some("x".to_owned());
        form.erase();
        assert_eq!(form.failure.as_deref(), None);
        form.failure = Some("x".to_owned());
        form.type_text("x");
        assert_eq!(form.failure.as_deref(), None);
    }

    #[test]
    fn committing_stores_the_gateway_with_its_approval_time() {
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
            stored.gateways[0].address.to_string(),
            "proxy.example.net:8443"
        );
        assert_eq!(stored.gateways[0].approved_at, Some(42));
        let again = Ok(catalog(&ConfigFile::default(), Some(dir.clone())));
        let mut twin = form("proxy.example.org", "lab", "");
        assert!(!commit(&mut twin, &again, Some(dir.clone()), 43));
        assert_eq!(
            twin.failure.as_deref(),
            Some("\"lab\" is already used by another gateway.")
        );
        assert_eq!(
            LinkedStore::new(dir.clone()).load().unwrap().gateways.len(),
            1
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn lab() -> Form {
        form("proxy.example.net", "lab", "")
    }

    fn other(name: &str, host: &str) -> LinkedGateway {
        LinkedGateway {
            name: name.parse().unwrap(),
            address: host.parse().unwrap(),
            portal_url: None,
            approved_at: None,
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
        assert_eq!(form.failure.as_deref(), Some(NOT_SAVED));
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
        assert_eq!(form.failure.as_deref(), Some(TAKEN));
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
        assert_eq!(form.failure.as_deref(), Some(TAKEN));
        assert_eq!(stored(&dir), ["edge proxy.example.net:443"]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn store_failures_get_fixed_wording() {
        for text in [TAKEN, FULL, NOT_SAVED] {
            for word in ["link", "gateinto"] {
                assert!(!text.contains(word), "{text}");
            }
        }
    }

    #[test]
    fn committing_without_a_store_folder_writes_nothing() {
        let mut form = form("proxy.example.net", "lab", "");
        assert!(!commit(&mut form, &known(vec![]), None, 1));
        assert_eq!(form.failure.as_deref(), Some(NO_FOLDER));
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
