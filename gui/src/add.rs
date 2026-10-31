use std::path::PathBuf;

use gateinto::config::{GatewayName, PortalUrl};
use gateinto::link::store::{LinkedStore, StoreError};
use gateinto::link::{
    self, Decision, IDENTITY, Known, LOCAL_ADDRESS, LinkError, LinkedGateway, Resolution, TRUST,
};
use gateinto::uri::{LaunchAuth, LaunchRequest, UriError};

use crate::gateways;
use crate::i18n::{Text, fill, tr};

pub const TITLE: Text = Text::AddGateway;
pub const ADDRESS_HINT: Text = Text::AddressHint;
pub const NAME_HINT: Text = Text::NameHint;
pub const PORTAL_HINT: Text = Text::PortalHint;
pub const NO_FOLDER: Text = Text::NoFolder;
const AMBIGUOUS: Text = Text::Ambiguous;
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
        UriError::InvalidValue("profile") => (Input::Name, Text::NameRule),
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
        LinkError::GatewayMismatch(name) | LinkError::ProfileCollision(name) => {
            (Some(Input::Name), Message::with(Text::NameUsed, name))
        }
        LinkError::LookAlikeProfile { existing, .. } => {
            (Some(Input::Name), Message::with(Text::TooClose, existing))
        }
        LinkError::AmbiguousGateway(_) => (Some(Input::Name), AMBIGUOUS.into()),
        LinkError::Damaged { .. } => (None, DAMAGED.into()),
        LinkError::Unstorable { .. } => (Some(Input::Address), UNSTORABLE.into()),
        LinkError::StoreUnavailable(_) => (None, UNAVAILABLE.into()),
        _ => (None, UNUSABLE.into()),
    };
    Verdict::Invalid(input, message)
}

pub fn check(form: &Form, listing: &Result<Known, String>) -> Verdict {
    if form.address.is_empty() {
        return Verdict::Incomplete;
    }
    let known = match listing {
        Ok(known) => known,
        Err(_) => return Verdict::Invalid(None, UNLISTED.into()),
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
            Message::with(Text::AlreadySetUp, shown(known, &launch.profile)),
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
        .or_else(|| Some((disclosure(), Tone::Warning)));
    Sheet {
        entries,
        focus: form.focus,
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
            (Some(Input::Name), AMBIGUOUS.english().to_owned())
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
        for text in [AMBIGUOUS, DAMAGED, UNSTORABLE, UNAVAILABLE, UNUSABLE] {
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
        assert_eq!(sheet.notice, Some((disclosure(), Tone::Warning)));
        assert!(!sheet.ready);
    }

    #[test]
    fn a_field_error_replaces_only_that_hint() {
        let form = form("proxy.example.net", "a.b", "");
        let sheet = sheet(&form, &known(vec![]));
        assert_eq!(sheet.entries[1].value, "a.b");
        assert_eq!(sheet.entries[1].tone, Tone::Error);
        assert_eq!(sheet.entries[0].note, ADDRESS_HINT.english());
        assert_eq!(sheet.entries[2].note, PORTAL_HINT.english());
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
        form.failure = Some(FULL.into());
        let sheet = sheet(&form, &known(vec![]));
        assert!(!sheet.ready);
        assert_eq!(sheet.notice, Some((FULL.english().to_owned(), Tone::Error)));
    }

    #[test]
    fn the_form_speaks_chinese_but_the_disclosure_stays_as_the_agent_words_it() {
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
                ("名稱", "顯示在清單中。留空則使用主機名稱。"),
                ("入口網頁", "選填。瀏覽器最先開啟的 https:// 網頁。"),
            ]
        );
        assert_eq!(sheet.notice, Some((disclosure(), Tone::Warning)));
        assert!(disclosure().starts_with(gateinto::link::IDENTITY));
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
        form.failure = Some(FULL.into());
        form.erase();
        assert_eq!(form.failure, None);
        form.failure = Some(FULL.into());
        form.type_text("x");
        assert_eq!(form.failure, None);
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
            twin.failure.as_ref().map(Message::text).as_deref(),
            Some("\"lab\" is already used by another gateway.")
        );
        assert_eq!(
            LinkedStore::new(dir.clone()).load().unwrap().gateways.len(),
            1
        );
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
