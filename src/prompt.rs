use std::io::{self, BufRead, Write};
use std::net::SocketAddr;

use zeroize::Zeroizing;

use crate::config::GatewayName;
use crate::link::Ask;
use crate::proxy::{SessionCredentials, Verification};
use crate::sessions::SessionId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unavailable;

impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "cannot ask to confirm the link: no desktop or terminal to ask on; nothing was stored \
             and no session was opened",
        )
    }
}

impl std::error::Error for Unavailable {}

fn choices(ask: &Ask) -> (&'static str, &'static str) {
    match ask {
        Ask::Add(_) => (
            "Choose OK to allow this gateway, or Cancel to refuse.",
            "Type yes to add this gateway: ",
        ),
        Ask::Loosen(_) => (
            "Choose OK to allow the mixed route for this session, or Cancel to refuse.",
            "Type yes to use the mixed route for this session: ",
        ),
    }
}

pub fn dialog_text(ask: &Ask) -> String {
    format!("{}\n\n{}", ask.message(), choices(ask).0)
}

pub fn ask_on(ask: &Ask, input: &mut impl BufRead, output: &mut impl Write) -> io::Result<bool> {
    write!(output, "{}\n\n{}", ask.message(), choices(ask).1)?;
    output.flush()?;
    let mut line = String::new();
    input.read_line(&mut line)?;
    Ok(line.trim() == "yes")
}

pub fn ask(ask: &Ask) -> Result<bool, Box<dyn std::error::Error>> {
    use std::io::IsTerminal;

    #[cfg(windows)]
    if windows::interactive_desktop() {
        return Ok(windows::message_box(&dialog_text(ask)));
    }
    if io::stdin().is_terminal() && io::stderr().is_terminal() {
        return Ok(ask_on(ask, &mut io::stdin().lock(), &mut io::stderr())?);
    }
    Err(Unavailable.into())
}

pub fn launch_error_text(error: &str) -> String {
    format!("Gateinto could not open the link.\n\n{error}")
}

pub fn show_launch_error(error: &str) {
    #[cfg(feature = "test-hooks")]
    if let Some(path) = std::env::var_os("GATEINTO_TEST_OPEN_ERROR_FILE") {
        if let Ok(mut output) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = writeln!(output, "{}", launch_error_text(error));
        }
        return;
    }
    #[cfg(windows)]
    windows::show_launch_error(&launch_error_text(error));
    #[cfg(not(windows))]
    let _ = error;
}

pub struct CredentialsNotice<'a> {
    pub session: Option<SessionId>,
    pub listen: SocketAddr,
    pub credentials: &'a SessionCredentials,
}

impl CredentialsNotice<'_> {
    fn title(&self) -> String {
        match self.session {
            Some(id) => format!("Gateinto session {id}"),
            None => "Gateinto local proxy".to_owned(),
        }
    }
}

pub fn credentials_text(notice: &CredentialsNotice) -> String {
    let listen = notice.listen;
    let mut text = format!(
        "{}\n\nProxy: {listen}\nUsername: {}\nPassword: {}\n\nEnter these only in the proxy \
         sign-in prompt for {listen}. Never enter them in a website's sign-in page or dialog. \
         Type them exactly, including the hyphens. They stop working when the session closes.",
        notice.title(),
        notice.credentials.username(),
        notice.credentials.password(),
    );
    if let Some(id) = notice.session {
        text.push_str(&format!(
            "\n\nTo see them again, run gateinto session credentials {id}."
        ));
    }
    text
}

pub fn unshown_text(notice: &CredentialsNotice) -> String {
    let how = match notice.session {
        Some(id) => format!("run `gateinto session credentials {id}` in a terminal"),
        None => "start the session from a terminal".to_owned(),
    };
    format!(
        "the credentials for {} on {} were not shown: no desktop or terminal to show them on; \
         to see them, {how}",
        notice.title(),
        notice.listen,
    )
}

pub fn show_credentials(notice: &CredentialsNotice) -> bool {
    use std::io::IsTerminal;

    let text = credentials_text(notice);
    #[cfg(feature = "test-hooks")]
    if let Some(path) = std::env::var_os("GATEINTO_TEST_CREDENTIALS_FILE") {
        return std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .and_then(|mut output| writeln!(output, "{text}"))
            .is_ok();
    }
    #[cfg(windows)]
    let desktop = windows::interactive_desktop().then_some(windows::show_credentials);
    #[cfg(not(windows))]
    let desktop = None::<fn(&str) -> bool>;
    show_on(&text, desktop, |text| {
        let mut stderr = io::stderr();
        stderr.is_terminal() && writeln!(stderr, "{text}").is_ok()
    })
}

const VERIFICATION_TEXT_OVERHEAD: usize = 256;
const VERIFICATION_TARGET_OVERHEAD: usize = 16;

pub fn verification_text(gateway: &GatewayName, verification: &Verification) -> Zeroizing<String> {
    let gateway = gateway.to_string();
    let targets: usize = verification
        .targets
        .iter()
        .map(|target| target.len() + VERIFICATION_TARGET_OVERHEAD)
        .sum();
    let mut text = Zeroizing::new(String::with_capacity(
        VERIFICATION_TEXT_OVERHEAD
            + gateway.len()
            + targets
            + verification.origin.len()
            + verification.auth_uri.len()
            + verification.user_code.len(),
    ));
    text.push_str("verification required for gateway ");
    push_printable(&mut text, &gateway);
    for target in &verification.targets {
        text.push_str("\n  target: ");
        push_printable(&mut text, target);
    }
    if verification.more_targets > 0 {
        text.push_str(&format!("\n  more targets: {}", verification.more_targets));
    }
    text.push_str("\n  verify at: ");
    push_printable(&mut text, &verification.origin);
    text.push_str("\n  link: ");
    push_printable(&mut text, &verification.auth_uri);
    text.push_str("\n  pairing code: ");
    push_printable(&mut text, &verification.user_code);
    text.push_str(&format!(
        "\n  expires in: {} s\nComplete verification, then retry the connection.",
        verification.expires_in
    ));
    text
}

fn push_printable(text: &mut String, value: &str) {
    text.extend(value.bytes().map(|byte| {
        if (0x20..=0x7e).contains(&byte) {
            char::from(byte)
        } else {
            '?'
        }
    }));
}

pub fn unshown_verification_text(gateway: &GatewayName) -> String {
    format!(
        "verification required for gateway {gateway}; not shown because standard error is not a \
         terminal"
    )
}

pub fn show_verification(gateway: &GatewayName, verification: &Verification) -> io::Result<bool> {
    use std::io::IsTerminal;

    let text = verification_text(gateway, verification);
    if let Some(shown) = show_in_test_file(&text) {
        return shown.map(|()| true);
    }
    let mut stderr = io::stderr();
    let terminal = stderr.is_terminal();
    show_on_terminal(&text, terminal, &mut stderr)
}

pub fn announce_verification(gateway: &GatewayName, verification: &Verification) {
    use std::io::IsTerminal;

    let mut stderr = io::stderr();
    let terminal = stderr.is_terminal();
    announce_on(gateway, verification, terminal, &mut stderr);
}

fn announce_on(
    gateway: &GatewayName,
    verification: &Verification,
    terminal: bool,
    output: &mut impl Write,
) {
    let text = verification_text(gateway, verification);
    let shown = match show_in_test_file(&text) {
        Some(shown) => shown.is_ok(),
        None => matches!(show_on_terminal(&text, terminal, output), Ok(true)),
    };
    if !shown {
        let _ = writeln!(output, "{}", unshown_verification_text(gateway));
    }
}

#[cfg(feature = "test-hooks")]
fn show_in_test_file(text: &str) -> Option<io::Result<()>> {
    let path = std::env::var_os("GATEINTO_TEST_VERIFICATION_FILE")?;
    Some(
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .and_then(|mut output| writeln!(output, "{text}")),
    )
}

#[cfg(not(feature = "test-hooks"))]
fn show_in_test_file(_text: &str) -> Option<io::Result<()>> {
    None
}

fn show_on_terminal(text: &str, terminal: bool, output: &mut impl Write) -> io::Result<bool> {
    if terminal {
        writeln!(output, "{text}")?;
    }
    Ok(terminal)
}

fn show_on(
    text: &str,
    desktop: Option<impl FnOnce(&str) -> bool>,
    terminal: impl FnOnce(&str) -> bool,
) -> bool {
    desktop.is_some_and(|show| show(text)) || terminal(text)
}

#[cfg(any(windows, test))]
fn launch_error_dialog_needed(interactive: bool, console_processes: u32, redirected: bool) -> bool {
    interactive && console_processes <= 1 && !redirected
}

#[cfg(windows)]
mod windows {
    use std::ptr::null_mut;

    use windows_sys::Win32::Storage::FileSystem::{
        FILE_TYPE_CHAR, FILE_TYPE_DISK, FILE_TYPE_PIPE, GetFileType,
    };
    use windows_sys::Win32::System::Console::{
        GetConsoleProcessList, GetStdHandle, STD_ERROR_HANDLE,
    };
    use windows_sys::Win32::System::StationsAndDesktops::{
        GetProcessWindowStation, GetUserObjectInformationW, UOI_FLAGS, USEROBJECTFLAGS,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        IDOK, MB_DEFBUTTON2, MB_ICONERROR, MB_ICONINFORMATION, MB_ICONWARNING, MB_OK, MB_OKCANCEL,
        MB_SETFOREGROUND, MB_TOPMOST, MESSAGEBOX_RESULT, MESSAGEBOX_STYLE, MessageBoxW,
        WSF_VISIBLE,
    };

    // OK and Cancel have no access keys and Cancel has the focus, so no single keystroke
    // approves; moving the focus to OK first still does.
    pub const STYLE: MESSAGEBOX_STYLE =
        MB_OKCANCEL | MB_ICONWARNING | MB_DEFBUTTON2 | MB_SETFOREGROUND | MB_TOPMOST;

    pub const ERROR_STYLE: MESSAGEBOX_STYLE = MB_OK | MB_ICONERROR | MB_SETFOREGROUND | MB_TOPMOST;

    pub const CREDENTIALS_STYLE: MESSAGEBOX_STYLE =
        MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND | MB_TOPMOST;

    pub fn show_credentials(text: &str) -> bool {
        shown(show(text, CREDENTIALS_STYLE))
    }

    fn shown(result: MESSAGEBOX_RESULT) -> bool {
        result != 0
    }

    pub fn show_launch_error(text: &str) {
        use std::io::IsTerminal;

        let mut processes = [0; 2];
        // SAFETY: processes is a writable buffer of the passed length.
        let console_processes =
            unsafe { GetConsoleProcessList(processes.as_mut_ptr(), processes.len() as u32) };
        // SAFETY: GetStdHandle returns a process-owned handle; GetFileType also accepts invalid handles.
        let stderr_type = unsafe { GetFileType(GetStdHandle(STD_ERROR_HANDLE)) };
        let redirected = matches!(stderr_type, FILE_TYPE_DISK | FILE_TYPE_PIPE)
            || (stderr_type == FILE_TYPE_CHAR && !std::io::stderr().is_terminal());
        if super::launch_error_dialog_needed(interactive_desktop(), console_processes, redirected) {
            show(text, ERROR_STYLE);
        }
    }

    pub fn approved(result: MESSAGEBOX_RESULT) -> bool {
        result == IDOK
    }

    pub fn interactive_desktop() -> bool {
        // SAFETY: the window station handle belongs to the process and is not closed here.
        let station = unsafe { GetProcessWindowStation() };
        if station.is_null() {
            return false;
        }
        let mut flags = USEROBJECTFLAGS::default();
        let mut needed = 0;
        // SAFETY: flags is a USEROBJECTFLAGS of the size passed; needed receives a u32.
        let queried = unsafe {
            GetUserObjectInformationW(
                station,
                UOI_FLAGS,
                (&raw mut flags).cast(),
                size_of::<USEROBJECTFLAGS>() as u32,
                &mut needed,
            )
        };
        queried != 0 && flags.dwFlags & WSF_VISIBLE as u32 != 0
    }

    pub fn message_box(text: &str) -> bool {
        approved(show(text, STYLE))
    }

    fn show(text: &str, style: MESSAGEBOX_STYLE) -> MESSAGEBOX_RESULT {
        let wide = |text: &str| text.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
        let (text, title) = (wide(text), wide("Gateinto"));
        // SAFETY: both buffers are NUL-terminated UTF-16 strings that outlive the call.
        unsafe { MessageBoxW(null_mut(), text.as_ptr(), title.as_ptr(), style) }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            IDABORT, IDCANCEL, IDNO, IDYES, MB_TYPEMASK,
        };

        #[test]
        fn the_dialog_has_no_access_keys_and_defaults_to_cancel() {
            assert_eq!(
                STYLE,
                MB_OKCANCEL | MB_ICONWARNING | MB_DEFBUTTON2 | MB_SETFOREGROUND | MB_TOPMOST
            );
            assert_eq!(STYLE & MB_TYPEMASK, MB_OKCANCEL);
        }

        #[test]
        fn error_notifications_have_one_ok_button_and_an_error_icon() {
            assert_eq!(ERROR_STYLE & MB_TYPEMASK, MB_OK);
            assert_ne!(ERROR_STYLE & MB_ICONERROR, 0);
        }

        #[test]
        fn the_credentials_box_has_one_ok_button_and_an_information_icon() {
            assert_eq!(CREDENTIALS_STYLE & MB_TYPEMASK, MB_OK);
            assert_ne!(CREDENTIALS_STYLE & MB_ICONINFORMATION, 0);
            assert_ne!(CREDENTIALS_STYLE & MB_TOPMOST, 0);
        }

        #[test]
        fn a_message_box_that_failed_to_appear_shows_nothing() {
            assert!(!shown(0));
            assert!(shown(IDOK));
        }

        #[test]
        fn only_ok_approves() {
            assert!(approved(IDOK));
            for result in [IDCANCEL, IDYES, IDNO, IDABORT, 0] {
                assert!(!approved(result), "{result}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn confirmation() -> Ask {
        Ask::Add(crate::link::Confirmation {
            route: crate::proxy::Route::Gateway,
            profile: "newco".parse().unwrap(),
            gateway: "proxy.newco.example".parse().unwrap(),
            portal: Some("https://portal.newco.example/home".parse().unwrap()),
        })
    }

    #[test]
    fn launch_errors_are_visible_only_without_a_persistent_console_or_redirected_stderr() {
        for count in [0, 1] {
            assert!(launch_error_dialog_needed(true, count, false));
            assert!(!launch_error_dialog_needed(false, count, false));
            assert!(!launch_error_dialog_needed(true, count, true));
        }
        for count in [2, 3, u32::MAX] {
            assert!(!launch_error_dialog_needed(true, count, false));
        }
    }

    #[test]
    fn launch_error_dialog_keeps_the_full_error() {
        let error = "error: browser executable C:\\Program Files\\Browser\\browser.exe not found";
        let text = launch_error_text(error);
        assert_eq!(
            text,
            format!("Gateinto could not open the link.\n\n{error}")
        );
    }

    #[test]
    fn the_terminal_prompt_needs_yes() {
        for (input, expected) in [
            ("yes\n", true),
            (" yes \r\n", true),
            ("yes", true),
            ("YES\n", false),
            ("y\n", false),
            ("yes please\n", false),
            ("no\n", false),
            ("\n", false),
            ("", false),
        ] {
            let mut output = Vec::new();
            let answer = ask_on(&confirmation(), &mut input.as_bytes(), &mut output).unwrap();
            assert_eq!(answer, expected, "{input:?}");
            let output = String::from_utf8(output).unwrap();
            assert!(output.starts_with(&confirmation().message()), "{output}");
            assert!(
                output.ends_with("Type yes to add this gateway: "),
                "{output}"
            );
        }
    }

    fn loosening() -> Ask {
        Ask::Loosen(crate::link::Loosening {
            profile: "corp".parse().unwrap(),
            gateway: Some("proxy.corp.example".parse().unwrap()),
        })
    }

    #[test]
    fn the_terminal_prompt_for_a_switch_to_mixed_names_the_session_and_needs_yes() {
        for (input, expected) in [("yes\n", true), ("y\n", false), ("\n", false)] {
            let mut output = Vec::new();
            let answer = ask_on(&loosening(), &mut input.as_bytes(), &mut output).unwrap();
            assert_eq!(answer, expected, "{input:?}");
            let output = String::from_utf8(output).unwrap();
            assert!(output.starts_with(&loosening().message()), "{output}");
            assert!(
                output.ends_with("Type yes to use the mixed route for this session: "),
                "{output}"
            );
            assert!(output.contains("from All to Mixed"), "{output}");
            assert!(output.contains(crate::link::MIXED_WARNING), "{output}");
        }
    }

    #[test]
    fn the_dialog_text_for_a_switch_to_mixed_says_that_ok_allows_it_for_this_session() {
        let text = dialog_text(&loosening());
        assert!(text.starts_with(&loosening().message()), "{text}");
        assert!(
            text.ends_with(
                "\n\nChoose OK to allow the mixed route for this session, or Cancel to refuse."
            ),
            "{text}"
        );
    }

    #[test]
    fn the_dialog_text_says_that_ok_allows_and_cancel_refuses() {
        let text = dialog_text(&confirmation());
        assert!(text.starts_with(&confirmation().message()), "{text}");
        assert!(
            text.ends_with("\n\nChoose OK to allow this gateway, or Cancel to refuse."),
            "{text}"
        );
        assert!(!text.contains("Yes") && !text.contains('?'), "{text}");
    }

    fn issued() -> SessionCredentials {
        SessionCredentials::parse("gateinto", "jkmn-pqrs-tuvw").unwrap()
    }

    fn notice(
        credentials: &SessionCredentials,
        session: Option<SessionId>,
    ) -> CredentialsNotice<'_> {
        CredentialsNotice {
            session,
            listen: "127.0.0.1:49152".parse().unwrap(),
            credentials,
        }
    }

    #[test]
    fn the_credentials_prompt_names_the_proxy_and_warns_against_other_dialogs() {
        let credentials = issued();
        let text = credentials_text(&notice(&credentials, Some("7".parse().unwrap())));
        for expected in [
            "Gateinto session 7",
            "Proxy: 127.0.0.1:49152",
            "Username: gateinto",
            "Password: jkmn-pqrs-tuvw",
            "Enter these only in the proxy sign-in prompt for 127.0.0.1:49152.",
            "Never enter them in a website's sign-in page or dialog",
            "including the hyphens",
            "stop working when the session closes",
            "gateinto session credentials 7",
        ] {
            assert!(text.contains(expected), "{expected:?} in {text}");
        }
    }

    #[test]
    fn credentials_of_a_session_outside_the_agent_cannot_be_shown_again() {
        let credentials = issued();
        let text = credentials_text(&notice(&credentials, None));
        assert!(text.contains("Gateinto local proxy"), "{text}");
        assert!(text.contains("Username: gateinto"), "{text}");
        assert!(!text.contains("gateinto session credentials"), "{text}");
    }

    #[test]
    fn the_note_for_unshown_credentials_names_the_way_to_see_them_without_them() {
        let credentials = issued();
        let text = unshown_text(&notice(&credentials, Some("7".parse().unwrap())));
        assert!(text.contains("not shown"), "{text}");
        assert!(text.contains("no desktop or terminal"), "{text}");
        assert!(
            text.contains("run `gateinto session credentials 7` in a terminal"),
            "{text}"
        );
        let local = unshown_text(&notice(&credentials, None));
        assert!(
            local.contains("start the session from a terminal"),
            "{local}"
        );
        for text in [text, local] {
            assert!(!text.contains("jkmn-pqrs-tuvw"), "{text}");
        }
    }

    #[test]
    fn a_message_box_that_fails_falls_back_to_the_terminal() {
        let mut terminal = Vec::new();
        assert!(show_on("text", Some(|_: &str| false), |text: &str| {
            terminal.push(text.to_owned());
            true
        }));
        assert_eq!(terminal, ["text"]);
        assert!(!show_on("text", Some(|_: &str| false), |_: &str| false));
        assert!(show_on("text", Some(|_: &str| true), |_: &str| -> bool {
            panic!("shown twice")
        }));
        assert!(show_on("text", None::<fn(&str) -> bool>, |_: &str| true));
        assert!(!show_on("text", None::<fn(&str) -> bool>, |_: &str| false));
    }

    fn verification(targets: &[&str], more_targets: u64) -> Verification {
        Verification {
            serial: 3,
            origin: Zeroizing::new("https://verify.example.test".to_owned()),
            auth_uri: Zeroizing::new(
                "https://verify.example.test/device?x=1&cert_sha256=ab".to_owned(),
            ),
            user_code: Zeroizing::new("WDJB-MJHT".to_owned()),
            expires_in: 300,
            targets: targets.iter().map(|target| (*target).to_owned()).collect(),
            more_targets,
            suppressed: 2,
        }
    }

    fn office() -> GatewayName {
        "office".parse().unwrap()
    }

    #[test]
    fn the_verification_names_gateway_target_origin_link_code_and_expiry() {
        let text = verification_text(&office(), &verification(&["example.com:443"], 0));
        assert_eq!(
            *text,
            "verification required for gateway office\n\
             \x20 target: example.com:443\n\
             \x20 verify at: https://verify.example.test\n\
             \x20 link: https://verify.example.test/device?x=1&cert_sha256=ab\n\
             \x20 pairing code: WDJB-MJHT\n\
             \x20 expires in: 300 s\n\
             Complete verification, then retry the connection."
        );
    }

    #[test]
    fn the_verification_lists_every_target_and_counts_the_rest() {
        let text = verification_text(&office(), &verification(&["a.test:443", "b.test:8443"], 4));
        assert!(
            text.contains(
                "\n  target: a.test:443\n  target: b.test:8443\n  more targets: 4\n  verify at: "
            ),
            "{}",
            *text
        );
    }

    #[test]
    fn the_verification_replaces_every_byte_a_terminal_could_interpret() {
        let mut hostile = verification(&["\x1b[2Jé.test:443"], 0);
        hostile.user_code = Zeroizing::new("WDJB\x07MJHT\x7f".to_owned());
        hostile.origin = Zeroizing::new("https://v\r\n.test\t".to_owned());
        let text = verification_text(&office(), &hostile);
        assert!(text.contains("  target: ?[2J??.test:443\n"), "{}", *text);
        assert!(text.contains("  pairing code: WDJB?MJHT?\n"), "{}", *text);
        assert!(
            text.contains("  verify at: https://v??.test?\n"),
            "{}",
            *text
        );
        let lines: Vec<&str> = text.split('\n').collect();
        assert_eq!(lines.len(), 7, "{}", *text);
        assert!(
            lines
                .iter()
                .all(|line| line.bytes().all(|byte| (0x20..=0x7e).contains(&byte))),
            "{}",
            *text
        );
    }

    #[test]
    fn an_unshown_verification_names_only_the_gateway() {
        assert_eq!(
            unshown_verification_text(&office()),
            "verification required for gateway office; not shown because standard error is not \
             a terminal"
        );
    }

    #[test]
    fn an_announcement_off_a_terminal_is_only_the_fixed_line() {
        let pending = verification(&["example.com:443"], 0);
        let mut output = Vec::new();
        announce_on(&office(), &pending, false, &mut output);
        assert_eq!(
            String::from_utf8(output).unwrap(),
            format!("{}\n", unshown_verification_text(&office()))
        );
        let mut output = Vec::new();
        announce_on(&office(), &pending, true, &mut output);
        assert_eq!(
            String::from_utf8(output).unwrap(),
            format!("{}\n", *verification_text(&office(), &pending))
        );
    }

    #[test]
    fn a_verification_reaches_only_a_terminal() {
        let mut output = Vec::new();
        assert!(!show_on_terminal("secret", false, &mut output).unwrap());
        assert!(output.is_empty());
        assert!(show_on_terminal("secret", true, &mut output).unwrap());
        assert_eq!(output, b"secret\n");
    }

    #[test]
    fn without_a_desktop_or_terminal_nothing_is_asked() {
        let error = Unavailable.to_string();
        assert!(error.contains("no desktop or terminal"), "{error}");
        assert!(error.contains("nothing was stored"), "{error}");
        assert!(error.contains("no session was opened"), "{error}");
    }
}
