use std::io::{self, BufRead, Write};

use crate::link::Confirmation;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unavailable;

impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "cannot ask whether to add the gateway: no desktop or terminal to ask on; nothing \
             was stored",
        )
    }
}

impl std::error::Error for Unavailable {}

pub fn dialog_text(confirmation: &Confirmation) -> String {
    format!(
        "{}\n\nChoose OK to allow this gateway, or Cancel to refuse.",
        confirmation.message()
    )
}

pub fn ask_on(
    confirmation: &Confirmation,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> io::Result<bool> {
    write!(
        output,
        "{}\n\nType yes to add this gateway: ",
        confirmation.message()
    )?;
    output.flush()?;
    let mut line = String::new();
    input.read_line(&mut line)?;
    Ok(line.trim() == "yes")
}

pub fn ask(confirmation: &Confirmation) -> Result<bool, Box<dyn std::error::Error>> {
    use std::io::IsTerminal;

    #[cfg(windows)]
    if windows::interactive_desktop() {
        return Ok(windows::message_box(&dialog_text(confirmation)));
    }
    if io::stdin().is_terminal() && io::stderr().is_terminal() {
        return Ok(ask_on(
            confirmation,
            &mut io::stdin().lock(),
            &mut io::stderr(),
        )?);
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
        IDOK, MB_DEFBUTTON2, MB_ICONERROR, MB_ICONWARNING, MB_OK, MB_OKCANCEL, MB_SETFOREGROUND,
        MB_TOPMOST, MESSAGEBOX_RESULT, MESSAGEBOX_STYLE, MessageBoxW, WSF_VISIBLE,
    };

    // OK and Cancel have no access keys and Cancel has the focus, so no single keystroke
    // approves; moving the focus to OK first still does.
    pub const STYLE: MESSAGEBOX_STYLE =
        MB_OKCANCEL | MB_ICONWARNING | MB_DEFBUTTON2 | MB_SETFOREGROUND | MB_TOPMOST;

    pub const ERROR_STYLE: MESSAGEBOX_STYLE = MB_OK | MB_ICONERROR | MB_SETFOREGROUND | MB_TOPMOST;

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

    fn confirmation() -> Confirmation {
        Confirmation {
            profile: "newco".parse().unwrap(),
            gateway: "proxy.newco.example".parse().unwrap(),
            portal: "https://portal.newco.example/home".parse().unwrap(),
        }
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

    #[test]
    fn without_a_desktop_or_terminal_nothing_is_asked() {
        let error = Unavailable.to_string();
        assert!(error.contains("no desktop or terminal"), "{error}");
        assert!(error.contains("nothing was stored"), "{error}");
    }
}
