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
        return Ok(windows::message_box(&confirmation.message()));
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

#[cfg(windows)]
mod windows {
    use std::ptr::null_mut;

    use windows_sys::Win32::System::StationsAndDesktops::{
        GetProcessWindowStation, GetUserObjectInformationW, UOI_FLAGS, USEROBJECTFLAGS,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        IDYES, MB_DEFBUTTON2, MB_ICONWARNING, MB_SETFOREGROUND, MB_TOPMOST, MB_YESNO,
        MESSAGEBOX_STYLE, MessageBoxW, WSF_VISIBLE,
    };

    pub const STYLE: MESSAGEBOX_STYLE =
        MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_SETFOREGROUND | MB_TOPMOST;

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
        let wide = |text: &str| text.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
        let (text, title) = (wide(text), wide("Gateinto"));
        // SAFETY: both buffers are NUL-terminated UTF-16 strings that outlive the call.
        unsafe { MessageBoxW(null_mut(), text.as_ptr(), title.as_ptr(), STYLE) == IDYES }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn the_dialog_defaults_to_no_and_stays_on_top() {
            assert_eq!(STYLE & MB_DEFBUTTON2, MB_DEFBUTTON2);
            assert_eq!(STYLE & MB_YESNO, MB_YESNO);
            assert_eq!(STYLE & MB_ICONWARNING, MB_ICONWARNING);
            assert_eq!(STYLE & MB_TOPMOST, MB_TOPMOST);
            assert_eq!(STYLE & MB_SETFOREGROUND, MB_SETFOREGROUND);
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
    fn without_a_desktop_or_terminal_nothing_is_asked() {
        let error = Unavailable.to_string();
        assert!(error.contains("no desktop or terminal"), "{error}");
        assert!(error.contains("nothing was stored"), "{error}");
    }
}
