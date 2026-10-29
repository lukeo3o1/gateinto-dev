use std::ffi::OsString;

use gateinto::link::handoff::FLAG;
use gateinto::uri::{self, LaunchRequest};

use crate::demo;
use crate::i18n::Text;

pub const COPYDATA: usize = 0x4754_4C4B;
pub const CAP: usize = uri::MAX_LEN;
pub const REFUSED: Text = Text::OpenRefused;
pub const DEMO: Text = demo::NOT_OPENED;

pub enum Start {
    Show,
    Open(Link),
    Refused(Text),
}

pub struct Link {
    uri: String,
    launch: LaunchRequest,
}

impl Link {
    pub fn uri(&self) -> &str {
        &self.uri
    }

    pub fn launch(&self) -> &LaunchRequest {
        &self.launch
    }

    pub fn payload(&self) -> &[u8] {
        self.uri.as_bytes()
    }
}

pub fn requested<I: IntoIterator<Item = OsString>>(args: I) -> Start {
    let args: Vec<OsString> = args.into_iter().collect();
    if !args.iter().skip(1).any(|arg| arg == FLAG) {
        return Start::Show;
    }
    if demo::requested(&args) {
        return Start::Refused(DEMO);
    }
    let [_, flag, uri] = &args[..] else {
        return Start::Refused(REFUSED);
    };
    match uri.to_str().filter(|_| flag == FLAG).and_then(parse) {
        Some(link) => Start::Open(link),
        None => Start::Refused(REFUSED),
    }
}

fn parse(uri: &str) -> Option<Link> {
    let launch = uri.parse().ok().filter(|_| uri.len() <= CAP)?;
    Some(Link {
        uri: uri.to_owned(),
        launch,
    })
}

pub fn decode(id: usize, data: &[u8]) -> Option<LaunchRequest> {
    if id != COPYDATA || data.len() > CAP {
        return None;
    }
    std::str::from_utf8(data).ok()?.parse().ok()
}

pub fn same_image(a: &str, b: &str) -> bool {
    !a.is_empty() && normalized(a).eq(normalized(b))
}

fn normalized(path: &str) -> impl Iterator<Item = char> + '_ {
    let (prefix, rest) = if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
        (r"\\", rest)
    } else if let Some(rest) = path.strip_prefix(r"\\?\") {
        ("", rest)
    } else {
        ("", path)
    };
    prefix
        .chars()
        .chain(rest.chars())
        .map(|c| if c == '/' { '\\' } else { c })
        .flat_map(char::to_uppercase)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;

    const LINK: &str = "gateinto://connect?profile=newco&gateway=proxy.newco.example";

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    #[test]
    fn without_the_flag_the_window_is_just_shown() {
        assert!(matches!(requested(args(&["gui.exe"])), Start::Show));
        assert!(matches!(
            requested(args(&["gui.exe", "--demo"])),
            Start::Show
        ));
    }

    #[test]
    fn one_gateinto_link_after_the_flag_is_opened() {
        let Start::Open(link) = requested(args(&["gui.exe", "--open", LINK])) else {
            panic!("the link was not opened");
        };

        assert_eq!(link.uri(), LINK);
        assert_eq!(*link.launch(), LINK.parse().unwrap());
    }

    #[test]
    fn the_scheme_is_matched_like_the_command_does() {
        let link = LINK.replacen("gateinto", "GateInto", 1);

        assert!(matches!(
            requested(args(&["gui.exe", "--open", &link])),
            Start::Open(_)
        ));
    }

    #[test]
    fn anything_else_after_the_flag_is_refused_without_the_link() {
        for list in [
            &["gui.exe", "--open"][..],
            &["gui.exe", "--open", LINK, LINK],
            &["gui.exe", "--other", "--open", LINK],
            &["gui.exe", LINK, "--open"],
            &["gui.exe", "--open", "https://proxy.newco.example"],
            &["gui.exe", "--open", "gateinto://elsewhere?profile=newco"],
            &["gui.exe", "--open", "gateinto://connect?profile=new co"],
            &["gui.exe", "--open", ""],
        ] {
            let Start::Refused(text) = requested(args(list)) else {
                panic!("{list:?} was not refused");
            };
            assert_eq!(text, REFUSED, "{list:?}");
        }
    }

    #[test]
    fn a_link_too_long_to_forward_is_refused() {
        let long = format!(
            "{LINK}&url=https://portal.newco.example/{}",
            "a".repeat(CAP)
        );

        assert!(matches!(
            requested(args(&["gui.exe", "--open", &long])),
            Start::Refused(REFUSED)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_link_that_is_not_unicode_is_refused() {
        use std::os::unix::ffi::OsStringExt;

        let mut link = LINK.as_bytes().to_vec();
        link.push(0xFF);
        let list = vec![
            OsString::from("gui.exe"),
            OsString::from("--open"),
            OsString::from_vec(link),
        ];

        assert!(matches!(requested(list), Start::Refused(REFUSED)));
    }

    #[test]
    fn the_demo_does_not_open_links() {
        for list in [
            &["gui.exe", "--demo", "--open", LINK][..],
            &["gui.exe", "--open", LINK, "--demo"],
        ] {
            assert!(
                matches!(requested(args(list)), Start::Refused(DEMO)),
                "{list:?}"
            );
        }
    }

    #[test]
    fn a_forwarded_link_comes_back_as_the_same_request() {
        let Start::Open(link) = requested(args(&["gui.exe", "--open", LINK])) else {
            panic!("the link was not opened");
        };

        assert_eq!(
            decode(COPYDATA, link.payload()),
            Some(LINK.parse().unwrap())
        );
    }

    #[test]
    fn a_received_payload_is_checked_like_an_argument() {
        assert_eq!(decode(COPYDATA + 1, LINK.as_bytes()), None);
        assert_eq!(decode(COPYDATA, b"https://proxy.newco.example"), None);
        assert_eq!(decode(COPYDATA, b""), None);
        assert_eq!(decode(COPYDATA, &[0xFF; 8]), None);
        let mut nul = LINK.as_bytes().to_vec();
        nul.push(0);
        assert_eq!(decode(COPYDATA, &nul), None);
    }

    #[test]
    fn a_received_payload_over_the_cap_is_not_read() {
        let mut long = LINK.as_bytes().to_vec();
        long.resize(CAP + 1, b'a');

        assert_eq!(decode(COPYDATA, &long), None);
    }

    #[test]
    fn the_cap_is_the_longest_link_the_command_accepts() {
        assert_eq!(CAP, gateinto::uri::MAX_LEN);
    }

    #[test]
    fn the_same_image_is_recognized_across_spellings() {
        let gui = r"C:\Program Files\Gateinto\gateinto-gui.exe";

        assert!(same_image(gui, gui));
        assert!(same_image(
            gui,
            r"c:\program files\gateinto\GATEINTO-GUI.EXE"
        ));
        assert!(same_image(
            gui,
            r"\\?\C:\Program Files\Gateinto\gateinto-gui.exe"
        ));
        assert!(same_image(
            gui,
            "C:/Program Files/Gateinto/gateinto-gui.exe"
        ));
        assert!(same_image(
            r"\\server\share\Gateinto\gateinto-gui.exe",
            r"\\?\UNC\server\share\Gateinto\gateinto-gui.exe"
        ));
        assert!(same_image(
            r"C:\Users\Émile\gateinto-gui.exe",
            r"C:\Users\émile\gateinto-gui.exe"
        ));
    }

    #[test]
    fn other_images_are_not_the_same() {
        let gui = r"C:\Program Files\Gateinto\gateinto-gui.exe";

        assert!(!same_image(gui, r"C:\Users\me\Downloads\gateinto-gui.exe"));
        assert!(!same_image(
            gui,
            r"C:\Program Files\Gateinto\gateinto-gui.exe.bak"
        ));
        assert!(!same_image(
            gui,
            r"C:\Program Files\Gateinto\gateinto-gui.ex"
        ));
        assert!(!same_image(
            gui,
            r"\\?\D:\Program Files\Gateinto\gateinto-gui.exe"
        ));
        assert!(!same_image(gui, ""));
        assert!(!same_image("", ""));
    }
}
