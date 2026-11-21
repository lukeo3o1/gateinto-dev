use std::error::Error;
use std::fmt;

use super::helper::ListenerPort;

pub const RULE_NAME: &str = "Gateinto-transparent-listener";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetshCommand(String);

impl NetshCommand {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub fn delete_rule() -> NetshCommand {
    NetshCommand(format!("advfirewall firewall delete rule name={RULE_NAME}"))
}

pub fn add_rule(port: ListenerPort, program: &str) -> Result<NetshCommand, InvalidProgram> {
    if !verbatim(program) || !absolute(program) {
        return Err(InvalidProgram);
    }
    Ok(NetshCommand(format!(
        "advfirewall firewall add rule name={RULE_NAME} dir=in action=allow protocol=TCP \
         localport={port} program=\"{program}\" enable=yes profile=any"
    )))
}

// A backslash right before the closing quote would escape it, and the firewall expands `%NAME%`.
fn verbatim(path: &str) -> bool {
    !path.ends_with('\\')
        && !path
            .chars()
            .any(|c| matches!(c, '"' | '%') || c.is_control())
}

fn absolute(path: &str) -> bool {
    let local = path.strip_prefix(r"\\?\").unwrap_or(path);
    match local.as_bytes() {
        [drive, b':', b'\\', ..] => drive.is_ascii_alphabetic(),
        _ => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidProgram;

impl fmt::Display for InvalidProgram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the program path cannot be used in a firewall rule")
    }
}

impl Error for InvalidProgram {}

#[cfg(test)]
mod tests {
    use super::*;

    fn port() -> ListenerPort {
        ListenerPort::new(49152).unwrap()
    }

    #[test]
    fn the_rule_is_deleted_by_its_fixed_name() {
        assert_eq!(RULE_NAME, "Gateinto-transparent-listener");
        assert_eq!(
            delete_rule().as_str(),
            "advfirewall firewall delete rule name=Gateinto-transparent-listener"
        );
    }

    #[test]
    fn the_rule_allows_inbound_tcp_to_the_listener_port_for_the_helper_image_only() {
        let program = r"C:\Users\Jane Doe\AppData\Local\Programs\Gateinto\gateinto.exe";
        assert_eq!(
            add_rule(port(), program).unwrap().as_str(),
            "advfirewall firewall add rule name=Gateinto-transparent-listener dir=in \
             action=allow protocol=TCP localport=49152 \
             program=\"C:\\Users\\Jane Doe\\AppData\\Local\\Programs\\Gateinto\\gateinto.exe\" \
             enable=yes profile=any"
        );
        let verbatim = r"\\?\D:\Program Files (x86)\Gateinto\gateinto.exe";
        assert_eq!(
            add_rule(ListenerPort::new(65535).unwrap(), verbatim)
                .unwrap()
                .as_str(),
            format!(
                "advfirewall firewall add rule name=Gateinto-transparent-listener dir=in \
                 action=allow protocol=TCP localport=65535 program=\"{verbatim}\" \
                 enable=yes profile=any"
            )
        );
        assert!(add_rule(port(), r"c:\gateinto.exe").is_ok());
    }

    #[test]
    fn a_program_path_that_cannot_be_quoted_safely_or_is_not_absolute_is_refused() {
        for refused in [
            "",
            "gateinto.exe",
            r".\gateinto.exe",
            r"..\gateinto.exe",
            r"C:gateinto.exe",
            r"C:/Gateinto/gateinto.exe",
            r"\Gateinto\gateinto.exe",
            r"\\server\share\gateinto.exe",
            r"\\.\C:\gateinto.exe",
            r"//?/C:/gateinto.exe",
            r"1:\gateinto.exe",
            "\u{e9}:\\gateinto.exe",
            r"C:\Gateinto\",
            r"\\?\",
            r#"C:\Gate"into\gateinto.exe"#,
            r#"C:\Gateinto\gateinto.exe" dir=out"#,
            "C:\\Gateinto\\gateinto.exe\0",
            "C:\\Gate\ninto\\gateinto.exe",
            "C:\\Gate\rinto\\gateinto.exe",
            "C:\\Gate\tinto\\gateinto.exe",
            "C:\\Gate\u{7f}into\\gateinto.exe",
            "C:\\Gate\u{85}into\\gateinto.exe",
            r"C:\Users\%USERNAME%\gateinto.exe",
            r"C:\100%\gateinto.exe",
            r"\\?\UNC\server\share\gateinto.exe",
            r"\\?\GLOBALROOT\Device\HarddiskVolume2\gateinto.exe",
            r"\\?\Volume{00000000-0000-0000-0000-000000000000}\gateinto.exe",
            r"\\?\C:gateinto.exe",
            r"\\?\1:\gateinto.exe",
            r"\\?\\C:\gateinto.exe",
        ] {
            assert_eq!(
                add_rule(port(), refused),
                Err(InvalidProgram),
                "{refused:?}"
            );
        }
    }

    #[test]
    fn an_invalid_program_has_a_fixed_message() {
        assert_eq!(
            InvalidProgram.to_string(),
            "the program path cannot be used in a firewall rule"
        );
    }
}
