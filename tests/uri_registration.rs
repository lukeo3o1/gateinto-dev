#![cfg(windows)]

use std::path::Path;
use std::process::Command;

use gateinto::registration::{
    RegistrationError, handler_command, register, registered_command, unregister,
};

struct TestScheme(String);

impl TestScheme {
    fn new(name: &str) -> Self {
        Self(format!("gateinto-test-{name}-{}", std::process::id()))
    }

    fn key(&self) -> String {
        format!(r"HKCU\Software\Classes\{}", self.0)
    }

    fn reg(&self, args: &[&str]) -> bool {
        Command::new("reg")
            .args(args)
            .output()
            .unwrap()
            .status
            .success()
    }

    fn exists(&self) -> bool {
        self.reg(&["query", &self.key()])
    }
}

impl Drop for TestScheme {
    fn drop(&mut self) {
        let key = self.key();
        self.reg(&["delete", &key, "/f"]);
    }
}

fn command() -> String {
    handler_command(
        Path::new(r"C:\Gateinto Test\gateinto.exe"),
        Some(Path::new(r"C:\Gateinto Test\gateinto.toml")),
    )
    .unwrap()
}

#[test]
fn registering_writes_a_url_protocol_handler_that_unregistering_removes() {
    let scheme = TestScheme::new("roundtrip");
    let command = command();

    register(&scheme.0, &command).unwrap();
    register(&scheme.0, &command).unwrap();

    assert_eq!(registered_command(&scheme.0).unwrap(), Some(command));
    assert!(scheme.reg(&["query", &scheme.key(), "/v", "URL Protocol"]));
    assert!(unregister(&scheme.0).unwrap());
    assert!(!scheme.exists());
    assert_eq!(registered_command(&scheme.0).unwrap(), None);
    assert!(!unregister(&scheme.0).unwrap());
}

#[test]
fn a_foreign_handler_is_neither_replaced_nor_removed() {
    let scheme = TestScheme::new("foreign");
    let foreign = r#""C:\Other\other.exe" "%1""#;
    let command_key = format!(r"{}\shell\open\command", scheme.key());
    assert!(scheme.reg(&["add", &command_key, "/ve", "/d", foreign, "/f"]));

    for error in [
        register(&scheme.0, &command()).unwrap_err(),
        unregister(&scheme.0).unwrap_err(),
    ] {
        assert!(
            matches!(error, RegistrationError::ForeignHandler { .. }),
            "{error}"
        );
    }
    assert_eq!(
        registered_command(&scheme.0).unwrap().as_deref(),
        Some(foreign)
    );
}

#[test]
fn a_key_without_a_command_is_left_alone() {
    let scheme = TestScheme::new("empty");
    assert!(scheme.reg(&["add", &scheme.key(), "/f"]));

    assert!(unregister(&scheme.0).is_err());
    assert!(register(&scheme.0, &command()).is_err());
    assert!(scheme.exists());
    assert_eq!(registered_command(&scheme.0).unwrap(), None);
}

#[test]
fn a_command_that_is_not_a_gateinto_handler_is_never_written() {
    let scheme = TestScheme::new("invalid");
    assert!(register(&scheme.0, r#""C:\Other\other.exe" "%1""#).is_err());
    assert!(!scheme.exists());
}
