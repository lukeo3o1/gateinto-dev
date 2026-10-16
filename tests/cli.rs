use std::process::Command;

#[test]
fn prints_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_gateinto"))
        .arg("--version")
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("gateinto {}\n", env!("CARGO_PKG_VERSION"))
    );
}

fn gateinto(args: &[&str]) -> (bool, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_gateinto"))
        .args(args)
        .output()
        .unwrap();
    (
        output.status.success(),
        String::from_utf8(output.stderr).unwrap(),
    )
}

#[test]
fn proxy_requires_an_upstream_endpoint() {
    let (success, stderr) = gateinto(&["proxy"]);
    assert!(!success);
    assert!(stderr.contains("--upstream-host"), "{stderr}");
    assert!(stderr.contains("--upstream-port"), "{stderr}");
}

#[test]
fn proxy_refuses_non_loopback_listen_address() {
    let (success, stderr) = gateinto(&[
        "proxy",
        "--listen",
        "0.0.0.0:0",
        "--upstream-host",
        "127.0.0.1",
        "--upstream-port",
        "9",
    ]);
    assert!(!success);
    assert!(
        stderr.contains("--unsafe-allow-non-loopback-listen"),
        "{stderr}"
    );
}

#[test]
fn proxy_reports_unreadable_ca_file() {
    let (success, stderr) = gateinto(&[
        "proxy",
        "--upstream-host",
        "127.0.0.1",
        "--upstream-port",
        "9",
        "--ca-file",
        "/nonexistent/gateinto-ca.pem",
    ]);
    assert!(!success);
    assert!(stderr.contains("/nonexistent/gateinto-ca.pem"), "{stderr}");
}

#[test]
fn proxy_rejects_zero_limits_and_ports() {
    for (flag, value) in [
        ("--upstream-port", "0"),
        ("--max-tunnels", "0"),
        ("--max-header-bytes", "0"),
        ("--connect-timeout-secs", "0"),
        ("--idle-timeout-secs", "0"),
    ] {
        let mut args = vec![
            "proxy",
            "--upstream-host",
            "127.0.0.1",
            "--upstream-port",
            "9",
        ];
        args.extend([flag, value]);
        let (success, stderr) = gateinto(&args);
        assert!(!success, "{flag}");
        assert!(stderr.contains(flag), "{stderr}");
    }
}

#[cfg(not(windows))]
#[test]
fn key_commands_require_windows() {
    for args in [
        &["key", "init"][..],
        &["key", "info"],
        &["key", "info", "--name", "other", "--spki-out", "unused.der"],
        &[
            "key",
            "init",
            "--backend",
            "software",
            "--no-software-fallback",
        ],
    ] {
        let (success, stderr) = gateinto(args);
        assert!(!success, "{args:?}");
        assert!(
            stderr.contains("device keys are only supported on Windows"),
            "{stderr}"
        );
    }
}

#[test]
fn key_commands_reject_an_empty_name() {
    for command in ["init", "info"] {
        let (success, stderr) = gateinto(&["key", command, "--name", ""]);
        assert!(!success);
        assert!(stderr.contains("key name must not be empty"), "{stderr}");
    }
}
