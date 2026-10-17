#![cfg(windows)]

use std::process::Command;
use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use gateinto::identity::device_key::{
    self, Backend, InitOptions, KeyError, KeyName, KeyStore, Provenance, StoreError, TpmProblem,
};
use gateinto::identity::windows_cng::{
    CngKey, CngStore, PLATFORM_CRYPTO_PROVIDER, SOFTWARE_KEY_STORAGE_PROVIDER, delete_key,
};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_ECCPRIVATE_BLOB, NCRYPT_EXPORT_POLICY_PROPERTY, NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
    NCRYPT_SILENT_FLAG, NCryptExportKey, NCryptGetProperty,
};
use windows_sys::Win32::System::TpmBaseServices::{TPM_DEVICE_INFO, Tbsi_GetDeviceInfo};

const TBS_E_TPM_NOT_FOUND: u32 = 0x8028_400F;

fn tpm_absent() -> bool {
    let mut info = TPM_DEVICE_INFO::default();
    let status =
        unsafe { Tbsi_GetDeviceInfo(size_of::<TPM_DEVICE_INFO>() as u32, (&raw mut info).cast()) };
    status == TBS_E_TPM_NOT_FOUND
}

struct TestKey(KeyName);

impl TestKey {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!(
            "gateinto-test-device-{}-{}-{}",
            std::process::id(),
            nanos,
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        Self(name.parse().unwrap())
    }

    fn name(&self) -> &KeyName {
        &self.0
    }
}

impl Drop for TestKey {
    fn drop(&mut self) {
        let _ = delete_key(PLATFORM_CRYPTO_PROVIDER, self.0.as_str());
        let _ = delete_key(SOFTWARE_KEY_STORAGE_PROVIDER, self.0.as_str());
    }
}

fn software() -> InitOptions {
    InitOptions {
        backend: Backend::Software,
        ..InitOptions::default()
    }
}

fn export_fails(key: &CngKey, blob_type: windows_sys::core::PCWSTR) -> bool {
    let mut size = 0;
    let status = unsafe {
        NCryptExportKey(
            key.handle(),
            0,
            blob_type,
            ptr::null(),
            ptr::null_mut(),
            0,
            &mut size,
            NCRYPT_SILENT_FLAG,
        )
    };
    if status != 0 {
        return true;
    }
    let mut blob = vec![0u8; size as usize];
    let status = unsafe {
        NCryptExportKey(
            key.handle(),
            0,
            blob_type,
            ptr::null(),
            blob.as_mut_ptr(),
            size,
            &mut size,
            NCRYPT_SILENT_FLAG,
        )
    };
    status != 0
}

fn export_policy(key: &CngKey) -> u32 {
    let mut policy = 0u32;
    let mut written = 0;
    let status = unsafe {
        NCryptGetProperty(
            key.handle(),
            NCRYPT_EXPORT_POLICY_PROPERTY,
            (&mut policy as *mut u32).cast(),
            size_of::<u32>() as u32,
            &mut written,
            NCRYPT_SILENT_FLAG,
        )
    };
    assert_eq!(status, 0);
    assert_eq!(written as usize, size_of::<u32>());
    policy
}

#[test]
fn missing_key_is_not_found_in_the_software_provider() {
    let key = TestKey::new();

    assert_eq!(
        CngStore.open(Backend::Software, key.name()).unwrap_err(),
        StoreError::NotFound
    );
}

#[test]
fn missing_key_is_not_found_or_unavailable_in_the_platform_provider() {
    let key = TestKey::new();

    let error = CngStore.open(Backend::Tpm, key.name()).unwrap_err();

    if tpm_absent() {
        assert!(
            matches!(error, StoreError::ProviderUnavailable(_)),
            "{error:?}"
        );
    } else {
        assert_eq!(error, StoreError::NotFound);
    }
}

#[test]
fn software_init_creates_once_and_then_reuses() {
    let key = TestKey::new();

    let (created, provenance) = device_key::init(&CngStore, key.name(), software()).unwrap();
    assert_eq!(provenance, Provenance::Created);
    assert_eq!(created.backend, Backend::Software);
    let fingerprint = created.fingerprint();
    drop(created);

    let (reused, provenance) = device_key::init(&CngStore, key.name(), software()).unwrap();
    assert_eq!(provenance, Provenance::Reused);
    assert_eq!(reused.backend, Backend::Software);
    assert_eq!(reused.fingerprint(), fingerprint);
}

#[test]
fn default_init_creates_a_working_key_with_or_without_a_tpm() {
    let key = TestKey::new();

    let (created, provenance) =
        device_key::init(&CngStore, key.name(), InitOptions::default()).unwrap();
    match (&provenance, created.backend, tpm_absent()) {
        (Provenance::Created, Backend::Tpm, false) => {}
        (Provenance::CreatedAfterFallback(TpmProblem::Unavailable(_)), Backend::Software, true) => {
        }
        (Provenance::CreatedAfterFallback(_), Backend::Software, false) => {}
        other => panic!("unexpected outcome {other:?}"),
    }
    let fingerprint = created.fingerprint();
    let backend = created.backend;
    drop(created);

    let (reused, provenance) =
        device_key::init(&CngStore, key.name(), InitOptions::default()).unwrap();
    assert_eq!(provenance, Provenance::Reused);
    assert_eq!(reused.backend, backend);
    assert_eq!(reused.fingerprint(), fingerprint);
}

#[test]
fn disabled_fallback_creates_nothing_in_software_when_the_tpm_is_unusable() {
    let key = TestKey::new();
    let options = InitOptions {
        allow_software_fallback: false,
        ..InitOptions::default()
    };

    let result = device_key::init(&CngStore, key.name(), options);

    if tpm_absent() {
        let error = result.map(drop).unwrap_err();
        assert!(
            matches!(&error, KeyError::TpmUnusable(TpmProblem::Unavailable(_))),
            "{error:?}"
        );
        assert!(
            error
                .to_string()
                .starts_with("the TPM provider is unavailable: "),
            "{error}"
        );
        assert!(matches!(
            CngStore.open(Backend::Tpm, key.name()).map(drop),
            Err(StoreError::ProviderUnavailable(_))
        ));
    } else {
        match result {
            Ok((created, provenance)) => {
                assert_eq!(created.backend, Backend::Tpm);
                assert_eq!(provenance, Provenance::Created);
                return;
            }
            Err(KeyError::TpmUnusable(_) | KeyError::ProviderNotReady { .. }) => {}
            Err(other) => panic!("{other}"),
        }
    }
    assert_eq!(
        CngStore
            .open(Backend::Software, key.name())
            .map(drop)
            .unwrap_err(),
        StoreError::NotFound
    );
}

#[test]
fn info_matches_init() {
    let key = TestKey::new();
    let (created, _) = device_key::init(&CngStore, key.name(), software()).unwrap();

    let (opened, duplicate) = device_key::info(&CngStore, key.name()).unwrap();

    assert_eq!(opened.backend, created.backend);
    assert_eq!(opened.point, created.point);
    assert_eq!(duplicate, None);
}

#[test]
fn keys_in_both_providers_stop_init_and_make_info_warn() {
    let key = TestKey::new();
    let Ok(tpm) = CngStore.create(Backend::Tpm, key.name()) else {
        return;
    };
    drop(tpm);
    drop(CngStore.create(Backend::Software, key.name()).unwrap());

    assert!(matches!(
        device_key::init(&CngStore, key.name(), InitOptions::default()),
        Err(KeyError::Duplicate(_))
    ));
    let (shown, duplicate) = device_key::info(&CngStore, key.name()).unwrap();
    assert_eq!(shown.backend, Backend::Tpm);
    assert!(duplicate.is_some());

    let (success, stdout, stderr) = gateinto(&["key", "info", "--name", key.name().as_str()]);
    assert!(success, "{stderr}");
    assert_eq!(field(&stdout, "backend"), "tpm");
    assert!(stderr.starts_with("warning: device keys named"), "{stderr}");
}

#[test]
fn info_never_creates_a_key() {
    let key = TestKey::new();

    assert_eq!(
        device_key::info(&CngStore, key.name()).unwrap_err(),
        KeyError::NotFound(key.name().clone())
    );
    assert_eq!(
        CngStore
            .open(Backend::Software, key.name())
            .map(drop)
            .unwrap_err(),
        StoreError::NotFound
    );
}

#[test]
fn created_software_key_is_not_exportable() {
    let key = TestKey::new();
    let created = CngStore.create(Backend::Software, key.name()).unwrap();

    assert_eq!(export_policy(&created), 0);
    assert!(export_fails(&created, BCRYPT_ECCPRIVATE_BLOB));
    assert!(export_fails(&created, NCRYPT_PKCS8_PRIVATE_KEY_BLOB));
}

#[test]
fn initialized_key_is_not_exportable_on_any_backend() {
    let key = TestKey::new();
    let (created, _) = device_key::init(&CngStore, key.name(), InitOptions::default()).unwrap();

    assert!(export_fails(&created.key, BCRYPT_ECCPRIVATE_BLOB));
    assert!(export_fails(&created.key, NCRYPT_PKCS8_PRIVATE_KEY_BLOB));
}

fn gateinto(args: &[&str]) -> (bool, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_gateinto"))
        .args(args)
        .output()
        .unwrap();
    (
        output.status.success(),
        String::from_utf8(output.stdout).unwrap(),
        String::from_utf8(output.stderr).unwrap(),
    )
}

fn field<'a>(output: &'a str, name: &str) -> &'a str {
    output
        .lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(": "))
        .unwrap_or_else(|| panic!("no {name} in {output}"))
}

#[test]
fn key_commands_create_reuse_and_describe_the_key() {
    let key = TestKey::new();
    let name = key.name().as_str();
    let spki_path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}.der"));

    let (success, first, stderr) =
        gateinto(&["key", "init", "--name", name, "--backend", "software"]);
    assert!(success, "{stderr}");
    assert!(
        first.starts_with(&format!("created device key \"{name}\"\n")),
        "{first}"
    );
    assert_eq!(field(&first, "backend"), "software");
    assert_eq!(field(&first, "algorithm"), "ECDSA P-256");

    let (success, second, stderr) = gateinto(&["key", "init", "--name", name]);
    assert!(success, "{stderr}");
    assert!(
        second.starts_with(&format!("using existing device key \"{name}\"\n")),
        "{second}"
    );
    assert_eq!(field(&second, "spki-sha256"), field(&first, "spki-sha256"));

    let (success, info, stderr) = gateinto(&[
        "key",
        "info",
        "--name",
        name,
        "--spki-out",
        spki_path.to_str().unwrap(),
    ]);
    assert!(success, "{stderr}");
    assert_eq!(field(&info, "backend"), "software");
    assert_eq!(field(&info, "spki-sha256"), field(&first, "spki-sha256"));
    assert!(field(&info, "trust").contains("not protected against copying"));
    let spki = std::fs::read(&spki_path).unwrap();
    let _ = std::fs::remove_file(&spki_path);
    assert_eq!(
        gateinto::identity::encoding::sha256_fingerprint(&spki),
        field(&first, "spki-sha256")
    );
}

#[test]
fn key_info_fails_for_a_missing_key() {
    let key = TestKey::new();

    let (success, _, stderr) = gateinto(&["key", "info", "--name", key.name().as_str()]);

    assert!(!success);
    assert!(stderr.contains("no device key named"), "{stderr}");
}

#[test]
fn key_init_reports_the_software_fallback() {
    let key = TestKey::new();

    let (success, stdout, stderr) = gateinto(&["key", "init", "--name", key.name().as_str()]);

    assert!(success, "{stderr}");
    match field(&stdout, "backend") {
        "tpm" => {
            assert!(!tpm_absent());
            assert!(stderr.is_empty(), "{stderr}");
        }
        "software" => {
            assert!(stdout.contains("created software device key"), "{stdout}");
            assert!(stderr.starts_with("warning: "), "{stderr}");
        }
        other => panic!("unexpected backend {other}"),
    }
}

#[test]
fn purge_deletes_only_the_confirmed_software_key() {
    let key = TestKey::new();
    let other = TestKey::new();
    let (created, _) = device_key::init(&CngStore, key.name(), software()).unwrap();
    let (kept, _) = device_key::init(&CngStore, other.name(), software()).unwrap();
    let wrong = if created.fingerprint().starts_with('0') {
        "1"
    } else {
        "0"
    }
    .repeat(16);

    assert!(matches!(
        device_key::purge(&CngStore, key.name(), &wrong.parse().unwrap()),
        Err(device_key::PurgeError::Mismatch { .. })
    ));
    let purged = device_key::purge(
        &CngStore,
        key.name(),
        &created.fingerprint().parse().unwrap(),
    )
    .unwrap();

    assert_eq!(purged.backend, Backend::Software);
    assert_eq!(purged.fingerprint, created.fingerprint());
    assert_eq!(
        device_key::info(&CngStore, key.name()).unwrap_err(),
        KeyError::NotFound(key.name().clone())
    );
    let (still, _) = device_key::info(&CngStore, other.name()).unwrap();
    assert_eq!(still.fingerprint(), kept.fingerprint());
}
