use crate::identity::device_key::StoreError;

#[derive(Clone, Copy)]
enum Class {
    NotFound,
    Unavailable,
    NotReady,
    Failed,
}

const TBS_SUCCESS: u32 = 0;
const TBS_E_TPM_NOT_FOUND: u32 = 0x8028_400F;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmProbeError {
    Status(u32),
    DeviceInfoUnavailable,
}

pub fn probe_device_info(
    get_device_info: Option<impl FnOnce() -> u32>,
) -> Result<(), TpmProbeError> {
    let get_device_info = get_device_info.ok_or(TpmProbeError::DeviceInfoUnavailable)?;
    match get_device_info() {
        TBS_SUCCESS => Ok(()),
        code => Err(TpmProbeError::Status(code)),
    }
}

const KNOWN: &[(u32, &str, Class)] = &[
    (0x8009_000D, "NTE_NO_KEY", Class::NotFound),
    (0x8009_0011, "NTE_NOT_FOUND", Class::NotFound),
    (0x8009_0016, "NTE_BAD_KEYSET", Class::NotFound),
    (0x8009_0013, "NTE_BAD_PROVIDER", Class::Unavailable),
    (0x8009_001D, "NTE_PROVIDER_DLL_FAIL", Class::NotReady),
    (0x8009_001E, "NTE_PROV_DLL_NOT_FOUND", Class::Unavailable),
    (0x8009_0030, "NTE_DEVICE_NOT_READY", Class::NotReady),
    (0x8009_0035, "NTE_DEVICE_NOT_FOUND", Class::Unavailable),
    (0x8028_4008, "TBS_E_SERVICE_NOT_RUNNING", Class::NotReady),
    (
        TBS_E_TPM_NOT_FOUND,
        "TBS_E_TPM_NOT_FOUND",
        Class::Unavailable,
    ),
    (0x8028_4010, "TBS_E_SERVICE_DISABLED", Class::NotReady),
    (0x8009_000F, "NTE_EXISTS", Class::Failed),
    (0x8009_0010, "NTE_PERM", Class::Failed),
    (0x8009_0029, "NTE_NOT_SUPPORTED", Class::Failed),
];

fn classify(code: u32) -> (String, Class) {
    match KNOWN.iter().find(|(known, ..)| *known == code) {
        Some((_, name, class)) => (format!("{name} ({code:#010x})"), *class),
        None => (format!("{code:#010x}"), Class::Failed),
    }
}

fn to_store_error(description: String, class: Class) -> StoreError {
    match class {
        Class::NotFound => StoreError::NotFound,
        Class::Unavailable => StoreError::ProviderUnavailable(description),
        Class::NotReady => StoreError::ProviderNotReady(description),
        Class::Failed => StoreError::Failed(description),
    }
}

pub fn store_error(code: u32) -> StoreError {
    let (description, class) = classify(code);
    to_store_error(description, class)
}

pub fn provider_error(code: u32) -> StoreError {
    match classify(code) {
        (description, Class::NotFound) => StoreError::ProviderUnavailable(description),
        (description, class) => to_store_error(description, class),
    }
}

pub fn tpm_provider_error(
    error: StoreError,
    probe_tpm: impl FnOnce() -> Result<(), TpmProbeError>,
) -> StoreError {
    let StoreError::ProviderNotReady(reason) = error else {
        return error;
    };
    match probe_tpm() {
        Ok(()) => StoreError::ProviderNotReady(reason),
        Err(TpmProbeError::DeviceInfoUnavailable) => StoreError::ProviderUnavailable(format!(
            "{reason}; TPM Base Services device info unavailable (Windows 7 or earlier)"
        )),
        Err(TpmProbeError::Status(code)) => {
            let reason = format!("{reason}; TPM Base Services report {}", classify(code).0);
            if code == TBS_E_TPM_NOT_FOUND {
                StoreError::ProviderUnavailable(reason)
            } else {
                StoreError::ProviderNotReady(reason)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tbs_status(code: u32) -> Result<(), TpmProbeError> {
        Err(TpmProbeError::Status(code))
    }

    #[test]
    fn missing_keys_are_not_found() {
        for code in [0x8009_0016, 0x8009_0011, 0x8009_000D] {
            assert_eq!(store_error(code), StoreError::NotFound, "{code:#x}");
        }
    }

    const ABSENT: [u32; 4] = [0x8028_400F, 0x8009_001E, 0x8009_0013, 0x8009_0035];
    const NOT_READY: [u32; 4] = [0x8009_0030, 0x8028_4008, 0x8028_4010, 0x8009_001D];

    #[test]
    fn missing_tpm_or_provider_is_unavailable() {
        assert_eq!(
            store_error(0x8028_400F),
            StoreError::ProviderUnavailable("TBS_E_TPM_NOT_FOUND (0x8028400f)".to_owned())
        );
        for code in ABSENT {
            assert!(
                matches!(store_error(code), StoreError::ProviderUnavailable(_)),
                "{code:#x}"
            );
        }
    }

    #[test]
    fn present_but_unusable_tpm_is_not_ready() {
        assert_eq!(
            store_error(0x8028_4008),
            StoreError::ProviderNotReady("TBS_E_SERVICE_NOT_RUNNING (0x80284008)".to_owned())
        );
        for code in NOT_READY {
            assert!(
                matches!(store_error(code), StoreError::ProviderNotReady(_)),
                "{code:#x}"
            );
        }
    }

    #[test]
    fn provider_that_is_absent_or_names_nothing_is_unavailable() {
        assert_eq!(
            provider_error(0x8009_0013),
            StoreError::ProviderUnavailable("NTE_BAD_PROVIDER (0x80090013)".to_owned())
        );
        for code in ABSENT.into_iter().chain([0x8009_0011, 0x8009_0016]) {
            assert!(
                matches!(provider_error(code), StoreError::ProviderUnavailable(_)),
                "{code:#x}"
            );
        }
    }

    #[test]
    fn provider_open_failures_other_than_absence_are_passed_through() {
        for code in NOT_READY {
            assert_eq!(provider_error(code), store_error(code), "{code:#x}");
        }
        assert_eq!(
            provider_error(0x8009_0010),
            StoreError::Failed("NTE_PERM (0x80090010)".to_owned())
        );
        assert_eq!(
            provider_error(0x1234_5678),
            StoreError::Failed("0x12345678".to_owned())
        );
    }

    #[test]
    fn missing_device_info_function_is_reported_as_unavailable() {
        assert_eq!(
            probe_device_info(None::<fn() -> u32>),
            Err(TpmProbeError::DeviceInfoUnavailable)
        );
    }

    #[test]
    fn device_info_status_is_passed_through() {
        assert_eq!(probe_device_info(Some(|| 0)), Ok(()));
        assert_eq!(
            probe_device_info(Some(|| TBS_E_TPM_NOT_FOUND)),
            Err(TpmProbeError::Status(TBS_E_TPM_NOT_FOUND))
        );
    }

    #[test]
    fn not_ready_tpm_provider_without_device_info_is_unavailable() {
        assert_eq!(
            tpm_provider_error(store_error(0x8009_0030), || Err(
                TpmProbeError::DeviceInfoUnavailable
            )),
            StoreError::ProviderUnavailable(
                "NTE_DEVICE_NOT_READY (0x80090030); TPM Base Services device info \
                 unavailable (Windows 7 or earlier)"
                    .to_owned()
            )
        );
    }

    #[test]
    fn not_ready_tpm_provider_without_a_tpm_is_unavailable() {
        assert_eq!(
            tpm_provider_error(store_error(0x8009_0030), || tbs_status(TBS_E_TPM_NOT_FOUND)),
            StoreError::ProviderUnavailable(
                "NTE_DEVICE_NOT_READY (0x80090030); TPM Base Services report \
                 TBS_E_TPM_NOT_FOUND (0x8028400f)"
                    .to_owned()
            )
        );
        for code in NOT_READY {
            assert!(
                matches!(
                    tpm_provider_error(provider_error(code), || tbs_status(TBS_E_TPM_NOT_FOUND)),
                    StoreError::ProviderUnavailable(_)
                ),
                "{code:#x}"
            );
        }
    }

    #[test]
    fn not_ready_tpm_provider_with_a_tpm_stays_not_ready() {
        for code in NOT_READY {
            assert_eq!(
                tpm_provider_error(store_error(code), || Ok(())),
                store_error(code),
                "{code:#x}"
            );
        }
    }

    #[test]
    fn not_ready_tpm_provider_with_an_inconclusive_probe_stays_not_ready() {
        assert_eq!(
            tpm_provider_error(store_error(0x8009_0030), || tbs_status(0x8028_4008)),
            StoreError::ProviderNotReady(
                "NTE_DEVICE_NOT_READY (0x80090030); TPM Base Services report \
                 TBS_E_SERVICE_NOT_RUNNING (0x80284008)"
                    .to_owned()
            )
        );
        assert!(matches!(
            tpm_provider_error(store_error(0x8009_0030), || tbs_status(0x1234_5678)),
            StoreError::ProviderNotReady(_)
        ));
    }

    #[test]
    fn tpm_presence_is_probed_only_when_the_provider_is_not_ready() {
        for error in [
            StoreError::NotFound,
            store_error(0x8009_0013),
            store_error(0x8009_0010),
        ] {
            assert_eq!(
                tpm_provider_error(error.clone(), || panic!("probed for {error:?}")),
                error
            );
        }
    }

    #[test]
    fn other_codes_are_failures() {
        assert_eq!(
            store_error(0x8009_0010),
            StoreError::Failed("NTE_PERM (0x80090010)".to_owned())
        );
        assert_eq!(
            store_error(0x1234_5678),
            StoreError::Failed("0x12345678".to_owned())
        );
    }
}
