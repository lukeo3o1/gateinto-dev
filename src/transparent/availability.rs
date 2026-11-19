use std::fmt;
#[cfg(any(windows, test))]
use std::io::{self, Read};

#[cfg(any(windows, test))]
use crate::divert::helper::sha256_matches;
#[cfg(any(windows, test))]
use crate::divert::windivert::PinnedFile;

#[cfg(windows)]
mod windows;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    Available,
    Unavailable(Reason),
}

impl fmt::Display for Availability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Available => f.write_str("available"),
            Self::Unavailable(reason) => write!(f, "unavailable: {reason}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    NotWindows,
    TooOld,
    Arm64,
    FilesMissing(&'static str),
    DigestMismatch(&'static str),
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotWindows => f.write_str("transparent sessions need Windows"),
            Self::TooOld => {
                f.write_str("Windows 10 1607 or Windows Server 2016 or later is required")
            }
            Self::Arm64 => f.write_str("Windows on ARM64 is not supported"),
            Self::FilesMissing(name) => write!(f, "{name} is missing next to gateinto.exe"),
            Self::DigestMismatch(name) => write!(
                f,
                "{name} next to gateinto.exe is not the file of the pinned WinDivert release"
            ),
        }
    }
}

pub fn available() -> Availability {
    #[cfg(windows)]
    {
        check(&mut windows::Probe, crate::divert::windivert::FILES)
    }
    #[cfg(not(windows))]
    {
        Availability::Unavailable(Reason::NotWindows)
    }
}

#[cfg(any(windows, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Version {
    major: u32,
    build: u32,
}

#[cfg(any(windows, test))]
trait Probe {
    type File: Read;

    fn version(&mut self) -> Option<Version>;
    fn arm64(&mut self) -> bool;
    fn open(&mut self, name: &str) -> io::Result<Self::File>;
}

#[cfg(any(windows, test))]
const FIRST_BUILD: u32 = 14393;

#[cfg(any(windows, test))]
fn check<P: Probe>(probe: &mut P, pinned: &[PinnedFile]) -> Availability {
    match refusal(probe, pinned) {
        Ok(()) => Availability::Available,
        Err(reason) => Availability::Unavailable(reason),
    }
}

#[cfg(any(windows, test))]
fn refusal<P: Probe>(probe: &mut P, pinned: &[PinnedFile]) -> Result<(), Reason> {
    let supported = probe.version().is_some_and(|version| {
        version.major > 10 || version.major == 10 && version.build >= FIRST_BUILD
    });
    if !supported {
        return Err(Reason::TooOld);
    }
    if probe.arm64() {
        return Err(Reason::Arm64);
    }
    let opened = pinned
        .iter()
        .map(|file| {
            probe
                .open(file.name)
                .map_err(|_| Reason::FilesMissing(file.name))
        })
        .collect::<Result<Vec<_>, _>>()?;
    for (file, pinned) in opened.into_iter().zip(pinned) {
        if !sha256_matches(file, &pinned.sha256) {
            return Err(Reason::DigestMismatch(pinned.name));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    const LIBRARY: &str = "WinDivert.dll";
    const DRIVER: &str = "WinDivert64.sys";

    fn pinned(name: &'static str, contents: &[u8]) -> PinnedFile {
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, contents);
        PinnedFile {
            name,
            sha256: digest.as_ref().try_into().unwrap(),
        }
    }

    fn release() -> [PinnedFile; 2] {
        [pinned(LIBRARY, b"library"), pinned(DRIVER, b"driver")]
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Asked {
        Version,
        Arm64,
        Open(&'static str),
    }

    #[derive(Clone, Copy)]
    enum Stored {
        Bytes(&'static [u8]),
        Unreadable,
        Refused,
    }

    struct Fake {
        version: Option<Version>,
        arm64: bool,
        files: HashMap<&'static str, Stored>,
        asked: Vec<Asked>,
    }

    struct FakeFile(Option<&'static [u8]>);

    impl Read for FakeFile {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            match &mut self.0 {
                Some(bytes) => bytes.read(buffer),
                None => Err(io::Error::other("unreadable")),
            }
        }
    }

    impl Probe for Fake {
        type File = FakeFile;

        fn version(&mut self) -> Option<Version> {
            self.asked.push(Asked::Version);
            self.version
        }

        fn arm64(&mut self) -> bool {
            self.asked.push(Asked::Arm64);
            self.arm64
        }

        fn open(&mut self, name: &str) -> io::Result<FakeFile> {
            let (&name, &stored) = self
                .files
                .get_key_value(name)
                .ok_or(io::ErrorKind::NotFound)?;
            self.asked.push(Asked::Open(name));
            match stored {
                Stored::Bytes(bytes) => Ok(FakeFile(Some(bytes))),
                Stored::Unreadable => Ok(FakeFile(None)),
                Stored::Refused => Err(io::ErrorKind::PermissionDenied.into()),
            }
        }
    }

    fn windows(major: u32, build: u32) -> Fake {
        Fake {
            version: Some(Version { major, build }),
            arm64: false,
            files: HashMap::from([
                (LIBRARY, Stored::Bytes(b"library")),
                (DRIVER, Stored::Bytes(b"driver")),
            ]),
            asked: Vec::new(),
        }
    }

    fn checked(fake: &mut Fake) -> Availability {
        check(fake, &release())
    }

    #[test]
    fn windows_10_1607_and_later_on_x86_or_x64_with_the_pinned_files_is_available() {
        for (major, build) in [(10, 14393), (10, 17763), (10, 26100), (11, 0)] {
            let mut fake = windows(major, build);
            assert_eq!(checked(&mut fake), Availability::Available, "{build}");
            assert_eq!(
                fake.asked,
                [
                    Asked::Version,
                    Asked::Arm64,
                    Asked::Open(LIBRARY),
                    Asked::Open(DRIVER)
                ]
            );
        }
        assert_eq!(Availability::Available.to_string(), "available");
    }

    #[test]
    fn windows_before_10_1607_is_too_old_and_nothing_else_is_probed() {
        for (major, build) in [(10, 14392), (10, 10240), (6, 3), (6, 7601), (6, 99999)] {
            let mut fake = windows(major, build);
            fake.arm64 = true;
            assert_eq!(
                checked(&mut fake),
                Availability::Unavailable(Reason::TooOld),
                "{major}.{build}"
            );
            assert_eq!(fake.asked, [Asked::Version]);
        }
        let mut unknown = windows(10, 26100);
        unknown.version = None;
        assert_eq!(
            checked(&mut unknown),
            Availability::Unavailable(Reason::TooOld)
        );
        assert_eq!(
            Availability::Unavailable(Reason::TooOld).to_string(),
            "unavailable: Windows 10 1607 or Windows Server 2016 or later is required"
        );
    }

    #[test]
    fn arm64_is_unavailable_before_any_file_is_opened() {
        let mut fake = windows(10, 26100);
        fake.arm64 = true;
        fake.files.clear();
        assert_eq!(checked(&mut fake), Availability::Unavailable(Reason::Arm64));
        assert_eq!(fake.asked, [Asked::Version, Asked::Arm64]);
        assert_eq!(
            Availability::Unavailable(Reason::Arm64).to_string(),
            "unavailable: Windows on ARM64 is not supported"
        );
    }

    #[test]
    fn a_missing_file_is_named_and_counts_before_any_digest() {
        let mut fake = windows(10, 26100);
        fake.files.remove(DRIVER);
        fake.files.insert(LIBRARY, Stored::Bytes(b"changed"));
        assert_eq!(
            checked(&mut fake),
            Availability::Unavailable(Reason::FilesMissing(DRIVER))
        );
        let mut refused = windows(10, 26100);
        refused.files.insert(LIBRARY, Stored::Refused);
        assert_eq!(
            checked(&mut refused),
            Availability::Unavailable(Reason::FilesMissing(LIBRARY))
        );
        assert_eq!(
            Availability::Unavailable(Reason::FilesMissing(DRIVER)).to_string(),
            "unavailable: WinDivert64.sys is missing next to gateinto.exe"
        );
    }

    #[test]
    fn the_first_file_whose_digest_differs_or_cannot_be_read_is_named() {
        let mut fake = windows(10, 26100);
        fake.files.insert(DRIVER, Stored::Bytes(b"changed"));
        assert_eq!(
            checked(&mut fake),
            Availability::Unavailable(Reason::DigestMismatch(DRIVER))
        );
        let mut unreadable = windows(10, 26100);
        unreadable.files.insert(LIBRARY, Stored::Unreadable);
        unreadable.files.insert(DRIVER, Stored::Bytes(b"changed"));
        assert_eq!(
            checked(&mut unreadable),
            Availability::Unavailable(Reason::DigestMismatch(LIBRARY))
        );
        assert_eq!(
            Availability::Unavailable(Reason::DigestMismatch(LIBRARY)).to_string(),
            "unavailable: WinDivert.dll next to gateinto.exe is not the file of the pinned \
             WinDivert release"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn transparent_sessions_are_unavailable_outside_windows() {
        assert_eq!(available(), Availability::Unavailable(Reason::NotWindows));
        assert_eq!(
            available().to_string(),
            "unavailable: transparent sessions need Windows"
        );
    }
}
