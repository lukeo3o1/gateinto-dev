use std::fmt;
use std::fs::Metadata;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv6Addr};
use std::num::NonZeroU16;
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;

use super::{DEFAULT_PORT, GatewayAddress, LinkedGateway, Origin};
use crate::config::{self, GatewayName, PortalUrl};
use crate::ipc::ConfirmToken;

pub const DIR_NAME: &str = "gateways";
pub const MAX_LINKED: usize = 32;
pub const MAX_FILE_BYTES: u64 = 16 * 1024;
pub const MAX_FILE_NAME: usize = 255;
const SUFFIX: &str = ".toml";

pub fn default_dir() -> Option<PathBuf> {
    Some(config::default_path()?.with_file_name(DIR_NAME))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unstorable(String);

impl fmt::Display for Unstorable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Unstorable {}

pub fn safe_file_name(name: &str) -> bool {
    let stem = name.strip_suffix(SUFFIX).unwrap_or_default();
    let mut components = Path::new(name).components();
    !stem.is_empty()
        && name.len() <= MAX_FILE_NAME
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        && !name.contains("..")
        && matches!(components.next(), Some(Component::Normal(_)))
        && components.next().is_none()
}

pub fn file_name(address: &GatewayAddress) -> Result<String, Unstorable> {
    let host = match address.host().parse::<IpAddr>() {
        Ok(ip) => match ip.to_canonical() {
            IpAddr::V6(ip) => ip.to_string().replace(':', "-"),
            ip => ip.to_string(),
        },
        Err(_) => address.host(),
    };
    let name = match address.port() {
        DEFAULT_PORT => format!("{host}{SUFFIX}"),
        port => format!("{host}_{port}{SUFFIX}"),
    };
    if name.len() > MAX_FILE_NAME {
        return Err(Unstorable(format!(
            "the gateway's host name is too long to store: its file name would have {} \
             bytes, at most {MAX_FILE_NAME} are allowed",
            name.len()
        )));
    }
    if !safe_file_name(&name) {
        return Err(Unstorable(
            "the gateway's address cannot be used as a file name".to_owned(),
        ));
    }
    Ok(name)
}

pub fn address_of_file(name: &str) -> Option<GatewayAddress> {
    if !safe_file_name(name) {
        return None;
    }
    let stem = name.strip_suffix(SUFFIX)?;
    let (host, port) = match stem.rsplit_once('_') {
        Some((host, port)) => (host, Some(port)),
        None => (stem, None),
    };
    let host = match host.replace('-', ":").parse::<Ipv6Addr>() {
        Ok(ip) => format!("[{ip}]"),
        Err(_) => host.to_owned(),
    };
    let text = match port {
        Some(port) => format!("{host}:{port}"),
        None => host,
    };
    let address: GatewayAddress = text.parse().ok()?;
    (file_name(&address).ok()? == name).then_some(address)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidEntry {
    pub file: PathBuf,
    pub name: Option<GatewayName>,
    pub addresses: Vec<GatewayAddress>,
    pub reason: String,
}

impl fmt::Display for InvalidEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.file.display(), self.reason)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Loaded {
    pub gateways: Vec<LinkedGateway>,
    pub invalid: Vec<InvalidEntry>,
}

#[derive(Debug)]
pub enum StoreError {
    Io(PathBuf, io::Error),
    NotADirectory(PathBuf),
    NotRegular(PathBuf),
    Escapes(PathBuf),
    Exists(GatewayName),
    AddressTaken(PathBuf),
    Full,
    Unstorable(Unstorable),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(path, error) => write!(f, "linked gateways {}: {error}", path.display()),
            Self::NotADirectory(path) => write!(
                f,
                "linked gateways {}: not a directory (links and reparse points are refused)",
                path.display()
            ),
            Self::NotRegular(path) => {
                write!(f, "linked gateway {}: not a regular file", path.display())
            }
            Self::Escapes(path) => write!(
                f,
                "linked gateway {}: outside the gateways directory",
                path.display()
            ),
            Self::Exists(name) => write!(f, "a linked gateway \"{name}\" already exists"),
            Self::AddressTaken(path) => write!(
                f,
                "linked gateway {} already exists; it is never overwritten",
                path.display()
            ),
            Self::Full => write!(
                f,
                "{MAX_LINKED} linked gateways are stored already; remove one with \
                 `gateinto gateway forget <name>`"
            ),
            Self::Unstorable(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for StoreError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    name: GatewayName,
    host: String,
    port: NonZeroU16,
    portal_url: PortalUrl,
    approved_at: Option<u64>,
}

fn plain(metadata: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return false;
        }
    }
    !metadata.file_type().is_symlink()
}

fn regular(path: &Path) -> io::Result<bool> {
    let metadata = std::fs::symlink_metadata(path)?;
    Ok(metadata.is_file() && plain(&metadata))
}

#[derive(Debug, Clone)]
pub struct LinkedStore {
    dir: PathBuf,
}

impl LinkedStore {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn io(&self, path: &Path) -> impl Fn(io::Error) -> StoreError {
        let path = path.to_owned();
        move |error| StoreError::Io(path.clone(), error)
    }

    fn existing_dir(&self) -> Result<bool, StoreError> {
        match std::fs::symlink_metadata(&self.dir) {
            Ok(metadata) if metadata.is_dir() && plain(&metadata) => Ok(true),
            Ok(_) => Err(StoreError::NotADirectory(self.dir.clone())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(StoreError::Io(self.dir.clone(), error)),
        }
    }

    fn ensure_dir(&self) -> Result<(), StoreError> {
        if self.existing_dir()? {
            return Ok(());
        }
        if let Some(parent) = self.dir.parent() {
            std::fs::create_dir_all(parent).map_err(self.io(parent))?;
        }
        match crate::browser::create_private_dir(&self.dir, false) {
            Err(error) if error.kind() != io::ErrorKind::AlreadyExists => {
                return Err(StoreError::Io(self.dir.clone(), error));
            }
            _ => {}
        }
        self.existing_dir().map(drop)
    }

    fn entry_path(&self, file: &str) -> Result<PathBuf, StoreError> {
        let path = self.dir.join(file);
        if !safe_file_name(file) || path.parent() != Some(self.dir.as_path()) {
            return Err(StoreError::Escapes(path));
        }
        Ok(path)
    }

    fn toml_files(&self) -> Result<Vec<(String, PathBuf)>, StoreError> {
        if !self.existing_dir()? {
            return Ok(Vec::new());
        }
        let mut files = Vec::new();
        for entry in std::fs::read_dir(&self.dir).map_err(self.io(&self.dir))? {
            let entry = entry.map_err(self.io(&self.dir))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(SUFFIX) {
                files.push((name, entry.path()));
            }
        }
        files.sort();
        Ok(files)
    }

    pub fn load(&self) -> Result<Loaded, StoreError> {
        let mut loaded = Loaded::default();
        for (index, (name, path)) in self.toml_files()?.into_iter().enumerate() {
            if index >= MAX_LINKED {
                loaded.invalid.push(InvalidEntry {
                    addresses: address_of_file(&name).into_iter().collect(),
                    name: None,
                    file: path,
                    reason: format!("more than {MAX_LINKED} gateway files; this one is not read"),
                });
                continue;
            }
            match read_entry(&path, &name) {
                Ok(gateway) => loaded.gateways.push(gateway),
                Err(entry) => loaded.invalid.push(entry),
            }
        }
        let gateways = std::mem::take(&mut loaded.gateways);
        let damaged = loaded.invalid.clone();
        for gateway in &gateways {
            if let Some(entry) = damaged
                .iter()
                .find(|entry| entry.name.as_ref() == Some(&gateway.name))
            {
                loaded.invalid.push(InvalidEntry {
                    file: self
                        .dir
                        .join(file_name(&gateway.address).unwrap_or_default()),
                    name: Some(gateway.name.clone()),
                    addresses: vec![gateway.address.clone()],
                    reason: format!(
                        "the profile name \"{}\" is also used by the damaged file {}",
                        gateway.name,
                        entry.file.file_name().unwrap_or_default().to_string_lossy()
                    ),
                });
                continue;
            }
            let others: Vec<&LinkedGateway> = gateways
                .iter()
                .filter(|other| other.name == gateway.name && other.address != gateway.address)
                .collect();
            if others.is_empty() {
                loaded.gateways.push(gateway.clone());
                continue;
            }
            let files: Vec<String> = others
                .iter()
                .map(|other| file_name(&other.address).unwrap_or_default())
                .collect();
            loaded.invalid.push(InvalidEntry {
                file: self
                    .dir
                    .join(file_name(&gateway.address).unwrap_or_default()),
                name: Some(gateway.name.clone()),
                addresses: vec![gateway.address.clone()],
                reason: format!(
                    "the profile name \"{}\" is also used by {}",
                    gateway.name,
                    files.join(", ")
                ),
            });
        }
        loaded.gateways.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(loaded)
    }

    pub fn add(&self, gateway: &LinkedGateway) -> Result<PathBuf, StoreError> {
        self.add_with(gateway, |_| {})
    }

    fn add_with(
        &self,
        gateway: &LinkedGateway,
        before_publish: impl FnOnce(&Path),
    ) -> Result<PathBuf, StoreError> {
        let file = file_name(&gateway.address).map_err(StoreError::Unstorable)?;
        self.ensure_dir()?;
        let loaded = self.load()?;
        let taken = loaded
            .gateways
            .iter()
            .any(|known| known.name == gateway.name)
            || loaded
                .invalid
                .iter()
                .any(|entry| entry.name.as_ref() == Some(&gateway.name));
        if taken {
            return Err(StoreError::Exists(gateway.name.clone()));
        }
        if loaded.gateways.len() + loaded.invalid.len() >= MAX_LINKED {
            return Err(StoreError::Full);
        }
        let path = self.entry_path(&file)?;
        if std::fs::symlink_metadata(&path).is_ok() {
            return Err(StoreError::AddressTaken(path));
        }
        let mut text = format!(
            "# A gateway added from a gateinto:// link after confirmation.\n\
             # Remove it with `gateinto gateway forget {}`.\n\
             name = \"{}\"\nhost = \"{}\"\nport = {}\nportal_url = \"{}\"\n",
            gateway.name,
            gateway.name,
            gateway.address.host(),
            gateway.address.port(),
            gateway.portal_url
        );
        if let Some(approved_at) = gateway.approved_at {
            text.push_str(&format!("approved_at = {approved_at}\n"));
        }
        let temp = self.dir.join(format!(
            ".{}.{}.tmp",
            std::process::id(),
            ConfirmToken::random().map_err(self.io(&self.dir))?
        ));
        let written = write_new(&temp, text.as_bytes());
        if written.is_ok() {
            before_publish(&path);
        }
        let published = written.and_then(|()| publish(&temp, &path, text.as_bytes()));
        let _ = std::fs::remove_file(&temp);
        match published {
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return Err(StoreError::AddressTaken(path));
            }
            published => published.map_err(self.io(&path))?,
        }
        self.sync_dir()?;
        Ok(path)
    }

    pub fn forget(&self, name: &GatewayName) -> Result<Option<PathBuf>, StoreError> {
        let loaded = self.load()?;
        let Some(gateway) = loaded.gateways.iter().find(|gateway| &gateway.name == name) else {
            return Ok(None);
        };
        let path =
            self.entry_path(&file_name(&gateway.address).map_err(StoreError::Unstorable)?)?;
        if !regular(&path).map_err(self.io(&path))? {
            return Err(StoreError::NotRegular(path));
        }
        std::fs::remove_file(&path).map_err(self.io(&path))?;
        self.sync_dir()?;
        Ok(Some(path))
    }

    pub fn purge_candidates(&self) -> Result<Vec<PathBuf>, StoreError> {
        if !self.existing_dir()? {
            return Ok(Vec::new());
        }
        let mut files = Vec::new();
        for entry in std::fs::read_dir(&self.dir).map_err(self.io(&self.dir))? {
            let entry = entry.map_err(self.io(&self.dir))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = entry.path();
            let ours = name.ends_with(SUFFIX) || temp_file_name(&name);
            if ours && regular(&path).map_err(self.io(&path))? {
                files.push(path);
            }
        }
        files.sort();
        Ok(files)
    }

    pub fn remove(&self, files: &[PathBuf]) -> Result<(), StoreError> {
        for path in files {
            if path.parent() != Some(self.dir.as_path()) {
                return Err(StoreError::Escapes(path.clone()));
            }
            if !regular(path).map_err(self.io(path))? {
                return Err(StoreError::NotRegular(path.clone()));
            }
            std::fs::remove_file(path).map_err(self.io(path))?;
        }
        if self.existing_dir()? {
            let _ = std::fs::remove_dir(&self.dir);
        }
        Ok(())
    }

    fn sync_dir(&self) -> Result<(), StoreError> {
        #[cfg(unix)]
        std::fs::File::open(&self.dir)
            .and_then(|dir| dir.sync_all())
            .map_err(self.io(&self.dir))?;
        Ok(())
    }
}

fn read_entry(path: &Path, file: &str) -> Result<LinkedGateway, InvalidEntry> {
    let hint: Vec<GatewayAddress> = address_of_file(file).into_iter().collect();
    let invalid =
        |name: Option<GatewayName>, addresses: Vec<GatewayAddress>, reason: String| InvalidEntry {
            file: path.to_owned(),
            name,
            addresses,
            reason,
        };
    let not_regular = || invalid(None, hint.clone(), "not a regular file".to_owned());
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| invalid(None, hint.clone(), error.to_string()))?;
    if !metadata.is_file() || !plain(&metadata) {
        return Err(not_regular());
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    std::os::windows::fs::OpenOptionsExt::custom_flags(
        &mut options,
        windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
    );
    let opened = options
        .open(path)
        .map_err(|error| invalid(None, hint.clone(), error.to_string()))?;
    let same = opened.metadata().is_ok_and(|now| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            now.is_file() && now.dev() == metadata.dev() && now.ino() == metadata.ino()
        }
        #[cfg(not(unix))]
        {
            now.is_file() && plain(&now)
        }
    });
    if !same {
        return Err(not_regular());
    }
    let mut text = String::new();
    opened
        .take(MAX_FILE_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|error| invalid(None, hint.clone(), error.to_string()))?;
    if text.len() as u64 > MAX_FILE_BYTES {
        return Err(invalid(
            None,
            hint.clone(),
            format!("larger than {MAX_FILE_BYTES} bytes"),
        ));
    }
    let entry: Entry = toml::from_str(&text).map_err(|error| {
        let name = toml::from_str::<toml::Table>(&text)
            .ok()
            .and_then(|table| table.get("name")?.as_str()?.parse().ok());
        invalid(
            name,
            hint.clone(),
            error.to_string().trim_end().replace('\n', " "),
        )
    })?;
    let name = Some(entry.name.clone());
    let address = if entry.host.contains(':') {
        format!("[{}]:{}", entry.host, entry.port)
    } else {
        format!("{}:{}", entry.host, entry.port)
    };
    let address: GatewayAddress = address
        .parse()
        .map_err(|error| invalid(name.clone(), hint.clone(), format!("{error}")))?;
    let mut addresses = vec![address.clone()];
    addresses.extend(hint.iter().filter(|hint| **hint != address).cloned());
    if Origin::of(&entry.portal_url).is_none() {
        return Err(invalid(
            name,
            addresses,
            "portal_url has no https origin".to_owned(),
        ));
    }
    let canonical = file_name(&address)
        .map_err(|error| invalid(name.clone(), addresses.clone(), error.to_string()))?;
    if canonical != file {
        return Err(invalid(
            name,
            addresses,
            format!("the file of this gateway must be named {canonical}"),
        ));
    }
    Ok(LinkedGateway {
        name: entry.name,
        address,
        portal_url: entry.portal_url,
        approved_at: entry.approved_at,
    })
}

fn temp_file_name(name: &str) -> bool {
    let Some(middle) = name
        .strip_prefix('.')
        .and_then(|rest| rest.strip_suffix(".tmp"))
    else {
        return false;
    };
    middle.split_once('.').is_some_and(|(pid, random)| {
        !pid.is_empty()
            && pid.bytes().all(|b| b.is_ascii_digit())
            && random.len() == 32
            && random
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

#[cfg(unix)]
fn publish(temp: &Path, path: &Path, bytes: &[u8]) -> io::Result<()> {
    publish_with(temp, path, bytes, |from, to| std::fs::hard_link(from, to))
}

// A hard link publishes the complete file atomically and, unlike a rename, never replaces a
// file that appeared after the check; without hard links the file is created new in place.
#[cfg(unix)]
fn publish_with(
    temp: &Path,
    path: &Path,
    bytes: &[u8],
    link: impl Fn(&Path, &Path) -> io::Result<()>,
) -> io::Result<()> {
    match link(temp, path) {
        Err(error) if error.kind() != io::ErrorKind::AlreadyExists => write_new(path, bytes)
            .inspect_err(|error| {
                if error.kind() != io::ErrorKind::AlreadyExists {
                    let _ = std::fs::remove_file(path);
                }
            }),
        result => result,
    }
}

// A `\\?\` path is not normalised by Windows and may exceed MAX_PATH; only absolute
// paths without `/`, `.` or `..` keep their meaning with it.
#[cfg_attr(not(windows), allow(dead_code))]
fn verbatim(path: &str) -> String {
    let normal = !path.contains('/')
        && path
            .split('\\')
            .all(|component| component != "." && component != "..");
    if path.starts_with(r"\\?\") || path.starts_with(r"\\.\") || !normal {
        return path.to_owned();
    }
    let bytes = path.as_bytes();
    if bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\' {
        return format!(r"\\?\{path}");
    }
    if let Some(rest) = path.strip_prefix(r"\\") {
        let mut parts = rest.split('\\');
        if let (Some(server), Some(share)) = (parts.next(), parts.next())
            && !server.is_empty()
            && !share.is_empty()
        {
            return format!(r"\\?\UNC\{rest}");
        }
    }
    path.to_owned()
}

#[cfg(windows)]
fn publish(temp: &Path, path: &Path, _bytes: &[u8]) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};

    let wide = |path: &Path| {
        let path = match path.to_str() {
            Some(text) => PathBuf::from(verbatim(text)),
            None => path.to_owned(),
        };
        path.as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<u16>>()
    };
    let (from, to) = (wide(temp), wide(path));
    // Without MOVEFILE_REPLACE_EXISTING the move fails instead of replacing a file.
    // SAFETY: both buffers are NUL-terminated UTF-16 paths that outlive the call.
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_WRITE_THROUGH) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_760_000_000;

    fn address(text: &str) -> GatewayAddress {
        text.parse().unwrap()
    }

    fn name(text: &str) -> GatewayName {
        text.parse().unwrap()
    }

    fn gateway(profile: &str, host: &str) -> LinkedGateway {
        LinkedGateway {
            name: name(profile),
            address: address(host),
            portal_url: format!("https://{profile}.example/").parse().unwrap(),
            approved_at: Some(NOW),
        }
    }

    fn store() -> LinkedStore {
        static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("gateinto-store-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        LinkedStore::new(root.join("config").join(DIR_NAME))
    }

    fn entry(profile: &str, host: &str, port: u16) -> String {
        format!(
            "name = \"{profile}\"\nhost = \"{host}\"\nport = {port}\n\
             portal_url = \"https://{profile}.example/\"\napproved_at = 1\n"
        )
    }

    fn plant(store: &LinkedStore, file: &str, text: &str) -> PathBuf {
        std::fs::create_dir_all(store.dir()).unwrap();
        let path = store.dir().join(file);
        std::fs::write(&path, text).unwrap();
        path
    }

    fn files(store: &LinkedStore) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(store.dir())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn file_names_come_from_the_canonical_address_only() {
        for (text, expected) in [
            ("proxy.corp.example", "proxy.corp.example.toml"),
            ("Proxy.Corp.Example:443", "proxy.corp.example.toml"),
            ("proxy.corp.example:8443", "proxy.corp.example_8443.toml"),
            ("10.0.0.1:3128", "10.0.0.1_3128.toml"),
            ("10.0.0.1", "10.0.0.1.toml"),
            ("[2001:db8::1]:3128", "2001-db8--1_3128.toml"),
            ("[2001:DB8:0:0:0:0:0:1]:3128", "2001-db8--1_3128.toml"),
            ("[::ffff:10.0.0.1]:3128", "10.0.0.1_3128.toml"),
            ("[::1]", "--1.toml"),
        ] {
            assert_eq!(file_name(&address(text)).as_deref(), Ok(expected), "{text}");
        }
    }

    #[test]
    fn file_names_longer_than_255_bytes_are_refused() {
        let host = |len: usize| {
            let mut host = format!("{}example", "a.".repeat((len - 7) / 2));
            if host.len() < len {
                host.insert(0, 'b');
            }
            assert_eq!(host.len(), len);
            host
        };
        assert_eq!(file_name(&address(&host(250))).unwrap().len(), 255);
        assert!(file_name(&address(&host(251))).is_err());
        assert_eq!(
            file_name(&address(&format!("{}:65535", host(244))))
                .unwrap()
                .len(),
            255
        );
        assert!(file_name(&address(&format!("{}:65535", host(245)))).is_err());
        assert!(file_name(&address(&host(253))).is_err());
    }

    #[test]
    fn only_plain_single_component_file_names_pass() {
        for name in [
            "proxy.example.toml",
            "10.0.0.1_3128.toml",
            "2001-db8--1.toml",
        ] {
            assert!(safe_file_name(name), "{name}");
        }
        for name in [
            "",
            ".toml",
            "..",
            "a..b.toml",
            "../a.toml",
            "a/b.toml",
            "a\\b.toml",
            "A.toml",
            "a b.toml",
            "a:b.toml",
            "a.toml ",
            "a.toml.",
            "a.txt",
            "caf\u{e9}.toml",
            &format!("{}.toml", "a".repeat(251)),
        ] {
            assert!(!safe_file_name(name), "{name:?}");
        }
    }

    #[test]
    fn file_names_map_back_to_their_address() {
        for text in [
            "proxy.corp.example",
            "proxy.corp.example:8443",
            "10.0.0.1:3128",
            "[2001:db8::1]:3128",
            "[::1]",
        ] {
            let address = address(text);
            assert_eq!(
                address_of_file(&file_name(&address).unwrap()),
                Some(address),
                "{text}"
            );
        }
        for file in [
            "x_443.toml",
            "x_0.toml",
            "x.txt",
            "nul.example.toml",
            "a_b_1.toml",
        ] {
            assert_eq!(address_of_file(file), None, "{file}");
        }
    }

    #[test]
    fn a_missing_directory_is_empty_and_adding_creates_a_private_one() {
        let store = store();
        assert_eq!(store.load().unwrap(), Loaded::default());
        let path = store
            .add(&gateway("newco", "Proxy.Newco.Example:8443"))
            .unwrap();
        assert_eq!(path, store.dir().join("proxy.newco.example_8443.toml"));
        store.add(&gateway("other", "[2001:db8::1]")).unwrap();
        assert_eq!(
            files(&store),
            vec!["2001-db8--1.toml", "proxy.newco.example_8443.toml"]
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "# A gateway added from a gateinto:// link after confirmation.\n\
             # Remove it with `gateinto gateway forget newco`.\n\
             name = \"newco\"\nhost = \"proxy.newco.example\"\nport = 8443\n\
             portal_url = \"https://newco.example/\"\napproved_at = 1760000000\n"
        );
        assert_eq!(
            store.load().unwrap(),
            Loaded {
                gateways: vec![
                    gateway("newco", "proxy.newco.example:8443"),
                    gateway("other", "[2001:db8::1]"),
                ],
                invalid: Vec::new(),
            }
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(store.dir()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
    }

    #[test]
    fn adding_never_overwrites_a_name_or_an_address() {
        let store = store();
        store.add(&gateway("newco", "a.example")).unwrap();
        assert!(matches!(
            store.add(&gateway("newco", "b.example")),
            Err(StoreError::Exists(_))
        ));
        let planted = plant(&store, "c.example.toml", "garbage");
        assert!(matches!(
            store.add(&gateway("other", "c.example")),
            Err(StoreError::AddressTaken(path)) if path == planted
        ));
        assert_eq!(std::fs::read_to_string(&planted).unwrap(), "garbage");
        assert_eq!(files(&store), vec!["a.example.toml", "c.example.toml"]);
    }

    #[test]
    fn windows_paths_get_the_verbatim_prefix_for_long_names() {
        for (path, expected) in [
            (
                r"C:\Users\me\AppData\Roaming\Gateinto\gateways\a.toml",
                r"\\?\C:\Users\me\AppData\Roaming\Gateinto\gateways\a.toml",
            ),
            (r"d:\g\a.toml", r"\\?\d:\g\a.toml"),
            (
                r"\\server\share\me\Gateinto\gateways\a.toml",
                r"\\?\UNC\server\share\me\Gateinto\gateways\a.toml",
            ),
            (r"\\?\C:\g\a.toml", r"\\?\C:\g\a.toml"),
            (
                r"\\?\UNC\server\share\a.toml",
                r"\\?\UNC\server\share\a.toml",
            ),
            (r"\\.\pipe\x", r"\\.\pipe\x"),
            (r"C:/g/a.toml", r"C:/g/a.toml"),
            (r"C:\g\..\a.toml", r"C:\g\..\a.toml"),
            (r"C:\g\.\a.toml", r"C:\g\.\a.toml"),
            (r"C:a.toml", r"C:a.toml"),
            (r"\g\a.toml", r"\g\a.toml"),
            (r"g\a.toml", r"g\a.toml"),
            (r"\\server", r"\\server"),
            (r"\\server\share", r"\\?\UNC\server\share"),
        ] {
            assert_eq!(verbatim(path), expected, "{path}");
        }
    }

    #[test]
    fn the_publish_step_never_overwrites_a_file_that_appears_late() {
        let store = store();
        let late = store.add_with(&gateway("newco", "a.example"), |path| {
            std::fs::write(path, "planted").unwrap();
        });
        let path = store.dir().join("a.example.toml");
        assert!(
            matches!(&late, Err(StoreError::AddressTaken(taken)) if *taken == path),
            "{late:?}"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "planted");
        assert_eq!(files(&store), vec!["a.example.toml"]);
    }

    #[cfg(unix)]
    #[test]
    fn without_hard_links_the_file_is_created_new_in_place() {
        let store = store();
        std::fs::create_dir_all(store.dir()).unwrap();
        let (temp, path) = (
            store.dir().join(".1.ab.tmp"),
            store.dir().join("a.example.toml"),
        );
        let unsupported = |_: &Path, _: &Path| Err(io::Error::from(io::ErrorKind::Unsupported));
        std::fs::write(&temp, "content").unwrap();
        publish_with(&temp, &path, b"content", unsupported).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "content");
        let again = publish_with(&temp, &path, b"other", unsupported).unwrap_err();
        assert_eq!(again.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "content");
        let linked = publish_with(&temp, &path, b"other", |from, to| {
            std::fs::hard_link(from, to)
        });
        assert_eq!(linked.unwrap_err().kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn a_valid_file_sharing_its_name_with_a_damaged_one_is_disabled_too() {
        let store = store();
        store.add(&gateway("same", "a.example")).unwrap();
        plant(
            &store,
            "b.example.toml",
            &format!("{}ca_file = \"x\"\n", entry("same", "b.example", 443)),
        );
        store.add(&gateway("other", "c.example")).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.gateways, vec![gateway("other", "c.example")]);
        assert_eq!(loaded.invalid.len(), 2);
        let disabled = loaded
            .invalid
            .iter()
            .find(|entry| entry.file == store.dir().join("a.example.toml"))
            .unwrap();
        assert!(
            disabled.reason.contains("b.example.toml"),
            "{}",
            disabled.reason
        );
    }

    #[test]
    fn purging_also_takes_leftover_temporary_files() {
        let store = store();
        store.add(&gateway("a", "a.example")).unwrap();
        let temp = plant(
            &store,
            &format!(".{}.{}.tmp", 4242, "0123456789abcdef0123456789abcdef"),
            "partial",
        );
        plant(&store, ".x.tmp", "foreign");
        plant(&store, ".1.0123.tmp", "short");
        std::fs::create_dir(store.dir().join(".2.0123456789abcdef0123456789abcdef.tmp")).unwrap();
        let candidates = store.purge_candidates().unwrap();
        assert_eq!(candidates, vec![temp, store.dir().join("a.example.toml")]);
        store.remove(&candidates).unwrap();
        assert_eq!(
            files(&store),
            vec![
                ".1.0123.tmp",
                ".2.0123456789abcdef0123456789abcdef.tmp",
                ".x.tmp"
            ]
        );

        let store = self::store();
        store.add(&gateway("a", "a.example")).unwrap();
        plant(&store, ".7.0123456789abcdef0123456789abcdef.tmp", "partial");
        let candidates = store.purge_candidates().unwrap();
        store.remove(&candidates).unwrap();
        assert!(!store.dir().exists());
    }

    #[test]
    fn the_store_holds_a_bounded_number_of_gateways() {
        let store = store();
        for n in 0..MAX_LINKED {
            store
                .add(&gateway(&format!("g{n}"), &format!("g{n}.example")))
                .unwrap();
        }
        let error = store.add(&gateway("more", "more.example")).unwrap_err();
        assert!(matches!(error, StoreError::Full), "{error}");
        assert!(error.to_string().contains("gateway forget"), "{error}");
        assert_eq!(store.load().unwrap().gateways.len(), MAX_LINKED);
    }

    #[test]
    fn forgetting_deletes_only_the_file_of_that_name() {
        let store = store();
        assert_eq!(store.forget(&name("newco")).unwrap(), None);
        store.add(&gateway("newco", "a.example")).unwrap();
        store.add(&gateway("other", "b.example")).unwrap();
        plant(
            &store,
            "c.example.toml",
            &entry("broken", "c.example", 443).replace("approved_at", "ca_file"),
        );
        assert_eq!(
            store.forget(&name("newco")).unwrap(),
            Some(store.dir().join("a.example.toml"))
        );
        assert_eq!(store.forget(&name("newco")).unwrap(), None);
        assert_eq!(store.forget(&name("broken")).unwrap(), None);
        assert_eq!(files(&store), vec!["b.example.toml", "c.example.toml"]);
    }

    #[test]
    fn an_invalid_file_disables_only_its_own_entry() {
        let store = store();
        store.add(&gateway("good", "a.example")).unwrap();
        let bad = plant(
            &store,
            "b.example_8443.toml",
            &format!("{}ca_file = \"x.pem\"\n", entry("bad", "b.example", 8443)),
        );
        let garbage = plant(&store, "garbage.example.toml", "not toml");
        let loaded = store.load().unwrap();
        assert_eq!(loaded.gateways, vec![gateway("good", "a.example")]);
        assert_eq!(loaded.invalid.len(), 2);
        let bad_entry = loaded.invalid.iter().find(|e| e.file == bad).unwrap();
        assert_eq!(bad_entry.name, Some(name("bad")));
        assert_eq!(bad_entry.addresses, vec![address("b.example:8443")]);
        assert!(bad_entry.reason.contains("ca_file"), "{}", bad_entry.reason);
        let garbage_entry = loaded.invalid.iter().find(|e| e.file == garbage).unwrap();
        assert_eq!(garbage_entry.name, None);
        assert_eq!(garbage_entry.addresses, vec![address("garbage.example")]);
        assert!(
            garbage_entry
                .to_string()
                .starts_with(&format!("{}: ", garbage.display())),
            "{garbage_entry}"
        );
    }

    #[test]
    fn a_renamed_or_planted_file_is_invalid() {
        let store = store();
        let renamed = plant(&store, "c.example.toml", &entry("newco", "a.example", 443));
        let explicit_port = plant(
            &store,
            "d.example_443.toml",
            &entry("other", "d.example", 443),
        );
        let loaded = store.load().unwrap();
        assert!(loaded.gateways.is_empty());
        let entry = loaded.invalid.iter().find(|e| e.file == renamed).unwrap();
        assert!(entry.reason.contains("a.example.toml"), "{}", entry.reason);
        assert_eq!(entry.name, Some(name("newco")));
        assert_eq!(
            entry.addresses,
            vec![address("a.example"), address("c.example")]
        );
        let entry = loaded
            .invalid
            .iter()
            .find(|e| e.file == explicit_port)
            .unwrap();
        assert!(entry.reason.contains("d.example.toml"), "{}", entry.reason);
    }

    #[test]
    fn a_profile_name_in_two_files_disables_both() {
        let store = store();
        plant(&store, "a.example.toml", &entry("same", "a.example", 443));
        plant(&store, "b.example.toml", &entry("same", "b.example", 443));
        store.add(&gateway("other", "c.example")).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.gateways, vec![gateway("other", "c.example")]);
        assert_eq!(loaded.invalid.len(), 2);
        for entry in &loaded.invalid {
            assert_eq!(entry.name, Some(name("same")));
            assert!(entry.reason.contains("also"), "{}", entry.reason);
        }
    }

    #[test]
    fn entries_must_be_small_regular_files_and_others_are_ignored() {
        let store = store();
        plant(
            &store,
            "big.example.toml",
            &format!(
                "{}# {}\n",
                entry("big", "big.example", 443),
                "x".repeat(MAX_FILE_BYTES as usize)
            ),
        );
        std::fs::create_dir(store.dir().join("dir.example.toml")).unwrap();
        plant(&store, "README.txt", "hello");
        plant(&store, ".x.tmp", "partial");
        store.add(&gateway("good", "a.example")).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.gateways, vec![gateway("good", "a.example")]);
        let reasons: Vec<&str> = loaded.invalid.iter().map(|e| e.reason.as_str()).collect();
        assert_eq!(loaded.invalid.len(), 2, "{reasons:?}");
        assert!(
            reasons.iter().any(|r| r.contains("larger than")),
            "{reasons:?}"
        );
        assert!(
            reasons.iter().any(|r| r.contains("not a regular file")),
            "{reasons:?}"
        );
    }

    #[test]
    fn files_beyond_the_limit_are_not_read() {
        let store = store();
        for n in 0..MAX_LINKED + 2 {
            plant(
                &store,
                &format!("g{n:02}.example.toml"),
                &entry(&format!("g{n:02}"), &format!("g{n:02}.example"), 443),
            );
        }
        let loaded = store.load().unwrap();
        assert_eq!(loaded.gateways.len(), MAX_LINKED);
        assert_eq!(loaded.invalid.len(), 2);
        assert!(
            loaded.invalid[0].reason.contains("more than"),
            "{}",
            loaded.invalid[0].reason
        );
    }

    #[cfg(unix)]
    #[test]
    fn links_are_never_followed() {
        let store = store();
        let outside = store.dir().parent().unwrap().join("outside.toml");
        std::fs::create_dir_all(store.dir()).unwrap();
        std::fs::write(&outside, entry("linked", "l.example", 443)).unwrap();
        std::os::unix::fs::symlink(&outside, store.dir().join("l.example.toml")).unwrap();
        let loaded = store.load().unwrap();
        assert!(loaded.gateways.is_empty());
        assert!(loaded.invalid[0].reason.contains("not a regular file"));
        assert_eq!(store.purge_candidates().unwrap(), Vec::<PathBuf>::new());

        let real = store.dir().parent().unwrap().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::write(real.join("a.example.toml"), entry("a", "a.example", 443)).unwrap();
        let linked_dir = LinkedStore::new(store.dir().parent().unwrap().join("linked-dir"));
        std::os::unix::fs::symlink(&real, linked_dir.dir()).unwrap();
        assert!(matches!(
            linked_dir.load(),
            Err(StoreError::NotADirectory(_))
        ));
        assert!(matches!(
            linked_dir.add(&gateway("b", "b.example")),
            Err(StoreError::NotADirectory(_))
        ));
        assert!(linked_dir.purge_candidates().is_err());
        assert_eq!(std::fs::read_dir(&real).unwrap().count(), 1);
    }

    #[test]
    fn a_file_in_place_of_the_directory_is_refused() {
        let store = store();
        std::fs::create_dir_all(store.dir().parent().unwrap()).unwrap();
        std::fs::write(store.dir(), "").unwrap();
        assert!(matches!(store.load(), Err(StoreError::NotADirectory(_))));
        assert!(matches!(
            store.add(&gateway("a", "a.example")),
            Err(StoreError::NotADirectory(_))
        ));
    }

    #[test]
    fn purging_takes_the_gateway_files_and_then_the_empty_directory() {
        let store = store();
        assert_eq!(store.purge_candidates().unwrap(), Vec::<PathBuf>::new());
        store.add(&gateway("a", "a.example")).unwrap();
        let broken = plant(&store, "b.example.toml", "garbage");
        let mut expected = vec![store.dir().join("a.example.toml"), broken];
        expected.sort();
        assert_eq!(store.purge_candidates().unwrap(), expected);
        store.remove(&expected).unwrap();
        assert!(!store.dir().exists());

        store.add(&gateway("a", "a.example")).unwrap();
        plant(&store, "notes.txt", "keep");
        let candidates = store.purge_candidates().unwrap();
        store.remove(&candidates).unwrap();
        assert_eq!(files(&store), vec!["notes.txt"]);
    }
}
