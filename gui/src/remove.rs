use std::path::PathBuf;

use gateinto::config::{ConfigFile, GatewayName};
use gateinto::link::store::{ForgetError, LinkedStore, StoreError};
use gateinto::link::{Known, KnownGateway, Source};

use crate::gateways;
use crate::i18n::{Text, fill};

pub const TITLE: Text = Text::RemoveGateway;
pub const REMOVE: Text = Text::Remove;
pub const KEEPS: Text = Text::RemoveKeeps;
const ASK: Text = Text::RemoveAsk;
const NO_FOLDER: Text = Text::NoFolder;
const UNLISTED: Text = Text::Unlisted;
const DAMAGED: Text = Text::Damaged;
const CONFIGURED: Text = Text::ConfigReadOnly;
const MISSING: Text = Text::NotAddedHere;
const AMBIGUOUS: Text = Text::NameHeldTwice;
const NOT_REMOVED: Text = Text::NotRemoved;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Removal {
    name: GatewayName,
    failure: Option<Text>,
}

impl Removal {
    pub fn new(name: GatewayName) -> Self {
        Self {
            name,
            failure: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prompt {
    pub question: String,
    pub failure: Option<&'static str>,
}

pub fn removable(gateway: &KnownGateway) -> bool {
    gateway.source == Source::Linked
}

pub fn prompt(listing: &Result<Known, String>, removal: &Removal) -> Option<Prompt> {
    let gateway = listing
        .as_ref()
        .ok()?
        .gateways
        .iter()
        .find(|gateway| gateway.name == removal.name && removable(gateway))?;
    Some(Prompt {
        question: fill(ASK, &[&gateways::label(gateway)]),
        failure: removal.failure.map(Text::get),
    })
}

pub fn commit(
    removal: &mut Removal,
    file: &Result<ConfigFile, String>,
    dir: Option<PathBuf>,
) -> bool {
    removal.failure = match (file, dir) {
        (Err(_), _) => Some(UNLISTED),
        (_, None) => Some(NO_FOLDER),
        (Ok(file), Some(dir)) => match LinkedStore::new(dir).forget_gateway(file, &removal.name) {
            Ok(_) => None,
            Err(ForgetError::Damaged(_)) => Some(DAMAGED),
            Err(ForgetError::Configured) => Some(CONFIGURED),
            Err(ForgetError::Missing) => Some(MISSING),
            Err(ForgetError::Store(StoreError::Ambiguous(..))) => Some(AMBIGUOUS),
            Err(ForgetError::Store(_)) => Some(NOT_REMOVED),
        },
    };
    removal.failure.is_none()
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};

    use gateinto::link::LinkedGateway;
    use gateinto::link::store::DIR_NAME;

    use super::*;
    use crate::i18n::{Language, speaking, tr};

    const PROFILE: &str = "g-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd";
    const CONFIG: &str = "[gateways.office]\nhost = \"proxy.example.com\"\n";

    fn name(text: &str) -> GatewayName {
        text.parse().unwrap()
    }

    fn known(text: &str, host: &str, source: Source) -> KnownGateway {
        KnownGateway {
            name: name(text),
            host: Some(host.to_owned()),
            port: Some(443),
            portal_url: None,
            route: gateinto::proxy::Route::Gateway,
            source,
        }
    }

    fn listing() -> Result<Known, String> {
        Ok(Known {
            gateways: vec![
                known("office", "proxy.example.com", Source::Config),
                known("lab", "lab.example.net", Source::Linked),
                known(PROFILE, "edge.example", Source::Linked),
            ],
            ..Known::default()
        })
    }

    fn scratch() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("gateinto-gui-remove-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn linked(profile: &str, host: &str) -> LinkedGateway {
        LinkedGateway {
            name: name(profile),
            address: host.parse().unwrap(),
            portal_url: None,
            approved_at: Some(1),
        }
    }

    fn files(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    fn config() -> Result<ConfigFile, String> {
        Ok(ConfigFile::parse(CONFIG).unwrap())
    }

    fn failed(removal: &Removal) -> Option<Text> {
        removal.failure
    }

    #[test]
    fn only_gateways_added_on_this_device_can_be_removed() {
        let listing = listing();
        let gateways = &listing.as_ref().unwrap().gateways;
        assert_eq!(
            gateways.iter().map(removable).collect::<Vec<_>>(),
            [false, true, true]
        );
        for text in ["office", "nope"] {
            assert_eq!(prompt(&listing, &Removal::new(name(text))), None, "{text}");
        }
        let unreadable = Err("broken".to_owned());
        assert_eq!(prompt(&unreadable, &Removal::new(name("lab"))), None);
    }

    #[test]
    fn the_prompt_names_the_gateway_as_the_list_shows_it() {
        let lab = prompt(&listing(), &Removal::new(name("lab"))).unwrap();
        assert_eq!(
            lab.question,
            "Remove \"lab\" from the gateways added on this device?"
        );
        assert_eq!(lab.failure, None);
        let edge = prompt(&listing(), &Removal::new(name(PROFILE))).unwrap();
        assert!(edge.question.contains("\"edge.example\""), "{edge:?}");
        assert!(!edge.question.contains(PROFILE));
    }

    #[test]
    fn the_prompt_speaks_chinese() {
        let _zh = speaking(Language::Chinese);
        let lab = prompt(&listing(), &Removal::new(name("lab"))).unwrap();
        assert_eq!(lab.question, "要從這台裝置上新增的閘道中移除「lab」嗎？");
        assert_eq!(tr(REMOVE), "移除");
    }

    #[test]
    fn committing_deletes_only_the_file_of_that_gateway() {
        let root = scratch();
        let dir = root.join(DIR_NAME);
        let store = LinkedStore::new(dir.clone());
        store.add(&linked("lab", "lab.example.net")).unwrap();
        store.add(&linked("edge", "edge.example")).unwrap();
        std::fs::write(dir.join("notes.txt"), b"keep").unwrap();
        std::fs::write(root.join("gateinto.toml"), CONFIG).unwrap();
        std::fs::write(root.join("device.key"), b"key").unwrap();
        let mut removal = Removal::new(name("lab"));
        assert!(commit(&mut removal, &config(), Some(dir.clone())));
        assert_eq!(failed(&removal), None);
        assert_eq!(files(&dir), ["edge.example.toml", "notes.txt"]);
        assert_eq!(files(&root), ["device.key", "gateinto.toml", DIR_NAME]);
        assert_eq!(
            std::fs::read_to_string(root.join("gateinto.toml")).unwrap(),
            CONFIG
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn committing_refuses_what_the_command_line_refuses() {
        let root = scratch();
        let dir = root.join(DIR_NAME);
        let store = LinkedStore::new(dir.clone());
        store.add(&linked("lab", "lab.example.net")).unwrap();
        std::fs::write(
            dir.join("c.example.toml"),
            "name = \"broken\"\nhost = \"c.example\"\nport = 443\nca_file = \"x\"\n",
        )
        .unwrap();
        for host in ["d.example", "e.example"] {
            std::fs::write(
                dir.join(format!("{host}.toml")),
                format!("name = \"twin\"\nhost = \"{host}\"\nport = 443\n"),
            )
            .unwrap();
        }
        let before = files(&dir);
        for (text, file, dir, expected) in [
            ("lab", Err("broken".to_owned()), Some(dir.clone()), UNLISTED),
            ("lab", config(), None, NO_FOLDER),
            ("broken", config(), Some(dir.clone()), DAMAGED),
            ("twin", config(), Some(dir.clone()), AMBIGUOUS),
            ("office", config(), Some(dir.clone()), CONFIGURED),
            ("nope", config(), Some(dir.clone()), MISSING),
        ] {
            let mut removal = Removal::new(name(text));
            assert!(!commit(&mut removal, &file, dir), "{text}");
            assert_eq!(failed(&removal), Some(expected), "{text}");
        }
        assert_eq!(files(&root.join(DIR_NAME)), before);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn committing_to_an_unusable_folder_gets_fixed_wording() {
        let root = scratch();
        let dir = root.join(DIR_NAME);
        std::fs::write(&dir, b"").unwrap();
        let mut removal = Removal::new(name("lab"));
        assert!(!commit(&mut removal, &config(), Some(dir.clone())));
        assert_eq!(failed(&removal), Some(NOT_REMOVED));
        assert!(std::fs::read(&dir).unwrap().is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_failure_shows_in_the_prompt_until_the_next_try_succeeds() {
        let root = scratch();
        let dir = root.join(DIR_NAME);
        let mut removal = Removal::new(name("lab"));
        assert!(!commit(&mut removal, &config(), None));
        let shown = prompt(&listing(), &removal).unwrap();
        assert_eq!(shown.failure, Some(NO_FOLDER.english()));
        LinkedStore::new(dir.clone())
            .add(&linked("lab", "lab.example.net"))
            .unwrap();
        assert!(commit(&mut removal, &config(), Some(dir)));
        assert_eq!(prompt(&listing(), &removal).unwrap().failure, None);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failures_and_notes_get_fixed_wording_without_paths() {
        for text in [
            NO_FOLDER,
            UNLISTED,
            DAMAGED,
            CONFIGURED,
            MISSING,
            AMBIGUOUS,
            NOT_REMOVED,
            KEEPS,
        ] {
            for word in ["link", "gateinto", "/", "\\", "{0}"] {
                assert!(!text.english().contains(word), "{text:?}");
                assert!(!text.chinese().contains(word), "{text:?}");
            }
        }
    }
}
