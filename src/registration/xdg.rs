use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Roots {
    pub(crate) config_home: Option<PathBuf>,
    pub(crate) config_dirs: Vec<PathBuf>,
    pub(crate) data_home: Option<PathBuf>,
    pub(crate) data_dirs: Vec<PathBuf>,
    pub(crate) desktops: Vec<String>,
}

impl Roots {
    pub(crate) fn from_env(env: impl Fn(&str) -> Option<OsString>) -> Self {
        let absolute = |name| {
            env(name)
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
        };
        let home = absolute("HOME");
        let home_dir = |name, default: &str| {
            absolute(name).or_else(|| home.as_ref().map(|home| home.join(default)))
        };
        let dirs = |name, defaults: &[&str]| {
            let dirs: Vec<PathBuf> = env(name)
                .map(|value| {
                    std::env::split_paths(&value)
                        .filter(|path| path.is_absolute())
                        .collect()
                })
                .unwrap_or_default();
            if dirs.is_empty() {
                defaults.iter().map(PathBuf::from).collect()
            } else {
                dirs
            }
        };
        Self {
            config_home: home_dir("XDG_CONFIG_HOME", ".config"),
            config_dirs: dirs("XDG_CONFIG_DIRS", &["/etc/xdg"]),
            data_home: home_dir("XDG_DATA_HOME", ".local/share"),
            data_dirs: dirs("XDG_DATA_DIRS", &["/usr/local/share", "/usr/share"]),
            desktops: env("XDG_CURRENT_DESKTOP")
                .map(|value| desktops(&value))
                .unwrap_or_default(),
        }
    }
}

fn desktops(value: &OsStr) -> Vec<String> {
    value
        .as_bytes()
        .split(|&byte| byte == b':')
        .filter_map(|name| std::str::from_utf8(name).ok())
        .filter(|name| !name.is_empty() && !name.contains('/'))
        .map(str::to_ascii_lowercase)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;

    fn roots(vars: &[(&str, &str)]) -> Roots {
        Roots::from_env(|name| {
            vars.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| OsString::from(value))
        })
    }

    fn paths(paths: &[&str]) -> Vec<PathBuf> {
        paths.iter().map(PathBuf::from).collect()
    }

    #[test]
    fn unset_variables_fall_back_to_the_defaults_under_home() {
        assert_eq!(
            roots(&[("HOME", "/home/me")]),
            Roots {
                config_home: Some(PathBuf::from("/home/me/.config")),
                config_dirs: paths(&["/etc/xdg"]),
                data_home: Some(PathBuf::from("/home/me/.local/share")),
                data_dirs: paths(&["/usr/local/share", "/usr/share"]),
                desktops: Vec::new(),
            }
        );
    }

    #[test]
    fn absolute_values_are_used_in_order() {
        assert_eq!(
            roots(&[
                ("HOME", "/home/me"),
                ("XDG_CONFIG_HOME", "/cfg"),
                ("XDG_CONFIG_DIRS", "/etc/a:/etc/b"),
                ("XDG_DATA_HOME", "/data"),
                ("XDG_DATA_DIRS", "/share/a:/share/b"),
                ("XDG_CURRENT_DESKTOP", "ubuntu:GNOME"),
            ]),
            Roots {
                config_home: Some(PathBuf::from("/cfg")),
                config_dirs: paths(&["/etc/a", "/etc/b"]),
                data_home: Some(PathBuf::from("/data")),
                data_dirs: paths(&["/share/a", "/share/b"]),
                desktops: vec!["ubuntu".to_owned(), "gnome".to_owned()],
            }
        );
    }

    #[test]
    fn empty_values_fall_back_to_the_defaults() {
        assert_eq!(
            roots(&[
                ("HOME", "/home/me"),
                ("XDG_CONFIG_HOME", ""),
                ("XDG_CONFIG_DIRS", ""),
                ("XDG_DATA_HOME", ""),
                ("XDG_DATA_DIRS", ""),
                ("XDG_CURRENT_DESKTOP", ""),
            ]),
            roots(&[("HOME", "/home/me")])
        );
    }

    #[test]
    fn relative_values_are_ignored() {
        assert_eq!(
            roots(&[
                ("HOME", "/home/me"),
                ("XDG_CONFIG_HOME", "cfg"),
                ("XDG_CONFIG_DIRS", "etc:/etc/a::./b"),
                ("XDG_DATA_HOME", "./data"),
                ("XDG_DATA_DIRS", "share:../share"),
            ]),
            Roots {
                config_dirs: paths(&["/etc/a"]),
                ..roots(&[("HOME", "/home/me")])
            }
        );
    }

    #[test]
    fn without_an_absolute_home_only_absolute_xdg_homes_are_known() {
        for home in [None, Some(""), Some("home/me")] {
            let mut vars = vec![("XDG_DATA_HOME", "/data")];
            vars.extend(home.map(|home| ("HOME", home)));
            let roots = roots(&vars);
            assert_eq!(roots.config_home, None, "{home:?}");
            assert_eq!(roots.data_home, Some(PathBuf::from("/data")), "{home:?}");
            assert_eq!(roots.config_dirs, paths(&["/etc/xdg"]), "{home:?}");
        }
    }

    #[test]
    fn desktop_names_that_cannot_name_a_file_are_dropped() {
        assert_eq!(
            roots(&[("XDG_CURRENT_DESKTOP", "KDE::../x:a/b:X-Cinnamon")]).desktops,
            vec!["kde".to_owned(), "x-cinnamon".to_owned()]
        );
        let desktops = Roots::from_env(|name| {
            (name == "XDG_CURRENT_DESKTOP").then(|| OsString::from_vec(b"a\xff:sway".to_vec()))
        })
        .desktops;
        assert_eq!(desktops, vec!["sway".to_owned()]);
    }
}
