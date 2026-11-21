use super::{PinnedFile, X86, X86_64, sha256};

const MANIFEST: &str = include_str!("../../../packaging/wix/windivert.txt");
const VERIFY: &str = include_str!("../../../packaging/wix/windivert.ps1");
const BUILD: &str = include_str!("../../../packaging/wix/build.ps1");
const WXS: &str = include_str!("../../../packaging/wix/gateinto.wxs");
const FETCH: &str = include_str!("../../../.github/scripts/fetch-windivert.ps1");
const CI: &str = include_str!("../../../.github/workflows/ci.yml");
const RELEASE: &str = include_str!("../../../.github/workflows/release.yml");
const DESIGN: &str = include_str!("../../../docs/design/transparent-session.md");

const RELEASE_DIR: &str = "WinDivert-2.2.2-A";
const ARCHIVE: &str = "WinDivert-2.2.2-A.zip";
const LICENSE: &str = "WinDivert-LICENSE.txt";
const ARCHES: [(&str, &[PinnedFile]); 2] = [("x64", X86_64), ("x86", X86)];
const X86_ONLY: &str = r#"<?if $(sys.BUILDARCH) = "x86" ?>"#;

#[derive(Debug)]
struct Row {
    kind: &'static str,
    source: &'static str,
    name: &'static str,
    sha256: [u8; 32],
}

fn rows() -> Vec<Row> {
    MANIFEST
        .lines()
        .map(|line| {
            let fields: Vec<&str> = line.split(' ').filter(|field| !field.is_empty()).collect();
            let [kind, source, name, digest] = fields[..] else {
                panic!("{line}");
            };
            Row {
                kind,
                source,
                name,
                sha256: sha256(digest),
            }
        })
        .collect()
}

fn of(kind: &str) -> Vec<Row> {
    rows().into_iter().filter(|row| row.kind == kind).collect()
}

fn named(files: &[PinnedFile]) -> Vec<(&str, [u8; 32])> {
    files.iter().map(|file| (file.name, file.sha256)).collect()
}

#[test]
fn the_manifest_names_the_pinned_files_of_each_arch_in_the_release() {
    for (arch, pinned) in ARCHES {
        let files: Vec<Row> = of(arch)
            .into_iter()
            .filter(|row| row.name != LICENSE)
            .collect();
        let manifest: Vec<_> = files.iter().map(|row| (row.name, row.sha256)).collect();
        assert_eq!(manifest, named(pinned), "{arch}");
        for row in files {
            assert_eq!(row.source, format!("{RELEASE_DIR}/{arch}/{}", row.name));
        }
    }
}

#[test]
fn each_arch_also_installs_the_license_of_the_release() {
    let licenses: Vec<Row> = rows()
        .into_iter()
        .filter(|row| row.name == LICENSE)
        .collect();
    assert_eq!(
        licenses.iter().map(|row| row.kind).collect::<Vec<_>>(),
        ["x64", "x86"]
    );
    for row in &licenses {
        assert_eq!(row.source, format!("{RELEASE_DIR}/LICENSE"));
        assert_eq!(row.sha256, licenses[0].sha256);
    }
}

fn designed_archive_digest() -> &'static str {
    let at = DESIGN.find(&format!("`{ARCHIVE}`")).unwrap();
    DESIGN[at..]
        .split('`')
        .find(|word| word.len() == 64 && word.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .unwrap()
}

#[test]
fn the_archive_is_the_upstream_release_with_the_digest_of_the_design() {
    let archives = of("archive");
    let [archive] = &archives[..] else {
        panic!("{archives:?}");
    };
    assert_eq!(
        archive.source,
        format!("https://github.com/basil00/WinDivert/releases/download/v2.2.2/{ARCHIVE}")
    );
    assert_eq!(archive.name, ARCHIVE);
    assert_eq!(archive.sha256, sha256(designed_archive_digest()));
    for row in rows() {
        assert!(["archive", "x64", "x86"].contains(&row.kind), "{row:?}");
    }
}

fn attribute<'a>(element: &'a str, name: &str) -> Option<&'a str> {
    let at = element.find(&format!(" {name}=\""))? + name.len() + 3;
    let value = &element[at..];
    Some(&value[..value.find('"').unwrap()])
}

fn elements<'a>(source: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag} ");
    source
        .match_indices(&open)
        .map(|(at, _)| {
            let element = &source[at..];
            &element[..element.find('>').unwrap()]
        })
        .collect()
}

fn directives() -> Vec<&'static str> {
    WXS.match_indices("<?")
        .map(|(at, _)| &WXS[at..at + WXS[at..].find("?>").unwrap() + 2])
        .filter(|directive| !directive.starts_with("<?xml "))
        .collect()
}

fn transparent_feature() -> &'static str {
    let feature = &WXS[WXS.find(r#"<Feature Id="Transparent""#).unwrap()..];
    &feature[..feature.find("</Feature>").unwrap()]
}

fn packaged(part: &str) -> Vec<&str> {
    elements(part, "File")
        .into_iter()
        .map(|file| {
            let name = attribute(file, "Name").unwrap();
            assert_eq!(
                attribute(file, "Source"),
                Some(format!(r"$(var.WinDivertDir)\{name}").as_str())
            );
            name
        })
        .collect()
}

fn sorted<'a>(names: impl IntoIterator<Item = &'a str>) -> Vec<&'a str> {
    let mut names: Vec<_> = names.into_iter().collect();
    names.sort_unstable();
    names
}

#[test]
fn the_installer_packages_the_manifest_files_of_each_arch_only_when_built_with_windivert() {
    assert_eq!(
        directives(),
        [
            "<?ifdef WinDivertDir?>",
            "<?endif?>",
            "<?ifdef WinDivertDir?>",
            X86_ONLY,
            "<?endif?>",
            "<?endif?>",
            "<?ifdef WinDivertDir?>",
            "<?else?>",
            "<?endif?>",
        ]
    );
    let feature = transparent_feature();
    let x86 = feature.find(X86_ONLY).unwrap();
    let end = x86 + feature[x86..].find("<?endif?>").unwrap();
    let common = [packaged(&feature[..x86]), packaged(&feature[end..])].concat();
    let only_x86 = packaged(&feature[x86..end]);
    for (arch, names) in [
        ("x64", common.clone()),
        ("x86", [common, only_x86].concat()),
    ] {
        assert_eq!(
            sorted(names),
            sorted(of(arch).iter().map(|row| row.name)),
            "{arch}"
        );
    }
    assert_eq!(
        WXS.matches("$(var.WinDivertDir)").count(),
        feature.matches("$(var.WinDivertDir)").count()
    );
}

#[test]
fn the_transparent_feature_is_off_unless_transparent_is_1_like_autostart() {
    let feature = transparent_feature();
    let element = elements(feature, "Feature")[0];
    assert_eq!(
        attribute(element, "Title"),
        Some("Transparent sessions (WinDivert driver)")
    );
    assert_eq!(attribute(element, "Level"), Some("2"));
    let autostart = r#"<Level Value="1" Condition="AUTOSTART = &quot;1&quot;" />"#;
    assert!(WXS.contains(autostart));
    assert_eq!(
        elements(feature, "Level"),
        [autostart
            .replace("AUTOSTART", "TRANSPARENT")
            .trim_end_matches('>')]
    );
    for property in ["AUTOSTART", "TRANSPARENT"] {
        assert_eq!(
            WXS.matches(&format!(r#"<Property Id="{property}" Secure="yes" />"#))
                .count(),
            1,
            "{property}"
        );
    }
    let transparent = WXS.find(r#"<Feature Id="Transparent""#).unwrap();
    assert!(WXS.find(r#"<Feature Id="Main""#).unwrap() < transparent);
    assert!(transparent < WXS.rfind("</Feature>").unwrap());
}

#[test]
fn removing_an_installed_transparent_feature_checks_that_the_agent_exited_before_file_validation() {
    let stop = elements(WXS, "CustomAction")
        .into_iter()
        .find(|element| attribute(element, "Id") == Some("StopAgent"))
        .unwrap();
    assert_eq!(attribute(stop, "Execute"), Some("immediate"));
    assert_eq!(attribute(stop, "Return"), Some("check"));
    assert_eq!(attribute(stop, "FileRef"), Some("GateintoExe"));
    let actions: Vec<_> = elements(WXS, "Custom")
        .into_iter()
        .filter(|element| attribute(element, "Action") == Some("StopAgent"))
        .collect();
    assert_eq!(actions.len(), 2);
    let conditions: Vec<_> = actions
        .iter()
        .map(|action| {
            assert_eq!(attribute(action, "Before"), Some("InstallValidate"));
            attribute(action, "Condition").unwrap()
        })
        .collect();
    for condition in &conditions {
        assert!(condition.starts_with("GATEINTOEXISTS AND (WIX_UPGRADE_DETECTED OR"));
        assert!(condition.contains("&amp;Main = 2 AND !Main = 3"));
    }
    assert!(conditions[0].contains("&amp;Transparent = 2 AND !Transparent = 3"));
    assert!(!conditions[1].contains("Transparent"));
}

#[test]
fn every_windivert_component_has_a_per_user_registry_key_path() {
    let feature = transparent_feature();
    let components: Vec<&str> = feature.split("<Component ").skip(1).collect();
    assert!(!components.is_empty());
    for component in components {
        let component = &component[..component.find("</Component>").unwrap()];
        for file in elements(component, "File") {
            assert_eq!(attribute(file, "KeyPath"), Some("no"), "{file}");
        }
        let keys: Vec<&str> = elements(component, "RegistryValue")
            .into_iter()
            .filter(|value| attribute(value, "KeyPath") == Some("yes"))
            .collect();
        let [key] = keys[..] else {
            panic!("{component}");
        };
        assert_eq!(attribute(key, "Root"), Some("HKCU"));
        assert_eq!(attribute(key, "Key"), Some(r"Software\Gateinto\Installer"));
    }
    let guids: Vec<&str> = elements(WXS, "Component")
        .into_iter()
        .filter_map(|component| attribute(component, "Guid"))
        .collect();
    let mut unique = sorted(guids.clone());
    unique.dedup();
    assert_eq!(unique.len(), guids.len());
}

fn hex_runs(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| !c.is_ascii_hexdigit())
        .filter(|run| run.len() >= 64)
}

#[test]
fn the_scripts_take_every_windivert_name_and_digest_from_the_manifest() {
    for (script, text) in [
        ("windivert.ps1", VERIFY),
        ("build.ps1", BUILD),
        ("fetch-windivert.ps1", FETCH),
        ("release.yml", RELEASE),
    ] {
        for row in rows() {
            assert!(!text.contains(row.name), "{script} names {}", row.name);
        }
        assert_eq!(hex_runs(text).count(), 0, "{script}");
    }
    assert!(VERIFY.contains("'windivert.txt'"));
    assert!(BUILD.contains("'windivert.ps1'"));
    assert!(BUILD.contains("WinDivertDir="));
    assert!(FETCH.contains(r"'..\..\packaging\wix\windivert.ps1'"));
}

#[test]
fn the_release_verifies_the_archive_before_extracting_and_builds_each_msi_with_windivert() {
    let checked = FETCH.find("-Archive $zip").unwrap();
    let opened = FETCH.find("::OpenRead(").unwrap();
    assert!(checked < opened);
    assert!(FETCH[opened..].contains("-Directory $Output"));
    let directory = "(Join-Path $env:RUNNER_TEMP 'windivert')";
    let fetched = RELEASE
        .find(&format!(
            ".github/scripts/fetch-windivert.ps1 -Arch $env:MSI_ARCH -Output {directory}"
        ))
        .unwrap();
    let built = RELEASE.find("packaging/wix/build.ps1").unwrap();
    assert!(fetched < built);
    assert_eq!(RELEASE.matches("packaging/wix/build.ps1").count(), 1);
    assert!(RELEASE[built..].contains(&format!("-WinDivert {directory}")));
}

#[test]
fn ci_tests_both_msi_builds_with_the_pinned_windivert_files() {
    let ci = CI.replace("\r\n", "\n");
    let (_, msi) = ci.split_once("\n  msi:\n").unwrap();
    let fetched = msi.find(".github/scripts/fetch-windivert.ps1").unwrap();
    let builds: Vec<_> = msi.match_indices("packaging/wix/build.ps1").collect();
    assert_eq!(builds.len(), 2);
    for (at, _) in builds {
        assert!(at > fetched);
        assert!(
            msi[at..].lines().next().unwrap().contains("-WinDivert "),
            "{msi}"
        );
    }
    assert!(msi.contains("-WinDivertArch $env:MSI_ARCH"));
}
