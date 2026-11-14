use super::keyfile;

const GROUP: &str = "Default Applications";

pub(crate) fn desktop_id(scheme: &str) -> String {
    format!("{scheme}.desktop")
}

pub(crate) fn default_ids<'a>(text: &'a str, scheme: &str) -> Vec<&'a str> {
    values(text, scheme).last().map_or_else(Vec::new, |value| {
        ids(value).filter(|id| !id.contains('\\')).collect()
    })
}

pub(crate) fn listed_ids<'a>(text: &'a str, scheme: &str) -> Vec<&'a str> {
    values(text, scheme).flat_map(ids).collect()
}

pub(crate) fn with_handler(text: &str, scheme: &str) -> String {
    let entry = format!("{}={}", key(scheme), desktop_id(scheme));
    let lines = lines(text, scheme);
    let mut out = String::with_capacity(text.len() + entry.len() + GROUP.len() + 4);
    if let Some(last) = lines.iter().rposition(|line| line.kind == Kind::Handler) {
        for (index, line) in lines.iter().enumerate() {
            if index == last {
                out.push_str(&entry);
                out.push_str(ending(line.text));
            } else if line.kind != Kind::Handler {
                out.push_str(line.text);
            }
        }
    } else if let Some(anchor) = insertion_point(&lines) {
        let newline = newline(text, lines[anchor].text);
        for (index, line) in lines.iter().enumerate() {
            out.push_str(line.text);
            if index == anchor {
                push_line(&mut out, &entry, newline);
            }
        }
    } else {
        let newline = newline(text, lines.last().map_or("", |line| line.text));
        out.push_str(text);
        push_line(&mut out, &format!("[{GROUP}]"), newline);
        push_line(&mut out, &entry, newline);
    }
    out
}

pub(crate) fn without_handler(text: &str, scheme: &str) -> Option<String> {
    let lines = lines(text, scheme);
    lines
        .iter()
        .any(|line| line.kind == Kind::Handler)
        .then(|| {
            lines
                .iter()
                .filter(|line| line.kind != Kind::Handler)
                .map(|line| line.text)
                .collect()
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Group { ours: bool },
    Entry,
    Handler,
    Other,
}

struct Line<'a> {
    text: &'a str,
    kind: Kind,
}

fn key(scheme: &str) -> String {
    format!("x-scheme-handler/{scheme}")
}

fn is_key(name: &str, scheme: &str) -> bool {
    name.eq_ignore_ascii_case(&key(scheme))
}

fn lines<'a>(text: &'a str, scheme: &str) -> Vec<Line<'a>> {
    keyfile::lines(text)
        .map(|line| {
            let ours = line.group == Some(GROUP);
            let kind = match line.kind {
                keyfile::Kind::Group(_) => Kind::Group { ours },
                keyfile::Kind::Entry { key, .. } if ours && is_key(key, scheme) => Kind::Handler,
                keyfile::Kind::Entry { .. } if ours => Kind::Entry,
                _ => Kind::Other,
            };
            Line {
                text: line.text,
                kind,
            }
        })
        .collect()
}

fn insertion_point(lines: &[Line]) -> Option<usize> {
    let header = lines
        .iter()
        .position(|line| line.kind == Kind::Group { ours: true })?;
    let group = &lines[header + 1..];
    let end = group
        .iter()
        .position(|line| matches!(line.kind, Kind::Group { .. }))
        .unwrap_or(group.len());
    Some(
        group[..end]
            .iter()
            .rposition(|line| line.kind == Kind::Entry)
            .map_or(header, |offset| header + 1 + offset),
    )
}

fn push_line(out: &mut String, line: &str, newline: &str) {
    if !out.trim_start_matches(keyfile::BOM).is_empty() && !out.ends_with('\n') {
        out.push_str(newline);
    }
    out.push_str(line);
    out.push_str(newline);
}

fn newline<'a>(text: &'a str, anchor: &'a str) -> &'a str {
    std::iter::once(anchor)
        .chain(text.split_inclusive('\n'))
        .map(ending)
        .find(|ending| ending.ends_with('\n'))
        .unwrap_or("\n")
}

fn values<'a>(text: &'a str, scheme: &str) -> impl Iterator<Item = &'a str> {
    keyfile::values(text, GROUP, move |name| is_key(name, scheme))
}

fn ids(value: &str) -> impl Iterator<Item = &str> {
    let mut escaped = false;
    value
        .split(move |c| {
            let separator = c == ';' && !escaped;
            escaped = c == '\\' && !escaped;
            separator
        })
        .map(keyfile::trim)
        .filter(|id| !id.is_empty())
}

fn ending(line: &str) -> &str {
    &line[line.trim_end_matches(['\r', '\n']).len()..]
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNRELATED: &str = "\
# kept as written
[Added Associations]
x-scheme-handler/gateinto=added.desktop;
text/html=firefox.desktop;

[Default Applications]
text/html = firefox.desktop
  # indented comment
x-scheme-handler/gateinto-test=other.desktop
x-scheme-handler/https=firefox.desktop;

[Removed Associations]
x-scheme-handler/gateinto=removed.desktop
";

    #[test]
    fn the_desktop_id_follows_the_scheme() {
        assert_eq!(desktop_id("gateinto"), "gateinto.desktop");
        assert_eq!(desktop_id("gateinto-test-1"), "gateinto-test-1.desktop");
    }

    #[test]
    fn only_the_schemes_key_in_default_applications_is_read() {
        assert_eq!(default_ids(UNRELATED, "gateinto"), Vec::<&str>::new());
        assert_eq!(default_ids(UNRELATED, "gateinto-test"), ["other.desktop"]);
        assert_eq!(default_ids(UNRELATED, "https"), ["firefox.desktop"]);
        assert_eq!(default_ids("", "gateinto"), Vec::<&str>::new());
    }

    #[test]
    fn values_are_semicolon_separated_lists_in_order() {
        for (text, expected) in [
            (
                "[Default Applications]\nx-scheme-handler/gateinto=foo.desktop;gateinto.desktop;\n",
                &["foo.desktop", "gateinto.desktop"][..],
            ),
            (
                "[Default Applications]\nx-scheme-handler/gateinto = a.desktop ;; b.desktop\n",
                &["a.desktop", "b.desktop"][..],
            ),
            (
                "[Default Applications]\r\nx-scheme-handler/gateinto=a.desktop\r\n",
                &["a.desktop"][..],
            ),
            (
                "[Default Applications]\nx-scheme-handler/gateinto=\n",
                &[][..],
            ),
            (
                "[Default Applications]\nx-scheme-handler/gateinto=;\n",
                &[][..],
            ),
            (
                "[Default Applications]\n#x-scheme-handler/gateinto=a.desktop\n",
                &[][..],
            ),
            ("x-scheme-handler/gateinto=a.desktop\n", &[][..]),
        ] {
            assert_eq!(default_ids(text, "gateinto"), expected, "{text:?}");
        }
    }

    #[test]
    fn escaped_ids_are_never_defaults_but_are_listed() {
        for (value, listed) in [
            (
                "a\\;b.desktop;c.desktop",
                &["a\\;b.desktop", "c.desktop"][..],
            ),
            (
                "a\\sb.desktop;c.desktop",
                &["a\\sb.desktop", "c.desktop"][..],
            ),
            (
                "a\\\\b.desktop;c.desktop",
                &["a\\\\b.desktop", "c.desktop"][..],
            ),
            ("c.desktop;d\\", &["c.desktop", "d\\"][..]),
        ] {
            let text = format!("[Default Applications]\nx-scheme-handler/gateinto={value}\n");
            assert_eq!(default_ids(&text, "gateinto"), ["c.desktop"], "{value}");
            assert_eq!(listed_ids(&text, "gateinto"), listed, "{value}");
        }
    }

    #[test]
    fn unicode_whitespace_is_part_of_the_key_and_the_ids() {
        let text = "[Default Applications]\n\
                    x-scheme-handler/gateinto\u{a0}=a.desktop\n\
                    x-scheme-handler/https=\u{3000}b.desktop\n";
        assert_eq!(default_ids(text, "gateinto"), Vec::<&str>::new());
        assert_eq!(default_ids(text, "https"), ["\u{3000}b.desktop"]);
    }

    #[test]
    fn the_key_is_matched_ignoring_ascii_case() {
        let text = "\
[Default Applications]
X-Scheme-Handler/gateinto=a.desktop
x-scheme-handler/GATEINTO=b.desktop
text/html=firefox.desktop
";
        assert_eq!(default_ids(text, "gateinto"), ["b.desktop"]);
        assert_eq!(listed_ids(text, "gateinto"), ["a.desktop", "b.desktop"]);
        assert_eq!(
            with_handler(text, "gateinto"),
            "[Default Applications]\n\
             x-scheme-handler/gateinto=gateinto.desktop\n\
             text/html=firefox.desktop\n"
        );
        assert_eq!(
            without_handler(text, "gateinto").as_deref(),
            Some("[Default Applications]\ntext/html=firefox.desktop\n")
        );
        let dotless = "[Default Applications]\nx-scheme-handler/gateİnto=a.desktop\n";
        assert_eq!(default_ids(dotless, "gateinto"), Vec::<&str>::new());
    }

    #[test]
    fn a_byte_order_mark_is_tolerated_and_kept() {
        let text = "\u{feff}[Default Applications]\nx-scheme-handler/gateinto=a.desktop\n";
        assert_eq!(default_ids(text, "gateinto"), ["a.desktop"]);
        assert_eq!(
            with_handler(text, "gateinto"),
            "\u{feff}[Default Applications]\nx-scheme-handler/gateinto=gateinto.desktop\n"
        );
        assert_eq!(
            without_handler(text, "gateinto").as_deref(),
            Some("\u{feff}[Default Applications]\n")
        );
        assert_eq!(
            with_handler("\u{feff}[Default Applications]\n", "gateinto"),
            "\u{feff}[Default Applications]\nx-scheme-handler/gateinto=gateinto.desktop\n"
        );
        assert_eq!(
            with_handler("\u{feff}", "gateinto"),
            "\u{feff}[Default Applications]\nx-scheme-handler/gateinto=gateinto.desktop\n"
        );
    }

    #[test]
    fn the_last_occurrence_is_the_default_and_every_occurrence_is_listed() {
        let text = "\
[Default Applications]
x-scheme-handler/gateinto=a.desktop;b.desktop
[Other]
[Default Applications]
x-scheme-handler/gateinto=c.desktop
x-scheme-handler/gateinto=gateinto.desktop
";
        assert_eq!(default_ids(text, "gateinto"), ["gateinto.desktop"]);
        assert_eq!(
            listed_ids(text, "gateinto"),
            ["a.desktop", "b.desktop", "c.desktop", "gateinto.desktop"]
        );
    }

    #[test]
    fn setting_replaces_the_value_in_place_and_keeps_everything_else() {
        let text = UNRELATED.replace(
            "x-scheme-handler/gateinto-test=other.desktop\n",
            "x-scheme-handler/gateinto-test=other.desktop\nx-scheme-handler/gateinto = foo.desktop;\n",
        );
        assert_eq!(
            with_handler(&text, "gateinto"),
            UNRELATED.replace(
                "x-scheme-handler/gateinto-test=other.desktop\n",
                "x-scheme-handler/gateinto-test=other.desktop\n\
                 x-scheme-handler/gateinto=gateinto.desktop\n",
            )
        );
    }

    #[test]
    fn setting_an_existing_handler_changes_nothing() {
        let text = with_handler(UNRELATED, "gateinto");
        assert_eq!(with_handler(&text, "gateinto"), text);
    }

    #[test]
    fn setting_adds_the_line_after_the_last_entry_of_the_group() {
        assert_eq!(
            with_handler(UNRELATED, "gateinto"),
            UNRELATED.replace(
                "x-scheme-handler/https=firefox.desktop;\n",
                "x-scheme-handler/https=firefox.desktop;\n\
                 x-scheme-handler/gateinto=gateinto.desktop\n",
            )
        );
        assert_eq!(
            with_handler("[Default Applications]\n\n[Other]\n", "gateinto"),
            "[Default Applications]\nx-scheme-handler/gateinto=gateinto.desktop\n\n[Other]\n"
        );
        assert_eq!(
            with_handler("[Default Applications]\na=b.desktop", "gateinto"),
            "[Default Applications]\na=b.desktop\nx-scheme-handler/gateinto=gateinto.desktop\n"
        );
    }

    #[test]
    fn setting_adds_the_group_at_the_end_when_it_is_missing() {
        for (text, expected) in [
            ("", ""),
            ("[Added Associations]\n", "[Added Associations]\n"),
            ("[Added Associations]", "[Added Associations]\n"),
        ] {
            assert_eq!(
                with_handler(text, "gateinto"),
                format!(
                    "{expected}[Default Applications]\nx-scheme-handler/gateinto=gateinto.desktop\n"
                ),
                "{text:?}"
            );
        }
    }

    #[test]
    fn added_lines_reuse_the_line_ending_of_the_line_they_follow() {
        for (text, expected) in [
            (
                "[Default Applications]\r\na=b.desktop\r\n",
                "[Default Applications]\r\na=b.desktop\r\n\
                 x-scheme-handler/gateinto=gateinto.desktop\r\n",
            ),
            (
                "[Default Applications]\r\n\r\n[Other]\n",
                "[Default Applications]\r\n\
                 x-scheme-handler/gateinto=gateinto.desktop\r\n\r\n[Other]\n",
            ),
            (
                "[Default Applications]\r\na=b.desktop",
                "[Default Applications]\r\na=b.desktop\r\n\
                 x-scheme-handler/gateinto=gateinto.desktop\r\n",
            ),
            (
                "[Added Associations]\r\n",
                "[Added Associations]\r\n[Default Applications]\r\n\
                 x-scheme-handler/gateinto=gateinto.desktop\r\n",
            ),
            (
                "[Added Associations]\r\na=b",
                "[Added Associations]\r\na=b\r\n[Default Applications]\r\n\
                 x-scheme-handler/gateinto=gateinto.desktop\r\n",
            ),
        ] {
            assert_eq!(with_handler(text, "gateinto"), expected, "{text:?}");
        }
    }

    #[test]
    fn setting_keeps_one_line_in_place_of_the_last_occurrence() {
        let text = "\
[Default Applications]
x-scheme-handler/gateinto=a.desktop
text/html=firefox.desktop
[Default Applications]
x-scheme-handler/gateinto=b.desktop\r
x-scheme-handler/gateinto=c.desktop";
        assert_eq!(
            with_handler(text, "gateinto"),
            "\
[Default Applications]
text/html=firefox.desktop
[Default Applications]
x-scheme-handler/gateinto=gateinto.desktop"
        );
        assert_eq!(
            with_handler(
                "[Default Applications]\r\nx-scheme-handler/gateinto=a\r\n",
                "gateinto"
            ),
            "[Default Applications]\r\nx-scheme-handler/gateinto=gateinto.desktop\r\n"
        );
    }

    #[test]
    fn removing_drops_every_occurrence_and_keeps_everything_else() {
        let text = with_handler(UNRELATED, "gateinto");
        assert_eq!(
            without_handler(&text, "gateinto").as_deref(),
            Some(UNRELATED)
        );
        assert_eq!(
            without_handler(
                "[Default Applications]\nx-scheme-handler/gateinto=a\n[Default Applications]\n\
                 x-scheme-handler/gateinto=b",
                "gateinto"
            )
            .as_deref(),
            Some("[Default Applications]\n[Default Applications]\n")
        );
    }

    #[test]
    fn removing_an_absent_handler_reports_no_change() {
        assert_eq!(without_handler(UNRELATED, "gateinto"), None);
        assert_eq!(without_handler("", "gateinto"), None);
    }
}
