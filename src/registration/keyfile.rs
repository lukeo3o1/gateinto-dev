#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind<'a> {
    Group(&'a str),
    Entry { key: &'a str, value: &'a str },
    Other,
}

pub(crate) struct Line<'a> {
    pub(crate) text: &'a str,
    pub(crate) group: Option<&'a str>,
    pub(crate) kind: Kind<'a>,
}

pub(crate) const BOM: char = '\u{feff}';

pub(crate) fn lines(text: &str) -> impl Iterator<Item = Line<'_>> {
    let mut group = None;
    let mut first = true;
    text.split_inclusive('\n').map(move |text| {
        let content = if std::mem::take(&mut first) {
            trim(text.strip_prefix(BOM).unwrap_or(text))
        } else {
            trim(text)
        };
        let kind = if let Some(name) = content
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            group = Some(name);
            Kind::Group(name)
        } else if content.starts_with('#') {
            Kind::Other
        } else {
            match content.split_once('=') {
                Some((key, value)) => Kind::Entry {
                    key: key.trim_end_matches(is_space),
                    value: value.trim_start_matches(is_space),
                },
                None => Kind::Other,
            }
        };
        Line { text, group, kind }
    })
}

pub(crate) fn trim(text: &str) -> &str {
    text.trim_matches(is_space)
}

fn is_space(c: char) -> bool {
    c.is_ascii_whitespace()
}

pub(crate) fn values<'a>(
    text: &'a str,
    group: &str,
    key: impl Fn(&str) -> bool,
) -> impl Iterator<Item = &'a str> {
    lines(text).filter_map(move |line| match line.kind {
        Kind::Entry { key: name, value } if line.group == Some(group) && key(name) => Some(value),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(text: &str) -> Vec<Kind<'_>> {
        lines(text).map(|line| line.kind).collect()
    }

    #[test]
    fn only_ascii_whitespace_is_trimmed() {
        assert_eq!(
            kinds(" \t[G]\r\n\tkey \t= \tvalue \r\n"),
            [
                Kind::Group("G"),
                Kind::Entry {
                    key: "key",
                    value: "value"
                }
            ]
        );
        assert_eq!(
            kinds("\u{a0}[G]\nkey\u{3000}=\u{2003}value\u{a0}\n"),
            [
                Kind::Other,
                Kind::Entry {
                    key: "key\u{3000}",
                    value: "\u{2003}value\u{a0}"
                }
            ]
        );
    }

    #[test]
    fn a_byte_order_mark_before_the_first_line_is_ignored() {
        assert_eq!(
            kinds("\u{feff}[G]\n\u{feff}[H]\n"),
            [Kind::Group("G"), Kind::Other]
        );
        assert_eq!(lines("\u{feff}[G]\n").next().unwrap().text, "\u{feff}[G]\n");
    }
}
