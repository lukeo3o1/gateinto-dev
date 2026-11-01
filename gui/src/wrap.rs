use std::ops::Range;

pub fn lines(text: &str, limit: u64, mut advance: impl FnMut(char) -> u64) -> Vec<Range<usize>> {
    let mut lines = Vec::new();
    let line =
        |start: usize, end: usize| start..start + text[start..end].trim_end_matches(' ').len();
    let (mut start, mut width) = (0, 0);
    let mut space = None;
    let mut continued = false;
    for (i, c) in text.char_indices() {
        let w = advance(c);
        if c == ' ' {
            if continued && i == start {
                start = i + 1;
            } else if width + w > limit {
                lines.push(line(start, i));
                (start, width, space, continued) = (i + 1, 0, None, true);
            } else {
                width += w;
                space = Some((i, width));
            }
            continue;
        }
        if width + w > limit {
            if let Some((at, before)) = space.take() {
                lines.push(line(start, at));
                (start, width, continued) = (at + 1, width - before, true);
            }
            if width + w > limit && i > start {
                lines.push(line(start, i));
                (start, width, continued) = (i, 0, true);
            }
        }
        width += w;
    }
    if start < text.len() || lines.is_empty() {
        lines.push(line(start, text.len()));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cells(c: char) -> u64 {
        if c.is_ascii() { 1 } else { 2 }
    }

    fn wrapped(text: &str, limit: u64) -> Vec<&str> {
        lines(text, limit, cells)
            .into_iter()
            .map(|range| &text[range])
            .collect()
    }

    #[test]
    fn text_that_fits_stays_on_one_line() {
        assert_eq!(wrapped("tunnel closed", 13), ["tunnel closed"]);
        assert_eq!(wrapped("", 5), [""]);
    }

    #[test]
    fn lines_break_at_the_last_space_that_fits() {
        assert_eq!(
            wrapped("upstream refused tunnel target=gw:443", 16),
            ["upstream refused", "tunnel", "target=gw:443"]
        );
        assert_eq!(wrapped("ab cd", 4), ["ab", "cd"]);
    }

    #[test]
    fn spaces_at_a_break_are_dropped_and_others_kept() {
        assert_eq!(wrapped("ab   cd ef", 5), ["ab", "cd ef"]);
        assert_eq!(wrapped("  indented text", 11), ["  indented", "text"]);
        assert_eq!(wrapped("ab ", 2), ["ab"]);
    }

    #[test]
    fn tokens_wider_than_a_line_are_cut_where_the_line_is_full() {
        assert_eq!(wrapped("abcdefghij", 4), ["abcd", "efgh", "ij"]);
        assert_eq!(wrapped("to abcdefghij", 4), ["to", "abcd", "efgh", "ij"]);
    }

    #[test]
    fn wide_characters_are_never_split_and_count_their_width() {
        assert_eq!(wrapped("代理程式a", 5), ["代理", "程式a"]);
        assert_eq!(wrapped("代", 1), ["代"]);
    }

    #[test]
    fn a_line_too_narrow_for_anything_still_shows_one_character_per_line() {
        assert_eq!(wrapped("ab c", 0), ["a", "b", "c"]);
    }

    #[test]
    fn no_line_is_wider_than_the_limit_and_no_text_is_lost() {
        let text = "WARN session 2 upstream refused tunnel target=gw.peztiacloud.com:443 \
                    error=CONNECT answered with status 403 代理程式 aaaaaaaaaaaaaaaaaaaaaaaaaa";
        for limit in 2..80 {
            let ranges = lines(text, limit, cells);
            let mut rest = text;
            for range in &ranges {
                let line = &text[range.clone()];
                assert!(line.chars().map(cells).sum::<u64>() <= limit, "{line:?}");
                rest = rest.trim_start_matches(' ');
                rest = rest
                    .strip_prefix(line)
                    .unwrap_or_else(|| panic!("{line:?}"));
            }
            assert_eq!(rest.trim(), "", "{limit}");
        }
    }
}
