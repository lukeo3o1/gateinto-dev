use gateinto::config::GatewayName;

const FALLBACK: &str = "gateway";

pub fn identifier(display: &str, host: &str, taken: &[&str]) -> GatewayName {
    let base = [slug(display), slug(&host.replace(['.', ':'], " "))]
        .into_iter()
        .find(|slug| !slug.is_empty())
        .unwrap_or_else(|| FALLBACK.to_owned());
    let free = |candidate: &str| {
        !taken
            .iter()
            .any(|name| name.eq_ignore_ascii_case(candidate))
    };
    let candidate = (1..)
        .map(|n| numbered(&base, n))
        .find(|candidate| free(candidate))
        .expect("some number is free");
    candidate
        .parse()
        .expect("an identifier uses only the name alphabet")
}

fn slug(text: &str) -> String {
    let mut slug = String::new();
    for c in text.chars().flat_map(char::to_lowercase) {
        let c = if c.is_whitespace() { '-' } else { c };
        let allowed = c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-';
        if allowed && !(c == '-' && (slug.is_empty() || slug.ends_with('-'))) {
            slug.push(c);
        }
    }
    slug.trim_end_matches('-').to_owned()
}

fn numbered(base: &str, n: usize) -> String {
    let suffix = if n == 1 {
        String::new()
    } else {
        format!("-{n}")
    };
    let room = GatewayName::MAX_LEN - suffix.len();
    let stem = base[..base.len().min(room)].trim_end_matches('-');
    format!("{stem}{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn made(display: &str, host: &str, taken: &[&str]) -> String {
        identifier(display, host, taken).to_string()
    }

    #[test]
    fn a_display_name_becomes_a_lowercase_identifier_with_dashes_for_spaces() {
        assert_eq!(made("Head Office", "proxy.example", &[]), "head-office");
        assert_eq!(made("Lab_2 West", "proxy.example", &[]), "lab_2-west");
        assert_eq!(made("R&D - Main", "proxy.example", &[]), "rd-main");
    }

    #[test]
    fn characters_outside_the_identifier_alphabet_are_dropped() {
        assert_eq!(made("台北 Office", "proxy.example", &[]), "office");
        assert_eq!(made("Café", "proxy.example", &[]), "caf");
        assert_eq!(made("-Edge-", "proxy.example", &[]), "edge");
    }

    #[test]
    fn a_name_without_usable_characters_falls_back_to_the_host() {
        assert_eq!(
            made("台北辦公室", "proxy.corp.example", &[]),
            "proxy-corp-example"
        );
        assert_eq!(made("— —", "10.0.0.1", &[]), "10-0-0-1");
        assert_eq!(made("台北", "::1", &[]), "1");
        assert_eq!(made("台北", "fe80::1", &[]), "fe80-1");
    }

    #[test]
    fn an_identifier_never_exceeds_the_name_limit() {
        let long = "a".repeat(100);
        let name = made(&long, "proxy.example", &[]);
        assert_eq!(name, "a".repeat(GatewayName::MAX_LEN));
        let spaced = format!("{} b", "a".repeat(GatewayName::MAX_LEN - 1));
        assert_eq!(made(&spaced, "proxy.example", &[]), "a".repeat(63));
        let host = format!("{}.example", "h".repeat(70));
        assert_eq!(made("台北", &host, &[]), "h".repeat(GatewayName::MAX_LEN));
    }

    #[test]
    fn a_taken_identifier_gets_the_next_free_number_ignoring_letter_case() {
        assert_eq!(made("Office", "p.example", &["office"]), "office-2");
        assert_eq!(
            made("Office", "p.example", &["OFFICE", "office-2"]),
            "office-3"
        );
        assert_eq!(
            made("台北", "p.example", &["p-example", "p-example-2"]),
            "p-example-3"
        );
        assert_eq!(made("Office", "p.example", &["Office-2"]), "office");
    }

    #[test]
    fn a_numbered_identifier_still_fits_the_limit() {
        let long = "a".repeat(GatewayName::MAX_LEN);
        assert_eq!(
            made(&long, "p.example", &[long.as_str()]),
            format!("{}-2", "a".repeat(GatewayName::MAX_LEN - 2))
        );
        let edge = format!("{}-b", "a".repeat(GatewayName::MAX_LEN - 3));
        let taken = [edge.as_str()];
        assert_eq!(
            made(&edge, "p.example", &taken),
            format!("{}-2", "a".repeat(GatewayName::MAX_LEN - 3))
        );
    }
}
