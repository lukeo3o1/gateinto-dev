use crate::ipc::SessionInfo;

const HEADER: [&str; 9] = [
    "ID", "KIND", "GATEWAY", "LISTEN", "ROUTE", "AUTH", "TUNNELS", "UPTIME", "BROWSER",
];

pub fn session_table(sessions: &[SessionInfo], now: u64) -> Vec<String> {
    let rows: Vec<[String; 9]> = std::iter::once(HEADER.map(str::to_owned))
        .chain(sessions.iter().map(|session| {
            [
                session.id.to_string(),
                session.kind.to_string(),
                session.gateway.clone(),
                session.listen.to_string(),
                session.route.to_string(),
                session.auth.to_string(),
                session.tunnels.to_string(),
                uptime(now.saturating_sub(session.started)),
                session
                    .browser
                    .map_or_else(|| "-".to_owned(), |browser| browser.to_string()),
            ]
        }))
        .collect();
    let widths: [usize; 9] =
        std::array::from_fn(|column| rows.iter().map(|row| row[column].len()).max().unwrap_or(0));
    rows.iter()
        .map(|row| {
            let mut line = String::new();
            for (cell, width) in row.iter().zip(widths) {
                line.push_str(&format!("{cell:width$}  "));
            }
            line.trim_end().to_owned()
        })
        .collect()
}

pub fn uptime(seconds: u64) -> String {
    let (minutes, hours, days) = (seconds / 60, seconds / 3_600, seconds / 86_400);
    if days > 0 {
        format!("{days}d{:02}h", hours % 24)
    } else if hours > 0 {
        format!("{hours}h{:02}m", minutes % 60)
    } else if minutes > 0 {
        format!("{minutes}m{:02}s", seconds % 60)
    } else {
        format!("{seconds}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{BrowserKind, SessionAuth, SessionKind, SessionRoute};

    fn session(id: u64, gateway: &str, browser: Option<BrowserKind>) -> SessionInfo {
        SessionInfo {
            id,
            kind: SessionKind::Browser,
            gateway: gateway.to_owned(),
            upstream: "proxy.example:443".to_owned(),
            listen: "127.0.0.1:49152".parse().unwrap(),
            route: SessionRoute::All,
            auth: SessionAuth::Password,
            started: 1_000,
            tunnels: 3,
            browser,
        }
    }

    #[test]
    fn an_empty_list_is_only_the_header() {
        assert_eq!(
            session_table(&[], 0),
            ["ID  KIND  GATEWAY  LISTEN  ROUTE  AUTH  TUNNELS  UPTIME  BROWSER"]
        );
    }

    #[test]
    fn columns_are_aligned_to_their_widest_cell() {
        let other = SessionInfo {
            kind: SessionKind::Unknown,
            listen: "[::1]:8080".parse().unwrap(),
            route: SessionRoute::Mixed,
            auth: SessionAuth::OsUser,
            started: 4_000,
            tunnels: 12,
            ..session(10, "office", None)
        };
        let table = session_table(
            &[session(1, "corporate", Some(BrowserKind::Chrome)), other],
            4_065,
        );
        assert_eq!(
            table,
            [
                "ID  KIND     GATEWAY    LISTEN           ROUTE  AUTH      TUNNELS  UPTIME  BROWSER",
                "1   browser  corporate  127.0.0.1:49152  all    password  3        51m05s  chrome",
                "10  unknown  office     [::1]:8080       mixed  os_user   12       1m05s   -",
            ]
        );
    }

    #[test]
    fn uptime_shows_the_two_largest_units() {
        for (seconds, shown) in [
            (0, "0s"),
            (59, "59s"),
            (60, "1m00s"),
            (3_599, "59m59s"),
            (3_600, "1h00m"),
            (86_399, "23h59m"),
            (86_400, "1d00h"),
            (90_061, "1d01h"),
        ] {
            assert_eq!(uptime(seconds), shown, "{seconds}");
        }
    }

    #[test]
    fn a_session_started_after_now_has_no_uptime_yet() {
        let table = session_table(&[session(1, "main", None)], 999);
        assert!(table[1].contains("  0s  "), "{table:?}");
    }
}
