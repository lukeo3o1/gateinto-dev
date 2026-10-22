use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use tokio::net::TcpStream;

use crate::http::{Authority, Host};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Route {
    #[default]
    Gateway,
    Mixed,
}

impl fmt::Display for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Gateway => "gateway",
            Self::Mixed => "mixed",
        })
    }
}

impl FromStr for Route {
    type Err = &'static str;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "gateway" => Ok(Self::Gateway),
            "mixed" => Ok(Self::Mixed),
            _ => Err("route must be gateway or mixed"),
        }
    }
}

pub(super) async fn resolve(host: String, port: u16) -> io::Result<Vec<SocketAddr>> {
    crate::dns::resolve(&host, port).await
}

pub(super) async fn attempt<F, R>(
    route: Route,
    opening_timeout: Duration,
    target: &Authority,
    gateway: (&str, u16),
    resolve: F,
) -> Option<TcpStream>
where
    F: Fn(String, u16) -> R,
    R: Future<Output = io::Result<Vec<SocketAddr>>>,
{
    if route == Route::Gateway {
        return None;
    }
    tokio::time::timeout(opening_timeout / 2, direct(target, gateway, resolve))
        .await
        .ok()
        .flatten()
}

async fn direct<F, R>(target: &Authority, gateway: (&str, u16), resolve: F) -> Option<TcpStream>
where
    F: Fn(String, u16) -> R,
    R: Future<Output = io::Result<Vec<SocketAddr>>>,
{
    let host = match &target.host {
        Host::Name(name) => name.clone(),
        Host::Ipv4(ip) => ip.to_string(),
        Host::Ipv6(ip) => ip.to_string(),
    };
    let (targets, gateways) = tokio::try_join!(
        resolve(host, target.port),
        resolve(gateway.0.to_owned(), gateway.1)
    )
    .ok()?;
    if targets.is_empty()
        || gateways.is_empty()
        || targets.iter().any(|target| {
            gateways
                .iter()
                .any(|gateway| target.ip().to_canonical() == gateway.ip().to_canonical())
        })
    {
        return None;
    }
    let stream = TcpStream::connect(targets.as_slice()).await.ok()?;
    let _ = stream.set_nodelay(true);
    Some(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::net::TcpListener;

    fn addr(ip: &str, port: u16) -> SocketAddr {
        SocketAddr::new(ip.parse().unwrap(), port)
    }

    #[tokio::test]
    async fn gateway_mode_never_resolves_a_target_locally() {
        let target: Authority = "internal.test:443".parse().unwrap();
        let result = attempt(
            Route::Gateway,
            Duration::from_secs(1),
            &target,
            ("gateway.test", 443),
            |_, _| async { panic!("unexpected local DNS lookup") },
        )
        .await;
        assert!(result.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_dns_leaves_half_the_opening_deadline_for_gateway_fallback() {
        let target: Authority = "internal.test:443".parse().unwrap();
        let started = tokio::time::Instant::now();
        let result = attempt(
            Route::Mixed,
            Duration::from_millis(80),
            &target,
            ("gateway.test", 443),
            |_, _| std::future::pending(),
        )
        .await;
        assert!(result.is_none());
        assert_eq!(started.elapsed(), Duration::from_millis(40));
    }

    #[tokio::test]
    async fn distinct_dns_answers_connect_using_the_resolved_target_and_port_once() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = listener.local_addr().unwrap();
        let target: Authority = format!("app.test:{}", target_addr.port()).parse().unwrap();
        let calls = Mutex::new(Vec::new());
        let stream = direct(&target, ("gateway.test", 443), |host, port| {
            calls.lock().unwrap().push((host.clone(), port));
            async move {
                Ok(vec![if host == "app.test" {
                    target_addr
                } else {
                    addr("127.0.0.2", port)
                }])
            }
        })
        .await
        .unwrap();
        assert_eq!(stream.peer_addr().unwrap(), target_addr);
        assert_eq!(
            *calls.lock().unwrap(),
            vec![
                ("app.test".into(), target_addr.port()),
                ("gateway.test".into(), 443)
            ]
        );
        listener.accept().await.unwrap();
    }

    #[tokio::test]
    async fn matching_any_address_including_mapped_ipv4_never_connects_directly() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = listener.local_addr().unwrap();
        let target: Authority = format!("app.test:{}", target_addr.port()).parse().unwrap();
        let result = direct(&target, ("gateway.test", 443), |host, port| async move {
            Ok(if host == "app.test" {
                vec![addr("127.0.0.2", port), target_addr]
            } else {
                vec![addr("::ffff:127.0.0.1", port)]
            })
        })
        .await;
        assert!(result.is_none());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn empty_or_failed_dns_on_either_side_selects_gateway() {
        let target: Authority = "app.test:443".parse().unwrap();
        for missing in ["app.test", "gateway.test"] {
            for fail in [false, true] {
                let result = direct(&target, ("gateway.test", 443), |host, port| async move {
                    if host == missing {
                        if fail {
                            Err(io::Error::other("DNS unavailable"))
                        } else {
                            Ok(Vec::new())
                        }
                    } else {
                        Ok(vec![addr("127.0.0.1", port)])
                    }
                })
                .await;
                assert!(result.is_none());
            }
        }
    }

    #[tokio::test]
    async fn failed_direct_tcp_selects_gateway() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let unavailable = listener.local_addr().unwrap();
        drop(listener);
        let target: Authority = format!("app.test:{}", unavailable.port()).parse().unwrap();
        assert!(
            direct(&target, ("gateway.test", 443), |host, port| async move {
                Ok(vec![if host == "app.test" {
                    unavailable
                } else {
                    addr("127.0.0.2", port)
                }])
            })
            .await
            .is_none()
        );
    }

    #[tokio::test]
    async fn distinct_ipv6_target_connects_directly() {
        let listener = TcpListener::bind("[::1]:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let authority: Authority = target.to_string().parse().unwrap();
        let stream = direct(&authority, ("127.0.0.1", 443), resolve)
            .await
            .unwrap();
        assert_eq!(stream.peer_addr().unwrap(), target);
        listener.accept().await.unwrap();
    }

    #[tokio::test]
    async fn ipv6_literals_resolve_without_dns() {
        assert_eq!(
            resolve("::1".into(), 8443).await.unwrap(),
            vec![addr("::1", 8443)]
        );
        assert_eq!(
            resolve("127.0.0.1".into(), 8443).await.unwrap(),
            vec![addr("127.0.0.1", 8443)]
        );
    }
}
