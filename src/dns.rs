use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, LazyLock};

use tokio::sync::Semaphore;

const MAX_LOOKUPS: usize = 64;
static RESOLVER: LazyLock<Resolver> = LazyLock::new(|| Resolver::new(MAX_LOOKUPS));

pub(crate) async fn resolve(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    RESOLVER
        .resolve_with(host.to_owned(), port, |host, port| {
            (host.as_str(), port)
                .to_socket_addrs()
                .map(Iterator::collect)
        })
        .await
}

struct Resolver {
    budget: Arc<Semaphore>,
}

impl Resolver {
    fn new(limit: usize) -> Self {
        Self {
            budget: Arc::new(Semaphore::new(limit)),
        }
    }

    async fn resolve_with<F>(
        &self,
        host: String,
        port: u16,
        lookup: F,
    ) -> io::Result<Vec<SocketAddr>>
    where
        F: FnOnce(String, u16) -> io::Result<Vec<SocketAddr>> + Send + 'static,
    {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        let permit = self.budget.clone().try_acquire_owned().map_err(|_| {
            io::Error::new(io::ErrorKind::WouldBlock, "DNS lookup capacity exhausted")
        })?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            lookup(host, port)
        })
        .await
        .map_err(|error| io::Error::other(format!("DNS worker failed: {error}")))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Condvar, Mutex};
    use std::time::Duration;
    use tokio::sync::oneshot;
    use tokio::time::timeout;

    const DEADLINE: Duration = Duration::from_secs(5);

    #[derive(Default)]
    struct Gate {
        open: Mutex<bool>,
        changed: Condvar,
    }

    impl Gate {
        fn wait(&self) {
            let mut open = self.open.lock().unwrap();
            while !*open {
                open = self.changed.wait(open).unwrap();
            }
        }

        fn release(&self) {
            *self.open.lock().unwrap() = true;
            self.changed.notify_all();
        }
    }

    struct Release(Arc<Gate>);

    impl Drop for Release {
        fn drop(&mut self) {
            self.0.release();
        }
    }

    fn answer(port: u16) -> Vec<SocketAddr> {
        vec![SocketAddr::from(([127, 0, 0, 1], port))]
    }

    async fn permits(resolver: &Resolver, expected: usize) {
        timeout(DEADLINE, async {
            while resolver.budget.available_permits() != expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn cancelling_a_waiter_does_not_release_a_running_lookup_budget() {
        let resolver = Arc::new(Resolver::new(1));
        let gate = Arc::new(Gate::default());
        let release = Release(gate.clone());
        let (entered, started) = oneshot::channel();
        let worker = resolver.clone();
        let waiting = tokio::spawn(async move {
            worker
                .resolve_with("slow.test".to_owned(), 443, move |_, port| {
                    entered.send(()).unwrap();
                    gate.wait();
                    Ok(answer(port))
                })
                .await
        });
        timeout(DEADLINE, started).await.unwrap().unwrap();
        waiting.abort();
        assert!(waiting.await.unwrap_err().is_cancelled());
        let submitted = Arc::new(AtomicUsize::new(0));
        let counted = submitted.clone();
        let result = resolver
            .resolve_with("another.test".to_owned(), 443, move |_, port| {
                counted.fetch_add(1, Ordering::SeqCst);
                Ok(answer(port))
            })
            .await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert_eq!(submitted.load(Ordering::SeqCst), 0);
        release.0.release();
        permits(&resolver, 1).await;
        assert_eq!(
            resolver
                .resolve_with("recovered.test".to_owned(), 8443, |_, port| Ok(answer(
                    port
                )))
                .await
                .unwrap(),
            answer(8443)
        );
    }

    #[test]
    fn cancelling_a_waiter_keeps_queued_lookup_work_within_the_same_budget() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let gate = Arc::new(Gate::default());
            let release = Release(gate.clone());
            let (entered, started) = oneshot::channel();
            let occupying = tokio::task::spawn_blocking(move || {
                entered.send(()).unwrap();
                gate.wait();
            });
            timeout(DEADLINE, started).await.unwrap().unwrap();
            let resolver = Arc::new(Resolver::new(1));
            let submitted = Arc::new(AtomicUsize::new(0));
            let counted = submitted.clone();
            let worker = resolver.clone();
            let waiting = tokio::spawn(async move {
                worker
                    .resolve_with("queued.test".to_owned(), 443, move |_, port| {
                        counted.fetch_add(1, Ordering::SeqCst);
                        Ok(answer(port))
                    })
                    .await
            });
            permits(&resolver, 0).await;
            waiting.abort();
            assert!(waiting.await.unwrap_err().is_cancelled());
            assert_eq!(submitted.load(Ordering::SeqCst), 0);
            let result = resolver
                .resolve_with("excess.test".to_owned(), 443, |_, _| {
                    panic!("a saturated resolver must not submit more work")
                })
                .await;
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
            release.0.release();
            occupying.await.unwrap();
            permits(&resolver, 1).await;
            assert_eq!(submitted.load(Ordering::SeqCst), 1);
        });
    }

    #[tokio::test]
    async fn repeated_timeouts_cannot_enqueue_more_work_and_literals_still_resolve() {
        let resolver = Arc::new(Resolver::new(2));
        let gate = Arc::new(Gate::default());
        let release = Release(gate.clone());
        let submitted = Arc::new(AtomicUsize::new(0));
        let (entered, mut started) = tokio::sync::mpsc::unbounded_channel();
        let mut waiters = Vec::new();
        for index in 0..2 {
            let worker = resolver.clone();
            let gate = gate.clone();
            let counted = submitted.clone();
            let entered = entered.clone();
            waiters.push(tokio::spawn(async move {
                timeout(
                    Duration::from_millis(20),
                    worker.resolve_with(format!("slow-{index}.test"), 443, move |_, port| {
                        counted.fetch_add(1, Ordering::SeqCst);
                        entered.send(()).unwrap();
                        gate.wait();
                        Ok(answer(port))
                    }),
                )
                .await
            }));
        }
        for _ in 0..2 {
            timeout(DEADLINE, started.recv()).await.unwrap().unwrap();
        }
        for waiter in waiters {
            assert!(waiter.await.unwrap().is_err());
        }
        for index in 0..128 {
            let counted = submitted.clone();
            let result = resolver
                .resolve_with(format!("excess-{index}.test"), 443, move |_, port| {
                    counted.fetch_add(1, Ordering::SeqCst);
                    Ok(answer(port))
                })
                .await;
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
        }
        assert_eq!(submitted.load(Ordering::SeqCst), 2);
        for host in ["127.0.0.1", "::1", "::ffff:127.0.0.1"] {
            assert_eq!(
                resolver
                    .resolve_with(host.to_owned(), 8443, |_, _| {
                        panic!("an IP literal must not enter the resolver pool")
                    })
                    .await
                    .unwrap(),
                vec![SocketAddr::new(host.parse().unwrap(), 8443)]
            );
        }
        release.0.release();
        permits(&resolver, 2).await;
    }

    #[tokio::test]
    async fn lookup_errors_and_panics_release_their_budget() {
        let resolver = Resolver::new(1);
        let error = resolver
            .resolve_with("error.test".to_owned(), 443, |_, _| {
                Err(io::Error::new(io::ErrorKind::NotFound, "no addresses"))
            })
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert_eq!(resolver.budget.available_permits(), 1);
        let error = resolver
            .resolve_with("panic.test".to_owned(), 443, |_, _| {
                panic!("resolver failed")
            })
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(resolver.budget.available_permits(), 1);
        assert_eq!(
            resolver
                .resolve_with("recovered.test".to_owned(), 443, |_, port| Ok(answer(port)))
                .await
                .unwrap(),
            answer(443)
        );
    }
}
