use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::divert::Dscp;
use crate::job::Job;
use crate::sessions::SessionId;
use crate::transparent::availability::Availability;
use crate::transparent::state::{Generation, State};

pub(super) type Boxed<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub(super) type Registry = State<SessionId, Job>;

pub(super) trait Engine: Send + Sync + 'static {
    fn available(&self) -> Availability;
    fn start(&self, dscp: Dscp) -> Boxed<'_, Result<Started, String>>;
    fn wait_for_exit(&self) -> Boxed<'_, Result<(), String>> {
        Box::pin(std::future::ready(Ok(())))
    }
}

pub(super) struct Started {
    pub(super) stopped: Boxed<'static, EngineStopped>,
    pub(super) listener: Box<dyn Listener>,
}

pub(super) struct EngineStopped {
    pub(super) message: String,
    pub(super) capture: Option<Box<dyn Send>>,
}

pub(super) trait Listener: Send {
    fn serve(
        self: Box<Self>,
        registry: Arc<Registry>,
        generation: Generation,
        shutdown: Boxed<'static, ()>,
    ) -> Boxed<'static, ()>;
}

#[cfg(any(windows, test))]
async fn start_after_job_check<T>(
    dscp: Dscp,
    current_dscp: impl FnOnce() -> std::io::Result<Option<u8>>,
    start: impl Future<Output = Result<T, String>>,
) -> Result<T, String> {
    let tag = current_dscp()
        .map_err(|error| format!("checking the agent's job DSCP tag failed: {error}"))?;
    if tag == Some(dscp.value()) {
        return Err(format!(
            "the agent's Windows job already uses DSCP tag {dscp}; run the agent outside that job"
        ));
    }
    start.await
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io;

    use super::*;

    #[tokio::test]
    async fn the_agent_refuses_to_start_capture_with_its_own_tag() {
        let dscp = Dscp::DEFAULT;
        let started = Cell::new(false);
        let outcome = start_after_job_check(dscp, || Ok(Some(dscp.value())), async {
            started.set(true);
            Ok(())
        })
        .await;

        assert!(!started.get());
        assert!(outcome.unwrap_err().contains(&format!("DSCP tag {dscp}")));
    }

    #[tokio::test]
    async fn capture_starts_after_the_agent_checks_for_a_conflicting_tag() {
        let dscp = Dscp::DEFAULT;
        for tag in [None, Some(0), Some(10)] {
            let checked = Cell::new(false);
            let outcome = start_after_job_check(
                dscp,
                || {
                    checked.set(true);
                    Ok(tag)
                },
                async {
                    assert!(checked.get());
                    Ok(1)
                },
            )
            .await;
            assert_eq!(outcome, Ok(1));
        }
    }

    #[tokio::test]
    async fn capture_does_not_start_when_the_job_query_fails() {
        let started = Cell::new(false);
        let outcome = start_after_job_check(
            Dscp::DEFAULT,
            || {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "query denied",
                ))
            },
            async {
                started.set(true);
                Ok(())
            },
        )
        .await;

        assert!(!started.get());
        assert_eq!(
            outcome.unwrap_err(),
            "checking the agent's job DSCP tag failed: query denied"
        );
    }
}

#[cfg(windows)]
pub(super) fn system() -> Arc<dyn Engine> {
    Arc::new(windows::Divert::new())
}

#[cfg(not(windows))]
pub(super) fn system() -> Arc<dyn Engine> {
    Arc::new(Unavailable)
}

#[cfg(not(windows))]
struct Unavailable;

#[cfg(not(windows))]
impl Engine for Unavailable {
    fn available(&self) -> Availability {
        crate::transparent::availability::available()
    }

    fn start(&self, _: Dscp) -> Boxed<'_, Result<Started, String>> {
        let refused = crate::transparent::availability::Reason::NotWindows.to_string();
        Box::pin(std::future::ready(Err(refused)))
    }
}

#[cfg(windows)]
mod windows {
    use std::sync::Arc;

    use tokio::net::TcpListener;

    use super::{Boxed, Engine, EngineStopped, Listener, Registry, Started, start_after_job_check};
    use crate::divert::Dscp;
    use crate::job::current_dscp_tag;
    use crate::proxy::{self, Attribution};
    use crate::transparent::availability::{self, Availability};
    use crate::transparent::helper::{self, Supervisor};
    use crate::transparent::state::Generation;
    use crate::transparent::{listener, serve};

    pub(super) struct Divert {
        supervisor: Supervisor<helper::Windows>,
    }

    impl Divert {
        pub(super) fn new() -> Self {
            Self {
                supervisor: Supervisor::new(helper::Windows),
            }
        }
    }

    impl Engine for Divert {
        fn available(&self) -> Availability {
            availability::available()
        }

        fn start(&self, dscp: Dscp) -> Boxed<'_, Result<Started, String>> {
            Box::pin(start_after_job_check(dscp, current_dscp_tag, async move {
                let attribution = Attribution::new().map_err(|error| {
                    format!(
                        "reading the user of the agent for the transparent listener failed: {error}"
                    )
                })?;
                let reserved = listener::reserve().map_err(|error| {
                    format!("reserving a port for the transparent listener failed: {error}")
                })?;
                let mut running = self
                    .supervisor
                    .start(reserved.port(), dscp)
                    .await
                    .map_err(|error| error.to_string())?;
                let listener = reserved.listen().map_err(|error| {
                    format!("listening for transparent connections failed: {error}")
                })?;
                Ok(Started {
                    stopped: Box::pin(async move {
                        let message = running.wait_for_stop().await.to_string();
                        EngineStopped {
                            message,
                            capture: Some(Box::new(running)),
                        }
                    }),
                    listener: Box::new(Listening {
                        listener,
                        attribution: Arc::new(attribution),
                    }),
                })
            }))
        }

        fn wait_for_exit(&self) -> Boxed<'_, Result<(), String>> {
            Box::pin(self.supervisor.shutdown())
        }
    }

    struct Listening {
        listener: TcpListener,
        attribution: Arc<Attribution>,
    }

    impl Listener for Listening {
        fn serve(
            self: Box<Self>,
            registry: Arc<Registry>,
            generation: Generation,
            shutdown: Boxed<'static, ()>,
        ) -> Boxed<'static, ()> {
            let Self {
                listener,
                attribution,
            } = *self;
            Box::pin(serve::serve(
                listener,
                registry,
                generation,
                attribution,
                proxy::Limits::default().handshake_timeout,
                shutdown,
            ))
        }
    }
}
