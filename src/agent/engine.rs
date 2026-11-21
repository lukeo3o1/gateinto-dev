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
    fn wait_for_exit(&self) -> Boxed<'_, ()> {
        Box::pin(std::future::ready(()))
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

    use super::{Boxed, Engine, EngineStopped, Listener, Registry, Started};
    use crate::divert::Dscp;
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
            Box::pin(async move {
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
            })
        }

        fn wait_for_exit(&self) -> Boxed<'_, ()> {
            Box::pin(self.supervisor.wait_for_exit())
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
