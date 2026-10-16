use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::{Instant, sleep_until};
use tokio_rustls::client::TlsStream;

pub(super) async fn relay(
    client: TcpStream,
    mut upstream: TlsStream<TcpStream>,
    idle_timeout: Duration,
) -> Option<io::Result<(u64, u64)>> {
    let activity = Activity::new();
    let mut client = Tracked {
        inner: client,
        activity: &activity,
    };
    tokio::select! {
        result = tokio::io::copy_bidirectional(&mut client, &mut upstream) => Some(result),
        () = activity.idle(idle_timeout) => None,
    }
}

struct Activity {
    start: Instant,
    last_millis: AtomicU64,
}

impl Activity {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            last_millis: AtomicU64::new(0),
        }
    }

    fn touch(&self) {
        let elapsed = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_millis.store(elapsed, Ordering::Relaxed);
    }

    async fn idle(&self, timeout: Duration) {
        loop {
            let last = Duration::from_millis(self.last_millis.load(Ordering::Relaxed));
            let deadline = self.start + last + timeout;
            if Instant::now() >= deadline {
                return;
            }
            sleep_until(deadline).await;
        }
    }
}

struct Tracked<'a, S> {
    inner: S,
    activity: &'a Activity,
}

impl<S: AsyncRead + Unpin> AsyncRead for Tracked<'_, S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if buf.filled().len() > before {
            self.activity.touch();
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Tracked<'_, S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        if matches!(poll, Poll::Ready(Ok(n)) if n > 0) {
            self.activity.touch();
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
