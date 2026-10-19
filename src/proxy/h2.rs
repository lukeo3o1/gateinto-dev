use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_rustls::client::TlsStream;

use super::UpstreamError;
use crate::http::Authority;

pub(crate) struct Driver(JoinHandle<()>);

impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Driver {
    pub(crate) fn finished(&self) -> bool {
        self.0.is_finished()
    }
}

pub(crate) async fn connect(
    tls: TlsStream<TcpStream>,
    max_header_bytes: usize,
) -> Result<(h2::client::SendRequest<Bytes>, Driver), UpstreamError> {
    let (sender, connection) = h2::client::Builder::new()
        .enable_push(false)
        .initial_max_send_streams(0)
        .initial_window_size(64 * 1024)
        .initial_connection_window_size(1024 * 1024)
        .max_header_list_size(u32::try_from(max_header_bytes).unwrap_or(u32::MAX))
        .handshake(tls)
        .await
        .map_err(UpstreamError::Http2)?;
    let driver = Driver(tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!(%error, "upstream HTTP/2 connection closed");
        }
    }));
    Ok((sender, driver))
}

pub(crate) struct Pending {
    response: h2::client::ResponseFuture,
    send: Option<h2::SendStream<Bytes>>,
}

impl Drop for Pending {
    fn drop(&mut self) {
        if let Some(send) = &mut self.send {
            send.send_reset(h2::Reason::CANCEL);
        }
    }
}

pub(crate) fn request(
    sender: &mut h2::client::SendRequest<Bytes>,
    target: &Authority,
) -> Result<Pending, UpstreamError> {
    let request = http::Request::builder()
        .method(http::Method::CONNECT)
        .version(http::Version::HTTP_2)
        .uri(target.to_string())
        .body(())
        .expect("a validated CONNECT authority is a valid URI");
    let (response, send) = sender
        .send_request(request, false)
        .map_err(UpstreamError::Http2)?;
    Ok(Pending {
        response,
        send: Some(send),
    })
}

impl Pending {
    pub(crate) async fn response(mut self) -> Result<(u16, Stream), UpstreamError> {
        let response = (&mut self.response).await.map_err(UpstreamError::Http2)?;
        let status = response.status().as_u16();
        Ok((
            status,
            Stream {
                send: self
                    .send
                    .take()
                    .expect("a pending CONNECT owns its send stream"),
                recv: response.into_body(),
                buffered: Bytes::new(),
                closed: false,
            },
        ))
    }
}

pub(crate) struct Stream {
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,
    buffered: Bytes,
    closed: bool,
}

impl Drop for Stream {
    fn drop(&mut self) {
        if !self.closed || !self.recv.is_end_stream() {
            self.send.send_reset(h2::Reason::CANCEL);
        }
    }
}

fn io_error(error: h2::Error) -> io::Error {
    io::Error::other(error)
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !self.buffered.is_empty() {
                let amount = buf.remaining().min(self.buffered.len());
                buf.put_slice(&self.buffered[..amount]);
                self.buffered.advance(amount);
                self.recv
                    .flow_control()
                    .release_capacity(amount)
                    .map_err(io_error)?;
                return Poll::Ready(Ok(()));
            }
            match ready!(self.recv.poll_data(cx)) {
                Some(Ok(data)) => self.buffered = data,
                Some(Err(error)) => return Poll::Ready(Err(io_error(error))),
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let wanted = buf.len().min(16 * 1024);
        self.send.reserve_capacity(wanted);
        loop {
            let capacity = match ready!(self.send.poll_capacity(cx)) {
                Some(Ok(capacity)) => capacity,
                Some(Err(error)) => return Poll::Ready(Err(io_error(error))),
                None => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            };
            let amount = wanted.min(capacity);
            if amount > 0 {
                self.send
                    .send_data(Bytes::copy_from_slice(&buf[..amount]), false)
                    .map_err(io_error)?;
                return Poll::Ready(Ok(amount));
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.closed {
            self.send.send_data(Bytes::new(), true).map_err(io_error)?;
            self.closed = true;
        }
        Poll::Ready(Ok(()))
    }
}

pub(crate) async fn ready(sender: &mut h2::client::SendRequest<Bytes>) -> Result<(), h2::Error> {
    poll_fn(|cx| sender.poll_ready(cx)).await
}
