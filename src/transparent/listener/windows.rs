use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::windows::io::AsRawSocket;

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use tokio::net::{TcpListener, TcpSocket};
use windows_sys::Win32::Networking::WinSock::{
    SO_EXCLUSIVEADDRUSE, SOCKET, SOCKET_ERROR, SOL_SOCKET, WSAGetLastError, setsockopt,
};

use super::{Bind, choose};
use crate::divert::helper::ListenerPort;

const BACKLOG: u32 = 1024;

pub struct Reserved {
    socket: TcpSocket,
    port: ListenerPort,
}

impl Reserved {
    pub fn port(&self) -> ListenerPort {
        self.port
    }

    pub fn listen(self) -> io::Result<TcpListener> {
        self.socket.listen(BACKLOG)
    }
}

pub fn reserve() -> io::Result<Reserved> {
    let (socket, port) = choose(&mut Exclusive, random)?;
    Ok(Reserved { socket, port })
}

fn random() -> io::Result<u16> {
    let mut bytes = [0; 2];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| io::Error::other("the system random number generator failed"))?;
    Ok(u16::from_ne_bytes(bytes))
}

struct Exclusive;

impl Bind for Exclusive {
    type Socket = TcpSocket;

    fn bind(&mut self, port: u16) -> io::Result<(TcpSocket, u16)> {
        let socket = TcpSocket::new_v4()?;
        let on: i32 = 1;
        // SAFETY: the socket is open and on is an i32 of the given length.
        let set = unsafe {
            setsockopt(
                socket.as_raw_socket() as SOCKET,
                SOL_SOCKET,
                SO_EXCLUSIVEADDRUSE,
                (&raw const on).cast(),
                size_of_val(&on) as i32,
            )
        };
        if set == SOCKET_ERROR {
            // SAFETY: WSAGetLastError only reads the calling thread's last socket error.
            return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
        }
        socket.bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))?;
        let port = socket.local_addr()?.port();
        Ok((socket, port))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::net::TcpStream;
    use windows_sys::Win32::Networking::WinSock::getsockopt;

    use super::*;

    #[test]
    fn a_reserved_port_is_in_the_dynamic_range_and_held_exclusively() {
        let reserved = reserve().unwrap();
        let port = reserved.port().get().get();
        assert!(port >= ListenerPort::MIN, "{port}");
        let mut exclusive: i32 = 0;
        let mut length = size_of_val(&exclusive) as i32;
        // SAFETY: the socket is open and exclusive is an i32 of the given length.
        let read = unsafe {
            getsockopt(
                reserved.socket.as_raw_socket() as SOCKET,
                SOL_SOCKET,
                SO_EXCLUSIVEADDRUSE,
                (&raw mut exclusive).cast(),
                &mut length,
            )
        };
        assert_eq!(read, 0, "{}", io::Error::last_os_error());
        assert_eq!(exclusive, 1);
        for ip in [Ipv4Addr::UNSPECIFIED, Ipv4Addr::LOCALHOST] {
            assert!(std::net::TcpListener::bind((ip, port)).is_err(), "{ip}");
        }
        let reusing = TcpSocket::new_v4().unwrap();
        reusing.set_reuseaddr(true).unwrap();
        assert!(
            reusing
                .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
                .is_err()
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_reserved_port_accepts_connections_only_once_it_listens() {
        let reserved = reserve().unwrap();
        let port = reserved.port().get().get();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let early = tokio::time::timeout(Duration::from_secs(30), TcpStream::connect(addr))
            .await
            .expect("the early connection was neither refused nor accepted");
        assert!(early.is_err());
        let listener = reserved.listen().unwrap();
        assert_eq!(
            listener.local_addr().unwrap(),
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, port))
        );
        let (client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        assert_eq!(client.unwrap().local_addr().unwrap(), accepted.unwrap().1);
    }
}
