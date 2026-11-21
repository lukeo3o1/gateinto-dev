use std::io;

use crate::divert::helper::ListenerPort;

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::{Reserved, reserve};

pub const PORT_ATTEMPTS: u16 = 64;

const PORTS: u16 = u16::MAX - ListenerPort::MIN + 1;

pub trait Bind {
    type Socket;

    fn bind(&mut self, port: u16) -> io::Result<(Self::Socket, u16)>;
}

pub fn choose<B: Bind>(
    binder: &mut B,
    mut random: impl FnMut() -> io::Result<u16>,
) -> io::Result<(B::Socket, ListenerPort)> {
    if let Some(chosen) = in_range(binder.bind(0)?) {
        return Ok(chosen);
    }
    for _ in 0..PORT_ATTEMPTS {
        let port = ListenerPort::MIN + random()? % PORTS;
        match binder.bind(port) {
            Ok(bound) => {
                if let Some(chosen) = in_range(bound) {
                    return Ok(chosen);
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied
                ) => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        format!(
            "no listener port from {} to {} was free after {PORT_ATTEMPTS} attempts",
            ListenerPort::MIN,
            u16::MAX
        ),
    ))
}

fn in_range<S>((socket, port): (S, u16)) -> Option<(S, ListenerPort)> {
    ListenerPort::new(port).ok().map(|port| (socket, port))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Event {
        Bound(u16),
        Refused(u16),
        Closed(u16),
    }

    type Log = Rc<RefCell<Vec<Event>>>;

    struct Socket {
        port: u16,
        log: Log,
    }

    impl Drop for Socket {
        fn drop(&mut self) {
            self.log.borrow_mut().push(Event::Closed(self.port));
        }
    }

    struct Fake {
        ephemeral: u16,
        refused: fn(u16) -> Option<io::ErrorKind>,
        log: Log,
    }

    impl Bind for Fake {
        type Socket = Socket;

        fn bind(&mut self, port: u16) -> io::Result<(Socket, u16)> {
            if let Some(kind) = (self.refused)(port) {
                self.log.borrow_mut().push(Event::Refused(port));
                return Err(kind.into());
            }
            let port = if port == 0 { self.ephemeral } else { port };
            self.log.borrow_mut().push(Event::Bound(port));
            let log = self.log.clone();
            Ok((Socket { port, log }, port))
        }
    }

    fn fake(ephemeral: u16, refused: fn(u16) -> Option<io::ErrorKind>) -> Fake {
        Fake {
            ephemeral,
            refused,
            log: Rc::default(),
        }
    }

    fn free(_: u16) -> Option<io::ErrorKind> {
        None
    }

    fn drawn(values: Vec<u16>) -> impl FnMut() -> io::Result<u16> {
        let mut values = values.into_iter();
        move || Ok(values.next().expect("no more random values"))
    }

    fn port(port: u16) -> ListenerPort {
        ListenerPort::new(port).unwrap()
    }

    #[test]
    fn an_ephemeral_port_in_the_dynamic_range_is_kept() {
        for ephemeral in [49152, 50000, 65535] {
            let mut binder = fake(ephemeral, free);
            let (socket, chosen) = choose(&mut binder, drawn(Vec::new())).unwrap();
            assert_eq!((socket.port, chosen), (ephemeral, port(ephemeral)));
            assert_eq!(*binder.log.borrow(), [Event::Bound(ephemeral)]);
        }
    }

    #[test]
    fn an_ephemeral_port_below_the_range_is_closed_before_an_explicit_port_is_tried() {
        for ephemeral in [1024, 49151] {
            let mut binder = fake(ephemeral, free);
            let (socket, chosen) = choose(&mut binder, drawn(vec![7])).unwrap();
            assert_eq!((socket.port, chosen), (49159, port(49159)));
            assert_eq!(
                *binder.log.borrow(),
                [
                    Event::Bound(ephemeral),
                    Event::Closed(ephemeral),
                    Event::Bound(49159)
                ]
            );
        }
    }

    #[test]
    fn random_values_map_onto_the_whole_dynamic_range() {
        for (random, expected) in [
            (0, 49152),
            (16383, 65535),
            (16384, 49152),
            (40000, 56384),
            (u16::MAX, 65535),
        ] {
            let mut binder = fake(1024, free);
            let (_, chosen) = choose(&mut binder, drawn(vec![random])).unwrap();
            assert_eq!(chosen, port(expected), "{random}");
        }
    }

    fn taken(port: u16) -> Option<io::ErrorKind> {
        match port {
            49152..=49160 => Some(io::ErrorKind::AddrInUse),
            65535 => Some(io::ErrorKind::PermissionDenied),
            _ => None,
        }
    }

    #[test]
    fn ports_in_use_or_excluded_are_skipped() {
        let mut binder = fake(1024, taken);
        let (_socket, chosen) = choose(&mut binder, drawn(vec![0, 16383, 3, 9])).unwrap();
        assert_eq!(chosen, port(49161));
        assert_eq!(
            *binder.log.borrow(),
            [
                Event::Bound(1024),
                Event::Closed(1024),
                Event::Refused(49152),
                Event::Refused(65535),
                Event::Refused(49155),
                Event::Bound(49161),
            ]
        );
    }

    #[test]
    fn the_search_gives_up_after_a_fixed_number_of_ports_in_use() {
        let mut binder = fake(1024, |port| (port != 0).then_some(io::ErrorKind::AddrInUse));
        let mut draws = 0;
        let random = || {
            draws += 1;
            Ok(draws)
        };
        let error = choose(&mut binder, random).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        assert!(error.to_string().contains("49152 to 65535"), "{error}");
        assert_eq!(draws, PORT_ATTEMPTS);
        let refused = binder
            .log
            .borrow()
            .iter()
            .filter(|event| matches!(event, Event::Refused(_)))
            .count();
        assert_eq!(refused, usize::from(PORT_ATTEMPTS));
    }

    #[test]
    fn any_other_bind_error_ends_the_search_at_once() {
        let mut binder = fake(1024, |port| (port != 0).then_some(io::ErrorKind::Other));
        let error = choose(&mut binder, drawn(vec![1, 2])).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(
            *binder.log.borrow(),
            [
                Event::Bound(1024),
                Event::Closed(1024),
                Event::Refused(49153)
            ]
        );
        let mut binder = fake(1024, |port| (port == 0).then_some(io::ErrorKind::AddrInUse));
        let error = choose(&mut binder, drawn(Vec::new())).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        assert_eq!(*binder.log.borrow(), [Event::Refused(0)]);
    }

    #[test]
    fn a_failing_random_source_ends_the_search() {
        let mut binder = fake(1024, free);
        let error = choose(&mut binder, || Err(io::Error::other("no randomness")))
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "no randomness");
        assert_eq!(
            *binder.log.borrow(),
            [Event::Bound(1024), Event::Closed(1024)]
        );
    }
}
