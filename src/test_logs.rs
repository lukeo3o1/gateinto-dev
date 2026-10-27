use std::cell::RefCell;
use std::io;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex, Once};

type Buffer = Arc<Mutex<Vec<u8>>>;

thread_local! {
    static ACTIVE: RefCell<Option<Buffer>> = const { RefCell::new(None) };
}

struct ActiveWriter;

impl io::Write for ActiveWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        ACTIVE.with_borrow(|active| {
            if let Some(buffer) = active {
                buffer.lock().unwrap().extend_from_slice(bytes);
            }
        });
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// A scoped dispatcher per test is not enough: while it is the only one
// registered, tracing-core caches a callsite's interest from whichever thread
// reaches it first, so a parallel test without a dispatcher can disable it.
fn install() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        tracing::subscriber::set_global_default(
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .with_writer(|| ActiveWriter)
                .finish(),
        )
        .expect("no other global subscriber in the test binary");
        tracing::callsite::rebuild_interest_cache();
    });
}

pub(crate) struct Capture {
    buffer: Buffer,
    previous: Option<Buffer>,
    thread_bound: PhantomData<*const ()>,
}

pub(crate) fn capture() -> Capture {
    install();
    let buffer = Buffer::default();
    let previous = ACTIVE.replace(Some(buffer.clone()));
    Capture {
        buffer,
        previous,
        thread_bound: PhantomData,
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        ACTIVE.set(self.previous.take());
    }
}

impl Capture {
    pub(crate) fn lines(&self, level: &str) -> Vec<String> {
        String::from_utf8(self.buffer.lock().unwrap().clone())
            .unwrap()
            .lines()
            .filter(|line| line.contains(level))
            .map(str::to_owned)
            .collect()
    }
}

mod tests {
    use super::*;

    #[test]
    fn an_event_first_seen_on_an_uncaptured_thread_is_still_captured() {
        let logs = capture();
        let emit = || tracing::warn!("first seen elsewhere");
        std::thread::scope(|scope| scope.spawn(emit).join().unwrap());
        emit();
        assert_eq!(logs.lines(" WARN ").len(), 1, "{:?}", logs.lines(""));
    }

    #[test]
    fn events_on_uncaptured_threads_are_discarded() {
        let logs = capture();
        std::thread::scope(|scope| {
            scope
                .spawn(|| tracing::debug!("spawned thread"))
                .join()
                .unwrap()
        });
        tracing::debug!("capturing thread");
        assert_eq!(logs.lines("capturing thread"), logs.lines(" DEBUG "));
        assert_eq!(logs.lines(" DEBUG ").len(), 1, "{:?}", logs.lines(""));
    }
}
