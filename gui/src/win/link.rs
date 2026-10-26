use std::io;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use gateinto::config;
use gateinto::ipc::{self, Endpoint, Request, RequestError};
use gateinto::link::{Known, store};
use tokio::runtime::Builder;
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::WindowsAndMessaging::{PostMessageW, WM_APP};

use crate::agent::AgentState;
use crate::gateways;
use crate::worker::{Command, Mailbox, Update, serve};

pub const WM_AGENT: u32 = WM_APP;

pub struct Link {
    commands: UnboundedSender<Command>,
    mailbox: Arc<Mutex<Mailbox>>,
}

fn open(mailbox: &Mutex<Mailbox>) -> MutexGuard<'_, Mailbox> {
    mailbox.lock().unwrap_or_else(PoisonError::into_inner)
}

fn known() -> Result<Known, String> {
    gateways::load(config::default_path(), store::default_dir())
}

impl Link {
    pub fn start(hwnd: HWND) -> Self {
        let (commands, inbox) = unbounded_channel();
        let mailbox = Arc::new(Mutex::new(Mailbox::default()));
        let shared = Arc::clone(&mailbox);
        let window = hwnd as isize;
        let deliver = move |update| {
            let mut mailbox = open(&shared);
            if mailbox.put(update) {
                unsafe { PostMessageW(window as HWND, WM_AGENT, 0, 0) };
            }
        };
        let _ = std::thread::Builder::new()
            .name("agent link".to_owned())
            .spawn(move || {
                let runtime = match Builder::new_current_thread().enable_all().build() {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        deliver(Update {
                            state: AgentState::Unreachable(error.to_string()),
                            gateways: known(),
                            failure: None,
                        });
                        return;
                    }
                };
                let endpoint = Endpoint::for_current_user();
                let send = |request: Request| {
                    let endpoint = &endpoint;
                    async move {
                        match endpoint {
                            Ok(endpoint) => ipc::send(endpoint, &request).await,
                            Err(error) => Err(RequestError::Io(io::Error::new(
                                error.kind(),
                                error.to_string(),
                            ))),
                        }
                    }
                };
                runtime.block_on(serve(inbox, send, known, deliver));
            });
        Self { commands, mailbox }
    }

    pub fn send(&self, command: Command) {
        let _ = self.commands.send(command);
    }

    pub fn take(&self) -> Option<Update> {
        open(&self.mailbox).take()
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        open(&self.mailbox).close();
    }
}
