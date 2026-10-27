use std::io;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use gateinto::browser::find_browser;
use gateinto::config;
use gateinto::ipc::{self, Endpoint, Request, RequestError};
use gateinto::link::store;
use tokio::runtime::Builder;
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::WindowsAndMessaging::{PostMessageW, WM_APP};

use super::device::system;
use crate::agent::AgentState;
use crate::device::{self, Probe};
use crate::gateways;
use crate::settings;
use crate::worker::{Command, Loaded, Mailbox, Update, serve};

pub const WM_AGENT: u32 = WM_APP;

pub struct Link {
    commands: UnboundedSender<Command>,
    mailbox: Arc<Mutex<Mailbox>>,
}

fn open(mailbox: &Mutex<Mailbox>) -> MutexGuard<'_, Mailbox> {
    mailbox.lock().unwrap_or_else(PoisonError::into_inner)
}

fn load() -> Loaded {
    let file = gateways::read(config::default_path());
    let known = file
        .as_ref()
        .map(|file| gateways::catalog(file, store::default_dir()))
        .map_err(Clone::clone);
    let listen = device::configured_listen(&file);
    let agent = file.map(|file| settings::agent(&file, || find_browser(None).ok()));
    Loaded {
        gateways: known,
        agent,
        listen,
    }
}

fn probe() -> Probe {
    let file = gateways::read(config::default_path());
    device::probe(&file, gateinto::identity::system_store, system())
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
                        let Loaded {
                            gateways,
                            agent,
                            listen,
                        } = load();
                        deliver(Update {
                            state: AgentState::Unreachable(error.to_string()),
                            gateways,
                            agent,
                            listen,
                            failure: None,
                            launched: 0,
                            device: None,
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
                runtime.block_on(serve(inbox, send, load, probe, deliver));
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
