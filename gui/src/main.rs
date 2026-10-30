#![windows_subsystem = "windows"]
#![cfg_attr(not(windows), allow(dead_code))]

mod add;
mod agent;
mod approval;
mod board;
mod credentials;
mod demo;
mod device;
mod focus;
mod fonts;
mod frame;
mod gateways;
mod handoff;
mod hit;
mod i18n;
mod icons;
mod instance;
mod layout;
mod log;
mod logo;
mod menu;
mod message;
mod nav;
mod pointer;
#[cfg(test)]
mod res;
mod scale;
mod scene;
mod scroll;
mod sessions;
mod settings;
mod start;
mod theme;
mod tray;
#[cfg(windows)]
mod win;
mod worker;

fn main() {
    #[cfg(windows)]
    win::run();
}
