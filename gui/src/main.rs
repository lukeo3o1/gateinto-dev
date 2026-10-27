#![windows_subsystem = "windows"]
#![cfg_attr(not(windows), allow(dead_code))]

mod agent;
mod board;
mod fonts;
mod frame;
mod gateways;
mod hit;
mod icons;
mod layout;
mod logo;
mod menu;
mod nav;
mod pointer;
#[cfg(test)]
mod res;
mod scale;
mod scene;
mod scroll;
mod sessions;
mod settings;
mod theme;
#[cfg(windows)]
mod win;
mod worker;

fn main() {
    #[cfg(windows)]
    win::run();
}
