#![windows_subsystem = "windows"]
#![cfg_attr(not(windows), allow(dead_code))]

mod agent;
mod fonts;
mod frame;
mod hit;
mod icons;
mod layout;
mod nav;
mod pointer;
#[cfg(test)]
mod res;
mod scale;
mod scene;
mod theme;
#[cfg(windows)]
mod win;

fn main() {
    #[cfg(windows)]
    win::run();
}
