#![windows_subsystem = "windows"]
#![cfg_attr(not(windows), allow(dead_code))]

mod color;
mod cue;
mod fonts;
mod geom;
mod icons;
mod layout;
mod model;
mod scale;
mod style;
#[cfg(windows)]
mod win;

fn main() {
    #[cfg(windows)]
    win::run();
}
