#![windows_subsystem = "windows"]
#![cfg_attr(not(windows), allow(dead_code))]

mod frame;
mod hit;
mod icons;
mod layout;
mod nav;
mod pointer;
#[cfg(test)]
mod res;
mod scale;
mod theme;

fn main() {}
