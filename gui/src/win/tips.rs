use std::mem::offset_of;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{HWND, LPARAM, RECT};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Controls::{
    ICC_BAR_CLASSES, INITCOMMONCONTROLSEX, InitCommonControlsEx, TOOLTIPS_CLASSW, TTF_ABSOLUTE,
    TTF_SUBCLASS, TTF_TRACK, TTM_ADDTOOLW, TTM_DELTOOLW, TTM_TRACKACTIVATE, TTM_TRACKPOSITION,
    TTS_ALWAYSTIP, TTS_NOPREFIX, TTTOOLINFOW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CW_USEDEFAULT, CreateWindowExW, SendMessageW, WS_EX_TOPMOST, WS_POPUP,
};

use super::sys::wide;
use crate::layout::Rect;

type Tip = (Rect, &'static str);
type Pinned = ((i32, i32), &'static str);

pub struct Tips {
    window: HWND,
    pin: HWND,
    owner: HWND,
    shown: Vec<Tip>,
    pinned: Option<Pinned>,
}

fn create(owner: HWND) -> HWND {
    unsafe {
        CreateWindowExW(
            WS_EX_TOPMOST,
            TOOLTIPS_CLASSW,
            null(),
            WS_POPUP | TTS_ALWAYSTIP | TTS_NOPREFIX,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            owner,
            null_mut(),
            GetModuleHandleW(null()),
            null(),
        )
    }
}

fn tool(owner: HWND, flags: u32, id: usize, r: Rect, text: *mut u16) -> TTTOOLINFOW {
    TTTOOLINFOW {
        cbSize: offset_of!(TTTOOLINFOW, lpReserved) as u32,
        uFlags: flags,
        hwnd: owner,
        uId: id,
        rect: RECT {
            left: r.x,
            top: r.y,
            right: r.right(),
            bottom: r.bottom(),
        },
        lpszText: text,
        ..Default::default()
    }
}

impl Tips {
    pub fn new(owner: HWND) -> Self {
        let init = INITCOMMONCONTROLSEX {
            dwSize: size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_BAR_CLASSES,
        };
        unsafe { InitCommonControlsEx(&init) };
        Self {
            window: create(owner),
            pin: create(owner),
            owner,
            shown: Vec::new(),
            pinned: None,
        }
    }

    pub fn windows(&self) -> [HWND; 2] {
        [self.window, self.pin]
    }

    pub fn pinned(&self) -> bool {
        self.pinned.is_some()
    }

    pub fn replace(&mut self, tips: Vec<Tip>) -> Option<Change> {
        if self.window.is_null() || tips == self.shown {
            return None;
        }
        Some(Change {
            window: self.window,
            owner: self.owner,
            old: std::mem::replace(&mut self.shown, tips.clone()),
            new: tips,
        })
    }

    pub fn pin(&mut self, tip: Option<Pinned>) -> Option<Pin> {
        if self.pin.is_null() || tip == self.pinned {
            return None;
        }
        Some(Pin {
            window: self.pin,
            owner: self.owner,
            old: std::mem::replace(&mut self.pinned, tip),
            new: tip,
        })
    }
}

pub struct Change {
    window: HWND,
    owner: HWND,
    old: Vec<Tip>,
    new: Vec<Tip>,
}

impl Change {
    // Sends messages that reach the owner window, so it must run outside `with_app`.
    pub fn apply(self) {
        for (index, &(r, _)) in self.old.iter().enumerate() {
            let info = tool(self.owner, TTF_SUBCLASS, index, r, null_mut());
            unsafe { SendMessageW(self.window, TTM_DELTOOLW, 0, &raw const info as LPARAM) };
        }
        for (index, &(r, text)) in self.new.iter().enumerate() {
            let mut buffer = wide(text);
            let info = tool(self.owner, TTF_SUBCLASS, index, r, buffer.as_mut_ptr());
            unsafe { SendMessageW(self.window, TTM_ADDTOOLW, 0, &raw const info as LPARAM) };
        }
    }
}

pub struct Pin {
    window: HWND,
    owner: HWND,
    old: Option<Pinned>,
    new: Option<Pinned>,
}

impl Pin {
    // Like `Change::apply`, it must run outside `with_app`.
    pub fn apply(self) {
        let flags = TTF_TRACK | TTF_ABSOLUTE;
        let none = Rect::new(0, 0, 0, 0);
        if self.old.is_some() {
            let info = tool(self.owner, flags, 0, none, null_mut());
            let info = &raw const info as LPARAM;
            unsafe {
                SendMessageW(self.window, TTM_TRACKACTIVATE, 0, info);
                SendMessageW(self.window, TTM_DELTOOLW, 0, info);
            }
        }
        if let Some(((x, y), text)) = self.new {
            let mut buffer = wide(text);
            let info = tool(self.owner, flags, 0, none, buffer.as_mut_ptr());
            let info = &raw const info as LPARAM;
            let at = ((y as u32 & 0xFFFF) << 16 | (x as u32 & 0xFFFF)) as LPARAM;
            unsafe {
                SendMessageW(self.window, TTM_ADDTOOLW, 0, info);
                SendMessageW(self.window, TTM_TRACKPOSITION, 0, at);
                SendMessageW(self.window, TTM_TRACKACTIVATE, 1, info);
            }
        }
    }
}
