use std::mem::offset_of;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{HWND, LPARAM, RECT};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Controls::{
    ICC_BAR_CLASSES, INITCOMMONCONTROLSEX, InitCommonControlsEx, TOOLTIPS_CLASSW, TTF_SUBCLASS,
    TTM_ADDTOOLW, TTM_DELTOOLW, TTS_ALWAYSTIP, TTS_NOPREFIX, TTTOOLINFOW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CW_USEDEFAULT, CreateWindowExW, SendMessageW, WS_EX_TOPMOST, WS_POPUP,
};

use super::sys::wide;
use crate::layout::Rect;

type Tip = (Rect, &'static str);

pub struct Tips {
    window: HWND,
    owner: HWND,
    shown: Vec<Tip>,
}

impl Tips {
    pub fn new(owner: HWND) -> Self {
        let init = INITCOMMONCONTROLSEX {
            dwSize: size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_BAR_CLASSES,
        };
        let window = unsafe {
            InitCommonControlsEx(&init);
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
        };
        Self {
            window,
            owner,
            shown: Vec::new(),
        }
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
        let tool = |index: usize, r: Rect, text: *mut u16| TTTOOLINFOW {
            cbSize: offset_of!(TTTOOLINFOW, lpReserved) as u32,
            uFlags: TTF_SUBCLASS,
            hwnd: self.owner,
            uId: index,
            rect: RECT {
                left: r.x,
                top: r.y,
                right: r.right(),
                bottom: r.bottom(),
            },
            lpszText: text,
            ..Default::default()
        };
        for (index, &(r, _)) in self.old.iter().enumerate() {
            let info = tool(index, r, null_mut());
            unsafe { SendMessageW(self.window, TTM_DELTOOLW, 0, &raw const info as LPARAM) };
        }
        for (index, &(r, text)) in self.new.iter().enumerate() {
            let mut buffer = wide(text);
            let info = tool(index, r, buffer.as_mut_ptr());
            unsafe { SendMessageW(self.window, TTM_ADDTOOLW, 0, &raw const info as LPARAM) };
        }
    }
}
