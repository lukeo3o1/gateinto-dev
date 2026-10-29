use std::ffi::c_void;
use std::ptr::{null, null_mut};
use std::time::Duration;

use gateinto::link::Confirmation;
use windows_sys::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{BeginPaint, EndPaint, InvalidateRect, PAINTSTRUCT};
use windows_sys::Win32::System::SystemInformation::GetTickCount64;
use windows_sys::Win32::UI::Controls::WM_MOUSELEAVE;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    GetCapture, ReleaseCapture, SetCapture, TME_LEAVE, VK_ESCAPE, VK_RETURN, VK_SPACE,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CREATESTRUCTW, CreateWindowExW, DefWindowProcW, DestroyWindow, GWLP_USERDATA, GetCursorPos,
    GetWindowLongPtrW, HWND_TOPMOST, IDC_ARROW, KillTimer, LoadCursorW, RegisterClassExW, SW_HIDE,
    SWP_NOACTIVATE, SWP_NOZORDER, SWP_SHOWWINDOW, SetForegroundWindow, SetTimer, SetWindowLongPtrW,
    SetWindowPos, SetWindowTextW, ShowWindow, WM_ACTIVATE, WM_CAPTURECHANGED, WM_CLOSE,
    WM_DPICHANGED, WM_ERASEBKGND, WM_KEYDOWN, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MOUSEMOVE,
    WM_NCCREATE, WM_PAINT, WM_SETFOCUS, WM_TIMER, WM_WINDOWPOSCHANGED, WNDCLASSEXW, WS_CAPTION,
    WS_EX_TOPMOST, WS_POPUP, WS_SYSMENU,
};

use super::d2d::Graphics;
use super::text::Fonts;
use super::{App, client_size, coords, sys, track, tray, wide, with_app};
use crate::approval::{self, Answer, Button, Dialog, Key};
use crate::board::approval::{self as sheet, Sheet};
use crate::hit::{Zone, find};
use crate::i18n::{Text, confirmation_notice, tr};
use crate::layout::Rect;
use crate::scale::Scale;
use crate::worker::{Command, Prompt};

const STYLE: u32 = WS_POPUP | WS_CAPTION | WS_SYSMENU;
const EX_STYLE: u32 = WS_EX_TOPMOST;
const TIMER: usize = 1;
const TICK_MS: u32 = 250;

pub struct Approval {
    hwnd: HWND,
    s: Scale,
    fonts: Option<Fonts>,
    open: Option<Open>,
    targets: Vec<(Rect, Zone)>,
}

struct Open {
    dialog: Dialog,
    confirmation: Confirmation,
    hover: Option<Button>,
    shown: Option<u64>,
}

impl Approval {
    pub fn new(s: Scale) -> Self {
        Self {
            hwnd: null_mut(),
            s,
            fonts: None,
            open: None,
            targets: Vec::new(),
        }
    }

    pub fn window(&self) -> HWND {
        self.hwnd
    }

    fn rescale(&mut self, gfx: &Graphics, s: Scale) {
        if self.fonts.is_some() && self.s == s {
            return;
        }
        if let Ok(fonts) = Fonts::new(gfx.dwrite(), s) {
            self.s = s;
            self.fonts = Some(fonts);
        }
    }

    pub(super) fn reshape(&mut self, gfx: &Graphics) {
        let title = wide(tr(Text::ApprovalTitle));
        unsafe { SetWindowTextW(self.hwnd, title.as_ptr()) };
        if self.fonts.is_some()
            && let Ok(fonts) = Fonts::new(gfx.dwrite(), self.s)
        {
            self.fonts = Some(fonts);
        }
        self.invalidate();
    }

    pub(super) fn invalidate(&self) {
        if self.open.is_some() {
            unsafe { InvalidateRect(self.hwnd, null(), 0) };
        }
    }

    fn rearm(&mut self) {
        if let Some(open) = &mut self.open {
            open.dialog.rearm(now());
            self.invalidate();
        }
    }
}

fn now() -> Duration {
    Duration::from_millis(unsafe { GetTickCount64() })
}

pub fn prompt(main: HWND, prompt: Prompt) {
    match prompt {
        Prompt::Ask(ticket, confirmation) => ask(main, ticket, confirmation),
        Prompt::Dismiss(ticket) => {
            let open = with_app(main, |app| {
                app.approval
                    .open
                    .as_ref()
                    .is_some_and(|open| open.dialog.ticket() == ticket)
            });
            if open == Some(true) {
                close(main);
            }
        }
    }
}

fn ask(main: HWND, ticket: u64, confirmation: Confirmation) {
    let Some((hwnd, r)) = place(main, ticket, confirmation) else {
        with_app(main, |app| {
            app.link.send(Command::Answer(ticket, Answer::Deny))
        });
        close(main);
        return;
    };
    unsafe {
        SetWindowPos(hwnd, HWND_TOPMOST, r.x, r.y, r.w, r.h, SWP_SHOWWINDOW);
        SetForegroundWindow(hwnd);
        SetTimer(hwnd, TIMER, TICK_MS, None);
    }
    with_app(main, |app| app.approval.rearm());
}

fn place(main: HWND, ticket: u64, confirmation: Confirmation) -> Option<(HWND, Rect)> {
    let mut cursor = POINT::default();
    unsafe { GetCursorPos(&mut cursor) };
    let (work, _, dpi) = tray::work_area(cursor)?;
    let s = Scale::new(dpi);
    with_app(main, |app| {
        let approval = &mut app.approval;
        approval.rescale(&app.gfx, s);
        let fonts = approval
            .fonts
            .as_ref()
            .filter(|_| !approval.hwnd.is_null())?;
        let (w, h) = outer(s, fonts, &confirmation);
        approval.open = Some(Open {
            dialog: Dialog::open(ticket, now()),
            confirmation,
            hover: None,
            shown: None,
        });
        approval.targets.clear();
        approval.invalidate();
        Some((approval.hwnd, approval::centred(work, w, h)))
    })
    .flatten()
}

fn outer(s: Scale, fonts: &Fonts, confirmation: &Confirmation) -> (i32, i32) {
    let notice = confirmation_notice(confirmation);
    let (w, h) = (sheet::width(s), sheet::height(s, fonts, &notice));
    let [left, top, right, bottom] = sys::adjusted_rect(w, h, STYLE, EX_STYLE, s.dpi);
    (right - left, bottom - top)
}

fn answer(main: HWND, answer: Answer) {
    let answered = with_app(main, |app| {
        let open = app.approval.open.as_ref()?;
        app.link.send(Command::Answer(open.dialog.ticket(), answer));
        Some(())
    });
    if answered.flatten().is_some() {
        close(main);
    }
}

fn close(main: HWND) {
    let hwnd = with_app(main, |app| {
        app.approval.open = None;
        app.approval.targets.clear();
        app.approval.hwnd
    });
    if let Some(hwnd) = hwnd.filter(|hwnd| !hwnd.is_null()) {
        release_capture(hwnd);
        unsafe {
            KillTimer(hwnd, TIMER);
            ShowWindow(hwnd, SW_HIDE);
        }
    }
}

fn release_capture(hwnd: HWND) {
    if unsafe { GetCapture() } == hwnd {
        unsafe { ReleaseCapture() };
    }
}

pub fn destroy(main: HWND) {
    answer(main, Answer::Deny);
    let hwnd = with_app(main, |app| {
        std::mem::replace(&mut app.approval.hwnd, null_mut())
    });
    if let Some(hwnd) = hwnd.filter(|hwnd| !hwnd.is_null()) {
        unsafe { DestroyWindow(hwnd) };
    }
}

fn paint(hwnd: HWND, main: HWND) {
    let mut ps = PAINTSTRUCT::default();
    let dc = unsafe { BeginPaint(hwnd, &mut ps) };
    with_app(main, |app| {
        let t = app.palette();
        let approval = &mut app.approval;
        let (Some(open), Some(fonts)) = (&mut approval.open, &approval.fonts) else {
            return;
        };
        let countdown = open.dialog.countdown(now());
        open.shown = countdown;
        let notice = confirmation_notice(&open.confirmation);
        let page = Sheet {
            notice: &notice,
            countdown,
            hover: open.hover,
            pressed: open.dialog.pressed(),
        };
        let (w, h) = client_size(hwnd);
        let frame = Rect::new(0, 0, w, h);
        let board = sheet::approval(frame, approval.s, t, &page, fonts);
        approval.targets = board.targets;
        if !app.gfx.draw(dc, frame, &board.ops, fonts) {
            approval.invalidate();
        }
    });
    unsafe { EndPaint(hwnd, &ps) };
}

fn pointed(app: &App, lp: LPARAM) -> Option<Button> {
    let (x, y) = coords(lp);
    sheet::button(find(&app.approval.targets, x, y))
}

fn mouse(hwnd: HWND, main: HWND, msg: u32, lp: LPARAM) {
    let outcome = with_app(main, |app| {
        let button = pointed(app, lp);
        let approval = &mut app.approval;
        let open = approval.open.as_mut()?;
        let before = (open.hover, open.dialog.pressed());
        open.hover = button;
        let answer = match msg {
            WM_LBUTTONDOWN => {
                open.dialog.press(button, now());
                None
            }
            WM_LBUTTONUP => open.dialog.release(button, now()),
            _ => None,
        };
        let pressed = open.dialog.pressed().is_some();
        if before != (open.hover, open.dialog.pressed()) {
            approval.invalidate();
        }
        Some((pressed, answer))
    });
    let Some(Some((pressed, answered))) = outcome else {
        if msg == WM_LBUTTONUP {
            release_capture(hwnd);
        }
        return;
    };
    match msg {
        WM_MOUSEMOVE => track(hwnd, TME_LEAVE),
        WM_LBUTTONDOWN if pressed => {
            unsafe { SetCapture(hwnd) };
        }
        WM_LBUTTONUP => release_capture(hwnd),
        _ => {}
    }
    if let Some(answered) = answered {
        answer(main, answered);
    }
}

fn left(main: HWND) {
    with_app(main, |app| {
        if let Some(open) = &mut app.approval.open
            && open.hover.take().is_some()
        {
            app.approval.invalidate();
        }
    });
}

fn cancelled(main: HWND) {
    with_app(main, |app| {
        if let Some(open) = &mut app.approval.open
            && open.dialog.pressed().is_some()
        {
            open.dialog.release(None, now());
            app.approval.invalidate();
        }
    });
}

fn key(main: HWND, wp: WPARAM) -> Option<LRESULT> {
    let key = match u16::try_from(wp).ok()? {
        VK_RETURN => Key::Enter,
        VK_SPACE => Key::Space,
        VK_ESCAPE => Key::Escape,
        _ => return None,
    };
    let answered = with_app(main, |app| {
        app.approval.open.as_mut().map(|open| open.dialog.key(key))
    });
    if let Some(Some(answered)) = answered {
        answer(main, answered);
    }
    Some(0)
}

fn tick(main: HWND) {
    let at = now();
    let expired = with_app(main, |app| {
        let approval = &app.approval;
        let open = approval.open.as_ref()?;
        if open.dialog.expired(at) {
            return Some(true);
        }
        if open.dialog.countdown(at) != open.shown {
            approval.invalidate();
        }
        Some(false)
    });
    if expired == Some(Some(true)) {
        answer(main, Answer::Deny);
    }
}

fn rescaled(hwnd: HWND, main: HWND, wp: WPARAM, lp: LPARAM) {
    let s = Scale::new((wp & 0xffff) as u32);
    let r = unsafe { &*(lp as *const RECT) };
    let size = with_app(main, |app| {
        let approval = &mut app.approval;
        approval.rescale(&app.gfx, s);
        approval.rearm();
        let open = approval.open.as_ref()?;
        Some(outer(
            approval.s,
            approval.fonts.as_ref()?,
            &open.confirmation,
        ))
    });
    let flags = SWP_NOZORDER | SWP_NOACTIVATE;
    let (w, h) = size
        .flatten()
        .unwrap_or((r.right - r.left, r.bottom - r.top));
    unsafe { SetWindowPos(hwnd, null_mut(), r.left, r.top, w, h, flags) };
}

fn rearm(main: HWND) {
    with_app(main, |app| app.approval.rearm());
}

unsafe extern "system" fn approval_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    if msg == WM_NCCREATE {
        let create = unsafe { &*(lp as *const CREATESTRUCTW) };
        unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, create.lpCreateParams as _) };
    }
    let main = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as HWND;
    let handled = match msg {
        _ if main.is_null() => None,
        WM_PAINT => {
            paint(hwnd, main);
            Some(0)
        }
        WM_ERASEBKGND => Some(1),
        WM_MOUSEMOVE | WM_LBUTTONDOWN | WM_LBUTTONUP => {
            mouse(hwnd, main, msg, lp);
            Some(0)
        }
        WM_MOUSELEAVE => {
            left(main);
            Some(0)
        }
        WM_CAPTURECHANGED => {
            cancelled(main);
            Some(0)
        }
        WM_ACTIVATE | WM_SETFOCUS | WM_WINDOWPOSCHANGED => {
            rearm(main);
            None
        }
        WM_DPICHANGED => {
            rescaled(hwnd, main, wp, lp);
            Some(0)
        }
        WM_KEYDOWN => key(main, wp),
        WM_CLOSE => {
            answer(main, Answer::Deny);
            Some(0)
        }
        WM_TIMER if wp == TIMER => {
            tick(main);
            Some(0)
        }
        _ => None,
    };
    handled.unwrap_or_else(|| unsafe { DefWindowProcW(hwnd, msg, wp, lp) })
}

pub fn install(main: HWND, instance: HINSTANCE, demo: bool) {
    let hwnd = create(main, instance, demo);
    if hwnd.is_null() {
        return;
    }
    let dark = with_app(main, |app| {
        app.approval.hwnd = hwnd;
        (app.dark, app.build)
    });
    if let Some((dark, build)) = dark {
        sys::dark_title_bar(hwnd, dark, build);
    }
}

fn create(main: HWND, instance: HINSTANCE, demo: bool) -> HWND {
    let class = wide(crate::instance::approval_class(demo));
    let title = wide(tr(Text::ApprovalTitle));
    let wc = WNDCLASSEXW {
        cbSize: size_of::<WNDCLASSEXW>() as u32,
        lpfnWndProc: Some(approval_proc),
        hInstance: instance,
        hCursor: unsafe { LoadCursorW(null_mut(), IDC_ARROW) },
        lpszClassName: class.as_ptr(),
        ..Default::default()
    };
    if unsafe { RegisterClassExW(&wc) } == 0 {
        return null_mut();
    }
    unsafe {
        CreateWindowExW(
            EX_STYLE,
            class.as_ptr(),
            title.as_ptr(),
            STYLE,
            0,
            0,
            0,
            0,
            null_mut(),
            null_mut(),
            instance,
            main as *const c_void,
        )
    }
}
