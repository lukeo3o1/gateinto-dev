use std::ffi::c_void;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicU32, Ordering};

use windows_sys::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    BeginPaint, EndPaint, GetMonitorInfoW, InvalidateRect, MONITOR_DEFAULTTONEAREST,
    MONITOR_DEFAULTTOPRIMARY, MONITORINFO, MonitorFromPoint, PAINTSTRUCT,
};
use windows_sys::Win32::System::SystemInformation::GetTickCount64;
use windows_sys::Win32::UI::Controls::WM_MOUSELEAVE;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    GetKeyState, ReleaseCapture, SetCapture, TME_LEAVE, VK_DOWN, VK_ESCAPE, VK_LEFT, VK_RIGHT,
    VK_SHIFT, VK_TAB, VK_UP,
};
use windows_sys::Win32::UI::Shell::{
    NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY, NIM_SETVERSION,
    NOTIFYICON_VERSION_4, NOTIFYICONDATAW, NOTIFYICONDATAW_0, Shell_NotifyIconW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CREATESTRUCTW, CS_DROPSHADOW, ChangeWindowMessageFilterEx, CreatePopupMenu,
    CreateWindowExW, DefWindowProcW, DestroyMenu, DestroyWindow, GWLP_USERDATA, GetCursorPos,
    GetWindowLongPtrW, HICON, HWND_TOPMOST, IDC_ARROW, IsWindowVisible, LoadCursorW, MF_STRING,
    MSGFLT_ALLOW, PostMessageW, RegisterClassExW, RegisterWindowMessageW, SM_CXSMICON, SW_HIDE,
    SWP_SHOWWINDOW, SetForegroundWindow, SetWindowLongPtrW, SetWindowPos, SetWindowTextW,
    ShowWindow, TPM_NONOTIFY, TPM_RETURNCMD, TPM_RIGHTBUTTON, TrackPopupMenu, WA_INACTIVE,
    WM_ACTIVATE, WM_CAPTURECHANGED, WM_CHAR, WM_DPICHANGED, WM_ERASEBKGND, WM_KEYDOWN,
    WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MOUSEMOVE, WM_NCCREATE, WM_NULL, WM_PAINT, WNDCLASSEXW,
    WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_POPUP,
};

use super::d2d::Graphics;
use super::icon::{self, Owned};
use super::text::Fonts;
use super::{App, Follow, client_size, coords, show_main, sys, track, with_app};
use crate::board::{self, Board};
use crate::focus::{self, Focus, Stop};
use crate::hit::{Zone, find};
use crate::i18n::tr;
use crate::layout::Rect;
use crate::logo;
use crate::message;
use crate::nav::Page as NavPage;
use crate::pointer::Action;
use crate::scale::Scale;
use crate::scene::{Op, View};
use crate::theme::Theme;
use crate::tray::{self, Event, Notice};
use crate::worker::Command;

pub const WM_TRAY: u32 = message::TRAY;
const ICON_ID: u32 = 1;
const OPEN_ID: usize = 1;
const EXIT_ID: usize = 2;
const WIDTH: f32 = 360.0;
const HEIGHT: f32 = 520.0;
const MARGIN: f32 = 12.0;

static TASKBAR_CREATED: AtomicU32 = AtomicU32::new(0);

#[derive(Default)]
pub struct Notify {
    added: bool,
    version4: bool,
    shown: Option<(logo::State, String, i32)>,
    icon: Option<Owned>,
}

impl Notify {
    pub fn added(&self) -> bool {
        self.added
    }
}

pub struct Panel {
    hwnd: HWND,
    s: Scale,
    fonts: Option<Fonts>,
    view: View,
    targets: Vec<(Rect, Zone)>,
    stops: Vec<Stop>,
    focus: Focus,
    visible: bool,
    hidden_at: Option<u64>,
    notice: Notice,
}

impl Panel {
    pub fn new(s: Scale) -> Self {
        Self {
            hwnd: null_mut(),
            s,
            fonts: None,
            view: View::default(),
            targets: Vec::new(),
            stops: Vec::new(),
            focus: Focus::default(),
            visible: false,
            hidden_at: None,
            notice: Notice::default(),
        }
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

    pub(super) fn reshape(&mut self, gfx: &Graphics, demo: bool) {
        let title = super::wide(tray::flyout_title(demo));
        unsafe { SetWindowTextW(self.hwnd, title.as_ptr()) };
        if self.fonts.is_some()
            && let Ok(fonts) = Fonts::new(gfx.dwrite(), self.s)
        {
            self.fonts = Some(fonts);
        }
    }

    fn invalidate(&self) {
        unsafe { InvalidateRect(self.hwnd, null(), 0) };
    }

    fn adopt(&mut self, board: Board, t: &Theme) -> Vec<Op> {
        let (stops, trapped) = focus::stops(&[], &board.order);
        self.focus.sync(&stops, trapped);
        self.stops = stops;
        self.targets = board.targets;
        let mut ops = board.ops;
        let ring = self.focus.ring();
        if let Some(stop) = self.stops.iter().find(|s| Some(s.zone) == ring) {
            ops.extend(focus::outline(stop, self.s, t));
        }
        ops
    }

    fn tab(&mut self, back: bool) {
        if self.focus.tab(&self.stops, back).is_some() {
            self.invalidate();
        }
    }

    fn hide_ring(&mut self, zone: Zone) {
        if self.focus.ring().is_some() {
            self.invalidate();
        }
        self.focus.clicked(zone, &self.stops);
    }

    fn reset(&mut self) {
        self.view = View::default();
        self.focus = Focus::default();
        self.stops.clear();
        self.targets.clear();
    }
}

impl App {
    fn flyout_board(&self) -> Option<Board> {
        let panel = &self.panel;
        let fonts = panel.fonts.as_ref()?;
        let f = match &self.update {
            Some(u) => tray::flyout(
                &u.gateways,
                &u.state,
                self.launches.busy(),
                panel.notice.text(),
            ),
            None => tray::waiting(),
        };
        let (w, h) = client_size(panel.hwnd);
        let frame = Rect::new(0, 0, w, h);
        Some(board::tray::flyout(
            frame,
            panel.s,
            self.palette(),
            &panel.view,
            &f,
            fonts,
        ))
    }

    pub(super) fn refresh_flyout(&mut self) {
        if !self.panel.visible {
            return;
        }
        let board = self.flyout_board().unwrap_or_default();
        let t = self.palette();
        self.panel.adopt(board, t);
        self.panel.invalidate();
    }

    pub(super) fn launch_settled(&mut self, failure: Option<&crate::i18n::Note>) {
        if !self.launches.busy() {
            self.panel.notice.settle(failure, self.panel.visible);
        }
    }

    pub(super) fn gateways_changed(&mut self) {
        self.view.pointer.gateways_changed();
        self.panel.view.pointer.gateways_changed();
    }
}

fn register(main: HWND) {
    let name = super::wide("TaskbarCreated");
    let id = unsafe { RegisterWindowMessageW(name.as_ptr()) };
    TASKBAR_CREATED.store(id, Ordering::Relaxed);
    if id != 0 {
        unsafe { ChangeWindowMessageFilterEx(main, id, MSGFLT_ALLOW, null_mut()) };
    }
}

pub fn taskbar_created(msg: u32) -> bool {
    let id = TASKBAR_CREATED.load(Ordering::Relaxed);
    id != 0 && msg == id
}

fn current(app: &App) -> (logo::State, String, i32) {
    let status = app
        .update
        .as_ref()
        .map_or_else(tray::pending, |u| tray::status(&u.state));
    (status.logo, tray::tooltip(&status, app.demo), icon_size())
}

fn icon_size() -> i32 {
    let primary = unsafe { MonitorFromPoint(POINT::default(), MONITOR_DEFAULTTOPRIMARY) };
    sys::metric_for_dpi(SM_CXSMICON, sys::monitor_dpi(primary)).max(1)
}

fn notify_data(main: HWND, icon: HICON, tip: &str) -> NOTIFYICONDATAW {
    let mut units = [0; 128];
    for (slot, unit) in units
        .iter_mut()
        .zip(tip.encode_utf16().take(tray::TIP_UNITS))
    {
        *slot = unit;
    }
    NOTIFYICONDATAW {
        cbSize: size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: main,
        uID: ICON_ID,
        uFlags: NIF_MESSAGE | NIF_ICON | NIF_TIP,
        uCallbackMessage: WM_TRAY,
        hIcon: icon,
        szTip: units,
        ..Default::default()
    }
}

fn add_icon(main: HWND) -> bool {
    let Some(wanted) = with_app(main, |app| current(app)) else {
        return false;
    };
    let Some(icon) = icon::render(wanted.0, wanted.2) else {
        return false;
    };
    let data = notify_data(main, icon.0, &wanted.1);
    let added = unsafe {
        Shell_NotifyIconW(NIM_ADD, &data) != 0
            || (Shell_NotifyIconW(NIM_DELETE, &data) != 0 && Shell_NotifyIconW(NIM_ADD, &data) != 0)
            || Shell_NotifyIconW(NIM_MODIFY, &data) != 0
    };
    let version = NOTIFYICONDATAW {
        Anonymous: NOTIFYICONDATAW_0 {
            uVersion: NOTIFYICON_VERSION_4,
        },
        ..data
    };
    let version4 = added && unsafe { Shell_NotifyIconW(NIM_SETVERSION, &version) } != 0;
    with_app(main, |app| {
        app.notify = if added {
            Notify {
                added,
                version4,
                shown: Some(wanted),
                icon: Some(icon),
            }
        } else {
            Notify::default()
        };
    });
    added
}

pub fn refresh_icon(main: HWND) {
    let wanted = with_app(main, |app| {
        let wanted = current(app);
        (app.notify.added && app.notify.shown.as_ref() != Some(&wanted)).then_some(wanted)
    });
    let Some(Some(wanted)) = wanted else {
        return;
    };
    let Some(icon) = icon::render(wanted.0, wanted.2) else {
        return;
    };
    let data = notify_data(main, icon.0, &wanted.1);
    if unsafe { Shell_NotifyIconW(NIM_MODIFY, &data) } != 0 {
        with_app(main, |app| {
            app.notify.shown = Some(wanted);
            app.notify.icon = Some(icon);
        });
    }
}

fn remove_icon(main: HWND) {
    let Some(notify) = with_app(main, |app| std::mem::take(&mut app.notify)) else {
        return;
    };
    if notify.added {
        let data = NOTIFYICONDATAW {
            cbSize: size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: main,
            uID: ICON_ID,
            ..Default::default()
        };
        unsafe { Shell_NotifyIconW(NIM_DELETE, &data) };
    }
}

pub fn on_taskbar_created(main: HWND) {
    with_app(main, |app| app.notify = Notify::default());
    if !add_icon(main) && unsafe { IsWindowVisible(main) } == 0 {
        hide_flyout(main);
        show_main(main);
    }
}

pub fn destroy(main: HWND) {
    remove_icon(main);
    let flyout = with_app(main, |app| {
        app.panel.visible = false;
        std::mem::replace(&mut app.panel.hwnd, null_mut())
    });
    if let Some(flyout) = flyout.filter(|hwnd| !hwnd.is_null()) {
        unsafe { DestroyWindow(flyout) };
    }
}

fn point(anchor: Option<(i32, i32)>) -> Option<POINT> {
    if let Some((x, y)) = anchor {
        return Some(POINT { x, y });
    }
    let mut p = POINT::default();
    (unsafe { GetCursorPos(&mut p) } != 0).then_some(p)
}

fn toggle(main: HWND, anchor: Option<(i32, i32)>) {
    let now = unsafe { GetTickCount64() };
    let reopen = with_app(main, |app| {
        (!app.panel.visible).then(|| tray::reopens(now, app.panel.hidden_at))
    });
    match reopen {
        Some(Some(true)) => show_flyout(main, anchor, false),
        Some(None) => hide_flyout(main),
        _ => {}
    }
}

pub fn on_tray(main: HWND, wp: WPARAM, lp: LPARAM) {
    let version4 = with_app(main, |app| app.notify.version4).unwrap_or(false);
    match tray::event(version4, wp, lp) {
        Some(Event::Click) => toggle(main, None),
        Some(Event::Select(anchor)) => toggle(main, Some(anchor)),
        Some(Event::KeySelect(anchor)) => {
            if with_app(main, |app| !app.panel.visible) == Some(true) {
                show_flyout(main, Some(anchor), true);
            }
        }
        Some(Event::Menu(anchor)) => context_menu(main, anchor),
        None => {}
    }
}

fn context_menu(main: HWND, anchor: Option<(i32, i32)>) {
    hide_flyout(main);
    let Some(p) = point(anchor) else {
        return;
    };
    let (open, exit) = (super::wide(tr(tray::OPEN)), super::wide(tr(tray::EXIT)));
    let choice = unsafe {
        let menu = CreatePopupMenu();
        if menu.is_null() {
            return;
        }
        AppendMenuW(menu, MF_STRING, OPEN_ID, open.as_ptr());
        AppendMenuW(menu, MF_STRING, EXIT_ID, exit.as_ptr());
        SetForegroundWindow(main);
        let flags = TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_NONOTIFY;
        let choice = TrackPopupMenu(menu, flags, p.x, p.y, 0, main, null());
        PostMessageW(main, WM_NULL, 0, 0);
        DestroyMenu(menu);
        choice as usize
    };
    match choice {
        OPEN_ID => show_main(main),
        EXIT_ID => {
            unsafe { DestroyWindow(main) };
        }
        _ => {}
    }
}

fn work_area(cursor: POINT) -> Option<(Rect, Rect, u32)> {
    let monitor = unsafe { MonitorFromPoint(cursor, MONITOR_DEFAULTTONEAREST) };
    let mut info = MONITORINFO {
        cbSize: size_of::<MONITORINFO>() as u32,
        ..Default::default()
    };
    if unsafe { GetMonitorInfoW(monitor, &mut info) } == 0 {
        return None;
    }
    let rect = |r: RECT| Rect::new(r.left, r.top, r.right - r.left, r.bottom - r.top);
    Some((
        rect(info.rcWork),
        rect(info.rcMonitor),
        sys::monitor_dpi(monitor),
    ))
}

fn show_flyout(main: HWND, anchor: Option<(i32, i32)>, keyboard: bool) {
    let Some(cursor) = point(anchor) else {
        return;
    };
    let Some((work, monitor, dpi)) = work_area(cursor) else {
        return;
    };
    let s = Scale::new(dpi);
    let size = (s.px(WIDTH), s.px(HEIGHT));
    let r = tray::place(work, monitor, (cursor.x, cursor.y), size, s.px(MARGIN));
    let hwnd = with_app(main, |app| {
        let panel = &mut app.panel;
        panel.rescale(&app.gfx, s);
        if panel.hwnd.is_null() || panel.fonts.is_none() {
            return None;
        }
        panel.reset();
        panel.visible = true;
        panel.notice.shown();
        Some(panel.hwnd)
    });
    let Some(Some(hwnd)) = hwnd else {
        return;
    };
    unsafe {
        SetWindowPos(hwnd, HWND_TOPMOST, r.x, r.y, r.w, r.h, SWP_SHOWWINDOW);
        SetForegroundWindow(hwnd);
    }
    with_app(main, |app| {
        app.refresh_flyout();
        if keyboard {
            app.panel.tab(false);
        }
    });
}

pub fn hide_flyout(main: HWND) {
    let now = unsafe { GetTickCount64() };
    let hwnd = with_app(main, |app| {
        let panel = &mut app.panel;
        if !panel.visible {
            return None;
        }
        panel.visible = false;
        panel.hidden_at = Some(now);
        panel.notice.hidden();
        panel.reset();
        Some(panel.hwnd)
    });
    if let Some(Some(hwnd)) = hwnd {
        unsafe { ShowWindow(hwnd, SW_HIDE) };
    }
}

fn act(main: HWND, action: Option<Action>) {
    match action {
        Some(Action::StartBrowser(row)) => {
            with_app(main, |app| {
                if app.launch(row) {
                    app.panel.notice.wait();
                }
                app.refresh_flyout();
            });
        }
        Some(Action::StopAgent) => {
            with_app(main, |app| app.link.send(Command::Stop));
        }
        Some(Action::AddGateway) => {
            open_main(main);
            with_app(main, |app| {
                app.dismiss();
                app.select(NavPage::Gateways);
                app.open_add();
            });
        }
        Some(Action::OpenMain) => open_main(main),
        _ => {}
    }
}

pub fn open_main(main: HWND) {
    hide_flyout(main);
    show_main(main);
}

fn paint(hwnd: HWND, main: HWND) {
    let mut ps = PAINTSTRUCT::default();
    let dc = unsafe { BeginPaint(hwnd, &mut ps) };
    with_app(main, |app| {
        let Some(board) = app.flyout_board() else {
            return;
        };
        let (w, h) = client_size(hwnd);
        let t = app.palette();
        let ops = app.panel.adopt(board, t);
        let Some(fonts) = &app.panel.fonts else {
            return;
        };
        if !app.gfx.draw(dc, Rect::new(0, 0, w, h), &ops, fonts) {
            app.panel.invalidate();
        }
    });
    unsafe { EndPaint(hwnd, &ps) };
}

fn mouse(hwnd: HWND, main: HWND, msg: u32, lp: LPARAM) {
    let (x, y) = coords(lp);
    let follow = with_app(main, |app| {
        let zone = find(&app.panel.targets, x, y);
        if msg == WM_LBUTTONDOWN {
            app.panel.hide_ring(zone);
        }
        let pointer = &mut app.panel.view.pointer;
        let (changed, follow) = match msg {
            WM_MOUSEMOVE => (pointer.moved(zone), Follow::Track),
            WM_LBUTTONDOWN if pointer.down(zone) => (true, Follow::Capture),
            WM_LBUTTONDOWN => (false, Follow::Nothing),
            _ => (true, Follow::Release(pointer.up(zone))),
        };
        if changed {
            app.panel.invalidate();
        }
        follow
    });
    match follow {
        Some(Follow::Track) => track(hwnd, TME_LEAVE),
        Some(Follow::Capture) => {
            unsafe { SetCapture(hwnd) };
        }
        Some(Follow::Release(action)) => {
            unsafe { ReleaseCapture() };
            act(main, action);
        }
        Some(Follow::Dismissed | Follow::Nothing) | None => {}
    }
}

fn key(main: HWND, key: u16) -> Option<LRESULT> {
    let back = match key {
        VK_TAB => (unsafe { GetKeyState(i32::from(VK_SHIFT)) }) < 0,
        VK_UP | VK_LEFT => true,
        VK_DOWN | VK_RIGHT => false,
        _ => return None,
    };
    with_app(main, |app| app.panel.tab(back));
    Some(0)
}

fn repoint(main: HWND, change: impl FnOnce(&mut View) -> bool) {
    with_app(main, |app| {
        if change(&mut app.panel.view) {
            app.panel.invalidate();
        }
    });
}

fn rescaled(main: HWND, wp: WPARAM) {
    let s = Scale::new((wp & 0xffff) as u32);
    with_app(main, |app| {
        app.panel.rescale(&app.gfx, s);
        app.refresh_flyout();
    });
}

unsafe extern "system" fn flyout_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
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
            repoint(main, |v| v.pointer.left());
            Some(0)
        }
        WM_CAPTURECHANGED => {
            repoint(main, |v| v.pointer.cancel());
            Some(0)
        }
        WM_ACTIVATE if (wp & 0xffff) as u32 == WA_INACTIVE => {
            hide_flyout(main);
            None
        }
        WM_KEYDOWN if wp == WPARAM::from(VK_ESCAPE) => {
            hide_flyout(main);
            Some(0)
        }
        WM_KEYDOWN => key(main, wp as u16),
        WM_CHAR if wp == WPARAM::from(b'\r') || wp == WPARAM::from(b' ') => {
            let action = with_app(main, |app| app.panel.focus.action(&app.panel.stops));
            act(main, action.flatten());
            Some(0)
        }
        WM_DPICHANGED => {
            rescaled(main, wp);
            Some(0)
        }
        _ => None,
    };
    handled.unwrap_or_else(|| unsafe { DefWindowProcW(hwnd, msg, wp, lp) })
}

pub fn install(main: HWND, instance: HINSTANCE, demo: bool) {
    let flyout = create_flyout(main, instance, demo);
    if flyout.is_null() {
        return;
    }
    with_app(main, |app| app.panel.hwnd = flyout);
    register(main);
    add_icon(main);
}

fn create_flyout(main: HWND, instance: HINSTANCE, demo: bool) -> HWND {
    let class = super::wide("GateintoFlyout");
    let title = super::wide(tray::flyout_title(demo));
    let wc = WNDCLASSEXW {
        cbSize: size_of::<WNDCLASSEXW>() as u32,
        style: CS_DROPSHADOW,
        lpfnWndProc: Some(flyout_proc),
        hInstance: instance,
        hCursor: unsafe { LoadCursorW(null_mut(), IDC_ARROW) },
        lpszClassName: class.as_ptr(),
        ..Default::default()
    };
    if unsafe { RegisterClassExW(&wc) } == 0 {
        return null_mut();
    }
    let hwnd = unsafe {
        CreateWindowExW(
            WS_EX_TOOLWINDOW | WS_EX_TOPMOST,
            class.as_ptr(),
            title.as_ptr(),
            WS_POPUP,
            0,
            0,
            0,
            0,
            null_mut(),
            null_mut(),
            instance,
            main as *const c_void,
        )
    };
    if !hwnd.is_null() {
        sys::round_corners(hwnd);
    }
    hwnd
}
