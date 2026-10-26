mod d2d;
mod paint;
mod sys;
mod text;

use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicIsize, Ordering};

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    BeginPaint, EndPaint, GetMonitorInfoW, InvalidateRect, MONITOR_DEFAULTTONEAREST, MONITORINFO,
    MonitorFromWindow, PAINTSTRUCT,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Controls::{DRAWITEMSTRUCT, ODS_FOCUS, ODS_SELECTED, WM_MOUSELEAVE};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    GetFocus, SetFocus, TME_LEAVE, TRACKMOUSEEVENT, TrackMouseEvent,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    BN_CLICKED, BS_OWNERDRAW, CREATESTRUCTW, CallWindowProcW, CreateWindowExW, DefWindowProcW,
    DispatchMessageW, GWLP_USERDATA, GWLP_WNDPROC, GetClientRect, GetDlgCtrlID, GetMessageW,
    GetWindowLongPtrW, HMENU, IDC_ARROW, IDC_HAND, IDI_APPLICATION, IDOK, IsDialogMessageW,
    LoadCursorW, LoadIconW, MB_ICONERROR, MB_ICONINFORMATION, MB_OK, MINMAXINFO, MSG, MessageBoxW,
    PostQuitMessage, RegisterClassExW, SPI_GETKEYBOARDCUES, SW_SHOW, SWP_NOACTIVATE, SWP_NOZORDER,
    SetCursor, SetWindowLongPtrW, SetWindowPos, ShowWindow, SystemParametersInfoW,
    TranslateMessage, WA_INACTIVE, WM_ACTIVATE, WM_COMMAND, WM_CREATE, WM_DESTROY, WM_DPICHANGED,
    WM_DRAWITEM, WM_ERASEBKGND, WM_GETMINMAXINFO, WM_KEYDOWN, WM_LBUTTONDBLCLK, WM_LBUTTONDOWN,
    WM_MOUSEMOVE, WM_NCDESTROY, WM_PAINT, WM_SETCURSOR, WM_SIZE, WM_SYSKEYDOWN, WNDCLASSEXW,
    WNDPROC, WS_CHILD, WS_CLIPCHILDREN, WS_OVERLAPPEDWINDOW, WS_TABSTOP, WS_VISIBLE,
};

use crate::cue::FocusCue;
use crate::layout::{self, Layout, Rect};
use crate::model::{self, SESSIONS};
use crate::scale::Scale;
use crate::style::{Control, State};
use d2d::Graphics;
use sys::wide;
use text::Fonts;

const STYLE: u32 = WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN;
const EX_STYLE: u32 = 0;

static BUTTON_PROC: AtomicIsize = AtomicIsize::new(0);

struct App {
    hwnd: HWND,
    s: Scale,
    gfx: Graphics,
    fonts: Fonts,
    layout: Layout,
    buttons: Vec<(Control, HWND)>,
    last_focus: HWND,
    cue: FocusCue,
}

impl App {
    fn new(hwnd: HWND, gfx: Graphics) -> Option<Self> {
        let s = Scale::new(sys::window_dpi(hwnd));
        let fonts = Fonts::new(gfx.dwrite(), s).ok()?;
        Some(Self {
            hwnd,
            s,
            layout: measure(hwnd, &fonts, s),
            gfx,
            fonts,
            buttons: Vec::new(),
            last_focus: null_mut(),
            cue: FocusCue::new(keyboard_cues_always()),
        })
    }

    fn relayout(&mut self) {
        self.layout = measure(self.hwnd, &self.fonts, self.s);
    }

    fn placements(&self) -> Vec<(HWND, Rect)> {
        self.buttons
            .iter()
            .filter_map(|&(c, hwnd)| self.layout.bounds(c, self.s).map(|r| (hwnd, r)))
            .collect()
    }

    fn ctx(&self) -> paint::Ctx<'_> {
        paint::Ctx {
            fonts: &self.fonts,
            s: self.s,
            layout: &self.layout,
            sessions: &SESSIONS,
        }
    }
}

fn measure(hwnd: HWND, fonts: &Fonts, s: Scale) -> Layout {
    let (w, h) = client_size(hwnd);
    let (min_w, min_h) = layout::min_client_size(s);
    layout::compute(w.max(min_w), h.max(min_h), s, fonts, &SESSIONS)
}

fn client_size(hwnd: HWND) -> (i32, i32) {
    let mut rc = RECT::default();
    unsafe { GetClientRect(hwnd, &mut rc) };
    (rc.right - rc.left, rc.bottom - rc.top)
}

fn app<'a>(hwnd: HWND) -> Option<&'a mut App> {
    unsafe { (GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut App).as_mut() }
}

fn place(placements: &[(HWND, Rect)]) {
    for &(hwnd, r) in placements {
        unsafe {
            SetWindowPos(
                hwnd,
                null_mut(),
                r.x,
                r.y,
                r.w,
                r.h,
                SWP_NOZORDER | SWP_NOACTIVATE,
            )
        };
    }
}

fn relayout(hwnd: HWND) {
    let Some(app) = app(hwnd) else { return };
    app.relayout();
    let placements = app.placements();
    place(&placements);
    unsafe { InvalidateRect(hwnd, null(), 0) };
    for (button, _) in placements {
        unsafe { InvalidateRect(button, null(), 0) };
    }
}

fn create_buttons(hwnd: HWND, app: &mut App) {
    let instance = unsafe { GetModuleHandleW(null()) };
    let class = wide("BUTTON");
    for control in app.layout.controls() {
        let text = wide(control.label());
        let button = unsafe {
            CreateWindowExW(
                0,
                class.as_ptr(),
                text.as_ptr(),
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW as u32,
                0,
                0,
                0,
                0,
                hwnd,
                usize::from(control.id()) as HMENU,
                instance,
                null(),
            )
        };
        if button.is_null() {
            continue;
        }
        let original =
            unsafe { SetWindowLongPtrW(button, GWLP_WNDPROC, button_proc as *const () as _) };
        BUTTON_PROC.store(original as isize, Ordering::Relaxed);
        app.buttons.push((control, button));
    }
    place(&app.placements());
}

fn original_button_proc() -> WNDPROC {
    unsafe { std::mem::transmute::<isize, WNDPROC>(BUTTON_PROC.load(Ordering::Relaxed)) }
}

unsafe extern "system" fn button_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    unsafe {
        match msg {
            WM_MOUSEMOVE if GetWindowLongPtrW(hwnd, GWLP_USERDATA) == 0 => {
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, 1);
                let mut track = TRACKMOUSEEVENT {
                    cbSize: size_of::<TRACKMOUSEEVENT>() as u32,
                    dwFlags: TME_LEAVE,
                    hwndTrack: hwnd,
                    dwHoverTime: 0,
                };
                TrackMouseEvent(&mut track);
                InvalidateRect(hwnd, null(), 0);
            }
            WM_MOUSELEAVE => {
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                InvalidateRect(hwnd, null(), 0);
            }
            WM_ERASEBKGND => return 1,
            WM_SETCURSOR if GetDlgCtrlID(hwnd) == i32::from(Control::Details.id()) => {
                SetCursor(LoadCursorW(null_mut(), IDC_HAND));
                return 1;
            }
            WM_LBUTTONDBLCLK => {
                return CallWindowProcW(original_button_proc(), hwnd, WM_LBUTTONDOWN, wp, lp);
            }
            _ => {}
        }
        CallWindowProcW(original_button_proc(), hwnd, msg, wp, lp)
    }
}

fn on_paint(hwnd: HWND) {
    let mut ps = PAINTSTRUCT::default();
    let dc = unsafe { BeginPaint(hwnd, &mut ps) };
    if let Some(app) = app(hwnd) {
        let (w, h) = client_size(hwnd);
        let ctx = app.ctx();
        let drawn = app.gfx.draw(dc, Rect::new(0, 0, w, h), |g| {
            paint::scene(g, w, h, &ctx);
        });
        if !drawn {
            unsafe { InvalidateRect(hwnd, null(), 0) };
        }
    }
    unsafe { EndPaint(hwnd, &ps) };
}

fn on_draw_item(hwnd: HWND, dis: &DRAWITEMSTRUCT) -> bool {
    let (Some(app), Some(control)) = (app(hwnd), Control::from_id(dis.CtlID as u16)) else {
        return false;
    };
    let Some(bounds) = app.layout.bounds(control, app.s) else {
        return false;
    };
    let state = State {
        hover: unsafe { GetWindowLongPtrW(dis.hwndItem, GWLP_USERDATA) } != 0,
        pressed: dis.itemState & ODS_SELECTED != 0,
        focused: dis.itemState & ODS_FOCUS != 0 && app.cue.visible(),
    };
    let rc = dis.rcItem;
    let (w, h) = (rc.right - rc.left, rc.bottom - rc.top);
    let bounds = Rect::new(bounds.x, bounds.y, w, h);
    let ctx = app.ctx();
    let drawn = app
        .gfx
        .draw(dis.hDC, Rect::new(rc.left, rc.top, w, h), |g| {
            paint::control(g, bounds, control, state, &ctx);
        });
    if !drawn {
        unsafe { InvalidateRect(dis.hwndItem, null(), 0) };
    }
    true
}

fn activate(hwnd: HWND, control: Control) {
    if !control.is_active() {
        return;
    }
    let text = wide(&format!(
        "\"{}\" is not available in this prototype.\n\nThe window shows sample data only.",
        control.label()
    ));
    let caption = wide("Gateinto prototype");
    unsafe {
        MessageBoxW(
            hwnd,
            text.as_ptr(),
            caption.as_ptr(),
            MB_OK | MB_ICONINFORMATION,
        )
    };
}

fn on_command(hwnd: HWND, wp: WPARAM) {
    let id = (wp & 0xffff) as u16;
    let code = ((wp >> 16) & 0xffff) as u32;
    let target = if i32::from(id) == IDOK {
        Control::from_id(unsafe { GetDlgCtrlID(GetFocus()) } as u16)
    } else if code == BN_CLICKED {
        Control::from_id(id)
    } else {
        None
    };
    if let Some(control) = target {
        activate(hwnd, control);
    }
}

fn on_dpi_changed(hwnd: HWND, wp: WPARAM, lp: LPARAM) {
    if let Some(app) = app(hwnd) {
        let s = Scale::new((wp & 0xffff) as u32);
        if let Ok(fonts) = Fonts::new(app.gfx.dwrite(), s) {
            app.s = s;
            app.fonts = fonts;
        }
    }
    let r = unsafe { &*(lp as *const RECT) };
    unsafe {
        SetWindowPos(
            hwnd,
            null_mut(),
            r.left,
            r.top,
            r.right - r.left,
            r.bottom - r.top,
            SWP_NOZORDER | SWP_NOACTIVATE,
        )
    };
    relayout(hwnd);
}

fn on_min_max(hwnd: HWND, info: &mut MINMAXINFO) {
    let s = app(hwnd).map_or_else(|| Scale::new(sys::window_dpi(hwnd)), |app| app.s);
    let (w, h) = layout::min_client_size(s);
    let (w, h) = sys::window_size_for_client(w, h, STYLE, EX_STYLE, s.dpi);
    info.ptMinTrackSize.x = w;
    info.ptMinTrackSize.y = h;
}

fn keyboard_cues_always() -> bool {
    let mut cues = 0i32;
    let queried =
        unsafe { SystemParametersInfoW(SPI_GETKEYBOARDCUES, 0, (&raw mut cues).cast(), 0) };
    queried != 0 && cues != 0
}

fn reveal_focus(hwnd: HWND) {
    let Some(app) = app(hwnd) else { return };
    if app.cue.reveal() {
        let focus = unsafe { GetFocus() };
        if !focus.is_null() {
            unsafe { InvalidateRect(focus, null(), 0) };
        }
    }
}

fn on_activate(hwnd: HWND, wp: WPARAM) {
    let Some(app) = app(hwnd) else { return };
    if (wp & 0xffff) as u32 == WA_INACTIVE {
        app.last_focus = unsafe { GetFocus() };
        return;
    }
    let target = if app.buttons.iter().any(|&(_, b)| b == app.last_focus) {
        app.last_focus
    } else {
        app.buttons.first().map_or(null_mut(), |&(_, b)| b)
    };
    if !target.is_null() {
        unsafe { SetFocus(target) };
    }
}

unsafe extern "system" fn window_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    match msg {
        WM_CREATE => {
            let create = unsafe { &*(lp as *const CREATESTRUCTW) };
            let gfx = unsafe { &mut *create.lpCreateParams.cast::<Option<Graphics>>() };
            let Some(mut state) = gfx.take().and_then(|gfx| App::new(hwnd, gfx)) else {
                return -1;
            };
            create_buttons(hwnd, &mut state);
            let state = Box::into_raw(Box::new(state));
            unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, state as _) };
            sys::apply_window_chrome(hwnd);
            0
        }
        WM_PAINT => {
            on_paint(hwnd);
            0
        }
        WM_ERASEBKGND => 1,
        WM_SIZE => {
            relayout(hwnd);
            0
        }
        WM_GETMINMAXINFO => {
            on_min_max(hwnd, unsafe { &mut *(lp as *mut MINMAXINFO) });
            0
        }
        WM_DPICHANGED => {
            on_dpi_changed(hwnd, wp, lp);
            0
        }
        WM_DRAWITEM => LRESULT::from(on_draw_item(hwnd, unsafe {
            &*(lp as *const DRAWITEMSTRUCT)
        })),
        WM_COMMAND => {
            on_command(hwnd, wp);
            0
        }
        WM_ACTIVATE => {
            on_activate(hwnd, wp);
            0
        }
        WM_DESTROY => {
            unsafe { PostQuitMessage(0) };
            0
        }
        WM_NCDESTROY => {
            let state = unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0) } as *mut App;
            if !state.is_null() {
                drop(unsafe { Box::from_raw(state) });
            }
            unsafe { DefWindowProcW(hwnd, msg, wp, lp) }
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wp, lp) },
    }
}

fn center_on_monitor(hwnd: HWND) {
    let s = Scale::new(sys::window_dpi(hwnd));
    let (cw, ch) = layout::min_client_size(s);
    let (w, h) = sys::window_size_for_client(cw, ch, STYLE, EX_STYLE, s.dpi);
    let mut info = MONITORINFO {
        cbSize: size_of::<MONITORINFO>() as u32,
        ..Default::default()
    };
    let work = unsafe {
        let monitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
        if GetMonitorInfoW(monitor, &mut info) != 0 {
            info.rcWork
        } else {
            RECT {
                left: 0,
                top: 0,
                right: w,
                bottom: h,
            }
        }
    };
    let x = work.left + ((work.right - work.left - w) / 2).max(0);
    let y = work.top + ((work.bottom - work.top - h) / 2).max(0);
    unsafe { SetWindowPos(hwnd, null_mut(), x, y, w, h, SWP_NOZORDER | SWP_NOACTIVATE) };
}

fn fail() {
    let text = wide("Gateinto could not initialise Direct2D and DirectWrite rendering.");
    let caption = wide(model::APP_NAME);
    unsafe {
        MessageBoxW(
            null_mut(),
            text.as_ptr(),
            caption.as_ptr(),
            MB_OK | MB_ICONERROR,
        )
    };
}

pub fn run() {
    sys::enable_dpi_awareness();
    let Ok(gfx) = Graphics::new() else {
        fail();
        return;
    };
    let mut gfx = Some(gfx);
    let instance = unsafe { GetModuleHandleW(null()) };
    let class = wide("GateintoSessions");
    let title = wide(model::APP_NAME);
    let wc = WNDCLASSEXW {
        cbSize: size_of::<WNDCLASSEXW>() as u32,
        lpfnWndProc: Some(window_proc),
        hInstance: instance,
        hIcon: unsafe { LoadIconW(null_mut(), IDI_APPLICATION) },
        hCursor: unsafe { LoadCursorW(null_mut(), IDC_ARROW) },
        lpszClassName: class.as_ptr(),
        ..Default::default()
    };
    if unsafe { RegisterClassExW(&wc) } == 0 {
        return;
    }
    let hwnd = unsafe {
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
            (&raw mut gfx).cast(),
        )
    };
    if hwnd.is_null() {
        fail();
        return;
    }
    center_on_monitor(hwnd);
    unsafe { ShowWindow(hwnd, SW_SHOW) };

    let mut msg = MSG::default();
    while unsafe { GetMessageW(&mut msg, null_mut(), 0, 0) } > 0 {
        if matches!(msg.message, WM_KEYDOWN | WM_SYSKEYDOWN) {
            reveal_focus(hwnd);
        }
        if unsafe { IsDialogMessageW(hwnd, &msg) } == 0 {
            unsafe {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
}
