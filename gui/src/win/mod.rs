mod d2d;
mod sys;
mod text;

use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    BeginPaint, EndPaint, GetMonitorInfoW, InvalidateRect, MONITOR_DEFAULTTONEAREST, MONITORINFO,
    MonitorFromWindow, PAINTSTRUCT, ScreenToClient,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Controls::WM_MOUSELEAVE;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    ReleaseCapture, SetCapture, TME_LEAVE, TME_NONCLIENT, TRACKMOUSEEVENT, TrackMouseEvent,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CREATESTRUCTW, CreateWindowExW, DI_NORMAL, DefWindowProcW, DestroyIcon, DispatchMessageW,
    DrawIconEx, GWLP_USERDATA, GetClientRect, GetMessageW, GetWindowLongPtrW, HICON, HTCAPTION,
    HTCLIENT, HTCLOSE, HTMAXBUTTON, HTMINBUTTON, HTTOP, HTTOPLEFT, HTTOPRIGHT, ICON_BIG,
    ICON_SMALL, IDC_ARROW, IMAGE_ICON, IsZoomed, LoadCursorW, LoadImageW, MB_ICONERROR, MB_OK,
    MINMAXINFO, MSG, MessageBoxW, NCCALCSIZE_PARAMS, PostMessageW, PostQuitMessage,
    RegisterClassExW, SC_CLOSE, SC_MAXIMIZE, SC_MINIMIZE, SC_RESTORE, SIZE_MAXIMIZED, SM_CXICON,
    SM_CXSMICON, SW_SHOW, SWP_FRAMECHANGED, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER,
    SYSTEM_METRICS_INDEX, SendMessageW, SetWindowLongPtrW, SetWindowPos, ShowWindow,
    TranslateMessage, WM_CAPTURECHANGED, WM_CREATE, WM_DESTROY, WM_DPICHANGED,
    WM_DWMCOMPOSITIONCHANGED, WM_ERASEBKGND, WM_GETMINMAXINFO, WM_LBUTTONDOWN, WM_LBUTTONUP,
    WM_MOUSEMOVE, WM_NCCALCSIZE, WM_NCDESTROY, WM_NCHITTEST, WM_NCLBUTTONDBLCLK, WM_NCLBUTTONDOWN,
    WM_NCLBUTTONUP, WM_NCMOUSELEAVE, WM_NCMOUSEMOVE, WM_PAINT, WM_SETICON, WM_SIZE, WM_SYSCOMMAND,
    WNDCLASSEXW, WS_OVERLAPPEDWINDOW,
};

use crate::frame::Frame;
use crate::hit::{Zone, hit};
use crate::layout::{Layout, Rect};
use crate::pointer::Action;
use crate::scale::Scale;
use crate::scene::{Op, View, scene};
use crate::theme::Theme;
use d2d::Graphics;
use sys::wide;
use text::Fonts;

const STYLE: u32 = WS_OVERLAPPEDWINDOW;
const EX_STYLE: u32 = 0;
const APP_ICON: usize = 1;
const TITLE: &str = "Gateinto";

fn load_icon(instance: HINSTANCE, size: i32) -> HICON {
    unsafe { LoadImageW(instance, APP_ICON as *const u16, IMAGE_ICON, size, size, 0) }
}

fn metric_icon(instance: HINSTANCE, metric: SYSTEM_METRICS_INDEX, dpi: u32) -> HICON {
    load_icon(instance, sys::metric_for_dpi(metric, dpi))
}

struct Icons {
    window: [HICON; 2],
    logo: HICON,
}

impl Icons {
    fn apply(hwnd: HWND, s: Scale, logo: i32) -> Self {
        let instance = unsafe { GetModuleHandleW(null()) };
        let window = [(ICON_BIG, SM_CXICON), (ICON_SMALL, SM_CXSMICON)].map(|(kind, metric)| {
            let icon = metric_icon(instance, metric, s.dpi);
            if !icon.is_null() {
                unsafe { SendMessageW(hwnd, WM_SETICON, kind as WPARAM, icon as LPARAM) };
            }
            icon
        });
        Self {
            window,
            logo: load_icon(instance, logo),
        }
    }
}

impl Drop for Icons {
    fn drop(&mut self) {
        for icon in self.window.into_iter().chain([self.logo]) {
            if !icon.is_null() {
                unsafe { DestroyIcon(icon) };
            }
        }
    }
}

struct App {
    hwnd: HWND,
    s: Scale,
    frame: Frame,
    gfx: Graphics,
    fonts: Fonts,
    layout: Layout,
    view: View,
    icons: Icons,
}

fn choose_frame() -> Frame {
    Frame::choose(sys::os_major(), sys::composition_enabled())
}

impl App {
    fn new(hwnd: HWND, gfx: Graphics) -> Option<Self> {
        let s = Scale::new(sys::window_dpi(hwnd));
        let frame = choose_frame();
        let fonts = Fonts::new(gfx.dwrite(), s).ok()?;
        let layout = measure(hwnd, s, frame);
        Some(Self {
            hwnd,
            s,
            frame,
            gfx,
            fonts,
            icons: Icons::apply(hwnd, s, layout.logo.w),
            layout,
            view: View::default(),
        })
    }

    fn relayout(&mut self) {
        self.layout = measure(self.hwnd, self.s, self.frame);
        self.invalidate();
    }

    fn invalidate(&self) {
        unsafe { InvalidateRect(self.hwnd, null(), 0) };
    }

    fn frame_y(&self) -> i32 {
        sys::frame_thickness(self.s.dpi)
    }

    fn zone(&self, x: i32, y: i32) -> Zone {
        let band = self
            .frame
            .top_resize_band(self.view.maximized, self.frame_y());
        hit(&self.layout, x, y, band)
    }

    fn screen_zone(&self, lp: LPARAM) -> Zone {
        let (x, y) = coords(lp);
        let mut p = POINT { x, y };
        unsafe { ScreenToClient(self.hwnd, &mut p) };
        self.zone(p.x, p.y)
    }
}

fn measure(hwnd: HWND, s: Scale, frame: Frame) -> Layout {
    let (w, h) = client_size(hwnd);
    let (min_w, min_h) = Layout::min_size(s);
    Layout::new(w.max(min_w), h.max(min_h), s, frame.draws_caption())
}

fn client_size(hwnd: HWND) -> (i32, i32) {
    let mut rc = RECT::default();
    unsafe { GetClientRect(hwnd, &mut rc) };
    (rc.right - rc.left, rc.bottom - rc.top)
}

fn coords(lp: LPARAM) -> (i32, i32) {
    (
        i32::from((lp & 0xffff) as u16 as i16),
        i32::from(((lp >> 16) & 0xffff) as u16 as i16),
    )
}

fn app<'a>(hwnd: HWND) -> Option<&'a mut App> {
    unsafe { (GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut App).as_mut() }
}

fn custom<'a>(hwnd: HWND) -> Option<&'a mut App> {
    app(hwnd).filter(|app| app.frame.draws_caption())
}

fn outer_size(frame: Frame, (w, h): (i32, i32), dpi: u32) -> (i32, i32) {
    frame.outer_size(sys::adjusted_rect(w, h, STYLE, EX_STYLE, dpi))
}

fn track(hwnd: HWND, flags: u32) {
    let mut track = TRACKMOUSEEVENT {
        cbSize: size_of::<TRACKMOUSEEVENT>() as u32,
        dwFlags: flags,
        hwndTrack: hwnd,
        dwHoverTime: 0,
    };
    unsafe { TrackMouseEvent(&mut track) };
}

fn hit_code(zone: Zone) -> u32 {
    match zone {
        Zone::Top => HTTOP,
        Zone::TopLeft => HTTOPLEFT,
        Zone::TopRight => HTTOPRIGHT,
        Zone::Caption => HTCAPTION,
        Zone::Minimize => HTMINBUTTON,
        Zone::Maximize => HTMAXBUTTON,
        Zone::Close => HTCLOSE,
        Zone::Nav(_) | Zone::Client => HTCLIENT,
    }
}

fn caption_button(code: WPARAM) -> Option<Zone> {
    match code as u32 {
        HTMINBUTTON => Some(Zone::Minimize),
        HTMAXBUTTON => Some(Zone::Maximize),
        HTCLOSE => Some(Zone::Close),
        _ => None,
    }
}

fn perform(hwnd: HWND, action: Option<Action>) {
    let command = match action {
        None => return,
        Some(Action::Select(page)) => {
            if let Some(app) = app(hwnd)
                && app.view.nav.select(page)
            {
                app.invalidate();
            }
            return;
        }
        Some(Action::Minimize) => SC_MINIMIZE,
        Some(Action::ToggleMaximize) if unsafe { IsZoomed(hwnd) } != 0 => SC_RESTORE,
        Some(Action::ToggleMaximize) => SC_MAXIMIZE,
        Some(Action::Close) => SC_CLOSE,
    };
    unsafe { PostMessageW(hwnd, WM_SYSCOMMAND, command as WPARAM, 0) };
}

fn on_paint(hwnd: HWND) {
    let mut ps = PAINTSTRUCT::default();
    let dc = unsafe { BeginPaint(hwnd, &mut ps) };
    if let Some(app) = app(hwnd) {
        let (w, h) = client_size(hwnd);
        let ops = scene(&app.layout, app.s, &Theme::LIGHT, &app.view);
        if !app.gfx.draw(dc, Rect::new(0, 0, w, h), &ops, &app.fonts) {
            app.invalidate();
        }
        for op in &ops {
            if let Op::Logo(r) = *op
                && !app.icons.logo.is_null()
            {
                unsafe {
                    DrawIconEx(
                        dc,
                        r.x,
                        r.y,
                        app.icons.logo,
                        r.w,
                        r.h,
                        0,
                        null_mut(),
                        DI_NORMAL,
                    )
                };
            }
        }
    }
    unsafe { EndPaint(hwnd, &ps) };
}

fn on_nc_calc_size(hwnd: HWND, wp: WPARAM, lp: LPARAM) -> Option<LRESULT> {
    let app = custom(hwnd).filter(|_| wp != 0)?;
    let frame_y = app.frame_y();
    let params = lp as *mut NCCALCSIZE_PARAMS;
    let top = unsafe { (*params).rgrc[0].top };
    let result = unsafe { DefWindowProcW(hwnd, WM_NCCALCSIZE, wp, lp) };
    if result != 0 {
        return Some(result);
    }
    let maximized = unsafe { IsZoomed(hwnd) } != 0;
    let params = unsafe { &mut *params };
    params.rgrc[0].top = Frame::client_top(top, maximized, frame_y);
    Some(0)
}

fn on_nc_hit_test(hwnd: HWND, lp: LPARAM) -> Option<LRESULT> {
    let app = custom(hwnd)?;
    let system = unsafe { DefWindowProcW(hwnd, WM_NCHITTEST, 0, lp) };
    if system != HTCLIENT as LRESULT {
        return Some(system);
    }
    Some(hit_code(app.screen_zone(lp)) as LRESULT)
}

fn on_nc_mouse(hwnd: HWND, msg: u32, wp: WPARAM) -> Option<LRESULT> {
    let app = custom(hwnd)?;
    let button = caption_button(wp);
    let zone = button.unwrap_or(Zone::Caption);
    let action = match msg {
        WM_NCMOUSEMOVE => {
            track(hwnd, TME_LEAVE | TME_NONCLIENT);
            if app.view.pointer.moved(zone) {
                app.invalidate();
            }
            None
        }
        WM_NCLBUTTONDOWN | WM_NCLBUTTONDBLCLK => {
            if app.view.pointer.down(zone) {
                app.invalidate();
            }
            None
        }
        _ => {
            let action = app.view.pointer.up(zone);
            app.invalidate();
            action
        }
    };
    button?;
    perform(hwnd, action);
    Some(0)
}

fn on_mouse(hwnd: HWND, msg: u32, lp: LPARAM) {
    let Some(app) = app(hwnd) else { return };
    let (x, y) = coords(lp);
    let zone = app.zone(x, y);
    match msg {
        WM_MOUSEMOVE => {
            track(hwnd, TME_LEAVE);
            if app.view.pointer.moved(zone) {
                app.invalidate();
            }
        }
        WM_LBUTTONDOWN => {
            if app.view.pointer.down(zone) {
                app.invalidate();
                unsafe { SetCapture(hwnd) };
            }
        }
        _ => {
            let action = app.view.pointer.up(zone);
            app.invalidate();
            unsafe { ReleaseCapture() };
            perform(hwnd, action);
        }
    }
}

fn on_left(hwnd: HWND) {
    if let Some(app) = app(hwnd)
        && app.view.pointer.left()
    {
        app.invalidate();
    }
}

fn on_capture_lost(hwnd: HWND) {
    if let Some(app) = app(hwnd)
        && app.view.pointer.cancel()
    {
        app.invalidate();
    }
}

fn on_size(hwnd: HWND, wp: WPARAM) {
    if let Some(app) = app(hwnd) {
        app.view.maximized = wp == SIZE_MAXIMIZED as WPARAM;
        app.relayout();
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
    if let Some(app) = app(hwnd) {
        app.relayout();
        app.icons = Icons::apply(hwnd, app.s, app.layout.logo.w);
    }
}

fn on_composition_changed(hwnd: HWND) {
    if let Some(app) = app(hwnd) {
        app.frame = choose_frame();
    }
    refresh_frame(hwnd);
    if let Some(app) = app(hwnd) {
        app.relayout();
    }
}

fn refresh_frame(hwnd: HWND) {
    let flags = SWP_FRAMECHANGED | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE;
    unsafe { SetWindowPos(hwnd, null_mut(), 0, 0, 0, 0, flags) };
}

fn on_min_max(hwnd: HWND, info: &mut MINMAXINFO) {
    let (s, frame) = app(hwnd).map_or_else(
        || (Scale::new(sys::window_dpi(hwnd)), Frame::System),
        |app| (app.s, app.frame),
    );
    let (w, h) = outer_size(frame, Layout::min_size(s), s.dpi);
    info.ptMinTrackSize.x = w;
    info.ptMinTrackSize.y = h;
}

unsafe extern "system" fn window_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    let handled = match msg {
        WM_NCCALCSIZE => on_nc_calc_size(hwnd, wp, lp),
        WM_NCHITTEST => on_nc_hit_test(hwnd, lp),
        WM_NCMOUSEMOVE | WM_NCLBUTTONDOWN | WM_NCLBUTTONDBLCLK | WM_NCLBUTTONUP => {
            on_nc_mouse(hwnd, msg, wp)
        }
        WM_NCMOUSELEAVE | WM_MOUSELEAVE => {
            on_left(hwnd);
            Some(0)
        }
        WM_CAPTURECHANGED => {
            on_capture_lost(hwnd);
            Some(0)
        }
        WM_MOUSEMOVE | WM_LBUTTONDOWN | WM_LBUTTONUP => {
            on_mouse(hwnd, msg, lp);
            Some(0)
        }
        WM_CREATE => {
            let create = unsafe { &*(lp as *const CREATESTRUCTW) };
            let gfx = unsafe { &mut *create.lpCreateParams.cast::<Option<Graphics>>() };
            let Some(state) = gfx.take().and_then(|gfx| App::new(hwnd, gfx)) else {
                return -1;
            };
            let state = Box::into_raw(Box::new(state));
            unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, state as _) };
            Some(0)
        }
        WM_PAINT => {
            on_paint(hwnd);
            Some(0)
        }
        WM_ERASEBKGND => Some(1),
        WM_SIZE => {
            on_size(hwnd, wp);
            Some(0)
        }
        WM_GETMINMAXINFO => {
            on_min_max(hwnd, unsafe { &mut *(lp as *mut MINMAXINFO) });
            Some(0)
        }
        WM_DPICHANGED => {
            on_dpi_changed(hwnd, wp, lp);
            Some(0)
        }
        WM_DWMCOMPOSITIONCHANGED => {
            on_composition_changed(hwnd);
            Some(0)
        }
        WM_DESTROY => {
            unsafe { PostQuitMessage(0) };
            Some(0)
        }
        WM_NCDESTROY => {
            let state = unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0) } as *mut App;
            if !state.is_null() {
                drop(unsafe { Box::from_raw(state) });
            }
            None
        }
        _ => None,
    };
    handled.unwrap_or_else(|| unsafe { DefWindowProcW(hwnd, msg, wp, lp) })
}

fn center_on_monitor(hwnd: HWND) {
    let s = Scale::new(sys::window_dpi(hwnd));
    let frame = app(hwnd).map_or(Frame::System, |app| app.frame);
    let (w, h) = outer_size(frame, Layout::default_size(s), s.dpi);
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
    let (w, h) = (w.min(work.right - work.left), h.min(work.bottom - work.top));
    let x = work.left + (work.right - work.left - w) / 2;
    let y = work.top + (work.bottom - work.top - h) / 2;
    let flags = SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED;
    unsafe { SetWindowPos(hwnd, null_mut(), x, y, w, h, flags) };
}

fn fail() {
    let text = wide("Gateinto could not start Direct2D and DirectWrite rendering.");
    let caption = wide(TITLE);
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
    let system_dpi = sys::window_dpi(null_mut());
    let class = wide("GateintoWindow");
    let title = wide(TITLE);
    let wc = WNDCLASSEXW {
        cbSize: size_of::<WNDCLASSEXW>() as u32,
        lpfnWndProc: Some(window_proc),
        hInstance: instance,
        hIcon: metric_icon(instance, SM_CXICON, system_dpi),
        hIconSm: metric_icon(instance, SM_CXSMICON, system_dpi),
        hCursor: unsafe { LoadCursorW(null_mut(), IDC_ARROW) },
        lpszClassName: class.as_ptr(),
        ..Default::default()
    };
    if unsafe { RegisterClassExW(&wc) } == 0 {
        fail();
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
        unsafe {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}
