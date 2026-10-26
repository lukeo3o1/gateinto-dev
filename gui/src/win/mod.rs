mod d2d;
mod link;
mod sys;
mod text;
mod tips;

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
    CREATESTRUCTW, CreateWindowExW, DefWindowProcW, DestroyIcon, DispatchMessageW, GWLP_USERDATA,
    GetClientRect, GetCursorPos, GetMessageW, GetWindowLongPtrW, HICON, HTCAPTION, HTCLIENT,
    HTCLOSE, HTMAXBUTTON, HTMINBUTTON, HTTOP, HTTOPLEFT, HTTOPRIGHT, ICON_BIG, ICON_SMALL,
    IDC_ARROW, IMAGE_ICON, IsZoomed, LoadCursorW, LoadImageW, MB_ICONERROR, MB_OK, MINMAXINFO, MSG,
    MessageBoxW, NCCALCSIZE_PARAMS, PostMessageW, PostQuitMessage, RegisterClassExW, SC_CLOSE,
    SC_MAXIMIZE, SC_MINIMIZE, SC_RESTORE, SIZE_MAXIMIZED, SM_CXICON, SM_CXSMICON, SW_SHOW,
    SWP_FRAMECHANGED, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER, SYSTEM_METRICS_INDEX,
    SendMessageW, SetWindowLongPtrW, SetWindowPos, ShowWindow, TranslateMessage, WM_CAPTURECHANGED,
    WM_CREATE, WM_DESTROY, WM_DPICHANGED, WM_DWMCOMPOSITIONCHANGED, WM_ERASEBKGND,
    WM_GETMINMAXINFO, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MOUSEMOVE, WM_MOUSEWHEEL, WM_NCCALCSIZE,
    WM_NCDESTROY, WM_NCHITTEST, WM_NCLBUTTONDBLCLK, WM_NCLBUTTONDOWN, WM_NCLBUTTONUP,
    WM_NCMOUSELEAVE, WM_NCMOUSEMOVE, WM_PAINT, WM_SETICON, WM_SIZE, WM_SYSCOMMAND, WNDCLASSEXW,
    WS_OVERLAPPEDWINDOW, WindowFromPoint,
};

use gateinto::clock::unix_now;

use crate::board::{self, Board, board, tips};
use crate::frame::Frame;
use crate::gateways::{self, Launches};
use crate::hit::{Zone, hit};
use crate::layout::{Layout, Rect};
use crate::nav::Page as NavPage;
use crate::pointer::Action;
use crate::scale::Scale;
use crate::scene::{View, scene};
use crate::scroll::Pane;
use crate::sessions;
use crate::theme::Theme;
use crate::worker::{Command, Update};
use d2d::Graphics;
use link::{Link, WM_AGENT};
use sys::wide;
use text::Fonts;
use tips::Tips;

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
}

impl Icons {
    fn apply(hwnd: HWND, s: Scale) -> Self {
        let instance = unsafe { GetModuleHandleW(null()) };
        let window = [(ICON_BIG, SM_CXICON), (ICON_SMALL, SM_CXSMICON)].map(|(kind, metric)| {
            let icon = metric_icon(instance, metric, s.dpi);
            if !icon.is_null() {
                unsafe { SendMessageW(hwnd, WM_SETICON, kind as WPARAM, icon as LPARAM) };
            }
            icon
        });
        Self { window }
    }
}

impl Drop for Icons {
    fn drop(&mut self) {
        for icon in self.window {
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
    targets: Vec<(Rect, Zone)>,
    pane: Option<Pane>,
    icons: Icons,
    update: Option<Update>,
    launches: Launches,
    link: Link,
    tips: Tips,
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
            icons: Icons::apply(hwnd, s),
            layout,
            view: View::default(),
            targets: Vec::new(),
            pane: None,
            update: None,
            launches: Launches::default(),
            link: Link::start(hwnd),
            tips: Tips::new(hwnd),
        })
    }

    fn relayout(&mut self) {
        self.layout = measure(self.hwnd, self.s, self.frame);
        self.retarget();
        self.invalidate();
    }

    fn board(&self) -> Board {
        let Some(update) = &self.update else {
            return Board::default();
        };
        let (l, s, t, v, m) = (&self.layout, self.s, &Theme::LIGHT, &self.view, &self.fonts);
        let failure = update.failure.as_deref();
        match v.nav.selected() {
            NavPage::Gateways => {
                let busy = self.launches.busy();
                let page = gateways::page(&update.gateways, &update.state, failure, busy);
                board::gateways::board(l, s, t, v, &page, m)
            }
            _ => board(
                l,
                s,
                t,
                v,
                &sessions::page(&update.state, failure, unix_now()),
                m,
            ),
        }
    }

    fn retarget(&mut self) {
        let board = self.board();
        self.adopt(board.targets, board.pane);
    }

    fn adopt(&mut self, targets: Vec<(Rect, Zone)>, pane: Option<Pane>) {
        self.targets = targets;
        self.pane = pane;
        if let Some(pane) = pane {
            let page = self.view.nav.selected();
            self.view.scroll.set(page, pane.offset);
        }
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
        hit(&self.layout, x, y, band, &self.targets)
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

// The closure must not call anything that sends a message back to this window.
fn with_app<R>(hwnd: HWND, f: impl FnOnce(&mut App) -> R) -> Option<R> {
    let state = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *mut App;
    unsafe { state.as_mut() }.map(f)
}

fn with_custom<R>(hwnd: HWND, f: impl FnOnce(&mut App) -> R) -> Option<R> {
    with_app(hwnd, |app| app.frame.draws_caption().then(|| f(app))).flatten()
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
        Zone::Nav(_) | Zone::StopAgent | Zone::Revoke(_) | Zone::StartBrowser(_) | Zone::Client => {
            HTCLIENT
        }
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
            with_app(hwnd, |app| {
                if app.view.nav.select(page) {
                    app.retarget();
                    app.invalidate();
                }
            });
            return;
        }
        Some(Action::StopAgent) => {
            with_app(hwnd, |app| app.link.send(Command::Stop));
            return;
        }
        Some(Action::Revoke(id)) => {
            with_app(hwnd, |app| app.link.send(Command::Close(id)));
            return;
        }
        Some(Action::StartBrowser(row)) => {
            with_app(hwnd, |app| {
                let names = app.update.as_ref().map(|u| gateways::names(&u.gateways));
                if let Some(name) = app.launches.start(&names.unwrap_or_default(), row) {
                    app.link.send(Command::Launch(name));
                    app.retarget();
                    app.invalidate();
                }
            });
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
    let change = with_app(hwnd, |app| {
        let (w, h) = client_size(hwnd);
        let mut ops = scene(&app.layout, app.s, &Theme::LIGHT, &app.view);
        let board = app.board();
        ops.extend(board.ops);
        app.adopt(board.targets, board.pane);
        if !app.gfx.draw(dc, Rect::new(0, 0, w, h), &ops, &app.fonts) {
            app.invalidate();
        }
        app.tips.replace(tips(&app.targets))
    });
    unsafe { EndPaint(hwnd, &ps) };
    if let Some(change) = change.flatten() {
        change.apply();
    }
}

fn on_agent(hwnd: HWND) {
    let delivered = with_app(hwnd, |app| {
        let Some(update) = app.link.take() else {
            return false;
        };
        let before = app.update.as_ref().map(|u| u.state.ids());
        if before != Some(update.state.ids()) {
            app.view.pointer.sessions_changed();
        }
        let before = app.update.as_ref().map(|u| gateways::names(&u.gateways));
        if before != Some(gateways::names(&update.gateways)) {
            app.view.pointer.gateways_changed();
        }
        app.launches.settle(update.launched);
        app.update = Some(update);
        app.retarget();
        app.invalidate();
        true
    });
    if delivered == Some(true) {
        rehover(hwnd);
    }
}

fn rehover(hwnd: HWND) {
    let mut p = POINT::default();
    if unsafe { GetCursorPos(&mut p) } == 0 || unsafe { WindowFromPoint(p) } != hwnd {
        return;
    }
    unsafe { ScreenToClient(hwnd, &mut p) };
    let (w, h) = client_size(hwnd);
    if !Rect::new(0, 0, w, h).contains(p.x, p.y) {
        return;
    }
    let inside = with_app(hwnd, |app| {
        let zone = app.zone(p.x, p.y);
        if hit_code(zone) != HTCLIENT {
            return false;
        }
        if app.view.pointer.moved(zone) {
            app.invalidate();
        }
        true
    });
    if inside == Some(true) {
        track(hwnd, TME_LEAVE);
    }
}

fn on_nc_calc_size(hwnd: HWND, wp: WPARAM, lp: LPARAM) -> Option<LRESULT> {
    if wp == 0 {
        return None;
    }
    let frame_y = with_custom(hwnd, |app| app.frame_y())?;
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
    with_custom(hwnd, |_| ())?;
    let system = unsafe { DefWindowProcW(hwnd, WM_NCHITTEST, 0, lp) };
    if system != HTCLIENT as LRESULT {
        return Some(system);
    }
    with_app(hwnd, |app| hit_code(app.screen_zone(lp)) as LRESULT)
}

fn on_nc_mouse(hwnd: HWND, msg: u32, wp: WPARAM) -> Option<LRESULT> {
    let button = caption_button(wp);
    let zone = button.unwrap_or(Zone::Caption);
    let action = with_custom(hwnd, |app| {
        let (changed, action) = match msg {
            WM_NCMOUSEMOVE => (app.view.pointer.moved(zone), None),
            WM_NCLBUTTONDOWN | WM_NCLBUTTONDBLCLK => (app.view.pointer.down(zone), None),
            _ => (true, app.view.pointer.up(zone)),
        };
        if changed {
            app.invalidate();
        }
        action
    })?;
    if msg == WM_NCMOUSEMOVE {
        track(hwnd, TME_LEAVE | TME_NONCLIENT);
    }
    button?;
    perform(hwnd, action);
    Some(0)
}

enum Follow {
    Track,
    Capture,
    Release(Option<Action>),
    Nothing,
}

fn on_mouse(hwnd: HWND, msg: u32, lp: LPARAM) {
    let (x, y) = coords(lp);
    let follow = with_app(hwnd, |app| {
        let zone = app.zone(x, y);
        let pointer = &mut app.view.pointer;
        let (changed, follow) = match msg {
            WM_MOUSEMOVE => (pointer.moved(zone), Follow::Track),
            WM_LBUTTONDOWN if pointer.down(zone) => (true, Follow::Capture),
            WM_LBUTTONDOWN => (false, Follow::Nothing),
            _ => (true, Follow::Release(pointer.up(zone))),
        };
        if changed {
            app.invalidate();
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
            perform(hwnd, action);
        }
        Some(Follow::Nothing) | None => {}
    }
}

fn on_wheel(hwnd: HWND, wp: WPARAM, lp: LPARAM) {
    let (x, y) = coords(lp);
    let mut p = POINT { x, y };
    unsafe { ScreenToClient(hwnd, &mut p) };
    let delta = i32::from((wp >> 16) as u16 as i16);
    let lines = sys::wheel_lines();
    let moved = with_app(hwnd, |app| {
        let Some(pane) = app.pane else {
            return false;
        };
        if !app.layout.content.contains(p.x, p.y) {
            return false;
        }
        let offset = pane.scrolled(delta, lines, app.s.px(20.0));
        let page = app.view.nav.selected();
        if !app.view.scroll.set(page, offset) {
            return false;
        }
        app.retarget();
        app.invalidate();
        true
    });
    if moved == Some(true) {
        rehover(hwnd);
    }
}

fn on_left(hwnd: HWND) {
    with_app(hwnd, |app| {
        if app.view.pointer.left() {
            app.invalidate();
        }
    });
}

fn on_capture_lost(hwnd: HWND) {
    with_app(hwnd, |app| {
        if app.view.pointer.cancel() {
            app.invalidate();
        }
    });
}

fn on_size(hwnd: HWND, wp: WPARAM) {
    with_app(hwnd, |app| {
        app.view.maximized = wp == SIZE_MAXIMIZED as WPARAM;
        app.relayout();
    });
}

fn on_dpi_changed(hwnd: HWND, wp: WPARAM, lp: LPARAM) {
    with_app(hwnd, |app| {
        let s = Scale::new((wp & 0xffff) as u32);
        if let Ok(fonts) = Fonts::new(app.gfx.dwrite(), s) {
            app.s = s;
            app.fonts = fonts;
        }
    });
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
    let Some(s) = with_app(hwnd, |app| {
        app.relayout();
        app.s
    }) else {
        return;
    };
    let icons = Icons::apply(hwnd, s);
    with_app(hwnd, |app| std::mem::replace(&mut app.icons, icons));
}

fn on_composition_changed(hwnd: HWND) {
    with_app(hwnd, |app| app.frame = choose_frame());
    refresh_frame(hwnd);
    with_app(hwnd, |app| app.relayout());
}

fn refresh_frame(hwnd: HWND) {
    let flags = SWP_FRAMECHANGED | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE;
    unsafe { SetWindowPos(hwnd, null_mut(), 0, 0, 0, 0, flags) };
}

fn on_min_max(hwnd: HWND, info: &mut MINMAXINFO) {
    let (s, frame) = with_app(hwnd, |app| (app.s, app.frame))
        .unwrap_or_else(|| (Scale::new(sys::window_dpi(hwnd)), Frame::System));
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
        WM_MOUSEWHEEL => {
            on_wheel(hwnd, wp, lp);
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
        WM_AGENT => {
            on_agent(hwnd);
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
    let frame = with_app(hwnd, |app| app.frame).unwrap_or(Frame::System);
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

fn fail(message: &str) {
    let text = wide(message);
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
        fail("Gateinto could not start Direct2D and DirectWrite rendering.");
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
        fail("Gateinto could not register its window class.");
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
        fail("Gateinto could not create its window.");
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
