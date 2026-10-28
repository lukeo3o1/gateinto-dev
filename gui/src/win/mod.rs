mod appearance;
mod d2d;
mod device;
mod link;
mod run;
mod sys;
mod text;
mod tips;
mod tray;

use std::path::PathBuf;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    BeginPaint, EndPaint, GetMonitorInfoW, InvalidateRect, MONITOR_DEFAULTTONEAREST, MONITORINFO,
    MonitorFromWindow, PAINTSTRUCT, ScreenToClient,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Controls::WM_MOUSELEAVE;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    GetKeyState, ReleaseCapture, SetCapture, TME_LEAVE, TME_NONCLIENT, TRACKMOUSEEVENT,
    TrackMouseEvent, VK_CONTROL, VK_DOWN, VK_ESCAPE, VK_LEFT, VK_MENU, VK_RIGHT, VK_SHIFT, VK_TAB,
    VK_UP,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CREATESTRUCTW, CreateWindowExW, DefWindowProcW, DestroyIcon, DispatchMessageW, GWLP_USERDATA,
    GetClientRect, GetCursorPos, GetMessageW, GetWindowLongPtrW, HICON, HTCAPTION, HTCLIENT,
    HTCLOSE, HTMAXBUTTON, HTMINBUTTON, HTTOP, HTTOPLEFT, HTTOPRIGHT, ICON_BIG, ICON_SMALL,
    IDC_ARROW, IMAGE_ICON, IsIconic, IsZoomed, KillTimer, LoadCursorW, LoadImageW, MB_ICONERROR,
    MB_OK, MINMAXINFO, MSG, MessageBoxW, NCCALCSIZE_PARAMS, PostMessageW, PostQuitMessage,
    RegisterClassExW, SC_CLOSE, SC_MAXIMIZE, SC_MINIMIZE, SC_RESTORE, SIZE_MAXIMIZED, SM_CXICON,
    SM_CXSMICON, SW_HIDE, SW_RESTORE, SW_SHOW, SWP_FRAMECHANGED, SWP_NOACTIVATE, SWP_NOMOVE,
    SWP_NOSIZE, SWP_NOZORDER, SYSTEM_METRICS_INDEX, SendMessageW, SetForegroundWindow, SetTimer,
    SetWindowLongPtrW, SetWindowPos, ShowWindow, TranslateMessage, WA_INACTIVE, WM_ACTIVATE,
    WM_CAPTURECHANGED, WM_CHAR, WM_CLOSE, WM_CREATE, WM_DESTROY, WM_DISPLAYCHANGE, WM_DPICHANGED,
    WM_DWMCOMPOSITIONCHANGED, WM_ERASEBKGND, WM_GETMINMAXINFO, WM_KEYDOWN, WM_KILLFOCUS,
    WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MOUSEMOVE, WM_MOUSEWHEEL, WM_NCCALCSIZE, WM_NCDESTROY,
    WM_NCHITTEST, WM_NCLBUTTONDBLCLK, WM_NCLBUTTONDOWN, WM_NCLBUTTONUP, WM_NCMOUSELEAVE,
    WM_NCMOUSEMOVE, WM_PAINT, WM_SETICON, WM_SETTINGCHANGE, WM_SIZE, WM_SYSCOMMAND, WM_TIMER,
    WNDCLASSEXW, WS_OVERLAPPEDWINDOW, WindowFromPoint,
};

use gateinto::clock::unix_now;
use gateinto::config::{self, GatewayName};
use gateinto::link::store;

use crate::add::{self, Form, Keyed, Units};
use crate::board::{self, Board, board, tips};
use crate::credentials::{self, Dialog, Field};
use crate::focus::{self, Focus, Stop};
use crate::frame::Frame;
use crate::gateways::{self, Launches};
use crate::hit::{Zone, hit};
use crate::layout::{Layout, Rect};
use crate::log::{self, Filter};
use crate::menu::{self, Choice, Entry, Popup, Wheel};
use crate::nav::{self, Page as NavPage};
use crate::pointer::{self, Action};
use crate::scale::Scale;
use crate::scene::{Op, View, scene};
use crate::scroll::Pane;
use crate::sessions;
use crate::settings;
use crate::theme::{self, Theme};
use crate::worker::{Command, Update};
use d2d::Graphics;
use link::{Link, WM_AGENT};
use sys::wide;
use text::Fonts;
use tips::Tips;
use tray::{Notify, Panel, WM_TRAY};

const STYLE: u32 = WS_OVERLAPPEDWINDOW;
const EX_STYLE: u32 = 0;
const APP_ICON: usize = 1;
const TITLE: &str = "Gateinto";
const COPIED_TIMER: usize = 1;
const IMMERSIVE: &str = "ImmersiveColorSet";
const COPIED_MS: u32 = 1500;
const PASTE_UNITS: usize = 4096;

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
    stops: Vec<Stop>,
    focus: Focus,
    pane: Option<Pane>,
    popup: Option<Pane>,
    icons: Icons,
    update: Option<Update>,
    launches: Launches,
    link: Link,
    tips: Tips,
    config: String,
    sign_in: bool,
    theme: theme::Choice,
    dark: bool,
    build: u32,
    copied: bool,
    filter: Filter,
    log: log::Body,
    dialog: Option<Dialog>,
    details: Option<GatewayName>,
    adding: Option<Form>,
    units: Units,
    tickets: u64,
    secret: Option<u32>,
    notify: Notify,
    panel: Panel,
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
        let theme = appearance::choice();
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
            stops: Vec::new(),
            focus: Focus::default(),
            pane: None,
            popup: None,
            update: None,
            launches: Launches::default(),
            link: Link::start(hwnd),
            tips: Tips::new(hwnd),
            config: config_line(),
            sign_in: false,
            theme,
            dark: theme.dark(appearance::light_apps()),
            build: sys::os_build(),
            copied: false,
            filter: Filter::default(),
            log: log::Body::Rows(Vec::new()),
            dialog: None,
            details: None,
            adding: None,
            units: Units::default(),
            tickets: 0,
            secret: None,
            notify: Notify::default(),
            panel: Panel::new(s),
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
        let (l, s, t, v, m) = (
            &self.layout,
            self.s,
            self.palette(),
            &self.view,
            &self.fonts,
        );
        let failure = update.failure.as_deref();
        let mut board = match v.nav.selected() {
            NavPage::Settings => {
                let page = settings::page(
                    &self.config,
                    &update.agent,
                    failure,
                    self.sign_in,
                    self.theme,
                );
                board::settings::board(l, s, t, v, &page, m)
            }
            NavPage::Device => {
                let device = update.device.as_ref();
                let gateways = &update.gateways;
                let (listen, state, copied) = (&update.listen, &update.state, self.copied);
                let page = crate::device::page(device, listen, state, gateways, failure, copied);
                board::device::board(l, s, t, v, &page, m)
            }
            NavPage::Log => {
                let page = log::page(&update.log, &self.log, self.filter, failure, self.copied);
                board::log::board(l, s, t, v, &page, m)
            }
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
                &sessions::page(&update.state, failure, unix_now(), self.launches.busy()),
                m,
            ),
        };
        if v.popup.is_some() {
            board::menu::overlay(&mut board, l, s, t, v, &self.entries(), m);
        }
        if let Some(dialog) = &self.dialog {
            let page = dialog.page(&update.state);
            board::dialog::credentials(&mut board, l, s, t, v, &page, m);
        }
        if let Some(details) = self.gateway_details() {
            board::dialog::gateway(&mut board, l, s, t, v, &details, m);
        }
        if let Some(form) = &self.adding {
            let sheet = add::sheet(form, &update.gateways);
            board::dialog::add(&mut board, l, s, t, v, &sheet, m);
        }
        board
    }

    fn entries(&self) -> Vec<Entry> {
        match (self.view.popup, &self.update) {
            (Some(Popup::Picker), Some(update)) => menu::picker(&update.gateways),
            (Some(Popup::Session(id)), Some(update)) => {
                menu::session(&update.gateways, &update.state, id)
            }
            _ => Vec::new(),
        }
    }

    fn retarget(&mut self) {
        let board = self.board();
        self.adopt(board);
    }

    fn adopt(&mut self, board: Board) -> Vec<Op> {
        let rail: Vec<Stop> = self
            .layout
            .nav
            .iter()
            .map(|item| Stop {
                rect: item.frame,
                zone: Zone::Nav(item.page),
                scrolls: false,
                clip: item.frame,
            })
            .collect();
        let (stops, trapped) = focus::stops(&rail, &board.order);
        self.focus.sync(&stops, trapped);
        if let (Some(form), None) = (&self.adding, self.focus.zone()) {
            self.focus.clicked(Zone::AddField(form.selected()), &stops);
        }
        self.stops = stops;
        self.targets = board.targets;
        self.pane = board.pane;
        if let Some(pane) = board.pane {
            let page = self.view.nav.selected();
            self.view.scroll.set(page, pane.offset);
        }
        self.popup = board.popup;
        if let Some(pane) = board.popup {
            self.view.popup_scroll = pane.offset;
        }
        if board.anchor.is_none() {
            self.view.popup = None;
            self.view.popup_scroll = 0;
        }
        board.ops
    }

    fn tab(&mut self, back: bool) {
        let zone = self.focus.tab(&self.stops, back);
        self.focused(zone);
    }

    fn arrow(&mut self, forward: bool) -> bool {
        let zone = self.focus.arrow(&self.stops, forward);
        self.focused(zone);
        zone.is_some()
    }

    fn focused(&mut self, zone: Option<Zone>) {
        let Some(zone) = zone else {
            return;
        };
        if let (Zone::AddField(input), Some(form)) = (zone, &mut self.adding) {
            form.select(input);
        }
        if let Some(stop) = self.stops.iter().find(|s| s.zone == zone && s.scrolls) {
            match (zone, self.popup, self.pane) {
                (Zone::Entry(_), Some(pane), _) => self.view.popup_scroll = pane.reveal(stop.rect),
                (Zone::Entry(_), None, _) => {}
                (_, _, Some(pane)) => {
                    let page = self.view.nav.selected();
                    self.view.scroll.set(page, pane.reveal(stop.rect));
                }
                _ => {}
            }
        }
        self.retarget();
        self.invalidate();
    }

    fn keyed_action(&self) -> Option<Action> {
        if matches!(self.focus.zone(), Some(Zone::AddField(_))) {
            return None;
        }
        self.focus.action(&self.stops)
    }

    fn hide_ring(&mut self, zone: Zone) {
        if self.focus.ring().is_some() {
            self.invalidate();
        }
        self.focus.clicked(zone, &self.stops);
    }

    fn ring(&self) -> Vec<Op> {
        let ring = self.focus.ring();
        self.stops
            .iter()
            .find(|s| Some(s.zone) == ring)
            .map_or_else(Vec::new, |stop| {
                focus::outline(stop, self.s, self.palette())
            })
    }

    fn gateway_details(&self) -> Option<gateways::Details> {
        let (update, name) = (self.update.as_ref()?, self.details.as_ref()?);
        gateways::details(&update.gateways, &update.sections, &update.state, name)
    }

    fn modal(&self) -> bool {
        self.dialog.is_some() || self.details.is_some() || self.adding.is_some()
    }

    fn portal(&self, id: u64) -> Option<String> {
        let update = self.update.as_ref()?;
        menu::portal(&update.gateways, &update.state, id).map(str::to_owned)
    }

    fn open(&mut self, popup: Popup) {
        self.view.popup = Some(popup);
        self.view.popup_scroll = 0;
        self.retarget();
        self.invalidate();
    }

    fn select(&mut self, page: NavPage) {
        let before = self.view.nav.selected();
        if self.view.nav.select(page) {
            if self.dialog.take().is_some() {
                self.forget_secret();
            }
            self.details = None;
            self.adding = None;
            self.relog();
            if self.copied {
                self.uncopy();
            }
            if (before == NavPage::Log) != (page == NavPage::Log) {
                self.link.send(Command::Watch(page == NavPage::Log));
            }
            if page == NavPage::Log {
                self.view.scroll.set(page, i32::MAX);
            }
            if page == NavPage::Settings {
                match run::enabled() {
                    Ok(on) => self.sign_in = on,
                    Err(()) => self.fail(settings::SIGN_IN_UNREAD),
                }
            }
            if page == NavPage::Device {
                self.link.send(Command::Probe);
            }
            self.retarget();
            self.invalidate();
        }
    }

    fn dismiss(&mut self) -> bool {
        if self.view.popup.take().is_none() {
            return false;
        }
        self.view.popup_scroll = 0;
        self.retarget();
        self.invalidate();
        true
    }

    fn reveal(&mut self, id: u64) {
        let Some(update) = &self.update else {
            return;
        };
        let ticket = self.tickets.wrapping_add(1);
        let Some(dialog) = Dialog::open(&update.state, id, ticket) else {
            return;
        };
        self.tickets = ticket;
        self.forget_secret();
        self.uncopy();
        self.details = None;
        self.adding = None;
        self.dialog = Some(dialog);
        self.link.send(Command::Credentials(id, ticket));
        self.retarget();
        self.invalidate();
    }

    fn show_gateway(&mut self, name: GatewayName) {
        self.close_dialog();
        self.details = Some(name);
        if self.gateway_details().is_none() {
            self.details = None;
        }
        self.retarget();
        self.invalidate();
    }

    fn gateway_row(&mut self, row: usize) {
        let names = self.update.as_ref().map(|u| gateways::names(&u.gateways));
        if let Some(name) = names.unwrap_or_default().get(row) {
            self.show_gateway(name.clone());
        }
    }

    fn session_gateway(&mut self, id: u64) {
        let name = self
            .update
            .as_ref()
            .and_then(|u| menu::gateway(&u.gateways, &u.state, id));
        match name {
            Some(name) => self.show_gateway(name),
            None => self.select(NavPage::Gateways),
        }
    }

    fn close_dialog(&mut self) -> bool {
        if self.details.take().is_some() || self.adding.take().is_some() {
            self.retarget();
            self.invalidate();
            return true;
        }
        if self.dialog.take().is_none() {
            return false;
        }
        self.forget_secret();
        self.uncopy();
        true
    }

    fn forget_secret(&mut self) {
        device::clear_secret(self.hwnd, self.secret.take());
    }

    fn open_add(&mut self) {
        self.close_dialog();
        self.units = Units::default();
        self.adding = Some(Form::default());
        self.retarget();
        self.invalidate();
    }

    fn edit(&mut self, change: impl FnOnce(&mut Form)) {
        if let Some(form) = &mut self.adding {
            change(form);
            self.retarget();
            self.invalidate();
        }
    }

    fn typed(&mut self, unit: u16) -> bool {
        if self.adding.is_none() {
            return false;
        }
        let Some(c) = self.units.push(unit) else {
            return true;
        };
        let field = match self.focus.zone() {
            Some(Zone::AddField(input)) => Some(input),
            _ => None,
        };
        let Some(form) = &mut self.adding else {
            return false;
        };
        match add::keyed(form, field, c) {
            Keyed::Changed => {}
            Keyed::Submit => return self.confirm_add(),
            Keyed::Paste => {
                let text = device::paste(self.hwnd, PASTE_UNITS);
                if let (Some(text), Some(form)) = (text, &mut self.adding) {
                    form.type_text(&text);
                }
            }
            Keyed::Ignored => return true,
        }
        self.retarget();
        self.invalidate();
        true
    }

    fn confirm_add(&mut self) -> bool {
        let Some(form) = &mut self.adding else {
            return false;
        };
        let listing = gateways::read(config::default_path())
            .map(|file| gateways::catalog(&file, store::default_dir()));
        if add::commit(form, &listing, store::default_dir(), unix_now()) {
            self.adding = None;
        }
        self.retarget();
        self.invalidate();
        true
    }

    fn revoke_credentials(&mut self) {
        if let Some(dialog) = &self.dialog {
            self.link.send(Command::Close(dialog.id()));
        }
        self.close_dialog();
    }

    fn toggle_password(&mut self) {
        if let Some(dialog) = &mut self.dialog {
            dialog.toggle();
            self.retarget();
            self.invalidate();
        }
    }

    fn copy_credential(&mut self, field: Field) {
        let Some(secret) = self.dialog.as_ref().and_then(|d| d.secret(field)) else {
            return;
        };
        if let Some(sequence) = device::copy_secret(self.hwnd, secret) {
            self.secret = Some(sequence);
            if let Some(dialog) = &mut self.dialog {
                dialog.copied(field);
            }
            unsafe { SetTimer(self.hwnd, COPIED_TIMER, COPIED_MS, None) };
        } else {
            self.fail(credentials::COPY_FAILED);
        }
        self.retarget();
        self.invalidate();
    }

    fn launch(&mut self, row: usize) -> bool {
        let names = self.update.as_ref().map(|u| gateways::names(&u.gateways));
        let Some(name) = self.launches.start(&names.unwrap_or_default(), row) else {
            return false;
        };
        self.link.send(Command::Launch(name));
        self.retarget();
        self.invalidate();
        true
    }

    fn toggle_sign_in(&mut self) {
        let on = !self.sign_in;
        match run::set(on) {
            Ok(()) => self.sign_in = on,
            Err(()) => self.fail(settings::SIGN_IN_FAILED),
        }
        self.retarget();
        self.invalidate();
    }

    fn choose_theme(&mut self, choice: theme::Choice) {
        if appearance::save(choice).is_err() {
            self.fail(settings::THEME_FAILED);
        }
        self.theme = choice;
        self.follow_system();
    }

    fn follow_system(&mut self) {
        self.dark = self.theme.dark(appearance::light_apps());
        self.retarget();
        self.invalidate();
    }

    fn palette(&self) -> &'static Theme {
        Theme::of(self.dark)
    }

    fn copy_id(&mut self) {
        let id = self
            .update
            .as_ref()
            .and_then(|u| crate::device::device_id(u.device.as_ref()));
        let Some(id) = id else {
            return;
        };
        if device::copy(self.hwnd, id) {
            self.copied = unsafe { SetTimer(self.hwnd, COPIED_TIMER, COPIED_MS, None) } != 0;
        } else {
            self.fail(crate::device::COPY_FAILED);
        }
        self.retarget();
        self.invalidate();
    }

    fn copy_log(&mut self) {
        let Some(update) = &self.update else {
            return;
        };
        let text = log::text(&update.log, self.filter, sys::utc_offset());
        if text.is_empty() {
            return;
        }
        if device::copy(self.hwnd, &text) {
            self.copied = unsafe { SetTimer(self.hwnd, COPIED_TIMER, COPIED_MS, None) } != 0;
        } else {
            self.fail(log::COPY_FAILED);
        }
        self.retarget();
        self.invalidate();
    }

    fn choose_filter(&mut self, filter: Filter) {
        if std::mem::replace(&mut self.filter, filter) == filter {
            return;
        }
        self.relog();
        self.view.scroll.set(NavPage::Log, i32::MAX);
        self.uncopy();
    }

    fn relog(&mut self) {
        self.log = match &self.update {
            Some(update) if self.view.nav.selected() == NavPage::Log => {
                log::body(&update.state, &update.log, self.filter, sys::utc_offset())
            }
            _ => log::Body::Rows(Vec::new()),
        };
    }

    fn pinned(&self) -> bool {
        self.view.nav.selected() == NavPage::Log && self.pane.is_none_or(|pane| pane.at_bottom())
    }

    fn uncopy(&mut self) {
        unsafe { KillTimer(self.hwnd, COPIED_TIMER) };
        self.copied = false;
        if let Some(dialog) = &mut self.dialog {
            dialog.uncopy();
        }
        self.retarget();
        self.invalidate();
    }

    fn fail(&mut self, failure: &str) {
        if let Some(update) = &mut self.update {
            update.failure = Some(failure.to_owned());
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
        match hit(&self.layout, x, y, band, &self.targets) {
            Zone::Nav(_) if self.modal() => Zone::Client,
            zone => zone,
        }
    }

    fn screen_zone(&self, lp: LPARAM) -> Zone {
        let (x, y) = coords(lp);
        let mut p = POINT { x, y };
        unsafe { ScreenToClient(self.hwnd, &mut p) };
        self.zone(p.x, p.y)
    }
}

fn config_line() -> String {
    let appdata = std::env::var_os("APPDATA").map(PathBuf::from);
    settings::shown(config::default_path().as_deref(), appdata.as_deref())
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
        Zone::Nav(_)
        | Zone::StopAgent
        | Zone::Revoke(_)
        | Zone::More(_)
        | Zone::StartBrowser(_)
        | Zone::GatewayCard(_)
        | Zone::Picker
        | Zone::Entry(_)
        | Zone::OpenConfig
        | Zone::SignIn
        | Zone::Theme(_)
        | Zone::CopyId
        | Zone::CopyLog
        | Zone::LogFilter(_)
        | Zone::Menu
        | Zone::Dialog
        | Zone::CopyCredential(_)
        | Zone::TogglePassword(_)
        | Zone::RevokeCredentials
        | Zone::CloseDialog
        | Zone::AddGateway
        | Zone::AddField(_)
        | Zone::ConfirmAdd
        | Zone::OpenMain
        | Zone::Client => HTCLIENT,
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
            with_app(hwnd, |app| app.select(page));
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
            with_app(hwnd, |app| app.launch(row));
            return;
        }
        Some(Action::GatewayDetails(row)) => {
            with_app(hwnd, |app| app.gateway_row(row));
            rehover(hwnd);
            return;
        }
        Some(Action::OpenPicker) => {
            with_app(hwnd, |app| app.open(Popup::Picker));
            rehover(hwnd);
            return;
        }
        Some(Action::More(id)) => {
            with_app(hwnd, |app| app.open(Popup::Session(id)));
            rehover(hwnd);
            return;
        }
        Some(Action::Choose(index)) => {
            let portal = with_app(hwnd, |app| {
                let choice = app.entries().get(index).and_then(|entry| entry.choice);
                app.dismiss();
                match choice {
                    Some(Choice::Launch(row)) => {
                        app.launch(row);
                    }
                    Some(Choice::Details(id)) => app.session_gateway(id),
                    Some(Choice::Portal(id)) => return app.portal(id),
                    Some(Choice::Credentials(id)) => app.reveal(id),
                    None => {}
                }
                None
            });
            rehover(hwnd);
            if let Some(url) = portal.flatten()
                && !sys::open_https(hwnd, &url)
            {
                with_app(hwnd, |app| {
                    app.fail(menu::PORTAL_FAILED);
                    app.retarget();
                    app.invalidate();
                });
            }
            return;
        }
        Some(Action::OpenConfig) => {
            let opened = config::default_path()
                .filter(|path| path.is_file())
                .is_some_and(|path| sys::open_file(hwnd, &path));
            if !opened {
                with_app(hwnd, |app| {
                    app.fail(settings::OPEN_FAILED);
                    app.retarget();
                    app.invalidate();
                });
            }
            return;
        }
        Some(Action::ToggleSignIn) => {
            with_app(hwnd, App::toggle_sign_in);
            return;
        }
        Some(Action::Theme(choice)) => {
            with_app(hwnd, |app| app.choose_theme(choice));
            apply_theme(hwnd);
            rehover(hwnd);
            return;
        }
        Some(Action::CopyId) => {
            with_app(hwnd, App::copy_id);
            return;
        }
        Some(Action::CopyLog) => {
            with_app(hwnd, App::copy_log);
            return;
        }
        Some(Action::Filter(filter)) => {
            with_app(hwnd, |app| app.choose_filter(filter));
            rehover(hwnd);
            return;
        }
        Some(Action::CopyCredential(field)) => {
            with_app(hwnd, |app| app.copy_credential(field));
            return;
        }
        Some(Action::TogglePassword) => {
            with_app(hwnd, App::toggle_password);
            return;
        }
        Some(Action::RevokeCredentials) => {
            with_app(hwnd, App::revoke_credentials);
            rehover(hwnd);
            return;
        }
        Some(Action::CloseDialog) => {
            with_app(hwnd, App::close_dialog);
            rehover(hwnd);
            return;
        }
        Some(Action::AddGateway) => {
            with_app(hwnd, App::open_add);
            rehover(hwnd);
            return;
        }
        Some(Action::Focus(input)) => {
            with_app(hwnd, |app| app.edit(|form| form.select(input)));
            return;
        }
        Some(Action::ConfirmAdd) => {
            with_app(hwnd, App::confirm_add);
            rehover(hwnd);
            return;
        }
        Some(Action::OpenMain) => {
            show_main(hwnd);
            return;
        }
        Some(Action::Minimize) => SC_MINIMIZE,
        Some(Action::ToggleMaximize) if unsafe { IsZoomed(hwnd) } != 0 => SC_RESTORE,
        Some(Action::ToggleMaximize) => SC_MAXIMIZE,
        Some(Action::Close) => SC_CLOSE,
    };
    unsafe { PostMessageW(hwnd, WM_SYSCOMMAND, command as WPARAM, 0) };
}

fn show_main(hwnd: HWND) {
    unsafe {
        if IsIconic(hwnd) != 0 {
            ShowWindow(hwnd, SW_RESTORE);
        } else {
            ShowWindow(hwnd, SW_SHOW);
        }
        SetForegroundWindow(hwnd);
    }
}

fn on_close(hwnd: HWND) -> Option<LRESULT> {
    let hides = with_app(hwnd, |app| {
        if !app.notify.added() {
            return false;
        }
        while app.close_dialog() {}
        app.dismiss();
        true
    })?;
    if !hides {
        return None;
    }
    unsafe { ShowWindow(hwnd, SW_HIDE) };
    Some(0)
}

fn on_paint(hwnd: HWND) {
    let mut ps = PAINTSTRUCT::default();
    let dc = unsafe { BeginPaint(hwnd, &mut ps) };
    let change = with_app(hwnd, |app| {
        let (w, h) = client_size(hwnd);
        let mut ops = scene(&app.layout, app.s, app.palette(), &app.view);
        let board = app.board();
        ops.extend(app.adopt(board));
        ops.extend(app.ring());
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
        let reveal = app.link.take_reveal();
        let revealed = reveal.is_some();
        if let Some(reveal) = reveal {
            credentials::deliver(app.dialog.as_mut(), reveal);
        }
        let Some(update) = app.link.take() else {
            if revealed {
                app.retarget();
                app.invalidate();
            }
            return false;
        };
        let before = app.update.as_ref().map(|u| u.state.ids());
        if before != Some(update.state.ids()) {
            app.view.pointer.sessions_changed();
        }
        let before = app.update.as_ref().map(|u| gateways::names(&u.gateways));
        if before != Some(gateways::names(&update.gateways)) {
            app.gateways_changed();
        }
        let entries = app.entries();
        let pinned = app.pinned();
        let evicted = app.update.as_ref().map_or(0, |before| {
            log::evicted(&before.log, &update.log, app.filter)
        });
        app.launches.settle(update.launched);
        app.launch_settled(update.failure.as_deref());
        if app.dialog.as_ref().is_some_and(|d| !d.lasts(&update.state)) {
            app.close_dialog();
        }
        app.update = Some(update);
        if app.details.is_some() && app.gateway_details().is_none() {
            app.details = None;
        }
        app.relog();
        if pinned {
            app.view.scroll.set(NavPage::Log, i32::MAX);
        } else if evicted > 0 {
            let offset = app.view.scroll.get(NavPage::Log);
            let row_h = board::log::row_height(app.s);
            let kept = log::kept_offset(offset, evicted, row_h);
            app.view.scroll.set(NavPage::Log, kept);
        }
        if app.entries() != entries {
            app.view.pointer.entries_changed();
        }
        app.retarget();
        app.invalidate();
        app.refresh_flyout();
        true
    });
    if delivered == Some(true) {
        tray::refresh_icon(hwnd);
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
    if msg != WM_NCMOUSEMOVE && msg != WM_NCLBUTTONUP {
        with_app(hwnd, App::dismiss);
    }
    let button = caption_button(wp);
    let zone = button.unwrap_or(Zone::Caption);
    let action = with_custom(hwnd, |app| {
        if msg == WM_NCLBUTTONDOWN || msg == WM_NCLBUTTONDBLCLK {
            app.hide_ring(zone);
        }
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
    Dismissed,
    Nothing,
}

fn on_mouse(hwnd: HWND, msg: u32, lp: LPARAM) {
    let (x, y) = coords(lp);
    let follow = with_app(hwnd, |app| {
        let zone = app.zone(x, y);
        if msg == WM_LBUTTONDOWN {
            app.hide_ring(zone);
        }
        if msg == WM_LBUTTONDOWN && app.view.popup.is_some() && menu::dismisses(zone) {
            app.dismiss();
            return Follow::Dismissed;
        }
        if msg == WM_LBUTTONDOWN
            && zone == Zone::Client
            && pointer::outside_click_closes(app.adding.is_some())
            && app.close_dialog()
        {
            return Follow::Dismissed;
        }
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
        Some(Follow::Dismissed) => rehover(hwnd),
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
        if app.modal() {
            return false;
        }
        let open = app.view.popup.is_some();
        let inside = app.layout.content.contains(p.x, p.y);
        let line = app.s.px(20.0);
        match menu::wheel(open, app.zone(p.x, p.y), inside) {
            Some(Wheel::Menu) => {
                let Some(pane) = app.popup else {
                    return false;
                };
                let offset = pane.scrolled(delta, lines, line);
                if std::mem::replace(&mut app.view.popup_scroll, offset) == offset {
                    return false;
                }
            }
            Some(Wheel::Page) => {
                let Some(pane) = app.pane else {
                    return false;
                };
                let page = app.view.nav.selected();
                if !app.view.scroll.set(page, pane.scrolled(delta, lines, line)) {
                    return false;
                }
            }
            None => return false,
        }
        app.retarget();
        app.invalidate();
        true
    });
    if moved == Some(true) {
        rehover(hwnd);
    }
}

fn on_char(hwnd: HWND, wp: WPARAM) -> Option<LRESULT> {
    let activates = wp == WPARAM::from(b'\r') || wp == WPARAM::from(b' ');
    if activates && let Some(action) = with_app(hwnd, |app| app.keyed_action())? {
        perform(hwnd, Some(action));
        rehover(hwnd);
        return Some(0);
    }
    let handled = with_app(hwnd, |app| app.typed(wp as u16))?;
    if !handled {
        return None;
    }
    rehover(hwnd);
    Some(0)
}

fn on_key(hwnd: HWND, wp: WPARAM) -> Option<LRESULT> {
    let held = |key: u16| unsafe { GetKeyState(i32::from(key)) } < 0;
    let key = wp as u16;
    if key == VK_TAB {
        with_app(hwnd, |app| app.tab(held(VK_SHIFT)))?;
        return Some(0);
    }
    let forward = match key {
        VK_LEFT | VK_UP => Some(false),
        VK_RIGHT | VK_DOWN => Some(true),
        _ => None,
    };
    if let Some(forward) = forward {
        return with_app(hwnd, |app| app.arrow(forward))?.then_some(0);
    }
    if let Some(page) = nav::shortcut(key, held(VK_CONTROL), held(VK_MENU)) {
        if !with_app(hwnd, |app| app.modal())? {
            perform(hwnd, Some(Action::Select(page)));
        }
        return Some(0);
    }
    if wp != WPARAM::from(VK_ESCAPE) {
        return None;
    }
    if !with_app(hwnd, |app| app.dismiss() || app.close_dialog())? {
        return None;
    }
    rehover(hwnd);
    Some(0)
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

fn apply_theme(hwnd: HWND) {
    let Some((dark, choice, build, tips)) = with_app(hwnd, |app| {
        (app.dark, app.theme, app.build, app.tips.window())
    }) else {
        return;
    };
    sys::dark_title_bar(hwnd, dark, build);
    sys::dark_controls(tips, dark, build);
    sys::menu_mode(choice, build);
}

fn on_setting_change(hwnd: HWND, lp: LPARAM) {
    if lp == 0 {
        return;
    }
    let area = lp as *const u16;
    for (i, want) in wide(IMMERSIVE).into_iter().enumerate() {
        if unsafe { *area.add(i) } != want {
            return;
        }
    }
    with_app(hwnd, App::follow_system);
    apply_theme(hwnd);
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
        WM_KEYDOWN => on_key(hwnd, wp),
        WM_CHAR => on_char(hwnd, wp),
        WM_ACTIVATE | WM_KILLFOCUS => {
            if msg == WM_KILLFOCUS || (wp & 0xFFFF) as u32 == WA_INACTIVE {
                with_app(hwnd, App::dismiss);
            }
            None
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
        WM_TIMER if wp == COPIED_TIMER => {
            with_app(hwnd, App::uncopy);
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
            tray::rescale_icon(hwnd);
            Some(0)
        }
        WM_DISPLAYCHANGE => {
            tray::rescale_icon(hwnd);
            None
        }
        WM_SETTINGCHANGE => {
            on_setting_change(hwnd, lp);
            None
        }
        WM_DWMCOMPOSITIONCHANGED => {
            on_composition_changed(hwnd);
            Some(0)
        }
        WM_CLOSE => on_close(hwnd),
        WM_TRAY => {
            tray::on_tray(hwnd, wp, lp);
            Some(0)
        }
        _ if tray::taskbar_created(msg) => {
            tray::on_taskbar_created(hwnd);
            Some(0)
        }
        WM_DESTROY => {
            tray::destroy(hwnd);
            with_app(hwnd, App::forget_secret);
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
    apply_theme(hwnd);
    center_on_monitor(hwnd);
    unsafe { ShowWindow(hwnd, SW_SHOW) };
    tray::install(hwnd, instance);

    let mut msg = MSG::default();
    while unsafe { GetMessageW(&mut msg, null_mut(), 0, 0) } > 0 {
        unsafe {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}
