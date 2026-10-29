use std::cell::RefCell;

use windows::Win32::Foundation::{D2DERR_RECREATE_TARGET, RECT};
use windows::Win32::Graphics::Direct2D::Common::{
    D2D_RECT_F, D2D_SIZE_F, D2D1_ALPHA_MODE_IGNORE, D2D1_BEZIER_SEGMENT, D2D1_COLOR_F,
    D2D1_FIGURE_BEGIN, D2D1_FIGURE_BEGIN_FILLED, D2D1_FIGURE_BEGIN_HOLLOW, D2D1_FIGURE_END_CLOSED,
    D2D1_FIGURE_END_OPEN, D2D1_PIXEL_FORMAT,
};
use windows::Win32::Graphics::Direct2D::{
    D2D1_ANTIALIAS_MODE_ALIASED, D2D1_ARC_SEGMENT, D2D1_ARC_SIZE_LARGE, D2D1_ARC_SIZE_SMALL,
    D2D1_CAP_STYLE_ROUND, D2D1_DRAW_TEXT_OPTIONS_CLIP, D2D1_ELLIPSE,
    D2D1_FACTORY_TYPE_SINGLE_THREADED, D2D1_FEATURE_LEVEL_DEFAULT, D2D1_LINE_JOIN_ROUND,
    D2D1_RENDER_TARGET_PROPERTIES, D2D1_RENDER_TARGET_TYPE_DEFAULT, D2D1_RENDER_TARGET_USAGE_NONE,
    D2D1_ROUNDED_RECT, D2D1_STROKE_STYLE_PROPERTIES, D2D1_SWEEP_DIRECTION_CLOCKWISE,
    D2D1_SWEEP_DIRECTION_COUNTER_CLOCKWISE, D2D1_TEXT_ANTIALIAS_MODE,
    D2D1_TEXT_ANTIALIAS_MODE_CLEARTYPE, D2D1_TEXT_ANTIALIAS_MODE_GRAYSCALE, D2D1CreateFactory,
    ID2D1DCRenderTarget, ID2D1Factory, ID2D1PathGeometry, ID2D1SolidColorBrush, ID2D1StrokeStyle,
};
use windows::Win32::Graphics::DirectWrite::{
    DWRITE_FACTORY_TYPE_SHARED, DWRITE_RENDERING_MODE_CLEARTYPE_NATURAL_SYMMETRIC,
    DWriteCreateFactory, IDWriteFactory, IDWriteRenderingParams,
};
use windows::Win32::Graphics::Dxgi::Common::DXGI_FORMAT_B8G8R8A8_UNORM;
use windows::Win32::Graphics::Gdi::HDC;
use windows::core::Result;
use windows_numerics::Vector2;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    FE_FONTSMOOTHINGCLEARTYPE, SPI_GETFONTSMOOTHING, SPI_GETFONTSMOOTHINGTYPE,
    SystemParametersInfoW,
};

use super::text::Fonts;
use crate::icons::{self, Icon, Prim, Seg};
use crate::layout::Rect;
use crate::logo::{self, Arch};
use crate::scene::Op;
use crate::theme::Rgb;

struct Target {
    rt: ID2D1DCRenderTarget,
    brush: ID2D1SolidColorBrush,
}

pub struct Graphics {
    d2d: ID2D1Factory,
    dw: IDWriteFactory,
    round: ID2D1StrokeStyle,
    params: Option<IDWriteRenderingParams>,
    target: RefCell<Option<Target>>,
}

fn color(c: Rgb) -> D2D1_COLOR_F {
    let [r, g, b, a] = c.channels();
    D2D1_COLOR_F { r, g, b, a }
}

fn point((x, y): icons::Point) -> Vector2 {
    Vector2::new(x, y)
}

fn rectf(x: f32, y: f32, w: f32, h: f32) -> D2D_RECT_F {
    D2D_RECT_F {
        left: x,
        top: y,
        right: x + w,
        bottom: y + h,
    }
}

fn rect(r: Rect) -> D2D_RECT_F {
    rectf(r.x as f32, r.y as f32, r.w as f32, r.h as f32)
}

fn rounded(rect: D2D_RECT_F, radius: f32) -> D2D1_ROUNDED_RECT {
    D2D1_ROUNDED_RECT {
        rect,
        radiusX: radius,
        radiusY: radius,
    }
}

fn system_flag(action: u32) -> u32 {
    let mut value = 0u32;
    let queried = unsafe { SystemParametersInfoW(action, 0, (&raw mut value).cast(), 0) };
    if queried != 0 { value } else { 0 }
}

fn text_antialias() -> D2D1_TEXT_ANTIALIAS_MODE {
    let smoothing = system_flag(SPI_GETFONTSMOOTHING) != 0;
    if smoothing && system_flag(SPI_GETFONTSMOOTHINGTYPE) == FE_FONTSMOOTHINGCLEARTYPE {
        D2D1_TEXT_ANTIALIAS_MODE_CLEARTYPE
    } else {
        D2D1_TEXT_ANTIALIAS_MODE_GRAYSCALE
    }
}

fn natural_symmetric(dw: &IDWriteFactory) -> Option<IDWriteRenderingParams> {
    unsafe {
        let system = dw.CreateRenderingParams().ok()?;
        dw.CreateCustomRenderingParams(
            system.GetGamma(),
            system.GetEnhancedContrast(),
            system.GetClearTypeLevel(),
            system.GetPixelGeometry(),
            DWRITE_RENDERING_MODE_CLEARTYPE_NATURAL_SYMMETRIC,
        )
        .ok()
    }
}

impl Graphics {
    pub fn new() -> Result<Self> {
        let d2d: ID2D1Factory =
            unsafe { D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, None)? };
        let dw: IDWriteFactory = unsafe { DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED)? };
        let props = D2D1_STROKE_STYLE_PROPERTIES {
            startCap: D2D1_CAP_STYLE_ROUND,
            endCap: D2D1_CAP_STYLE_ROUND,
            dashCap: D2D1_CAP_STYLE_ROUND,
            lineJoin: D2D1_LINE_JOIN_ROUND,
            miterLimit: 10.0,
            ..Default::default()
        };
        let round = unsafe { d2d.CreateStrokeStyle(&props, None)? };
        let params = natural_symmetric(&dw);
        let graphics = Self {
            d2d,
            dw,
            round,
            params,
            target: RefCell::new(None),
        };
        *graphics.target.borrow_mut() = Some(graphics.create_target()?);
        Ok(graphics)
    }

    pub fn dwrite(&self) -> &IDWriteFactory {
        &self.dw
    }

    fn create_target(&self) -> Result<Target> {
        let props = D2D1_RENDER_TARGET_PROPERTIES {
            r#type: D2D1_RENDER_TARGET_TYPE_DEFAULT,
            pixelFormat: D2D1_PIXEL_FORMAT {
                format: DXGI_FORMAT_B8G8R8A8_UNORM,
                alphaMode: D2D1_ALPHA_MODE_IGNORE,
            },
            dpiX: 96.0,
            dpiY: 96.0,
            usage: D2D1_RENDER_TARGET_USAGE_NONE,
            minLevel: D2D1_FEATURE_LEVEL_DEFAULT,
        };
        unsafe {
            let rt = self.d2d.CreateDCRenderTarget(&props)?;
            if let Some(params) = &self.params {
                rt.SetTextRenderingParams(params);
            }
            let brush = rt.CreateSolidColorBrush(&color(Rgb(0)), None)?;
            Ok(Target { rt, brush })
        }
    }

    pub fn draw(
        &self,
        hdc: windows_sys::Win32::Graphics::Gdi::HDC,
        bounds: Rect,
        ops: &[Op],
        fonts: &Fonts,
    ) -> bool {
        let mut slot = self.target.borrow_mut();
        if slot.is_none() {
            *slot = self.create_target().ok();
        }
        let Some(target) = slot.as_ref() else {
            return true;
        };
        let sub = RECT {
            left: bounds.x,
            top: bounds.y,
            right: bounds.right(),
            bottom: bounds.bottom(),
        };
        if unsafe { target.rt.BindDC(HDC(hdc), &sub) }.is_err() {
            return true;
        }
        unsafe {
            target.rt.BeginDraw();
            target.rt.SetTextAntialiasMode(text_antialias());
        }
        let canvas = Canvas {
            d2d: &self.d2d,
            rt: &target.rt,
            brush: &target.brush,
            round: &self.round,
        };
        for op in ops {
            canvas.op(op, fonts);
        }
        let ended = unsafe { target.rt.EndDraw(None, None) };
        if ended.is_err_and(|e| e.code() == D2DERR_RECREATE_TARGET) {
            *slot = None;
            return false;
        }
        true
    }
}

struct Canvas<'a> {
    d2d: &'a ID2D1Factory,
    rt: &'a ID2D1DCRenderTarget,
    brush: &'a ID2D1SolidColorBrush,
    round: &'a ID2D1StrokeStyle,
}

impl Canvas<'_> {
    fn paint(&self, c: Rgb) -> &ID2D1SolidColorBrush {
        unsafe { self.brush.SetColor(&color(c)) };
        self.brush
    }

    fn op(&self, op: &Op, fonts: &Fonts) {
        match *op {
            Op::Fill(r, c) => unsafe { self.rt.FillRectangle(&rect(r), self.paint(c)) },
            Op::Shade(r, c, alpha) => unsafe {
                let tint = D2D1_COLOR_F {
                    a: alpha,
                    ..color(c)
                };
                self.brush.SetColor(&tint);
                self.rt.FillRectangle(&rect(r), self.brush)
            },
            Op::Round(r, radius, c) => unsafe {
                self.rt
                    .FillRoundedRectangle(&rounded(rect(r), radius), self.paint(c))
            },
            Op::Icon(icon, r, width, c) => self.icon(&icon, r, width, c),
            Op::Text(font, ref s, r, c) => {
                if let Some(layout) = fonts.layout(font, s, r.w as f32, r.h as f32) {
                    let origin = Vector2::new(r.x as f32, r.y as f32);
                    unsafe {
                        self.rt.DrawTextLayout(
                            origin,
                            &layout,
                            self.paint(c),
                            D2D1_DRAW_TEXT_OPTIONS_CLIP,
                        )
                    };
                }
            }
            Op::Logo(r, state) => self.logo(r, state),
            Op::Ring(r, radius, width, c) => unsafe {
                let half = width / 2.0;
                let mut box_ = rect(r);
                box_.left += half;
                box_.top += half;
                box_.right -= half;
                box_.bottom -= half;
                self.rt.DrawRoundedRectangle(
                    &rounded(box_, radius - half),
                    self.paint(c),
                    width,
                    None,
                )
            },
            Op::Clip(r) => unsafe {
                self.rt
                    .PushAxisAlignedClip(&rect(r), D2D1_ANTIALIAS_MODE_ALIASED)
            },
            Op::Unclip => unsafe { self.rt.PopAxisAlignedClip() },
        }
    }

    fn figure(&self, start: icons::Point, segs: &[Seg], closed: bool) -> Option<ID2D1PathGeometry> {
        self.path(D2D1_FIGURE_BEGIN_HOLLOW, start, segs, closed)
    }

    fn path(
        &self,
        begin: D2D1_FIGURE_BEGIN,
        start: icons::Point,
        segs: &[Seg],
        closed: bool,
    ) -> Option<ID2D1PathGeometry> {
        unsafe {
            let path = self.d2d.CreatePathGeometry().ok()?;
            let sink = path.Open().ok()?;
            sink.BeginFigure(point(start), begin);
            for seg in segs {
                match *seg {
                    Seg::Line(to) => sink.AddLine(point(to)),
                    Seg::Cubic { c1, c2, to } => sink.AddBezier(&D2D1_BEZIER_SEGMENT {
                        point1: point(c1),
                        point2: point(c2),
                        point3: point(to),
                    }),
                    Seg::Arc { to, r, sweep } => sink.AddArc(&D2D1_ARC_SEGMENT {
                        point: point(to),
                        size: D2D_SIZE_F {
                            width: r,
                            height: r,
                        },
                        rotationAngle: 0.0,
                        sweepDirection: if sweep > 0.0 {
                            D2D1_SWEEP_DIRECTION_CLOCKWISE
                        } else {
                            D2D1_SWEEP_DIRECTION_COUNTER_CLOCKWISE
                        },
                        arcSize: if sweep.abs() > 180.0 {
                            D2D1_ARC_SIZE_LARGE
                        } else {
                            D2D1_ARC_SIZE_SMALL
                        },
                    }),
                }
            }
            sink.EndFigure(if closed {
                D2D1_FIGURE_END_CLOSED
            } else {
                D2D1_FIGURE_END_OPEN
            });
            sink.Close().ok()?;
            Some(path)
        }
    }

    fn arch(&self, a: Arch, begin: D2D1_FIGURE_BEGIN) -> Option<ID2D1PathGeometry> {
        let segs = [
            Seg::Line((a.left, a.crown)),
            Seg::Arc {
                to: (a.right, a.crown),
                r: (a.right - a.left) / 2.0,
                sweep: 180.0,
            },
            Seg::Line((a.right, a.foot)),
        ];
        let closed = begin == D2D1_FIGURE_BEGIN_FILLED;
        self.path(begin, (a.left, a.foot), &segs, closed)
    }

    fn logo(&self, r: Rect, state: logo::State) {
        let m = logo::mark(r);
        let (x, y, w, h) = m.tile;
        unsafe {
            self.rt.FillRoundedRectangle(
                &rounded(rectf(x, y, w, h), m.radius),
                self.paint(logo::TILE),
            );
            if let Some(door) = self.arch(m.door, D2D1_FIGURE_BEGIN_FILLED) {
                self.rt.FillGeometry(&door, self.paint(logo::DOOR), None);
            }
            if let Some(arch) = self.arch(m.arch, D2D1_FIGURE_BEGIN_HOLLOW) {
                self.rt
                    .DrawGeometry(&arch, self.paint(logo::ARCH), m.stroke, self.round);
            }
            match state.eyes() {
                Some(c) => {
                    for eye in m.eyes {
                        self.rt
                            .FillEllipse(&ellipse((eye.cx, eye.cy), eye.rx, eye.ry), self.paint(c));
                    }
                }
                None => {
                    for (a, b) in m.lids {
                        self.rt.DrawLine(
                            Vector2::new(a.0, a.1),
                            Vector2::new(b.0, b.1),
                            self.paint(logo::DASH),
                            m.lid,
                            self.round,
                        );
                    }
                }
            }
            if state.badge() {
                let b = m.badge;
                let disc = ellipse((b.cx, b.cy), b.r, b.r);
                self.rt.FillEllipse(&disc, self.paint(logo::BADGE));
                self.rt
                    .DrawEllipse(&disc, self.paint(logo::BADGE_INK), b.ring, self.round);
                self.rt.DrawLine(
                    Vector2::new(b.bar.0.0, b.bar.0.1),
                    Vector2::new(b.bar.1.0, b.bar.1.1),
                    self.paint(logo::BADGE_INK),
                    b.bar_w,
                    self.round,
                );
                self.rt.FillEllipse(
                    &ellipse(b.dot, b.dot_r, b.dot_r),
                    self.paint(logo::BADGE_INK),
                );
            }
        }
    }

    fn icon(&self, icon: &Icon, target: Rect, width: f32, c: Rgb) {
        let brush = self.paint(c);
        for prim in icons::trace(icon, target, width) {
            unsafe {
                match prim {
                    Prim::RoundRect { x, y, w, h, r } => self.rt.DrawRoundedRectangle(
                        &rounded(rectf(x, y, w, h), r),
                        brush,
                        width,
                        self.round,
                    ),
                    Prim::Circle { cx, cy, r } => self.rt.DrawEllipse(
                        &D2D1_ELLIPSE {
                            point: Vector2::new(cx, cy),
                            radiusX: r,
                            radiusY: r,
                        },
                        brush,
                        width,
                        self.round,
                    ),
                    Prim::Figure {
                        start,
                        segs,
                        closed,
                    } => {
                        if let Some(path) = self.figure(start, &segs, closed) {
                            self.rt.DrawGeometry(&path, brush, width, self.round);
                        }
                    }
                }
            }
        }
    }
}

fn ellipse(center: (f32, f32), rx: f32, ry: f32) -> D2D1_ELLIPSE {
    D2D1_ELLIPSE {
        point: Vector2::new(center.0, center.1),
        radiusX: rx,
        radiusY: ry,
    }
}
