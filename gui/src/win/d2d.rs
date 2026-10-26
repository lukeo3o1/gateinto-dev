use std::cell::RefCell;

use windows::Win32::Foundation::{D2DERR_RECREATE_TARGET, RECT};
use windows::Win32::Graphics::Direct2D::Common::{
    D2D_RECT_F, D2D_SIZE_F, D2D1_ALPHA_MODE_IGNORE, D2D1_BEZIER_SEGMENT, D2D1_COLOR_F,
    D2D1_FIGURE_BEGIN_FILLED, D2D1_FIGURE_BEGIN_HOLLOW, D2D1_FIGURE_END_CLOSED,
    D2D1_FIGURE_END_OPEN, D2D1_PIXEL_FORMAT,
};
use windows::Win32::Graphics::Direct2D::{
    D2D1_ARC_SEGMENT, D2D1_ARC_SIZE_LARGE, D2D1_ARC_SIZE_SMALL, D2D1_CAP_STYLE_ROUND,
    D2D1_DRAW_TEXT_OPTIONS_CLIP, D2D1_DRAW_TEXT_OPTIONS_NONE, D2D1_ELLIPSE,
    D2D1_FACTORY_TYPE_SINGLE_THREADED, D2D1_FEATURE_LEVEL_DEFAULT, D2D1_LINE_JOIN_ROUND,
    D2D1_RENDER_TARGET_PROPERTIES, D2D1_RENDER_TARGET_TYPE_DEFAULT, D2D1_RENDER_TARGET_USAGE_NONE,
    D2D1_ROUNDED_RECT, D2D1_STROKE_STYLE_PROPERTIES, D2D1_SWEEP_DIRECTION_CLOCKWISE,
    D2D1_SWEEP_DIRECTION_COUNTER_CLOCKWISE, D2D1_TEXT_ANTIALIAS_MODE,
    D2D1_TEXT_ANTIALIAS_MODE_CLEARTYPE, D2D1_TEXT_ANTIALIAS_MODE_GRAYSCALE, D2D1CreateFactory,
    ID2D1Brush, ID2D1DCRenderTarget, ID2D1Factory, ID2D1GeometrySink, ID2D1PathGeometry,
    ID2D1SolidColorBrush, ID2D1StrokeStyle,
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

use super::text::{Align, Fonts};
use crate::color::Rgb;
use crate::geom::{self, RectF};
use crate::icons::{self, Icon, Prim, Seg};
use crate::layout::{Font, Rect};

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
    let [r, g, b, a] = geom::channels(c);
    D2D1_COLOR_F { r, g, b, a }
}

fn point((x, y): icons::Point) -> Vector2 {
    Vector2::new(x, y)
}

fn rect(r: RectF) -> D2D_RECT_F {
    D2D_RECT_F {
        left: r.x,
        top: r.y,
        right: r.right(),
        bottom: r.bottom(),
    }
}

fn rounded(r: RectF, radius: f32) -> D2D1_ROUNDED_RECT {
    D2D1_ROUNDED_RECT {
        rect: rect(r),
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
        paint: impl FnOnce(&Canvas),
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
        paint(&Canvas {
            d2d: &self.d2d,
            rt: &target.rt,
            brush: &target.brush,
            round: &self.round,
        });
        let ended = unsafe { target.rt.EndDraw(None, None) };
        if ended.is_err_and(|e| e.code() == D2DERR_RECREATE_TARGET) {
            *slot = None;
            return false;
        }
        true
    }
}

pub struct Canvas<'a> {
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

    fn path(&self, build: impl FnOnce(&ID2D1GeometrySink)) -> Option<ID2D1PathGeometry> {
        unsafe {
            let path = self.d2d.CreatePathGeometry().ok()?;
            let sink = path.Open().ok()?;
            build(&sink);
            sink.Close().ok()?;
            Some(path)
        }
    }

    pub fn fill_rect(&self, r: Rect, c: Rgb) {
        unsafe { self.rt.FillRectangle(&rect(r.into()), self.paint(c)) };
    }

    pub fn fill_round(&self, r: Rect, radius: f32, c: Rgb) {
        let rr = rounded(r.into(), radius.max(0.0));
        unsafe { self.rt.FillRoundedRectangle(&rr, self.paint(c)) };
    }

    pub fn stroke_round(&self, edge: Rect, radius: f32, width: f32, c: Rgb) {
        let (r, radius) = geom::border(edge, radius, width);
        unsafe {
            self.rt
                .DrawRoundedRectangle(&rounded(r, radius), self.paint(c), width, self.round)
        };
    }

    pub fn bordered_round(&self, edge: Rect, radius: f32, width: f32, border: Rgb, fill: Rgb) {
        let (r, inner) = geom::border(edge, radius, width);
        unsafe {
            self.rt
                .FillRoundedRectangle(&rounded(r, inner), self.paint(fill))
        };
        self.stroke_round(edge, radius, width, border);
    }

    pub fn fill_top_left_round(&self, r: RectF, radius: f32, c: Rgb) {
        let path = self.path(|sink| unsafe {
            sink.BeginFigure(Vector2::new(r.x, r.y + radius), D2D1_FIGURE_BEGIN_FILLED);
            sink.AddArc(&D2D1_ARC_SEGMENT {
                point: Vector2::new(r.x + radius, r.y),
                size: D2D_SIZE_F {
                    width: radius,
                    height: radius,
                },
                rotationAngle: 0.0,
                sweepDirection: D2D1_SWEEP_DIRECTION_CLOCKWISE,
                arcSize: D2D1_ARC_SIZE_SMALL,
            });
            sink.AddLine(Vector2::new(r.right(), r.y));
            sink.AddLine(Vector2::new(r.right(), r.bottom()));
            sink.AddLine(Vector2::new(r.x, r.bottom()));
            sink.EndFigure(D2D1_FIGURE_END_CLOSED);
        });
        if let Some(path) = path {
            unsafe {
                self.rt
                    .FillGeometry(&path, self.paint(c), None::<&ID2D1Brush>)
            };
        }
    }

    fn figure(&self, start: icons::Point, segs: &[Seg], closed: bool) -> Option<ID2D1PathGeometry> {
        self.path(|sink| unsafe {
            sink.BeginFigure(point(start), D2D1_FIGURE_BEGIN_HOLLOW);
            for seg in segs {
                match *seg {
                    Seg::Line(to) => sink.AddLine(point(to)),
                    Seg::Cubic(c1, c2, to) => sink.AddBezier(&D2D1_BEZIER_SEGMENT {
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
        })
    }

    pub fn icon(&self, icon: &Icon, target: Rect, width: f32, c: Rgb) {
        let brush = self.paint(c);
        for prim in icons::trace(icon, target, width) {
            unsafe {
                match prim {
                    Prim::RoundRect { x, y, w, h, r } => self.rt.DrawRoundedRectangle(
                        &rounded(RectF { x, y, w, h }, r),
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

    pub fn text(&self, fonts: &Fonts, font: Font, s: &str, r: Rect, c: Rgb, align: Align) {
        let Some(layout) = fonts.layout(font, s, r.w as f32, r.h as f32, align) else {
            return;
        };
        let options = if align.ellipsis {
            D2D1_DRAW_TEXT_OPTIONS_CLIP
        } else {
            D2D1_DRAW_TEXT_OPTIONS_NONE
        };
        let origin = Vector2::new(r.x as f32, r.y as f32);
        unsafe {
            self.rt
                .DrawTextLayout(origin, &layout, self.paint(c), options)
        };
    }
}
