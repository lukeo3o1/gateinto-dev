use std::ptr::null_mut;

use windows_sys::Win32::Graphics::Gdi::HDC;
use windows_sys::Win32::Graphics::GdiPlus::{
    DashCapFlat, FillModeAlternate, GdipAddPathArc, GdipAddPathBezier, GdipAddPathEllipse,
    GdipAddPathLine, GdipAddPathRectangle, GdipClosePathFigure, GdipCreateFromHDC, GdipCreatePath,
    GdipCreatePen1, GdipCreateSolidFill, GdipDeleteBrush, GdipDeleteGraphics, GdipDeletePath,
    GdipDeletePen, GdipDrawPath, GdipFillPath, GdipSetPenLineCap197819, GdipSetPixelOffsetMode,
    GdipSetSmoothingMode, GdipStartPathFigure, GdiplusShutdown, GdiplusStartup,
    GdiplusStartupInput, GpGraphics, GpPath, GpPen, GpSolidFill, LineCapFlat, LineCapRound,
    PixelOffsetModeHalf, SmoothingModeAntiAlias, UnitPixel,
};

use crate::color::Rgb;
use crate::icons::{Cmd, Icon, Shape, Transform, arc_end};
use crate::layout::Rect;

pub struct Runtime(usize);

impl Runtime {
    pub fn start() -> Option<Self> {
        let input = GdiplusStartupInput {
            GdiplusVersion: 1,
            ..Default::default()
        };
        let mut token = 0;
        let status = unsafe { GdiplusStartup(&mut token, &input, null_mut()) };
        (status == 0).then_some(Self(token))
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        unsafe { GdiplusShutdown(self.0) };
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RectF {
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub h: f32,
}

impl From<Rect> for RectF {
    fn from(r: Rect) -> Self {
        Self {
            x: r.x as f32,
            y: r.y as f32,
            w: r.w as f32,
            h: r.h as f32,
        }
    }
}

impl RectF {
    pub fn inset(self, d: f32) -> Self {
        Self {
            x: self.x + d,
            y: self.y + d,
            w: self.w - 2.0 * d,
            h: self.h - 2.0 * d,
        }
    }
}

pub struct Path(*mut GpPath);

impl Path {
    fn new() -> Self {
        let mut path = null_mut();
        unsafe { GdipCreatePath(FillModeAlternate, &mut path) };
        Self(path)
    }

    pub fn round_rect(r: RectF, radius: f32) -> Self {
        let path = Self::new();
        let radius = radius.min(r.w / 2.0).min(r.h / 2.0);
        unsafe {
            if radius <= 0.0 {
                GdipAddPathRectangle(path.0, r.x, r.y, r.w, r.h);
            } else {
                let d = 2.0 * radius;
                GdipAddPathArc(path.0, r.x, r.y, d, d, 180.0, 90.0);
                GdipAddPathArc(path.0, r.x + r.w - d, r.y, d, d, 270.0, 90.0);
                GdipAddPathArc(path.0, r.x + r.w - d, r.y + r.h - d, d, d, 0.0, 90.0);
                GdipAddPathArc(path.0, r.x, r.y + r.h - d, d, d, 90.0, 90.0);
                GdipClosePathFigure(path.0);
            }
        }
        path
    }

    pub fn top_left_round(r: RectF, radius: f32) -> Self {
        let path = Self::new();
        let d = 2.0 * radius;
        unsafe {
            GdipAddPathArc(path.0, r.x, r.y, d, d, 180.0, 90.0);
            GdipAddPathLine(path.0, r.x + radius, r.y, r.x + r.w, r.y);
            GdipAddPathLine(path.0, r.x + r.w, r.y, r.x + r.w, r.y + r.h);
            GdipAddPathLine(path.0, r.x + r.w, r.y + r.h, r.x, r.y + r.h);
            GdipClosePathFigure(path.0);
        }
        path
    }

    fn shape(shape: &Shape, t: Transform) -> Self {
        let path = Self::new();
        unsafe {
            match *shape {
                Shape::RoundRect { x, y, w, h, r } => {
                    let (x, y) = t.point(x, y);
                    return Self::round_rect(
                        RectF {
                            x,
                            y,
                            w: t.len(w),
                            h: t.len(h),
                        },
                        t.len(r),
                    );
                }
                Shape::Circle { cx, cy, r } => {
                    let (x, y) = t.point(cx - r, cy - r);
                    GdipAddPathEllipse(path.0, x, y, t.len(2.0 * r), t.len(2.0 * r));
                }
                Shape::Path(cmds) => {
                    let mut at = (0.0, 0.0);
                    for cmd in cmds {
                        match *cmd {
                            Cmd::Move(x, y) => {
                                GdipStartPathFigure(path.0);
                                at = t.point(x, y);
                            }
                            Cmd::Line(x, y) => {
                                let to = t.point(x, y);
                                GdipAddPathLine(path.0, at.0, at.1, to.0, to.1);
                                at = to;
                            }
                            Cmd::Cubic(x1, y1, x2, y2, x, y) => {
                                let (c1, c2, to) =
                                    (t.point(x1, y1), t.point(x2, y2), t.point(x, y));
                                GdipAddPathBezier(
                                    path.0, at.0, at.1, c1.0, c1.1, c2.0, c2.1, to.0, to.1,
                                );
                                at = to;
                            }
                            Cmd::Arc {
                                cx,
                                cy,
                                r,
                                start,
                                sweep,
                            } => {
                                let (x, y) = t.point(cx - r, cy - r);
                                let d = t.len(2.0 * r);
                                GdipAddPathArc(path.0, x, y, d, d, start, sweep);
                                let (ex, ey) = arc_end(cx, cy, r, start, sweep);
                                at = t.point(ex, ey);
                            }
                            Cmd::Close => {
                                GdipClosePathFigure(path.0);
                            }
                        }
                    }
                }
            }
        }
        path
    }
}

impl Drop for Path {
    fn drop(&mut self) {
        unsafe { GdipDeletePath(self.0) };
    }
}

struct Brush(*mut GpSolidFill);

impl Brush {
    fn new(color: Rgb) -> Self {
        let mut brush = null_mut();
        unsafe { GdipCreateSolidFill(color.argb(), &mut brush) };
        Self(brush)
    }
}

impl Drop for Brush {
    fn drop(&mut self) {
        unsafe { GdipDeleteBrush(self.0.cast()) };
    }
}

struct Pen(*mut GpPen);

impl Pen {
    fn new(color: Rgb, width: f32, round: bool) -> Self {
        let mut pen = null_mut();
        unsafe {
            GdipCreatePen1(color.argb(), width, UnitPixel, &mut pen);
            if round {
                GdipSetPenLineCap197819(pen, LineCapRound, LineCapRound, DashCapFlat);
            } else {
                GdipSetPenLineCap197819(pen, LineCapFlat, LineCapFlat, DashCapFlat);
            }
        }
        Self(pen)
    }
}

impl Drop for Pen {
    fn drop(&mut self) {
        unsafe { GdipDeletePen(self.0) };
    }
}

pub struct Graphics(*mut GpGraphics);

impl Graphics {
    pub fn new(dc: HDC) -> Option<Self> {
        let mut g = null_mut();
        if unsafe { GdipCreateFromHDC(dc, &mut g) } != 0 || g.is_null() {
            return None;
        }
        unsafe {
            GdipSetSmoothingMode(g, SmoothingModeAntiAlias);
            GdipSetPixelOffsetMode(g, PixelOffsetModeHalf);
        }
        Some(Self(g))
    }

    pub fn fill(&self, path: &Path, color: Rgb) {
        let brush = Brush::new(color);
        unsafe { GdipFillPath(self.0, brush.0.cast(), path.0) };
    }

    pub fn stroke(&self, path: &Path, color: Rgb, width: f32) {
        let pen = Pen::new(color, width, false);
        unsafe { GdipDrawPath(self.0, pen.0, path.0) };
    }

    pub fn fill_round(&self, r: RectF, radius: f32, color: Rgb) {
        self.fill(&Path::round_rect(r, radius), color);
    }

    pub fn bordered_round(&self, r: RectF, radius: f32, border: f32, stroke: Rgb, fill: Rgb) {
        self.fill_round(r, radius, stroke);
        self.fill_round(r.inset(border), (radius - border).max(0.0), fill);
    }

    pub fn icon(&self, icon: &Icon, target: Rect, color: Rgb) {
        let t = Transform::fit(icon.view, target);
        let pen = Pen::new(color, t.len(icon.stroke), icon.round_caps);
        for shape in icon.shapes {
            let path = Path::shape(shape, t);
            unsafe { GdipDrawPath(self.0, pen.0, path.0) };
        }
    }
}

impl Drop for Graphics {
    fn drop(&mut self) {
        unsafe { GdipDeleteGraphics(self.0) };
    }
}
