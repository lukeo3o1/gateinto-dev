use crate::layout::Rect;
use crate::nav::{KeyKind, Page};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Cmd {
    Move(f32, f32),
    Line(f32, f32),
    Arc {
        cx: f32,
        cy: f32,
        r: f32,
        start: f32,
        sweep: f32,
    },
    Close,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Shape {
    RoundRect {
        x: f32,
        y: f32,
        w: f32,
        h: f32,
        r: f32,
    },
    Circle {
        cx: f32,
        cy: f32,
        r: f32,
    },
    Path(&'static [Cmd]),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Icon {
    pub view: f32,
    pub stroke: f32,
    pub shapes: &'static [Shape],
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Transform {
    pub x: f32,
    pub y: f32,
    pub k: f32,
}

impl Transform {
    pub fn fit(view: f32, target: Rect) -> Self {
        Self {
            x: target.x as f32,
            y: target.y as f32,
            k: target.w as f32 / view,
        }
    }

    pub fn point(self, x: f32, y: f32) -> (f32, f32) {
        (self.x + x * self.k, self.y + y * self.k)
    }

    pub fn len(self, v: f32) -> f32 {
        v * self.k
    }
}

pub type Point = (f32, f32);

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Seg {
    Line(Point),
    Arc { to: Point, r: f32, sweep: f32 },
}

#[derive(Clone, Debug, PartialEq)]
pub enum Prim {
    RoundRect {
        x: f32,
        y: f32,
        w: f32,
        h: f32,
        r: f32,
    },
    Circle {
        cx: f32,
        cy: f32,
        r: f32,
    },
    Figure {
        start: Point,
        segs: Vec<Seg>,
        closed: bool,
    },
}

pub fn snap(v: f32, width: f32) -> f32 {
    if width.round() as i64 % 2 == 1 {
        (v - 0.5).round() + 0.5
    } else {
        v.round()
    }
}

fn about(offset: f32, centre: f32) -> f32 {
    centre + offset.round()
}

struct Grid {
    t: Transform,
    mid: f32,
    centre: Point,
}

impl Grid {
    fn new(icon: &Icon, target: Rect, width: f32) -> Self {
        let t = Transform::fit(icon.view, target);
        let mid = icon.view / 2.0;
        let (x, y) = t.point(mid, mid);
        Self {
            t,
            mid,
            centre: (snap(x, width), snap(y, width)),
        }
    }

    fn raw(&self, (x, y): Point) -> Point {
        self.t.point(x, y)
    }

    fn snap(&self, (x, y): Point) -> Point {
        (
            about(self.t.len(x - self.mid), self.centre.0),
            about(self.t.len(y - self.mid), self.centre.1),
        )
    }
}

fn distance(a: Point, b: Point) -> f32 {
    (a.0 - b.0).hypot(a.1 - b.1)
}

fn figures(cmds: &[Cmd], g: &Grid, out: &mut Vec<Prim>) {
    let mut current: Option<(Point, Vec<Seg>, bool)> = None;
    let (mut raw, mut at) = ((0.0, 0.0), (0.0, 0.0));
    let flush = |current: Option<(Point, Vec<Seg>, bool)>, out: &mut Vec<Prim>| {
        out.extend(current.map(|(start, segs, closed)| Prim::Figure {
            start,
            segs,
            closed,
        }))
    };
    for cmd in cmds {
        let (to_raw, seg) = match *cmd {
            Cmd::Move(x, y) => {
                flush(current.take(), out);
                raw = g.raw((x, y));
                at = g.snap((x, y));
                current = Some((at, Vec::new(), false));
                continue;
            }
            Cmd::Line(x, y) => (g.raw((x, y)), Seg::Line(g.snap((x, y)))),
            Cmd::Arc {
                cx,
                cy,
                r,
                start,
                sweep,
            } => {
                let end = arc_end(cx, cy, r, start, sweep);
                let (to_raw, to) = (g.raw(end), g.snap(end));
                let chord = distance(raw, to_raw);
                let scale = if chord > 0.0 {
                    distance(at, to) / chord
                } else {
                    1.0
                };
                let r = g.t.len(r) * scale;
                (to_raw, Seg::Arc { to, r, sweep })
            }
            Cmd::Close => {
                if let Some(figure) = current.as_mut() {
                    figure.2 = true;
                }
                continue;
            }
        };
        raw = to_raw;
        at = match seg {
            Seg::Line(p) | Seg::Arc { to: p, .. } => p,
        };
        if let Some(figure) = current.as_mut() {
            figure.1.push(seg);
        }
    }
    flush(current, out);
}

pub fn trace(icon: &Icon, target: Rect, width: f32) -> Vec<Prim> {
    let g = Grid::new(icon, target, width);
    let mut out = Vec::new();
    for shape in icon.shapes {
        match *shape {
            Shape::RoundRect { x, y, w, h, r } => {
                let (x0, y0) = g.snap((x, y));
                let (x1, y1) = g.snap((x + w, y + h));
                out.push(Prim::RoundRect {
                    x: x0,
                    y: y0,
                    w: x1 - x0,
                    h: y1 - y0,
                    r: g.t.len(r),
                });
            }
            Shape::Circle { cx, cy, r } => {
                let (cx, cy) = g.snap((cx, cy));
                out.push(Prim::Circle {
                    cx,
                    cy,
                    r: g.t.len(r).round().max(1.0),
                });
            }
            Shape::Path(cmds) => figures(cmds, &g, &mut out),
        }
    }
    out
}

pub fn arc_end(cx: f32, cy: f32, r: f32, start: f32, sweep: f32) -> (f32, f32) {
    let a = (start + sweep).to_radians();
    let settle = |v: f32| (v * 1024.0).round() / 1024.0;
    (settle(cx + r * a.cos()), settle(cy + r * a.sin()))
}

const fn line(x1: f32, y1: f32, x2: f32, y2: f32) -> [Cmd; 2] {
    [Cmd::Move(x1, y1), Cmd::Line(x2, y2)]
}

const fn rect(x: f32, y: f32, w: f32, h: f32, r: f32) -> Shape {
    Shape::RoundRect { x, y, w, h, r }
}

const fn circle(cx: f32, cy: f32, r: f32) -> Shape {
    Shape::Circle { cx, cy, r }
}

const RAIL: f32 = 24.0;
const RAIL_STROKE: f32 = 1.6;
const CAPTION: f32 = 10.0;
const CAPTION_STROKE: f32 = 1.0;

pub const SESSIONS: Icon = Icon {
    view: RAIL,
    stroke: RAIL_STROKE,
    shapes: &[
        rect(3.0, 5.0, 18.0, 14.0, 2.5),
        Shape::Path(&line(3.0, 9.5, 21.0, 9.5)),
        circle(6.0, 7.2, 0.4),
    ],
};

pub const GATEWAYS: Icon = Icon {
    view: RAIL,
    stroke: RAIL_STROKE,
    shapes: &[
        Shape::Path(&[
            Cmd::Move(6.5, 20.0),
            Cmd::Line(6.5, 11.5),
            Cmd::Arc {
                cx: 12.0,
                cy: 11.5,
                r: 5.5,
                start: 180.0,
                sweep: 180.0,
            },
            Cmd::Line(17.5, 20.0),
        ]),
        Shape::Path(&line(3.5, 20.0, 20.5, 20.0)),
    ],
};

pub const DEVICE: Icon = Icon {
    view: RAIL,
    stroke: RAIL_STROKE,
    shapes: &[
        rect(3.0, 4.5, 18.0, 12.0, 2.0),
        Shape::Path(&line(8.5, 20.0, 15.5, 20.0)),
        Shape::Path(&line(12.0, 16.5, 12.0, 20.0)),
    ],
};

pub const CHIP: Icon = Icon {
    view: RAIL,
    stroke: RAIL_STROKE,
    shapes: &[
        rect(6.5, 6.5, 11.0, 11.0, 2.0),
        rect(9.5, 9.5, 5.0, 5.0, 1.0),
        Shape::Path(&line(9.5, 3.5, 9.5, 6.5)),
        Shape::Path(&line(14.5, 3.5, 14.5, 6.5)),
        Shape::Path(&line(9.5, 17.5, 9.5, 20.5)),
        Shape::Path(&line(14.5, 17.5, 14.5, 20.5)),
        Shape::Path(&line(3.5, 9.5, 6.5, 9.5)),
        Shape::Path(&line(3.5, 14.5, 6.5, 14.5)),
        Shape::Path(&line(17.5, 9.5, 20.5, 9.5)),
        Shape::Path(&line(17.5, 14.5, 20.5, 14.5)),
    ],
};

pub const KEYFILE: Icon = Icon {
    view: RAIL,
    stroke: RAIL_STROKE,
    shapes: &[
        Shape::Path(&[
            Cmd::Move(6.0, 3.5),
            Cmd::Line(14.0, 3.5),
            Cmd::Line(18.0, 7.5),
            Cmd::Line(18.0, 20.5),
            Cmd::Line(6.0, 20.5),
            Cmd::Close,
        ]),
        Shape::Path(&[
            Cmd::Move(14.0, 3.5),
            Cmd::Line(14.0, 7.5),
            Cmd::Line(18.0, 7.5),
        ]),
        circle(10.0, 14.5, 2.0),
        Shape::Path(&line(12.0, 14.5, 16.0, 14.5)),
        Shape::Path(&line(14.5, 14.5, 14.5, 16.5)),
    ],
};

pub const LOG: Icon = Icon {
    view: RAIL,
    stroke: RAIL_STROKE,
    shapes: &[
        Shape::Path(&[
            Cmd::Move(6.0, 4.0),
            Cmd::Line(15.0, 4.0),
            Cmd::Line(18.0, 7.0),
            Cmd::Line(18.0, 20.0),
            Cmd::Line(6.0, 20.0),
            Cmd::Close,
        ]),
        Shape::Path(&line(9.0, 11.0, 15.0, 11.0)),
        Shape::Path(&line(9.0, 14.5, 15.0, 14.5)),
        Shape::Path(&line(9.0, 18.0, 12.5, 18.0)),
    ],
};

pub const SETTINGS: Icon = Icon {
    view: RAIL,
    stroke: RAIL_STROKE,
    shapes: &[
        Shape::Path(&line(4.0, 7.5, 13.0, 7.5)),
        Shape::Path(&line(17.0, 7.5, 20.0, 7.5)),
        Shape::Path(&line(4.0, 16.5, 7.0, 16.5)),
        Shape::Path(&line(11.0, 16.5, 20.0, 16.5)),
        circle(15.0, 7.5, 2.0),
        circle(9.0, 16.5, 2.0),
    ],
};

pub const MINIMIZE: Icon = Icon {
    view: CAPTION,
    stroke: CAPTION_STROKE,
    shapes: &[Shape::Path(&line(0.0, 5.0, 10.0, 5.0))],
};

pub const MAXIMIZE: Icon = Icon {
    view: CAPTION,
    stroke: CAPTION_STROKE,
    shapes: &[rect(0.5, 0.5, 9.0, 9.0, 1.5)],
};

pub const RESTORE: Icon = Icon {
    view: CAPTION,
    stroke: CAPTION_STROKE,
    shapes: &[
        rect(0.5, 2.5, 7.0, 7.0, 1.5),
        Shape::Path(&[
            Cmd::Move(2.5, 0.5),
            Cmd::Line(8.0, 0.5),
            Cmd::Arc {
                cx: 8.0,
                cy: 2.0,
                r: 1.5,
                start: 270.0,
                sweep: 90.0,
            },
            Cmd::Line(9.5, 7.5),
        ]),
    ],
};

pub const CLOSE: Icon = Icon {
    view: CAPTION,
    stroke: CAPTION_STROKE,
    shapes: &[
        Shape::Path(&line(0.0, 0.0, 10.0, 10.0)),
        Shape::Path(&line(10.0, 0.0, 0.0, 10.0)),
    ],
};

pub fn rail_icon(page: Page, key: Option<KeyKind>) -> Icon {
    match (page, key) {
        (Page::Sessions, _) => SESSIONS,
        (Page::Gateways, _) => GATEWAYS,
        (Page::Device, None) => DEVICE,
        (Page::Device, Some(KeyKind::Hardware)) => CHIP,
        (Page::Device, Some(KeyKind::Software)) => KEYFILE,
        (Page::Log, _) => LOG,
        (Page::Settings, _) => SETTINGS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Icon; 11] = [
        SESSIONS, GATEWAYS, DEVICE, CHIP, KEYFILE, LOG, SETTINGS, MINIMIZE, MAXIMIZE, RESTORE,
        CLOSE,
    ];

    #[test]
    fn maps_the_view_box_onto_the_target_rect() {
        let t = Transform::fit(24.0, Rect::new(10, 20, 18, 18));
        assert_eq!(t.point(0.0, 0.0), (10.0, 20.0));
        assert_eq!(t.point(12.0, 24.0), (19.0, 38.0));
        assert_eq!(t.len(1.6), 1.2);
    }

    #[test]
    fn arc_end_follows_clockwise_degrees_in_y_down_space() {
        let (x, y) = arc_end(12.0, 7.0, 4.0, 180.0, 180.0);
        assert!((x - 16.0).abs() < 1e-4 && (y - 7.0).abs() < 1e-4);
        let (x, y) = arc_end(0.0, 0.0, 2.0, 0.0, 90.0);
        assert!(x.abs() < 1e-4 && (y - 2.0).abs() < 1e-4);
    }

    #[test]
    fn odd_strokes_snap_to_pixel_centres() {
        assert_eq!(snap(6.0, 1.0), 6.5);
        assert_eq!(snap(6.75, 1.0), 6.5);
        assert_eq!(snap(7.2, 1.0), 7.5);
        assert_eq!(snap(6.4, 3.0), 6.5);
    }

    #[test]
    fn even_strokes_snap_to_pixel_edges() {
        assert_eq!(snap(6.75, 2.0), 7.0);
        assert_eq!(snap(6.2, 2.0), 6.0);
    }

    #[test]
    fn offsets_from_the_centre_round_by_magnitude() {
        assert_eq!(about(-5.25, 29.5), 24.5);
        assert_eq!(about(5.25, 29.5), 34.5);
        assert_eq!(about(-2.5, 29.5), 26.5);
        assert_eq!(about(2.5, 29.5), 32.5);
        assert_eq!(about(0.0, 29.5), 29.5);
    }

    #[test]
    fn traces_rects_lines_and_dots_on_the_pixel_grid() {
        let prims = trace(&SESSIONS, Rect::new(0, 0, 24, 24), 1.0);
        assert_eq!(
            prims,
            [
                Prim::RoundRect {
                    x: 3.5,
                    y: 5.5,
                    w: 18.0,
                    h: 14.0,
                    r: 2.5
                },
                Prim::Figure {
                    start: (3.5, 9.5),
                    segs: vec![Seg::Line((21.5, 9.5))],
                    closed: false,
                },
                Prim::Circle {
                    cx: 6.5,
                    cy: 7.5,
                    r: 1.0
                },
            ]
        );
    }

    #[test]
    fn arcs_end_on_snapped_points_with_the_radius_following_the_chord() {
        let prims = trace(&GATEWAYS, Rect::new(0, 0, 20, 20), 1.0);
        assert_eq!(
            prims[0],
            Prim::Figure {
                start: (5.5, 17.5),
                segs: vec![
                    Seg::Line((5.5, 10.5)),
                    Seg::Arc {
                        to: (15.5, 10.5),
                        r: 5.0,
                        sweep: 180.0
                    },
                    Seg::Line((15.5, 17.5)),
                ],
                closed: false,
            }
        );
    }

    #[test]
    fn closed_paths_stay_closed() {
        let prims = trace(&LOG, Rect::new(0, 0, 24, 24), 1.0);
        let Prim::Figure { closed, segs, .. } = &prims[0] else {
            panic!("expected the page outline");
        };
        assert!(*closed);
        assert_eq!(segs.len(), 4);
    }

    fn anchors(prims: &[Prim]) -> Vec<Point> {
        let mut points = Vec::new();
        for prim in prims {
            match prim {
                Prim::RoundRect { x, y, w, h, .. } => {
                    points.extend([(*x, *y), (x + w, *y), (*x, y + h), (x + w, y + h)])
                }
                Prim::Circle { cx, cy, .. } => points.push((*cx, *cy)),
                Prim::Figure { start, segs, .. } => {
                    points.push(*start);
                    points.extend(segs.iter().map(|seg| match *seg {
                        Seg::Line(p) | Seg::Arc { to: p, .. } => p,
                    }));
                }
            }
        }
        points
    }

    #[test]
    fn every_anchor_sits_on_a_pixel_centre_for_odd_strokes() {
        let half = |v: f32| (v - v.floor() - 0.5).abs() < 1e-4;
        for icon in ALL {
            for size in [10, 15, 20, 25, 30, 40] {
                for prim in trace(&icon, Rect::new(3, 7, size, size), 1.0) {
                    if let Prim::Circle { r, .. } = prim {
                        assert_eq!(r, r.round());
                    }
                    for (x, y) in anchors(&[prim]) {
                        assert!(half(x) && half(y), "{x},{y} at {size}px");
                    }
                }
            }
        }
    }

    fn sorted(points: Vec<Point>) -> Vec<(i64, i64)> {
        let mut keys: Vec<_> = points
            .into_iter()
            .map(|(x, y)| ((x * 1000.0).round() as i64, (y * 1000.0).round() as i64))
            .collect();
        keys.sort_unstable();
        keys
    }

    #[test]
    fn mirror_symmetric_icons_trace_symmetrically_about_the_snapped_axis() {
        for icon in [GATEWAYS, DEVICE, CHIP, MINIMIZE, MAXIMIZE, CLOSE] {
            for size in [10, 15, 20, 25, 30, 40] {
                for width in [1.0, 2.0, 3.0] {
                    let target = Rect::new(3, 7, size, size);
                    let axis = snap(target.x as f32 + target.w as f32 / 2.0, width);
                    let points = anchors(&trace(&icon, target, width));
                    let mirrored = points.iter().map(|&(x, y)| (2.0 * axis - x, y)).collect();
                    assert_eq!(
                        sorted(points),
                        sorted(mirrored),
                        "{icon:?} at {size}px width {width}"
                    );
                }
            }
        }
    }

    #[test]
    fn rail_icons_follow_the_page_and_the_device_key() {
        assert_eq!(rail_icon(Page::Sessions, None), SESSIONS);
        assert_eq!(rail_icon(Page::Gateways, Some(KeyKind::Hardware)), GATEWAYS);
        assert_eq!(rail_icon(Page::Log, None), LOG);
        assert_eq!(rail_icon(Page::Settings, None), SETTINGS);
        assert_eq!(rail_icon(Page::Device, None), DEVICE);
        assert_eq!(rail_icon(Page::Device, Some(KeyKind::Hardware)), CHIP);
        assert_eq!(rail_icon(Page::Device, Some(KeyKind::Software)), KEYFILE);
    }
}
