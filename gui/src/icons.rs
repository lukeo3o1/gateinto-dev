use crate::layout::Rect;
use crate::nav::Page;

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
    Cubic(Point, Point, Point),
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
    Cubic { c1: Point, c2: Point, to: Point },
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

fn settle(v: f32) -> f32 {
    (v * 1024.0).round() / 1024.0
}

fn about(offset: f32, centre: f32) -> f32 {
    centre + settle(offset).round()
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

    fn exact(&self, (x, y): Point) -> Point {
        (
            self.centre.0 + self.t.len(x - self.mid),
            self.centre.1 + self.t.len(y - self.mid),
        )
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
            Cmd::Cubic(c1, c2, to) => (
                g.raw(to),
                Seg::Cubic {
                    c1: g.exact(c1),
                    c2: g.exact(c2),
                    to: g.snap(to),
                },
            ),
            Cmd::Close => {
                if let Some(figure) = current.as_mut() {
                    figure.2 = true;
                }
                continue;
            }
        };
        raw = to_raw;
        at = match seg {
            Seg::Line(p) | Seg::Arc { to: p, .. } | Seg::Cubic { to: p, .. } => p,
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

pub const GLOBE: Icon = Icon {
    view: RAIL,
    stroke: RAIL_STROKE,
    shapes: &[
        circle(12.0, 12.0, 8.5),
        Shape::Path(&line(3.5, 12.0, 20.5, 12.0)),
        Shape::Path(&[
            Cmd::Move(12.0, 3.5),
            Cmd::Cubic((14.6, 5.9), (15.8, 8.7), (15.8, 12.0)),
            Cmd::Cubic((15.8, 15.3), (14.6, 18.1), (12.0, 20.5)),
            Cmd::Cubic((9.4, 18.1), (8.2, 15.3), (8.2, 12.0)),
            Cmd::Cubic((8.2, 8.7), (9.4, 5.9), (12.0, 3.5)),
            Cmd::Close,
        ]),
    ],
};

pub const POWER: Icon = Icon {
    view: RAIL,
    stroke: RAIL_STROKE,
    shapes: &[
        Shape::Path(&line(12.0, 3.5, 12.0, 11.5)),
        Shape::Path(&[
            Cmd::Move(7.2, 6.4),
            Cmd::Arc {
                cx: 12.0,
                cy: 12.163,
                r: 7.5,
                start: 230.209,
                sweep: -280.418,
            },
        ]),
    ],
};

pub const STOP: Icon = Icon {
    view: RAIL,
    stroke: RAIL_STROKE,
    shapes: &[rect(6.5, 6.5, 11.0, 11.0, 2.0)],
};

pub const LOCK: Icon = Icon {
    view: RAIL,
    stroke: RAIL_STROKE,
    shapes: &[
        rect(5.0, 10.5, 14.0, 10.0, 2.0),
        Shape::Path(&[
            Cmd::Move(8.5, 10.5),
            Cmd::Line(8.5, 8.0),
            Cmd::Arc {
                cx: 12.0,
                cy: 8.0,
                r: 3.5,
                start: 180.0,
                sweep: 180.0,
            },
            Cmd::Line(15.5, 10.5),
        ]),
    ],
};

pub const PLUS: Icon = Icon {
    view: RAIL,
    stroke: 2.0,
    shapes: &[
        Shape::Path(&line(12.0, 5.0, 12.0, 19.0)),
        Shape::Path(&line(5.0, 12.0, 19.0, 12.0)),
    ],
};

pub const MORE: Icon = Icon {
    view: RAIL,
    stroke: RAIL_STROKE,
    shapes: &[
        circle(5.5, 12.0, 0.6),
        circle(12.0, 12.0, 0.6),
        circle(18.5, 12.0, 0.6),
    ],
};

pub const EXTERNAL: Icon = Icon {
    view: RAIL,
    stroke: RAIL_STROKE,
    shapes: &[
        Shape::Path(&[
            Cmd::Move(13.5, 4.5),
            Cmd::Line(19.5, 4.5),
            Cmd::Line(19.5, 10.5),
        ]),
        Shape::Path(&line(19.5, 4.5, 11.5, 12.5)),
        Shape::Path(&[
            Cmd::Move(17.5, 14.0),
            Cmd::Line(17.5, 18.5),
            Cmd::Arc {
                cx: 16.0,
                cy: 18.5,
                r: 1.5,
                start: 0.0,
                sweep: 90.0,
            },
            Cmd::Line(6.0, 20.0),
            Cmd::Arc {
                cx: 6.0,
                cy: 18.5,
                r: 1.5,
                start: 90.0,
                sweep: 90.0,
            },
            Cmd::Line(4.5, 8.0),
            Cmd::Arc {
                cx: 6.0,
                cy: 8.0,
                r: 1.5,
                start: 180.0,
                sweep: 90.0,
            },
            Cmd::Line(10.5, 6.5),
        ]),
    ],
};

pub fn rail_icon(page: Page) -> Icon {
    match page {
        Page::Sessions => SESSIONS,
        Page::Gateways => GATEWAYS,
        Page::Device => DEVICE,
        Page::Log => LOG,
        Page::Settings => SETTINGS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Icon; 16] = [
        SESSIONS, GATEWAYS, DEVICE, LOG, SETTINGS, MINIMIZE, MAXIMIZE, RESTORE, CLOSE, GLOBE,
        POWER, STOP, LOCK, PLUS, MORE, EXTERNAL,
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
    fn offsets_within_float_noise_of_a_half_round_alike() {
        assert_eq!(about(-3.4998, 0.5), -3.5);
        assert_eq!(about(-3.500_000_2, 0.5), -3.5);
        assert_eq!(about(3.4998, 0.5), 4.5);
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
    fn cubic_controls_keep_their_exact_offset_from_the_snapped_centre() {
        let prims = trace(&GLOBE, Rect::new(0, 0, 24, 24), 1.0);
        let Prim::Figure {
            start,
            segs,
            closed,
        } = &prims[2]
        else {
            panic!("expected the meridian");
        };
        assert_eq!(*start, (12.5, 3.5));
        assert!(*closed);
        let Seg::Cubic { c1, c2, to } = segs[0] else {
            panic!("expected a cubic");
        };
        let near = |a: Point, b: Point| (a.0 - b.0).abs() < 1e-4 && (a.1 - b.1).abs() < 1e-4;
        assert!(near(c1, (15.1, 6.4)), "{c1:?}");
        assert!(near(c2, (16.3, 9.2)), "{c2:?}");
        assert_eq!(to, (16.5, 12.5));
    }

    #[test]
    fn the_power_arc_runs_counter_clockwise_around_the_bottom() {
        let prims = trace(&POWER, Rect::new(0, 0, 24, 24), 1.0);
        let Prim::Figure { start, segs, .. } = &prims[1] else {
            panic!("expected the ring");
        };
        assert_eq!(*start, (7.5, 6.5));
        let Seg::Arc { to, sweep, .. } = segs[0] else {
            panic!("expected an arc");
        };
        assert_eq!(to, (17.5, 6.5));
        assert!(sweep < -180.0);
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
                        Seg::Line(p) | Seg::Arc { to: p, .. } | Seg::Cubic { to: p, .. } => p,
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
        for icon in [
            GATEWAYS, DEVICE, MINIMIZE, MAXIMIZE, CLOSE, GLOBE, POWER, STOP, LOCK, PLUS, MORE,
        ] {
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
    fn the_more_icon_is_three_dots_in_a_row() {
        let prims = trace(&MORE, Rect::new(0, 0, 24, 24), 1.0);
        let dot = |cx| Prim::Circle {
            cx,
            cy: 12.5,
            r: 1.0,
        };
        assert_eq!(prims, [dot(5.5), dot(12.5), dot(19.5)]);
    }

    #[test]
    fn rail_icons_follow_the_page() {
        assert_eq!(rail_icon(Page::Sessions), SESSIONS);
        assert_eq!(rail_icon(Page::Gateways), GATEWAYS);
        assert_eq!(rail_icon(Page::Device), DEVICE);
        assert_eq!(rail_icon(Page::Log), LOG);
        assert_eq!(rail_icon(Page::Settings), SETTINGS);
    }
}
