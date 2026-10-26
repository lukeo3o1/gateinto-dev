use crate::layout::Rect;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Cmd {
    Move(f32, f32),
    Line(f32, f32),
    Cubic(f32, f32, f32, f32, f32, f32),
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
    pub glyph: char,
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

pub const STROKE: f32 = 1.4;

pub type Point = (f32, f32);

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Seg {
    Line(Point),
    Cubic(Point, Point, Point),
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

    fn shift(&self, p: Point, from: Point, to: Point) -> Point {
        let (x, y) = self.raw(p);
        (x + to.0 - from.0, y + to.1 - from.1)
    }
}

fn distance(a: Point, b: Point) -> f32 {
    (a.0 - b.0).hypot(a.1 - b.1)
}

fn figures(cmds: &[Cmd], g: &Grid, out: &mut Vec<Prim>) {
    let mut current: Option<(Point, Vec<Seg>, bool)> = None;
    let (mut raw, mut at) = ((0.0, 0.0), (0.0, 0.0));
    for cmd in cmds {
        let (next_raw, seg) = match *cmd {
            Cmd::Move(x, y) => {
                out.extend(current.take().map(|(start, segs, closed)| Prim::Figure {
                    start,
                    segs,
                    closed,
                }));
                raw = g.raw((x, y));
                at = g.snap((x, y));
                current = Some((at, Vec::new(), false));
                continue;
            }
            Cmd::Line(x, y) => (g.raw((x, y)), Seg::Line(g.snap((x, y)))),
            Cmd::Cubic(x1, y1, x2, y2, x, y) => {
                let to = g.snap((x, y));
                let to_raw = g.raw((x, y));
                let c1 = g.shift((x1, y1), raw, at);
                let c2 = g.shift((x2, y2), to_raw, to);
                (to_raw, Seg::Cubic(c1, c2, to))
            }
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
        raw = next_raw;
        at = match seg {
            Seg::Line(p) | Seg::Cubic(_, _, p) | Seg::Arc { to: p, .. } => p,
        };
        if let Some(figure) = current.as_mut() {
            figure.1.push(seg);
        }
    }
    out.extend(current.map(|(start, segs, closed)| Prim::Figure {
        start,
        segs,
        closed,
    }));
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

pub const SESSIONS: Icon = Icon {
    view: 24.0,
    glyph: '\u{E737}',
    shapes: &[
        Shape::RoundRect {
            x: 3.0,
            y: 4.0,
            w: 18.0,
            h: 14.0,
            r: 2.0,
        },
        Shape::Path(&line(3.0, 9.0, 21.0, 9.0)),
        Shape::Path(&line(8.0, 21.0, 16.0, 21.0)),
    ],
};

pub const GATEWAYS: Icon = Icon {
    view: 24.0,
    glyph: '\u{E774}',
    shapes: &[
        Shape::Circle {
            cx: 12.0,
            cy: 12.0,
            r: 9.0,
        },
        Shape::Path(&line(3.0, 12.0, 21.0, 12.0)),
        Shape::Path(&[
            Cmd::Move(12.0, 3.0),
            Cmd::Cubic(15.0, 6.5, 15.0, 17.5, 12.0, 21.0),
        ]),
        Shape::Path(&[
            Cmd::Move(12.0, 3.0),
            Cmd::Cubic(9.0, 6.5, 9.0, 17.5, 12.0, 21.0),
        ]),
    ],
};

pub const IDENTITY: Icon = Icon {
    view: 24.0,
    glyph: '\u{E72E}',
    shapes: &[
        Shape::RoundRect {
            x: 5.0,
            y: 10.0,
            w: 14.0,
            h: 10.0,
            r: 2.0,
        },
        Shape::Path(&[
            Cmd::Move(8.0, 10.0),
            Cmd::Line(8.0, 7.0),
            Cmd::Arc {
                cx: 12.0,
                cy: 7.0,
                r: 4.0,
                start: 180.0,
                sweep: 180.0,
            },
            Cmd::Line(16.0, 10.0),
        ]),
    ],
};

pub const SETTINGS: Icon = Icon {
    view: 24.0,
    glyph: '\u{E713}',
    shapes: &[
        Shape::Circle {
            cx: 12.0,
            cy: 12.0,
            r: 3.0,
        },
        Shape::Path(&line(12.0, 2.0, 12.0, 5.0)),
        Shape::Path(&line(12.0, 19.0, 12.0, 22.0)),
        Shape::Path(&line(2.0, 12.0, 5.0, 12.0)),
        Shape::Path(&line(19.0, 12.0, 22.0, 12.0)),
        Shape::Path(&line(4.9, 4.9, 7.0, 7.0)),
        Shape::Path(&line(17.0, 17.0, 19.1, 19.1)),
        Shape::Path(&line(4.9, 19.1, 7.0, 17.0)),
        Shape::Path(&line(17.0, 7.0, 19.1, 4.9)),
    ],
};

pub const DEVICE: Icon = Icon {
    view: 24.0,
    glyph: '\u{E7F4}',
    shapes: &[
        Shape::RoundRect {
            x: 3.0,
            y: 4.0,
            w: 18.0,
            h: 12.0,
            r: 2.0,
        },
        Shape::Path(&line(8.0, 20.0, 16.0, 20.0)),
        Shape::Path(&line(12.0, 16.0, 12.0, 20.0)),
    ],
};

pub const BROWSER: Icon = Icon {
    view: 24.0,
    glyph: '\u{E909}',
    shapes: &[
        Shape::Circle {
            cx: 12.0,
            cy: 12.0,
            r: 9.0,
        },
        Shape::Circle {
            cx: 12.0,
            cy: 12.0,
            r: 3.5,
        },
        Shape::Path(&line(12.0, 8.5, 20.2, 8.5)),
        Shape::Path(&line(9.0, 13.8, 4.9, 6.6)),
        Shape::Path(&line(15.0, 13.8, 10.9, 20.9)),
    ],
};

pub const SHIELD: Icon = Icon {
    view: 24.0,
    glyph: '\u{EA18}',
    shapes: &[
        Shape::Path(&[
            Cmd::Move(12.0, 3.0),
            Cmd::Line(20.0, 6.0),
            Cmd::Line(20.0, 12.0),
            Cmd::Cubic(20.0, 16.5, 16.6, 20.0, 12.0, 21.0),
            Cmd::Cubic(7.4, 20.0, 4.0, 16.5, 4.0, 12.0),
            Cmd::Line(4.0, 6.0),
            Cmd::Close,
        ]),
        Shape::Path(&[
            Cmd::Move(8.5, 12.0),
            Cmd::Line(11.0, 14.5),
            Cmd::Line(15.5, 9.5),
        ]),
    ],
};

pub const PLUS: Icon = Icon {
    view: 14.0,
    glyph: '\u{E710}',
    shapes: &[
        Shape::Path(&line(7.0, 1.0, 7.0, 13.0)),
        Shape::Path(&line(1.0, 7.0, 13.0, 7.0)),
    ],
};

#[cfg(test)]
mod tests {
    use super::*;

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
    fn offsets_from_the_centre_round_by_magnitude() {
        assert_eq!(about(-5.25, 29.5), 24.5);
        assert_eq!(about(5.25, 29.5), 34.5);
        assert_eq!(about(-2.5, 29.5), 26.5);
        assert_eq!(about(2.5, 29.5), 32.5);
        assert_eq!(about(0.0, 29.5), 29.5);
    }

    #[test]
    fn even_strokes_snap_to_pixel_edges() {
        assert_eq!(snap(6.75, 2.0), 7.0);
        assert_eq!(snap(6.2, 2.0), 6.0);
    }

    #[test]
    fn traces_rects_and_lines_on_the_pixel_grid() {
        let prims = trace(&SESSIONS, Rect::new(20, 19, 18, 18), 1.0);
        assert_eq!(
            prims[0],
            Prim::RoundRect {
                x: 22.5,
                y: 22.5,
                w: 14.0,
                h: 11.0,
                r: 1.5
            }
        );
        assert_eq!(
            prims[1],
            Prim::Figure {
                start: (22.5, 26.5),
                segs: vec![Seg::Line((36.5, 26.5))],
                closed: false,
            }
        );
    }

    #[test]
    fn circles_get_whole_pixel_radii_around_a_snapped_centre() {
        let prims = trace(&GATEWAYS, Rect::new(20, 19, 18, 18), 1.0);
        assert_eq!(
            prims[0],
            Prim::Circle {
                cx: 29.5,
                cy: 28.5,
                r: 7.0
            }
        );
    }

    #[test]
    fn arcs_end_on_snapped_points_with_the_radius_following_the_chord() {
        let prims = trace(&IDENTITY, Rect::new(20, 19, 18, 18), 1.0);
        assert_eq!(
            prims[1],
            Prim::Figure {
                start: (26.5, 26.5),
                segs: vec![
                    Seg::Line((26.5, 24.5)),
                    Seg::Arc {
                        to: (32.5, 24.5),
                        r: 3.0,
                        sweep: 180.0
                    },
                    Seg::Line((32.5, 26.5)),
                ],
                closed: false,
            }
        );
    }

    #[test]
    fn cubic_control_points_move_with_their_end_points() {
        let prims = trace(&GATEWAYS, Rect::new(0, 0, 24, 24), 2.0);
        assert_eq!(
            prims[2],
            Prim::Figure {
                start: (12.0, 3.0),
                segs: vec![Seg::Cubic((15.0, 6.5), (15.0, 17.5), (12.0, 21.0))],
                closed: false,
            }
        );
        let prims = trace(&GATEWAYS, Rect::new(0, 0, 18, 18), 1.0);
        let Prim::Figure { start, segs, .. } = &prims[2] else {
            panic!("expected a figure");
        };
        assert_eq!(*start, (9.5, 2.5));
        assert_eq!(
            segs[0],
            Seg::Cubic((11.75, 5.125), (11.75, 13.875), (9.5, 16.5))
        );
    }

    #[test]
    fn every_anchor_of_every_icon_sits_on_a_pixel_centre_for_odd_strokes() {
        let half = |v: f32| (v - v.floor() - 0.5).abs() < 1e-4;
        for icon in [
            SESSIONS, GATEWAYS, IDENTITY, SETTINGS, DEVICE, BROWSER, SHIELD, PLUS,
        ] {
            for size in [14, 18, 20, 27, 30] {
                for prim in trace(&icon, Rect::new(3, 7, size, size), 1.0) {
                    let mut points = Vec::new();
                    match prim {
                        Prim::RoundRect { x, y, w, h, .. } => {
                            points.extend([(x, y), (x + w, y + h)])
                        }
                        Prim::Circle { cx, cy, r } => {
                            assert_eq!(r, r.round());
                            points.push((cx, cy));
                        }
                        Prim::Figure { start, segs, .. } => {
                            points.push(start);
                            points.extend(segs.iter().map(|seg| match *seg {
                                Seg::Line(p) | Seg::Cubic(_, _, p) | Seg::Arc { to: p, .. } => p,
                            }));
                        }
                    }
                    for (x, y) in points {
                        assert!(half(x) && half(y), "{x},{y} at {size}px");
                    }
                }
            }
        }
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
                    for seg in segs {
                        match *seg {
                            Seg::Line(p) | Seg::Arc { to: p, .. } => points.push(p),
                            Seg::Cubic(c1, c2, p) => points.extend([c1, c2, p]),
                        }
                    }
                }
            }
        }
        points
    }

    fn sorted(mut points: Vec<Point>) -> Vec<(i64, i64)> {
        let mut keys: Vec<_> = points
            .drain(..)
            .map(|(x, y)| ((x * 1000.0).round() as i64, (y * 1000.0).round() as i64))
            .collect();
        keys.sort_unstable();
        keys
    }

    #[test]
    fn mirror_symmetric_icons_trace_symmetrically_about_the_snapped_axis() {
        for icon in [SESSIONS, GATEWAYS, IDENTITY, SETTINGS, DEVICE, PLUS] {
            for size in [16, 18, 20, 24, 27, 30, 36] {
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
    fn the_lock_shackle_is_centred_on_its_body() {
        for size in [16, 18, 20, 24, 27, 30, 36] {
            for width in [1.0, 2.0, 3.0] {
                let prims = trace(&IDENTITY, Rect::new(20, 19, size, size), width);
                let Prim::RoundRect { x, w, .. } = prims[0] else {
                    panic!("expected the body");
                };
                let Prim::Figure { start, segs, .. } = &prims[1] else {
                    panic!("expected the shackle");
                };
                let Seg::Line(end) = segs[2] else {
                    panic!("expected the right leg");
                };
                assert_eq!(
                    x + w / 2.0,
                    (start.0 + end.0) / 2.0,
                    "{size}px width {width}"
                );
            }
        }
    }
}
