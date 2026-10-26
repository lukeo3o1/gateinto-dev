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
    pub stroke: f32,
    pub round_caps: bool,
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

pub fn arc_end(cx: f32, cy: f32, r: f32, start: f32, sweep: f32) -> (f32, f32) {
    let a = (start + sweep).to_radians();
    (cx + r * a.cos(), cy + r * a.sin())
}

const fn line(x1: f32, y1: f32, x2: f32, y2: f32) -> [Cmd; 2] {
    [Cmd::Move(x1, y1), Cmd::Line(x2, y2)]
}

pub const SESSIONS: Icon = Icon {
    view: 24.0,
    stroke: 1.6,
    round_caps: false,
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
    stroke: 1.6,
    round_caps: false,
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
    stroke: 1.6,
    round_caps: false,
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
    stroke: 1.6,
    round_caps: false,
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
    stroke: 1.7,
    round_caps: false,
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
    stroke: 1.7,
    round_caps: false,
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
    stroke: 1.7,
    round_caps: false,
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
    stroke: 1.6,
    round_caps: true,
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
}
