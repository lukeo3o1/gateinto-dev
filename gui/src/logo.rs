use crate::layout::Rect;
use crate::theme::Rgb;

pub const TILE: Rgb = Rgb(0x262b36);
pub const DOOR: Rgb = Rgb(0x0c0e13);
pub const ARCH: Rgb = Rgb(0xffffff);

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Arch {
    pub left: f32,
    pub right: f32,
    pub crown: f32,
    pub foot: f32,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Eye {
    pub cx: f32,
    pub cy: f32,
    pub rx: f32,
    pub ry: f32,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Mark {
    pub tile: (f32, f32, f32, f32),
    pub radius: f32,
    pub door: Arch,
    pub arch: Arch,
    pub stroke: f32,
    pub eyes: [Eye; 2],
}

pub fn mark(r: Rect) -> Mark {
    let k = r.w as f32 / 48.0;
    let x = |v: f32| r.x as f32 + v * k;
    let y = |v: f32| r.y as f32 + v * k;
    let arch = |left, right| Arch {
        left: x(left),
        right: x(right),
        crown: y(23.0),
        foot: y(40.0),
    };
    let eye = |cx| Eye {
        cx: x(cx),
        cy: y(27.0),
        rx: 2.2 * k,
        ry: 3.0 * k,
    };
    Mark {
        tile: (x(2.0), y(2.0), 44.0 * k, 44.0 * k),
        radius: 11.0 * k,
        door: arch(15.25, 32.75),
        arch: arch(13.0, 35.0),
        stroke: 4.5 * k,
        eyes: [eye(20.3), eye(27.7)],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn follows_the_svg_at_its_own_size() {
        let arch = |left, right| Arch {
            left,
            right,
            crown: 23.0,
            foot: 40.0,
        };
        let eye = |cx| Eye {
            cx,
            cy: 27.0,
            rx: 2.2,
            ry: 3.0,
        };
        assert_eq!(
            mark(Rect::new(0, 0, 48, 48)),
            Mark {
                tile: (2.0, 2.0, 44.0, 44.0),
                radius: 11.0,
                door: arch(15.25, 32.75),
                arch: arch(13.0, 35.0),
                stroke: 4.5,
                eyes: [eye(20.3), eye(27.7)],
            }
        );
    }

    #[test]
    fn scales_and_moves_with_its_rect() {
        let m = mark(Rect::new(10, 20, 96, 96));
        assert_eq!(m.tile, (14.0, 24.0, 88.0, 88.0));
        assert_eq!(m.radius, 22.0);
        assert_eq!(m.stroke, 9.0);
        assert_eq!(
            m.arch,
            Arch {
                left: 36.0,
                right: 80.0,
                crown: 66.0,
                foot: 100.0
            }
        );
        assert_eq!(m.eyes[1].cy, 74.0);
        assert_eq!(m.eyes[1].ry, 6.0);
    }
}
