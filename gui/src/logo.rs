use crate::layout::Rect;
use crate::sessions::Eyes;
use crate::theme::Rgb;

pub const TILE: Rgb = Rgb(0x262b36);
pub const DOOR: Rgb = Rgb(0x0c0e13);
pub const ARCH: Rgb = Rgb(0xffffff);
pub const LIT: Rgb = Rgb(0xffc94a);
pub const DIM: Rgb = Rgb(0x9aa1b1);
pub const DASH: Rgb = Rgb(0x8a90a0);

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

const SAMPLES: i32 = 4;

pub fn pixels(size: i32, eyes: Eyes) -> Vec<u32> {
    let m = mark(Rect::new(0, 0, size, size));
    let k = size as f32 / 48.0;
    let mut out = Vec::with_capacity((size * size).max(0) as usize);
    for py in 0..size {
        for px in 0..size {
            let (mut hits, mut sum) = (0u32, [0u32; 3]);
            for sy in 0..SAMPLES {
                for sx in 0..SAMPLES {
                    let x = px as f32 + (sx as f32 + 0.5) / SAMPLES as f32;
                    let y = py as f32 + (sy as f32 + 0.5) / SAMPLES as f32;
                    if let Some(c) = sample(&m, k, eyes, x, y) {
                        hits += 1;
                        for (i, shift) in [16, 8, 0].into_iter().enumerate() {
                            sum[i] += (c.0 >> shift) & 0xff;
                        }
                    }
                }
            }
            out.push(match hits {
                0 => 0,
                n => {
                    let alpha = n * 255 / (SAMPLES * SAMPLES) as u32;
                    let ch = |v: u32| (v + n / 2) / n;
                    alpha << 24 | ch(sum[0]) << 16 | ch(sum[1]) << 8 | ch(sum[2])
                }
            });
        }
    }
    out
}

fn sample(m: &Mark, k: f32, eyes: Eyes, x: f32, y: f32) -> Option<Rgb> {
    let (tx, ty, tw, th) = m.tile;
    let dx = (tx + m.radius - x).max(x - (tx + tw - m.radius)).max(0.0);
    let dy = (ty + m.radius - y).max(y - (ty + th - m.radius)).max(0.0);
    let inside = x >= tx && x < tx + tw && y >= ty && y < ty + th;
    if !inside || dx * dx + dy * dy > m.radius * m.radius {
        return None;
    }
    let eye = match eyes {
        Eyes::Lit => Some(LIT),
        Eyes::Dim => Some(DIM),
        Eyes::Closed => None,
    };
    let on_eye = m.eyes.iter().any(|e| {
        let (u, v) = ((x - e.cx) / e.rx, (y - e.cy) / e.ry);
        u * u + v * v <= 1.0
    });
    let on_dash = [18.3, 25.7].iter().any(|&left| {
        let (x0, x1, cy) = (left * k, (left + 4.0) * k, 28.0 * k);
        segment(x, y, (x0, cy), (x1, cy)) <= 1.1 * k
    });
    Some(match eye {
        Some(c) if on_eye => c,
        None if on_dash => DASH,
        _ if arch_distance(m.arch, x, y) <= m.stroke / 2.0 => ARCH,
        _ if in_door(m.door, x, y) => DOOR,
        _ => TILE,
    })
}

fn in_door(a: Arch, x: f32, y: f32) -> bool {
    let r = (a.right - a.left) / 2.0;
    let (cx, cy) = (a.left + r, a.crown);
    x >= a.left
        && x <= a.right
        && y <= a.foot
        && (y >= cy || (x - cx) * (x - cx) + (y - cy) * (y - cy) <= r * r)
}

fn arch_distance(a: Arch, x: f32, y: f32) -> f32 {
    let r = (a.right - a.left) / 2.0;
    let (cx, cy) = (a.left + r, a.crown);
    let legs = segment(x, y, (a.left, a.foot), (a.left, a.crown)).min(segment(
        x,
        y,
        (a.right, a.foot),
        (a.right, a.crown),
    ));
    if y <= cy {
        legs.min(((x - cx).hypot(y - cy) - r).abs())
    } else {
        legs
    }
}

fn segment(x: f32, y: f32, a: (f32, f32), b: (f32, f32)) -> f32 {
    let (vx, vy) = (b.0 - a.0, b.1 - a.1);
    let t = (((x - a.0) * vx + (y - a.1) * vy) / (vx * vx + vy * vy)).clamp(0.0, 1.0);
    (x - a.0 - t * vx).hypot(y - a.1 - t * vy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sessions::Eyes;

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

    fn at(size: i32, eyes: Eyes, x: i32, y: i32) -> u32 {
        let image = pixels(size, eyes);
        assert_eq!(image.len(), (size * size) as usize);
        image[(y * size + x) as usize]
    }

    #[test]
    fn leaves_the_corners_transparent() {
        assert_eq!(at(48, Eyes::Lit, 0, 0) >> 24, 0);
        assert_eq!(at(48, Eyes::Lit, 47, 47) >> 24, 0);
    }

    #[test]
    fn paints_the_tile_door_and_arch_opaque() {
        assert_eq!(at(48, Eyes::Dim, 24, 5), 0xff262b36);
        assert_eq!(at(48, Eyes::Dim, 24, 35), 0xff0c0e13);
        assert_eq!(at(48, Eyes::Dim, 12, 35), 0xffffffff);
    }

    #[test]
    fn colors_the_eyes_by_traffic() {
        assert_eq!(at(48, Eyes::Lit, 20, 27), 0xffffc94a);
        assert_eq!(at(48, Eyes::Dim, 20, 27), 0xff9aa1b1);
    }

    #[test]
    fn closes_the_eyes_into_dashes_when_stopped() {
        assert_eq!(at(48, Eyes::Closed, 20, 27), 0xff8a90a0);
        assert_eq!(at(48, Eyes::Closed, 20, 25), 0xff0c0e13);
    }

    #[test]
    fn blends_edges_with_partial_alpha() {
        let edge = (0..16).map(|x| at(16, Eyes::Lit, x, 0) >> 24);
        assert!(edge.clone().any(|a| a > 0 && a < 255));
        assert!(edge.clone().any(|a| a == 0));
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
