use crate::color::Rgb;
use crate::layout::Rect;

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
    pub fn right(self) -> f32 {
        self.x + self.w
    }

    pub fn bottom(self) -> f32 {
        self.y + self.h
    }

    pub fn inset(self, d: f32) -> Self {
        Self {
            x: self.x + d,
            y: self.y + d,
            w: self.w - 2.0 * d,
            h: self.h - 2.0 * d,
        }
    }
}

pub fn border(edge: Rect, radius: f32, width: f32) -> (RectF, f32) {
    let half = width / 2.0;
    (RectF::from(edge).inset(half), (radius - half).max(0.0))
}

pub fn channels(color: Rgb) -> [f32; 4] {
    let c = |shift: u32| ((color.0 >> shift) & 0xff) as f32 / 255.0;
    [c(16), c(8), c(0), 1.0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rects_convert_to_floats() {
        let r = RectF::from(Rect::new(3, 4, 10, 20));
        assert_eq!(
            r,
            RectF {
                x: 3.0,
                y: 4.0,
                w: 10.0,
                h: 20.0
            }
        );
        assert_eq!(r.right(), 13.0);
        assert_eq!(r.bottom(), 24.0);
    }

    #[test]
    fn inset_shrinks_every_side() {
        let r = RectF {
            x: 0.0,
            y: 0.0,
            w: 10.0,
            h: 6.0,
        }
        .inset(0.5);
        assert_eq!(
            r,
            RectF {
                x: 0.5,
                y: 0.5,
                w: 9.0,
                h: 5.0
            }
        );
    }

    #[test]
    fn borders_are_stroked_on_the_centre_of_their_device_pixels() {
        let edge = Rect::new(10, 20, 100, 40);
        let (r, radius) = border(edge, 6.0, 1.0);
        assert_eq!(
            r,
            RectF {
                x: 10.5,
                y: 20.5,
                w: 99.0,
                h: 39.0
            }
        );
        assert_eq!(radius, 5.5);
        let (r, radius) = border(edge, 1.0, 2.0);
        assert_eq!(
            r,
            RectF {
                x: 11.0,
                y: 21.0,
                w: 98.0,
                h: 38.0
            }
        );
        assert_eq!(radius, 0.0);
    }

    #[test]
    fn colours_become_normalised_opaque_channels() {
        assert_eq!(channels(Rgb(0xff8000)), [1.0, 128.0 / 255.0, 0.0, 1.0]);
        assert_eq!(channels(Rgb(0x000000)), [0.0, 0.0, 0.0, 1.0]);
    }
}
