#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scale {
    pub dpi: u32,
}

impl Scale {
    pub const BASE_DPI: u32 = 96;

    pub fn new(dpi: u32) -> Self {
        Self { dpi }
    }

    pub fn px(self, dip: f32) -> i32 {
        self.pxf(dip).round() as i32
    }

    pub fn pxf(self, dip: f32) -> f32 {
        dip * self.dpi as f32 / Self::BASE_DPI as f32
    }

    pub fn hairline(self) -> i32 {
        (self.dpi / Self::BASE_DPI).max(1) as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_at_96_dpi() {
        let s = Scale::new(96);
        assert_eq!(s.px(28.0), 28);
        assert_eq!(s.pxf(1.6), 1.6);
    }

    #[test]
    fn scales_and_rounds_to_nearest_pixel() {
        assert_eq!(Scale::new(144).px(28.0), 42);
        assert_eq!(Scale::new(144).px(1.0), 2);
        assert_eq!(Scale::new(120).px(14.0), 18);
        assert_eq!(Scale::new(120).px(6.0), 8);
        assert_eq!(Scale::new(192).px(232.0), 464);
        assert!((Scale::new(144).pxf(1.6) - 2.4).abs() < 1e-5);
    }

    #[test]
    fn hairline_is_whole_device_pixels_never_zero() {
        assert_eq!(Scale::new(96).hairline(), 1);
        assert_eq!(Scale::new(120).hairline(), 1);
        assert_eq!(Scale::new(144).hairline(), 1);
        assert_eq!(Scale::new(192).hairline(), 2);
        assert_eq!(Scale::new(288).hairline(), 3);
    }
}
