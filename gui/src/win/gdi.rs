use windows_sys::Win32::Foundation::{LPARAM, RECT, SIZE};
use windows_sys::Win32::Graphics::Gdi::{
    BitBlt, CLEARTYPE_QUALITY, CreateCompatibleBitmap, CreateCompatibleDC, CreateFontIndirectW,
    DEFAULT_CHARSET, DEFAULT_PITCH, DT_CENTER, DT_END_ELLIPSIS, DT_NOCLIP, DT_NOPREFIX,
    DT_SINGLELINE, DT_VCENTER, DeleteDC, DeleteObject, DrawTextW, EnumFontFamiliesExW, FF_MODERN,
    FIXED_PITCH, GetTextExtentPoint32W, GetTextMetricsW, HBITMAP, HDC, HFONT, HGDIOBJ, LOGFONTW,
    SRCCOPY, SelectObject, SetBkMode, SetTextColor, TEXTMETRICW, TRANSPARENT,
};

use crate::color::Rgb;
use crate::fonts::{self, MONO_FAMILIES, UI_FAMILIES};
use crate::layout::{Font, Measure, Rect};
use crate::scale::Scale;

pub fn installed_families(dc: HDC) -> Vec<String> {
    unsafe extern "system" fn collect(
        font: *const LOGFONTW,
        _: *const TEXTMETRICW,
        _: u32,
        out: LPARAM,
    ) -> i32 {
        let (font, out) = unsafe { (&*font, &mut *(out as *mut Vec<String>)) };
        let len = font.lfFaceName.iter().position(|&c| c == 0).unwrap_or(32);
        out.push(String::from_utf16_lossy(&font.lfFaceName[..len]));
        1
    }
    let mut families = Vec::new();
    let query = LOGFONTW {
        lfCharSet: DEFAULT_CHARSET,
        ..Default::default()
    };
    unsafe {
        EnumFontFamiliesExW(dc, &query, Some(collect), (&raw mut families) as LPARAM, 0);
    }
    families
}

pub struct Fonts([HFONT; 10]);

impl Fonts {
    pub fn new(installed: &[String], s: Scale) -> Self {
        let ui = fonts::choose_family(installed, UI_FAMILIES);
        let mono = fonts::choose_family(installed, MONO_FAMILIES);
        let semibold = fonts::semibold_family(installed, ui);
        Self(fonts::ALL.map(|font| {
            let spec = fonts::spec(font);
            let family = match (spec.mono, spec.weight > 400) {
                (true, _) => mono,
                (false, true) => semibold.as_str(),
                (false, false) => ui,
            };
            let mut face = [0u16; 32];
            for (dst, src) in face.iter_mut().take(31).zip(family.encode_utf16()) {
                *dst = src;
            }
            let lf = LOGFONTW {
                lfHeight: -s.px(f32::from(spec.size)),
                lfWeight: i32::from(spec.weight),
                lfUnderline: u8::from(spec.underline),
                lfCharSet: DEFAULT_CHARSET,
                lfQuality: CLEARTYPE_QUALITY,
                lfPitchAndFamily: if spec.mono {
                    FIXED_PITCH | FF_MODERN
                } else {
                    DEFAULT_PITCH
                },
                lfFaceName: face,
                ..Default::default()
            };
            unsafe { CreateFontIndirectW(&lf) }
        }))
    }

    pub fn get(&self, font: Font) -> HFONT {
        self.0[font as usize]
    }
}

impl Drop for Fonts {
    fn drop(&mut self) {
        for font in self.0 {
            unsafe { DeleteObject(font as HGDIOBJ) };
        }
    }
}

struct Selected {
    dc: HDC,
    old: HGDIOBJ,
}

impl Selected {
    fn new(dc: HDC, object: HGDIOBJ) -> Self {
        Self {
            dc,
            old: unsafe { SelectObject(dc, object) },
        }
    }
}

impl Drop for Selected {
    fn drop(&mut self) {
        unsafe { SelectObject(self.dc, self.old) };
    }
}

pub struct Measurer<'a> {
    pub dc: HDC,
    pub fonts: &'a Fonts,
}

impl Measure for Measurer<'_> {
    fn width(&self, font: Font, text: &str) -> i32 {
        let _font = Selected::new(self.dc, self.fonts.get(font) as HGDIOBJ);
        let text: Vec<u16> = text.encode_utf16().collect();
        let mut size = SIZE::default();
        unsafe { GetTextExtentPoint32W(self.dc, text.as_ptr(), text.len() as i32, &mut size) };
        size.cx
    }

    fn line_height(&self, font: Font) -> i32 {
        let _font = Selected::new(self.dc, self.fonts.get(font) as HGDIOBJ);
        let mut tm = TEXTMETRICW::default();
        unsafe { GetTextMetricsW(self.dc, &mut tm) };
        tm.tmHeight
    }
}

#[derive(Clone, Copy, Default)]
pub struct Align {
    pub center: bool,
    pub ellipsis: bool,
}

pub fn text(dc: HDC, fonts: &Fonts, font: Font, s: &str, r: Rect, color: Rgb, align: Align) {
    let _font = Selected::new(dc, fonts.get(font) as HGDIOBJ);
    let wide: Vec<u16> = s.encode_utf16().collect();
    let mut rc = RECT {
        left: r.x,
        top: r.y,
        right: r.right(),
        bottom: r.bottom(),
    };
    let mut flags = DT_SINGLELINE | DT_NOPREFIX | DT_VCENTER;
    if align.center {
        flags |= DT_CENTER;
    }
    flags |= if align.ellipsis {
        DT_END_ELLIPSIS
    } else {
        DT_NOCLIP
    };
    unsafe {
        SetBkMode(dc, TRANSPARENT as i32);
        SetTextColor(dc, color.colorref());
        DrawTextW(dc, wide.as_ptr(), wide.len() as i32, &mut rc, flags);
    }
}

pub struct Buffer {
    target: HDC,
    dc: HDC,
    bitmap: HBITMAP,
    old: HGDIOBJ,
    w: i32,
    h: i32,
}

impl Buffer {
    pub fn new(target: HDC, w: i32, h: i32) -> Option<Self> {
        let (w, h) = (w.max(1), h.max(1));
        unsafe {
            let dc = CreateCompatibleDC(target);
            if dc.is_null() {
                return None;
            }
            let bitmap = CreateCompatibleBitmap(target, w, h);
            if bitmap.is_null() {
                DeleteDC(dc);
                return None;
            }
            let old = SelectObject(dc, bitmap as HGDIOBJ);
            Some(Self {
                target,
                dc,
                bitmap,
                old,
                w,
                h,
            })
        }
    }

    pub fn dc(&self) -> HDC {
        self.dc
    }

    pub fn present(&self, x: i32, y: i32) {
        unsafe { BitBlt(self.target, x, y, self.w, self.h, self.dc, 0, 0, SRCCOPY) };
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        unsafe {
            SelectObject(self.dc, self.old);
            DeleteObject(self.bitmap as HGDIOBJ);
            DeleteDC(self.dc);
        }
    }
}
