use windows::Win32::Graphics::DirectWrite::{
    DWRITE_FONT_STRETCH_NORMAL, DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_WEIGHT,
    DWRITE_PARAGRAPH_ALIGNMENT_CENTER, DWRITE_TEXT_ALIGNMENT_CENTER, DWRITE_TEXT_METRICS,
    DWRITE_TEXT_RANGE, DWRITE_TRIMMING, DWRITE_TRIMMING_GRANULARITY_CHARACTER,
    DWRITE_WORD_WRAPPING_NO_WRAP, IDWriteFactory, IDWriteFontCollection, IDWriteInlineObject,
    IDWriteTextFormat, IDWriteTextLayout,
};
use windows::core::{BOOL, PCWSTR, Result};

use super::sys::wide;
use crate::fonts::{self, MONO_FAMILIES, UI_FAMILIES};
use crate::layout::{Font, Measure};
use crate::scale::Scale;

const UNBOUNDED: f32 = 100_000.0;

#[derive(Clone, Copy, Default)]
pub struct Align {
    pub center: bool,
    pub ellipsis: bool,
}

pub struct Fonts {
    dw: IDWriteFactory,
    formats: Vec<IDWriteTextFormat>,
    trims: Vec<IDWriteInlineObject>,
    heights: Vec<i32>,
}

fn installed(collection: &IDWriteFontCollection) -> Vec<&'static str> {
    UI_FAMILIES
        .iter()
        .chain(MONO_FAMILIES)
        .copied()
        .filter(|name| {
            let name = wide(name);
            let (mut index, mut exists) = (0, BOOL(0));
            let found = unsafe {
                collection.FindFamilyName(PCWSTR(name.as_ptr()), &mut index, &mut exists)
            };
            found.is_ok() && exists.as_bool()
        })
        .collect()
}

impl Fonts {
    pub fn new(dw: &IDWriteFactory, s: Scale) -> Result<Self> {
        let mut collection = None;
        unsafe { dw.GetSystemFontCollection(&mut collection, false)? };
        let collection = collection.ok_or_else(windows::core::Error::empty)?;
        let installed = installed(&collection);
        let ui = wide(fonts::choose_family(&installed, UI_FAMILIES));
        let mono = wide(fonts::choose_family(&installed, MONO_FAMILIES));
        let locale = wide("en-us");
        let mut formats = Vec::with_capacity(fonts::ALL.len());
        let mut trims = Vec::with_capacity(fonts::ALL.len());
        for font in fonts::ALL {
            let spec = fonts::spec(font);
            let family = if spec.mono { &mono } else { &ui };
            let format = unsafe {
                dw.CreateTextFormat(
                    PCWSTR(family.as_ptr()),
                    &collection,
                    DWRITE_FONT_WEIGHT(i32::from(spec.weight)),
                    DWRITE_FONT_STYLE_NORMAL,
                    DWRITE_FONT_STRETCH_NORMAL,
                    s.pxf(f32::from(spec.size)),
                    PCWSTR(locale.as_ptr()),
                )?
            };
            unsafe {
                format.SetWordWrapping(DWRITE_WORD_WRAPPING_NO_WRAP)?;
                format.SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER)?;
            }
            trims.push(unsafe { dw.CreateEllipsisTrimmingSign(&format)? });
            formats.push(format);
        }
        let mut fonts = Self {
            dw: dw.clone(),
            formats,
            trims,
            heights: Vec::new(),
        };
        fonts.heights = fonts::ALL
            .iter()
            .map(|&font| {
                fonts
                    .metrics(font, "Ag")
                    .map_or(0, |m| m.height.ceil() as i32)
            })
            .collect();
        Ok(fonts)
    }

    fn metrics(&self, font: Font, text: &str) -> Option<DWRITE_TEXT_METRICS> {
        let layout = self.layout(font, text, UNBOUNDED, UNBOUNDED, Align::default())?;
        let mut metrics = DWRITE_TEXT_METRICS::default();
        unsafe { layout.GetMetrics(&mut metrics) }.ok()?;
        Some(metrics)
    }

    pub fn layout(
        &self,
        font: Font,
        text: &str,
        w: f32,
        h: f32,
        align: Align,
    ) -> Option<IDWriteTextLayout> {
        let i = font as usize;
        let text: Vec<u16> = text.encode_utf16().collect();
        let layout = unsafe { self.dw.CreateTextLayout(&text, &self.formats[i], w, h) }.ok()?;
        unsafe {
            if align.center {
                layout.SetTextAlignment(DWRITE_TEXT_ALIGNMENT_CENTER).ok()?;
            }
            if align.ellipsis {
                let trimming = DWRITE_TRIMMING {
                    granularity: DWRITE_TRIMMING_GRANULARITY_CHARACTER,
                    ..Default::default()
                };
                layout.SetTrimming(&trimming, &self.trims[i]).ok()?;
            }
            if fonts::spec(font).underline {
                let range = DWRITE_TEXT_RANGE {
                    startPosition: 0,
                    length: text.len() as u32,
                };
                layout.SetUnderline(true, range).ok()?;
            }
        }
        Some(layout)
    }
}

impl Measure for Fonts {
    fn width(&self, font: Font, text: &str) -> i32 {
        self.metrics(font, text)
            .map_or(0, |m| m.widthIncludingTrailingWhitespace.ceil() as i32)
    }

    fn line_height(&self, font: Font) -> i32 {
        self.heights[font as usize]
    }
}
