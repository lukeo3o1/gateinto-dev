use windows::Win32::Graphics::DirectWrite::{
    DWRITE_FONT_STRETCH_NORMAL, DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_WEIGHT,
    DWRITE_PARAGRAPH_ALIGNMENT_CENTER, DWRITE_TEXT_METRICS, DWRITE_TRIMMING,
    DWRITE_TRIMMING_GRANULARITY_CHARACTER, DWRITE_UNICODE_RANGE, DWRITE_WORD_WRAPPING_NO_WRAP,
    IDWriteFactory, IDWriteFactory2, IDWriteFontCollection, IDWriteFontFallback, IDWriteTextFormat,
    IDWriteTextFormat1, IDWriteTextLayout,
};
use windows::core::{BOOL, Interface, PCWSTR, Result};

use super::sys::wide;
use crate::fonts::{self, CJK_FAMILY, CJK_RANGES, Font, MONO_FAMILIES, Measure, UI_FAMILIES};
use crate::i18n;
use crate::scale::Scale;

pub struct Fonts {
    dw: IDWriteFactory,
    formats: Vec<IDWriteTextFormat>,
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

fn fallback(
    dw: &IDWriteFactory,
    collection: &IDWriteFontCollection,
) -> Option<IDWriteFontFallback> {
    let dw: IDWriteFactory2 = dw.cast().ok()?;
    let ranges: Vec<DWRITE_UNICODE_RANGE> = CJK_RANGES
        .iter()
        .map(|r| DWRITE_UNICODE_RANGE {
            first: *r.start(),
            last: *r.end(),
        })
        .collect();
    let family = wide(CJK_FAMILY);
    let locale = wide(fonts::locale(i18n::Language::Chinese));
    unsafe {
        let builder = dw.CreateFontFallbackBuilder().ok()?;
        builder
            .AddMapping(
                &ranges,
                &[family.as_ptr()],
                collection,
                PCWSTR(locale.as_ptr()),
                PCWSTR::null(),
                1.0,
            )
            .ok()?;
        builder
            .AddMappings(&dw.GetSystemFontFallback().ok()?)
            .ok()?;
        builder.CreateFontFallback().ok()
    }
}

impl Fonts {
    pub fn new(dw: &IDWriteFactory, s: Scale) -> Result<Self> {
        let mut collection = None;
        unsafe { dw.GetSystemFontCollection(&mut collection, false)? };
        let collection = collection.ok_or_else(windows::core::Error::empty)?;
        let installed = installed(&collection);
        let locale = wide(fonts::locale(i18n::current()));
        let fallback = fallback(dw, &collection);
        let trimming = DWRITE_TRIMMING {
            granularity: DWRITE_TRIMMING_GRANULARITY_CHARACTER,
            ..Default::default()
        };
        let formats = Font::ALL
            .iter()
            .map(|font| {
                let spec = font.spec();
                let family = wide(fonts::choose_family(&installed, font.families()));
                unsafe {
                    let format = dw.CreateTextFormat(
                        PCWSTR(family.as_ptr()),
                        &collection,
                        DWRITE_FONT_WEIGHT(i32::from(spec.weight)),
                        DWRITE_FONT_STYLE_NORMAL,
                        DWRITE_FONT_STRETCH_NORMAL,
                        s.pxf(f32::from(spec.size)),
                        PCWSTR(locale.as_ptr()),
                    )?;
                    format.SetWordWrapping(DWRITE_WORD_WRAPPING_NO_WRAP)?;
                    format.SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER)?;
                    let ellipsis = dw.CreateEllipsisTrimmingSign(&format)?;
                    format.SetTrimming(&trimming, &ellipsis)?;
                    if let (Some(fallback), Ok(format)) =
                        (&fallback, format.cast::<IDWriteTextFormat1>())
                    {
                        let _ = format.SetFontFallback(fallback);
                    }
                    Ok(format)
                }
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            dw: dw.clone(),
            formats,
        })
    }

    pub fn layout(&self, font: Font, text: &str, w: f32, h: f32) -> Option<IDWriteTextLayout> {
        let text: Vec<u16> = text.encode_utf16().collect();
        unsafe {
            self.dw
                .CreateTextLayout(&text, &self.formats[font as usize], w, h)
        }
        .ok()
    }
}

impl Measure for Fonts {
    fn width(&self, font: Font, text: &str) -> i32 {
        let Some(layout) = self.layout(font, text, f32::MAX, f32::MAX) else {
            return 0;
        };
        let mut metrics = DWRITE_TEXT_METRICS::default();
        match unsafe { layout.GetMetrics(&mut metrics) } {
            Ok(()) => metrics.widthIncludingTrailingWhitespace.ceil() as i32,
            Err(_) => 0,
        }
    }
}
