use windows::Win32::Graphics::DirectWrite::{
    DWRITE_FONT_STRETCH_NORMAL, DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_WEIGHT,
    DWRITE_PARAGRAPH_ALIGNMENT_CENTER, DWRITE_TRIMMING, DWRITE_TRIMMING_GRANULARITY_CHARACTER,
    DWRITE_WORD_WRAPPING_NO_WRAP, IDWriteFactory, IDWriteFontCollection, IDWriteTextFormat,
    IDWriteTextLayout,
};
use windows::core::{BOOL, PCWSTR, Result};

use super::sys::wide;
use crate::fonts::{self, Font, MONO_FAMILIES, UI_FAMILIES};
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

impl Fonts {
    pub fn new(dw: &IDWriteFactory, s: Scale) -> Result<Self> {
        let mut collection = None;
        unsafe { dw.GetSystemFontCollection(&mut collection, false)? };
        let collection = collection.ok_or_else(windows::core::Error::empty)?;
        let installed = installed(&collection);
        let locale = wide("en-us");
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
