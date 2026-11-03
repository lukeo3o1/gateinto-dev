use std::ffi::c_void;
use std::ptr::null_mut;

use windows_sys::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, CreateBitmap, CreateDIBSection, DIB_RGB_COLORS,
    DeleteObject,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateIconIndirect, DestroyIcon, HICON, ICONINFO,
};

use crate::logo;

pub struct Owned(pub HICON);

impl Drop for Owned {
    fn drop(&mut self) {
        unsafe { DestroyIcon(self.0) };
    }
}

pub fn render(state: logo::State, size: i32) -> Option<Owned> {
    let pixels = logo::pixels(size, state);
    let info = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: size,
            biHeight: -size,
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB,
            ..Default::default()
        },
        ..Default::default()
    };
    let stride = (size as usize).div_ceil(16) * 2;
    let mask_bits = vec![0u8; stride * size as usize];
    let mut bits: *mut c_void = null_mut();
    unsafe {
        let color = CreateDIBSection(null_mut(), &info, DIB_RGB_COLORS, &mut bits, null_mut(), 0);
        if color.is_null() {
            return None;
        }
        let mut icon = null_mut();
        if !bits.is_null() {
            std::ptr::copy_nonoverlapping(pixels.as_ptr(), bits.cast::<u32>(), pixels.len());
            let mask = CreateBitmap(size, size, 1, 1, mask_bits.as_ptr().cast());
            if !mask.is_null() {
                icon = CreateIconIndirect(&ICONINFO {
                    fIcon: 1,
                    xHotspot: 0,
                    yHotspot: 0,
                    hbmMask: mask,
                    hbmColor: color,
                });
                DeleteObject(mask);
            }
        }
        DeleteObject(color);
        (!icon.is_null()).then_some(Owned(icon))
    }
}
