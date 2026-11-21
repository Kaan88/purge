//! Icons of files and programs: one square, top-down BGRA image at a requested edge length.
//!
//! M3_DESIGN.md à15, package M3-ICONS. `SHGetFileInfoW` gives the shell's icon of a path (an `.exe`,
//! a `.ico`, a shortcut, any file), `GetIconInfo` its colour bitmap, and `GetDIBits` the 32-bit BGRA
//! pixels. The colour bitmap is downscaled to the requested size with an alpha-weighted box filter;
//! a legacy icon whose colour bitmap has no alpha channel takes its transparency from the AND mask.
//!
//! Display only: a path that cannot be read, a file without an icon and a malformed resource all give
//! `None`, which the caller shows as the placeholder tile. No caller treats that as an error.

use std::ffi::c_void;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::Graphics::Gdi::{
    BI_RGB, BITMAP, BITMAPINFO, BITMAPINFOHEADER, CreateCompatibleDC, DIB_RGB_COLORS, DeleteDC,
    DeleteObject, GetDIBits, GetObjectW, HBITMAP, HDC,
};
use windows_sys::Win32::UI::Shell::{SHFILEINFOW, SHGFI_ICON, SHGFI_SHELLICONSIZE, SHGetFileInfoW};
use windows_sys::Win32::UI::WindowsAndMessaging::{DestroyIcon, GetIconInfo, HICON, ICONINFO};

/// The largest edge length this module renders. A request over it is not an icon (`None`).
pub const MAX_PX: u16 = 256;

/// The BGRA pixels of `path`'s icon at `px` × `px`, top-down, `px * px * 4` bytes.
///
/// `None` when the path has no icon, cannot be read, or `px` is zero or over [`MAX_PX`].
pub fn icon_bgra(path: &Path, px: u16) -> Option<Vec<u8>> {
    if px == 0 || px > MAX_PX {
        return None;
    }
    let path_w: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut shfi: SHFILEINFOW = SHFILEINFOW::default();
    // SAFETY: `path_w` is NUL-terminated and `shfi` is a writable SHFILEINFOW of the stated size.
    let found = unsafe {
        SHGetFileInfoW(
            path_w.as_ptr(),
            0,
            &mut shfi,
            size_of::<SHFILEINFOW>() as u32,
            SHGFI_ICON | SHGFI_SHELLICONSIZE,
        )
    };
    if found == 0 || shfi.hIcon.is_null() {
        return None;
    }
    let icon = OwnedIcon(shfi.hIcon);
    let (pixels, width, height) = icon_pixels(icon.0)?;
    Some(resize_bgra(&pixels, width, height, px))
}

/// The colour bitmap of an icon as `(BGRA, width, height)`, top-down, bottom-up source rows turned
/// around. Alpha comes from the colour bitmap, or from the AND mask when the colour bitmap has none.
fn icon_pixels(icon: HICON) -> Option<(Vec<u8>, usize, usize)> {
    let mut info: ICONINFO = ICONINFO::default();
    // SAFETY: `icon` is a live icon handle and `info` is a writable ICONINFO.
    if unsafe { GetIconInfo(icon, &mut info) } == 0 {
        return None;
    }
    // GetIconInfo hands over both bitmaps; they are ours to delete even when the colour one is null.
    let mask = (!info.hbmMask.is_null()).then(|| OwnedBitmap(info.hbmMask));
    if info.hbmColor.is_null() {
        // A monochrome icon carries its image in the double-height mask; treat it as no icon.
        return None;
    }
    let color = OwnedBitmap(info.hbmColor);

    let mut bitmap: BITMAP = BITMAP::default();
    // SAFETY: `bitmap` is a writable BITMAP and `color` is a live bitmap handle.
    let got = unsafe {
        GetObjectW(
            color.0,
            size_of::<BITMAP>() as i32,
            std::ptr::addr_of_mut!(bitmap).cast::<c_void>(),
        )
    };
    if got == 0 || bitmap.bmWidth <= 0 || bitmap.bmHeight <= 0 {
        return None;
    }
    let (width, height) = (bitmap.bmWidth as usize, bitmap.bmHeight as usize);
    if width > 1024 || height > 1024 {
        return None;
    }
    if width.checked_mul(height)?.checked_mul(4)? > 64 * 1024 * 1024 {
        return None;
    }

    // SAFETY: a memory DC needs no window; a null handle asks for one compatible with the screen.
    let dc = OwnedDc(unsafe { CreateCompatibleDC(std::ptr::null_mut()) });
    if dc.0.is_null() {
        return None;
    }

    let mut pixels = vec![0u8; width * height * 4];
    let mut bmi = dib_header(width as i32, height as i32, 32);
    // SAFETY: `dc` is a live memory DC, `color` a live 32-bit bitmap, `pixels` holds
    // `width * height * 4` bytes, and `bmi` describes that buffer.
    let lines = unsafe {
        GetDIBits(
            dc.0,
            color.0,
            0,
            height as u32,
            pixels.as_mut_ptr().cast::<c_void>(),
            &mut bmi,
            DIB_RGB_COLORS,
        )
    };
    if lines == 0 {
        return None;
    }

    // A legacy icon has no alpha channel: the AND mask says which pixels are transparent.
    if pixels.chunks_exact(4).all(|p| p[3] == 0) {
        match mask {
            Some(mask) => apply_mask_alpha(dc.0, mask.0, &mut pixels, width, height),
            None => {
                for p in pixels.chunks_exact_mut(4) {
                    p[3] = 255;
                }
            }
        }
    }

    flip_rows(&mut pixels, width, height);
    Some((pixels, width, height))
}

/// Sets each pixel's alpha from the AND mask: white is transparent, black is opaque.
fn apply_mask_alpha(dc: HDC, mask: HBITMAP, pixels: &mut [u8], width: usize, height: usize) {
    let mut bitmap: BITMAP = BITMAP::default();
    // SAFETY: `bitmap` is a writable BITMAP and `mask` is a live bitmap handle.
    let got = unsafe {
        GetObjectW(
            mask,
            size_of::<BITMAP>() as i32,
            std::ptr::addr_of_mut!(bitmap).cast::<c_void>(),
        )
    };
    if got == 0 || bitmap.bmWidth <= 0 || bitmap.bmHeight <= 0 {
        return;
    }
    let (mask_w, mask_h) = (bitmap.bmWidth as usize, bitmap.bmHeight as usize);
    let fits = mask_w
        .checked_mul(mask_h)
        .and_then(|n| n.checked_mul(4))
        .is_some_and(|n| n <= 64 * 1024 * 1024);
    if mask_w < width || mask_h < height || !fits {
        return;
    }
    let mut mask_pixels = vec![0u8; mask_w * mask_h * 4];
    let mut bmi = dib_header(mask_w as i32, mask_h as i32, 32);
    // SAFETY: as in `icon_pixels`: the DC is live, `mask` is a live bitmap and the buffer fits `bmi`.
    let lines = unsafe {
        GetDIBits(
            dc,
            mask,
            0,
            mask_h as u32,
            mask_pixels.as_mut_ptr().cast::<c_void>(),
            &mut bmi,
            DIB_RGB_COLORS,
        )
    };
    if lines == 0 {
        return;
    }
    for y in 0..height {
        // Both bitmaps are bottom-up until `flip_rows`.
        let src = (mask_h - 1 - y) * mask_w;
        let dst = (height - 1 - y) * width;
        for x in 0..width {
            let opaque = mask_pixels[(src + x) * 4..][..3]
                .iter()
                .all(|&channel| channel == 0);
            pixels[(dst + x) * 4 + 3] = if opaque { 255 } else { 0 };
        }
    }
}

/// Turns bottom-up DIB rows into top-down rows.
fn flip_rows(pixels: &mut [u8], width: usize, height: usize) {
    let stride = width * 4;
    let mut top = vec![0u8; stride];
    for y in 0..height / 2 {
        let (a, b) = (y * stride, (height - 1 - y) * stride);
        top.copy_from_slice(&pixels[a..a + stride]);
        pixels.copy_within(b..b + stride, a);
        pixels[b..b + stride].copy_from_slice(&top);
    }
}

/// A 32-bit `BITMAPINFO` for `GetDIBits`, bottom-up (`height` positive).
fn dib_header(width: i32, height: i32, bits: u16) -> BITMAPINFO {
    BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: width,
            biHeight: height,
            biPlanes: 1,
            biBitCount: bits,
            biCompression: BI_RGB,
            biSizeImage: 0,
            biXPelsPerMeter: 0,
            biYPelsPerMeter: 0,
            biClrUsed: 0,
            biClrImportant: 0,
        },
        ..BITMAPINFO::default()
    }
}

/// An alpha-weighted box filter from `src_w` × `src_h` to `px` × `px`.
fn resize_bgra(src: &[u8], src_w: usize, src_h: usize, px: u16) -> Vec<u8> {
    let side = usize::from(px);
    let mut out = vec![0u8; side * side * 4];
    if src_w == side && src_h == side {
        out.copy_from_slice(&src[..side * side * 4]);
        return out;
    }
    for dy in 0..side {
        let y0 = dy * src_h / side;
        let y1 = (((dy + 1) * src_h / side).max(y0 + 1)).min(src_h);
        for dx in 0..side {
            let x0 = dx * src_w / side;
            let x1 = (((dx + 1) * src_w / side).max(x0 + 1)).min(src_w);
            let (mut a, mut r, mut g, mut b, mut n) = (0u64, 0u64, 0u64, 0u64, 0u64);
            for y in y0..y1 {
                for x in x0..x1 {
                    let i = (y * src_w + x) * 4;
                    let alpha = u64::from(src[i + 3]);
                    a += alpha;
                    // Premultiplied, so an opaque pixel is not dragged towards a transparent one.
                    b += u64::from(src[i]) * alpha;
                    g += u64::from(src[i + 1]) * alpha;
                    r += u64::from(src[i + 2]) * alpha;
                    n += 1;
                }
            }
            let o = (dy * side + dx) * 4;
            if let (Some(blue), Some(green), Some(red)) =
                (b.checked_div(a), g.checked_div(a), r.checked_div(a))
            {
                out[o] = blue as u8;
                out[o + 1] = green as u8;
                out[o + 2] = red as u8;
            }
            out[o + 3] = (a / n.max(1)) as u8;
        }
    }
    out
}

/// An icon handle from `SHGetFileInfoW`, destroyed on drop.
struct OwnedIcon(HICON);

impl Drop for OwnedIcon {
    fn drop(&mut self) {
        // SAFETY: the handle came from SHGetFileInfoW with SHGFI_ICON and is not used after this.
        unsafe { DestroyIcon(self.0) };
    }
}

/// A bitmap from `GetIconInfo`, deleted on drop.
struct OwnedBitmap(HBITMAP);

impl Drop for OwnedBitmap {
    fn drop(&mut self) {
        // SAFETY: the handle came from GetIconInfo and is not selected into a DC.
        unsafe { DeleteObject(self.0) };
    }
}

/// A memory DC from `CreateCompatibleDC`, deleted on drop.
struct OwnedDc(HDC);

impl Drop for OwnedDc {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the DC came from CreateCompatibleDC and has no selected objects of ours.
            unsafe { DeleteDC(self.0) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn a_missing_file_has_no_icon() {
        let missing = PathBuf::from(r"C:\Purge\tests\this-file-does-not-exist.exe");
        assert!(icon_bgra(&missing, 24).is_none());
    }

    #[test]
    fn a_zero_or_oversize_edge_has_no_icon() {
        let exe = std::env::current_exe().expect("test executable");
        assert!(icon_bgra(&exe, 0).is_none());
        assert!(icon_bgra(&exe, MAX_PX + 1).is_none());
    }

    #[test]
    fn the_test_executable_renders_a_24_px_bgra_icon() {
        let exe = std::env::current_exe().expect("test executable");
        let pixels =
            icon_bgra(&exe, 24).expect("the test executable has the shell's executable icon");
        assert_eq!(pixels.len(), 24 * 24 * 4);
        assert!(
            pixels.chunks_exact(4).any(|p| p[3] > 0),
            "not a fully transparent image"
        );
    }
}
