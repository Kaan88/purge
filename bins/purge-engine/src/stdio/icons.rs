//! `programs.icons` ? `icon.batch`: 24 px BGRA icons, viewport first, at most [`ICONS_PER_LINE`].
//!
//! M3_DESIGN.md à10, package M3-ICONS. The stdio dispatcher owns the inventory and the frame writer,
//! so this module is a self-contained handler over two callbacks:
//!
//! - [`ProgramIcons`] answers a program's raw `DisplayIcon` (from the ARP entry);
//! - [`IconExtractor`] turns a path and an edge length into BGRA pixels ([`WindowsIcons`] is the real
//!   one, on `purge_win::icons`).
//!
//! Each batch of at most 32 icons goes to the supplied [`Notify`] sink as one `icon.batch` line, in
//! request order, so a viewport-first request sends a viewport-first batch. A program whose icon
//! cannot be read still gets an `Icon` with `bgra: None`: display only, a failed icon is a placeholder
//! and never an error. The handler returns the number of programs it answered, for the `{count}`
//! result of `programs.icons`.

use std::path::{Path, PathBuf};

use purge_model::ProgramId;
use purge_rpc::frame::{FrameError, RequestId};
use purge_rpc::methods::{ICONS_PER_LINE, Icon, IconBatch, IconsParams, ServerNotification};
use purge_rpc::table::Notify;

/// The edge length `programs.icons` asks for: 24 px (M3_DESIGN.md à10).
pub const DEFAULT_PX: u16 = 24;

/// The raw `DisplayIcon` value of one program.
pub trait ProgramIcons {
    /// The ARP entry's `DisplayIcon`, as written in the key; `None` when it has none.
    fn display_icon(&self, program_id: &ProgramId) -> Option<String>;
}

/// Turns an icon source path into BGRA pixels of `px` × `px`.
pub trait IconExtractor {
    /// The pixels, or `None` when the path has no readable icon (shown as the placeholder).
    fn extract(&self, path: &Path, px: u16) -> Option<Vec<u8>>;
}

/// The real extractor, over `purge_win::icons`.
pub struct WindowsIcons;

impl IconExtractor for WindowsIcons {
    fn extract(&self, path: &Path, px: u16) -> Option<Vec<u8>> {
        purge_win::icons::icon_bgra(path, px)
    }
}

/// Answers one `programs.icons` request with `icon.batch` lines.
///
/// The batches preserve the request's order (viewport first) and hold at most
/// [`ICONS_PER_LINE`] icons each. A transport failure from `notify` stops the batch loop and is
/// returned; an icon that cannot be read is not a failure.
pub fn handle(
    request: RequestId,
    params: &IconsParams,
    programs: &dyn ProgramIcons,
    extractor: &dyn IconExtractor,
    notify: &mut dyn Notify,
) -> Result<usize, FrameError> {
    let px = if params.px == 0 {
        DEFAULT_PX
    } else {
        params.px
    };
    let program_ids = params.program_ids.as_slice();
    for chunk in program_ids.chunks(ICONS_PER_LINE) {
        let mut icons = Vec::with_capacity(chunk.len());
        for program_id in chunk {
            let bgra = programs
                .display_icon(program_id)
                .and_then(|value| display_icon_path(&value))
                .and_then(|path| extractor.extract(&path, px))
                .map(|pixels| base64(&pixels));
            icons.push(Icon {
                program_id: program_id.clone(),
                px,
                bgra,
            });
        }
        notify.notify(&ServerNotification::IconBatch(IconBatch { request, icons }))?;
    }
    Ok(program_ids.len())
}

/// The file or executable named by an ARP `DisplayIcon` value.
///
/// Handles the forms the registry uses: `C:\path\app.exe`, `C:\path\app.exe,0`,
/// `"C:\Program Files\App\app.exe",-1`, and an `@` prefix. A trailing `,<number>` is an icon
/// resource index, not part of the path. `None` for an empty or unterminated value.
pub fn display_icon_path(display_icon: &str) -> Option<PathBuf> {
    let value = display_icon.trim();
    let value = value.strip_prefix('@').unwrap_or(value).trim();
    let path = match value.strip_prefix('"') {
        Some(rest) => rest.split_once('"')?.0,
        None => value,
    };
    let path = match path.rsplit_once(',') {
        Some((head, tail)) if !head.trim().is_empty() && tail.trim().parse::<i32>().is_ok() => {
            head.trim()
        }
        _ => path.trim(),
    };
    (!path.is_empty()).then(|| PathBuf::from(path))
}

/// Standard base64 with padding, so a batch line is plain JSON text.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        out.push(char::from(ALPHABET[(n >> 18) as usize & 63]));
        out.push(char::from(ALPHABET[(n >> 12) as usize & 63]));
        out.push(if chunk.len() > 1 {
            char::from(ALPHABET[(n >> 6) as usize & 63])
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            char::from(ALPHABET[n as usize & 63])
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use purge_model::View;
    use purge_rpc::methods::NonEmpty;

    /// Records every notification and answers a fixed icon per path.
    struct Sink {
        batches: Vec<IconBatch>,
    }

    impl Notify for Sink {
        fn notify(&mut self, notification: &ServerNotification) -> Result<(), FrameError> {
            match notification {
                ServerNotification::IconBatch(batch) => self.batches.push(batch.clone()),
                other => panic!("unexpected notification {other:?}"),
            }
            Ok(())
        }
    }

    /// `DisplayIcon` values of `prog<n>` are `C:\icons\prog<n>.ico`; `missing` has no icon.
    struct Programs {
        count: usize,
        missing: &'static str,
    }

    impl ProgramIcons for Programs {
        fn display_icon(&self, program_id: &ProgramId) -> Option<String> {
            let key = program_id.key_name();
            if key == self.missing {
                return Some(format!(r"C:\icons\{key}.ico"));
            }
            key.strip_prefix("prog")
                .and_then(|n| n.parse::<usize>().ok())
                .filter(|&n| n < self.count)
                .map(|n| format!(r"C:\icons\prog{n}.ico"))
        }
    }

    /// Pixels of one solid colour: the first byte is the program's number.
    struct Pixels;

    impl IconExtractor for Pixels {
        fn extract(&self, path: &Path, px: u16) -> Option<Vec<u8>> {
            let stem = path.file_stem()?.to_str()?;
            let n: u8 = stem.strip_prefix("prog")?.parse().ok()?;
            Some(vec![n; usize::from(px) * usize::from(px) * 4])
        }
    }

    fn request(ids: Vec<ProgramId>, px: u16) -> IconsParams {
        IconsParams {
            program_ids: NonEmpty::new(ids).expect("at least one id"),
            px,
        }
    }

    fn id(n: usize) -> ProgramId {
        ProgramId::machine(View::K64, format!("prog{n}")).expect("program id")
    }

    #[test]
    fn batches_hold_at_most_32_icons_in_request_order() {
        let ids: Vec<ProgramId> = (0..70).map(id).collect();
        let params = request(ids.clone(), 24);
        let programs = Programs {
            count: 70,
            missing: "",
        };
        let mut sink = Sink { batches: vec![] };
        let count = handle(RequestId(7), &params, &programs, &Pixels, &mut sink).expect("handled");

        assert_eq!(count, 70);
        assert_eq!(
            sink.batches
                .iter()
                .map(|b| b.icons.len())
                .collect::<Vec<_>>(),
            [32, 32, 6]
        );
        let order: Vec<&ProgramId> = sink
            .batches
            .iter()
            .flat_map(|b| b.icons.iter().map(|i| &i.program_id))
            .collect();
        assert_eq!(order, ids.iter().collect::<Vec<_>>());
        assert!(sink.batches.iter().all(|b| b.request == RequestId(7)));
    }

    #[test]
    fn a_missing_file_is_a_placeholder_not_an_error() {
        let ids = vec![id(0), ProgramId::machine(View::K64, "missing").unwrap()];
        let params = request(ids, 24);
        let programs = Programs {
            count: 1,
            missing: "missing",
        };
        let mut sink = Sink { batches: vec![] };
        let count = handle(RequestId(1), &params, &programs, &Pixels, &mut sink).expect("handled");

        assert_eq!(count, 2);
        let icons = &sink.batches[0].icons;
        let expected = base64(&[0u8; 24 * 24 * 4]);
        assert_eq!(icons[0].bgra.as_deref(), Some(expected.as_str()));
        assert_eq!(icons[1].program_id.key_name(), "missing");
        assert_eq!(icons[1].px, 24);
        assert!(icons[1].bgra.is_none(), "a failed icon is a placeholder");
    }

    #[test]
    fn the_default_edge_is_24_px() {
        let params = request(vec![id(0)], 0);
        let programs = Programs {
            count: 1,
            missing: "",
        };
        let mut sink = Sink { batches: vec![] };
        handle(RequestId(2), &params, &programs, &Pixels, &mut sink).expect("handled");
        assert_eq!(sink.batches[0].icons[0].px, 24);
        assert_eq!(
            sink.batches[0].icons[0].bgra.as_deref().map(str::len),
            Some((24 * 24 * 4usize).div_ceil(3) * 4)
        );
    }

    #[test]
    fn display_icon_values_become_paths() {
        for (value, expected) in [
            (r"C:\icons\app.ico", r"C:\icons\app.ico"),
            (r"C:\icons\app.exe,0", r"C:\icons\app.exe"),
            (
                r#""C:\Program Files\App\app.exe",-1"#,
                r"C:\Program Files\App\app.exe",
            ),
            (r"@C:\icons\app.ico", r"C:\icons\app.ico"),
        ] {
            assert_eq!(
                display_icon_path(value).as_deref(),
                Some(Path::new(expected)),
                "{value}"
            );
        }
        assert!(display_icon_path("").is_none());
        assert!(display_icon_path(r#""C:\icons\app.ico"#).is_none());
    }

    #[test]
    fn base64_matches_the_fixture() {
        assert_eq!(base64(&[0, 0, 0, 255]), "AAAA/w==");
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
    }
}
