//! `rigtool baseline` (RIG.md §8): clean-Windows names from `rig-base`'s snap-0, minus rig items.
//!
//! Output (gzip TSV): header `#purge-baseline 1\t<time>\t<computer>\t<edition>\t<build.ubr>`, then
//! `K\tkey`, `V\tkey\tname\ttype\thash`, `D\tpath`, `F\tpath`.

use crate::err::{Context, Result};
use crate::escape::escape_into;
use crate::items::RigRules;
use crate::snap::{self, Header, Rec, Snap};
use crate::target::TASKCACHE;
use flate2::Compression;
use flate2::write::GzEncoder;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

pub fn output_path(o: &Path, h: &Header) -> PathBuf {
    let s = o.to_string_lossy();
    if o.is_dir() || s.ends_with('\\') || s.ends_with('/') {
        let ed = if h.edition.is_empty() { "Unknown" } else { &h.edition };
        o.join(format!("{ed}-{}.tsv.gz", h.build))
    } else {
        o.to_path_buf()
    }
}

pub fn cmd_baseline(snap_path: &Path, out: &Path) -> Result<()> {
    // Pass 1: header and the rig tasks' TaskCache GUIDs.
    let tree = format!("{TASKCACHE}\\Tree\\").to_ascii_lowercase();
    let mut mini = Snap::default();
    snap::for_each_rec(snap_path, true, |r| {
        match &r {
            Rec::Header(_) => mini.add(r, true),
            Rec::K { key, .. } | Rec::V { key, .. } if key.to_ascii_lowercase().starts_with(&tree) => mini.add(r, true),
            _ => {}
        }
        Ok(())
    })?;
    mini.finish();
    let rig = RigRules::new(&[&mini]);
    let header = mini.header.clone();
    let out = output_path(out, &header);
    if let Some(p) = out.parent()
        && !p.as_os_str().is_empty()
    {
        std::fs::create_dir_all(p).ok();
    }
    let f = std::fs::File::create(&out).with_context(|| format!("create {}", out.display()))?;
    let mut w = GzEncoder::new(BufWriter::with_capacity(1 << 20, f), Compression::new(6));
    let mut line = String::from("#purge-baseline 1");
    for x in [&header.time, &header.computer, &header.edition, &header.build] {
        line.push('\t');
        escape_into(x, &mut line);
    }
    line.push('\n');
    line.push_str(&snap::meta_line("source", &[snap_path.display().to_string()]));
    w.write_all(line.as_bytes())?;

    let (mut kept, mut dropped) = (0u64, 0u64);
    let mut buf = String::with_capacity(1 << 16);
    snap::for_each_rec(snap_path, false, |r| {
        buf.clear();
        let cs = match &r {
            Rec::D { path, .. } | Rec::F { path, .. } => format!("P:{path}"),
            Rec::K { key, .. } => format!("K:{key}"),
            Rec::V { key, name, .. } => format!("V:{key}|{name}"),
            _ => return Ok(()),
        };
        if rig.check(&cs).is_some() {
            dropped += 1;
            return Ok(());
        }
        kept += 1;
        match &r {
            Rec::D { path, .. } => {
                buf.push_str("D\t");
                escape_into(path, &mut buf);
            }
            Rec::F { path, .. } => {
                buf.push_str("F\t");
                escape_into(path, &mut buf);
            }
            Rec::K { key, .. } => {
                buf.push_str("K\t");
                escape_into(key, &mut buf);
            }
            Rec::V { key, name, typ, hash, .. } => {
                buf.push_str("V\t");
                escape_into(key, &mut buf);
                buf.push('\t');
                escape_into(name, &mut buf);
                buf.push_str(&format!("\t{typ}\t{hash:016x}"));
            }
            _ => {}
        }
        buf.push('\n');
        w.write_all(buf.as_bytes())?;
        Ok(())
    })?;
    w.finish()?.flush()?;
    eprintln!("baseline: {kept} records, {dropped} rig records dropped -> {}", out.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_drops_rig_and_trims_fields() {
        let dir = std::env::temp_dir().join(format!("rigtool-test-baseline-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut t = snap::header_line(&Header {
            time: "t".into(),
            computer: "pc".into(),
            edition: "EnterpriseS".into(),
            build: "26100.4000".into(),
        });
        let tk = format!("{TASKCACHE}\\Tree\\PurgeRigAgent");
        snap::write_k(&mut t, &tk, 1, Some(1), Some(0));
        snap::write_v(&mut t, &tk, "Id", 1, 4, 1, "{G}");
        snap::write_k(&mut t, &format!("{TASKCACHE}\\Tasks\\{{G}}"), 1, Some(0), Some(0));
        snap::write_k(&mut t, "HKLM\\SOFTWARE\\Keep", 1, Some(1), Some(0));
        snap::write_v(&mut t, "HKLM\\SOFTWARE\\Keep", "v", 4, 4, 0xabc, "1");
        snap::write_d(&mut t, "C:\\cr", 0x10, 1, 0);
        snap::write_f(&mut t, "C:\\cr\\agent.ps1", 1, 0x20, 1, 0);
        snap::write_f(&mut t, "C:\\Windows\\notepad.exe", 1, 0x20, 1, 0);
        let src = dir.join("snap-0.tsv");
        std::fs::write(&src, t).unwrap();
        let outdir = PathBuf::from(format!("{}\\", dir.display()));
        cmd_baseline(&src, &outdir).unwrap();
        let out = dir.join("EnterpriseS-26100.4000.tsv.gz");
        let mut text = String::new();
        std::io::Read::read_to_string(&mut snap::open_text(&out).unwrap(), &mut text).unwrap();
        let lines: Vec<&str> = text.lines().filter(|l| !l.starts_with('#')).collect();
        assert_eq!(
            lines,
            vec![
                "K\tHKLM\\\\SOFTWARE\\\\Keep",
                "V\tHKLM\\\\SOFTWARE\\\\Keep\tv\t4\t0000000000000abc",
                "F\tC:\\\\Windows\\\\notepad.exe"
            ]
        );
        assert!(text.starts_with("#purge-baseline 1\tt\tpc\tEnterpriseS\t26100.4000\n"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
