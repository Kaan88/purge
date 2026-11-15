//! `rigtool diff A B`: added / removed / changed records between two snaps.

use crate::canon;
use crate::err::Result;
use crate::escape::escape;
use crate::snap::{FsRec, KeyRec, LoadOpts, Snap, ValRec};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Serialize, Clone, Debug)]
pub struct Change {
    pub op: char,
    pub rec: char,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub changes: Vec<String>,
}

fn fs_changes(a: &FsRec, b: &FsRec) -> Vec<String> {
    let mut v = Vec::new();
    if a.dir != b.dir {
        v.push(format!("kind {}->{}", if a.dir { "D" } else { "F" }, if b.dir { "D" } else { "F" }));
    }
    if !a.dir && a.size != b.size {
        v.push(format!("size {}->{}", a.size, b.size));
    }
    if a.attrs != b.attrs {
        v.push(format!("attrs {:x}->{:x}", a.attrs, b.attrs));
    }
    if a.mtime != b.mtime {
        v.push(format!("mtime {}->{}", a.mtime, b.mtime));
    }
    if a.reparse != b.reparse {
        v.push(format!("reparse {:x}->{:x}", a.reparse, b.reparse));
    }
    v
}

fn key_changes(a: &KeyRec, b: &KeyRec) -> Vec<String> {
    let mut v = Vec::new();
    if a.lwt != b.lwt {
        v.push(format!("lwt {}->{}", a.lwt, b.lwt));
    }
    let o = |x: Option<u32>| x.map(|n| n.to_string()).unwrap_or_else(|| "?".into());
    if a.nv != b.nv {
        v.push(format!("n_values {}->{}", o(a.nv), o(b.nv)));
    }
    if a.ns != b.ns {
        v.push(format!("n_subkeys {}->{}", o(a.ns), o(b.ns)));
    }
    v
}

fn val_changes(a: &ValRec, b: &ValRec) -> Vec<String> {
    let mut v = Vec::new();
    if a.typ != b.typ {
        v.push(format!("type {}->{}", a.typ, b.typ));
    }
    if a.hash != b.hash {
        v.push(format!("hash {:016x}->{:016x}", a.hash, b.hash));
        if a.preview != b.preview && (a.preview.len() + b.preview.len()) < 400 {
            v.push(format!("preview \"{}\"->\"{}\"", a.preview, b.preview));
        }
    }
    v
}

fn ch(op: char, rec: char, path: &str, name: Option<&str>, changes: Vec<String>) -> Change {
    Change { op, rec, path: path.to_string(), name: name.map(str::to_string), changes }
}

pub fn diff(a: &Snap, b: &Snap) -> Vec<Change> {
    let mut out = Vec::new();
    for (p, rb) in &b.fs {
        let rec = if rb.dir { 'D' } else { 'F' };
        match a.path(p.as_str()) {
            None => out.push(ch('+', rec, p.as_str(), None, vec![])),
            Some(ra) => {
                let c = fs_changes(ra, rb);
                if !c.is_empty() {
                    out.push(ch('~', rec, p.as_str(), None, c));
                }
            }
        }
    }
    for (p, ra) in &a.fs {
        if !b.has_path(p.as_str()) {
            out.push(ch('-', if ra.dir { 'D' } else { 'F' }, p.as_str(), None, vec![]));
        }
    }
    for (k, kb) in &b.keys {
        let ka = a.keys.get(canon::CiStr::new(k.as_str()));
        if kb.seen {
            match ka.filter(|x| x.seen) {
                None => out.push(ch('+', 'K', k.as_str(), None, vec![])),
                Some(ka) => {
                    let c = key_changes(ka, kb);
                    if !c.is_empty() {
                        out.push(ch('~', 'K', k.as_str(), None, c));
                    }
                }
            }
        }
        for v in &kb.values {
            match ka.and_then(|x| x.value(&v.name)) {
                None => out.push(ch('+', 'V', k.as_str(), Some(&v.name), vec![])),
                Some(va) => {
                    let c = val_changes(va, v);
                    if !c.is_empty() {
                        out.push(ch('~', 'V', k.as_str(), Some(&v.name), c));
                    }
                }
            }
        }
    }
    for (k, ka) in &a.keys {
        let kb = b.keys.get(canon::CiStr::new(k.as_str()));
        if ka.seen && !kb.is_some_and(|x| x.seen) {
            out.push(ch('-', 'K', k.as_str(), None, vec![]));
        }
        for v in &ka.values {
            if kb.and_then(|x| x.value(&v.name)).is_none() {
                out.push(ch('-', 'V', k.as_str(), Some(&v.name), vec![]));
            }
        }
    }
    let rank = |r: char| match r {
        'D' => 0,
        'F' => 1,
        'K' => 2,
        _ => 3,
    };
    out.sort_by(|x, y| {
        rank(x.rec)
            .cmp(&rank(y.rec))
            .then_with(|| canon::ci_cmp(&x.path, &y.path))
            .then_with(|| canon::ci_cmp(x.name.as_deref().unwrap_or(""), y.name.as_deref().unwrap_or("")))
            .then_with(|| x.op.cmp(&y.op))
    });
    out
}

pub fn summary(v: &[Change]) -> BTreeMap<String, usize> {
    let mut m = BTreeMap::new();
    for c in v {
        *m.entry(format!("{}{}", c.op, c.rec)).or_insert(0) += 1;
    }
    m
}

pub fn cmd_diff(a: &Path, b: &Path, json: bool) -> Result<()> {
    use std::io::Write;
    let sa = Snap::load(a, LoadOpts::default())?;
    let sb = Snap::load(b, LoadOpts::default())?;
    let d = diff(&sa, &sb);
    let sum = summary(&d);
    let stdout = std::io::stdout();
    let mut w = std::io::BufWriter::new(stdout.lock());
    if json {
        let pick = |op: char| d.iter().filter(|c| c.op == op).collect::<Vec<&Change>>();
        let j = serde_json::json!({
            "a": a.display().to_string(),
            "b": b.display().to_string(),
            "summary": sum,
            "added": pick('+'),
            "removed": pick('-'),
            "changed": pick('~'),
        });
        serde_json::to_writer_pretty(&mut w, &j)?;
        writeln!(w)?;
    } else {
        for c in &d {
            write!(w, "{}\t{}\t{}", c.op, c.rec, escape(&c.path))?;
            if let Some(n) = &c.name {
                write!(w, "\t{}", escape(n))?;
            }
            if !c.changes.is_empty() {
                write!(w, "\t{}", escape(&c.changes.join(", ")))?;
            }
            writeln!(w)?;
        }
    }
    w.flush()?;
    if sum.is_empty() {
        eprintln!("diff: no differences");
    } else {
        eprintln!("diff: {}", sum.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(" "));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snap::{write_d, write_f, write_k, write_v};
    use crate::testutil::snap_text;

    #[test]
    fn diff_records() {
        let a = snap_text(|t| {
            write_d(t, "C:\\a", 0x10, 1, 0);
            write_f(t, "C:\\a\\f", 1, 0x20, 1, 0);
            write_f(t, "C:\\a\\gone", 1, 0x20, 1, 0);
            write_k(t, "HKLM\\SOFTWARE\\K", 1, Some(1), Some(0));
            write_v(t, "HKLM\\SOFTWARE\\K", "v", 4, 4, 1, "1");
        });
        let b = snap_text(|t| {
            write_d(t, "C:\\A", 0x10, 1, 0);
            write_f(t, "C:\\a\\f", 2, 0x20, 1, 0);
            write_f(t, "C:\\a\\new", 1, 0x20, 1, 0);
            write_k(t, "HKLM\\SOFTWARE\\K", 1, Some(2), Some(0));
            write_v(t, "HKLM\\SOFTWARE\\K", "V", 4, 4, 2, "2");
            write_v(t, "HKLM\\SOFTWARE\\K", "w", 4, 4, 3, "3");
        });
        let d = diff(&a, &b);
        let s: Vec<String> = d
            .iter()
            .map(|c| {
                format!(
                    "{}{} {}{}",
                    c.op,
                    c.rec,
                    c.path,
                    c.name.as_deref().map(|n| format!("|{n}")).unwrap_or_default()
                )
            })
            .collect();
        assert_eq!(
            s,
            vec![
                "~F C:\\a\\f",
                "-F C:\\a\\gone",
                "+F C:\\a\\new",
                "~K HKLM\\SOFTWARE\\K",
                "~V HKLM\\SOFTWARE\\K|V",
                "+V HKLM\\SOFTWARE\\K|w"
            ]
        );
        assert_eq!(d[0].changes, vec!["size 1->2"]);
    }
}
