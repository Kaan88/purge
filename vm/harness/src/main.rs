//! clone-harness: runs the clone's (draft_clone) program list and leftover scan without its UI.
//!
//!   clone-harness list                       -> JSON: programs (+category), store count, startup items
//!   clone-harness uninstall <name> <cmd|default|quiet> [timeout_s]
//!       captures the entry, runs the uninstall command, waits for the entry to go away,
//!       then runs leftovers::scan on the captured entry -> JSON leftovers (what the clone
//!       would pre-check for deletion). Nothing is deleted.
#![allow(dead_code, unused_imports)]

#[path = "../../../../draft_clone/src/util.rs"]
mod util;
#[path = "../../../../draft_clone/src/programs.rs"]
mod programs;
#[path = "../../../../draft_clone/src/trace.rs"]
mod trace;
#[path = "../../../../draft_clone/src/leftovers.rs"]
mod leftovers;
#[path = "../../../../draft_clone/src/store.rs"]
mod store;
#[path = "../../../../draft_clone/src/startup.rs"]
mod startup;

use serde_json::{json, Value};
use std::time::{Duration, Instant};

fn prog_json(p: &programs::Program) -> Value {
    json!({
        "name": p.name, "version": p.version, "publisher": p.publisher,
        "category": format!("{:?}", p.category), "is_update": p.is_update,
        "hive": format!("{:?}", p.hive), "wow64": p.wow64, "key": p.key_path,
        "size_kb": p.size_kb, "install_days": p.install_days,
        "uninstall": p.uninstall_string, "quiet": p.quiet_uninstall,
        "parent_key": p.parent_key, "folder": p.folder(),
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("list") => {
            let progs = programs::load_all();
            let count = |c: programs::Category| progs.iter().filter(|p| p.category == c && !p.is_update).count();
            let store = store::load();
            let startup = startup::load();
            let out = json!({
                "admin": util::is_admin(),
                "counts": { "apps": count(programs::Category::Apps), "system": count(programs::Category::System),
                            "hidden": count(programs::Category::Hidden), "updates": progs.iter().filter(|p| p.is_update).count(),
                            "store": store.len(), "startup": startup.len() },
                "programs": progs.iter().map(prog_json).collect::<Vec<_>>(),
                "startup": startup.iter().map(|i| format!("{:?}", i)).collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        }
        Some("uninstall") => {
            let name = args.get(2).expect("name");
            let how = args.get(3).map(|s| s.as_str()).unwrap_or("default");
            let timeout = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(900u64);
            let progs = programs::load_all();
            let Some(p) = progs.iter().find(|p| &p.name == name).cloned() else {
                println!("{}", json!({"error": format!("not found: {name}")}));
                std::process::exit(2);
            };
            let cmd = match how {
                "default" => p.uninstall_string.replace("/I{", "/X{"),
                "quiet" => p.quiet_uninstall.clone(),
                other => other.to_string(),
            };
            let t0 = Instant::now();
            let code = util::run_and_wait(&cmd).map_err(|e| e.to_string());
            // Uninstallers often hand off to a temp copy (NSIS Au_.exe, Inno _iu*.tmp) or msiexec;
            // wait until the entry is gone, then give file deletes a moment to finish.
            while programs::entry_exists(&p) && t0.elapsed() < Duration::from_secs(timeout) {
                std::thread::sleep(Duration::from_secs(3));
            }
            std::thread::sleep(Duration::from_secs(10));
            let left = leftovers::scan(&p, None);
            let out = json!({
                "program": prog_json(&p), "command": cmd, "exit": code,
                "seconds": t0.elapsed().as_secs(), "entry_still_present": programs::entry_exists(&p),
                "leftovers": left.iter().map(|l| json!({"kind": format!("{:?}", l.kind), "path": l.label(), "size": l.size, "checked": l.checked})).collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        }
        _ => eprintln!("usage: clone-harness list | uninstall <name> <cmd|default|quiet> [timeout_s]"),
    }
}
