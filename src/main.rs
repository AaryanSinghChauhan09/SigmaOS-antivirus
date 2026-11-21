//! SigmaOS-antivirus — antivirus scanner CLI.
//!
//! Usage:
//!   sigmaos-av status|sigs|kinds
//!   sigmaos-av sig-add <id> <name> <kind> <needle> <severity>
//!   sigmaos-av sig-del <id> | sig-enable <id> on|off
//!   sigmaos-av scan <path> [--json]
//!   sigmaos-av quarantine <path> --to <dir>   (rescans then quarantines hits)

use antivirus::{HostFs, SigmaOSAv, SigKind};
use std::path::{Path, PathBuf};
use std::process::exit;

fn usage() -> ! {
    eprintln!("usage: sigmaos-av <status|sigs|kinds|sig-add|sig-del|sig-enable|scan|quarantine> [args]");
    exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() { usage(); }
    let db = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/tmp".into()))
        .join(".local/share/sigmaos/av-signatures.json");
    let mut m = SigmaOSAv::load(&db).unwrap_or_else(|_| SigmaOSAv::new());
    let cmd = args[0].as_str();
    let rest = &args[1..];
    let arg = |i: usize| -> &str { rest.get(i).map(|s| s.as_str()).unwrap_or_else(|| usage()) };
    let fs = HostFs;

    let result: Result<(), String> = (|| -> Result<(), String> { match cmd {
        "status" => { println!("{}", m.status_line()); Ok(()) }
        "sigs" => {
            for s in m.signatures() {
                println!("{:<18} {:<10} {:<10} sev={} {} {}", s.id, s.kind.label(),
                    if s.enabled {"on"} else {"off"}, s.severity, s.name, s.needle);
            }
            Ok(())
        }
        "kinds" => {
            for k in [SigKind::Malware, SigKind::Pua, SigKind::Riskware, SigKind::Heuristic] {
                println!("{:<10} {}", k.label(), m.signatures().filter(|s| s.kind==k).count());
            }
            Ok(())
        }
        "sig-add" => {
            let kind = SigKind::parse(arg(2)).ok_or_else(|| format!("bad kind {}", arg(2)))?;
            let sev: u8 = arg(4).parse().map_err(|_| "bad severity".to_string())?;
            m.add_signature(arg(0), arg(1), kind, arg(3), sev).map_err(|e| e.to_string())?;
            println!("added {}", arg(0)); Ok(())
        }
        "sig-del" => { m.remove_signature(arg(0)).map_err(|e| e.to_string())?; println!("removed {}", arg(0)); Ok(()) }
        "sig-enable" => {
            let on = match arg(1) { "on"|"true"|"1"=>true, "off"|"false"|"0"=>false, _=>return Err("bad on/off".into()) };
            m.set_signature_enabled(arg(0), on).map_err(|e| e.to_string())?;
            println!("{} {}", arg(0), if on {"enabled"} else {"disabled"}); Ok(())
        }
        "scan" => {
            let root = PathBuf::from(arg(0));
            let rep = m.scan(&root, &fs).map_err(|e| e.to_string())?;
            if rest.contains(&"--json".to_string()) {
                let hits: Vec<_> = rep.hits.iter().map(|h| serde_json::json!({
                    "path": h.path, "sig": h.signature, "name": h.sig_name,
                    "kind": h.kind.label(), "severity": h.severity })).collect();
                println!("{}", serde_json::json!({
                    "root": rep.root, "files": rep.files_scanned, "bytes": rep.bytes_scanned,
                    "hits": hits, "skipped": rep.skipped, "errors": rep.errors }));
            } else {
                println!("scan {}: {} files, {} bytes, {} hits ({} skipped, {} errors)",
                    rep.root.display(), rep.files_scanned, rep.bytes_scanned,
                    rep.hits.len(), rep.skipped, rep.errors);
                for h in rep.hits.iter().take(50) {
                    println!("  HIT sev={} {:<10} {} -> {}", h.severity, h.kind.label(), h.sig_name, h.path.display());
                }
                if rep.hits.len() > 50 { println!("  ... {} more", rep.hits.len()-50); }
            }
            if rep.infected() { std::process::exit(1); }
            Ok(())
        }
        "quarantine" => {
            let root = PathBuf::from(arg(0));
            let qi = rest.iter().position(|a| a=="--to").ok_or("need --to <dir>")?;
            let qdir = PathBuf::from(rest.get(qi+1).ok_or("need --to <dir>")?);
            let rep = m.scan(&root, &fs).map_err(|e| e.to_string())?;
            let moved = m.quarantine_hits(&rep, &qdir, &fs).map_err(|e| e.to_string())?;
            println!("quarantined {} file(s) -> {}", moved.len(), qdir.display());
            for p in &moved { println!("  {}", p.display()); }
            Ok(())
        }
        _ => usage(),
    } })();

    match result {
        Ok(()) => {
            if let Err(e) = m.save(&db) { eprintln!("sigmaos-av: warn: sig db save: {e}"); }
        }
        Err(e) => { eprintln!("sigmaos-av: {e}"); exit(1); }
    }
}
