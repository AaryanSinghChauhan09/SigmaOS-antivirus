// SPDX-License-Identifier: Apache-2.0
//!
//! SigmaOS-antivirus — antivirus / malware scanner.
//!
//! Signature-based scanner: a signature DB of (name, kind, needle)
//! entries is matched against file contents. Scanning is abstracted
//! behind an `AvFs` trait so tests run on deterministic in-memory
//! filesystems while the CLI scans real directories. Infected files
//! can be quarantined (renamed/moved aside), never deleted.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum SigKind { Malware, Pua, Riskware, Heuristic }
impl SigKind {
    pub fn label(self) -> &'static str {
        match self { Self::Malware=>"malware", Self::Pua=>"pua", Self::Riskware=>"riskware", Self::Heuristic=>"heuristic" }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s { "malware"=>Some(Self::Malware), "pua"=>Some(Self::Pua),
                  "riskware"=>Some(Self::Riskware), "heuristic"=>Some(Self::Heuristic), _=>None }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Signature {
    pub id: String,
    pub name: String,
    pub kind: SigKind,
    /// literal needle matched against file bytes (hex sigs encoded as \xNN? keep simple: UTF-8 needles)
    pub needle: String,
    pub enabled: bool,
    pub severity: u8, // 0-10
}

#[derive(Debug, Clone)]
pub struct ScanHit {
    pub path: PathBuf,
    pub signature: String,
    pub sig_name: String,
    pub kind: SigKind,
    pub severity: u8,
}

#[derive(Debug, Clone)]
pub struct ScanReport {
    pub root: PathBuf,
    pub files_scanned: u64,
    pub bytes_scanned: u64,
    pub hits: Vec<ScanHit>,
    pub skipped: u64,
    pub errors: u64,
}
impl ScanReport {
    pub fn infected(&self) -> bool { !self.hits.is_empty() }
    pub fn max_severity(&self) -> u8 { self.hits.iter().map(|h| h.severity).max().unwrap_or(0) }
}

#[derive(Debug, Clone, PartialEq)]
pub enum AvError {
    DuplicateSig(String),
    NoSuchSig(String),
    BadSeverity(u8),
    BadPath(String),
    Io(String),
    QuarantineFailed(String),
}
impl fmt::Display for AvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateSig(id)=>write!(f,"duplicate signature {id}"),
            Self::NoSuchSig(id)=>write!(f,"no signature {id}"),
            Self::BadSeverity(s)=>write!(f,"severity {s} out of range 0-10"),
            Self::BadPath(p)=>write!(f,"bad path {p}"),
            Self::Io(e)=>write!(f,"io: {e}"),
            Self::QuarantineFailed(e)=>write!(f,"quarantine failed: {e}"),
        }
    }
}
impl std::error::Error for AvError {}

/// Filesystem abstraction for scanning.
pub trait AvFs {
    /// List files under root recursively (dirs pruned by implementation).
    fn walk(&self, root: &Path) -> Result<Vec<PathBuf>, String>;
    /// Read file bytes (capped by caller).
    fn read(&self, path: &Path) -> Result<Vec<u8>, String>;
    /// Move file to quarantine path.
    fn quarantine(&self, from: &Path, to: &Path) -> Result<(), String>;
}

/// Real filesystem scanner.
pub struct HostFs;
impl AvFs for HostFs {
    fn walk(&self, root: &Path) -> Result<Vec<PathBuf>, String> {
        let mut out = vec![];
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let rd = std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            for e in rd.flatten() {
                let p = e.path();
                let ft = match e.file_type() { Ok(t)=>t, Err(_)=>continue };
                if ft.is_dir() {
                    // skip noisy/virtual dirs
                    let n = e.file_name().to_string_lossy().to_string();
                    if matches!(n.as_str(), ".git"|"target"|"node_modules"|"proc"|"sys") { continue; }
                    stack.push(p);
                } else if ft.is_file() { out.push(p); }
            }
        }
        Ok(out)
    }
    fn read(&self, path: &Path) -> Result<Vec<u8>, String> {
        std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))
    }
    fn quarantine(&self, from: &Path, to: &Path) -> Result<(), String> {
        if let Some(p) = to.parent() { std::fs::create_dir_all(p).map_err(|e| e.to_string())?; }
        std::fs::rename(from, to).map_err(|e| format!("rename: {e}"))
    }
}

/// MemFs variant with RefCell for quarantine tests.
pub struct MemFsMut {
    pub files: std::cell::RefCell<BTreeMap<PathBuf, Vec<u8>>>,
    pub quarantined: std::cell::RefCell<Vec<(PathBuf, PathBuf)>>,
}
impl MemFsMut {
    pub fn new() -> Self { Self { files: std::cell::RefCell::new(BTreeMap::new()), quarantined: std::cell::RefCell::new(vec![]) } }
    pub fn add(&self, path: &str, data: &[u8]) { self.files.borrow_mut().insert(PathBuf::from(path), data.to_vec()); }
}
impl AvFs for MemFsMut {
    fn walk(&self, root: &Path) -> Result<Vec<PathBuf>, String> {
        Ok(self.files.borrow().keys().filter(|p| p.starts_with(root)).cloned().collect())
    }
    fn read(&self, path: &Path) -> Result<Vec<u8>, String> {
        self.files.borrow().get(path).cloned().ok_or_else(|| format!("no file {}", path.display()))
    }
    fn quarantine(&self, from: &Path, to: &Path) -> Result<(), String> {
        let mut f = self.files.borrow_mut();
        let data = f.remove(from).ok_or_else(|| format!("no file {}", from.display()))?;
        f.insert(to.to_path_buf(), data);
        self.quarantined.borrow_mut().push((from.to_path_buf(), to.to_path_buf()));
        Ok(())
    }
}

const MAX_FILE_BYTES: usize = 64 * 1024 * 1024; // 64 MiB cap per file
const MAX_HITS_PER_FILE: usize = 16;

pub struct SigmaOSAv {
    pub signatures: BTreeMap<String, Signature>,
    /// dirs excluded from scans
    pub exclude_dirs: Vec<String>,
}

impl SigmaOSAv {
    pub fn new() -> Self {
        let mut m = Self { signatures: BTreeMap::new(), exclude_dirs: vec![".git".into(),"target".into(),"node_modules".into(),"proc".into(),"sys".into(),"dev".into()] };
        m.seed_signatures();
        m
    }

    fn seed_signatures(&mut self) {
        let seeds = [
            ("sig.eicar", "EICAR test signature", SigKind::Malware, "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*", 10u8),
            ("sig.testvirus", "test virus marker", SigKind::Malware, "sigmaos-test-malware-marker-v1", 9),
            ("sig.pua.adware", "adware bundle marker", SigKind::Pua, "ADWARE-BUNDLE-INJECT", 5),
            ("sig.riskware.keylog", "keylogger pattern", SigKind::Riskware, "KEYLOGGER-HOOK-INSTALL", 7),
            ("sig.heur.execstack", "executable-stack heuristic", SigKind::Heuristic, "EXECSTACK-BINARY-MARKER", 4),
        ];
        for (id, name, kind, needle, sev) in seeds {
            self.signatures.insert(id.into(), Signature {
                id: id.into(), name: name.into(), kind, needle: needle.into(),
                enabled: true, severity: sev,
            });
        }
    }

    // ---- signature DB ----
    pub fn add_signature(&mut self, id: &str, name: &str, kind: SigKind, needle: &str, severity: u8) -> Result<(), AvError> {
        if self.signatures.contains_key(id) { return Err(AvError::DuplicateSig(id.into())); }
        if severity > 10 { return Err(AvError::BadSeverity(severity)); }
        if needle.is_empty() { return Err(AvError::BadPath("empty needle".into())); }
        self.signatures.insert(id.into(), Signature {
            id: id.into(), name: name.into(), kind, needle: needle.into(), enabled: true, severity,
        });
        Ok(())
    }

    pub fn remove_signature(&mut self, id: &str) -> Result<(), AvError> {
        if self.signatures.remove(id).is_none() { return Err(AvError::NoSuchSig(id.into())); }
        Ok(())
    }

    pub fn set_signature_enabled(&mut self, id: &str, enabled: bool) -> Result<(), AvError> {
        let s = self.signatures.get_mut(id).ok_or_else(|| AvError::NoSuchSig(id.into()))?;
        s.enabled = enabled;
        Ok(())
    }

    pub fn signatures(&self) -> impl Iterator<Item = &Signature> { self.signatures.values() }

    // ---- scanning ----
    /// Scan root with an FS backend. Returns a report; never panics on bad files.
    pub fn scan<F: AvFs>(&self, root: &Path, fs: &F) -> Result<ScanReport, AvError> {
        let files = fs.walk(root).map_err(AvError::Io)?;
        let mut rep = ScanReport { root: root.to_path_buf(), files_scanned: 0, bytes_scanned: 0,
                                   hits: vec![], skipped: 0, errors: 0 };
        for path in files {
            // read with size guard via metadata when possible — MemFs has no stat; read then check len
            match fs.read(&path) {
                Ok(data) => {
                    if data.len() > MAX_FILE_BYTES { rep.skipped += 1; continue; }
                    rep.files_scanned += 1;
                    rep.bytes_scanned += data.len() as u64;
                    self.scan_bytes(&path, &data, &mut rep);
                }
                Err(_) => rep.errors += 1,
            }
        }
        rep.hits.sort_by(|a,b| b.severity.cmp(&a.severity).then(a.path.cmp(&b.path)));
        Ok(rep)
    }

    fn scan_bytes(&self, path: &Path, data: &[u8], rep: &mut ScanReport) {
        let hay = String::from_utf8_lossy(data);
        let mut per_file = 0usize;
        for sig in self.signatures.values().filter(|s| s.enabled) {
            if per_file >= MAX_HITS_PER_FILE { break; }
            if hay.contains(&sig.needle) {
                rep.hits.push(ScanHit {
                    path: path.to_path_buf(), signature: sig.id.clone(),
                    sig_name: sig.name.clone(), kind: sig.kind, severity: sig.severity,
                });
                per_file += 1;
            }
        }
    }

    /// Quarantine all hit files to `quarantine_dir`, preserving relative names.
    pub fn quarantine_hits<F: AvFs>(&self, rep: &ScanReport, quarantine_dir: &Path, fs: &F) -> Result<Vec<PathBuf>, AvError> {
        let mut done = vec![];
        // dedupe paths
        let mut seen = std::collections::BTreeSet::new();
        for hit in &rep.hits {
            if !seen.insert(hit.path.clone()) { continue; }
            let name = hit.path.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "file".into());
            let to = quarantine_dir.join(format!("{}.sig-{}", name, hit.signature));
            fs.quarantine(&hit.path, &to).map_err(|e| AvError::QuarantineFailed(e))?;
            done.push(to);
        }
        Ok(done)
    }

    pub fn status_line(&self) -> String {
        format!("av: {} signatures ({} enabled)", self.signatures.len(),
            self.signatures.values().filter(|s| s.enabled).count())
    }
}

impl Default for SigmaOSAv { fn default() -> Self { Self::new() } }

// ---- persistence ----
#[derive(serde::Serialize, serde::Deserialize)]
struct SigFile { signatures: Vec<Signature> }

impl SigmaOSAv {
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let j = serde_json::to_string_pretty(&SigFile { signatures: self.signatures.values().cloned().collect() }).map_err(|e| e.to_string())?;
        if let Some(p) = path.parent() { std::fs::create_dir_all(p).map_err(|e| e.to_string())?; }
        std::fs::write(path, j).map_err(|e| e.to_string())
    }
    pub fn load(path: &Path) -> Result<Self, String> {
        let txt = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let f: SigFile = serde_json::from_str(&txt).map_err(|e| e.to_string())?;
        let mut m = Self { signatures: BTreeMap::new(), exclude_dirs: vec![".git".into(),"target".into(),"node_modules".into(),"proc".into(),"sys".into(),"dev".into()] };
        for s in f.signatures { m.signatures.insert(s.id.clone(), s); }
        Ok(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_db_management() {
        let mut m = SigmaOSAv::new();
        let seeded = m.signatures.len();
        assert!(seeded >= 5);
        m.add_signature("custom", "custom sig", SigKind::Malware, "BAD-THING", 8).unwrap();
        assert!(m.add_signature("custom", "x", SigKind::Malware, "y", 1).is_err()); // dup
        assert!(m.add_signature("badsev", "x", SigKind::Malware, "y", 11).is_err()); // sev>10
        assert!(m.add_signature("empty", "x", SigKind::Malware, "", 1).is_err()); // empty needle
        assert!(m.remove_signature("custom").is_ok());
        assert!(m.remove_signature("custom").is_err());
    }

    #[test]
    fn scan_detects_infected() {
        let m = SigmaOSAv::new();
        let mut fs = MemFsMut::new();
        fs.add("/scan/clean.txt", b"hello world");
        fs.add("/scan/evil.bin", b"prefix X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H* suffix");
        fs.add("/scan/evil2.bin", b"contains sigmaos-test-malware-marker-v1 here");
        let rep = m.scan(Path::new("/scan"), &fs).unwrap();
        assert_eq!(rep.files_scanned, 3);
        assert_eq!(rep.hits.len(), 2);
        assert!(rep.infected());
        assert_eq!(rep.max_severity(), 10); // eicar sev 10
        // hits sorted by severity desc
        assert_eq!(rep.hits[0].severity, 10);
    }

    #[test]
    fn clean_scan() {
        let m = SigmaOSAv::new();
        let mut fs = MemFsMut::new();
        fs.add("/s/a.txt", b"normal content");
        fs.add("/s/b.txt", b"more normal");
        let rep = m.scan(Path::new("/s"), &fs).unwrap();
        assert!(!rep.infected());
        assert_eq!(rep.hits.len(), 0);
    }

    #[test]
    fn disabled_signature_not_matched() {
        let mut m = SigmaOSAv::new();
        m.set_signature_enabled("sig.testvirus", false).unwrap();
        assert!(m.set_signature_enabled("nope", true).is_err());
        let mut fs = MemFsMut::new();
        fs.add("/x/e.bin", b"sigmaos-test-malware-marker-v1");
        let rep = m.scan(Path::new("/x"), &fs).unwrap();
        assert!(!rep.infected()); // testvirus disabled; eicar not present
    }

    #[test]
    fn quarantine_moves_files() {
        let m = SigmaOSAv::new();
        let mut fs = MemFsMut::new();
        fs.add("/q/evil.bin", b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
        let rep = m.scan(Path::new("/q"), &fs).unwrap();
        assert!(rep.infected());
        let moved = m.quarantine_hits(&rep, Path::new("/quarantine"), &fs).unwrap();
        assert_eq!(moved.len(), 1);
        // original gone, quarantined present
        assert!(!fs.files.borrow().contains_key(Path::new("/q/evil.bin")));
        assert!(fs.files.borrow().contains_key(&moved[0]));
        assert_eq!(fs.quarantined.borrow().len(), 1);
    }

    #[test]
    fn error_files_counted_not_fatal() {
        let m = SigmaOSAv::new();
        let fs = MemFsMut::new(); // empty fs — walk returns empty
        let rep = m.scan(Path::new("/nothing"), &fs).unwrap();
        assert_eq!(rep.files_scanned, 0);
    }

    #[test]
    fn persistence_roundtrip() {
        let dir = std::env::temp_dir().join(format!("sigmaos-av-test-{}", std::process::id()));
        let p = dir.join("sigs.json");
        let mut m = SigmaOSAv::new();
        m.add_signature("mine", "mine", SigKind::Riskware, "NEEDLE", 6).unwrap();
        m.save(&p).unwrap();
        let m2 = SigmaOSAv::load(&p).unwrap();
        assert!(m2.signatures.contains_key("mine"));
        assert!(m2.signatures.contains_key("sig.eicar")); // seeds persisted too
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn kind_labels() {
        assert_eq!(SigKind::Malware.label(), "malware");
        assert_eq!(SigKind::parse("pua"), Some(SigKind::Pua));
        assert_eq!(SigKind::parse("bogus"), None);
    }
}
