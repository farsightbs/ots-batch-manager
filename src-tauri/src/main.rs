#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod net;
mod ots;

use ots::{hash_file, Attestation, DetachedFile, Op, Timestamp};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    ffi::OsStr,
    path::{Path, PathBuf},
    sync::Mutex,
};

const SUBDIR: &str = "OTS-Files";
/// Calendar domains trusted for upgrades (same whitelist as the reference client).
const TRUSTED_CALENDAR_SUFFIXES: [&str; 3] =
    [".calendar.opentimestamps.org", ".calendar.eternitywall.com", ".calendar.catallaxy.com"];

#[derive(Default)]
struct HeaderCache(Mutex<HashMap<u64, Vec<u8>>>);

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T, String> + Send + 'static) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|e| e.to_string())?
}

// ---------- path conventions ----------

fn ots_target(original: &Path, same_dir: bool) -> PathBuf {
    let mut name = original.file_name().unwrap_or_default().to_os_string();
    name.push(".ots");
    let dir = original.parent().unwrap_or(Path::new("."));
    if same_dir { dir.join(name) } else { dir.join(SUBDIR).join(name) }
}

fn ots_candidates(original: &Path) -> [PathBuf; 2] {
    [ots_target(original, false), ots_target(original, true)]
}

fn original_for(ots: &Path) -> Option<PathBuf> {
    let name = ots.file_name()?.to_str()?.strip_suffix(".ots")?;
    let mut dir = ots.parent()?;
    if dir.file_name() == Some(OsStr::new(SUBDIR)) {
        dir = dir.parent()?;
    }
    Some(dir.join(name))
}

/// Write via a temp file + rename so an interrupted write never leaves a corrupt proof.
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let err = |e: std::io::Error| format!("{}: {e}", path.display());
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(err)?;
    }
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    std::fs::write(&tmp, bytes).map_err(err)?;
    std::fs::rename(&tmp, path).map_err(err)
}

fn backup(path: &Path) -> Result<(), String> {
    let mut bak = path.as_os_str().to_os_string();
    bak.push(".bak");
    std::fs::copy(path, &bak).map(|_| ()).map_err(|e| format!("{}: {e}", path.display()))
}

fn ots_matches(original: &Path, ots: &Path, sha256: &[u8]) -> bool {
    let Ok(f) = DetachedFile::read(ots) else { return false };
    if f.hash_op == Op::Sha256 {
        f.digest == sha256
    } else {
        hash_file(original, &f.hash_op).map(|h| h == f.digest).unwrap_or(false)
    }
}

fn host(url: &str) -> Option<&str> {
    url.strip_prefix("https://")?.split(['/', ':']).next()
}

fn calendar_trusted(uri: &str, calendars: &[String]) -> bool {
    let Some(h) = host(uri) else { return false };
    TRUSTED_CALENDAR_SUFFIXES.iter().any(|s| h.ends_with(s)) || calendars.iter().any(|c| host(c) == Some(h))
}

// ---------- commands: files ----------

/// Expand dropped/selected paths: folders are walked recursively, hidden files skipped.
#[tauri::command]
async fn expand_paths(paths: Vec<String>) -> Result<Vec<String>, String> {
    fn walk(p: &Path, out: &mut Vec<String>) {
        if p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with('.')) {
            return;
        }
        if p.is_dir() {
            let Ok(rd) = std::fs::read_dir(p) else { return };
            let mut entries: Vec<_> = rd.flatten().map(|e| e.path()).collect();
            entries.sort();
            entries.iter().for_each(|e| walk(e, out));
        } else if p.is_file() {
            out.push(p.to_string_lossy().into_owned());
        }
    }
    blocking(move || {
        let mut out = Vec::new();
        paths.iter().for_each(|p| walk(Path::new(p), &mut out));
        Ok(out)
    })
    .await
}

#[tauri::command]
async fn hash_sha256(path: String) -> Result<String, String> {
    blocking(move || hash_file(Path::new(&path), &Op::Sha256).map(hex::encode)).await
}

#[tauri::command]
fn find_ots(path: String) -> Option<String> {
    ots_candidates(Path::new(&path)).into_iter().find(|c| c.is_file()).map(|c| c.to_string_lossy().into_owned())
}

#[tauri::command]
fn find_original(ots: String) -> Option<String> {
    original_for(Path::new(&ots)).filter(|p| p.is_file()).map(|p| p.to_string_lossy().into_owned())
}

// ---------- commands: create ----------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateInfo {
    existing: Option<String>,
    matches: bool,
}

/// Look for an existing proof (in OTS-Files/ or next to the file) and check it matches the file.
#[tauri::command]
async fn inspect_original(path: String) -> Result<CreateInfo, String> {
    blocking(move || {
        let p = Path::new(&path);
        let digest = hash_file(p, &Op::Sha256)?;
        let mut info = CreateInfo { existing: None, matches: false };
        for c in ots_candidates(p).into_iter().filter(|c| c.is_file()) {
            info.matches = ots_matches(p, &c, &digest);
            info.existing = Some(c.to_string_lossy().into_owned());
            if info.matches {
                break;
            }
        }
        Ok(info)
    })
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StampResult {
    ots_path: Option<String>,
    error: Option<String>,
}

/// Merkle tree over the leaves (odd node carried up, as in the reference client).
/// Returns the root and, for each leaf, the ops leading from the leaf to the root.
fn merkle_paths(leaves: &[Vec<u8>]) -> (Vec<u8>, Vec<Vec<Op>>) {
    let mut paths = vec![Vec::new(); leaves.len()];
    let mut level: Vec<(Vec<u8>, Vec<usize>)> = leaves.iter().cloned().enumerate().map(|(i, d)| (d, vec![i])).collect();
    while level.len() > 1 {
        let mut next = Vec::new();
        let mut it = level.into_iter();
        while let Some((l, li)) = it.next() {
            match it.next() {
                Some((r, ri)) => {
                    li.iter().for_each(|&i| paths[i].extend([Op::Append(r.clone()), Op::Sha256]));
                    ri.iter().for_each(|&i| paths[i].extend([Op::Prepend(l.clone()), Op::Sha256]));
                    next.push((Sha256::digest([l, r].concat()).to_vec(), [li, ri].concat()));
                }
                None => next.push((l, li)),
            }
        }
        level = next;
    }
    (level.pop().map(|(d, _)| d).unwrap_or_default(), paths)
}

fn chain(ops: Vec<Op>, end: Timestamp) -> Timestamp {
    ops.into_iter().rev().fold(end, |acc, op| Timestamp { attestations: vec![], ops: vec![(op, acc)] })
}

/// Timestamp a batch of files with a single calendar round-trip (one Merkle root for the batch).
#[tauri::command]
async fn stamp_files(paths: Vec<String>, same_dir: bool, calendars: Vec<String>) -> Result<Vec<StampResult>, String> {
    let ps = paths.clone();
    let digests: Vec<Result<Vec<u8>, String>> =
        blocking(move || Ok(ps.iter().map(|p| hash_file(Path::new(p), &Op::Sha256)).collect())).await?;

    // Per-file random nonce so the calendar never learns the file hash.
    let mut leaves = Vec::new();
    let mut prefix_ops = Vec::new();
    for d in digests.iter().flatten() {
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).map_err(|e| e.to_string())?;
        leaves.push(Sha256::digest([d.as_slice(), &nonce].concat()).to_vec());
        prefix_ops.push(vec![Op::Append(nonce.to_vec()), Op::Sha256]);
    }
    if leaves.is_empty() {
        return Ok(digests.into_iter().map(|d| StampResult { ots_path: None, error: d.err() }).collect());
    }
    let (root, merkle) = merkle_paths(&leaves);

    let handles: Vec<_> = calendars
        .iter()
        .map(|c| {
            let (c, root) = (c.clone(), root.clone());
            tauri::async_runtime::spawn(async move { net::submit(&c, &root).await })
        })
        .collect();
    let mut tip = Timestamp::default();
    let mut errors = Vec::new();
    for h in handles {
        match h.await.map_err(|e| e.to_string()).and_then(|r| r) {
            Ok(ts) => tip.merge(ts),
            Err(e) => errors.push(e),
        }
    }
    if tip == Timestamp::default() {
        return Err(format!("No calendar server answered: {}", errors.join("; ")));
    }

    blocking(move || {
        let mut leaf = prefix_ops.into_iter().zip(merkle);
        Ok(paths
            .iter()
            .zip(digests)
            .map(|(p, d)| {
                let d = match d {
                    Ok(d) => d,
                    Err(e) => return StampResult { ots_path: None, error: Some(e) },
                };
                let (prefix, path) = leaf.next().unwrap();
                let file = DetachedFile { hash_op: Op::Sha256, digest: d, ts: chain([prefix, path].concat(), tip.clone()) };
                let target = ots_target(Path::new(p), same_dir);
                // Never destroy an existing (non-matching) proof: keep it as .ots.bak.
                let res = if target.is_file() { backup(&target) } else { Ok(()) }
                    .and_then(|_| atomic_write(&target, &file.to_bytes()));
                match res {
                    Ok(()) => StampResult { ots_path: Some(target.to_string_lossy().into_owned()), error: None },
                    Err(e) => StampResult { ots_path: None, error: Some(e) },
                }
            })
            .collect())
    })
    .await
}

// ---------- commands: upgrade ----------

#[tauri::command]
async fn ots_complete(path: String) -> Result<bool, String> {
    blocking(move || DetachedFile::read(Path::new(&path)).map(|f| f.is_complete())).await
}

/// Returns "complete" (nothing to do), "upgraded" or "pending" (not confirmed in Bitcoin yet).
#[tauri::command]
async fn upgrade_file(path: String, backup_original: bool, calendars: Vec<String>) -> Result<String, String> {
    let p = PathBuf::from(&path);
    let mut file = { let p = p.clone(); blocking(move || DetachedFile::read(&p)).await? };
    if file.is_complete() {
        return Ok("complete".into());
    }
    let mut pending: Vec<(Vec<u8>, String)> = file
        .ts
        .attestations_with_msg(&file.digest)
        .into_iter()
        .filter_map(|(msg, a)| match a {
            Attestation::Pending(uri) => Some((msg, uri)),
            _ => None,
        })
        .collect();
    pending.dedup();

    let mut changed = false;
    let mut errors = Vec::new();
    for (commitment, uri) in &pending {
        if !calendar_trusted(uri, &calendars) {
            errors.push(format!("Untrusted calendar skipped: {uri}"));
            continue;
        }
        match net::fetch_upgrade(uri, commitment).await {
            Ok(Some(up)) => {
                let digest = file.digest.clone();
                changed |= file.ts.merge_at(&digest, commitment, &up);
            }
            Ok(None) => {}
            Err(e) => errors.push(e),
        }
    }
    if !changed {
        return if !errors.is_empty() && errors.len() == pending.len() { Err(errors.join("; ")) } else { Ok("pending".into()) };
    }
    let complete = file.is_complete();
    blocking(move || {
        if backup_original {
            backup(&p)?;
        }
        atomic_write(&p, &file.to_bytes())
    })
    .await?;
    Ok(if complete { "upgraded" } else { "pending" }.into())
}

// ---------- commands: verify ----------

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct VerifyResult {
    digest: String,
    complete: bool,
    /// valid | pending | invalid | error
    status: String,
    detail: String,
    height: Option<u64>,
    time: Option<u32>,
}

#[tauri::command]
async fn verify(
    original: String,
    ots: String,
    explorers: Vec<String>,
    cache: tauri::State<'_, HeaderCache>,
) -> Result<VerifyResult, String> {
    verify_pair(original, ots, &explorers, &cache).await
}

async fn verify_pair(original: String, ots: String, explorers: &[String], cache: &HeaderCache) -> Result<VerifyResult, String> {
    let (sha, file, matches) = blocking(move || {
        let p = Path::new(&original);
        let sha = hash_file(p, &Op::Sha256)?;
        let file = DetachedFile::read(Path::new(&ots))?;
        let file_digest = if file.hash_op == Op::Sha256 { sha.clone() } else { hash_file(p, &file.hash_op)? };
        let matches = file_digest == file.digest;
        Ok((sha, file, matches))
    })
    .await?;

    let mut res = VerifyResult { digest: hex::encode(sha), complete: file.is_complete(), ..Default::default() };
    if !matches {
        res.status = "invalid".into();
        res.detail = "File hash does not match the OTS proof".into();
        return Ok(res);
    }

    let mut errors = Vec::new();
    let mut mismatch = None;
    for (msg, a) in file.ts.attestations_with_msg(&file.digest) {
        let Attestation::Bitcoin(height) = a else { continue };
        let cached = cache.0.lock().unwrap().get(&height).cloned();
        let header = match cached {
            Some(h) => h,
            None => match net::block_header(explorers, height).await {
                Ok(h) => {
                    cache.0.lock().unwrap().insert(height, h.clone());
                    h
                }
                Err(e) => {
                    errors.push(e);
                    continue;
                }
            },
        };
        if msg.len() == 32 && header[36..68] == msg[..] {
            if res.height.is_none_or(|h| height < h) {
                res.height = Some(height);
                res.time = Some(u32::from_le_bytes(header[68..72].try_into().unwrap()));
            }
        } else {
            mismatch = Some(height);
        }
    }
    (res.status, res.detail) = match (res.height, mismatch, res.complete) {
        (Some(_), _, _) => ("valid".into(), String::new()),
        (None, Some(h), _) => ("invalid".into(), format!("Merkle root does not match Bitcoin block {h}")),
        (None, None, true) => ("error".into(), errors.join("; ")),
        (None, None, false) => ("pending".into(), "Not yet anchored in the Bitcoin blockchain".into()),
    };
    Ok(res)
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .manage(HeaderCache::default())
        .invoke_handler(tauri::generate_handler![
            expand_paths,
            hash_sha256,
            find_ots,
            find_original,
            inspect_original,
            stamp_files,
            ots_complete,
            upgrade_file,
            verify
        ])
        .run(tauri::generate_context!())
        .expect("error while running OTS Manager");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_paths_reach_root() {
        for n in 1..=9 {
            let leaves: Vec<Vec<u8>> = (0..n).map(|i| Sha256::digest([i as u8]).to_vec()).collect();
            let (root, paths) = merkle_paths(&leaves);
            for (leaf, ops) in leaves.iter().zip(paths) {
                assert_eq!(ops.iter().fold(leaf.clone(), |m, op| op.apply(&m)), root, "n={n}");
            }
        }
    }

    #[test]
    fn path_conventions() {
        let f = Path::new("/a/b/doc.pdf");
        assert_eq!(ots_target(f, false), Path::new("/a/b/OTS-Files/doc.pdf.ots"));
        assert_eq!(ots_target(f, true), Path::new("/a/b/doc.pdf.ots"));
        assert_eq!(original_for(Path::new("/a/b/OTS-Files/doc.pdf.ots")).unwrap(), f);
        assert_eq!(original_for(Path::new("/a/b/doc.pdf.ots")).unwrap(), f);
    }

    /// End-to-end against real calendars and explorers: `cargo test -- --ignored`
    #[tokio::test]
    #[ignore]
    async fn create_verify_upgrade_workflow() {
        let cals: Vec<String> = ["https://a.pool.opentimestamps.org", "https://b.pool.opentimestamps.org"].map(String::from).to_vec();
        let exps = vec!["https://mempool.space/api".to_string()];
        let dir = std::env::temp_dir().join(format!("ots-e2e-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let files: Vec<String> = (0..5).map(|i| {
            let p = dir.join(format!("doc{i}.txt"));
            std::fs::write(&p, format!("content {i}")).unwrap();
            p.to_string_lossy().into_owned()
        }).collect();

        let res = stamp_files(files.clone(), false, cals.clone()).await.unwrap();
        assert!(res.iter().all(|r| r.error.is_none()));
        assert!(dir.join("OTS-Files/doc0.txt.ots").is_file());

        let info = inspect_original(files[0].clone()).await.unwrap();
        assert!(info.matches);
        let cache = HeaderCache::default();
        let ots0 = find_ots(files[0].clone()).unwrap();
        let v = verify_pair(files[0].clone(), ots0.clone(), &exps, &cache).await.unwrap();
        assert_eq!((v.status.as_str(), v.complete), ("pending", false));

        assert_eq!(upgrade_file(ots0.clone(), true, cals.clone()).await.unwrap(), "pending");
        assert_eq!(find_original(ots0.clone()).unwrap(), files[0]);

        std::fs::write(&files[1], "tampered").unwrap();
        let v = verify_pair(files[1].clone(), find_ots(files[1].clone()).unwrap(), &exps, &cache).await.unwrap();
        assert_eq!(v.status, "invalid");
        let info = inspect_original(files[1].clone()).await.unwrap();
        assert!(info.existing.is_some() && !info.matches);
        // Re-stamping a mismatched proof keeps the old one as .bak
        stamp_files(vec![files[1].clone()], false, cals.clone()).await.unwrap();
        assert!(dir.join("OTS-Files/doc1.txt.ots.bak").is_file());
        assert!(inspect_original(files[1].clone()).await.unwrap().matches);

        // Complete proof: genesis coinbase (block 0 merkle root = sha256d(tx)).
        let tx = hex::decode("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000").unwrap();
        let g = dir.join("genesis.bin");
        std::fs::write(&g, &tx).unwrap();
        let f = DetachedFile { hash_op: Op::Sha256, digest: Sha256::digest(&tx).to_vec(),
            ts: Timestamp { attestations: vec![], ops: vec![(Op::Sha256, Timestamp { attestations: vec![Attestation::Bitcoin(0)], ops: vec![] })] } };
        let gots = ots_target(&g, false);
        atomic_write(&gots, &f.to_bytes()).unwrap();
        assert_eq!(upgrade_file(gots.to_string_lossy().into(), false, cals).await.unwrap(), "complete");
        let v = verify_pair(g.to_string_lossy().into(), gots.to_string_lossy().into(), &exps, &cache).await.unwrap();
        assert_eq!((v.status.as_str(), v.height, v.time), ("valid", Some(0), Some(1231006505)));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn calendar_whitelist() {
        let cals = vec!["https://a.pool.opentimestamps.org".to_string()];
        assert!(calendar_trusted("https://alice.btc.calendar.opentimestamps.org", &cals));
        assert!(calendar_trusted("https://a.pool.opentimestamps.org", &cals));
        assert!(!calendar_trusted("https://evil.example.com", &cals));
        assert!(!calendar_trusted("http://alice.btc.calendar.opentimestamps.org", &cals));
    }
}
