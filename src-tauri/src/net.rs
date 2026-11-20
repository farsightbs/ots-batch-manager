//! Network access: calendar servers (stamp / upgrade) and Esplora block explorers (verify).

use crate::ots::{parse_timestamp, Timestamp};
use sha2::{Digest, Sha256};
use std::{sync::OnceLock, time::Duration};

const ACCEPT: &str = "application/vnd.opentimestamps.v1";
const MAX_RESPONSE: usize = 10_000;

fn client() -> &'static reqwest::Client {
    static C: OnceLock<reqwest::Client> = OnceLock::new();
    C.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("OTS-Manager/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("HTTP client")
    })
}

fn e2s(e: reqwest::Error) -> String {
    e.to_string()
}

async fn read_timestamp(resp: reqwest::Response) -> Result<Timestamp, String> {
    let b = resp.bytes().await.map_err(e2s)?;
    if b.len() > MAX_RESPONSE {
        return Err("Calendar response too large".into());
    }
    parse_timestamp(&b)
}

/// POST a digest to a calendar; returns the (pending) timestamp for that digest.
pub async fn submit(calendar: &str, digest: &[u8]) -> Result<Timestamp, String> {
    let url = format!("{}/digest", calendar.trim_end_matches('/'));
    let resp = client().post(&url).header("Accept", ACCEPT).body(digest.to_vec()).send().await.map_err(e2s)?;
    if !resp.status().is_success() {
        return Err(format!("{url}: HTTP {}", resp.status()));
    }
    read_timestamp(resp).await
}

/// Ask a calendar for the upgraded timestamp of a commitment. Ok(None) = not confirmed yet.
pub async fn fetch_upgrade(calendar: &str, commitment: &[u8]) -> Result<Option<Timestamp>, String> {
    let url = format!("{}/timestamp/{}", calendar.trim_end_matches('/'), hex::encode(commitment));
    let resp = client().get(&url).header("Accept", ACCEPT).send().await.map_err(e2s)?;
    match resp.status() {
        s if s.is_success() => read_timestamp(resp).await.map(Some),
        reqwest::StatusCode::NOT_FOUND => Ok(None),
        s => Err(format!("{url}: HTTP {s}")),
    }
}

async fn get_text(url: &str) -> Result<String, String> {
    let resp = client().get(url).send().await.map_err(e2s)?;
    if !resp.status().is_success() {
        return Err(format!("{url}: HTTP {}", resp.status()));
    }
    resp.text().await.map_err(e2s)
}

/// Raw 80-byte Bitcoin block header at `height`, from the first explorer that answers consistently.
pub async fn block_header(explorers: &[String], height: u64) -> Result<Vec<u8>, String> {
    let mut errors = Vec::new();
    for base in explorers {
        match header_from(base.trim_end_matches('/'), height).await {
            Ok(h) => return Ok(h),
            Err(e) => errors.push(e),
        }
    }
    Err(if errors.is_empty() { "No block explorer configured".into() } else { errors.join("; ") })
}

async fn header_from(base: &str, height: u64) -> Result<Vec<u8>, String> {
    let hash = get_text(&format!("{base}/block-height/{height}")).await?.trim().to_lowercase();
    let header = hex::decode(get_text(&format!("{base}/block/{hash}/header")).await?.trim())
        .map_err(|_| format!("{base}: invalid header"))?;
    // The header must hash to the block hash the explorer announced.
    let mut h = Sha256::digest(Sha256::digest(&header)).to_vec();
    h.reverse();
    if header.len() != 80 || hex::encode(h) != hash {
        return Err(format!("{base}: inconsistent block header"));
    }
    Ok(header)
}

#[cfg(test)]
mod live_tests {
    //! Hit real servers: `cargo test -- --ignored`
    use super::*;
    use crate::ots::{Attestation, DetachedFile, Op};

    /// Genesis block has a single tx, so its merkle root = sha256d(coinbase): a real, verifiable proof.
    #[tokio::test]
    #[ignore]
    async fn genesis_proof_verifies() {
        let explorers = vec!["https://mempool.space/api".to_string(), "https://blockstream.info/api".to_string()];
        let txid = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
        let tx = hex::decode(get_text(&format!("{}/tx/{txid}/hex", explorers[0])).await.unwrap().trim()).unwrap();
        let file = DetachedFile {
            hash_op: Op::Sha256,
            digest: Sha256::digest(&tx).to_vec(),
            ts: Timestamp { attestations: vec![], ops: vec![(Op::Sha256, Timestamp { attestations: vec![Attestation::Bitcoin(0)], ops: vec![] })] },
        };
        let file = DetachedFile::parse(&file.to_bytes()).unwrap();
        let (msg, a) = file.ts.attestations_with_msg(&file.digest).pop().unwrap();
        assert_eq!(a, Attestation::Bitcoin(0));
        for e in &explorers {
            let header = block_header(&[e.clone()], 0).await.unwrap();
            assert_eq!(&header[36..68], &msg[..], "{e}");
        }
    }

    #[tokio::test]
    #[ignore]
    async fn calendars_accept_digest() {
        let digest = Sha256::digest(b"ots-manager live test").to_vec();
        for c in ["https://a.pool.opentimestamps.org", "https://b.pool.opentimestamps.org", "https://a.pool.eternitywall.com", "https://ots.btc.catallaxy.com"] {
            match submit(c, &digest).await {
                Ok(ts) => {
                    for (msg, a) in ts.attestations_with_msg(&digest) {
                        println!("{c} -> {a:?}");
                        if let Attestation::Pending(uri) = a {
                            println!("   upgrade now: {:?}", fetch_upgrade(&uri, &msg).await.map(|o| o.is_some()));
                        }
                    }
                }
                Err(e) => println!("{c} -> ERROR {e}"),
            }
        }
    }
}
