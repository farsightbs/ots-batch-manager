//! OpenTimestamps proof format: parsing, serialization, merging and traversal.
//! Mirrors the reference implementation (python-opentimestamps `core/timestamp.py`, `core/op.py`, `core/notary.py`).

use sha2::{Digest, Sha256};
use std::{fs::File, io::Read, path::Path};

pub const MAGIC: &[u8] = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";
const TAG_PENDING: [u8; 8] = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];
const TAG_BITCOIN: [u8; 8] = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];
const MAX_DEPTH: usize = 256;
const MAX_ARG: usize = 4096;

#[derive(Clone, Debug, PartialEq)]
pub enum Op {
    Sha1,
    Ripemd160,
    Sha256,
    Keccak256,
    Append(Vec<u8>),
    Prepend(Vec<u8>),
    Reverse,
    Hexlify,
}

impl Op {
    fn tag(&self) -> u8 {
        match self {
            Op::Sha1 => 0x02,
            Op::Ripemd160 => 0x03,
            Op::Sha256 => 0x08,
            Op::Keccak256 => 0x67,
            Op::Append(_) => 0xf0,
            Op::Prepend(_) => 0xf1,
            Op::Reverse => 0xf2,
            Op::Hexlify => 0xf3,
        }
    }

    pub fn apply(&self, msg: &[u8]) -> Vec<u8> {
        match self {
            Op::Sha1 => sha1::Sha1::digest(msg).to_vec(),
            Op::Ripemd160 => ripemd::Ripemd160::digest(msg).to_vec(),
            Op::Sha256 => Sha256::digest(msg).to_vec(),
            Op::Keccak256 => sha3::Keccak256::digest(msg).to_vec(),
            Op::Append(a) => [msg, a].concat(),
            Op::Prepend(a) => [a.as_slice(), msg].concat(),
            Op::Reverse => msg.iter().rev().copied().collect(),
            Op::Hexlify => hex::encode(msg).into_bytes(),
        }
    }

    fn digest_len(&self) -> Option<usize> {
        match self {
            Op::Sha1 | Op::Ripemd160 => Some(20),
            Op::Sha256 | Op::Keccak256 => Some(32),
            _ => None,
        }
    }

    fn parse(r: &mut Reader, tag: u8) -> Result<Op, String> {
        Ok(match tag {
            0x02 => Op::Sha1,
            0x03 => Op::Ripemd160,
            0x08 => Op::Sha256,
            0x67 => Op::Keccak256,
            0xf0 => Op::Append(r.varbytes(MAX_ARG)?.to_vec()),
            0xf1 => Op::Prepend(r.varbytes(MAX_ARG)?.to_vec()),
            0xf2 => Op::Reverse,
            0xf3 => Op::Hexlify,
            _ => return Err(format!("Unknown operation 0x{tag:02x}")),
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.push(self.tag());
        if let Op::Append(a) | Op::Prepend(a) = self {
            write_varbytes(out, a);
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Attestation {
    Pending(String),
    Bitcoin(u64),
    /// Litecoin, Ethereum and future attestation types: kept verbatim.
    Unknown([u8; 8], Vec<u8>),
}

impl Attestation {
    fn parse(r: &mut Reader) -> Result<Self, String> {
        let tag: [u8; 8] = r.bytes(8)?.try_into().unwrap();
        let payload = r.varbytes(8192)?;
        let mut p = Reader::new(payload);
        Ok(match tag {
            TAG_PENDING => Attestation::Pending(
                String::from_utf8(p.varbytes(1000)?.to_vec()).map_err(|_| "Invalid calendar URI")?,
            ),
            TAG_BITCOIN => Attestation::Bitcoin(p.varuint()?),
            _ => Attestation::Unknown(tag, payload.to_vec()),
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        let mut payload = Vec::new();
        let tag = match self {
            Attestation::Pending(uri) => {
                write_varbytes(&mut payload, uri.as_bytes());
                TAG_PENDING
            }
            Attestation::Bitcoin(h) => {
                write_varuint(&mut payload, *h);
                TAG_BITCOIN
            }
            Attestation::Unknown(t, p) => {
                payload = p.clone();
                *t
            }
        };
        out.extend_from_slice(&tag);
        write_varbytes(out, &payload);
    }
}

/// A commitment-operation tree. The message at each node is derived from the root digest.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Timestamp {
    pub attestations: Vec<Attestation>,
    pub ops: Vec<(Op, Timestamp)>,
}

impl Timestamp {
    fn parse(r: &mut Reader, depth: usize) -> Result<Self, String> {
        if depth > MAX_DEPTH {
            return Err("OTS proof is nested too deeply".into());
        }
        let mut ts = Timestamp::default();
        let mut tag = r.byte()?;
        while tag == 0xff {
            let t = r.byte()?;
            ts.parse_item(r, t, depth)?;
            tag = r.byte()?;
        }
        ts.parse_item(r, tag, depth)?;
        Ok(ts)
    }

    fn parse_item(&mut self, r: &mut Reader, tag: u8, depth: usize) -> Result<(), String> {
        if tag == 0x00 {
            self.attestations.push(Attestation::parse(r)?);
        } else {
            let op = Op::parse(r, tag)?;
            self.ops.push((op, Timestamp::parse(r, depth + 1)?));
        }
        Ok(())
    }

    /// Same layout as the reference: every item but the last is prefixed with 0xff.
    fn write(&self, out: &mut Vec<u8>) {
        let total = self.attestations.len() + self.ops.len();
        let mut i = 0;
        for a in &self.attestations {
            i += 1;
            if i < total {
                out.push(0xff);
            }
            out.push(0x00);
            a.write(out);
        }
        for (op, ts) in &self.ops {
            i += 1;
            if i < total {
                out.push(0xff);
            }
            op.write(out);
            ts.write(out);
        }
    }

    pub fn merge(&mut self, other: Timestamp) {
        for a in other.attestations {
            if !self.attestations.contains(&a) {
                self.attestations.push(a);
            }
        }
        for (op, ts) in other.ops {
            match self.ops.iter_mut().find(|(o, _)| *o == op) {
                Some((_, mine)) => mine.merge(ts),
                None => self.ops.push((op, ts)),
            }
        }
    }

    /// Every attestation together with the message it commits to.
    pub fn attestations_with_msg(&self, msg: &[u8]) -> Vec<(Vec<u8>, Attestation)> {
        let mut out = Vec::new();
        self.collect(msg, &mut out);
        out
    }

    fn collect(&self, msg: &[u8], out: &mut Vec<(Vec<u8>, Attestation)>) {
        for a in &self.attestations {
            out.push((msg.to_vec(), a.clone()));
        }
        for (op, ts) in &self.ops {
            ts.collect(&op.apply(msg), out);
        }
    }

    /// Merge `upgrade` into every node whose message equals `target`. Returns true if any node matched.
    pub fn merge_at(&mut self, msg: &[u8], target: &[u8], upgrade: &Timestamp) -> bool {
        let mut hit = false;
        for (op, ts) in self.ops.iter_mut() {
            hit |= ts.merge_at(&op.apply(msg), target, upgrade);
        }
        if msg == target {
            self.merge(upgrade.clone());
            hit = true;
        }
        hit
    }

    pub fn is_complete(&self, msg: &[u8]) -> bool {
        self.attestations_with_msg(msg)
            .iter()
            .any(|(_, a)| matches!(a, Attestation::Bitcoin(_)))
    }
}

/// Parse a bare timestamp, as returned by calendar servers.
pub fn parse_timestamp(bytes: &[u8]) -> Result<Timestamp, String> {
    let mut r = Reader::new(bytes);
    let ts = Timestamp::parse(&mut r, 0)?;
    r.end()?;
    Ok(ts)
}

/// A `.ots` file: the hash of the original file plus its timestamp.
#[derive(Clone, Debug, PartialEq)]
pub struct DetachedFile {
    pub hash_op: Op,
    pub digest: Vec<u8>,
    pub ts: Timestamp,
}

impl DetachedFile {
    pub fn parse(b: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(b);
        if r.bytes(MAGIC.len()).ok() != Some(MAGIC) {
            return Err("Not an OpenTimestamps proof file".into());
        }
        let v = r.varuint()?;
        if v != 1 {
            return Err(format!("Unsupported OTS version {v}"));
        }
        let tag = r.byte()?;
        let hash_op = Op::parse(&mut r, tag)?;
        let len = hash_op.digest_len().ok_or("Invalid file hash operation")?;
        let digest = r.bytes(len)?.to_vec();
        let ts = Timestamp::parse(&mut r, 0)?;
        r.end()?;
        Ok(DetachedFile { hash_op, digest, ts })
    }

    pub fn read(path: &Path) -> Result<Self, String> {
        let b = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::parse(&b)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut o = MAGIC.to_vec();
        write_varuint(&mut o, 1);
        o.push(self.hash_op.tag());
        o.extend_from_slice(&self.digest);
        self.ts.write(&mut o);
        o
    }

    pub fn is_complete(&self) -> bool {
        self.ts.is_complete(&self.digest)
    }
}

pub fn hash_file(path: &Path, op: &Op) -> Result<Vec<u8>, String> {
    match op {
        Op::Sha256 => stream::<Sha256>(path),
        Op::Sha1 => stream::<sha1::Sha1>(path),
        Op::Ripemd160 => stream::<ripemd::Ripemd160>(path),
        Op::Keccak256 => stream::<sha3::Keccak256>(path),
        _ => Err("Unsupported file hash".into()),
    }
}

fn stream<D: Digest>(path: &Path) -> Result<Vec<u8>, String> {
    let err = |e: std::io::Error| format!("{}: {e}", path.display());
    let mut f = File::open(path).map_err(err)?;
    let mut h = D::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf).map_err(err)?;
        if n == 0 {
            return Ok(h.finalize().to_vec());
        }
        h.update(&buf[..n]);
    }
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b, pos: 0 }
    }
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.pos + n > self.b.len() {
            return Err("Truncated OTS data".into());
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn byte(&mut self) -> Result<u8, String> {
        Ok(self.bytes(1)?[0])
    }
    fn varuint(&mut self) -> Result<u64, String> {
        let (mut v, mut shift) = (0u64, 0u32);
        loop {
            let b = self.byte()?;
            if shift > 63 {
                return Err("Invalid varuint".into());
            }
            v |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                return Ok(v);
            }
            shift += 7;
        }
    }
    fn varbytes(&mut self, max: usize) -> Result<&'a [u8], String> {
        let n = self.varuint()? as usize;
        if n > max {
            return Err("OTS field too long".into());
        }
        self.bytes(n)
    }
    fn end(&self) -> Result<(), String> {
        if self.pos == self.b.len() {
            Ok(())
        } else {
            Err("Trailing garbage after OTS data".into())
        }
    }
}

fn write_varuint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn write_varbytes(out: &mut Vec<u8>, b: &[u8]) {
    write_varuint(out, b.len() as u64);
    out.extend_from_slice(b);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> DetachedFile {
        let digest = Sha256::digest(b"hello").to_vec();
        let leaf = Timestamp {
            attestations: vec![Attestation::Pending("https://alice.btc.calendar.opentimestamps.org".into())],
            ops: vec![],
        };
        let btc = Timestamp { attestations: vec![Attestation::Bitcoin(840_000)], ops: vec![] };
        DetachedFile {
            hash_op: Op::Sha256,
            digest,
            ts: Timestamp {
                attestations: vec![],
                ops: vec![(
                    Op::Append(vec![1, 2, 3]),
                    Timestamp {
                        attestations: vec![],
                        ops: vec![
                            (Op::Sha256, leaf),
                            (Op::Prepend(vec![9; 40]), Timestamp { attestations: vec![], ops: vec![(Op::Sha256, btc)] }),
                        ],
                    },
                )],
            },
        }
    }

    #[test]
    fn roundtrip() {
        let f = sample();
        let bytes = f.to_bytes();
        assert_eq!(DetachedFile::parse(&bytes).unwrap(), f);
        assert!(f.is_complete());
        assert!(DetachedFile::parse(&bytes[..bytes.len() - 1]).is_err());
        assert!(DetachedFile::parse(&[bytes.clone(), vec![0]].concat()).is_err());
    }

    #[test]
    fn merge_at_commitment() {
        let mut f = sample();
        let atts = f.ts.attestations_with_msg(&f.digest);
        let (commit, _) = atts.iter().find(|(_, a)| matches!(a, Attestation::Pending(_))).unwrap().clone();
        let up = Timestamp { attestations: vec![Attestation::Bitcoin(1)], ops: vec![] };
        assert!(f.ts.merge_at(&f.digest.clone(), &commit, &up));
        let after = f.ts.attestations_with_msg(&f.digest);
        assert!(after.contains(&(commit, Attestation::Bitcoin(1))));
    }

    #[test]
    fn varuint_roundtrip() {
        for v in [0u64, 1, 127, 128, 300, 840_000, u64::MAX] {
            let mut o = vec![];
            write_varuint(&mut o, v);
            assert_eq!(Reader::new(&o).varuint().unwrap(), v);
        }
    }
}
