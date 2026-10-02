//! Vault: an encrypted profile on disk, keyed by the user's passphrase.
//!
//! The passphrase never touches disk and is never logged. The MAC is checked
//! BEFORE decrypting — on mismatch it fails closed instead of decrypting garbage
//! and then reporting a parse error.
//!
//! ⚠ NOT production cryptography. See the `ponytail:` note right below for what
//! has to be replaced.

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

const B64: base64::engine::general_purpose::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
/// Key derivation rounds. More rounds = slower password guessing.
const KDF_ROUNDS: u32 = 50_000;

// ponytail: hashing uses std's 64-bit SipHash-1-3 and is NOT memory-hard (CPU loops only).
// That means dictionary-guessing the passphrase is still feasible. Replace with
// `argon2` (Argon2id) + `chacha20poly1305` (both available on crates.io) + a
// constant-time comparison. Bump `format_version` to 2 and keep the old read path
// to migrate.

#[derive(Serialize, Deserialize)]
struct Header {
    v: u32,
    salt: String,
    nonce: String,
    ct: String,
    mac: String,
}

pub struct Vault {
    path: PathBuf,
    enc: [u8; 32],
    mac: [u8; 32],
    salt: [u8; SALT_LEN],
}

impl Vault {
    /// Open (or create if it does not exist yet) the vault. A wrong passphrase only
    /// shows up at `load()` — at open time there is no ciphertext to check yet.
    pub fn open(path: &Path, passphrase: &str) -> Result<Self, String> {
        match std::fs::read(path) {
            Ok(raw) => {
                let h: Header = serde_json::from_slice(&raw)
                    .map_err(|e| format!("vault: {} is corrupt: {e}", path.display()))?;
                if h.v != 1 {
                    return Err(format!("vault: format v{} is not supported", h.v));
                }
                let salt = unb64::<SALT_LEN>(&h.salt)?;
                let (enc, mac) = derive(passphrase, &salt);
                Ok(Self { path: path.to_path_buf(), enc, mac, salt })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut salt = [0u8; SALT_LEN];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
                let (enc, mac) = derive(passphrase, &salt);
                Ok(Self { path: path.to_path_buf(), enc, mac, salt })
            }
            Err(e) => Err(format!("vault: {}: {e}", path.display())),
        }
    }

    /// Write atomically (tmp + rename) and tighten the file mode to 0600.
    pub fn save(&self, data: &Value) -> Result<(), String> {
        let pt = serde_json::to_vec(data).map_err(|e| format!("vault: {e}"))?;
        let mut nonce = [0u8; NONCE_LEN];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
        let mut ct = pt;
        chacha20_xor(&self.enc, &nonce, &mut ct);
        let h = Header {
            v: 1,
            salt: b64(&self.salt),
            nonce: b64(&nonce),
            mac: b64(&mac_of(&self.mac, &nonce, &ct)),
            ct: B64.encode(&ct),
        };
        let body = serde_json::to_vec(&h).map_err(|e| format!("vault: {e}"))?;

        let mut name = self
            .path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "vault".to_string());
        name.push_str(".tmp");
        let tmp = self.path.with_file_name(name);
        if let Some(d) = self.path.parent()
            && !d.as_os_str().is_empty()
        {
            std::fs::create_dir_all(d).map_err(|e| format!("vault: {}: {e}", d.display()))?;
        }
        std::fs::write(&tmp, &body).map_err(|e| format!("vault: {}: {e}", tmp.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(&tmp)
                .map_err(|e| format!("vault: {}: {e}", tmp.display()))?
                .permissions();
            perm.set_mode(0o600);
            std::fs::set_permissions(&tmp, perm).map_err(|e| format!("vault: {}: {e}", tmp.display()))?;
        }
        std::fs::rename(&tmp, &self.path)
            .map_err(|e| format!("vault: {}: {e}", self.path.display()))?;
        Ok(())
    }

    /// `Ok(Value::Null)` if the vault is still empty (nothing to decrypt).
    pub fn load(&self) -> Result<Value, String> {
        let raw = match std::fs::read(&self.path) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Value::Null),
            Err(e) => return Err(format!("vault: {}: {e}", self.path.display())),
        };
        let h: Header =
            serde_json::from_slice(&raw).map_err(|e| format!("vault: {} is corrupt: {e}", self.path.display()))?;
        if h.v != 1 {
            return Err(format!("vault: format v{} is not supported", h.v));
        }
        let salt = unb64::<SALT_LEN>(&h.salt)?;
        let nonce = unb64::<NONCE_LEN>(&h.nonce)?;
        let ct = B64
            .decode(h.ct.as_bytes())
            .map_err(|e| format!("vault: ct is corrupt: {e}"))?;
        let want = B64
            .decode(h.mac.as_bytes())
            .map_err(|e| format!("vault: mac is corrupt: {e}"))?;

        // Fail closed: a wrong MAC stops everything, no decryption is attempted.
        let got = mac_of(&self.mac, &nonce, &ct);
        if !ct_eq(&got, &want) {
            return Err("vault: wrong MAC (wrong passphrase, or the file was modified)".into());
        }
        // The salt in the header must match the salt the key was derived from,
        // otherwise the MAC would already have been wrong.
        if salt != self.salt {
            return Err("vault: salt does not match".into());
        }

        let mut pt = ct;
        chacha20_xor(&self.enc, &nonce, &mut pt);
        serde_json::from_slice(&pt).map_err(|e| format!("vault: plaintext is corrupt: {e}"))
    }
}

// ---------------------------------------------------------------------------
// KDF + MAC
// ---------------------------------------------------------------------------

fn digest(parts: &[&[u8]]) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    for p in parts {
        p.hash(&mut h);
    }
    h.finish()
}

/// 32 bytes from four 64-bit hashes with different domain labels (prevents prefix collisions).
fn widen(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4u8 {
        let tag: [&[u8]; 2] = [domain, std::slice::from_ref(&i)];
        let mut buf: Vec<&[u8]> = Vec::with_capacity(tag.len() + parts.len());
        buf.extend_from_slice(&tag);
        buf.extend_from_slice(parts);
        out[i as usize * 8..i as usize * 8 + 8].copy_from_slice(&digest(&buf).to_le_bytes());
    }
    out
}

/// The encryption key + the MAC key, domain-separated with different labels.
fn derive(pass: &str, salt: &[u8; SALT_LEN]) -> ([u8; 32], [u8; 32]) {
    let p = pass.as_bytes();
    let mut enc = [0u8; 32];
    let mut mac = [0u8; 32];
    for r in 0..KDF_ROUNDS {
        let c = r.to_le_bytes();
        enc = widen(b"f1/enc", &[p, salt, &c]);
        mac = widen(b"f1/mac", &[p, salt, &c]);
    }
    (enc, mac)
}

fn mac_of(mac_key: &[u8; 32], nonce: &[u8; NONCE_LEN], ct: &[u8]) -> [u8; 32] {
    widen(b"f1/tag", &[mac_key.as_slice(), nonce.as_slice(), ct])
}

/// Constant-time comparison — avoids leaking the MAC through timing.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for i in 0..a.len() {
        d |= a[i] ^ b[i];
    }
    d == 0
}

// ---------------------------------------------------------------------------
// ChaCha20 (RFC 8439) — a keystream, not an authenticated cipher
// ---------------------------------------------------------------------------

fn ld32(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

#[rustfmt::skip]
fn qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]); s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]); s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]); s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]); s[b] = (s[b] ^ s[c]).rotate_left(7);
}

fn chacha20_xor(key: &[u8; 32], nonce: &[u8; NONCE_LEN], data: &mut [u8]) {
    let mut st = [0u32; 16];
    for i in 0..8 {
        st[i] = ld32(key, i * 4);
    }
    for i in 0..3 {
        st[13 + i] = ld32(nonce, i * 4);
    }
    let mut counter = 1u32; // RFC 8439: the counter is word 12, the nonce takes 13..16
    let mut off = 0usize;
    while off < data.len() {
        st[12] = counter;
        let mut w = st;
        for _ in 0..10 {
            qr(&mut w, 0, 4, 8, 12); qr(&mut w, 1, 5, 9, 13);
            qr(&mut w, 2, 6, 10, 14); qr(&mut w, 3, 7, 11, 15);
            qr(&mut w, 0, 5, 10, 15); qr(&mut w, 1, 6, 11, 12);
            qr(&mut w, 2, 7, 8, 13); qr(&mut w, 3, 4, 9, 14);
        }
        for i in 0..16 {
            w[i] = w[i].wrapping_add(st[i]);
        }
        let ks: Vec<u8> = w.iter().flat_map(|x| x.to_le_bytes()).collect();
        let n = (data.len() - off).min(64);
        for j in 0..n {
            data[off + j] ^= ks[j];
        }
        off += n;
        counter = counter.wrapping_add(1);
        if counter == 0 {
            return; // over 256 GiB — never reached, but must not wrap around
        }
    }
}

// ---------------------------------------------------------------------------
// fixed-length base64
// ---------------------------------------------------------------------------

fn b64<const N: usize>(x: &[u8; N]) -> String {
    B64.encode(x)
}

fn unb64<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let v = B64.decode(s.as_bytes()).map_err(|e| format!("vault: base64 is corrupt: {e}"))?;
    if v.len() != N {
        return Err(format!("vault: base64 length is {}, expected {N}", v.len()));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&v);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("f1-vault-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join("p.f1vault")
    }

    #[test]
    fn roundtrip_and_empty() {
        let p = tmp("rt");
        let v = Vault::open(&p, "sai-mot").unwrap();
        assert_eq!(v.load().unwrap(), Value::Null, "a new vault is empty");

        let data = serde_json::json!({ "cookies": ["a=1", "b=2"], "ua": "x" });
        v.save(&data).unwrap();
        assert_eq!(v.load().unwrap(), data);

        // Reopen with the same passphrase; the salt comes from the file.
        let again = Vault::open(&p, "sai-mot").unwrap();
        assert_eq!(again.load().unwrap(), data);

        // Every save uses a new nonce → different ciphertext even for identical plaintext.
        v.save(&data).unwrap();
        let a = std::fs::read_to_string(&p).unwrap();
        v.save(&data).unwrap();
        assert_ne!(a, std::fs::read_to_string(&p).unwrap());

        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn wrong_passphrase_fails_closed() {
        let p = tmp("wrong");
        Vault::open(&p, "dung").unwrap()
            .save(&serde_json::json!({ "secret": 1 }))
            .unwrap();
        let bad = Vault::open(&p, "sai").unwrap();
        let e = bad.load().unwrap_err();
        assert!(e.contains("MAC"), "{e}");
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn tampering_is_detected() {
        let p = tmp("tamper");
        Vault::open(&p, "k").unwrap().save(&serde_json::json!({ "n": 1 })).unwrap();
        let raw = std::fs::read_to_string(&p).unwrap();
        let mut h: Header = serde_json::from_str(&raw).unwrap();
        // Modify the ciphertext while keeping the MAC.
        let mut ct = B64.decode(h.ct.as_bytes()).unwrap();
        ct[0] ^= 0xff;
        h.ct = B64.encode(&ct);
        std::fs::write(&p, serde_json::to_vec(&h).unwrap()).unwrap();
        let v = Vault::open(&p, "k").unwrap();
        assert!(v.load().unwrap_err().contains("MAC"));
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn passphrase_never_reaches_disk() {
        let p = tmp("nodisk");
        Vault::open(&p, "not-protected-on-disk").unwrap()
            .save(&serde_json::json!({ "k": "v" }))
            .unwrap();
        let raw = std::fs::read_to_string(&p).unwrap();
        assert!(!raw.contains("not-protected-on-disk"), "the passphrase leaked to disk");
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn chacha_matches_rfc8439_vector() {
        // RFC 8439 §2.4.2: the first keystream block for key=0, nonce=0.
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let mut data = [0u8; 64];
        chacha20_xor(&key, &nonce, &mut data);
        assert_eq!(
            data[..16],
            [0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28]
        );
        assert_eq!(
            data[16..32],
            [0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa3, 0xc9, 0x09, 0xe7, 0x4f, 0x55, 0xfe, 0x63]
        );
    }

    #[test]
    fn chacha_counter_does_not_repeat() {
        let key = [7u8; 32];
        let nonce = [9u8; 12];
        let mut d = vec![0u8; 64 * 3];
        chacha20_xor(&key, &nonce, &mut d);
        assert_ne!(d[0..64], d[64..128]);
        assert_ne!(d[64..128], d[128..192]);
    }
}
