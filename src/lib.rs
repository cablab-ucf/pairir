//! Hand a secret to another device with a code said aloud (`k7m-x9q-p3a`,
//! one minute, one try) or an offline QR code. See README.md.

#![forbid(unsafe_code)]

use anyhow::{Context, Result, bail, ensure};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305,
    aead::{Aead, Payload},
};
use iroh::{EndpointAddr, RelayUrl, SecretKey, TransportAddr, endpoint::Builder};
use rand_chacha::{
    ChaCha20Rng,
    rand_core::{Rng, SeedableRng},
};
use sha2::{Digest, Sha256};
use std::{sync::Mutex, time::Duration};
use tokio::{io::AsyncReadExt, task::JoinSet, time::timeout};
use x_wing::kem::Ciphertext;
use x_wing::{Decapsulate, DecapsulationKey, Decapsulator, Encapsulate, EncapsulationKey};
use x_wing::{KeyExport, XWingKem};
use zeroize::Zeroizing;

/// How long a code is answered.
pub const TTL: Duration = Duration::from_secs(60);
const ALPN: &[u8] = b"irpair/1";
const ABC: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";
const LEN: usize = 9;
const KEM_CT: usize = 1120;
const MAX: usize = 1 << 16;
pub const SECRET: usize = 32 << 10;

fn rand<const N: usize>() -> [u8; N] {
    let mut b = [0; N];
    getrandom::fill(&mut b).expect("os randomness");
    b
}

fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0, |x, (a, b)| x | (a ^ b)) == 0
}

/// OS randomness hashed with a secret (RFC 8937): a rigged RNG alone
/// predicts nothing.
fn hedged(secret: &[u8]) -> ChaCha20Rng {
    ChaCha20Rng::from_seed(
        Sha256::new().chain_update(rand::<32>()).chain_update(secret).finalize().into(),
    )
}

fn seal(key: &[u8; 32], msg: &[u8], rng: &mut ChaCha20Rng) -> Vec<u8> {
    let mut n = [0u8; 24];
    rng.fill_bytes(&mut n);
    let ct = XChaCha20Poly1305::new(key.into()).encrypt(&n.into(), Payload { msg, aad: ALPN });
    [&n[..], &ct.expect("in memory")].concat()
}

fn open(key: &[u8; 32], b: &[u8]) -> Option<Vec<u8>> {
    let (n, msg) = b.split_at_checked(24)?;
    let n: [u8; 24] = n.try_into().ok()?;
    XChaCha20Poly1305::new(key.into()).decrypt(&n.into(), Payload { msg, aad: ALPN }).ok()
}

/// As typed: any case, dashes or spaces; i and l read as 1, o as 0.
fn norm(code: &str) -> Result<String> {
    let fix = |c: char| match c {
        'i' | 'l' => '1',
        'o' => '0',
        c => c,
    };
    let c: String = code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| fix(c.to_ascii_lowercase()))
        .collect();
    ensure!(c.len() == LEN && c.bytes().all(|b| ABC.contains(&b)), "not a short code");
    Ok(c)
}

fn minute() -> u64 {
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
    t.map_or(0, |d| d.as_secs() / 60)
}

fn argon(secret: &[u8], salt: &[u8], out: &mut [u8], m: u32, t: u32) -> Result<()> {
    let p = argon2::Params::new(m, t, 1, None).map_err(|e| anyhow::anyhow!("{e}"))?;
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, p)
        .hash_password_into(secret, salt, out)
        .map_err(|e| anyhow::anyhow!("{e}"))
}

/// A code's identity and proof, for `app`, given in minute `m`.
fn keys(app: &str, code: &str, m: u64) -> Result<(SecretKey, [u8; 32])> {
    let salt = [b"irpair 1 ", app.as_bytes(), b" ", &m.to_le_bytes()].concat();
    let mut k = Zeroizing::new([0u8; 64]);
    // 2^45 guesses within a minute: cheap is enough.
    argon(norm(code)?.as_bytes(), &salt, &mut k[..], 19 << 10, 2)?;
    let (sk, proof) = k.split_at(32);
    Ok((SecretKey::from_bytes(sk.try_into()?), proof.try_into()?))
}

async fn stretched(app: &str, code: &str, m: u64) -> Result<(SecretKey, [u8; 32])> {
    let (app, code) = (app.to_string(), code.to_string());
    tokio::task::spawn_blocking(move || keys(&app, &code, m)).await?
}

/// A password's key, salted by the code's proof: holds if X-Wing falls.
async fn locked(password: &str, proof: [u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    ensure!(!password.is_empty(), "empty password");
    let p = Zeroizing::new(password.to_string());
    tokio::task::spawn_blocking(move || {
        let mut k = Zeroizing::new([0u8; 32]);
        argon(p.as_bytes(), &proof, &mut k[..], 256 << 10, 4).map(|_| k)
    })
    .await?
}

async fn rest(rx: &mut iroh::endpoint::RecvStream, max: usize) -> Result<Vec<u8>> {
    let mut b = Vec::new();
    rx.take(max as u64 + 1).read_to_end(&mut b).await?;
    ensure!(b.len() <= max, "over {max} bytes");
    Ok(b)
}

/// A short code for `secret`, answered for `TTL`. Pass a password for
/// anything that opens other secrets.
pub async fn give(ep: Builder, app: &str, secret: &[u8], password: Option<&str>) -> Result<String> {
    ensure!(secret.len() <= SECRET, "over {SECRET} bytes: too long to hand over");
    let mut rng = hedged(&[secret, password.unwrap_or("").as_bytes()].concat());
    let mut c = [0u8; LEN];
    rng.fill_bytes(&mut c);
    let c: String = c.iter().map(|b| ABC[*b as usize % 32] as char).collect();
    let code = format!("{}-{}-{}", &c[..3], &c[3..6], &c[6..]);
    let (sk, proof) = stretched(app, &code, minute()).await?;
    let body = Zeroizing::new(match password {
        None => [&[0][..], secret].concat(),
        Some(p) => [&[1][..], &seal(&*locked(p, proof).await?, secret, &mut rng)].concat(),
    });
    let ep = ep.secret_key(sk).alpns(vec![ALPN.to_vec()]).bind().await?;
    let _ = timeout(Duration::from_secs(10), ep.online()).await;
    tokio::spawn(async move {
        let one = async {
            let c = ep.accept().await?.await.ok()?;
            let (mut tx, mut rx) = c.accept_bi().await.ok()?;
            let b = rest(&mut rx, 32 + 2048).await.ok()?;
            let (got, pk) = b.split_at_checked(32)?;
            // One try: right or wrong, the code is spent.
            let sealed = same(got, &proof).then(|| kem_seal(pk, &body, &mut rng))??;
            tx.write_all(&sealed).await.ok()?;
            tx.finish().ok()?;
            let _ = timeout(Duration::from_secs(5), c.closed()).await;
            Some(())
        };
        let _ = timeout(TTL, one).await;
        ep.close().await;
    });
    Ok(code)
}

fn kem_seal(pk: &[u8], msg: &[u8], rng: &mut ChaCha20Rng) -> Option<Vec<u8>> {
    let (ct, ss) = EncapsulationKey::try_from(pk).ok()?.encapsulate_with_rng(rng);
    Some([&ct[..], &seal(&Zeroizing::new(ss.into()), msg, rng)].concat())
}

fn kem_open(dk: &DecapsulationKey, b: &[u8]) -> Option<Vec<u8>> {
    let (ct, rest) = b.split_at_checked(KEM_CT)?;
    let ct = Ciphertext::<XWingKem>::try_from(ct).ok()?;
    open(&Zeroizing::new(dk.decapsulate(&ct).into()), rest)
}

/// The last locked secret taken, for a password given after its one try.
type Held = (String, String, [u8; 32], Vec<u8>);
static HELD: Mutex<Option<Held>> = Mutex::new(None);

/// The secret a short code stands for, from its giver on `relays`.
pub async fn take(
    ep: Builder,
    relays: &[RelayUrl],
    app: &str,
    code: &str,
    password: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>> {
    let code = norm(code)?;
    let held =
        HELD.lock().unwrap_or_else(|e| e.into_inner()).take_if(|h| h.0 == app && h.1 == code);
    if let Some((_, code, proof, b)) = held {
        return unlock(app, code, proof, b, password).await;
    }
    let m = minute();
    let mut tries = vec![];
    for m in [m.saturating_sub(1), m, m + 1] {
        tries.push(stretched(app, &code, m).await?);
    }
    let mut seed = [0u8; 32];
    hedged(code.as_bytes()).fill_bytes(&mut seed);
    let dk: DecapsulationKey = seed.into();
    let ek = dk.encapsulation_key().to_bytes();
    let ep = ep.bind().await?;
    let go = async {
        // This minute's identity or a neighbour's (clock skew).
        let mut dials = JoinSet::new();
        for (sk, proof) in tries {
            let (ep, to) = (ep.clone(), relays.iter().cloned().map(TransportAddr::Relay));
            let at = EndpointAddr::from_parts(sk.public(), to);
            dials.spawn(async move {
                loop {
                    match ep.connect(at.clone(), ALPN).await {
                        Ok(c) => break (c, proof),
                        Err(_) => tokio::time::sleep(Duration::from_secs(2)).await,
                    }
                }
            });
        }
        let (c, proof) = dials.join_next().await.context("no code")??;
        drop(dials);
        let (mut tx, mut rx) = c.open_bi().await?;
        tx.write_all(&[&proof[..], &ek].concat()).await?;
        tx.finish()?;
        let b = rest(&mut rx, MAX).await?;
        let body = Zeroizing::new(kem_open(&dk, &b).context("that code was used or is wrong")?);
        match body.split_first() {
            Some((0, s)) => Ok(Zeroizing::new(s.to_vec())),
            Some((1, s)) => unlock(app, code, proof, s.to_vec(), password).await,
            _ => bail!("not a code's secret"),
        }
    };
    let r = timeout(Duration::from_secs(30), go).await;
    ep.close().await;
    r.unwrap_or_else(|_| bail!("nobody answers that code: wrong, or past its minute"))
}

async fn unlock(
    app: &str,
    code: String,
    proof: [u8; 32],
    b: Vec<u8>,
    password: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>> {
    if let Some(p) = password
        && let Some(s) = open(&*locked(p, proof).await?, &b)
    {
        return Ok(Zeroizing::new(s));
    }
    *HELD.lock().unwrap_or_else(|e| e.into_inner()) = Some((app.into(), code, proof, b));
    bail!(if password.is_some() { "wrong password" } else { "that code has a password" })
}

/// 100 random bits: `k7m2-x9qp-...`.
pub fn password() -> String {
    let abc = b"23456789abcdefghjkmnpqrstuvwxyz";
    let c: Vec<char> = rand::<20>().iter().map(|b| abc[*b as usize % 31] as char).collect();
    c.chunks(4).map(|g| g.iter().collect::<String>()).collect::<Vec<_>>().join("-")
}

const QR: &str = "IRPAIR1:";
pub const QR_SECRET: usize = 2 << 10;

async fn qr_key(app: &str, password: &str, salt: [u8; 16]) -> Result<Zeroizing<[u8; 32]>> {
    let salt = [b"irpair qr 1 ", app.as_bytes(), b" ", &salt].concat();
    let p = Zeroizing::new(password.to_string());
    tokio::task::spawn_blocking(move || {
        let mut k = Zeroizing::new([0u8; 32]);
        argon(p.as_bytes(), &salt, &mut k[..], 256 << 10, 4).map(|_| k)
    })
    .await?
}

/// An offline QR code's text: `secret` under `password` alone (Argon2id
/// 256 MiB, XChaCha20-Poly1305), so make it [`password`].
pub async fn seal_qr(app: &str, secret: &[u8], password: &str) -> Result<String> {
    ensure!(secret.len() <= QR_SECRET, "over {QR_SECRET} bytes: too long for a QR code");
    ensure!(!password.is_empty(), "empty password");
    let mut rng = hedged(&[secret, password.as_bytes()].concat());
    let mut salt = [0u8; 16];
    rng.fill_bytes(&mut salt);
    let ct = seal(&*qr_key(app, password, salt).await?, secret, &mut rng);
    Ok(format!("{QR}{}", data_encoding::BASE32_NOPAD.encode(&[&salt[..], &ct].concat())))
}

pub async fn open_qr(app: &str, text: &str, password: &str) -> Result<Zeroizing<Vec<u8>>> {
    let body = text.trim().strip_prefix(QR).context("not an irpair QR code")?;
    let b = data_encoding::BASE32_NOPAD.decode(body.as_bytes()).context("not an irpair QR code")?;
    let (salt, ct) = b.split_at_checked(16).context("not an irpair QR code")?;
    let k = qr_key(app, password, salt.try_into()?).await?;
    open(&k, ct).map(Zeroizing::new).context("wrong password, or another app's code")
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::{RelayMode, endpoint::presets};
    use iroh_relay::server::{RelayConfig, Server, ServerConfig};

    async fn relay() -> (Server, RelayUrl) {
        let mut cfg = ServerConfig::default();
        cfg.relay = Some(RelayConfig::new(([127, 0, 0, 1], 0)));
        let s = Server::spawn(cfg).await.unwrap();
        let url = format!("http://{}/", s.http_addr().unwrap()).parse().unwrap();
        (s, url)
    }

    fn ep(r: &RelayUrl) -> Builder {
        iroh::Endpoint::builder(presets::Minimal).relay_mode(RelayMode::custom([r.clone()]))
    }

    #[test]
    fn codes_read_as_typed_and_change_each_minute_and_app() {
        let a = keys("x", "k7m-x9q-p3a", 1).unwrap();
        assert_eq!(a.0.public(), keys("x", "K7M X9Q P3A", 1).unwrap().0.public());
        assert_eq!(norm("o1l-000-111").unwrap(), "011000111");
        assert!(norm("k7m-x9q").is_err() && norm("k7m-x9q-p3u").is_err());
        for b in [keys("x", "k7m-x9q-p3a", 2).unwrap(), keys("y", "k7m-x9q-p3a", 1).unwrap()] {
            assert!(a.0.public() != b.0.public() && a.1 != b.1);
        }
    }

    /// Given on one device, taken on another over a relay; then spent.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_short_code_hands_over_its_secret_once() {
        let (_s, r) = relay().await;
        let code = give(ep(&r), "test", b"invite", None).await.unwrap();
        assert_eq!(code.len(), 11, "xxx-xxx-xxx");
        let got = take(ep(&r), std::slice::from_ref(&r), "test", &code.to_uppercase(), None).await;
        assert_eq!(*got.unwrap(), b"invite");
        assert!(
            take(ep(&r), std::slice::from_ref(&r), "test", &code, None).await.is_err(),
            "spent"
        );
        // Another app's code never opens here.
        let code = give(ep(&r), "test", b"invite", None).await.unwrap();
        assert!(take(ep(&r), std::slice::from_ref(&r), "other", &code, None).await.is_err());
    }

    /// With a password: the taker needs it too, and may give it after.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_password_locks_it_once_more() {
        let (_s, r) = relay().await;
        let code = give(ep(&r), "test", b"seed", Some("horse battery")).await.unwrap();
        let rs = [r.clone()];
        let t = |p| take(ep(&r), &rs, "test", &code, p);
        assert!(t(None).await.unwrap_err().to_string().contains("has a password"));
        assert!(t(Some("wrong")).await.unwrap_err().to_string().contains("wrong password"));
        assert_eq!(*t(Some("horse battery")).await.unwrap(), b"seed");
    }

    /// The largest secret, locked, still fits its sealed answer; one more
    /// byte is refused before any code is made.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_largest_secret_fits() {
        let (_s, r) = relay().await;
        let big = vec![7u8; SECRET];
        assert!(give(ep(&r), "test", &[0; SECRET + 1], None).await.is_err());
        let code = give(ep(&r), "test", &big, Some("pw")).await.unwrap();
        let got = take(ep(&r), std::slice::from_ref(&r), "test", &code, Some("pw")).await;
        assert_eq!(*got.unwrap(), big);
    }

    /// A QR code opens offline with its password, for its app alone.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_qr_code_opens_with_its_password() {
        let pw = password();
        assert_eq!(pw.len(), 24);
        let t = seal_qr("test", b"store", &pw).await.unwrap();
        assert!(t.starts_with(QR) && t[QR.len()..].bytes().all(|b| b.is_ascii_alphanumeric()));
        assert_eq!(*open_qr("test", &t, &pw).await.unwrap(), b"store");
        assert!(open_qr("test", &t, "wrong").await.is_err());
        assert!(open_qr("other", &t, &pw).await.is_err());
        assert!(seal_qr("test", &[0; QR_SECRET + 1], &pw).await.is_err());
    }

    /// A wrong proof, even to the right identity, gets nothing and burns it.
    #[tokio::test(flavor = "multi_thread")]
    async fn one_wrong_proof_burns_a_code() {
        let (_s, r) = relay().await;
        let (code, m) = loop {
            let m = minute();
            let code = give(ep(&r), "test", b"x", None).await.unwrap();
            if minute() == m {
                break (code, m);
            }
        };
        let (sk, _) = keys("test", &code, m).unwrap();
        let e = ep(&r).bind().await.unwrap();
        let at = EndpointAddr::from_parts(sk.public(), [TransportAddr::Relay(r.clone())]);
        let c = e.connect(at, ALPN).await.unwrap();
        let (mut tx, mut rx) = c.open_bi().await.unwrap();
        let dk: DecapsulationKey = rand::<32>().into();
        let pk = dk.encapsulation_key().to_bytes();
        tx.write_all(&[&[0u8; 32][..], &pk].concat()).await.unwrap();
        tx.finish().unwrap();
        assert!(rest(&mut rx, MAX).await.unwrap_or_default().is_empty());
        assert!(
            take(ep(&r), std::slice::from_ref(&r), "test", &code, None).await.is_err(),
            "burnt"
        );
    }
}
