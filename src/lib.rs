//! Hand a secret to another device with a code said aloud
//! (`k7m-x9q-p3a-b2c`, one minute, one try) or an offline QR code. See
//! README.md.

#![forbid(unsafe_code)]

use anyhow::{Context, Result, anyhow, bail, ensure};
use chacha20::{
    ChaCha20Rng,
    rand_core::{Rng, SeedableRng},
};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305,
    aead::{Aead, Payload},
};
use curve25519_dalek::traits::IsIdentity;
use curve25519_dalek::{RistrettoPoint, Scalar, ristretto::CompressedRistretto};
use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointAddr, RelayUrl, SecretKey, TransportAddr};
use n0_future::task::{JoinHandle, JoinSet, spawn};
use n0_future::time::{Duration, Instant, SystemTime, sleep, timeout};
use sha2::{Digest, Sha256, Sha512};
use std::sync::Mutex;
use x_wing::kem::Ciphertext;
use x_wing::{Decapsulate, DecapsulationKey, Decapsulator, Encapsulate, EncapsulationKey};
use x_wing::{KeyExport, XWingKem};
use zeroize::Zeroizing;

/// How long a code is answered.
pub const TTL: Duration = Duration::from_secs(60);
const ALPN: &[u8] = b"pairir/3";
const ABC: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";
const LEN: usize = 12;
/// The code's first half, its nameplate: public, it only finds the giver.
/// 30 bits: too many rendezvous to dial them all within a code's minute.
const PLATE: usize = 6;
const EK: usize = 1216;
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
/// predicts nothing the secret does not.
fn hedged(secrets: &[&[u8]]) -> ChaCha20Rng {
    let h = Sha256::new().chain_update(rand::<32>());
    ChaCha20Rng::from_seed(secrets.iter().fold(h, |h, s| h.chain_update(s)).finalize().into())
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
    let t = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH);
    t.map_or(0, |d| d.as_secs() / 60)
}

fn argon(secret: &[u8], salt: &[u8], out: &mut [u8], m: u32, t: u32) -> Result<()> {
    let p = argon2::Params::new(m, t, 1, None).map_err(|e| anyhow!("{e}"))?;
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, p)
        .hash_password_into(secret, salt, out)
        .map_err(|e| anyhow!("{e}"))
}

/// A password's key (Argon2id 256 MiB, 4 passes) for `app` and a salt.
async fn locked(
    tag: &str,
    app: &str,
    password: &str,
    salt: [u8; 16],
) -> Result<Zeroizing<[u8; 32]>> {
    ensure!(!password.is_empty(), "empty password");
    let salt = [tag.as_bytes(), app.as_bytes(), b" ", &salt].concat();
    let p = Zeroizing::new(password.to_string());
    let f = move || {
        let mut k = Zeroizing::new([0u8; 32]);
        argon(p.as_bytes(), &salt, &mut k[..], 256 << 10, 4).map(|_| k)
    };
    // A browser has no blocking pool: run pairir there in a Web Worker.
    #[cfg(target_arch = "wasm32")]
    return f();
    #[cfg(not(target_arch = "wasm32"))]
    tokio::task::spawn_blocking(f).await?
}

/// Length-value encoding (CPace's lv_cat): each part after its LEB128 length.
fn lv(parts: &[&[u8]]) -> Vec<u8> {
    let mut v = vec![];
    for p in parts {
        let mut n = p.len();
        while n >= 128 {
            v.push(n as u8 | 0x80);
            n >>= 7;
        }
        v.push(n as u8);
        v.extend_from_slice(p);
    }
    v
}

/// The giver's rendezvous key, from the nameplate alone: anyone may derive
/// it, so TLS hides the handoff but proves nothing; CPace does.
fn meet(app: &str, plate: &str, m: u64) -> SecretKey {
    let h =
        Sha256::digest(lv(&[b"pairir 3 meet", app.as_bytes(), &m.to_le_bytes(), plate.as_bytes()]));
    SecretKey::from_bytes(&h.into())
}

// CPace (draft-irtf-cfrg-cpace-21), CPACE-RISTR255-SHA512: the taker
// initiates, the giver responds. PRS: the code after its nameplate. CI: the
// app. sid: the TLS exporter. ADa: the taker's X-Wing key. ADb: empty.

const DSI: &[u8] = b"CPaceRistretto255";

fn generator(prs: &[u8], ci: &[u8], sid: &[u8]) -> RistrettoPoint {
    let zpad = 128usize.saturating_sub(lv(&[prs]).len() + lv(&[DSI]).len() + 1);
    let h: [u8; 64] = Sha512::digest(lv(&[DSI, prs, &vec![0; zpad], ci, sid])).into();
    RistrettoPoint::from_uniform_bytes(&h)
}

/// A scalar of 252 random bits, as the draft recommends, and its share.
fn share(g: RistrettoPoint, rng: &mut ChaCha20Rng) -> (Zeroizing<Scalar>, [u8; 32]) {
    let mut b = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut *b);
    b[31] &= 0x0f;
    let y = Zeroizing::new(Scalar::from_bytes_mod_order(*b));
    let ours = (g * *y).compress().to_bytes();
    (y, ours)
}

/// ISK for `y` and the peer's share; `None` if the share fails to decode or
/// yields the identity.
fn isk(y: &Scalar, theirs: &[u8], sid: &[u8], transcript: &[u8]) -> Option<Zeroizing<[u8; 64]>> {
    let k = CompressedRistretto::from_slice(theirs).ok()?.decompress()? * y;
    if k.is_identity() {
        return None;
    }
    let h = Sha512::new()
        .chain_update(lv(&[b"CPaceRistretto255_ISK", sid, k.compress().as_bytes()]))
        .chain_update(transcript)
        .finalize();
    Some(Zeroizing::new(h.into()))
}

/// The CPace generator and sid both ends derive, bound to `c`.
fn cpace(c: &Connection, app: &str, pw: &str) -> Result<(RistrettoPoint, [u8; 32])> {
    let mut sid = [0; 32];
    c.export_keying_material(&mut sid, b"EXPORTER-pairir-cpace", b"")
        .map_err(|e| anyhow!("tls exporter: {e:?}"))?;
    Ok((generator(pw.as_bytes(), &lv(&[b"pairir 3", app.as_bytes()]), &sid), sid))
}

/// The taker's proof that it holds the code, before the giver answers.
fn proof(isk: &[u8]) -> [u8; 32] {
    Sha256::digest(lv(&[b"pairir 3 taker", isk])).into()
}

/// The answer's key: CPace and X-Wing together, so it holds while either does.
fn key(isk: &[u8], ss: &[u8]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(Sha256::digest(lv(&[b"pairir 3 key", isk, ss])).into())
}

/// How a code ended: handed to a taker who proved it; spent by someone who
/// reached it and did not (a wrong code, a broken exchange: tell the user);
/// or never reached.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum End {
    Taken,
    Spent,
    Expired,
}

/// A short code for `secret`, answered for `TTL` on `relays` (none: the
/// lab's) from an irnet endpoint, and how it ends. Pass a
/// password for anything that opens other secrets.
pub async fn give(
    relays: &[RelayUrl],
    app: &str,
    secret: &[u8],
    password: Option<&str>,
) -> Result<(String, JoinHandle<End>)> {
    ensure!(secret.len() <= SECRET, "over {SECRET} bytes: too long to hand over");
    let mut rng = hedged(&[secret, password.unwrap_or("").as_bytes()]);
    let mut c = [0u8; LEN];
    rng.fill_bytes(&mut c);
    let c: String = c.iter().map(|b| ABC[*b as usize % 32] as char).collect();
    let code = format!("{}-{}-{}-{}", &c[..3], &c[3..6], &c[6..9], &c[9..]);
    let body = Zeroizing::new(match password {
        None => [&[0][..], secret].concat(),
        Some(p) => {
            let mut salt = [0u8; 16];
            rng.fill_bytes(&mut salt);
            let k = locked("pairir 3 ", app, p, salt).await?;
            [&[1][..], &salt, &seal(&k, secret, &mut rng)].concat()
        }
    });
    let ep = irnet::on(relays).secret_key(meet(app, &c[..PLATE], minute()));
    let ep = ep.alpns(vec![ALPN.to_vec()]);
    let ep = ep.bind().await?;
    // The lab's: its first relay, the next once that has not answered for
    // 10 s (the taker dials both).
    let wait = match relays.is_empty() {
        true => {
            spawn(irnet::fallback(ep.clone()));
            25
        }
        false => 10,
    };
    if timeout(Duration::from_secs(wait), ep.online()).await.is_err() {
        ep.close().await;
        bail!("no relay answers: nobody could reach a code");
    }
    let (app, pw) = (app.to_string(), Zeroizing::new(c[PLATE..].to_string()));
    let end = spawn(async move {
        // One try: right or wrong, the code is spent.
        let end = match timeout(TTL, answer(&ep, &app, &pw, &body, &mut rng)).await {
            Ok(Some(())) => End::Taken,
            Ok(None) => End::Spent,
            Err(_) => End::Expired,
        };
        ep.close().await;
        end
    });
    Ok((code, end))
}

async fn answer(
    ep: &Endpoint,
    app: &str,
    pw: &str,
    body: &[u8],
    rng: &mut ChaCha20Rng,
) -> Option<()> {
    let c = ep.accept().await?.await.ok()?;
    let (mut tx, mut rx) = c.accept_bi().await.ok()?;
    let mut m = [0u8; 32 + EK];
    rx.read_exact(&mut m).await.ok()?;
    let (ya, ek) = m.split_at(32);
    let (g, sid) = cpace(&c, app, pw).ok()?;
    let (y, yb) = share(g, rng);
    tx.write_all(&yb).await.ok()?;
    let isk = isk(&y, ya, &sid, &lv(&[ya, ek, &yb, b""]))?;
    let mut got = [0u8; 32];
    rx.read_exact(&mut got).await.ok()?;
    if !same(&got, &proof(&*isk)) {
        return None;
    }
    let (ct, ss) = EncapsulationKey::try_from(ek).ok()?.encapsulate_with_rng(rng);
    let ss: Zeroizing<[u8; 32]> = Zeroizing::new(ss.into());
    tx.write_all(&[&ct[..], &seal(&key(&*isk, &*ss), body, rng)].concat()).await.ok()?;
    tx.finish().ok()?;
    let _ = timeout(Duration::from_secs(5), c.closed()).await;
    Some(())
}

/// The last locked secret taken, for a password given within [`HOLD`] of
/// its one try: then it is dropped.
type Held = (String, String, Vec<u8>, Instant);
static HELD: Mutex<Option<Held>> = Mutex::new(None);
const HOLD: Duration = Duration::from_secs(600);

/// The secret a short code stands for, from its giver on `relays`.
pub async fn take(
    relays: &[RelayUrl],
    app: &str,
    code: &str,
    password: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>> {
    let code = norm(code)?;
    let held =
        HELD.lock().unwrap_or_else(|e| e.into_inner()).take_if(|h| h.0 == app && h.1 == code);
    if let Some((_, code, b, _)) = held {
        return unlock(app, code, b, password).await;
    }
    let (plate, pw) = code.split_at(PLATE);
    let mut rng = hedged(&[code.as_bytes()]);
    let mut seed = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut *seed);
    let dk: DecapsulationKey = (*seed).into();
    let ek = dk.encapsulation_key().to_bytes();
    // A fresh key: the taker is nobody the giver or the relay knows.
    let ep = irnet::on(relays).secret_key(SecretKey::from_bytes(&rand())).bind().await?;
    let lab = irnet::relays();
    let relays = if relays.is_empty() { &lab[..] } else { relays };
    let go = async {
        // This minute's rendezvous or a neighbour's (clock skew).
        let m = minute();
        let mut dials = JoinSet::new();
        for m in [m.saturating_sub(1), m, m + 1] {
            let (ep, to) = (ep.clone(), relays.iter().cloned().map(TransportAddr::Relay));
            let at = EndpointAddr::from_parts(meet(app, plate, m).public(), to);
            dials.spawn(async move {
                loop {
                    match ep.connect(at.clone(), ALPN).await {
                        Ok(c) => break c,
                        Err(_) => sleep(Duration::from_secs(2)).await,
                    }
                }
            });
        }
        let c = dials.join_next().await.context("no code")??;
        drop(dials);
        let (g, sid) = cpace(&c, app, pw)?;
        let (y, ya) = share(g, &mut rng);
        let (mut tx, mut rx) = c.open_bi().await?;
        tx.write_all(&[&ya[..], &ek].concat()).await?;
        let mut yb = [0u8; 32];
        rx.read_exact(&mut yb).await?;
        let isk = isk(&y, &yb, &sid, &lv(&[&ya, &ek, &yb, b""])).context("not a code's answer")?;
        tx.write_all(&proof(&*isk)).await?;
        tx.finish()?;
        let b = rx.read_to_end(MAX).await.unwrap_or_default();
        kem_open(&dk, &*isk, &b).context("that code was used or is wrong")
    };
    let r = timeout(Duration::from_secs(30), go).await;
    ep.close().await;
    let body = r.unwrap_or_else(|_| bail!("nobody answers that code: wrong, or past its minute"));
    // Past the deadline above: the code is spent, so a slow Argon2 must not
    // lose its secret.
    match Zeroizing::new(body?).split_first() {
        Some((0, s)) => Ok(Zeroizing::new(s.to_vec())),
        Some((1, s)) => unlock(app, code, s.to_vec(), password).await,
        _ => bail!("not a code's secret"),
    }
}

fn kem_open(dk: &DecapsulationKey, isk: &[u8], b: &[u8]) -> Option<Vec<u8>> {
    let (ct, rest) = b.split_at_checked(KEM_CT)?;
    let ct = Ciphertext::<XWingKem>::try_from(ct).ok()?;
    let ss: Zeroizing<[u8; 32]> = Zeroizing::new(dk.decapsulate(&ct).into());
    open(&key(isk, &*ss), rest)
}

async fn unlock(
    app: &str,
    code: String,
    b: Vec<u8>,
    password: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>> {
    if let Some(p) = password
        && let Some((salt, ct)) = b.split_at_checked(16)
        && let Some(s) = open(&*locked("pairir 3 ", app, p, salt.try_into()?).await?, ct)
    {
        return Ok(Zeroizing::new(s));
    }
    let at = Instant::now();
    *HELD.lock().unwrap_or_else(|e| e.into_inner()) = Some((app.into(), code, b, at));
    spawn(async move {
        sleep(HOLD).await;
        HELD.lock().unwrap_or_else(|e| e.into_inner()).take_if(|h| h.3 == at);
    });
    bail!(if password.is_some() { "wrong password" } else { "that code has a password" })
}

/// 99 random bits: `k7m2-x9qp-...`.
pub fn password() -> String {
    let abc = b"23456789abcdefghjkmnpqrstuvwxyz";
    // Bytes under 248 = 8 * 31 alone: no letter likelier than another.
    let mut c = std::iter::repeat_with(|| rand::<1>()[0])
        .filter(|b| *b < 248)
        .map(|b| abc[b as usize % 31] as char);
    (0..5).map(|_| c.by_ref().take(4).collect()).collect::<Vec<String>>().join("-")
}

const QR: &str = "PAIRIR1:";
pub const QR_SECRET: usize = 2 << 10;

/// An offline QR code's text: `secret` under `password` alone (Argon2id
/// 256 MiB, XChaCha20-Poly1305), so make it [`password`].
pub async fn seal_qr(app: &str, secret: &[u8], password: &str) -> Result<String> {
    ensure!(secret.len() <= QR_SECRET, "over {QR_SECRET} bytes: too long for a QR code");
    let mut rng = hedged(&[secret, password.as_bytes()]);
    let mut salt = [0u8; 16];
    rng.fill_bytes(&mut salt);
    let ct = seal(&*locked("pairir qr 1 ", app, password, salt).await?, secret, &mut rng);
    Ok(format!("{QR}{}", data_encoding::BASE32_NOPAD.encode(&[&salt[..], &ct].concat())))
}

pub async fn open_qr(app: &str, text: &str, password: &str) -> Result<Zeroizing<Vec<u8>>> {
    let body = text.trim().strip_prefix(QR).context("not an pairir QR code")?;
    let b = data_encoding::BASE32_NOPAD.decode(body.as_bytes()).context("not an pairir QR code")?;
    let (salt, ct) = b.split_at_checked(16).context("not an pairir QR code")?;
    let k = locked("pairir qr 1 ", app, password, salt.try_into()?).await?;
    open(&k, ct).map(Zeroizing::new).context("wrong password, or another app's code")
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh_relay::server::{RelayConfig, Server, ServerConfig};

    async fn relay() -> (Server, RelayUrl) {
        let mut cfg = ServerConfig::default();
        cfg.relay = Some(RelayConfig::new(([127, 0, 0, 1], 0)));
        let s = Server::spawn(cfg).await.unwrap();
        let url = format!("http://{}/", s.http_addr().unwrap()).parse().unwrap();
        (s, url)
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn scalar(s: &str) -> Scalar {
        Scalar::from_bytes_mod_order(hex(s).try_into().unwrap())
    }

    #[test]
    fn codes_read_as_typed_and_meet_by_nameplate_minute_and_app() {
        assert_eq!(norm("K7M X9Q P3A B2C").unwrap(), "k7mx9qp3ab2c");
        assert_eq!(norm("o1l-000-111-ilo").unwrap(), "011000111110");
        assert!(norm("k7m-x9q-p3a").is_err() && norm("k7m-x9q-p3a-b2u").is_err());
        let a = meet("x", "k7mx9q", 1).public();
        assert_eq!(a, meet("x", "k7mx9q", 1).public());
        for b in [meet("x", "k7mx9r", 1), meet("x", "k7mx9q", 2), meet("y", "k7mx9q", 1)] {
            assert!(a != b.public());
        }
    }

    /// draft-irtf-cfrg-cpace-21, appendix B.3: CPACE-RISTR255-SHA512.
    #[test]
    fn cpace_matches_the_drafts_vectors() {
        let ci: &[u8] = b"\x0bA_initiator\x0bB_responder";
        let sid = hex("7e4b4791d6a8ef019b936c79fb7f2c57");
        let g = generator(b"Password", ci, &sid);
        let g_hex = "222b6b195fe84b1652badb6f6a3ae3d24341e7306967f0b8115b40d5698c7e56";
        assert_eq!(g.compress().to_bytes().to_vec(), hex(g_hex));
        let ya = scalar("da3d23700a9e5699258aef94dc060dfda5ebb61f02a5ea77fad53f4ff0976d08");
        let yb = scalar("d2316b454718c35362d83d69df6320f38578ed5984651435e2949762d900b80d");
        let (pa, pb) = ((g * ya).compress().to_bytes(), (g * yb).compress().to_bytes());
        let pa_hex = "d6bac480f2c386c394efc7c47adb9925dcd2630b64f240c50f8d0eec482b9157";
        let pb_hex = "3ea7e0b19560d7c0b0f5734f63b955286dfa8232b5ebe63324e2d9e7433f7258";
        assert_eq!((pa.to_vec(), pb.to_vec()), (hex(pa_hex), hex(pb_hex)));
        let t = lv(&[&pa, b"ADa", &pb, b"ADb"]);
        let want = hex(concat!(
            "b69effbf61b51d56401c0f65601abe428de8206feaaf0e32198896dcae7b35cd",
            "2b38950a39dfd5d4a79164614c2984f7daa460b588c1e80c3fa2068af7900447"
        ));
        assert_eq!(isk(&ya, &pb, &sid, &t).unwrap().to_vec(), want);
        assert_eq!(isk(&yb, &pa, &sid, &t).unwrap().to_vec(), want);
        // B.3.11: a share that fails to decode, and the identity, abort.
        let s = scalar("7cd0e075fa7955ba52c02759a6c90dbbfc10e6d40aea8d283e407d88cf538a05");
        let bad = hex("2b3c6b8c4f3800e7aef6864025b4ed79bd599117e427c41bd47d93d654b4a51c");
        assert!(isk(&s, &bad, &sid, &t).is_none() && isk(&s, &[0; 32], &sid, &t).is_none());
    }

    /// Given on one device, taken on another over a relay; then spent.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_short_code_hands_over_its_secret_once() {
        let (_s, r) = relay().await;
        let (code, end) = give(std::slice::from_ref(&r), "test", b"invite", None).await.unwrap();
        assert_eq!(code.len(), 15, "xxx-xxx-xxx-xxx");
        let got = take(std::slice::from_ref(&r), "test", &code.to_uppercase(), None).await;
        assert_eq!(*got.unwrap(), b"invite");
        assert_eq!(end.await.unwrap(), End::Taken);
        assert!(take(std::slice::from_ref(&r), "test", &code, None).await.is_err(), "spent");
        // Another app's code never opens here.
        let (code, _) = give(std::slice::from_ref(&r), "test", b"invite", None).await.unwrap();
        assert!(take(std::slice::from_ref(&r), "other", &code, None).await.is_err());
    }

    /// With a password: the taker needs it too, and may give it after.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_password_locks_it_once_more() {
        let (_s, r) = relay().await;
        let (code, _) =
            give(std::slice::from_ref(&r), "test", b"seed", Some("horse battery")).await.unwrap();
        let rs = [r.clone()];
        let t = |p| take(&rs, "test", &code, p);
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
        assert!(give(std::slice::from_ref(&r), "test", &[0; SECRET + 1], None).await.is_err());
        let (code, _) = give(std::slice::from_ref(&r), "test", &big, Some("pw")).await.unwrap();
        let got = take(std::slice::from_ref(&r), "test", &code, Some("pw")).await;
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

    /// Anyone may reach the giver by its public nameplate, but one wrong
    /// guess at the rest of the code gets nothing and burns it.
    #[tokio::test(flavor = "multi_thread")]
    async fn one_wrong_guess_burns_a_code() {
        let (_s, r) = relay().await;
        let (code, end, m) = loop {
            let m = minute();
            let (code, end) = give(std::slice::from_ref(&r), "test", b"x", None).await.unwrap();
            if minute() == m {
                break (norm(&code).unwrap(), end, m);
            }
        };
        let e = irnet::on(std::slice::from_ref(&r)).bind().await.unwrap();
        let at = EndpointAddr::from_parts(
            meet("test", &code[..PLATE], m).public(),
            [TransportAddr::Relay(r.clone())],
        );
        let c = e.connect(at, ALPN).await.unwrap();
        let guess = if &code[PLATE..] == "000000" { "000001" } else { "000000" };
        let (g, sid) = cpace(&c, "test", guess).unwrap();
        let (y, ya) = share(g, &mut hedged(&[]));
        let ek = [0u8; EK];
        let (mut tx, mut rx) = c.open_bi().await.unwrap();
        tx.write_all(&[&ya[..], &ek].concat()).await.unwrap();
        let mut yb = [0u8; 32];
        rx.read_exact(&mut yb).await.unwrap();
        let isk = isk(&y, &yb, &sid, &lv(&[&ya, &ek, &yb, b""])).unwrap();
        tx.write_all(&proof(&*isk)).await.unwrap();
        tx.finish().unwrap();
        assert!(rx.read_to_end(MAX).await.unwrap_or_default().is_empty());
        assert_eq!(end.await.unwrap(), End::Spent);
        assert!(take(std::slice::from_ref(&r), "test", &code, None).await.is_err(), "burnt");
    }
}
