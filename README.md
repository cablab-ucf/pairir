# pairir

Hand a secret to another device with a code said aloud (`k7m-x9q-p3a-b2c`,
one minute, one try), or offline with a QR code.

```rust
let (code, end) = pairir::give(&[], "app", secret, Some(&pw)).await?;   // &[]: the lab's relays
let secret = pairir::take(&[], "app", &code, Some(&pw)).await?;
let text = pairir::seal_qr("app", secret, &pw).await?;     // QR code, no network
let secret = pairir::open_qr("app", &text, &pw).await?;
```

The code's first half (`k7m-x9q`, 30 bits) is a public nameplate: it only
finds the giver at the relay. The rest (`p3a-b2c`, 30 bits) runs CPace
(draft-irtf-cfrg-cpace, Ristretto255), a PAKE: nothing on the wire or at the
relay lets anyone test it offline, the taker proves it before the giver
answers, and a wrong guess spends the code. An impostor wins once in 2^30, at
most once per code.

Layers, each enough alone against a recording:

| Layer | Breaks only if |
|---|---|
| irnet's endpoint: TLS 1.3 with X25519MLKEM768, or the handshake is refused | TLS falls |
| sealed to the taker's fresh X-Wing key, under a key from X-Wing and CPace together | ML-KEM and X25519 both fall, and CPace too |
| under the password: Argon2id 256 MiB, 4 passes | the password is guessed |

- Post-quantum: every layer that guards a recording rests on ML-KEM.
  Authentication rests on CPace, which a quantum attacker can chip at only
  one discrete log per guessed code ("quantum-annoying"), within the
  giver's minute.
- One try, one minute: a code is answered once, for 60 s, to whoever
  reaches it first, even with a broken exchange. Whoever knows its nameplate
  (who heard it, and the relay) can so spend a code, never read it; nobody
  else finds it: dialing all 2^30 nameplates of a minute is over a terabyte.
  `end` tells the giver how its code ended (`Taken`, `Spent`, `Expired`):
  show `Spent`, for someone else used the code. Two codes with one nameplate
  in one app and minute (1 in 2^30 per pair) collide: give again.
- Every random draw is hedged (RFC 8937): OS randomness hashed with the
  secret (giver) or the code (taker). A rigged RNG on the giver predicts
  nothing; on the taker, whose only secret is the code, only the password
  layer holds.
- A QR code has only the password layer: use `password()` (99 bits).
- Clocks over a minute apart cannot meet. ML-KEM and X-Wing are RustCrypto's,
  not yet independently audited.

`android/pairir`: `Qr.bitmap(text, size)` and `ScanQr` (CameraX + ZXing, no
Play Services, under FLAG_SECURE).

License: GPL-3.0-or-later.
