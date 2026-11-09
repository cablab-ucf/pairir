# irpair

Hand a secret to another device with a code said aloud (`k7m-x9q-p3a`, one
minute, one try), or offline with a QR code.

```rust
let code = irpair::give(irnet::endpoint(), "app", secret, Some(&pw)).await?;
let secret = irpair::take(irnet::endpoint(), &relays, "app", &code, Some(&pw)).await?;
let text = irpair::seal_qr("app", secret, &pw).await?;     // QR code, no network
let secret = irpair::open_qr("app", &text, &pw).await?;
```

Layers, each enough alone against a recording:

| Layer | Breaks only if |
|---|---|
| iroh TLS 1.3, X25519MLKEM768, to an identity derived from the code (no CA) | TLS falls |
| sealed to the taker's fresh X-Wing key | ML-KEM and X25519 both fall |
| under the password: Argon2id 256 MiB, 4 passes, salted by the code's proof | the password is guessed |

- The code (45 bits, Argon2id, salted by app and UTC minute) is a throwaway
  identity the giver answers as. One wrong proof spends it.
- Every random draw is hedged (RFC 8937): OS randomness hashed with the
  secret (giver) or the code (taker), so a rigged RNG alone predicts no
  key, nonce or code.
- A QR code has only the password layer: use `password()` (100 bits).
- Clocks over a minute apart cannot meet. ML-KEM and X-Wing are RustCrypto's,
  not yet independently audited.

`android/irpair`: `Qr.bitmap(text, size)` and `ScanQr` (CameraX + ZXing, no
Play Services, under FLAG_SECURE).

License: GPL-3.0-or-later.
