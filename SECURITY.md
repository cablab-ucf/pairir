# Security

pairir hands a secret from one device to another with a short code (or a
password-sealed QR code). Report a vulnerability privately (GitHub security
advisory on this repository).

## Properties

- Short codes: 2^30 secrets; each code gives its holder one online try,
  spent by any connection within 20 s (the giver then hears Spent, never a
  silent Expired). A wrong guess learns nothing (CPace).
- CPace follows draft-irtf-cfrg-cpace (generator, ISK, transcript; checked
  against its test vectors). Deviations, all deliberate: the session id is
  the TLS exporter; party identities are bound by it, not by CI; key
  confirmation is one-sided (the taker), the giver confirmed by its sealed
  answer; ADa is the taker's X-Wing key, so it cannot be swapped.
- The answer is sealed to the taker with X-Wing (ML-KEM-768 + X25519) and
  keyed by both ISK and the KEM secret: safe if either holds against a
  passive attacker.
- QR codes: sealed under Argon2id (256 MiB, t=4) of a password of 16 or more
  characters (`password()` makes 99 bits); open has no minimum, so older
  codes still open.
- Transport: iroh QUIC, TLS 1.3 with X25519MLKEM768 only (irnet).

## Known limits (accepted, with reason)

- The rendezvous is derived from the code's first half: someone who sees
  that half can answer, which costs the code its one try (said as Spent).
- A man in the middle at the public rendezvous gets one online guess (2^-30).
- The QR's offline strength is its password's: a weak one typed by hand
  falls to a dictionary.

## Wire compatibility

Short codes (alphabet, CPace, sealing, password layer) stay as chatir v0.4.5
peers speak them (CLAUDE.md).
