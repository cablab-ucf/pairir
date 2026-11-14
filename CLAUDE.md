# Notes for Claude

- CI and release builds are deliberate, never routine: Actions minutes are
  scarce (private repos' Actions do not run; chatir's ci.yml is off by hand).
  Verify locally (`cargo fmt`, `clippy -D warnings`, tests). Never dispatch a
  workflow or push a tag to see whether something builds. A release is built
  once, when everything it ships is verified, merged and built as it should
  ship; not a version that is replaced hours later.
- The wire stays compatible with chatir v0.4.5 and later: short codes
  (their alphabet, CPace, the sealing to the taker, the password layer).
  Change it only when nothing else works, keeping the old form beside the
  new.
- A code that joins a space, starts a DM or links a device must leave
  both sides reachable by push at once (each side's lane told, a
  sleeping phone woken): chatir's core tests (solo.rs, net.rs) before it
  lands.
