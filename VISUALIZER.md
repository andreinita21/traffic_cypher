# The Visualizer — Camera Entropy Pipeline

How the **Visualizer** works when entropy comes from the **phone camera**.

Two things are involved: the Visualizer is a *read-only view* in the
password-manager dashboard, and the camera (`phone.html`) is the *entropy
source* that feeds it. They are separate browser contexts talking to the same
daemon.

Paths below refer to the Rust backend (`traffic_cypher_in_Rust/src/`); the C
build (`traffic_cypher_in_C/src_c/`) mirrors the same pipeline.

---

## Setup (happens once)

**1. Unlock spawns the entropy daemon.** When you unlock the vault, the
`unlock` handler spawns the entropy-collection daemon as a background task —
`web/routes.rs:457` → `key_rotation::start_rotation_daemon`. It runs *only
while the vault is unlocked*; locking cancels it. This is why the Visualizer
(an authenticated endpoint) and a live pipeline always coincide.

**2. Phone registers a camera slot.** On `phone.html`, hitting *Start* POSTs
`{label}` to `/api/streams/phone` (`frontend/phone.html`, `start()`). The
backend `register_phone` (`multi_stream.rs:391`) appends a `SlotKind::Phone`
slot, generates a **32-byte random upload token**, and returns
`{index, upload_token}`. The token is the auth boundary for every subsequent
frame — no Bearer session needed.

---

## Per-second loop (camera → entropy)

**3. Phone captures a frame** — `captureAndSend()` runs every 1000 ms
(`frontend/phone.html`):

- draws the live `<video>` onto a **320×240 canvas**;
- `getImageData()` → RGBA pixels;
- `rgbaToPpm()` drops alpha and builds a **P6 PPM** blob
  (`P6\n320 240\n255\n` + 230 400 RGB bytes).

**4. Phone POSTs the frame** to `/api/streams/phone/{index}/frame` with header
`X-Upload-Token: <64-hex>`.

**5. Backend ingests it** — `push_phone_frame` (`web/routes.rs:1164` →
`multi_stream.rs:425`):

- `parse_ppm_header` validates the `P6` header and that pixel length equals
  `width * height * 3`;
- the token is **constant-time compared** against the slot's token
  (`ct_eq_hex64`) — mismatch → `403`;
- the first valid frame flips the slot `CONNECTING → ACTIVE`;
- the frame is `try_send` into a shared bounded channel (full ring → `503`,
  phone retries on its next tick).

**6. Rotation daemon picks a frame** — its loop ticks every 1 s
(`key_rotation.rs:104`). `pick_random_frame` (`multi_stream.rs:339`) drains
*all* queued frames, bumps each slot's `frames_captured`, groups frames by
stream, picks one stream at random, and returns its **most recent** frame.

**7. Entropy extraction** — `extract_entropy` (`entropy_extractor.rs:27`) turns
pixels into entropy bytes:

- full-frame SHA-256;
- **inter-frame delta**: `current XOR previous`, then SHA-256 of the delta —
  *this is the real entropy: pixel motion between consecutive frames*;
- 8×8 spatial block hashes.

(The first frame has no predecessor, so it has no delta component yet.)

**8. Entropy pool** — `pool.push(...)` into an 8-slot rolling `VecDeque`
(`entropy_pool.rs:5`); the oldest entry is evicted past 8. `pool.digest()` is
a SHA-256 over all buffered frames.

**9. Mix + derive** — `system_entropy_mixer::mix_entropy` folds in OS
randomness; `crypto_derivation::derive_key` (HKDF) chains the result with the
previous key into a fresh 32-byte value.

**10. State updated** (`key_rotation.rs:141-145`): `key_epoch++`,
`frames_processed++`, `latest_entropy`, `pool_depth`, and
`has_traffic_entropy = true`. If no frame arrives for 3 ticks
(`TRAFFIC_GRACE_TICKS`), `has_traffic_entropy` flips back to `false`.

---

## Visualizer renders it

**11. Poll** — `startVisualizerPolling` (`frontend/app.js:927`) issues
`GET /api/entropy-snapshot` every 1000 ms. The handler
(`web/routes.rs:1239`) returns:

```json
{
  "key_epoch": 0,
  "frames_processed": 0,
  "pool_depth": 0,
  "has_traffic_entropy": false,
  "is_running": true,
  "entropy_source": "os",
  "latest_key_hex": "0000000000000000"
}
```

**12. Paint** — each poll updates the 7-node pipeline and 4 stat cards
(`frontend/app.js:936-997`).

---

## What's real vs. decorative

The Visualizer mixes live data with animation. Worth knowing which is which:

| Element | Source |
|---|---|
| Stat cards: Key Epoch, Frames Processed, Pool Depth, Pipeline Status | ✅ real — straight from the snapshot |
| "Entropy Pool" 8 slots filling | ✅ real — `pool_depth / 8` |
| "Frame Capture" detail (Traffic Stream / OS) | ✅ real — `entropy_source` |
| "DEK Generation" hex | ✅ real — `latest_key_hex` (first 32 bytes of latest derived entropy) |
| **"Entropy Extraction" flowing hex** | ❌ **fake** — 16 random hex chars generated client-side each tick (`app.js:956-958`) |
| Node pulses, particles, scanlines, mixer ring, lock pulse | ❌ decorative CSS animation |
| "System Mixer" / "Vault Encryption" captions | static text, always shown |

When the camera is feeding the pipeline, the honest signals are:

- **Frames Processed** climbing,
- **Pool Depth** reaching `8/8`,
- **Key Epoch** incrementing every second,
- **Frame Capture** showing the traffic/phone source.

The animated hash stream is eye-candy, not the actual SHA-256.

> **Nuance:** `frames_processed` only increments on ticks where the daemon
> actually *consumed* a camera frame. If it stalls while the phone reports
> frames sent, frames are arriving but the daemon isn't picking them — e.g. a
> disabled slot, or ring-buffer pressure.
