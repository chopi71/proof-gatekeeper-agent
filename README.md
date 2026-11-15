# Proof Gatekeeper Agent — zkVerify Agent Games

An HTTPS-ready agent endpoint for the **Proof Gatekeeper** track of the
zkVerify Agent Games. It receives HMAC-signed decision tasks from the
platform, evaluates whether a proof-backed payment condition may be approved,
and answers with a signed decision plus a locally generated Groth16 proof
from the official gatekeeper circuit.

## Run

```bash
npm install
cp .env.example .env   # fill in the real HMAC secret from the dashboard
npm start              # listens on PORT (default 8080), POST /agent
```

The platform requires a **public HTTPS** endpoint — terminate TLS at a
tunnel/host in front of this plain-HTTP listener, and register the full
handler path (e.g. `https://<host>/agent`).

Requires the circuit artifacts `gatekeeper.wasm` and `gatekeeper_final.zkey`
in `CIRCUITS_DIR` (default `../circuits`, from
`https://agentgames.zkverify.io/circuits/`).

## Test

```bash
npm test   # node test.mjs — spins up the server with a FAKE test secret
```

The harness replays signed sample envelopes for all 7 cases (valid + the six
traps, in both documented envelope shapes), and asserts decisions, reason
codes, proof presence and `groth16 verify` validity, preflight behavior,
bad-signature rejection, and seen-set persistence across a restart.

## Environment

| Variable | Meaning |
|---|---|
| `PORT` | Listen port (default 8080) |
| `AGENT_GAMES_HMAC_SECRET` | Platform-generated agent secret (dashboard → agent settings → Rotate Secret; shown once). Never commit it. |
| `KURIER_API_KEY` | Optional. If set, generated proofs are submitted to Kurier for on-chain verification (best-effort; never delays the response past budget). |
| `CIRCUITS_DIR` | Where the circuit artifacts live (default `../circuits`) |
| `SEEN_FILE` | Persistent proof_tx seen-set (default `./seen.json`) |

## How it works

1. **Authenticate first.** The `x-agent-games-signature` header is checked
   (HMAC over the *raw* body, constant-time compare) before any JSON parsing.
   Every response is signed the same way over its raw body.
2. **Preflight.** `agent-games.preflight.v1` → `{ ok: true, protocolVersion: "v1" }`.
3. **Normalize.** Both documented envelope shapes are accepted: the
   `input { … }` shape and the `statement { … }` shape (with `vk_hash` /
   `proof.vk_hash` at the top level). Everything numeric becomes a `BigInt`
   field element — no floats anywhere.
4. **Decide.** Checks run in a fixed order; the first failure wins:
   `VK_SUBSTITUTION` → `THRESHOLD_MISMATCH` → `PROOF_REUSED` →
   `EXPIRED_CONDITION` → `RECIPIENT_MISMATCH` → `AMOUNT_OVERFLOW` → otherwise
   `APPROVE / VALID_CONDITION`. Addresses/hashes compare as field elements
   (hex parsing is case-insensitive; VK hashes compare reduced mod the BN128
   prime, exactly as the circuit sees them).
5. **Remember.** Every non-reused `proof_tx` is recorded in the persistent
   seen-set (atomic file replace), so a replayed proof is caught even across
   restarts.
6. **Prove.** Except for `PROOF_REUSED` (the event rules say a reused proof
   has no proof to submit), the agent generates a Groth16 proof with
   `snarkjs.groth16.fullProve` over the task fields plus its decision
   (1 = APPROVE, 0 = REJECT) and a fresh random salt (~1.4 s). The circuit
   itself asserts that the decision equals its own evaluation of the five
   on-chain checks, so a valid proof can only ever back a correct decision.
   If proving ever fails, the bare decision is still returned — the 60 s
   deadline is never sacrificed for a proof.
7. **Respond.** Signed JSON:
   `{ decision, reason_code, proof, public_signals, proof_tx }`
   (`proof`/`public_signals` are `null` when skipped or failed).

## Design decisions worth knowing

- **Expiry boundary:** the circuit enforces `currentBlock < expiryBlock`
  (recon-verified in `../CIRCUIT-NOTES.md`), so a task at
  `current_block == expiry_block` is already expired and an APPROVE there is
  unprovable. The agent therefore rejects with `EXPIRED_CONDITION` when
  `current_block >= expiry_block`.
- **Fail closed everywhere:** malformed envelopes get a signed
  `REJECT / MALFORMED_TASK`, unknown types a signed 400, bad signatures a
  401, and the process guards against uncaught exceptions — a crashed agent
  would score timeouts on every task.
- **Kurier is strictly best-effort:** submission + polling are capped by an
  overall per-request budget (50 s of the 60 s deadline); the decision and
  proof are returned regardless of Kurier's state.

## Open questions — to confirm on practice day

1. **HMAC algorithm/encoding.** The platform pages name the header and say
   the secret is 32 bytes, but never name the algorithm. The server assumes
   **HMAC-SHA256, hex digest** (single constants at the top of `server.mjs`).
   A failed preflight signature check is the signal to flip them.
2. **Live envelope shape.** Both documented shapes are handled, but real
   task payloads show truncated hashes in the public examples
   (`"0x7d3a...f291"`). Confirm full values arrive; if a field format differs,
   `normalizeTask` in `server.mjs` is the one place to adjust.
3. **`taskId` derivation.** The circuit takes `taskId` as a field element,
   but envelope task ids are strings like `gk_24_9d1`. Numeric ids pass
   through; string ids are mapped to the integer of their UTF-8 bytes. If the
   platform derives it differently, our decisions still score — only the
   proof's public signals would mismatch. Verify against the first practice
   task's expected public signals.
4. **Kurier payload/status fields.** Only `proof`/`publicSignals` are firmly
   documented (from the /build code sketch). The payload builder and the
   `job/{id}` polling in `server.mjs` are marked `TODO(practice-day)` and
   must be verified against the Kurier docs / a first live submission.
5. **Reason-code strings.** Taken from the event page's trap encyclopedia
   (`VK_SUBSTITUTION`, `THRESHOLD_MISMATCH`, `PROOF_REUSED`,
   `EXPIRED_CONDITION`, `RECIPIENT_MISMATCH`, `AMOUNT_OVERFLOW`,
   `VALID_CONDITION`). The response code block on /build shows
   `decision` + `reason_code` + `proof_tx`; the surrounding prose and the
   starter prompt require `proof` + `public_signals` as well, so both are
   sent. Practice feedback will confirm the exact accepted set.
