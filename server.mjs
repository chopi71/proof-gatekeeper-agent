// Proof Gatekeeper agent — zkVerify Agent Games
//
// Receives HMAC-signed tasks from the platform, evaluates proof-backed
// payment conditions, and answers with a signed decision plus a Groth16
// proof generated locally with the gatekeeper circuit (snarkjs).
//
// Protocol facts (from the platform's own /build + /guide pages and the
// circuit recon in ../CIRCUIT-NOTES.md):
//   - POST <registered path> with header `x-agent-games-signature` =
//     HMAC over the RAW request body; verify BEFORE parsing JSON.
//   - Every response is signed the same way over the raw response body.
//   - Preflight: type "agent-games.preflight.v1" -> { ok: true, protocolVersion: "v1" }.
//   - Gatekeeper response: { decision, reason_code, proof, public_signals, proof_tx }.
//   - Tasks carry a hard 60 s response deadline: NEVER let proving or a
//     Kurier round-trip make us miss it — a correct decision without a proof
//     still scores; a timeout scores worse.

import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as snarkjs from 'snarkjs';

// ============================================================================
// CONFIG — assumptions to confirm on practice day (see README "Open questions")
// ============================================================================
// The platform pages name the header (`x-agent-games-signature`) and say the
// secret is a platform-generated 32-byte value, but never name the HMAC
// algorithm or digest encoding. HMAC-SHA256 hex is the working assumption;
// flip these two constants if practice feedback says otherwise.
const HMAC_ALGO = 'sha256';
const HMAC_DIGEST_ENCODING = 'hex';
// ============================================================================

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// --- tiny .env loader (no dependency) ---------------------------------------
function loadDotEnv(file) {
  try {
    for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
      const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
      if (m && process.env[m[1]] === undefined) {
        process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
      }
    }
  } catch { /* no .env file — fine, env may come from the host */ }
}
loadDotEnv(path.join(__dirname, '.env'));

const PORT = Number(process.env.PORT || 8080);
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const KURIER_API_KEY = process.env.KURIER_API_KEY || '';
const CIRCUITS_DIR = path.resolve(__dirname, process.env.CIRCUITS_DIR || '../circuits');
const WASM_PATH = path.join(CIRCUITS_DIR, 'gatekeeper.wasm');
const ZKEY_PATH = path.join(CIRCUITS_DIR, 'gatekeeper_final.zkey');
const SEEN_FILE = path.resolve(__dirname, process.env.SEEN_FILE || './seen.json');

const GATEKEEPER_VK_HASH = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const KURIER_BASE = 'https://api.kurier.xyz/api/v1';
const MAX_BODY_BYTES = 1024 * 1024;
// Overall per-request budget: keep the whole handling comfortably inside the
// platform's 60 s deadline, with margin for network jitter.
const REQUEST_BUDGET_MS = 50_000;

// BN128 scalar field prime (Fr). All circuit values are field elements mod p.
const FIELD_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

if (!HMAC_SECRET) {
  console.error('[boot] WARNING: AGENT_GAMES_HMAC_SECRET is not set — every signed request will fail verification.');
}
for (const f of [WASM_PATH, ZKEY_PATH]) {
  if (!fs.existsSync(f)) {
    console.error(`[boot] WARNING: circuit artifact missing: ${f} — decisions will be served without proofs.`);
  }
}

// --- logging ------------------------------------------------------------------
function log(...args) {
  console.log(new Date().toISOString(), ...args);
}

// --- HMAC helpers ---------------------------------------------------------------
function hmacHex(rawBody) {
  return crypto.createHmac(HMAC_ALGO, HMAC_SECRET).update(rawBody).digest(HMAC_DIGEST_ENCODING);
}

function verifySignature(rawBody, headerValue) {
  if (!HMAC_SECRET || !headerValue) return false;
  // Defensive: accept an optional "sha256=" style prefix.
  const provided = String(headerValue).trim().replace(/^sha256=/i, '').toLowerCase();
  const expected = hmacHex(rawBody);
  const a = Buffer.from(provided, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// --- field-element helpers (BigInt only, never float) ---------------------------
function toField(value, fieldName) {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) throw new Error(`field ${fieldName}: non-integer number`);
    return BigInt(value);
  }
  if (typeof value === 'string') {
    const s = value.trim();
    if (/^0[xX][0-9a-fA-F]+$/.test(s)) return BigInt(s);
    if (/^[0-9]+$/.test(s)) return BigInt(s);
    if (/^-[0-9]+$/.test(s)) return BigInt(s);
    throw new Error(`field ${fieldName}: not an integer string: ${JSON.stringify(value)}`);
  }
  throw new Error(`field ${fieldName}: unsupported type ${typeof value}`);
}
const modP = (x) => ((x % FIELD_P) + FIELD_P) % FIELD_P;
// VK hashes are compared as field elements (the circuit sees them reduced mod p).
const fieldsEqual = (a, b) => modP(a) === modP(b);

// Derive the circuit's taskId field element from the envelope's task_id.
// Numeric ids pass through unchanged. String ids ("gk_24_9d1") are mapped to
// the integer of their UTF-8 bytes — a deterministic GUESS; the platform's
// own derivation is not documented and must be confirmed from a live
// practice task (see README). If wrong, the decision still scores; only the
// proof's public signals would mismatch.
function taskIdToField(taskId) {
  if (taskId === undefined || taskId === null) return 0n;
  const s = String(taskId).trim();
  try { return modP(toField(s, 'task_id')); } catch { /* fall through */ }
  return modP(BigInt('0x' + Buffer.from(s, 'utf8').toString('hex')));
}

// --- persistent seen-set of proof_tx (proof-reuse detection) --------------------
const seenProofTx = new Set();
function loadSeen() {
  try {
    const arr = JSON.parse(fs.readFileSync(SEEN_FILE, 'utf8'));
    if (Array.isArray(arr)) for (const v of arr) seenProofTx.add(String(v));
    log(`[seen] loaded ${seenProofTx.size} proof_tx entries from ${SEEN_FILE}`);
  } catch { log('[seen] starting with an empty seen-set'); }
}
function saveSeen() {
  const tmp = `${SEEN_FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify([...seenProofTx]));
  fs.renameSync(tmp, SEEN_FILE); // atomic replace
}
const normalizeTx = (tx) => String(tx).trim().toLowerCase();
loadSeen();

// --- envelope normalization -------------------------------------------------------
// Both documented shapes are accepted:
//  (a) { type, task_id, input: { registered_vk, proof_vk, minimum, public_balance,
//        expiry_block, current_block, recipient, condition_recipient, amount,
//        max_transfer, proof_tx } }
//  (b) { type, task_id, vk_hash, proof: { vk_hash, ... }, max_transfer, proof_tx,
//        statement: { amount, minimum, public_balance, expiry_block, current_block,
//                     recipient, condition_recipient, task_id } }
function pick(...candidates) {
  for (const c of candidates) {
    if (c !== undefined && c !== null) return c;
  }
  return undefined;
}

function normalizeTask(env) {
  const input = env.input && typeof env.input === 'object' ? env.input : {};
  const st = env.statement && typeof env.statement === 'object' ? env.statement : {};
  const proofObj = env.proof && typeof env.proof === 'object' ? env.proof : {};

  const raw = {
    task_id: pick(st.task_id, env.task_id, input.task_id),
    registered_vk: pick(input.registered_vk, env.registered_vk, env.vk_hash, st.registered_vk),
    proof_vk: pick(input.proof_vk, env.proof_vk, proofObj.vk_hash, env.proof_vk_hash),
    minimum: pick(input.minimum, st.minimum, env.minimum),
    public_balance: pick(input.public_balance, st.public_balance, env.public_balance),
    expiry_block: pick(input.expiry_block, st.expiry_block, env.expiry_block),
    current_block: pick(input.current_block, st.current_block, env.current_block),
    recipient: pick(input.recipient, st.recipient, env.recipient),
    condition_recipient: pick(input.condition_recipient, st.condition_recipient, env.condition_recipient),
    amount: pick(input.amount, st.amount, env.amount),
    max_transfer: pick(input.max_transfer, st.max_transfer, env.max_transfer),
    proof_tx: pick(input.proof_tx, env.proof_tx, st.proof_tx),
    deadline_at: pick(env.deadline_at, env.expires_at),
  };

  // Throws on any missing/invalid numeric field — the caller fails closed.
  const t = {
    task_id: raw.task_id,
    proof_tx_raw: raw.proof_tx,
    registered_vk: toField(raw.registered_vk, 'registered_vk'),
    proof_vk: toField(raw.proof_vk, 'proof_vk'),
    minimum: toField(raw.minimum, 'minimum'),
    public_balance: toField(raw.public_balance, 'public_balance'),
    expiry_block: toField(raw.expiry_block, 'expiry_block'),
    current_block: toField(raw.current_block, 'current_block'),
    recipient: toField(raw.recipient, 'recipient'),
    condition_recipient: toField(raw.condition_recipient, 'condition_recipient'),
    amount: toField(raw.amount, 'amount'),
    max_transfer: toField(raw.max_transfer, 'max_transfer'),
    deadline_at: raw.deadline_at,
  };
  return t;
}

// --- decision logic ---------------------------------------------------------------
// Checks run in the mandated order; the FIRST failure wins the reason_code.
function decide(t) {
  // 1. Verification-key substitution.
  if (!fieldsEqual(t.proof_vk, t.registered_vk)) {
    return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION' };
  }
  // 2. Public balance below the condition minimum.
  if (t.public_balance < t.minimum) {
    return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH' };
  }
  // 3. Proof reference already seen (agent-side; the circuit cannot check this).
  const txKey = t.proof_tx_raw != null ? normalizeTx(t.proof_tx_raw) : null;
  if (txKey && seenProofTx.has(txKey)) {
    return { decision: 'REJECT', reason_code: 'PROOF_REUSED', reused: true };
  }
  // 4. Expired condition.
  //    NOTE: the circuit asserts decision correctness with the check
  //    `currentBlock < expiryBlock` (CIRCUIT-NOTES, recon-verified), i.e. a
  //    task at current_block == expiry_block is already expired on-chain and
  //    an APPROVE there is literally unprovable. We therefore use >= here
  //    rather than the prose's "expiry has passed" (>). Flagged in README.
  if (t.current_block >= t.expiry_block) {
    return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION' };
  }
  // 5. Recipient committed in the proof != recipient on the condition.
  //    (Hex parsing is case-insensitive, so BigInt comparison covers case.)
  if (t.recipient !== t.condition_recipient) {
    return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH' };
  }
  // 6. Amount above the single-transfer cap.
  if (t.amount > t.max_transfer) {
    return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW' };
  }
  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION' };
}

// --- proof generation ---------------------------------------------------------------
function randomSalt() {
  // 31 random bytes < 2^248 << p — always a valid field element.
  return BigInt('0x' + crypto.randomBytes(31).toString('hex')).toString();
}

async function generateProof(t, decision) {
  const input = {
    registeredVkHash: modP(t.registered_vk).toString(),
    proofVkHash: modP(t.proof_vk).toString(),
    minimum: modP(t.minimum).toString(),
    publicBalance: modP(t.public_balance).toString(),
    expiryBlock: modP(t.expiry_block).toString(),
    currentBlock: modP(t.current_block).toString(),
    recipient: modP(t.recipient).toString(),
    conditionRecipient: modP(t.condition_recipient).toString(),
    amount: modP(t.amount).toString(),
    maxTransfer: modP(t.max_transfer).toString(),
    decision: decision === 'APPROVE' ? '1' : '0',
    taskId: taskIdToField(t.task_id).toString(),
    salt: randomSalt(),
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM_PATH, ZKEY_PATH);
  return { proof, publicSignals };
}

// --- Kurier (optional, best-effort, never blocks past the budget) -------------------
// TODO(practice-day): the exact Kurier request/response field names beyond
// proof/publicSignals come from the /build page's code sketch only. Verify
// against the Kurier docs / a first live submission before relying on this.
function buildKurierPayload(proof, publicSignals) {
  return {
    proofType: 'groth16',
    vkRegistered: true,
    proofOptions: { library: 'snarkjs', curve: 'bn128' },
    proofData: {
      proof,
      publicSignals,
      vkHash: GATEKEEPER_VK_HASH,
    },
  };
}

async function submitToKurier(proof, publicSignals, deadlineMs) {
  if (!KURIER_API_KEY) return; // skip silently
  const remaining = () => deadlineMs - Date.now();
  try {
    const res = await fetch(`${KURIER_BASE}/submit-proof/${KURIER_API_KEY}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(buildKurierPayload(proof, publicSignals)),
      signal: AbortSignal.timeout(Math.max(1000, remaining())),
    });
    const data = await res.json().catch(() => ({}));
    const jobId = data.jobId || data.job_id || data.proofId || data.id;
    log(`[kurier] submitted, status=${res.status}, job=${jobId || 'n/a'}, state=${data.status || data.state || 'n/a'}`);
    if (!jobId) return;
    // Poll until Finalized, hard-capped by the request budget.
    while (remaining() > 1500) {
      await new Promise((r) => setTimeout(r, 2000));
      try {
        const pr = await fetch(`${KURIER_BASE}/job/${jobId}`, {
          signal: AbortSignal.timeout(Math.max(1000, remaining())),
        });
        const pj = await pr.json().catch(() => ({}));
        const state = String(pj.status || pj.state || '');
        if (/final/i.test(state)) { log(`[kurier] job ${jobId} Finalized`); return; }
        if (/fail|error|invalid/i.test(state)) { log(`[kurier] job ${jobId} terminal state: ${state}`); return; }
      } catch (e) {
        log(`[kurier] poll error (continuing): ${e.message}`);
        return;
      }
    }
    log('[kurier] not finalized within budget — responding anyway');
  } catch (e) {
    log(`[kurier] submission failed (non-fatal): ${e.message}`);
  }
}

// --- gatekeeper handling --------------------------------------------------------------
async function handleGatekeeper(env, startedAt) {
  let t;
  try {
    t = normalizeTask(env);
  } catch (e) {
    log(`[task] malformed envelope, failing closed: ${e.message}`);
    return {
      status: 200,
      body: {
        decision: 'REJECT',
        reason_code: 'MALFORMED_TASK',
        proof: null,
        public_signals: null,
        proof_tx: env && env.proof_tx != null ? env.proof_tx : null,
      },
    };
  }

  const { decision, reason_code, reused } = decide(t);
  log(`[task] id=${t.task_id} decision=${decision} reason=${reason_code}`);

  // Record every non-reused proof_tx, whatever the decision was.
  const txKey = t.proof_tx_raw != null ? normalizeTx(t.proof_tx_raw) : null;
  if (txKey && !reused) {
    seenProofTx.add(txKey);
    try { saveSeen(); } catch (e) { log(`[seen] save failed: ${e.message}`); }
  }

  // Prove — except for PROOF_REUSED, which by the event rules has no proof
  // to submit. A proving failure must never cost the deadline: fall back to
  // the bare decision.
  let proof = null;
  let publicSignals = null;
  if (!reused) {
    const p0 = Date.now();
    try {
      ({ proof, publicSignals } = await generateProof(t, decision));
      log(`[task] id=${t.task_id} proof generated in ${Date.now() - p0} ms`);
    } catch (e) {
      log(`[task] id=${t.task_id} PROVING FAILED (decision still returned): ${e.message}`);
    }
  }

  if (proof) {
    const deadlineMs = startedAt + REQUEST_BUDGET_MS;
    await submitToKurier(proof, publicSignals, deadlineMs);
  }

  return {
    status: 200,
    body: {
      decision,
      reason_code,
      proof,
      public_signals: publicSignals,
      proof_tx: t.proof_tx_raw != null ? t.proof_tx_raw : null,
    },
  };
}

// --- HTTP plumbing -----------------------------------------------------------------------
function sendSigned(res, status, obj) {
  const raw = Buffer.from(JSON.stringify(obj), 'utf8');
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'x-agent-games-signature': hmacHex(raw),
  });
  res.end(raw);
}

const server = http.createServer((req, res) => {
  const startedAt = Date.now();

  if (req.method === 'GET' && (req.url === '/health' || req.url === '/')) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, service: 'proof-gatekeeper-agent' }));
    return;
  }

  if (req.method !== 'POST' || req.url !== '/agent') {
    sendSigned(res, 404, { error: 'not_found' });
    return;
  }

  const chunks = [];
  let size = 0;
  req.on('data', (chunk) => {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) {
      sendSigned(res, 413, { error: 'body_too_large' });
      req.destroy();
      return;
    }
    chunks.push(chunk);
  });
  req.on('error', () => { /* client went away — nothing to do */ });
  req.on('end', async () => {
    const raw = Buffer.concat(chunks);
    try {
      // 1. Verify the signature over the RAW body BEFORE parsing.
      if (!verifySignature(raw, req.headers['x-agent-games-signature'])) {
        log('[auth] signature verification FAILED');
        sendSigned(res, 401, { error: 'invalid_signature' });
        return;
      }
      // 2. Parse.
      let env;
      try {
        env = JSON.parse(raw.toString('utf8'));
      } catch {
        sendSigned(res, 400, { error: 'invalid_json' });
        return;
      }
      // 3. Dispatch.
      if (env.type === 'agent-games.preflight.v1') {
        sendSigned(res, 200, { ok: true, protocolVersion: 'v1' });
        return;
      }
      if (env.type === 'agent-games.proof-gatekeeper.v1') {
        const { status, body } = await handleGatekeeper(env, startedAt);
        sendSigned(res, status, body);
        return;
      }
      log(`[dispatch] unknown type: ${JSON.stringify(env.type)}`);
      sendSigned(res, 400, { error: 'unknown_type', type: env.type ?? null });
    } catch (e) {
      // Fail closed, never crash: if this was a gatekeeper task, answer with a
      // bare REJECT; otherwise a signed 500.
      log(`[error] unhandled: ${e.stack || e.message}`);
      try {
        sendSigned(res, 500, { error: 'internal_error' });
      } catch { /* socket already gone */ }
    }
  });
});

// Keep the process alive through unexpected async failures — a crashed agent
// scores timeouts on every task.
process.on('uncaughtException', (e) => log(`[fatal-guard] uncaughtException: ${e.message}`));
process.on('unhandledRejection', (e) => log(`[fatal-guard] unhandledRejection: ${e && e.message}`));
// Exported for serverless hosts: Vercel's Node runtime takes this file as
// the app entry and requires the http.Server as the default export. A direct
// `node server.mjs` run listens as before.
export { server };
export default server;

const runDirectly = process.argv[1] !== undefined && import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (runDirectly) {
  server.listen(PORT, () => log(`[boot] proof-gatekeeper-agent listening on :${PORT} (POST /agent)`));
}
