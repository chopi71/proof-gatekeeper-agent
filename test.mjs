// Local test harness for the Proof Gatekeeper agent.
//
// Starts server.mjs with the FAKE test secret from .env.test, replays signed
// sample envelopes for all 7 cases (valid + the 6 traps, in both documented
// envelope shapes where practical), and asserts decisions, reason codes,
// proof presence/validity, preflight behavior, and signature rejection.
//
// Run: node test.mjs   (exit code 0 = all pass)

import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as snarkjs from 'snarkjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// --- load the test-only (fake) config ----------------------------------------
const testEnv = {};
for (const line of fs.readFileSync(path.join(__dirname, '.env.test'), 'utf8').split('\n')) {
  const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
  if (m) testEnv[m[1]] = m[2];
}
const SECRET = testEnv.AGENT_GAMES_HMAC_SECRET;
const PORT = Number(testEnv.PORT || 18099);
const BASE = `http://127.0.0.1:${PORT}`;
const SEEN_ABS = path.resolve(__dirname, testEnv.SEEN_FILE || './seen.test.json');
const VKEY = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../vkey.json'), 'utf8'));

// --- sample data (values mirror the platform's published examples) ------------
const VK_REGISTERED = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0'; // gatekeeper vk
const VK_OTHER = '0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047';      // vfyPolicy vk (a realistic substitution)
const RECIPIENT = '0x0000000000000000000000000000000000001001';
const RECIPIENT_OTHER = '0x0000000000000000000000000000000000002002';
const BASE_FIELDS = {
  registered_vk: VK_REGISTERED,
  proof_vk: VK_REGISTERED,
  minimum: '1000',
  public_balance: '1460',
  expiry_block: 19842201,
  current_block: 19832000,
  recipient: RECIPIENT,
  condition_recipient: RECIPIENT,
  amount: '500',
  max_transfer: '1000',
};
const tx = (n) => '0x' + n.toString(16).padStart(64, '0');

function shapeA(taskId, overrides = {}) {
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: taskId,
    mode: 'competition',
    issued_at: '2026-11-15T09:00:00Z',
    deadline_at: '2026-11-15T09:01:00Z',
    input: { ...BASE_FIELDS, proof_tx: tx(0xf00d), ...overrides },
  };
}

function shapeB(taskId, overrides = {}) {
  const f = { ...BASE_FIELDS, ...overrides };
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: taskId,
    timestamp: '2026-11-15T09:00:00Z',
    expires_at: '2026-11-15T09:01:00Z',
    agent: { id: 'test-agent' },
    vk_hash: f.registered_vk,
    proof: {
      pi_a: ['0', '0', '1'],
      pi_b: [['0', '0'], ['0', '0'], ['1', '0']],
      pi_c: ['0', '0', '1'],
      protocol: 'groth16',
      curve: 'bn128',
      vk_hash: f.proof_vk,
    },
    statement: {
      claim: 'PUBLIC_BALANCE >= MINIMUM',
      amount: f.amount,
      minimum: f.minimum,
      public_balance: f.public_balance,
      expiry_block: f.expiry_block,
      current_block: f.current_block,
      recipient: f.recipient,
      condition_recipient: f.condition_recipient,
      task_id: taskId,
    },
    max_transfer: f.max_transfer,
    proof_tx: f.proof_tx || tx(0xbeef),
    requester: '0x0000000000000000000000000000000000009999',
  };
}

// --- tiny assertion framework ---------------------------------------------------
let passed = 0;
let failed = 0;
const failures = [];
function check(name, cond, detail = '') {
  if (cond) { passed++; console.log(`  PASS  ${name}`); }
  else { failed++; failures.push(name); console.log(`  FAIL  ${name}${detail ? ` — ${detail}` : ''}`); }
}

const sign = (raw) => crypto.createHmac('sha256', SECRET).update(raw).digest('hex');

async function postSigned(obj, { secret = SECRET, pathName = '/agent' } = {}) {
  const raw = Buffer.from(JSON.stringify(obj), 'utf8');
  const t0 = Date.now();
  const res = await fetch(`${BASE}${pathName}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-agent-games-signature': crypto.createHmac('sha256', secret).update(raw).digest('hex') },
    body: raw,
  });
  const text = await res.text();
  const ms = Date.now() - t0;
  let body = null;
  try { body = JSON.parse(text); } catch { /* leave null */ }
  // Verify the response signature the same way the platform would.
  const expectedSig = crypto.createHmac('sha256', SECRET).update(Buffer.from(text, 'utf8')).digest('hex');
  const sigOk = res.headers.get('x-agent-games-signature') === expectedSig;
  return { status: res.status, body, ms, sigOk };
}

async function expectDecision(label, envelope, wantDecision, wantReason, { wantProof } = {}) {
  console.log(`\nCASE ${label}`);
  const r = await postSigned(envelope);
  check(`${label}: HTTP 200`, r.status === 200, `got ${r.status}`);
  check(`${label}: response signature valid`, r.sigOk);
  check(`${label}: decision=${wantDecision}`, r.body && r.body.decision === wantDecision, `got ${r.body && r.body.decision}`);
  check(`${label}: reason_code=${wantReason}`, r.body && r.body.reason_code === wantReason, `got ${r.body && r.body.reason_code}`);
  if (wantProof === true) {
    check(`${label}: proof present`, !!(r.body && r.body.proof && Array.isArray(r.body.public_signals)));
    if (r.body && r.body.proof) {
      let ok = false;
      try { ok = await snarkjs.groth16.verify(VKEY, r.body.public_signals, r.body.proof); } catch (e) { ok = false; }
      check(`${label}: groth16 verify OK`, ok === true);
    }
    console.log(`        round-trip ${r.ms} ms (proving dominates)`);
  } else if (wantProof === false) {
    check(`${label}: proof absent (null)`, r.body && r.body.proof === null && r.body.public_signals === null);
    console.log(`        round-trip ${r.ms} ms`);
  }
  return r;
}

// --- server lifecycle ---------------------------------------------------------------
function startServer() {
  const child = spawn(process.execPath, ['server.mjs'], {
    cwd: __dirname,
    env: {
      ...process.env,
      PORT: String(PORT),
      AGENT_GAMES_HMAC_SECRET: SECRET,
      SEEN_FILE: testEnv.SEEN_FILE || './seen.test.json',
      KURIER_API_KEY: '', // tests must never hit the real Kurier
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', (d) => process.stdout.write(`  [server] ${d}`));
  child.stderr.on('data', (d) => process.stdout.write(`  [server!] ${d}`));
  return child;
}

async function waitForHealth() {
  for (let i = 0; i < 50; i++) {
    try {
      const r = await fetch(`${BASE}/health`);
      if (r.ok) return;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error('server did not become healthy');
}

async function main() {
  fs.rmSync(SEEN_ABS, { force: true });
  let server = startServer();
  try {
    await waitForHealth();
    console.log('Server up. Running cases…');

    // 1. Preflight
    console.log('\nCASE preflight');
    {
      const r = await postSigned({ type: 'agent-games.preflight.v1', nonce: 'test-1' });
      check('preflight: HTTP 200', r.status === 200, `got ${r.status}`);
      check('preflight: ok=true', r.body && r.body.ok === true);
      check('preflight: protocolVersion=v1', r.body && r.body.protocolVersion === 'v1');
      check('preflight: response signature valid', r.sigOk);
    }

    // 2–8. Shape (a): valid + all six traps (each with its own proof_tx)
    await expectDecision('A valid', shapeA('101', { proof_tx: tx(1) }), 'APPROVE', 'VALID_CONDITION', { wantProof: true });
    await expectDecision('A vk-substitution', shapeA('102', { proof_vk: VK_OTHER, proof_tx: tx(2) }), 'REJECT', 'VK_SUBSTITUTION', { wantProof: true });
    await expectDecision('A threshold', shapeA('103', { public_balance: '999', proof_tx: tx(3) }), 'REJECT', 'THRESHOLD_MISMATCH', { wantProof: true });
    await expectDecision('A expired', shapeA('104', { current_block: 19842202, proof_tx: tx(4) }), 'REJECT', 'EXPIRED_CONDITION', { wantProof: true });
    await expectDecision('A expired-at-boundary (current == expiry)', shapeA('105', { current_block: 19842201, proof_tx: tx(5) }), 'REJECT', 'EXPIRED_CONDITION', { wantProof: true });
    await expectDecision('A recipient', shapeA('106', { condition_recipient: RECIPIENT_OTHER, proof_tx: tx(6) }), 'REJECT', 'RECIPIENT_MISMATCH', { wantProof: true });
    await expectDecision('A overflow', shapeA('107', { amount: '1001', proof_tx: tx(7) }), 'REJECT', 'AMOUNT_OVERFLOW', { wantProof: true });

    // 9. Proof reuse: first submission proves + approves, replay is rejected without a proof
    const reuseEnv = shapeA('108', { proof_tx: tx(8) });
    await expectDecision('A reuse (first)', reuseEnv, 'APPROVE', 'VALID_CONDITION', { wantProof: true });
    await expectDecision('A reuse (replay)', reuseEnv, 'REJECT', 'PROOF_REUSED', { wantProof: false });

    // 10–11. Shape (b): valid + VK trap (string task_id exercises the taskId derivation)
    await expectDecision('B valid', shapeB('gk_test_b1', { proof_tx: tx(9) }), 'APPROVE', 'VALID_CONDITION', { wantProof: true });
    await expectDecision('B vk-substitution', shapeB('gk_test_b2', { proof_vk: VK_OTHER, proof_tx: tx(10) }), 'REJECT', 'VK_SUBSTITUTION', { wantProof: true });

    // 12. Bad signature is rejected outright
    console.log('\nCASE bad signature');
    {
      const r = await postSigned(shapeA('109', { proof_tx: tx(11) }), { secret: 'wrong-secret' });
      check('bad-signature: HTTP 401', r.status === 401, `got ${r.status}`);
      check('bad-signature: no decision leaked', !r.body || r.body.decision === undefined);
    }

    // 13. Unknown type: signed 400, and the server is still alive afterwards
    console.log('\nCASE unknown type');
    {
      const r = await postSigned({ type: 'agent-games.something-else.v9' });
      check('unknown-type: HTTP 400', r.status === 400, `got ${r.status}`);
      const p = await postSigned({ type: 'agent-games.preflight.v1' });
      check('unknown-type: server still alive (preflight ok)', p.status === 200 && p.body && p.body.ok === true);
    }

    // 14. Seen-set persistence across a restart: replaying tx(1) after a
    //     restart must still be PROOF_REUSED.
    console.log('\nRestarting server to test seen-set persistence…');
    server.kill('SIGTERM');
    await new Promise((r) => setTimeout(r, 400));
    server = startServer();
    await waitForHealth();
    await expectDecision('A reuse after restart', shapeA('110', { proof_tx: tx(1) }), 'REJECT', 'PROOF_REUSED', { wantProof: false });
  } finally {
    server.kill('SIGTERM');
  }

  console.log(`\n==== SUMMARY: ${passed} passed, ${failed} failed ====`);
  if (failures.length) console.log('Failed checks:\n - ' + failures.join('\n - '));
  fs.rmSync(SEEN_ABS, { force: true });
  process.exit(failed ? 1 : 0);
}

main().catch((e) => {
  console.error('HARNESS ERROR:', e);
  process.exit(2);
});
