#!/usr/bin/env node
// Runs the passkey flow in a real browser with a virtual authenticator: a real
// server, the real agent with a fake package manager, hauswart-admin with a real
// ssh-agent and Chromium driven over the DevTools protocol. The second half plays
// a hacked server, which writes tasks straight into the database, with assertions
// from the authenticator.
//
// Needs `make build`, chromium-browser, certutil, ssh-agent and ssh-keygen. It runs
// as a normal user. Usage: node test/passkeys.mjs [screenshot directory]
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DIST = join(ROOT, 'dist');
const PORT = 18931;
const OTHER_PORT = 18932; // the same host through another port is another origin
const DEBUG_PORT = 18933;
const HOST = 'hauswart.localhost';
const ORIGIN = `https://${HOST}:${PORT}`;
const PASSWORD = 'correct horse battery';
const shots = process.argv[2];

const tmp = mkdtempSync(join(tmpdir(), 'hauswart-passkeys-'));
const children = [];
let failures = 0;
let sshPid;

function cleanUp() {
  for (const child of children) child.kill();
  if (sshPid) spawnSync('kill', [sshPid]);
  rmSync(tmp, { recursive: true, force: true, maxRetries: 3 });
}
process.on('exit', cleanUp);

function check(name, ok, detail = '') {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${detail ? `: ${detail}` : ''}`);
  if (!ok) failures++;
}

function start(command, args, env = {}) {
  const log = join(tmp, `${command.split('/').pop()}-${children.length}.log`);
  const child = spawn(command, args, { env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  const write = (chunk) => writeFileSync(log, chunk, { flag: 'a' });
  child.stdout.on('data', write);
  child.stderr.on('data', write);
  children.push(child);
  return { child, log };
}

async function until(what, fn, seconds = 40) {
  const end = Date.now() + seconds * 1000;
  for (;;) {
    const value = await fn().catch(() => undefined);
    if (value) return value;
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await sleep(250);
  }
}

// --- server, ssh-agent, tool ---

const data = join(tmp, 'data');
mkdirSync(data);
const server = start(join(DIST, 'hauswart-server'), ['-data', data, '-addr', `127.0.0.1:${PORT}`, '-url', ORIGIN]);
await until('the server', async () => {
  try {
    return readFileSync(join(data, 'initial-admin-password'), 'utf8');
  } catch {
    return undefined;
  }
});
await sleep(500);
const adminPassword = readFileSync(join(data, 'initial-admin-password'), 'utf8').trim();
const caPEM = readFileSync(join(data, 'pki', 'ca.pem'));

const agentOut = execFileSync('ssh-agent', ['-s', '-a', join(tmp, 'ssh.sock')], { encoding: 'utf8' });
sshPid = /SSH_AGENT_PID=(\d+)/.exec(agentOut)[1];
const adminEnv = { ...process.env, SSH_AUTH_SOCK: join(tmp, 'ssh.sock'), HAUSWART_ADMIN_DIR: join(tmp, 'admin') };
for (const name of ['one', 'two']) {
  execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', join(tmp, name)]);
}
execFileSync('ssh-add', ['-q', join(tmp, 'one')], { env: adminEnv });

function admin(args, input = '') {
  const run = spawnSync(join(DIST, 'hauswart-admin'), args, { env: adminEnv, input, encoding: 'utf8' });
  if (run.status !== 0) throw new Error(`hauswart-admin ${args.join(' ')}: ${run.stdout}${run.stderr}`);
  return run.stdout;
}

const certFingerprint = /ca_fingerprint=(\S+)/.exec(readFileSync(server.log, 'utf8'))[1];
admin(['login', '--server', ORIGIN, '--ca-fingerprint', certFingerprint, '--user', 'admin'], adminPassword + '\n');
admin(['keys', 'add', join(tmp, 'one.pub'), join(tmp, 'two.pub')]);

// --- agent with a fake package manager ---

const fakeBin = join(tmp, 'bin');
const installed = join(tmp, 'installed');
mkdirSync(fakeBin);
writeFileSync(join(fakeBin, 'dnf5'), `#!/bin/sh\necho "$@" >> ${installed}\n`);
chmodSync(join(fakeBin, 'dnf5'), 0o755);
const agentEnv = { PATH: `${fakeBin}:${process.env.PATH}` };
const agentDir = join(tmp, 'agent');

const enroll = admin(['enroll-command']).trim();
const enrollArgs = enroll.match(/'[^']*'|\S+/g).map((part) => part.replace(/^'|'$/g, ''));
execFileSync(join(DIST, 'hauswart-agent'), [...enrollArgs.slice(2), '--dir', agentDir], {
  env: { ...process.env, ...agentEnv },
  stdio: 'ignore',
});
const deviceId = JSON.parse(readFileSync(join(agentDir, 'agent.json'), 'utf8')).device_id;
admin(['name', deviceId, 'laptop']);
let agent = start(join(DIST, 'hauswart-agent'), ['run', '--dir', agentDir], agentEnv);

async function restartAgent() {
  agent.child.kill();
  await sleep(300);
  agent = start(join(DIST, 'hauswart-agent'), ['run', '--dir', agentDir], agentEnv);
}

// --- browser ---

const home = join(tmp, 'home');
mkdirSync(join(home, '.pki', 'nssdb'), { recursive: true });
const nss = `sql:${join(home, '.pki', 'nssdb')}`;
execFileSync('certutil', ['-d', nss, '-N', '--empty-password']);
writeFileSync(join(tmp, 'ca.pem'), caPEM);
execFileSync('certutil', ['-d', nss, '-A', '-n', 'hauswart', '-t', 'C,,', '-i', join(tmp, 'ca.pem')]);

const forward = net
  .createServer((socket) => {
    const target = net.connect(PORT, '127.0.0.1');
    socket.pipe(target).pipe(socket);
    socket.on('error', () => target.destroy());
    target.on('error', () => socket.destroy());
  })
  .listen(OTHER_PORT, '127.0.0.1');

start(
  process.env.CHROMIUM ?? 'chromium-browser',
  [
    '--headless=new',
    `--remote-debugging-port=${DEBUG_PORT}`,
    `--user-data-dir=${join(tmp, 'chrome')}`,
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-gpu',
    '--lang=en',
    '--window-size=1200,900',
    'about:blank',
  ],
  { HOME: home },
);

const target = await until('Chromium', async () => {
  const res = await fetch(`http://127.0.0.1:${DEBUG_PORT}/json/new?about:blank`, { method: 'PUT' });
  return res.ok ? res.json() : undefined;
});
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((ok, no) => {
  ws.onopen = ok;
  ws.onerror = no;
});
let nextId = 1;
const pending = new Map();
ws.onmessage = (event) => {
  const message = JSON.parse(event.data);
  if (!message.id) return;
  const { ok, no } = pending.get(message.id);
  pending.delete(message.id);
  if (message.error) no(new Error(JSON.stringify(message.error)));
  else ok(message.result);
};
function cdp(method, params = {}) {
  const id = nextId++;
  ws.send(JSON.stringify({ id, method, params }));
  return new Promise((ok, no) => pending.set(id, { ok, no }));
}
async function ev(expression) {
  const out = await cdp('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true, userGesture: true });
  if (out.exceptionDetails) {
    throw new Error(out.exceptionDetails.exception?.description ?? out.exceptionDetails.text);
  }
  return out.result.value;
}
async function navigate(url) {
  await cdp('Page.navigate', { url });
  await until(`loading ${url}`, () => ev(`document.readyState === 'complete' && location.href.startsWith(${JSON.stringify(url)})`));
}
async function shot(name) {
  if (!shots) return;
  mkdirSync(shots, { recursive: true });
  const { data: png } = await cdp('Page.captureScreenshot', { format: 'png' });
  writeFileSync(join(shots, `${name}.png`), Buffer.from(png, 'base64'));
}

await cdp('Page.enable');
await cdp('Runtime.enable');
await cdp('Emulation.setFocusEmulationEnabled', { enabled: true });
await cdp('WebAuthn.enable');
const { authenticatorId } = await cdp('WebAuthn.addVirtualAuthenticator', {
  options: {
    protocol: 'ctap2',
    transport: 'internal',
    hasResidentKey: true,
    hasUserVerification: true,
    isUserVerified: true,
    automaticPresenceSimulation: true,
  },
});

async function call(method, path, body) {
  return ev(`(async () => {
    const res = await fetch(${JSON.stringify(path)}, {
      method: ${JSON.stringify(method)},
      headers: { 'Content-Type': 'application/json', 'X-Hauswart': '1' },
      body: ${body === undefined ? 'undefined' : JSON.stringify(JSON.stringify(body))},
    });
    const text = await res.text();
    return { status: res.status, body: text ? JSON.parse(text) : null };
  })()`);
}
async function loginAs(name, password) {
  await call('POST', '/api/logout').catch(() => {});
  const out = await call('POST', '/api/login', { username: name, password });
  if (out.status !== 200) throw new Error(`login ${name}: ${out.status}`);
  await ev(`localStorage.setItem('hauswart-language', 'en')`);
  await navigate(`${ORIGIN}/`);
  await until('the dashboard', () => ev(`!!document.querySelector('nav')`));
}
const clickButton = (label) =>
  ev(`(() => {
    const button = [...document.querySelectorAll('button')].find((b) => b.textContent.trim() === ${JSON.stringify(label)} && !b.disabled);
    if (!button) return false;
    button.click();
    return true;
  })()`);
const pageText = () => ev('document.body.innerText');

// --- the normal flow, through the dashboard ---

await navigate(`${ORIGIN}/`);
check('browser trusts the Hauswart CA on a DNS name', (await ev('window.isSecureContext')) === true);
const created = (await (async () => {
  await call('POST', '/api/login', { username: 'admin', password: adminPassword });
  return call('POST', '/api/users', { username: 'mama', password: PASSWORD, role: 'approver' });
})());
check('admin creates an approver', created.status === 201, String(created.status));

await loginAs('mama', PASSWORD);
const nav = await ev(`document.querySelector('nav').innerText`);
check('approver sees approvals, not admin views', nav.includes('Approvals') && !nav.includes('Audit') && !nav.includes('Users'), nav.replaceAll('\n', ' '));
await until('the approvals link', () => clickButton('Approvals'));
await until('the weakness notice', async () => (await pageText()).includes('it can show you one task here and have your passkey confirm another'));
check('dashboard states the weakness', true);
await shot('1-approvals');

await ev(`document.querySelector('input[placeholder="For example: phone"]').focus()`);
await cdp('Input.insertText', { text: 'phone' });
await until('the add button', () => clickButton('Add passkey'));
const registered = await until('the passkey on the server', async () => {
  const list = await call('GET', '/api/passkeys');
  return list.body?.length ? list.body[0] : undefined;
});
check('passkey registered through the dashboard', registered.name === 'phone' && registered.rp_id === HOST);
const credential = await cdp('WebAuthn.getCredentials', { authenticatorId });
check('authenticator holds a credential for the RP', credential.credentials.length === 1 && credential.credentials[0].rpId === HOST);

// Before the pin, nothing works.
const sendTask = async (type, payload) => {
  await loginAs('admin', adminPassword);
  const out = await call('POST', `/api/devices/${deviceId}/tasks`, { type, payload });
  if (out.status !== 201) throw new Error(`task: ${out.status} ${JSON.stringify(out.body)}`);
  return out.body.id;
};
await until('the device report', async () => {
  await loginAs('admin', adminPassword);
  const devices = await call('GET', '/api/devices');
  return devices.body?.[0]?.report?.protected;
}, 90);
const earlyTask = await sendTask('pkg.install', { packages: ['too-early'] });
await loginAs('mama', PASSWORD);
const early = await call('POST', `/api/tasks/${earlyTask}/passkey-challenge`);
check('unpinned passkey gets no challenge', early.status === 409 && early.body.code === 'passkey_not_pinned', JSON.stringify(early.body));
await call('POST', `/api/tasks/${earlyTask}/reject`);

const pinOut = admin(['passkeys', 'pin', '--device', deviceId, '--passkey', String(registered.id)], 'y\n');
check('hauswart-admin shows what it pins', pinOut.includes('phone') && pinOut.includes('SHA256:'));
await until('the signed keys.set', async () => {
  const config = JSON.parse(readFileSync(join(agentDir, 'agent.json'), 'utf8'));
  return config.passkeys?.length === 1;
});
check('passkey pinned through a signed keys.set', true);
await restartAgent();
await until('the report with the pin', async () => {
  await loginAs('admin', adminPassword);
  const devices = await call('GET', '/api/devices');
  return devices.body?.[0]?.report?.passkeys?.length === 1;
}, 30);

const taskId = await sendTask('pkg.install', { packages: ['vim'] });
await loginAs('mama', PASSWORD);
await until('the approvals link', () => clickButton('Approvals'));
await until('the approve button', () => clickButton('Approve with passkey'));
await until('the confirm dialog', async () => (await pageText()).includes('Confirm with passkey'));
const dialog = await ev(`document.querySelector('[role=dialog]').innerText`);
check('dialog shows the envelope', dialog.includes('vim') && dialog.includes(deviceId), dialog.slice(0, 60).replaceAll('\n', ' '));
check('dialog states the weakness', dialog.includes('A passkey is weaker than hauswart-admin'));
await shot('2-confirm');
await until('the confirm button', () => clickButton('Confirm with passkey'));
await until('the fake dnf', async () => readFileSync(installed, 'utf8').includes('vim'), 40);
check('approved task ran on the device', true);
await shot('3-approved');

// --- a hacked server: straight into the database ---

function database(work) {
  const db = new DatabaseSync(join(data, 'hauswart.db'));
  db.exec('PRAGMA busy_timeout = 5000');
  try {
    return work(db);
  } finally {
    db.close();
  }
}
// The value the device last reported, which a hacked server can read as well.
const deviceFreshness = () =>
  JSON.parse(database((db) => db.prepare('SELECT report FROM devices WHERE id = ?').get(deviceId)).report).passkey_freshness;
function envelope(type, payload, counter, freshness = deviceFreshness()) {
  return Buffer.from(
    JSON.stringify({
      type,
      payload,
      device_id: deviceId,
      counter,
      not_after: new Date(Date.now() + 3600_000).toISOString(),
      freshness,
    }),
  );
}
// What hostile dashboard code can do: ask the authenticator for any challenge.
async function assertion(raw, credentialId = registered.credential_id) {
  return ev(`(async () => {
    const decode = (v) => Uint8Array.from(atob(v), (c) => c.charCodeAt(0));
    const encode = (v) => btoa(String.fromCharCode(...new Uint8Array(v)));
    const prefix = new TextEncoder().encode('hauswart-task-passkey@v1\\0');
    const envelope = decode(${JSON.stringify(raw.toString('base64'))});
    const message = new Uint8Array(prefix.length + envelope.length);
    message.set(prefix);
    message.set(envelope, prefix.length);
    const got = await navigator.credentials.get({ publicKey: {
      challenge: await crypto.subtle.digest('SHA-256', message),
      rpId: ${JSON.stringify(HOST)},
      allowCredentials: [{ type: 'public-key', id: decode(${JSON.stringify(credentialId)}) }],
      userVerification: 'required',
    }});
    return {
      credential_id: encode(got.rawId),
      authenticator_data: encode(got.response.authenticatorData),
      client_data_json: encode(got.response.clientDataJSON),
      signature: encode(got.response.signature),
    };
  })()`);
}
function inject(type, raw, passkey) {
  const id = randomBytes(16).toString('hex');
  const signed = JSON.stringify({ envelope: raw.toString('base64'), signature: null, passkey });
  database((db) =>
    db
      .prepare(`INSERT INTO tasks (id, device_id, type, payload, status, signed, created_by, created_at) VALUES (?,?,?,?,'pending',?,'attacker',?)`)
      .run(id, deviceId, type, '{}', signed, Math.floor(Date.now() / 1000)),
  );
  return id;
}
const taskRow = (id) => database((db) => db.prepare('SELECT status, output FROM tasks WHERE id = ?').get(id));
async function outcome(id) {
  return until(`task ${id}`, async () => {
    const row = taskRow(id);
    return row.status === 'done' || row.status === 'failed' ? row : undefined;
  }, 90);
}

const sudo = envelope('sudo.grant', { user: 'attacker', expires_at: new Date(Date.now() + 3600_000).toISOString() }, 100);
const keys = envelope('keys.set', { keys: [readFileSync(join(tmp, 'two.pub'), 'utf8').trim()] }, 100);
const good = envelope('pkg.install', { packages: ['nmap'] }, 100);
const swapped = Buffer.from(good.toString().replace('nmap', 'evil'));
// An approval collected for later names a value the device no longer knows.
const stockpiled = envelope('pkg.install', { packages: ['nmap'] }, 100, 'collected-months-ago');
const otherCredential = await ev(`(async () => {
  const created = await navigator.credentials.create({ publicKey: {
    challenge: new Uint8Array(32),
    rp: { id: ${JSON.stringify(HOST)}, name: 'Hauswart' },
    user: { id: new Uint8Array([9]), name: 'attacker', displayName: 'attacker' },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
  }});
  return btoa(String.fromCharCode(...new Uint8Array(created.rawId)));
})()`);

const refused = [
  ['unlisted type sudo.grant', inject('sudo.grant', sudo, await assertion(sudo)), 'may not approve sudo.grant'],
  ['unlisted type keys.set', inject('keys.set', keys, await assertion(keys)), 'may not approve keys.set'],
  ['changed envelope', inject('pkg.install', swapped, await assertion(good)), 'different envelope'],
  ['stockpiled approval', inject('pkg.install', stockpiled, await assertion(stockpiled)), 'too old'],
  ['passkey not pinned', inject('pkg.install', good, await assertion(good, otherCredential)), 'not pinned'],
];
await navigate(`https://${HOST}:${OTHER_PORT}/`);
refused.push(['wrong origin', inject('pkg.install', good, await assertion(good)), 'comes from origin']);
await navigate(`${ORIGIN}/`);

for (const [name, id, reason] of refused) {
  const row = await outcome(id);
  check(`refused on the device: ${name}`, row.status === 'failed' && row.output.includes(reason), row.output);
}

// The same harness has to get a valid assertion through, or the refusals above
// prove nothing.
const valid = await assertion(good);
const first = await outcome(inject('pkg.install', good, valid));
check('control: the valid assertion runs', first.status === 'done', first.output);
check('control: the device ran it', readFileSync(installed, 'utf8').includes('nmap'));
const replay = await outcome(inject('pkg.install', good, valid));
check('refused on the device: replay', replay.status === 'failed' && replay.output.includes('is not above'), replay.output);
// Opening access is on the list now: a phone can lift a block without the CLI.
const open = envelope('access.set', { mode: 'open' }, 101);
const opened = await outcome(inject('access.set', open, await assertion(open)));
check('a passkey opens access', opened.status === 'done' && opened.output.includes('open'), opened.output);
const lines = readFileSync(installed, 'utf8').split('\n').filter((line) => line.includes('nmap')).length;
check('the replay did not run', lines === 1, `${lines} runs`);
const tampered = readFileSync(installed, 'utf8');
check('nothing refused reached the package manager', !tampered.includes('evil'));

const journal = readFileSync(agent.log, 'utf8');
check('device logs what a passkey approved', journal.includes('approved by passkey') && journal.includes('nmap'));

// --- roles in the dashboard ---

await loginAs('admin', adminPassword);
await call('POST', '/api/users', { username: 'kind', password: PASSWORD, role: 'member' });
await navigate(`${ORIGIN}/`);
await until('the users link', () => clickButton('Users'));
await until('the member row', async () => (await ev(`!!document.querySelector('[aria-label="Devices of kind"]')`)));
await shot('4-users');
const users = await call('GET', '/api/users');
const kind = users.body.find((u) => u.username === 'kind');
await loginAs('kind', PASSWORD);
const before = await call('GET', '/api/devices');
check('member sees no device before the assignment', before.body.length === 0);
await loginAs('admin', adminPassword);
await call('PUT', `/api/users/${kind.id}/devices`, { devices: [deviceId] });
await loginAs('kind', PASSWORD);
const after = await call('GET', '/api/devices');
check('member sees the assigned device', after.body.length === 1 && after.body[0].report === null);
const memberNav = await ev(`document.querySelector('nav').innerText`);
check('member has no approvals', !memberNav.includes('Approvals'), memberNav.replaceAll('\n', ' '));

// --- the signing path still works next to all this ---

const signedTask = await sendTask('pkg.install', { packages: ['htop'] });
const approveOut = admin(['approve'], 'y\n');
check('hauswart-admin still signs', approveOut.includes('Signed.'), approveOut.trim().split('\n').at(-1));
const signedRow = await outcome(signedTask);
check('signed task ran after passkey tasks', signedRow.status === 'done', signedRow.output);

const unpinOut = admin(['passkeys', 'unpin', '--device', deviceId], 'y\n');
check('hauswart-admin unpins', unpinOut.includes('none'));
await until('the unpin on the device', async () => {
  const config = JSON.parse(readFileSync(join(agentDir, 'agent.json'), 'utf8'));
  return !config.passkeys?.length;
});
const again = envelope('pkg.install', { packages: ['after-unpin'] }, 200);
const afterUnpin = await outcome(inject('pkg.install', again, await assertion(again)));
check('refused on the device: unpinned passkey', afterUnpin.status === 'failed' && afterUnpin.output.includes('not pinned'), afterUnpin.output);

console.log(failures ? `${failures} checks failed` : 'all checks passed');
process.exit(failures ? 1 : 0);
