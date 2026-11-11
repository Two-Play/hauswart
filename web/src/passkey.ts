/** WebAuthn for the dashboard. The server says nothing about what a device
 * accepts: the agent verifies every assertion against its own pins. */
import { api } from './api';

const NAMESPACE = 'hauswart-task-passkey@v1\0';
const BATCH_NAMESPACE = 'hauswart-task-passkey-batch@v1\0';

function fromBase64(value: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
}

function toBase64(value: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(value)));
}

export function passkeysAvailable(): boolean {
  return window.isSecureContext && 'PublicKeyCredential' in window;
}

interface RegistrationOptions {
  challenge: string;
  rp_id: string;
  user_id: string;
  username: string;
  exclude: string[];
}

export async function registerPasskey(name: string) {
  const options = await api<RegistrationOptions>('POST', '/api/passkeys/options');
  const credential = (await navigator.credentials.create({
    publicKey: {
      challenge: fromBase64(options.challenge),
      rp: { id: options.rp_id, name: 'Hauswart' },
      user: { id: fromBase64(options.user_id), name: options.username, displayName: options.username },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -8 },
      ],
      excludeCredentials: options.exclude.map((id) => ({ type: 'public-key', id: fromBase64(id) })),
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
      attestation: 'none',
    },
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error('no credential');
  const response = credential.response as AuthenticatorAttestationResponse;
  const publicKey = response.getPublicKey();
  if (!publicKey) throw new Error('no public key');
  await api('POST', '/api/passkeys', {
    name,
    credential_id: toBase64(credential.rawId),
    public_key: toBase64(publicKey),
    client_data_json: toBase64(response.clientDataJSON),
  });
}

export interface Envelope {
  type: string;
  payload: unknown;
  device_id: string;
  counter: number;
  not_after: string;
}

export interface Challenge {
  envelope: string;
  credentials: string[];
  rp_id: string;
  hostname: string;
}

/** What a passkey is about to confirm, read from the bytes it will sign and not
 * from a list next to them. */
export function decodeEnvelope(challenge: Challenge): Envelope {
  return JSON.parse(new TextDecoder().decode(fromBase64(challenge.envelope))) as Envelope;
}

/** The dashboard computes the hash itself, so the challenge cannot be anything
 * but the envelope it has just shown. The same hash is in internal/sign. */
async function envelopeChallenge(envelope: Uint8Array<ArrayBuffer>): Promise<ArrayBuffer> {
  const prefix = new TextEncoder().encode(NAMESPACE);
  const message = new Uint8Array(prefix.length + envelope.length);
  message.set(prefix);
  message.set(envelope, prefix.length);
  return crypto.subtle.digest('SHA-256', message);
}

/** Asks the authenticator to sign a challenge, and returns the assertion as
 * the server takes it. */
async function assert(challenge: ArrayBuffer, rpId: string, credentials: string[]) {
  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge,
      rpId,
      allowCredentials: credentials.map((id) => ({ type: 'public-key', id: fromBase64(id) })),
      userVerification: 'required',
    },
  })) as PublicKeyCredential | null;
  if (!assertion) throw new Error('no assertion');
  const response = assertion.response as AuthenticatorAssertionResponse;
  return {
    credential_id: toBase64(assertion.rawId),
    authenticator_data: toBase64(response.authenticatorData),
    client_data_json: toBase64(response.clientDataJSON),
    signature: toBase64(response.signature),
  };
}

export interface BatchItem {
  task: string;
  envelope: string;
  hostname: string;
}

export interface BatchChallenge {
  items: BatchItem[];
  credentials: string[];
  rp_id: string;
}

export interface BatchResult {
  task: string;
  ok: boolean;
  code?: string;
}

/** What one touch is about to confirm, each read from the bytes it signs. */
export function decodeBatch(challenge: BatchChallenge): Envelope[] {
  return challenge.items.map((item) => JSON.parse(new TextDecoder().decode(fromBase64(item.envelope))) as Envelope);
}

/** The challenge of a batch covers the hashes of the envelopes shown, in their
 * order, so it cannot stand for any other list. The same hash is in internal/sign. */
async function batchChallenge(envelopes: Uint8Array<ArrayBuffer>[]): Promise<ArrayBuffer> {
  const prefix = new TextEncoder().encode(BATCH_NAMESPACE);
  const hashes = await Promise.all(envelopes.map((e) => crypto.subtle.digest('SHA-256', e)));
  const message = new Uint8Array(prefix.length + 32 * hashes.length);
  message.set(prefix);
  hashes.forEach((hash, i) => message.set(new Uint8Array(hash), prefix.length + 32 * i));
  return crypto.subtle.digest('SHA-256', message);
}

/** Approves several tasks with one touch. Each device checks for itself that its
 * task is in the list the touch covers. */
export async function approveBatch(challenge: BatchChallenge): Promise<BatchResult[]> {
  const envelopes = challenge.items.map((item) => fromBase64(item.envelope));
  const assertion = await assert(await batchChallenge(envelopes), challenge.rp_id, challenge.credentials);
  return api<BatchResult[]>('POST', '/api/passkey-batch/approval', {
    tasks: challenge.items.map((item) => item.task),
    assertion,
  });
}

export async function approveWithPasskey(taskId: string, challenge: Challenge) {
  const assertion = await assert(
    await envelopeChallenge(fromBase64(challenge.envelope)),
    challenge.rp_id,
    challenge.credentials,
  );
  await api('POST', `/api/tasks/${taskId}/passkey-approval`, assertion);
}
