/** WebAuthn for the dashboard. The server says nothing about what a device
 * accepts: the agent verifies every assertion against its own pins. */
import { api } from './api';

const NAMESPACE = 'hauswart-task-passkey@v1\0';

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

export async function approveWithPasskey(taskId: string, challenge: Challenge) {
  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge: await envelopeChallenge(fromBase64(challenge.envelope)),
      rpId: challenge.rp_id,
      allowCredentials: challenge.credentials.map((id) => ({ type: 'public-key', id: fromBase64(id) })),
      userVerification: 'required',
    },
  })) as PublicKeyCredential | null;
  if (!assertion) throw new Error('no assertion');
  const response = assertion.response as AuthenticatorAssertionResponse;
  await api('POST', `/api/tasks/${taskId}/passkey-approval`, {
    credential_id: toBase64(assertion.rawId),
    authenticator_data: toBase64(response.authenticatorData),
    client_data_json: toBase64(response.clientDataJSON),
    signature: toBase64(response.signature),
  });
}
