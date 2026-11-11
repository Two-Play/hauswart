import type { TaskField } from './tasks';

/** How long a power task or message stays valid, in minutes. */
const VALID_MINUTES = 60;

const user: TaskField = { name: 'user', required: true };
const group: TaskField = { name: 'group', required: true };
const power: TaskField[] = [
  { name: 'delay_minutes', kind: 'number', required: true },
  { name: 'message', label: 'power_message' },
];

export const ACTION_FIELDS: Record<string, TaskField[]> = {
  'power.reboot': power,
  'power.shutdown': power,
  'power.cancel': [],
  'notify.send': [
    { name: 'message', label: 'notify_message', required: true },
    { name: 'user', label: 'notify_user' },
  ],
  'group.add': [user, group],
  'group.remove': [user, group],
  'screen.extend': [user, { name: 'extend_minutes', kind: 'number', required: true }],
  'access.lock': [
    { name: 'access_users', label: 'access_users', hint: 'access_lock_hint' },
    { name: 'access_hours', label: 'access_hours', kind: 'number' },
  ],
  'access.deny': [
    { name: 'access_users', label: 'access_users', hint: 'access_deny_hint' },
    { name: 'access_hours', label: 'access_hours', kind: 'number' },
  ],
  'access.cover': [
    { name: 'access_users', label: 'access_users', hint: 'access_cover_hint' },
    { name: 'access_hours', label: 'access_hours', kind: 'number' },
    { name: 'access_message', label: 'access_message' },
    { name: 'access_image', label: 'access_image', kind: 'image' },
  ],
  'access.open': [],
};

/** The access tasks, one per kind of block. */
const ACCESS_TYPES = ['access.lock', 'access.deny', 'access.cover', 'access.open'];

/** Adds what these tasks need beyond the form. */
export function addActionPayload(type: string, payload: Record<string, unknown>): Record<string, unknown> {
  if (type === 'power.reboot' || type === 'power.shutdown' || type === 'notify.send') {
    payload.expires_at = new Date(Date.now() + VALID_MINUTES * 60_000).toISOString();
  }
  if (payload.extend_minutes !== undefined) {
    payload.until = new Date(Date.now() + Number(payload.extend_minutes) * 60_000).toISOString();
    delete payload.extend_minutes;
  }
  if (ACCESS_TYPES.includes(type)) {
    const users = String(payload.access_users ?? '').split(/[\s,]+/).filter(Boolean);
    if (users.length > 0) payload.users = users;
    if (payload.access_hours !== undefined) {
      payload.until = new Date(Date.now() + Number(payload.access_hours) * 3_600_000).toISOString();
    }
    if (type === 'access.cover') {
      if (payload.access_message) payload.message = payload.access_message;
      if (payload.access_image) payload.image = payload.access_image;
    }
    delete payload.access_users;
    delete payload.access_hours;
    delete payload.access_message;
    delete payload.access_image;
  }
  if (payload.delay_minutes !== undefined) {
    payload.delay_minutes = Number(payload.delay_minutes);
  }
  return payload;
}
