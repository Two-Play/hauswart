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
};

/** Adds what these tasks need beyond the form. */
export function addActionPayload(type: string, payload: Record<string, unknown>): Record<string, unknown> {
  if (type === 'power.reboot' || type === 'power.shutdown' || type === 'notify.send') {
    payload.expires_at = new Date(Date.now() + VALID_MINUTES * 60_000).toISOString();
  }
  if (payload.extend_minutes !== undefined) {
    payload.until = new Date(Date.now() + Number(payload.extend_minutes) * 60_000).toISOString();
    delete payload.extend_minutes;
  }
  if (payload.delay_minutes !== undefined) {
    payload.delay_minutes = Number(payload.delay_minutes);
  }
  return payload;
}
