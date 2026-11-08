import { ACTION_FIELDS, addActionPayload } from './tasks_actions';

export type FieldKind = 'text' | 'number' | 'textarea' | 'select';

export interface TaskField {
  name: string;
  /** Translation key below `fields`; defaults to the field name. */
  label?: string;
  kind?: FieldKind;
  required?: boolean;
  /** The choices of a select, as values; their labels are below `fields`. */
  options?: string[];
  /** A hint under the field, below `fields`. */
  hint?: string;
}

const user: TaskField = { name: 'user', required: true };

export const TASK_FIELDS: Record<string, TaskField[]> = {
  'pkg.install': [{ name: 'packages', required: true }],
  'pkg.remove': [{ name: 'packages', required: true }],
  'pkg.upgrade': [],
  'flatpak.install': [{ name: 'packages', label: 'flatpaks', required: true }],
  'file.put': [
    { name: 'path', required: true },
    { name: 'mode' },
    { name: 'content', kind: 'textarea' },
  ],
  'ca.install': [
    { name: 'name', required: true },
    { name: 'pem', kind: 'textarea', required: true },
  ],
  'sudo.grant': [user, { name: 'minutes', kind: 'number', required: true }],
  'sudo.revoke': [user],
  'user.create': [user, { name: 'full_name' }],
  'user.lock': [user],
  'user.unlock': [user],
  'user.passwd': [user],
  'limit.set': [
    user,
    { name: 'cpu_percent', kind: 'number' },
    { name: 'memory_mb', kind: 'number' },
  ],
  ...ACTION_FIELDS,
};

/** Translation key of a task type; i18next reads dots as nesting. */
export function taskKey(type: string): string {
  return `taskTypes.${type.replace('.', '_')}`;
}

export function buildPayload(values: Record<string, string>, type = ''): Record<string, unknown> {
  const payload: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(values)) {
    if (value === '') continue;
    if (key === 'packages') {
      payload.packages = value.split(/\s+/).filter(Boolean);
    } else if (key === 'minutes') {
      payload.expires_at = new Date(Date.now() + Number(value) * 60_000).toISOString();
    } else if (key === 'cpu_percent' || key === 'memory_mb') {
      payload[key] = Number(value);
    } else {
      payload[key] = value;
    }
  }
  return addActionPayload(type, payload);
}
