export type FieldKind = 'text' | 'number' | 'textarea';

export interface TaskField {
  name: string;
  /** Translation key below `fields`; defaults to the field name. */
  label?: string;
  kind?: FieldKind;
  required?: boolean;
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
  'limit.set': [
    user,
    { name: 'cpu_percent', kind: 'number' },
    { name: 'memory_mb', kind: 'number' },
  ],
};

/** Translation key of a task type; i18next reads dots as nesting. */
export function taskKey(type: string): string {
  return `taskTypes.${type.replace('.', '_')}`;
}

export function buildPayload(values: Record<string, string>): Record<string, unknown> {
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
  return payload;
}
