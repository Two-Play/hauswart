import {
  Button,
  FileInput,
  Image,
  Code,
  CopyButton,
  Group,
  Modal,
  Select,
  Stack,
  TagsInput,
  Text,
  Textarea,
  TextInput,
} from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { api, type Device } from '../api';
import { buildPayload, TASK_FIELDS, taskKey } from '../tasks';
import { showError } from '../ui';
import { knownNames, NameInput } from './NameInput';
import { PackageSearch } from './PackageSearch';

/** The form of one action for one device, with suggestions from that device. */
export function ActionForm({ device, type, onDone }: { device: Device; type: string; onDone: (ran: boolean) => void }) {
  const { t } = useTranslation();
  const [values, setValues] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [startPassword, setStartPassword] = useState<string>();
  const names = knownNames([device]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      if (type === 'user.passwd') {
        const out = await api<{ password: string }>('POST', `/api/devices/${device.id}/start-password`, {
          user: values.user,
        });
        setStartPassword(out.password);
        return;
      }
      await api('POST', `/api/devices/${device.id}/tasks`, { type, payload: buildPayload(values, type) });
      notifications.show({ color: 'teal', message: t('actions.queued', { name: device.hostname }) });
      onDone(true);
    } catch (err) {
      showError(err);
    } finally {
      setBusy(false);
    }
  }

  if (startPassword) {
    return (
      <Stack>
        <Text size="sm">{t('actions.startPasswordHint', { user: values.user })}</Text>
        <Code block>{startPassword}</Code>
        <Group justify="flex-end">
          <CopyButton value={startPassword}>
            {({ copied, copy }) => (
              <Button variant="default" onClick={copy}>
                {t(copied ? 'common.copied' : 'common.copy')}
              </Button>
            )}
          </CopyButton>
          <Button onClick={() => onDone(true)}>{t('actions.close')}</Button>
        </Group>
      </Stack>
    );
  }

  return (
    <form onSubmit={submit}>
      <Stack>
        {TASK_FIELDS[type].length === 0 && <Text size="sm">{t('actions.noFields')}</Text>}
        {TASK_FIELDS[type].map((field) => {
          const value = values[field.name] ?? '';
          const set = (next: string) => setValues((v) => ({ ...v, [field.name]: next }));
          const label = t(`fields.${field.label ?? field.name}`);
          if (field.name === 'packages') {
            return (
              <PackageSearch
                key={`${type}-${field.name}`}
                kind={type === 'flatpak.install' ? 'flatpak' : 'package'}
                scope={{ device: device.id }}
                label={label}
                required={field.required}
                value={value.split(/\s+/).filter(Boolean)}
                onChange={(next) => set(next.join(' '))}
              />
            );
          }
          if (field.name === 'user' || field.name === 'group') {
            return (
              <NameInput
                key={field.name}
                of={field.name === 'user' ? 'users' : 'groups'}
                names={names}
                label={label}
                required={field.required}
                value={value}
                onChange={set}
              />
            );
          }
          if (field.name === 'access_users') {
            return (
              <TagsInput
                key={field.name}
                label={label}
                description={field.hint && t(`fields.${field.hint}`)}
                data={names.users}
                value={value.split(/\s+/).filter(Boolean)}
                onChange={(next) => set(next.join(' '))}
                clearable
              />
            );
          }
          if (field.kind === 'image') {
            return (
              <Stack key={field.name} gap={4}>
                <FileInput
                  label={label}
                  accept="image/png,image/jpeg"
                  clearable
                  onChange={(file) => {
                    if (!file) return set('');
                    const reader = new FileReader();
                    reader.onload = () => set(String(reader.result).replace(/^data:[^,]*,/, ''));
                    reader.readAsDataURL(file);
                  }}
                />
                {value && <Image src={`data:image/*;base64,${value}`} mah={160} fit="contain" alt="" />}
              </Stack>
            );
          }
          if (field.kind === 'select') {
            return (
              <Select
                key={field.name}
                label={label}
                required={field.required}
                allowDeselect={false}
                description={field.hint && t(`fields.${field.hint}`)}
                value={values[field.name] ?? null}
                onChange={(next) => set(next ?? '')}
                data={(field.options ?? []).map((option) => ({ value: option, label: t(`fields.${field.name}_${option}`) }))}
              />
            );
          }
          const shared = {
            label,
            required: field.required,
            value,
            onChange: (e: { currentTarget: { value: string } }) => set(e.currentTarget.value),
          };
          return field.kind === 'textarea' ? (
            <Textarea key={field.name} autosize minRows={5} maxRows={14} ff="monospace" {...shared} />
          ) : (
            <TextInput key={field.name} type={field.kind === 'number' ? 'number' : 'text'} {...shared} />
          );
        })}
        <Group justify="flex-end">
          <Button variant="default" onClick={() => onDone(false)}>
            {t('common.cancel')}
          </Button>
          <Button type="submit" loading={busy}>
            {t('actions.run')}
          </Button>
        </Group>
      </Stack>
    </form>
  );
}

/** ActionModal shows the form of one action in a dialog. */
export function ActionModal({ device, type, onClose }: { device: Device; type: string; onClose: (ran: boolean) => void }) {
  const { t } = useTranslation();
  return (
    <Modal opened onClose={() => onClose(false)} title={`${t(taskKey(type))} · ${device.hostname}`}>
      <ActionForm device={device} type={type} onDone={onClose} />
    </Modal>
  );
}
