import {
  Badge,
  Button,
  Card,
  Code,
  CopyButton,
  Group,
  Modal,
  Progress,
  Select,
  SimpleGrid,
  Stack,
  Text,
  Textarea,
  TextInput,
  Title,
} from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { api, useResource, type Device, type User } from '../api';
import { buildPayload, TASK_FIELDS, taskKey } from '../tasks';
import { formatBytes, Loaded, showError } from '../ui';

const ONLINE_SECONDS = 90;

function Usage({ label, used = 0, total = 0 }: { label: string; used?: number; total?: number }) {
  const { t } = useTranslation();
  const percent = total ? (used / total) * 100 : 0;
  return (
    <div>
      <Group justify="space-between" gap="xs">
        <Text size="xs" c="dimmed">
          {label}
        </Text>
        <Text size="xs" c="dimmed">
          {t('devices.usage', { used: formatBytes(used), total: formatBytes(total) })}
        </Text>
      </Group>
      <Progress value={percent} size="sm" color={percent > 90 ? 'red' : undefined} aria-label={label} />
    </div>
  );
}

function DeviceState({ device }: { device: Device }) {
  const { t } = useTranslation();
  if (device.revoked) return <Badge color="red" variant="light">{t('devices.revoked')}</Badge>;
  const online = Date.now() / 1000 - device.last_seen < ONLINE_SECONDS;
  return (
    <Badge color={online ? 'teal' : 'gray'} variant="light">
      {t(online ? 'devices.online' : 'devices.offline')}
    </Badge>
  );
}

function TaskModal({ device, onClose }: { device: Device; onClose: (ran: boolean) => void }) {
  const { t } = useTranslation();
  const [type, setType] = useState('pkg.install');
  const [values, setValues] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [startPassword, setStartPassword] = useState<string>();

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
      await api('POST', `/api/devices/${device.id}/tasks`, { type, payload: buildPayload(values) });
      notifications.show({ color: 'teal', message: t('actions.queued', { name: device.hostname }) });
      onClose(true);
    } catch (err) {
      showError(err);
    } finally {
      setBusy(false);
    }
  }

  if (startPassword) {
    return (
      <Modal
        opened
        onClose={() => onClose(true)}
        title={t('actions.startPasswordTitle', { user: values.user })}
        closeOnClickOutside={false}
      >
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
            <Button onClick={() => onClose(true)}>{t('actions.close')}</Button>
          </Group>
        </Stack>
      </Modal>
    );
  }

  return (
    <Modal opened onClose={() => onClose(false)} title={t('actions.title', { name: device.hostname })}>
      <form onSubmit={submit}>
        <Stack>
          <Select
            label={t('actions.type')}
            allowDeselect={false}
            value={type}
            onChange={(next) => {
              setType(next ?? type);
              setValues({});
            }}
            data={Object.keys(TASK_FIELDS).map((key) => ({ value: key, label: t(taskKey(key)) }))}
          />
          {TASK_FIELDS[type].map((field) => {
            const shared = {
              label: t(`fields.${field.label ?? field.name}`),
              required: field.required,
              value: values[field.name] ?? '',
              onChange: (e: { currentTarget: { value: string } }) => {
                const { value } = e.currentTarget;
                setValues((v) => ({ ...v, [field.name]: value }));
              },
            };
            return field.kind === 'textarea' ? (
              <Textarea key={field.name} autosize minRows={5} maxRows={14} ff="monospace" {...shared} />
            ) : (
              <TextInput key={field.name} type={field.kind === 'number' ? 'number' : 'text'} {...shared} />
            );
          })}
          <Group justify="flex-end">
            <Button variant="default" onClick={() => onClose(false)}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" loading={busy}>
              {t('actions.run')}
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

function EnrollModal({ command, onClose }: { command: string; onClose: () => void }) {
  const { t } = useTranslation();
  return (
    <Modal opened onClose={onClose} title={t('devices.add')} size="lg">
      <Stack>
        <Text size="sm">{t('devices.addHint')}</Text>
        <Code block>{command}</Code>
        <CopyButton value={command}>
          {({ copied, copy }) => (
            <Button variant="default" onClick={copy}>
              {t(copied ? 'common.copied' : 'common.copy')}
            </Button>
          )}
        </CopyButton>
      </Stack>
    </Modal>
  );
}

export function DevicesView({ user }: { user: User }) {
  const { t } = useTranslation();
  const isAdmin = user.role === 'admin';
  const { data, error, reload } = useResource<Device[]>('/api/devices', 10_000);
  const [taskDevice, setTaskDevice] = useState<Device>();
  const [revokeDevice, setRevokeDevice] = useState<Device>();
  const [enrollCommand, setEnrollCommand] = useState<string>();

  async function addDevice() {
    try {
      const out = await api<{ command: string }>('POST', '/api/enroll-tokens');
      setEnrollCommand(out.command);
    } catch (err) {
      showError(err);
    }
  }

  async function revoke(device: Device) {
    try {
      await api('POST', `/api/devices/${device.id}/revoke`);
      setRevokeDevice(undefined);
      reload();
    } catch (err) {
      showError(err);
    }
  }

  return (
    <Stack>
      <Group justify="space-between">
        <Title order={2}>{t('nav.devices')}</Title>
        {isAdmin && (
          <Button variant="default" onClick={addDevice}>
            {t('devices.add')}
          </Button>
        )}
      </Group>

      <Loaded data={data} error={error}>
        {(devices) =>
          devices.length === 0 ? (
            <Text c="dimmed">{t('devices.empty')}</Text>
          ) : (
            <SimpleGrid cols={{ base: 1, sm: 2, lg: 3 }}>
              {devices.map((d) => (
                <Card key={d.id} withBorder>
                  <Stack gap="xs">
                    <Group justify="space-between" wrap="nowrap">
                      <Text fw={600} truncate>
                        {d.hostname}
                      </Text>
                      <DeviceState device={d} />
                    </Group>
                    {d.report && (
                      <>
                        <Text size="sm" c="dimmed">
                          {d.report.distro ?? t('devices.unknownDistro')}
                          {d.report.kernel && ` · ${t('devices.kernel', { version: d.report.kernel })}`}
                        </Text>
                        <Usage label={t('devices.memory')} used={d.report.mem_used} total={d.report.mem_total} />
                        <Usage label={t('devices.disk')} used={d.report.disk_used} total={d.report.disk_total} />
                        <Text size="xs" c="dimmed">
                          {t('devices.load', { load: (d.report.load1 ?? 0).toFixed(2), cpus: d.report.cpus ?? '?' })}
                          {' · '}
                          {d.report.backends?.join(', ') || t('devices.noBackend')}
                        </Text>
                      </>
                    )}
                    {isAdmin && !d.revoked && (
                      <Group gap="xs" mt="xs">
                        <Button size="xs" onClick={() => setTaskDevice(d)}>
                          {t('devices.action')}
                        </Button>
                        <Button size="xs" variant="subtle" color="red" onClick={() => setRevokeDevice(d)}>
                          {t('devices.revoke')}
                        </Button>
                      </Group>
                    )}
                  </Stack>
                </Card>
              ))}
            </SimpleGrid>
          )
        }
      </Loaded>

      {taskDevice && <TaskModal device={taskDevice} onClose={() => setTaskDevice(undefined)} />}
      {enrollCommand && <EnrollModal command={enrollCommand} onClose={() => setEnrollCommand(undefined)} />}
      {revokeDevice && (
        <Modal opened onClose={() => setRevokeDevice(undefined)} title={t('devices.revokeTitle', { name: revokeDevice.hostname })}>
          <Stack>
            <Text size="sm">{t('devices.revokeText')}</Text>
            <Group justify="flex-end">
              <Button variant="default" onClick={() => setRevokeDevice(undefined)}>
                {t('common.cancel')}
              </Button>
              <Button color="red" onClick={() => revoke(revokeDevice)}>
                {t('devices.revokeConfirm')}
              </Button>
            </Group>
          </Stack>
        </Modal>
      )}
    </Stack>
  );
}
