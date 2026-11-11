import { Alert, Badge, Button, Code, Group, Modal, Paper, Stack, Text, TextInput, Title } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { IconAlertTriangle } from '@tabler/icons-react';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { api, ApiError, useResource, type PasskeyEntry, type Task, type User, type WaitingTask } from '../api';
import {
  approveWithPasskey,
  decodeEnvelope,
  passkeysAvailable,
  registerPasskey,
  type Challenge,
  type Envelope,
} from '../passkey';
import { taskKey } from '../tasks';
import { PasskeyTypesPanel } from './PasskeyTypesPanel';
import { DataTable, ExpandableText, formatTime, Loaded, showError } from '../ui';

function Weakness() {
  const { t } = useTranslation();
  return (
    <Alert color="orange" icon={<IconAlertTriangle size={18} />} title={t('approvals.weaknessTitle')}>
      <ExpandableText size="sm" lines={2}>
        {t('approvals.weakness')}
      </ExpandableText>
    </Alert>
  );
}

function PasskeyList() {
  const { t } = useTranslation();
  const { data, error, reload } = useResource<PasskeyEntry[]>('/api/passkeys');
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);

  async function add(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      await registerPasskey(name);
      setName('');
      notifications.show({ color: 'teal', message: t('approvals.registered') });
      reload();
    } catch (err) {
      showError(err);
    }
    setBusy(false);
  }

  async function remove(id: number) {
    try {
      await api('DELETE', `/api/passkeys/${id}`);
      reload();
    } catch (err) {
      showError(err);
    }
  }

  return (
    <Paper withBorder p="md">
      <Stack>
        <Title order={4}>{t('approvals.passkeys')}</Title>
        <ExpandableText size="sm" c="dimmed" lines={2}>
          {t('approvals.passkeysHint')}
        </ExpandableText>
        <Loaded data={data} error={error}>
          {(list) => (
            <Stack>
            {list.length > 0 && list.every((p) => (p.pinned_on ?? []).length === 0) && (
              <Alert color="orange" title={t('approvals.nothingPinnedTitle')}>
                <ExpandableText size="sm" lines={3}>
                  {t('approvals.nothingPinned')}
                </ExpandableText>
              </Alert>
            )}
            <DataTable
              empty={t('approvals.noPasskeys')}
              headers={[t('approvals.passkeyName'), t('approvals.owner'), t('approvals.added'), t('approvals.pinnedOn'), '']}
              rows={list.map((p) => ({
                key: String(p.id),
                cells: [
                  p.name,
                  p.username,
                  formatTime(p.created_at),
                  (p.pinned_on ?? []).length > 0 ? (
                    <Group gap={4}>
                      {(p.pinned_on ?? []).map((d) => (
                        <Badge key={d.id} variant="light" color="teal">
                          {d.hostname}
                        </Badge>
                      ))}
                    </Group>
                  ) : (
                    <Stack gap={2}>
                      <Badge variant="light" color="orange">
                        {t('approvals.pinnedNowhere')}
                      </Badge>
                      <ExpandableText size="xs" c="dimmed" lines={1} maw={340}>
                        {t('approvals.pinHow', { id: p.id })}
                      </ExpandableText>
                    </Stack>
                  ),
                  <Button size="xs" variant="subtle" color="red" onClick={() => remove(p.id)}>
                    {t('approvals.deletePasskey')}
                  </Button>,
                ],
              }))}
            />
            </Stack>
          )}
        </Loaded>
        <form onSubmit={add}>
          <Group align="flex-end">
            <TextInput
              label={t('approvals.passkeyName')}
              placeholder={t('approvals.passkeyNameHint')}
              required
              maxLength={64}
              value={name}
              onChange={(e) => setName(e.currentTarget.value)}
            />
            <Button type="submit" loading={busy} disabled={!passkeysAvailable()}>
              {t('approvals.register')}
            </Button>
          </Group>
        </form>
      </Stack>
    </Paper>
  );
}

/** Shows what is in the envelope and only then asks for the passkey. */
function ConfirmModal({
  task,
  challenge,
  onClose,
}: {
  task: WaitingTask;
  challenge: Challenge;
  onClose: (done: boolean) => void;
}) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);
  const envelope: Envelope = decodeEnvelope(challenge);

  async function confirm() {
    setBusy(true);
    try {
      await approveWithPasskey(task.id, challenge);
      notifications.show({ color: 'teal', message: t('approvals.approved') });
      onClose(true);
    } catch (err) {
      setBusy(false);
      if (err instanceof ApiError && err.code === 'passkey_retry') {
        onClose(false);
      }
      showError(err);
    }
  }

  return (
    <Modal opened onClose={() => onClose(false)} title={t('approvals.confirmTitle')}>
      <Stack>
        <Weakness />
        <Text size="sm">
          {t('approvals.device')}: <strong>{challenge.hostname}</strong> ({envelope.device_id})
        </Text>
        <Text size="sm">
          {t('approvals.task')}: <strong>{t(taskKey(envelope.type), { defaultValue: envelope.type })}</strong>
        </Text>
        <Code block>{JSON.stringify(envelope.payload, null, 2)}</Code>
        <Text size="sm" c="dimmed">
          {t('approvals.validUntil', { time: new Date(envelope.not_after).toLocaleString() })}
        </Text>
        <Group justify="flex-end">
          <Button variant="default" onClick={() => onClose(false)}>
            {t('common.cancel')}
          </Button>
          <Button loading={busy} onClick={confirm}>
            {t('approvals.confirm')}
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}

function Queue() {
  const { t } = useTranslation();
  const { data, error, reload } = useResource<WaitingTask[]>('/api/approvals', 10_000);
  const [open, setOpen] = useState<{ task: WaitingTask; challenge: Challenge }>();

  async function start(task: WaitingTask) {
    try {
      setOpen({ task, challenge: await api<Challenge>('POST', `/api/tasks/${task.id}/passkey-challenge`) });
    } catch (err) {
      showError(err);
    }
  }

  async function reject(task: WaitingTask) {
    try {
      await api('POST', `/api/tasks/${task.id}/reject`);
    } catch (err) {
      showError(err);
    }
    reload();
  }

  return (
    <Paper withBorder p="md">
      <Stack>
        <Title order={4}>{t('approvals.queue')}</Title>
        <Loaded data={data} error={error}>
          {(list) => (
            <DataTable
              empty={t('approvals.empty')}
              headers={[t('approvals.time'), t('approvals.device'), t('approvals.task'), t('approvals.from'), '']}
              rows={list.map((task) => ({
                key: task.id,
                cells: [
                  formatTime(task.created_at),
                  task.hostname,
                  t(taskKey(task.type), { defaultValue: task.type }),
                  task.created_by,
                  <Group gap="xs" wrap="nowrap">
                    <Button size="xs" disabled={!passkeysAvailable()} onClick={() => start(task)}>
                      {t('approvals.approve')}
                    </Button>
                    <Button size="xs" variant="subtle" color="red" onClick={() => reject(task)}>
                      {t('approvals.reject')}
                    </Button>
                  </Group>,
                ],
              }))}
            />
          )}
        </Loaded>
      </Stack>
      {open && (
        <ConfirmModal
          task={open.task}
          challenge={open.challenge}
          onClose={() => {
            setOpen(undefined);
            reload();
          }}
        />
      )}
    </Paper>
  );
}

/** What only the signing tool can approve, so an admin sees all that waits. */
function SigningQueue() {
  const { t } = useTranslation();
  const { data, error } = useResource<Task[]>('/api/signing', 10_000);
  const { data: passkeyQueue } = useResource<WaitingTask[]>('/api/approvals', 10_000);
  const offered = new Set((passkeyQueue ?? []).map((task) => task.id));

  return (
    <Paper withBorder p="md">
      <Stack>
        <Title order={4}>{t('approvals.signing')}</Title>
        <ExpandableText size="sm" c="dimmed" lines={2}>
          {t('approvals.signingHint')}
        </ExpandableText>
        <Loaded data={data} error={error}>
          {(list) => (
            <DataTable
              empty={t('approvals.signingEmpty')}
              headers={[t('approvals.time'), t('approvals.device'), t('approvals.task'), t('approvals.from')]}
              rows={list
                .filter((task) => !offered.has(task.id))
                .map((task) => ({
                  key: task.id,
                  cells: [
                    formatTime(task.created_at),
                    task.device_id.slice(0, 12),
                    t(taskKey(task.type), { defaultValue: task.type }),
                    task.created_by,
                  ],
                }))}
            />
          )}
        </Loaded>
      </Stack>
    </Paper>
  );
}

export function ApprovalsView({ user }: { user: User }) {
  const { t } = useTranslation();
  return (
    <Stack>
      <div>
        <Title order={2}>{t('nav.approvals')}</Title>
        <Text c="dimmed">{t('approvals.subtitle')}</Text>
      </div>
      <Weakness />
      {!passkeysAvailable() && (
        <Alert color="red" title={t('approvals.unavailableTitle')}>
          <Text size="sm">{t('approvals.unavailable')}</Text>
        </Alert>
      )}
      <Queue />
      {user.role === 'admin' && <SigningQueue />}
      <PasskeyList />
      {user.role === 'admin' && <PasskeyTypesPanel />}
    </Stack>
  );
}
