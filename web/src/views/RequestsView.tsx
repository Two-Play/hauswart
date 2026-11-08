import { Button, Group, Paper, Select, SimpleGrid, Stack, TextInput, Title } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { api, isApprover, useResource, type AccessRequest, type Device, type User } from '../api';
import { DataTable, formatTime, Loaded, showError, StatusBadge } from '../ui';
import { REQUEST_KINDS } from './ApprovalRulesPanel';

export function RequestsView({ user }: { user: User }) {
  const { t } = useTranslation();
  const requests = useResource<AccessRequest[]>('/api/requests', 10_000);
  const devices = useResource<Device[]>('/api/devices');
  const [deviceId, setDeviceId] = useState<string | null>(null);
  const [kind, setKind] = useState<string>('software');
  const [detail, setDetail] = useState('');
  const [reason, setReason] = useState('');

  const options = (devices.data ?? []).filter((d) => !d.revoked).map((d) => ({ value: d.id, label: d.hostname }));

  async function submit(e: FormEvent) {
    e.preventDefault();
    try {
      const out = await api<{ status: string }>('POST', '/api/requests', { device_id: deviceId, kind, detail, reason });
      notifications.show({
        color: 'teal',
        message: t(out.status === 'approved' ? 'requests.autoApproved' : 'requests.filed'),
      });
      setDetail('');
      setReason('');
      requests.reload();
    } catch (err) {
      showError(err);
    }
  }

  async function decide(id: string, action: 'approve' | 'deny') {
    try {
      await api('POST', `/api/requests/${id}/${action}`);
    } catch (err) {
      showError(err);
    }
    requests.reload();
  }

  // Approvers leave their own requests to someone else, and admin-only ones to
  // an admin, as the server insists.
  function canDecide(r: AccessRequest) {
    if (!isApprover(user) || r.status !== 'open') return false;
    if (user.role === 'admin') return true;
    return r.username !== user.username && r.mode !== 'admin' && r.mode !== 'blocked';
  }

  function decider(r: AccessRequest) {
    if (r.status === 'open') return r.mode === 'admin' || r.mode === 'blocked' ? t('requests.adminDecides') : '';
    return r.decided_by === 'auto' ? t('requests.automatic') : r.decided_by;
  }

  function describe(r: AccessRequest) {
    const timed = r.kind === 'sudo' || r.kind === 'screen';
    const detailText = timed ? t('requests.sudoDetail', { minutes: r.detail }) : r.detail;
    return `${t(`requests.kinds.${r.kind}`)}: ${detailText}`;
  }

  return (
    <Stack>
      <Title order={2}>{t('nav.requests')}</Title>

      <Paper withBorder p="md">
        <form onSubmit={submit}>
          <Stack>
            <Title order={4}>{t('requests.new')}</Title>
            <SimpleGrid cols={{ base: 1, sm: 2 }}>
              <Select
                label={t('requests.device')}
                required
                data={options}
                value={deviceId}
                onChange={setDeviceId}
              />
              <Select
                label={t('requests.kind')}
                allowDeselect={false}
                value={kind}
                onChange={(next) => setKind(next ?? kind)}
                data={REQUEST_KINDS.map((k) => ({ value: k, label: t(`requests.kinds.${k}`) }))}
              />
              <TextInput
                label={t(kind === 'sudo' || kind === 'screen' ? 'requests.minutes' : 'requests.packages')}
                type={kind === 'sudo' || kind === 'screen' ? 'number' : 'text'}
                required
                value={detail}
                onChange={(e) => setDetail(e.currentTarget.value)}
              />
              <TextInput
                label={t('requests.reason')}
                value={reason}
                onChange={(e) => setReason(e.currentTarget.value)}
              />
            </SimpleGrid>
            <Group>
              <Button type="submit" disabled={!deviceId}>
                {t('requests.submit')}
              </Button>
            </Group>
          </Stack>
        </form>
      </Paper>

      <Paper withBorder p="md">
        <Loaded data={requests.data} error={requests.error}>
          {(list) => (
            <DataTable
              empty={t('requests.empty')}
              headers={[
                t('requests.time'),
                t('requests.from'),
                t('requests.device'),
                t('requests.request'),
                t('requests.reason'),
                t('requests.status'),
                t('requests.decidedBy'),
                '',
              ]}
              rows={list.map((r) => ({
                key: r.id,
                cells: [
                  formatTime(r.created_at),
                  r.username,
                  r.hostname,
                  describe(r),
                  r.reason,
                  <StatusBadge status={r.status} />,
                  decider(r),
                  canDecide(r) && (
                    <Group gap="xs" wrap="nowrap">
                      <Button size="xs" onClick={() => decide(r.id, 'approve')}>
                        {t('requests.approve')}
                      </Button>
                      <Button size="xs" variant="subtle" color="red" onClick={() => decide(r.id, 'deny')}>
                        {t('requests.deny')}
                      </Button>
                    </Group>
                  ),
                ],
              }))}
            />
          )}
        </Loaded>
      </Paper>
    </Stack>
  );
}
