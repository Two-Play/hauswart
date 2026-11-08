import { Button, Group, MultiSelect, Paper, Select, Stack, Text, TextInput, Title } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { api, useResource, type Device } from '../api';
import { buildPayload, taskKey } from '../tasks';
import { Loaded, showError } from '../ui';
import { ApprovalRulesPanel } from './ApprovalRulesPanel';
import { PackageSearch } from './PackageSearch';
import { PolicyPanel } from './PolicyPanel';

interface DeviceGroup {
  id: number;
  name: string;
  devices: string[];
}

const words = (text: string) => text.split(/\s+/).filter(Boolean);

const GROUP_TASKS = ['pkg.upgrade', 'pkg.install', 'pkg.remove', 'flatpak.install'];

function GroupCard({ group, devices, reload }: { group: DeviceGroup; devices: Device[]; reload: () => void }) {
  const { t } = useTranslation();
  const [type, setType] = useState('pkg.upgrade');
  const [packages, setPackages] = useState('');

  async function setMembers(next: string[]) {
    try {
      await api('PUT', `/api/groups/${group.id}/devices`, { devices: next });
      reload();
    } catch (err) {
      showError(err);
    }
  }

  async function run(e: FormEvent) {
    e.preventDefault();
    try {
      const payload = type === 'pkg.upgrade' ? {} : buildPayload({ packages });
      const out = await api<{ tasks: string[] }>('POST', `/api/groups/${group.id}/tasks`, { type, payload });
      notifications.show({ color: 'teal', message: t('groups.queued', { count: out.tasks.length }) });
      setPackages('');
    } catch (err) {
      showError(err);
    }
  }

  async function remove() {
    try {
      await api('DELETE', `/api/groups/${group.id}`);
      reload();
    } catch (err) {
      showError(err);
    }
  }

  return (
    <Paper withBorder p="md">
      <Stack>
        <Group justify="space-between">
          <Title order={4}>{group.name}</Title>
          <Button size="xs" variant="subtle" color="red" onClick={remove}>
            {t('groups.delete')}
          </Button>
        </Group>
        <MultiSelect
          label={t('groups.members')}
          data={devices.map((d) => ({ value: d.id, label: d.hostname }))}
          value={group.devices}
          onChange={setMembers}
        />
        <form onSubmit={run}>
          <Group align="flex-end">
            <Select
              label={t('actions.type')}
              allowDeselect={false}
              value={type}
              onChange={(next) => setType(next ?? type)}
              data={GROUP_TASKS.map((key) => ({ value: key, label: t(taskKey(key)) }))}
            />
            {type !== 'pkg.upgrade' && (
              <PackageSearch
                kind={type === 'flatpak.install' ? 'flatpak' : 'package'}
                scope={{ group: group.id }}
                label={t('fields.packages')}
                required
                miw={260}
                value={words(packages)}
                onChange={(next) => setPackages(next.join(' '))}
              />
            )}
            <Button type="submit" disabled={group.devices.length === 0}>
              {t('actions.run')}
            </Button>
          </Group>
        </form>
        <PolicyPanel groupId={group.id} devices={devices} />
        <ApprovalRulesPanel path={`/api/groups/${group.id}/approval-rules`} inherit scope={{ group: group.id }} />
      </Stack>
    </Paper>
  );
}

export function GroupsView() {
  const { t } = useTranslation();
  const groups = useResource<DeviceGroup[]>('/api/groups');
  const devices = useResource<Device[]>('/api/devices');
  const [name, setName] = useState('');

  async function create(e: FormEvent) {
    e.preventDefault();
    try {
      await api('POST', '/api/groups', { name });
      setName('');
      groups.reload();
    } catch (err) {
      showError(err);
    }
  }

  return (
    <Stack>
      <Title order={2}>{t('nav.groups')}</Title>
      <Paper withBorder p="md">
        <form onSubmit={create}>
          <Group align="flex-end">
            <TextInput label={t('groups.name')} required value={name} onChange={(e) => setName(e.currentTarget.value)} />
            <Button type="submit">{t('groups.create')}</Button>
          </Group>
        </form>
        <Text size="xs" c="dimmed" mt="xs">
          {t('groups.hint')}
        </Text>
      </Paper>
      <Paper withBorder p="md">
        <ApprovalRulesPanel path="/api/approval-rules" inherit={false} />
      </Paper>
      <Loaded data={groups.data} error={groups.error}>
        {(list) =>
          list.length === 0 ? (
            <Text c="dimmed">{t('groups.empty')}</Text>
          ) : (
            list.map((group) => (
              <GroupCard
                key={group.id}
                group={group}
                devices={(devices.data ?? []).filter((d) => !d.revoked)}
                reload={groups.reload}
              />
            ))
          )
        }
      </Loaded>
    </Stack>
  );
}
