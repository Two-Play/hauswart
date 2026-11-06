import {
  ActionIcon,
  Badge,
  Button,
  Checkbox,
  Divider,
  Group,
  Modal,
  MultiSelect,
  Paper,
  PasswordInput,
  Select,
  Stack,
  TagsInput,
  Text,
  Textarea,
  TextInput,
  Title,
} from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api, useResource, type Device } from '../api';
import { Loaded, showError } from '../ui';

interface Window {
  days: string[];
  start: string;
  end: string;
}

interface FileRule {
  path: string;
  content: string;
  mode: string;
}

interface CARule {
  name: string;
  pem: string;
}

interface ScreenRule {
  user: string;
  windows: Window[];
}

interface Policy {
  required_packages?: string[];
  forbidden_packages?: string[];
  required_flatpaks?: string[];
  forbidden_flatpaks?: string[];
  files?: FileRule[];
  cas?: CARule[];
  updates?: { window: Window; reboot: string };
  security?: { firewall?: boolean; disk_encryption?: boolean; screen_lock?: boolean };
  time_zone?: string;
  screen_time?: ScreenRule[];
  language?: string;
  directory?: { uri: string; base_dn: string; bind_dn: string; bind_password: string; ca: string };
  mounts?: { server: string; share: string; folder: string }[];
  nextcloud?: { url: string; mode: string };
}

interface DevicePolicy {
  id: string;
  state: string;
  conflicts?: { item: string; groups: string[] }[];
  deviations?: { kind: string; item: string; detail?: string }[];
  corrected?: string[];
  checks?: Record<string, string>;
}

interface PolicyView {
  policy: Policy | null;
  devices: DevicePolicy[];
}

const DAYS = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'];

const STATE_COLORS: Record<string, string> = {
  none: 'gray',
  current: 'teal',
  signature: 'yellow',
  pending: 'blue',
  outdated: 'orange',
  deviation: 'orange',
  conflict: 'red',
  unprotected: 'red',
};

function DaysInput({ value, onChange }: { value: string[]; onChange: (days: string[]) => void }) {
  const { t } = useTranslation();
  return (
    <MultiSelect
      label={t('policies.days')}
      data={DAYS.map((day) => ({ value: day, label: t(`policies.day.${day}`) }))}
      value={value}
      onChange={onChange}
    />
  );
}

function WindowInput({ value, onChange }: { value: Window; onChange: (window: Window) => void }) {
  const { t } = useTranslation();
  return (
    <Group align="flex-end" grow>
      <DaysInput value={value.days} onChange={(days) => onChange({ ...value, days })} />
      <TextInput
        label={t('policies.start')}
        placeholder="15:00"
        value={value.start}
        onChange={(e) => onChange({ ...value, start: e.currentTarget.value })}
      />
      <TextInput
        label={t('policies.end')}
        placeholder="19:00"
        value={value.end}
        onChange={(e) => onChange({ ...value, end: e.currentTarget.value })}
      />
    </Group>
  );
}

function replaced<T>(list: T[], index: number, next: T): T[] {
  return list.map((entry, i) => (i === index ? next : entry));
}

function without<T>(list: T[], index: number): T[] {
  return list.filter((_, i) => i !== index);
}

function PolicyForm({ initial, onSave, onClose }: { initial: Policy; onSave: (p: Policy) => void; onClose: () => void }) {
  const { t } = useTranslation();
  const [p, setP] = useState<Policy>(initial);
  const change = (next: Partial<Policy>) => setP({ ...p, ...next });
  const files = p.files ?? [];
  const cas = p.cas ?? [];
  const rules = p.screen_time ?? [];
  const security = p.security ?? {};
  const mounts = p.mounts ?? [];
  const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;

  return (
    <Stack>
      <Title order={5}>{t('policies.software')}</Title>
      <TagsInput
        label={t('policies.requiredPackages')}
        value={p.required_packages ?? []}
        onChange={(required_packages) => change({ required_packages })}
      />
      <TagsInput
        label={t('policies.forbiddenPackages')}
        description={t('policies.forbiddenHint')}
        value={p.forbidden_packages ?? []}
        onChange={(forbidden_packages) => change({ forbidden_packages })}
      />
      <TagsInput
        label={t('policies.requiredFlatpaks')}
        value={p.required_flatpaks ?? []}
        onChange={(required_flatpaks) => change({ required_flatpaks })}
      />
      <TagsInput
        label={t('policies.forbiddenFlatpaks')}
        value={p.forbidden_flatpaks ?? []}
        onChange={(forbidden_flatpaks) => change({ forbidden_flatpaks })}
      />

      <Divider />
      <Title order={5}>{t('policies.files')}</Title>
      <Text size="xs" c="dimmed">
        {t('policies.filesHint')}
      </Text>
      {files.map((file, i) => (
        <Paper withBorder p="xs" key={i}>
          <Stack gap="xs">
            <Group align="flex-end" grow>
              <TextInput
                label={t('policies.path')}
                value={file.path}
                onChange={(e) => change({ files: replaced(files, i, { ...file, path: e.currentTarget.value }) })}
              />
              <TextInput
                label={t('policies.mode')}
                placeholder="0644"
                value={file.mode}
                onChange={(e) => change({ files: replaced(files, i, { ...file, mode: e.currentTarget.value }) })}
              />
            </Group>
            <Textarea
              label={t('policies.content')}
              autosize
              minRows={2}
              maxRows={10}
              value={file.content}
              onChange={(e) => change({ files: replaced(files, i, { ...file, content: e.currentTarget.value }) })}
            />
            <Button size="xs" variant="subtle" color="red" onClick={() => change({ files: without(files, i) })}>
              {t('policies.remove')}
            </Button>
          </Stack>
        </Paper>
      ))}
      <Button size="xs" variant="light" onClick={() => change({ files: [...files, { path: '', content: '', mode: '' }] })}>
        {t('policies.addFile')}
      </Button>

      <Divider />
      <Title order={5}>{t('policies.cas')}</Title>
      <Text size="xs" c="dimmed">
        {t('policies.casHint')}
      </Text>
      {cas.map((ca, i) => (
        <Paper withBorder p="xs" key={i}>
          <Stack gap="xs">
            <TextInput
              label={t('policies.caName')}
              value={ca.name}
              onChange={(e) => change({ cas: replaced(cas, i, { ...ca, name: e.currentTarget.value }) })}
            />
            <Textarea
              label={t('policies.caPem')}
              autosize
              minRows={3}
              maxRows={8}
              value={ca.pem}
              onChange={(e) => change({ cas: replaced(cas, i, { ...ca, pem: e.currentTarget.value }) })}
            />
            <Button size="xs" variant="subtle" color="red" onClick={() => change({ cas: without(cas, i) })}>
              {t('policies.remove')}
            </Button>
          </Stack>
        </Paper>
      ))}
      <Button size="xs" variant="light" onClick={() => change({ cas: [...cas, { name: '', pem: '' }] })}>
        {t('policies.addCA')}
      </Button>

      <Divider />
      <Title order={5}>{t('policies.updates')}</Title>
      <Checkbox
        label={t('policies.updatesOn')}
        checked={!!p.updates}
        onChange={(e) =>
          change({
            updates: e.currentTarget.checked
              ? { window: { days: ['sat'], start: '02:00', end: '04:00' }, reboot: 'never' }
              : undefined,
          })
        }
      />
      {p.updates && (
        <>
          <WindowInput
            value={p.updates.window}
            onChange={(window) => change({ updates: { reboot: p.updates?.reboot ?? 'never', window } })}
          />
          <Select
            label={t('policies.reboot')}
            allowDeselect={false}
            value={p.updates.reboot}
            onChange={(reboot) => p.updates && change({ updates: { ...p.updates, reboot: reboot ?? 'never' } })}
            data={['never', 'window'].map((value) => ({ value, label: t(`policies.rebootRule.${value}`) }))}
          />
        </>
      )}

      <Divider />
      <Title order={5}>{t('policies.security')}</Title>
      <Checkbox
        label={t('policies.firewall')}
        checked={!!security.firewall}
        onChange={(e) => change({ security: { ...security, firewall: e.currentTarget.checked } })}
      />
      <Checkbox
        label={t('policies.diskEncryption')}
        checked={!!security.disk_encryption}
        onChange={(e) => change({ security: { ...security, disk_encryption: e.currentTarget.checked } })}
      />
      <Checkbox
        label={t('policies.screenLock')}
        checked={!!security.screen_lock}
        onChange={(e) => change({ security: { ...security, screen_lock: e.currentTarget.checked } })}
      />

      <Divider />
      <Title order={5}>{t('policies.screenTime')}</Title>
      <Text size="xs" c="dimmed">
        {t('policies.screenTimeHint')}
      </Text>
      <TextInput
        label={t('policies.timeZone')}
        placeholder={zone}
        value={p.time_zone ?? ''}
        onChange={(e) => change({ time_zone: e.currentTarget.value })}
      />
      {rules.map((rule, i) => (
        <Paper withBorder p="xs" key={i}>
          <Stack gap="xs">
            <TextInput
              label={t('policies.linuxUser')}
              value={rule.user}
              onChange={(e) => change({ screen_time: replaced(rules, i, { ...rule, user: e.currentTarget.value }) })}
            />
            {rule.windows.map((window, w) => (
              <Group key={w} align="flex-end" wrap="nowrap">
                <div style={{ flex: 1 }}>
                  <WindowInput
                    value={window}
                    onChange={(next) =>
                      change({ screen_time: replaced(rules, i, { ...rule, windows: replaced(rule.windows, w, next) }) })
                    }
                  />
                </div>
                <ActionIcon
                  variant="subtle"
                  color="red"
                  aria-label={t('policies.remove')}
                  onClick={() => change({ screen_time: replaced(rules, i, { ...rule, windows: without(rule.windows, w) }) })}
                >
                  ×
                </ActionIcon>
              </Group>
            ))}
            <Group>
              <Button
                size="xs"
                variant="light"
                onClick={() =>
                  change({
                    screen_time: replaced(rules, i, {
                      ...rule,
                      windows: [...rule.windows, { days: DAYS.slice(0, 5), start: '15:00', end: '19:00' }],
                    }),
                  })
                }
              >
                {t('policies.addWindow')}
              </Button>
              <Button size="xs" variant="subtle" color="red" onClick={() => change({ screen_time: without(rules, i) })}>
                {t('policies.remove')}
              </Button>
            </Group>
          </Stack>
        </Paper>
      ))}
      <Button
        size="xs"
        variant="light"
        onClick={() =>
          change({ screen_time: [...rules, { user: '', windows: [] }], time_zone: p.time_zone || zone })
        }
      >
        {t('policies.addRule')}
      </Button>

      <Divider />
      <Title order={5}>{t('policies.directory')}</Title>
      <Text size="xs" c="dimmed">
        {t('policies.directoryHint')}
      </Text>
      <Checkbox
        label={t('policies.directoryOn')}
        checked={!!p.directory}
        onChange={(e) =>
          change({
            directory: e.currentTarget.checked ? { uri: '', base_dn: '', bind_dn: '', bind_password: '', ca: '' } : undefined,
          })
        }
      />
      {p.directory && (
        <>
          <TextInput
            label={t('policies.uri')}
            value={p.directory.uri}
            onChange={(e) => p.directory && change({ directory: { ...p.directory, uri: e.currentTarget.value } })}
          />
          <TextInput
            label={t('policies.baseDn')}
            value={p.directory.base_dn}
            onChange={(e) => p.directory && change({ directory: { ...p.directory, base_dn: e.currentTarget.value } })}
          />
          <TextInput
            label={t('policies.bindDn')}
            value={p.directory.bind_dn}
            onChange={(e) => p.directory && change({ directory: { ...p.directory, bind_dn: e.currentTarget.value } })}
          />
          <PasswordInput
            label={t('policies.bindPassword')}
            value={p.directory.bind_password}
            onChange={(e) => p.directory && change({ directory: { ...p.directory, bind_password: e.currentTarget.value } })}
          />
          <Textarea
            label={t('policies.directoryCa')}
            description={t('policies.directoryCaHint')}
            autosize
            minRows={3}
            maxRows={8}
            value={p.directory.ca}
            onChange={(e) => p.directory && change({ directory: { ...p.directory, ca: e.currentTarget.value } })}
          />
        </>
      )}

      <Divider />
      <Title order={5}>{t('policies.mounts')}</Title>
      <Text size="xs" c="dimmed">
        {t('policies.mountsHint')}
      </Text>
      {mounts.map((mount, i) => (
        <Group key={i} align="flex-end" wrap="nowrap">
          <TextInput
            label={t('policies.server')}
            value={mount.server}
            onChange={(e) => change({ mounts: replaced(mounts, i, { ...mount, server: e.currentTarget.value }) })}
          />
          <TextInput
            label={t('policies.share')}
            value={mount.share}
            onChange={(e) => change({ mounts: replaced(mounts, i, { ...mount, share: e.currentTarget.value }) })}
          />
          <TextInput
            label={t('policies.folder')}
            value={mount.folder}
            onChange={(e) => change({ mounts: replaced(mounts, i, { ...mount, folder: e.currentTarget.value }) })}
          />
          <ActionIcon
            variant="subtle"
            color="red"
            aria-label={t('policies.remove')}
            onClick={() => change({ mounts: without(mounts, i) })}
          >
            ×
          </ActionIcon>
        </Group>
      ))}
      <Button size="xs" variant="light" onClick={() => change({ mounts: [...mounts, { server: '', share: '', folder: '' }] })}>
        {t('policies.addMount')}
      </Button>

      <Divider />
      <Title order={5}>{t('policies.nextcloud')}</Title>
      <Checkbox
        label={t('policies.nextcloudOn')}
        checked={!!p.nextcloud}
        onChange={(e) => change({ nextcloud: e.currentTarget.checked ? { url: '', mode: 'client' } : undefined })}
      />
      {p.nextcloud && (
        <>
          <TextInput
            label={t('policies.nextcloudUrl')}
            value={p.nextcloud.url}
            onChange={(e) => p.nextcloud && change({ nextcloud: { ...p.nextcloud, url: e.currentTarget.value } })}
          />
          <Select
            label={t('policies.nextcloudMode')}
            allowDeselect={false}
            value={p.nextcloud.mode}
            onChange={(mode) => p.nextcloud && change({ nextcloud: { ...p.nextcloud, mode: mode ?? 'client' } })}
            data={['client', 'drive'].map((value) => ({ value, label: t(`policies.nextcloudModes.${value}`) }))}
          />
        </>
      )}

      <Group justify="flex-end">
        <Button variant="subtle" onClick={onClose}>
          {t('policies.cancel')}
        </Button>
        <Button onClick={() => onSave(p)}>{t('policies.save')}</Button>
      </Group>
    </Stack>
  );
}

// What the server would treat as nothing should not reach it as empty lists.
function normalized(p: Policy, language: string): Policy {
  const out: Policy = { ...p };
  // Warnings come in the language of whoever sets the rules.
  if (p.screen_time?.length) out.language = language.startsWith('de') ? 'de' : 'en';
  const security = p.security;
  if (security && !security.firewall && !security.disk_encryption && !security.screen_lock) delete out.security;
  if (!p.time_zone) delete out.time_zone;
  return out;
}

function hasPolicy(view: PolicyView) {
  return view.policy !== null;
}

function DeviceRow({ state, hostname }: { state: DevicePolicy; hostname: string }) {
  const { t } = useTranslation();
  return (
    <Stack gap={2}>
      <Group gap="xs">
        <Text size="sm">{hostname}</Text>
        <Badge size="sm" variant="light" color={STATE_COLORS[state.state] ?? 'gray'}>
          {t(`policies.states.${state.state}`)}
        </Badge>
      </Group>
      {state.conflicts?.map((c) => (
        <Text size="xs" c="red" key={c.item}>
          {t('policies.conflict', { item: c.item, groups: c.groups.join(', ') })}
        </Text>
      ))}
      {state.deviations?.map((d) => (
        <Text size="xs" c="orange" key={`${d.kind} ${d.item}`}>
          {d.kind} {d.item}
          {d.detail ? `: ${d.detail}` : ''}
        </Text>
      ))}
      {state.checks && (
        <Text size="xs" c="dimmed">
          {Object.entries(state.checks)
            .map(([name, value]) => `${t(`policies.checks.${name}`)}: ${t(`policies.checkState.${value}`)}`)
            .join(' · ')}
        </Text>
      )}
      {state.corrected && state.corrected.length > 0 && (
        <Text size="xs" c="dimmed">
          {t('policies.corrected', { items: state.corrected.join(', ') })}
        </Text>
      )}
    </Stack>
  );
}

export function PolicyPanel({ groupId, devices }: { groupId: number; devices: Device[] }) {
  const { t, i18n } = useTranslation();
  const view = useResource<PolicyView>(`/api/groups/${groupId}/policy`, 10_000);
  const [editing, setEditing] = useState(false);

  async function save(policy: Policy) {
    try {
      await api('PUT', `/api/groups/${groupId}/policy`, normalized(policy, i18n.language));
      notifications.show({ color: 'teal', message: t('policies.saved') });
      setEditing(false);
      view.reload();
    } catch (err) {
      showError(err);
    }
  }

  async function remove() {
    await save({});
  }

  return (
    <>
      <Divider />
      <Loaded data={view.data} error={view.error}>
        {(data) => (
          <Stack gap="xs">
            <Group justify="space-between">
              <Title order={5}>{t('policies.title')}</Title>
              <Group gap="xs">
                {hasPolicy(data) && (
                  <Button size="xs" variant="subtle" color="red" onClick={remove}>
                    {t('policies.delete')}
                  </Button>
                )}
                <Button size="xs" variant="light" onClick={() => setEditing(true)}>
                  {t(hasPolicy(data) ? 'policies.edit' : 'policies.create')}
                </Button>
              </Group>
            </Group>
            {hasPolicy(data) ? (
              data.devices.map((state) => (
                <DeviceRow
                  key={state.id}
                  state={state}
                  hostname={devices.find((d) => d.id === state.id)?.hostname ?? state.id}
                />
              ))
            ) : (
              <Text size="sm" c="dimmed">
                {t('policies.empty')}
              </Text>
            )}
            <Modal opened={editing} onClose={() => setEditing(false)} title={t('policies.title')} size="xl">
              <PolicyForm initial={data.policy ?? {}} onSave={save} onClose={() => setEditing(false)} />
            </Modal>
          </Stack>
        )}
      </Loaded>
    </>
  );
}
