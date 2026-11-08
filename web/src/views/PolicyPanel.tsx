import {
  ActionIcon,
  Badge,
  Button,
  Checkbox,
  Divider,
  Group,
  Modal,
  MultiSelect,
  NumberInput,
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
import { knownNames, KnownNamesContext, NameInput } from './NameInput';
import { PackageSearch, SearchScopeContext } from './PackageSearch';

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

export interface ScreenRule {
  user: string;
  windows: Window[];
  daily_minutes?: number;
}

export interface Policy {
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
  wifi?: { ssid: string; password: string; hidden?: boolean; security?: string }[];
  printers?: { name: string; uri: string; default?: boolean }[];
  apps?: AppRule[];
}

interface AppRule {
  user: string;
  block_downloads?: boolean;
  forbidden_programs?: string[];
  strict?: boolean;
  allowed_apps?: string[];
  flatpaks?: { mode: string; apps: string[] };
}

interface DevicePolicy {
  id: string;
  state: string;
  conflicts?: { item: string; groups: string[] }[];
  deviations?: { kind: string; item: string; detail?: string }[];
  corrected?: string[];
  checks?: Record<string, string>;
  apps?: { id: string; name: string }[];
}

export interface PolicyView {
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

/** ScreenTimeRules edits the screen time of people: windows and a daily quota. */
export function ScreenTimeRules({ rules, onChange }: { rules: ScreenRule[]; onChange: (rules: ScreenRule[]) => void }) {
  const { t } = useTranslation();
  const set = (i: number, next: ScreenRule) => onChange(replaced(rules, i, next));
  return (
    <Stack gap="xs">
      {rules.map((rule, i) => (
        <Paper withBorder p="xs" key={i}>
          <Stack gap="xs">
            <Group align="flex-end" grow>
              <NameInput of="users" label={t('policies.linuxUser')} value={rule.user} onChange={(user) => set(i, { ...rule, user })} />
              <NumberInput
                label={t('policies.dailyMinutes')}
                description={t('policies.dailyMinutesHint')}
                min={0}
                max={1440}
                step={15}
                value={rule.daily_minutes ?? ''}
                onChange={(value) => set(i, { ...rule, daily_minutes: typeof value === 'number' && value > 0 ? value : undefined })}
              />
            </Group>
            {rule.windows.map((window, w) => (
              <Group key={w} align="flex-end" wrap="nowrap">
                <div style={{ flex: 1 }}>
                  <WindowInput value={window} onChange={(next) => set(i, { ...rule, windows: replaced(rule.windows, w, next) })} />
                </div>
                <ActionIcon
                  variant="subtle"
                  color="red"
                  aria-label={t('policies.remove')}
                  onClick={() => set(i, { ...rule, windows: without(rule.windows, w) })}
                >
                  ×
                </ActionIcon>
              </Group>
            ))}
            {rule.windows.length === 0 && (
              <Text size="xs" c="dimmed">
                {t(rule.daily_minutes ? 'policies.quotaAllDay' : 'policies.noWindows')}
              </Text>
            )}
            <Group>
              <Button
                size="xs"
                variant="light"
                onClick={() =>
                  set(i, { ...rule, windows: [...rule.windows, { days: DAYS.slice(0, 5), start: '15:00', end: '19:00' }] })
                }
              >
                {t('policies.addWindow')}
              </Button>
              <Button size="xs" variant="subtle" color="red" onClick={() => onChange(without(rules, i))}>
                {t('policies.remove')}
              </Button>
            </Group>
          </Stack>
        </Paper>
      ))}
      <Group>
        <Button size="xs" variant="light" onClick={() => onChange([...rules, { user: '', windows: [], daily_minutes: 120 }])}>
          {t('policies.addRule')}
        </Button>
      </Group>
    </Stack>
  );
}

function AppRuleForm({
  rule,
  known,
  onChange,
  onRemove,
}: {
  rule: AppRule;
  known: { value: string; label: string }[];
  onChange: (rule: AppRule) => void;
  onRemove: () => void;
}) {
  const { t } = useTranslation();
  const mode = rule.flatpaks?.mode ?? 'none';
  const allowed = rule.allowed_apps ?? [];
  // A rule from another device may name what this list does not know.
  const choices = [...known, ...allowed.filter((id) => !known.some((k) => k.value === id)).map((id) => ({ value: id, label: id }))];
  return (
    <Paper withBorder p="xs">
      <Stack gap="xs">
        <NameInput
          of="users"
          label={t('policies.appUser')}
          value={rule.user}
          onChange={(user) => onChange({ ...rule, user })}
        />
        <Checkbox
          label={t('policies.appDownloads')}
          checked={!!rule.block_downloads || !!rule.strict}
          disabled={!!rule.strict}
          onChange={(e) => onChange({ ...rule, block_downloads: e.currentTarget.checked })}
        />
        <TagsInput
          label={t('policies.appForbidden')}
          placeholder="/usr/bin/steam"
          value={rule.forbidden_programs ?? []}
          onChange={(forbidden_programs) => onChange({ ...rule, forbidden_programs })}
        />
        <Checkbox
          label={t('policies.appStrict')}
          checked={!!rule.strict}
          onChange={(e) => {
            const strict = e.currentTarget.checked;
            onChange({ ...rule, strict, flatpaks: strict && rule.flatpaks?.mode === 'deny' ? undefined : rule.flatpaks });
          }}
        />
        {rule.strict &&
          (known.length > 0 ? (
            <MultiSelect
              label={t('policies.appAllowed')}
              searchable
              data={choices}
              value={allowed}
              onChange={(allowed_apps) => onChange({ ...rule, allowed_apps })}
            />
          ) : (
            // No device has reported yet, and the rule should not have to wait for one.
            <TagsInput
              label={t('policies.appAllowed')}
              value={allowed}
              onChange={(allowed_apps) => onChange({ ...rule, allowed_apps })}
            />
          ))}
        <Select
          label={t('policies.appFlatpakMode')}
          allowDeselect={false}
          value={mode}
          onChange={(next) =>
            onChange({
              ...rule,
              flatpaks: !next || next === 'none' ? undefined : { mode: next, apps: rule.flatpaks?.apps ?? [] },
            })
          }
          data={(rule.strict ? ['none', 'allow'] : ['none', 'allow', 'deny']).map((value) => ({
            value,
            label: t(`policies.appFlatpakModes.${value}`),
          }))}
        />
        {rule.flatpaks && (
          <PackageSearch
            kind="flatpak"
            label={t('policies.appFlatpaks')}
            value={rule.flatpaks.apps}
            onChange={(apps) => rule.flatpaks && onChange({ ...rule, flatpaks: { ...rule.flatpaks, apps } })}
          />
        )}
        <Button size="xs" variant="subtle" color="red" onClick={onRemove}>
          {t('policies.remove')}
        </Button>
      </Stack>
    </Paper>
  );
}

function PolicyForm({
  initial,
  known,
  onSave,
  onClose,
}: {
  initial: Policy;
  known: { value: string; label: string }[];
  onSave: (p: Policy) => void;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const [p, setP] = useState<Policy>(initial);
  const change = (next: Partial<Policy>) => setP({ ...p, ...next });
  const files = p.files ?? [];
  const cas = p.cas ?? [];
  const rules = p.screen_time ?? [];
  const security = p.security ?? {};
  const mounts = p.mounts ?? [];
  const appRules = p.apps ?? [];
  const wifi = p.wifi ?? [];
  const printers = p.printers ?? [];
  const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;

  return (
    <Stack>
      <Title order={5}>{t('policies.software')}</Title>
      <PackageSearch
        kind="package"
        label={t('policies.requiredPackages')}
        value={p.required_packages ?? []}
        onChange={(required_packages) => change({ required_packages })}
      />
      <PackageSearch
        kind="package"
        label={t('policies.forbiddenPackages')}
        description={t('policies.forbiddenHint')}
        value={p.forbidden_packages ?? []}
        onChange={(forbidden_packages) => change({ forbidden_packages })}
      />
      <PackageSearch
        kind="flatpak"
        label={t('policies.requiredFlatpaks')}
        value={p.required_flatpaks ?? []}
        onChange={(required_flatpaks) => change({ required_flatpaks })}
      />
      <PackageSearch
        kind="flatpak"
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
      <ScreenTimeRules
        rules={rules}
        onChange={(screen_time) => change({ screen_time, time_zone: p.time_zone || zone })}
      />

      <Divider />
      <Title order={5}>{t('policies.apps')}</Title>
      <Text size="xs" c="dimmed">
        {t('policies.appsHint')}
      </Text>
      {appRules.map((rule, i) => (
        <AppRuleForm
          key={i}
          rule={rule}
          known={known}
          onChange={(next) => change({ apps: replaced(appRules, i, next) })}
          onRemove={() => change({ apps: without(appRules, i) })}
        />
      ))}
      <Button size="xs" variant="light" onClick={() => change({ apps: [...appRules, { user: '' }] })}>
        {t('policies.addAppRule')}
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

      <Divider />
      <Title order={5}>{t('policies.wifi')}</Title>
      <Text size="xs" c="dimmed">
        {t('policies.wifiHint')}
      </Text>
      {wifi.map((net, i) => (
        <Paper withBorder p="xs" key={i}>
          <Group align="flex-end" grow>
            <TextInput
              label={t('policies.ssid')}
              required
              value={net.ssid}
              onChange={(e) => change({ wifi: replaced(wifi, i, { ...net, ssid: e.currentTarget.value }) })}
            />
            <PasswordInput
              label={t('policies.wifiPassword')}
              required
              value={net.password}
              onChange={(e) => change({ wifi: replaced(wifi, i, { ...net, password: e.currentTarget.value }) })}
            />
            <Select
              label={t('policies.wifiSecurity')}
              allowDeselect={false}
              value={net.security ?? 'wpa2'}
              onChange={(security) => change({ wifi: replaced(wifi, i, { ...net, security: security ?? 'wpa2' }) })}
              data={['wpa2', 'wpa3'].map((value) => ({ value, label: value.toUpperCase() }))}
            />
          </Group>
          <Group mt="xs">
            <Checkbox
              label={t('policies.wifiHidden')}
              checked={!!net.hidden}
              onChange={(e) => change({ wifi: replaced(wifi, i, { ...net, hidden: e.currentTarget.checked || undefined }) })}
            />
            <Button size="xs" variant="subtle" color="red" onClick={() => change({ wifi: without(wifi, i) })}>
              {t('policies.remove')}
            </Button>
          </Group>
        </Paper>
      ))}
      <Group>
        <Button size="xs" variant="light" onClick={() => change({ wifi: [...wifi, { ssid: '', password: '' }] })}>
          {t('policies.addWifi')}
        </Button>
      </Group>

      <Divider />
      <Title order={5}>{t('policies.printers')}</Title>
      <Text size="xs" c="dimmed">
        {t('policies.printersHint')}
      </Text>
      {printers.map((printer, i) => (
        <Paper withBorder p="xs" key={i}>
          <Group align="flex-end" grow>
            <TextInput
              label={t('policies.printerName')}
              required
              value={printer.name}
              onChange={(e) => change({ printers: replaced(printers, i, { ...printer, name: e.currentTarget.value }) })}
            />
            <TextInput
              label={t('policies.printerUri')}
              placeholder="ipp://drucker.local/ipp/print"
              required
              value={printer.uri}
              onChange={(e) => change({ printers: replaced(printers, i, { ...printer, uri: e.currentTarget.value }) })}
            />
          </Group>
          <Group mt="xs">
            <Checkbox
              label={t('policies.printerDefault')}
              checked={!!printer.default}
              onChange={(e) =>
                change({
                  // Only one printer can be the default.
                  printers: printers.map((other, j) => ({
                    ...other,
                    default: j === i ? e.currentTarget.checked || undefined : e.currentTarget.checked ? undefined : other.default,
                  })),
                })
              }
            />
            <Button size="xs" variant="subtle" color="red" onClick={() => change({ printers: without(printers, i) })}>
              {t('policies.remove')}
            </Button>
          </Group>
        </Paper>
      ))}
      <Group>
        <Button size="xs" variant="light" onClick={() => change({ printers: [...printers, { name: '', uri: '' }] })}>
          {t('policies.addPrinter')}
        </Button>
      </Group>

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
export function normalized(p: Policy, language: string): Policy {
  const out: Policy = { ...p };
  // Warnings come in the language of whoever sets the rules.
  if (p.screen_time?.length) out.language = language.startsWith('de') ? 'de' : 'en';
  const security = p.security;
  if (security && !security.firewall && !security.disk_encryption && !security.screen_lock) delete out.security;
  if (!p.time_zone) delete out.time_zone;
  return out;
}

// What the members of the group have, for choosing from.
function knownApps(view: PolicyView) {
  const seen = new Map<string, string>();
  for (const device of view.devices) {
    for (const app of device.apps ?? []) seen.set(app.id, app.name);
  }
  return [...seen].map(([value, label]) => ({ value, label })).sort((a, b) => a.label.localeCompare(b.label));
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
              <SearchScopeContext.Provider value={{ group: groupId }}>
                <KnownNamesContext.Provider
                  value={knownNames(devices.filter((d) => data.devices.some((state) => state.id === d.id)))}
                >
                  <PolicyForm initial={data.policy ?? {}} known={knownApps(data)} onSave={save} onClose={() => setEditing(false)} />
                </KnownNamesContext.Provider>
              </SearchScopeContext.Provider>
            </Modal>
          </Stack>
        )}
      </Loaded>
    </>
  );
}
