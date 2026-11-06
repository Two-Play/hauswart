import {
  Alert,
  Anchor,
  Badge,
  Button,
  Drawer,
  Group,
  Paper,
  Select,
  SimpleGrid,
  Stack,
  Tabs,
  Text,
  Textarea,
  TextInput,
  Title,
} from '@mantine/core';
import { useDebouncedValue } from '@mantine/hooks';
import { IconDownload } from '@tabler/icons-react';
import { useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { api, useResource, type Asset, type InventoryDevice, type SoftwareEntry } from '../api';
import { DataTable, formatBytes, formatTime, Loaded, showError } from '../ui';
import { useWarningText } from './DeviceInsight';

const REFRESH_MS = 60_000;
const MIN_QUERY = 2;
const SEARCH_DELAY_MS = 300;
// A device can have thousands of packages, and nobody reads them all at once.
const MAX_SHOWN_PACKAGES = 300;

function CheckBadge({ state }: { state?: string }) {
  const { t } = useTranslation();
  const color = state === 'on' ? 'green' : state === 'off' ? 'red' : 'gray';
  return (
    <Badge color={color} variant="light">
      {t(`inventory.check.${state === 'on' || state === 'off' ? state : 'unknown'}`)}
    </Badge>
  );
}

function matches(device: InventoryDevice, query: string) {
  const hardware = device.inventory?.hardware;
  const { tag, person, location } = device.asset;
  return [device.hostname, tag, person, location, hardware?.vendor, hardware?.model, hardware?.serial].some((value) =>
    value?.toLowerCase().includes(query),
  );
}

const FILTERS: Record<string, (device: InventoryDevice) => boolean> = {
  all: () => true,
  unencrypted: (d) => d.inventory?.security.disk_encryption === 'off',
  firewall: (d) => d.inventory?.security.firewall === 'off',
  warranty: (d) => !!d.warnings?.some((w) => w.code === 'warranty_ending'),
  updates: (d) => (d.updates?.pending ?? 0) > 0,
  revoked: (d) => d.revoked,
};

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <Text size="xs" c="dimmed">
        {label}
      </Text>
      <Text size="sm" component="div" style={{ overflowWrap: 'anywhere' }}>
        {children || '–'}
      </Text>
    </div>
  );
}

function AssetForm({ device, onSaved }: { device: InventoryDevice; onSaved: () => void }) {
  const { t } = useTranslation();
  const [asset, setAsset] = useState<Asset>(device.asset);
  const [saving, setSaving] = useState(false);
  const field = (key: keyof Asset, type = 'text') => (
    <TextInput
      type={type}
      label={t(`inventory.asset.${key}`)}
      value={asset[key] ?? ''}
      onChange={(e) => setAsset({ ...asset, [key]: e.currentTarget.value })}
    />
  );
  const save = async () => {
    setSaving(true);
    try {
      await api('PUT', `/api/inventory/${device.id}/asset`, asset);
      onSaved();
    } catch (err) {
      showError(err);
    } finally {
      setSaving(false);
    }
  };
  return (
    <Stack gap="xs">
      <SimpleGrid cols={{ base: 1, xs: 2 }}>
        {field('tag')}
        {field('person')}
        {field('location')}
        {field('purchased', 'date')}
        {field('warranty_until', 'date')}
      </SimpleGrid>
      <Textarea
        label={t('inventory.asset.note')}
        autosize
        minRows={2}
        value={asset.note ?? ''}
        onChange={(e) => setAsset({ ...asset, note: e.currentTarget.value })}
      />
      <Group justify="flex-end">
        <Button loading={saving} onClick={save}>
          {t('inventory.save')}
        </Button>
      </Group>
    </Stack>
  );
}

function Packages({ device }: { device: InventoryDevice }) {
  const { t } = useTranslation();
  const [query, setQuery] = useState('');
  const wanted = query.trim().toLowerCase();
  const found = (device.packages ?? []).filter((p) => p.name.toLowerCase().includes(wanted));
  return (
    <Stack gap="xs">
      {device.inventory?.truncated && <Alert color="yellow">{t('inventory.truncated')}</Alert>}
      <TextInput
        aria-label={t('inventory.searchPackages')}
        placeholder={t('inventory.searchPackages')}
        value={query}
        onChange={(e) => setQuery(e.currentTarget.value)}
      />
      <DataTable
        empty={t('inventory.noPackages')}
        headers={[t('inventory.package'), t('inventory.version'), t('inventory.kind')]}
        rows={found.slice(0, MAX_SHOWN_PACKAGES).map((p) => ({
          key: `${p.kind} ${p.name} ${p.version}`,
          cells: [p.name, p.version, t(`inventory.kinds.${p.kind}`)],
        }))}
      />
      {found.length > MAX_SHOWN_PACKAGES && (
        <Text size="sm" c="dimmed">
          {t('inventory.morePackages', { shown: MAX_SHOWN_PACKAGES, count: found.length })}
        </Text>
      )}
    </Stack>
  );
}

function Details({ id, onSaved }: { id: string; onSaved: () => void }) {
  const { t } = useTranslation();
  const { data, error, reload } = useResource<InventoryDevice>(`/api/inventory/${id}`);
  return (
    <Loaded data={data} error={error}>
      {(device) => {
        const inventory = device.inventory;
        const hardware = inventory?.hardware;
        return (
          <Stack>
            {device.revoked && <Alert color="gray">{t('inventory.revokedHint')}</Alert>}
            <AssetForm
              key={device.id}
              device={device}
              onSaved={() => {
                reload();
                onSaved();
              }}
            />
            <Text size="sm" c="dimmed">
              {inventory
                ? t('inventory.reportedAt', { time: formatTime(inventory.updated_at) })
                : t('inventory.reported')}
            </Text>
            {!inventory && <Text c="dimmed">{t('inventory.none')}</Text>}
            {inventory && (
              <Tabs defaultValue="hardware">
                <Tabs.List>
                  <Tabs.Tab value="hardware">{t('inventory.tabs.hardware')}</Tabs.Tab>
                  <Tabs.Tab value="software">{t('inventory.tabs.software', { count: inventory.package_count })}</Tabs.Tab>
                  <Tabs.Tab value="network">{t('inventory.tabs.network')}</Tabs.Tab>
                  <Tabs.Tab value="security">{t('inventory.tabs.security')}</Tabs.Tab>
                </Tabs.List>
                <Tabs.Panel value="hardware" pt="md">
                  <SimpleGrid cols={{ base: 1, xs: 2 }}>
                    <Fact label={t('inventory.vendor')}>{hardware?.vendor}</Fact>
                    <Fact label={t('inventory.model')}>{hardware?.model}</Fact>
                    <Fact label={t('inventory.serial')}>{hardware?.serial}</Fact>
                    <Fact label={t('inventory.bios')}>{hardware?.bios}</Fact>
                    <Fact label={t('inventory.cpu')}>
                      {hardware?.cpu}
                      {device.cpus ? ` (${device.cpus})` : ''}
                    </Fact>
                    <Fact label={t('inventory.memory')}>{device.mem_total ? formatBytes(device.mem_total) : ''}</Fact>
                    <Fact label={t('inventory.system')}>{device.distro}</Fact>
                    <Fact label={t('inventory.kernel')}>{device.kernel}</Fact>
                    <Fact label={t('inventory.agent')}>{device.agent_version}</Fact>
                    <Fact label={t('inventory.disks')}>
                      {inventory.disks?.map((d) => (
                        <div key={d.name}>
                          {d.name} {d.model} ({formatBytes(d.size)})
                        </div>
                      ))}
                    </Fact>
                  </SimpleGrid>
                </Tabs.Panel>
                <Tabs.Panel value="software" pt="md">
                  <Packages device={device} />
                </Tabs.Panel>
                <Tabs.Panel value="network" pt="md">
                  <DataTable
                    empty={t('inventory.noNetwork')}
                    headers={[t('inventory.card'), t('inventory.mac'), t('inventory.addresses')]}
                    rows={(inventory.network ?? []).map((n) => ({
                      key: n.name,
                      cells: [n.name, n.mac, n.addresses?.join(', ')],
                    }))}
                  />
                </Tabs.Panel>
                <Tabs.Panel value="security" pt="md">
                  <SimpleGrid cols={{ base: 1, xs: 2 }}>
                    <Fact label={t('inventory.encryption')}>
                      <CheckBadge state={inventory.security.disk_encryption} />
                    </Fact>
                    <Fact label={t('inventory.screenLock')}>
                      <CheckBadge state={inventory.security.screen_lock} />
                    </Fact>
                    <Fact label={t('inventory.firewall')}>
                      <CheckBadge state={inventory.security.firewall} />
                    </Fact>
                    <Fact label={t('inventory.updates')}>
                      {device.updates?.checked_at ? t('inventory.pending', { count: device.updates.pending }) : ''}
                    </Fact>
                  </SimpleGrid>
                </Tabs.Panel>
              </Tabs>
            )}
          </Stack>
        );
      }}
    </Loaded>
  );
}

function Devices() {
  const { t } = useTranslation();
  const warningText = useWarningText();
  const { data, error, reload } = useResource<InventoryDevice[]>('/api/inventory', REFRESH_MS);
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState('all');
  const [open, setOpen] = useState<InventoryDevice>();
  return (
    <Stack>
      <Group grow preventGrowOverflow={false} align="flex-end">
        <TextInput
          label={t('inventory.search')}
          placeholder={t('inventory.searchHint')}
          value={query}
          onChange={(e) => setQuery(e.currentTarget.value)}
        />
        <Select
          label={t('inventory.filter')}
          allowDeselect={false}
          value={filter}
          onChange={(value) => setFilter(value ?? 'all')}
          data={Object.keys(FILTERS).map((value) => ({ value, label: t(`inventory.filters.${value}`) }))}
        />
      </Group>
      <Loaded data={data} error={error}>
        {(devices) => {
          const wanted = query.trim().toLowerCase();
          const shown = devices.filter((d) => FILTERS[filter](d) && (!wanted || matches(d, wanted)));
          return (
            <DataTable
              empty={t('inventory.empty')}
              headers={[
                t('inventory.device'),
                t('inventory.asset.person'),
                t('inventory.asset.location'),
                t('inventory.model'),
                t('inventory.serial'),
                t('inventory.encryption'),
                t('inventory.updates'),
              ]}
              rows={shown.map((d) => ({
                key: d.id,
                cells: [
                  <Stack gap={2} key="name" align="flex-start">
                    <Anchor component="button" type="button" onClick={() => setOpen(d)}>
                      {d.hostname || d.id}
                    </Anchor>
                    {d.revoked && (
                      <Badge color="gray" variant="light">
                        {t('inventory.revoked')}
                      </Badge>
                    )}
                    {d.warnings
                      ?.filter((w) => w.code === 'warranty_ending')
                      .map((w) => (
                        <Badge key={w.code} color="yellow" variant="light">
                          {warningText(w)}
                        </Badge>
                      ))}
                  </Stack>,
                  d.asset.person,
                  d.asset.location,
                  [d.inventory?.hardware.vendor, d.inventory?.hardware.model].filter(Boolean).join(' '),
                  d.inventory?.hardware.serial,
                  d.inventory && <CheckBadge key="crypt" state={d.inventory.security.disk_encryption} />,
                  d.updates?.checked_at ? t('inventory.pending', { count: d.updates.pending }) : '',
                ],
              }))}
            />
          );
        }}
      </Loaded>
      <Drawer
        opened={!!open}
        onClose={() => setOpen(undefined)}
        position="right"
        size="xl"
        title={open?.hostname || open?.id}
      >
        {open && <Details key={open.id} id={open.id} onSaved={reload} />}
      </Drawer>
    </Stack>
  );
}

function Software() {
  const { t } = useTranslation();
  const [query, setQuery] = useState('');
  const [wanted] = useDebouncedValue(query.trim(), SEARCH_DELAY_MS);
  return (
    <Stack>
      <TextInput
        label={t('inventory.software')}
        placeholder={t('inventory.softwareHint')}
        value={query}
        onChange={(e) => setQuery(e.currentTarget.value)}
      />
      {wanted.length >= MIN_QUERY && <SoftwareResults key={wanted} query={wanted} />}
    </Stack>
  );
}

function SoftwareResults({ query }: { query: string }) {
  const { t } = useTranslation();
  const { data, error } = useResource<{ entries: SoftwareEntry[]; more: boolean }>(
    `/api/inventory/software?q=${encodeURIComponent(query)}`,
  );
  return (
    <Loaded data={data} error={error}>
      {({ entries, more }) => (
        <>
          <DataTable
            empty={t('inventory.noSoftware')}
            headers={[t('inventory.package'), t('inventory.version'), t('inventory.kind'), t('inventory.devices')]}
            rows={entries.map((e) => ({
              key: `${e.kind} ${e.name} ${e.version}`,
              cells: [e.name, e.version, t(`inventory.kinds.${e.kind}`), e.devices.map((d) => d.hostname || d.id).join(', ')],
            }))}
          />
          {more && (
            <Text size="sm" c="dimmed">
              {t('inventory.moreSoftware')}
            </Text>
          )}
        </>
      )}
    </Loaded>
  );
}

export function InventoryView() {
  const { t } = useTranslation();
  return (
    <Stack>
      <Group justify="space-between">
        <Title order={2}>{t('nav.inventory')}</Title>
        <Button component="a" href="/api/inventory.csv" variant="default" leftSection={<IconDownload size={16} />}>
          {t('inventory.export')}
        </Button>
      </Group>
      <Paper withBorder p="md">
        <Tabs defaultValue="devices" keepMounted={false}>
          <Tabs.List mb="md">
            <Tabs.Tab value="devices">{t('inventory.tabs.devices')}</Tabs.Tab>
            <Tabs.Tab value="software">{t('inventory.software')}</Tabs.Tab>
          </Tabs.List>
          <Tabs.Panel value="devices">
            <Devices />
          </Tabs.Panel>
          <Tabs.Panel value="software">
            <Software />
          </Tabs.Panel>
        </Tabs>
      </Paper>
    </Stack>
  );
}
