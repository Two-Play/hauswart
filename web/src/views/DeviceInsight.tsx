import {
  Alert,
  Badge,
  Button,
  Code,
  Group,
  List,
  Modal,
  ScrollArea,
  SegmentedControl,
  SimpleGrid,
  Stack,
  Tabs,
  Text,
} from '@mantine/core';
import type { TFunction } from 'i18next';
import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api, useResource, type Device, type UpdateStatus, type Warning } from '../api';
import { DataTable, formatBytes, formatTime, Loaded, showError } from '../ui';
import { HistoryChart, type Point } from './HistoryChart';

const REFRESH_MS = 60_000;
const LOG_POLL_MS = 1_500;
const LOG_LINES = 200;
const HOUR = 3600;

interface Sample {
  ts: number;
  load1: number;
  mem_used: number;
  mem_total: number;
  disk_used: number;
  disk_total: number;
}

interface LogEntry {
  time: string;
  priority: number;
  source: string;
  message: string;
}

interface LogsResult {
  available: boolean;
  agent: LogEntry[];
  system: LogEntry[];
  withheld: number;
}

interface LogTask {
  status: string;
  output: string;
  data?: LogsResult;
}

function seconds(date: string): number {
  return Math.floor(new Date(date).getTime() / 1000);
}

function useWarningText() {
  const { t } = useTranslation();
  return (warning: Warning) => {
    if (warning.code === 'disk_full') return t('insight.diskFull', { percent: warning.value });
    return warning.value < 0
      ? t('insight.certExpired')
      : t('insight.certExpiring', { count: warning.value });
  };
}

function updatesLabel(updates: UpdateStatus, t: TFunction) {
  return updates.pending > 0 ? t('insight.pending', { count: updates.pending }) : t('insight.upToDate');
}

/** What needs attention, for the device card. */
export function InsightBadges({ device }: { device: Device }) {
  const { t } = useTranslation();
  const warningText = useWarningText();
  const updates = device.report?.updates;
  const warnings = device.warnings ?? [];
  if (!updates && warnings.length === 0) return null;
  return (
    <Group gap={4}>
      {warnings.map((warning) => (
        <Badge key={warning.code} color={warning.code === 'disk_full' ? 'red' : 'yellow'} variant="light">
          {warningText(warning)}
        </Badge>
      ))}
      {updates?.checked_at && (
        <Badge color={updates.pending > 0 ? 'blue' : 'gray'} variant="light">
          {updatesLabel(updates, t)}
        </Badge>
      )}
      {updates?.reboot === 'required' && (
        <Badge color="yellow" variant="light">
          {t('insight.rebootRequired')}
        </Badge>
      )}
    </Group>
  );
}

function percent(used: number, total: number): number {
  return total ? (used / total) * 100 : 0;
}

function HistoryTab({ device }: { device: Device }) {
  const { t } = useTranslation();
  const [hours, setHours] = useState('24');
  const { data, error } = useResource<Sample[]>(`/api/devices/${device.id}/history?hours=${hours}`, REFRESH_MS);
  const warningText = useWarningText();
  const report = device.report;

  const until = Math.floor(Date.now() / 1000);
  const since = until - Number(hours) * HOUR;
  const step = Number(hours) > 24 ? 1800 : 300;
  const shared = { step, since, until };
  const percentText = (value: number) => `${Math.round(value)} %`;
  const series = (pick: (sample: Sample) => number) => (samples: Sample[]): Point[] =>
    samples.map((sample) => ({ ts: sample.ts, value: pick(sample) }));

  return (
    <Stack>
      {device.warnings?.map((warning) => (
        <Alert key={warning.code} color={warning.code === 'disk_full' ? 'red' : 'yellow'}>
          {warningText(warning)}
          {warning.code === 'cert_expiring' && `. ${t('insight.certHint')}`}
        </Alert>
      ))}
      <Group justify="space-between">
        <Text size="sm" c="dimmed">
          {report?.cert_expires
            ? t('insight.certValid', { date: formatTime(seconds(report.cert_expires)) })
            : t('insight.certUnknown')}
          {' · '}
          {t('insight.diskNow', { used: formatBytes(report?.disk_used), total: formatBytes(report?.disk_total) })}
        </Text>
        <SegmentedControl
          size="xs"
          value={hours}
          onChange={setHours}
          data={[
            { value: '24', label: t('insight.range24h') },
            { value: '168', label: t('insight.range7d') },
          ]}
        />
      </Group>
      <Loaded data={data} error={error}>
        {(samples) => (
          <SimpleGrid cols={1}>
            <HistoryChart
              title={t('devices.disk')}
              points={series((s) => percent(s.disk_used, s.disk_total))(samples)}
              max={100}
              limit={90}
              format={percentText}
              {...shared}
            />
            <HistoryChart
              title={t('devices.memory')}
              points={series((s) => percent(s.mem_used, s.mem_total))(samples)}
              max={100}
              format={percentText}
              {...shared}
            />
            <HistoryChart
              title={t('insight.loadTitle')}
              points={series((s) => s.load1)(samples)}
              format={(value) => value.toFixed(2)}
              {...shared}
            />
          </SimpleGrid>
        )}
      </Loaded>
    </Stack>
  );
}

function UpdatesTab({ device }: { device: Device }) {
  const { t } = useTranslation();
  const updates = device.report?.updates;
  if (!updates) return <Text c="dimmed">{t('insight.notChecked')}</Text>;
  const shown = updates.packages?.length ?? 0;
  return (
    <Stack>
      {updates.error && (
        <Alert color="red" title={t('insight.checkFailed')}>
          <Text size="sm" style={{ wordBreak: 'break-word' }}>
            {updates.error}
          </Text>
        </Alert>
      )}
      <Group gap="xs">
        {updates.checked_at && (
          <Badge color={updates.pending > 0 ? 'blue' : 'teal'} variant="light">
            {updatesLabel(updates, t)}
          </Badge>
        )}
        <Badge
          color={{ required: 'yellow', not_required: 'teal', unknown: 'gray' }[updates.reboot]}
          variant="light"
        >
          {t(`insight.reboot_${updates.reboot}`)}
        </Badge>
      </Group>
      <Text size="sm" c="dimmed">
        {updates.checked_at
          ? t('insight.checkedAt', { date: formatTime(seconds(updates.checked_at)) })
          : t('insight.notChecked')}
      </Text>
      {shown > 0 && (
        <ScrollArea.Autosize mah={320}>
          <List size="sm" spacing={2}>
            {updates.packages?.map((name) => (
              <List.Item key={name}>{name}</List.Item>
            ))}
          </List>
        </ScrollArea.Autosize>
      )}
      {updates.pending > shown && shown > 0 && (
        <Text size="sm" c="dimmed">
          {t('insight.morePackages', { count: updates.pending - shown })}
        </Text>
      )}
    </Stack>
  );
}

function AccountsTab({ device }: { device: Device }) {
  const { t } = useTranslation();
  return (
    <Stack>
      <Text size="sm" c="dimmed">
        {t('insight.accountsHint')}
      </Text>
      <DataTable
        headers={[t('insight.account'), t('insight.groups'), t('insight.sudo'), t('insight.grant')]}
        empty={t('insight.noAccounts')}
        rows={(device.report?.accounts ?? []).map((account) => ({
          key: account.name,
          cells: [
            <>
              <Text size="sm" fw={500}>
                {account.name}
              </Text>
              <Text size="xs" c="dimmed">
                {t('insight.uid', { uid: account.uid })}
              </Text>
            </>,
            <Group gap={4}>
              {account.groups.map((group) => (
                <Badge
                  key={group}
                  variant="light"
                  color={account.privileged?.includes(group) ? 'red' : 'gray'}
                  tt="none"
                >
                  {group}
                </Badge>
              ))}
            </Group>,
            account.sudo_unknown ? (
              <Text size="sm" c="dimmed">
                {t('insight.sudoUnknown')}
              </Text>
            ) : account.sudo?.length ? (
              <Stack gap={2}>
                {account.sudo.map((rule) => (
                  <Code key={rule}>{rule}</Code>
                ))}
              </Stack>
            ) : (
              <Text size="sm" c="dimmed">
                {t('insight.noSudo')}
              </Text>
            ),
            account.grant_expires ? (
              <Text size="sm">{t('insight.grantUntil', { date: formatTime(seconds(account.grant_expires)) })}</Text>
            ) : (
              '–'
            ),
          ],
        }))}
      />
    </Stack>
  );
}

const PRIORITY_COLOR = ['red', 'red', 'red', 'red', 'yellow', 'gray', 'gray', 'gray'];

function LogList({ title, entries }: { title: string; entries: LogEntry[] }) {
  const { t } = useTranslation();
  return (
    <div>
      <Text size="sm" fw={500} mb={4}>
        {title}
      </Text>
      {entries.length === 0 ? (
        <Text size="sm" c="dimmed">
          {t('insight.noEntries')}
        </Text>
      ) : (
        <ScrollArea.Autosize mah={280} type="auto">
          <Stack gap={4}>
            {[...entries].reverse().map((entry, i) => (
              <div key={i}>
                <Group gap={6} wrap="nowrap">
                  <Badge size="xs" variant="light" color={PRIORITY_COLOR[entry.priority] ?? 'gray'}>
                    {t(`insight.priority${entry.priority}`, { defaultValue: String(entry.priority) })}
                  </Badge>
                  <Text size="xs" c="dimmed" truncate>
                    {formatTime(seconds(entry.time))} · {entry.source}
                  </Text>
                </Group>
                <Text size="xs" ff="monospace" style={{ wordBreak: 'break-word' }}>
                  {entry.message}
                </Text>
              </div>
            ))}
          </Stack>
        </ScrollArea.Autosize>
      )}
    </div>
  );
}

function LogsTab({ device }: { device: Device }) {
  const { t } = useTranslation();
  const [task, setTask] = useState<LogTask>();
  const [busy, setBusy] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);

  useEffect(() => () => clearTimeout(timer.current), []);

  async function poll(id: string) {
    try {
      const next = await api<LogTask>('GET', `/api/tasks/${id}/data`);
      setTask(next);
      if (next.status === 'done' || next.status === 'failed') {
        setBusy(false);
        return;
      }
      timer.current = setTimeout(() => poll(id), LOG_POLL_MS);
    } catch (err) {
      setBusy(false);
      showError(err);
    }
  }

  async function fetchLogs() {
    setBusy(true);
    setTask(undefined);
    try {
      const out = await api<{ id: string }>('POST', `/api/devices/${device.id}/tasks`, {
        type: 'logs.fetch',
        payload: { lines: LOG_LINES },
      });
      await poll(out.id);
    } catch (err) {
      setBusy(false);
      showError(err);
    }
  }

  const logs = task?.data;
  return (
    <Stack>
      <Text size="sm" c="dimmed">
        {t('insight.logsHint')}
      </Text>
      <Group>
        <Button size="xs" onClick={fetchLogs} loading={busy}>
          {t('insight.fetchLogs')}
        </Button>
        {busy && (
          <Text size="sm" c="dimmed">
            {t('insight.waitingForDevice')}
          </Text>
        )}
      </Group>
      {task?.status === 'failed' && (
        <Alert color="red" title={t('common.failed')}>
          <Text size="sm" style={{ wordBreak: 'break-word' }}>
            {task.output}
          </Text>
        </Alert>
      )}
      {logs && !logs.available && <Text c="dimmed">{t('insight.noJournal')}</Text>}
      {logs?.available && (
        <>
          {logs.withheld > 0 && (
            <Text size="sm" c="dimmed">
              {t('insight.withheld', { count: logs.withheld })}
            </Text>
          )}
          <LogList title={t('insight.logsSystem')} entries={logs.system} />
          <LogList title={t('insight.logsAgent')} entries={logs.agent} />
        </>
      )}
    </Stack>
  );
}

export function DeviceInsight({ device, onClose }: { device: Device; onClose: () => void }) {
  const { t } = useTranslation();
  return (
    <Modal opened onClose={onClose} size="xl" title={t('insight.title', { name: device.hostname })}>
      <Tabs defaultValue="history" keepMounted={false}>
        <Tabs.List mb="md">
          <Tabs.Tab value="history">{t('insight.tabHistory')}</Tabs.Tab>
          <Tabs.Tab value="updates">{t('insight.tabUpdates')}</Tabs.Tab>
          <Tabs.Tab value="accounts">{t('insight.tabAccounts')}</Tabs.Tab>
          <Tabs.Tab value="logs">{t('insight.tabLogs')}</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="history">
          <HistoryTab device={device} />
        </Tabs.Panel>
        <Tabs.Panel value="updates">
          <UpdatesTab device={device} />
        </Tabs.Panel>
        <Tabs.Panel value="accounts">
          <AccountsTab device={device} />
        </Tabs.Panel>
        <Tabs.Panel value="logs">
          <LogsTab device={device} />
        </Tabs.Panel>
      </Tabs>
    </Modal>
  );
}
