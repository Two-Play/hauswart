import { Alert, Badge, Button, Code, Group, Stack, Table, Text } from '@mantine/core';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api, useResource, type Device } from '../api';
import { formatTime, Loaded, showError } from '../ui';

interface BootState {
  secure_boot: boolean;
  secure_boot_keys: string;
  revocations: string;
  firmware: string;
  bootloaders?: string[];
  command_line: string;
}

interface BootChange {
  kind: string;
  alarm: boolean;
  at: string;
}

interface BootStatus {
  registered: boolean;
  ek?: string;
  baseline?: BootState;
  current?: BootState;
  changes: BootChange[];
  last_at?: string;
  other_tpm?: string;
}

const short = (digest?: string) => (digest ? digest.slice(0, 12) : '–');
const seconds = (date: string) => Math.floor(new Date(date).getTime() / 1000);

/** What the TPM of a device proved about its boot, and what differs from the
 * boot an admin accepted. */
export function BootTab({ device }: { device: Device }) {
  const { t } = useTranslation();
  const { data, error, reload } = useResource<BootStatus>(`/api/devices/${device.id}/boot`, 60_000);
  const [busy, setBusy] = useState(false);

  async function accept() {
    setBusy(true);
    try {
      await api('POST', `/api/devices/${device.id}/boot/accept`);
      reload();
    } catch (err) {
      showError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Loaded data={data} error={error}>
      {(status) => {
        if (!status.registered) {
          return (
            <Text size="sm" c="dimmed">
              {t('boot.none')}
            </Text>
          );
        }
        const rows: [string, (s?: BootState) => string][] = [
          [t('boot.secureBoot'), (s) => (s ? t(s.secure_boot ? 'boot.on' : 'boot.off') : '–')],
          [t('boot.keys'), (s) => short(s?.secure_boot_keys)],
          [t('boot.revocations'), (s) => short(s?.revocations)],
          [t('boot.firmware'), (s) => short(s?.firmware)],
          [t('boot.bootloaders'), (s) => (s?.bootloaders ?? []).map(short).join(' → ') || '–'],
          [t('boot.commandLine'), (s) => s?.command_line || '–'],
        ];
        return (
          <Stack>
            {status.other_tpm && <Alert color="red">{t('boot.otherTPM')}</Alert>}
            {status.changes.length > 0 && (
              <Alert color={status.changes.some((c) => c.alarm) ? 'red' : 'yellow'} title={t('boot.changed')}>
                <Stack gap={4}>
                  {status.changes.map((change) => (
                    <Group key={change.kind} gap="xs">
                      <Badge color={change.alarm ? 'red' : 'yellow'} variant="light">
                        {t(change.alarm ? 'boot.alarm' : 'boot.hint')}
                      </Badge>
                      <Text size="sm">
                        {t(`boot.kinds.${change.kind}`, { defaultValue: change.kind })} · {formatTime(seconds(change.at))}
                      </Text>
                    </Group>
                  ))}
                  <Text size="sm">{t('boot.acceptHint')}</Text>
                  <Group>
                    <Button size="xs" loading={busy} onClick={accept}>
                      {t(status.other_tpm ? 'boot.acceptTPM' : 'boot.accept')}
                    </Button>
                  </Group>
                </Stack>
              </Alert>
            )}
            {!status.current?.secure_boot && status.current && <Alert color="gray">{t('boot.noSecureBoot')}</Alert>}
            <Text size="sm" c="dimmed">
              {status.last_at ? t('boot.lastAt', { time: formatTime(seconds(status.last_at)) }) : t('boot.waiting')}
              {' · '}
              {t('boot.tpm', { ek: short(status.ek) })}
            </Text>
            <Table>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th />
                  <Table.Th>{t('boot.accepted')}</Table.Th>
                  <Table.Th>{t('boot.current')}</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {rows.map(([label, value]) => (
                  <Table.Tr key={label}>
                    <Table.Td>{label}</Table.Td>
                    <Table.Td>
                      <Code>{value(status.baseline)}</Code>
                    </Table.Td>
                    <Table.Td>
                      <Code color={value(status.baseline) !== value(status.current) ? 'yellow' : undefined}>
                        {value(status.current)}
                      </Code>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Stack>
        );
      }}
    </Loaded>
  );
}
