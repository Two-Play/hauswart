import {
  Badge,
  Button,
  Card,
  Code,
  CopyButton,
  Group,
  Modal,
  Progress,
  SimpleGrid,
  Stack,
  Text,
  Title,
} from '@mantine/core';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api, useResource, type Device, type User } from '../api';
import { useNavigation } from '../navigation';
import { formatBytes, Loaded, showError } from '../ui';
import { DeviceInsight, InsightBadges } from './DeviceInsight';

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
  if (device.suspended) return <Badge color="orange" variant="light">{t('devices.suspended')}</Badge>;
  const online = Date.now() / 1000 - device.last_seen < ONLINE_SECONDS;
  return (
    <Badge color={online ? 'teal' : 'gray'} variant="light">
      {t(online ? 'devices.online' : 'devices.offline')}
    </Badge>
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
  const navigation = useNavigation();
  const [insightDevice, setInsightDevice] = useState<string>();
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

  async function suspend(device: Device, on: boolean) {
    try {
      await api('POST', `/api/devices/${device.id}/${on ? 'suspend' : 'resume'}`);
      reload();
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
                      <Group gap={4} wrap="nowrap">
                        {d.report?.access && (
                          <Badge color="red" variant="light">
                            {t(`devices.access_${d.report.access.mode}`)}
                          </Badge>
                        )}
                        {d.report?.protected && (
                          <Badge color="grape" variant="light">
                            {t('devices.protected')}
                          </Badge>
                        )}
                        <DeviceState device={d} />
                      </Group>
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
                        {isAdmin && <InsightBadges device={d} />}
                      </>
                    )}
                    {isAdmin && !d.revoked && (
                      <Group gap="xs" mt="xs">
                        <Button size="xs" onClick={() => navigation.open('actions', d.id)}>
                          {t('devices.action')}
                        </Button>
                        <Button size="xs" variant="default" onClick={() => setInsightDevice(d.id)}>
                          {t('insight.open')}
                        </Button>
                        <Button size="xs" variant="subtle" color="orange" onClick={() => suspend(d, !d.suspended)}>
                          {t(d.suspended ? 'devices.resume' : 'devices.suspend')}
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

      {data?.some((d) => d.id === insightDevice) && (
        <DeviceInsight
          device={data.find((d) => d.id === insightDevice)!}
          onClose={() => setInsightDevice(undefined)}
        />
      )}
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
