import { Card, Group, Select, SimpleGrid, Stack, Text, TextInput, Title, UnstyledButton } from '@mantine/core';
import { IconSearch } from '@tabler/icons-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useResource, type Device } from '../api';
import { useNavigation } from '../navigation';
import { ACTION_AREAS, taskKey } from '../tasks';
import { Loaded } from '../ui';
import { ActionModal } from './ActionForm';

/** matches says whether an action fits what someone typed, in either language of its label. */
export function matches(label: string, type: string, query: string): boolean {
  const q = query.trim().toLowerCase();
  return q === '' || label.toLowerCase().includes(q) || type.toLowerCase().includes(q);
}

/** ActionsView offers every action as a tile, grouped by area, for one device. */
export function ActionsView() {
  const { t } = useTranslation();
  const navigation = useNavigation();
  const devices = useResource<Device[]>('/api/devices', 30_000);
  const [deviceId, setDeviceId] = useState<string | null>(navigation.device ?? null);
  const [query, setQuery] = useState('');
  const [type, setType] = useState<string>();
  const usable = (devices.data ?? []).filter((d) => !d.revoked);
  // With a single device there is nothing to choose.
  const device = usable.find((d) => d.id === deviceId) ?? (usable.length === 1 ? usable[0] : undefined);

  return (
    <Stack>
      <Title order={2}>{t('nav.actions')}</Title>
      <Text size="sm" c="dimmed">
        {t('actions.pageHint')}
      </Text>
      <Loaded data={devices.data} error={devices.error}>
        {() => (
          <Group align="flex-end" grow>
            <Select
              label={t('actions.device')}
              placeholder={t('actions.pickDevice')}
              searchable
              value={device?.id ?? null}
              onChange={setDeviceId}
              data={usable.map((d) => ({ value: d.id, label: d.hostname }))}
            />
            <TextInput
              label={t('actions.search')}
              leftSection={<IconSearch size={16} />}
              value={query}
              onChange={(e) => setQuery(e.currentTarget.value)}
            />
          </Group>
        )}
      </Loaded>
      {ACTION_AREAS.map((area) => {
        const shown = area.types.filter((type) => matches(t(taskKey(type)), type, query));
        if (shown.length === 0) return null;
        return (
          <Stack key={area.key} gap="xs">
            <Title order={4}>{t(`actions.area.${area.key}`)}</Title>
            <SimpleGrid cols={{ base: 1, xs: 2, md: 4 }}>
              {shown.map((type) => (
                <UnstyledButton key={type} disabled={!device} onClick={() => setType(type)} aria-label={t(taskKey(type))}>
                  <Card withBorder padding="sm" style={{ opacity: device ? 1 : 0.5, cursor: device ? 'pointer' : 'default' }}>
                    <Text fw={600} size="sm">
                      {t(taskKey(type))}
                    </Text>
                    <Text size="xs" c="dimmed">
                      {type}
                    </Text>
                  </Card>
                </UnstyledButton>
              ))}
            </SimpleGrid>
          </Stack>
        );
      })}
      {device && type && <ActionModal device={device} type={type} onClose={() => setType(undefined)} />}
    </Stack>
  );
}
