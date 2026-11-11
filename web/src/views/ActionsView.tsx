import { Badge, Card, Group, Select, SimpleGrid, Stack, Text, TextInput, ThemeIcon, Title, UnstyledButton } from '@mantine/core';
import { IconSearch } from '@tabler/icons-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useResource, type Device } from '../api';

interface PasskeyTypes {
  types: string[];
  unsigned: string[];
}
import { useNavigation } from '../navigation';
import { ACTION_ICONS, helpKey } from '../actionIcons';
import { ACTION_AREAS, taskKey } from '../tasks';
import { ExpandableText, Loaded } from '../ui';
import { ActionModal } from './ActionForm';

/** matches says whether an action fits what someone typed, in its label, its
 * description or its type. */
export function matches(label: string, type: string, query: string, help = ''): boolean {
  const q = query.trim().toLowerCase();
  return q === '' || label.toLowerCase().includes(q) || type.toLowerCase().includes(q) || help.toLowerCase().includes(q);
}

/** ApprovalBadge says how an action is approved on a protected device. */
function ApprovalBadge({ type, passkeys }: { type: string; passkeys?: PasskeyTypes }) {
  const { t } = useTranslation();
  if (!passkeys) return null;
  if (passkeys.unsigned.includes(type)) {
    return (
      <Badge size="xs" variant="light" color="gray">
        {t('actions.approval.direct')}
      </Badge>
    );
  }
  const passkey = passkeys.types.includes(type);
  return (
    <Badge size="xs" variant="light" color={passkey ? 'teal' : 'grape'}>
      {t(passkey ? 'actions.approval.passkey' : 'actions.approval.signature')}
    </Badge>
  );
}

/** ActionsView offers every action as a tile, grouped by area, for one device. */
export function ActionsView() {
  const { t } = useTranslation();
  const navigation = useNavigation();
  const devices = useResource<Device[]>('/api/devices', 30_000);
  const [deviceId, setDeviceId] = useState<string | null>(navigation.device ?? null);
  const [query, setQuery] = useState('');
  const [type, setType] = useState<string>();
  const passkeys = useResource<PasskeyTypes>('/api/passkey-types');
  const usable = (devices.data ?? []).filter((d) => !d.revoked);
  // With a single device there is nothing to choose.
  const device = usable.find((d) => d.id === deviceId) ?? (usable.length === 1 ? usable[0] : undefined);

  return (
    <Stack>
      <Title order={2}>{t('nav.actions')}</Title>
      <ExpandableText size="sm" c="dimmed">
        {t('actions.pageHint')}
      </ExpandableText>
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
        const shown = area.types.filter((type) => matches(t(taskKey(type)), type, query, t(helpKey(type))));
        if (shown.length === 0) return null;
        return (
          <Stack key={area.key} gap="xs">
            <Title order={4}>{t(`actions.area.${area.key}`)}</Title>
            <SimpleGrid cols={{ base: 1, sm: 2, xl: 3 }}>
              {shown.map((type) => (
                <UnstyledButton key={type} disabled={!device} onClick={() => setType(type)} aria-label={t(taskKey(type))}>
                  <Card
                    withBorder
                    padding="sm"
                    h="100%"
                    style={{ opacity: device ? 1 : 0.5, cursor: device ? 'pointer' : 'default' }}
                  >
                    <Group gap="sm" wrap="nowrap" align="flex-start">
                      <ThemeIcon variant="light" size="lg" radius="md">
                        {(() => {
                          const ActionIcon = ACTION_ICONS[type];
                          return ActionIcon ? <ActionIcon size={20} /> : null;
                        })()}
                      </ThemeIcon>
                      <Stack gap={2}>
                        <Text fw={600} size="sm">
                          {t(taskKey(type))}
                        </Text>
                        <Text size="xs" c="dimmed">
                          {t(helpKey(type))}
                        </Text>
                        <Group gap={6} mt={4}>
                          {device?.report?.protected && <ApprovalBadge type={type} passkeys={passkeys.data} />}
                          <Text size="xs" c="dimmed" ff="monospace">
                            {type}
                          </Text>
                        </Group>
                      </Stack>
                    </Group>
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
