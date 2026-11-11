import { Alert, Badge, Button, Group, Paper, Stack, Switch, Table, Text, Title } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api, useResource } from '../api';
import { taskKey } from '../tasks';
import { ExpandableText, Loaded, showError } from '../ui';

interface PasskeyTypes {
  types: string[];
  chosen: boolean;
  capable: string[];
  devices: { applied: number; waiting: number; total: number };
}

// Actions that always need hauswart-admin, with the reason, for the list below
// the switches. They are never within reach of a passkey.
const SIGNATURE_ONLY = ['sudo.grant', 'user.passwd', 'file.put', 'ca.install', 'user.create', 'group.add', 'keys.set', 'passkeys.types'];

/** What a passkey may approve: one switch per action, which reaches the
 * devices only with a signature. */
export function PasskeyTypesPanel() {
  const { t } = useTranslation();
  const { data, error, reload } = useResource<PasskeyTypes>('/api/passkey-types', 30_000);
  const [chosen, setChosen] = useState<string[]>();
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (data) setChosen(data.types);
  }, [data]);

  const changed = data && chosen && (data.types.length !== chosen.length || data.types.some((x) => !chosen.includes(x)));

  async function save() {
    setSaving(true);
    try {
      await api('PUT', '/api/passkey-types', { types: chosen });
      notifications.show({ color: 'green', message: t('passkeyTypes.saved') });
      reload();
    } catch (err) {
      showError(err);
    } finally {
      setSaving(false);
    }
  }

  return (
    <Paper withBorder p="md">
      <Loaded data={data} error={error}>
        {(view) => (
          <Stack>
            <Title order={4}>{t('passkeyTypes.title')}</Title>
            <ExpandableText size="sm" c="dimmed">
              {t('passkeyTypes.hint')}
            </ExpandableText>
            {view.devices.total > 0 && (
              <Group gap="xs">
                <Badge color="green" variant="light">
                  {t('passkeyTypes.applied', { count: view.devices.applied, total: view.devices.total })}
                </Badge>
                {view.devices.waiting > 0 && (
                  <Badge color="grape" variant="light">
                    {t('passkeyTypes.waiting', { count: view.devices.waiting })}
                  </Badge>
                )}
              </Group>
            )}
            {!view.chosen && <Alert color="gray">{t('passkeyTypes.notChosen')}</Alert>}
            <Table>
              <Table.Tbody>
                {view.capable.map((type) => (
                  <Table.Tr key={type}>
                    <Table.Td>
                      <Text size="sm" fw={500}>
                        {t(taskKey(type), { defaultValue: type })}
                      </Text>
                      <Text size="xs" c="dimmed">
                        {t(`passkeyTypes.risk.${type.replace('.', '_')}`, { defaultValue: '' })}
                      </Text>
                    </Table.Td>
                    <Table.Td w={220}>
                      <Switch
                        label={t(chosen?.includes(type) ? 'passkeyTypes.passkey' : 'passkeyTypes.signature')}
                        checked={chosen?.includes(type) ?? false}
                        onChange={(e) => {
                          const on = e.currentTarget.checked;
                          setChosen((list) => (on ? [...(list ?? []), type] : (list ?? []).filter((x) => x !== type)));
                        }}
                      />
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
            <Text size="sm" c="dimmed">
              {t('passkeyTypes.always', {
                list: SIGNATURE_ONLY.map((type) => t(taskKey(type), { defaultValue: type })).join(', '),
              })}
            </Text>
            <Group>
              <Button loading={saving} disabled={!changed && view.chosen} onClick={save}>
                {t('passkeyTypes.save')}
              </Button>
            </Group>
          </Stack>
        )}
      </Loaded>
    </Paper>
  );
}
