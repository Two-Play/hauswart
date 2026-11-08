import { Button, Card, Group, Stack, Text, Title } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api, useResource, type Device } from '../api';
import { useNavigation } from '../navigation';
import type { DeviceGroup } from './GroupsView';
import { showError, Loaded } from '../ui';
import { knownNames, KnownNamesContext } from './NameInput';
import { normalized, ScreenTimeRules, type Policy, type PolicyView, type ScreenRule } from './PolicyPanel';

/** GroupScreenTime edits the screen time in the policy of one group. */
function GroupScreenTime({ group, devices }: { group: DeviceGroup; devices: Device[] }) {
  const { t, i18n } = useTranslation();
  const view = useResource<PolicyView>(`/api/groups/${group.id}/policy`);
  const [rules, setRules] = useState<ScreenRule[]>();
  useEffect(() => setRules(view.data?.policy?.screen_time ?? []), [view.data]);
  const members = devices.filter((d) => group.devices?.includes(d.id));

  async function save() {
    const policy: Policy = { ...(view.data?.policy ?? {}), screen_time: rules };
    if (!policy.time_zone && rules && rules.length > 0) {
      policy.time_zone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    }
    try {
      await api('PUT', `/api/groups/${group.id}/policy`, normalized(policy, i18n.language));
      notifications.show({ color: 'teal', message: t('policies.saved') });
      view.reload();
    } catch (err) {
      showError(err);
    }
  }

  return (
    <Card withBorder>
      <Stack gap="xs">
        <Group justify="space-between">
          <Title order={4}>{group.name}</Title>
          <Text size="xs" c="dimmed">
            {members.map((d) => d.hostname).join(', ') || t('screen.noDevices')}
          </Text>
        </Group>
        <Loaded data={rules} error={view.error}>
          {(list) => (
            <KnownNamesContext.Provider value={knownNames(members)}>
              <ScreenTimeRules rules={list} onChange={setRules} />
              <Group justify="flex-end">
                <Button onClick={save}>{t('screen.save')}</Button>
              </Group>
            </KnownNamesContext.Provider>
          )}
        </Loaded>
      </Stack>
    </Card>
  );
}

/** ScreenTimeView gathers the screen time of every group on one page. */
export function ScreenTimeView() {
  const { t } = useTranslation();
  const groups = useResource<DeviceGroup[]>('/api/groups');
  const devices = useResource<Device[]>('/api/devices');
  const navigation = useNavigation();
  return (
    <Stack>
      <Title order={2}>{t('nav.screentime')}</Title>
      <Text size="sm" c="dimmed">
        {t('screen.hint')}
      </Text>
      <Loaded data={groups.data} error={groups.error}>
        {(list) =>
          list.length === 0 ? (
            <Stack align="flex-start">
              <Text c="dimmed">{t('screen.noGroups')}</Text>
              <Button variant="light" onClick={() => navigation.open('groups')}>
                {t('screen.toGroups')}
              </Button>
            </Stack>
          ) : (
            list.map((group) => <GroupScreenTime key={group.id} group={group} devices={devices.data ?? []} />)
          )
        }
      </Loaded>
    </Stack>
  );
}
