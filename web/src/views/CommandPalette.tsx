import { ActionIcon, Kbd, Modal, NavLink, ScrollArea, Stack, Text, TextInput, Tooltip } from '@mantine/core';
import { IconBolt } from '@tabler/icons-react';
import { useHotkeys } from '@mantine/hooks';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api, type Device } from '../api';
import { ACTION_AREAS, taskKey } from '../tasks';
import { showError } from '../ui';
import { ActionForm } from './ActionForm';
import { matches } from './ActionsView';

const ALL_TYPES = ACTION_AREAS.flatMap((area) => area.types);

/** CommandPalette opens with Ctrl+K: an action, then a device, then its form. */
export function CommandPalette() {
  const { t } = useTranslation();
  const [opened, setOpened] = useState(false);
  const [query, setQuery] = useState('');
  const [type, setType] = useState<string>();
  const [devices, setDevices] = useState<Device[]>();
  const [device, setDevice] = useState<Device>();

  function open() {
    setOpened(true);
    setQuery('');
    setType(undefined);
    setDevice(undefined);
    api<Device[]>('GET', '/api/devices')
      .then((list) => setDevices(list.filter((d) => !d.revoked)))
      .catch(showError);
  }
  const close = () => setOpened(false);
  useHotkeys([['mod+K', open]]);

  const actions = ALL_TYPES.filter((each) => matches(t(taskKey(each)), each, query));
  const machines = (devices ?? []).filter((d) => d.hostname.toLowerCase().includes(query.trim().toLowerCase()));
  const choose = () => {
    if (!type && actions.length > 0) {
      setType(actions[0]);
      setQuery('');
    } else if (type && !device && machines.length > 0) {
      setDevice(machines[0]);
    }
  };

  const title = device && type ? `${t(taskKey(type))} · ${device.hostname}` : t('palette.title');
  return (
    <>
    <Tooltip label={t('palette.hint')}>
      <ActionIcon variant="default" size="lg" aria-label={t('palette.title')} onClick={open}>
        <IconBolt size={18} />
      </ActionIcon>
    </Tooltip>
    <Modal opened={opened} onClose={close} title={title} size="lg">
      {device && type ? (
        <ActionForm device={device} type={type} onDone={close} />
      ) : (
        <Stack gap="xs">
          <TextInput
            data-autofocus
            placeholder={t(type ? 'palette.device' : 'palette.action')}
            value={query}
            onChange={(e) => setQuery(e.currentTarget.value)}
            onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), choose())}
            rightSection={<Kbd>↵</Kbd>}
          />
          {type && (
            <Text size="sm" c="dimmed">
              {t(taskKey(type))}
            </Text>
          )}
          <ScrollArea.Autosize mah={360}>
            {!type &&
              actions.map((each) => (
                <NavLink key={each} label={t(taskKey(each))} description={each} onClick={() => (setType(each), setQuery(''))} />
              ))}
            {type &&
              machines.map((each) => <NavLink key={each.id} label={each.hostname} onClick={() => setDevice(each)} />)}
          </ScrollArea.Autosize>
        </Stack>
      )}
    </Modal>
    </>
  );
}
