import {
  ActionIcon,
  AppShell,
  Badge,
  Burger,
  Button,
  Center,
  Group,
  Loader,
  NavLink,
  SegmentedControl,
  Text,
  Title,
  useComputedColorScheme,
  useMantineColorScheme,
} from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import {
  IconBolt,
  IconCertificate,
  IconClockHour4,
  IconClipboardList,
  IconClipboardData,
  IconDevicesPc,
  IconFingerprint,
  IconFolders,
  IconHistory,
  IconKey,
  IconListCheck,
  IconLogout,
  IconMoon,
  IconSun,
  IconUsers,
} from '@tabler/icons-react';
import { useEffect, useState, type ComponentType } from 'react';
import { useTranslation } from 'react-i18next';
import { api, isApprover, setUnauthorizedHandler, useResource, type User } from './api';
import { LANGUAGES, setLanguage } from './i18n';
import { NavigationContext } from './navigation';
import { ActionsView } from './views/ActionsView';
import { CommandPalette } from './views/CommandPalette';
import { ApprovalsView } from './views/ApprovalsView';
import { AuditView } from './views/AuditView';
import { CertificatesView } from './views/CertificatesView';
import { DevicesView } from './views/DevicesView';
import { GroupsView } from './views/GroupsView';
import { InventoryView } from './views/InventoryView';
import { LoginView } from './views/LoginView';
import { PasswordModal } from './views/PasswordModal';
import { RequestsView } from './views/RequestsView';
import { ScreenTimeView } from './views/ScreenTimeView';
import { TasksView } from './views/TasksView';
import { UsersView } from './views/UsersView';

interface ViewProps {
  user: User;
}

const VIEWS: {
  key: string;
  icon: typeof IconUsers;
  view: ComponentType<ViewProps>;
  adminOnly?: boolean;
  approverOnly?: boolean;
}[] = [
  { key: 'devices', icon: IconDevicesPc, view: DevicesView },
  { key: 'actions', icon: IconBolt, view: ActionsView, adminOnly: true },
  { key: 'groups', icon: IconFolders, view: GroupsView, adminOnly: true },
  { key: 'screentime', icon: IconClockHour4, view: ScreenTimeView, adminOnly: true },
  { key: 'requests', icon: IconClipboardList, view: RequestsView },
  { key: 'approvals', icon: IconFingerprint, view: ApprovalsView, approverOnly: true },
  { key: 'inventory', icon: IconClipboardData, view: InventoryView, adminOnly: true },
  { key: 'tasks', icon: IconListCheck, view: TasksView, adminOnly: true },
  { key: 'certificates', icon: IconCertificate, view: CertificatesView, adminOnly: true },
  { key: 'users', icon: IconUsers, view: UsersView, adminOnly: true },
  { key: 'audit', icon: IconHistory, view: AuditView, adminOnly: true },
];

function ColorSchemeToggle() {
  const { t } = useTranslation();
  const { setColorScheme } = useMantineColorScheme();
  const computed = useComputedColorScheme('light');
  return (
    <ActionIcon
      variant="default"
      size="lg"
      aria-label={t('nav.theme')}
      onClick={() => setColorScheme(computed === 'dark' ? 'light' : 'dark')}
    >
      {computed === 'dark' ? <IconSun size={18} /> : <IconMoon size={18} />}
    </ActionIcon>
  );
}

interface Attention {
  failed_tasks: number;
  deviating_devices: number;
  boot_alarms?: number;
}

/** Attention counts what an admin should look at, next to the views that show it. */
function useAttention(admin: boolean): Partial<Record<string, number>> {
  const { data } = useResource<Attention>(admin ? '/api/attention' : '', 30_000);
  if (!admin || !data) return {};
  return { devices: data.boot_alarms, tasks: data.failed_tasks, groups: data.deviating_devices };
}

function LanguageSwitch() {
  const { i18n } = useTranslation();
  return (
    <SegmentedControl
      size="xs"
      value={i18n.language}
      onChange={setLanguage}
      data={LANGUAGES.map((l) => ({ value: l, label: l.toUpperCase() }))}
    />
  );
}

export function App() {
  const { t } = useTranslation();
  const [user, setUser] = useState<User | null>();
  const [active, setActive] = useState('devices');
  // The device a view chose for the actions page.
  const [chosen, setChosen] = useState<string>();
  const [opened, { toggle, close }] = useDisclosure();
  const [changingPassword, setChangingPassword] = useState(false);
  const attention = useAttention(user?.role === 'admin');

  useEffect(() => {
    setUnauthorizedHandler(() => setUser(null));
    api<User>('GET', '/api/me')
      .then(setUser)
      .catch(() => setUser(null));
  }, []);

  if (user === undefined) {
    return (
      <Center h="100vh">
        <Loader aria-label={t('common.loading')} />
      </Center>
    );
  }
  if (user === null) {
    return <LoginView onLogin={setUser} controls={<LanguageSwitch />} />;
  }

  const views = VIEWS.filter(
    (v) => (!v.adminOnly || user.role === 'admin') && (!v.approverOnly || isApprover(user)),
  );
  const View = (views.find((v) => v.key === active) ?? views[0]).view;

  const navigation = {
    open: (view: string, device?: string) => {
      setChosen(device);
      setActive(view);
    },
    device: chosen,
  };

  return (
    <NavigationContext.Provider value={navigation}>
    <AppShell
      header={{ height: 56 }}
      navbar={{ width: 220, breakpoint: 'sm', collapsed: { mobile: !opened } }}
      padding="md"
    >
      <AppShell.Header>
        <Group h="100%" px="md" justify="space-between" wrap="nowrap">
          <Group gap="sm" wrap="nowrap">
            <Burger opened={opened} onClick={toggle} hiddenFrom="sm" size="sm" aria-label={t('nav.menu')} />
            <Title order={4}>Hauswart</Title>
          </Group>
          <Group gap="xs" wrap="nowrap">
            {user.role === 'admin' && <CommandPalette />}
            <LanguageSwitch />
            <ColorSchemeToggle />
          </Group>
        </Group>
      </AppShell.Header>

      <AppShell.Navbar p="sm">
        <AppShell.Section grow>
          {views.map((v) => (
            <NavLink
              key={v.key}
              component="button"
              label={t(`nav.${v.key}`)}
              leftSection={<v.icon size={18} />}
              rightSection={
                attention[v.key] ? (
                  <Badge size="sm" color="red" circle aria-label={t(`nav.attention.${v.key}`, { count: attention[v.key] })}>
                    {attention[v.key]}
                  </Badge>
                ) : undefined
              }
              active={v.key === active}
              onClick={() => {
                setChosen(undefined);
                setActive(v.key);
                close();
              }}
            />
          ))}
        </AppShell.Section>
        <AppShell.Section>
          <Text size="sm" c="dimmed" mb="xs" truncate>
            {user.username}
          </Text>
          {!user.source && (
            <Button
              variant="default"
              fullWidth
              mb="xs"
              leftSection={<IconKey size={16} />}
              onClick={() => setChangingPassword(true)}
            >
              {t('nav.password')}
            </Button>
          )}
          <Button
            variant="default"
            fullWidth
            leftSection={<IconLogout size={16} />}
            onClick={() => api('POST', '/api/logout').finally(() => setUser(null))}
          >
            {t('nav.logout')}
          </Button>
        </AppShell.Section>
      </AppShell.Navbar>

      <AppShell.Main>
        <View key={`${active}-${chosen ?? ''}`} user={user} />
      </AppShell.Main>
      {changingPassword && <PasswordModal onClose={() => setChangingPassword(false)} />}
    </AppShell>
    </NavigationContext.Provider>
  );
}
