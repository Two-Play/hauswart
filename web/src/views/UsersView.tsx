import { Button, Group, Paper, PasswordInput, Select, SimpleGrid, Stack, TextInput, Title } from '@mantine/core';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { api, useResource, type User } from '../api';
import { DataTable, Loaded, showError } from '../ui';

export function UsersView() {
  const { t } = useTranslation();
  const { data, error, reload } = useResource<User[]>('/api/users');
  const [username, setUsername] = useState('');
  const [linuxUser, setLinuxUser] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('member');

  async function submit(e: FormEvent) {
    e.preventDefault();
    try {
      await api('POST', '/api/users', { username, linux_user: linuxUser, password, role });
      setUsername('');
      setLinuxUser('');
      setPassword('');
      reload();
    } catch (err) {
      showError(err);
    }
  }

  return (
    <Stack>
      <Title order={2}>{t('nav.users')}</Title>

      <Paper withBorder p="md">
        <form onSubmit={submit}>
          <Stack>
            <Title order={4}>{t('users.new')}</Title>
            <SimpleGrid cols={{ base: 1, sm: 2 }}>
              <TextInput
                label={t('users.username')}
                required
                value={username}
                onChange={(e) => setUsername(e.currentTarget.value)}
              />
              <TextInput
                label={t('users.linuxUser')}
                description={t('users.linuxUserHint')}
                value={linuxUser}
                onChange={(e) => setLinuxUser(e.currentTarget.value)}
              />
              <PasswordInput
                label={t('users.password')}
                description={t('users.passwordHint')}
                autoComplete="new-password"
                required
                minLength={10}
                value={password}
                onChange={(e) => setPassword(e.currentTarget.value)}
              />
              <Select
                label={t('users.role')}
                allowDeselect={false}
                value={role}
                onChange={(next) => setRole(next ?? role)}
                data={[
                  { value: 'member', label: t('users.member') },
                  { value: 'admin', label: t('users.admin') },
                ]}
              />
            </SimpleGrid>
            <Group>
              <Button type="submit">{t('users.create')}</Button>
            </Group>
          </Stack>
        </form>
      </Paper>

      <Paper withBorder p="md">
        <Loaded data={data} error={error}>
          {(users) => (
            <DataTable
              empty=""
              headers={[t('users.username'), t('users.linuxUser'), t('users.role')]}
              rows={users.map((u) => ({
                key: String(u.id),
                cells: [u.username, u.linux_user, t(`users.${u.role}`)],
              }))}
            />
          )}
        </Loaded>
      </Paper>
    </Stack>
  );
}
