import { Alert, Button, Center, Group, Paper, PasswordInput, Stack, TextInput, Title } from '@mantine/core';
import { useState, type FormEvent, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { api, type User } from '../api';

export function LoginView({ onLogin, controls }: { onLogin: (user: User) => void; controls: ReactNode }) {
  const { t } = useTranslation();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      onLogin(await api<User>('POST', '/api/login', { username, password }));
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Center mih="100vh" p="md">
      <Paper withBorder p="lg" w={360} maw="100%">
        <form onSubmit={submit}>
          <Stack>
            <Group justify="flex-end">{controls}</Group>
            <Title order={3}>{t('login.title')}</Title>
            <TextInput
              label={t('login.username')}
              autoComplete="username"
              required
              value={username}
              onChange={(e) => setUsername(e.currentTarget.value)}
            />
            <PasswordInput
              label={t('login.password')}
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.currentTarget.value)}
            />
            {error && <Alert color="red">{error}</Alert>}
            <Button type="submit" loading={busy}>
              {t('login.submit')}
            </Button>
          </Stack>
        </form>
      </Paper>
    </Center>
  );
}
