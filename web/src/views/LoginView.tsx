import { Alert, Button, Center, Divider, Group, Paper, PasswordInput, Stack, TextInput, Title } from '@mantine/core';
import { useEffect, useState, type FormEvent, type ReactNode } from 'react';
import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import { api, type User } from '../api';

// A login through Authentik comes back here, with a code if it failed.
function loginError(t: TFunction): string | undefined {
  const code = new URLSearchParams(window.location.search).get('login_error');
  if (!code) return undefined;
  window.history.replaceState(null, '', '/');
  return t(`errors.${code}`, { defaultValue: t('errors.oidc_failed') });
}

export function LoginView({ onLogin, controls }: { onLogin: (user: User) => void; controls: ReactNode }) {
  const { t } = useTranslation();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | undefined>(() => loginError(t));
  const [busy, setBusy] = useState(false);
  const [oidc, setOidc] = useState(false);

  useEffect(() => {
    api<{ oidc: boolean }>('GET', '/api/login-options')
      .then((options) => setOidc(options.oidc))
      .catch(() => setOidc(false)); // the local login works without this
  }, []);

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
            {oidc && (
              <>
                <Divider label={t('login.or')} />
                <Button component="a" href="/auth/oidc/start" variant="light">
                  {t('login.oidc')}
                </Button>
              </>
            )}
          </Stack>
        </form>
      </Paper>
    </Center>
  );
}
