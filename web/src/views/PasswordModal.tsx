import { Button, Group, Modal, PasswordInput, Stack } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '../api';
import { ExpandableText, showError } from '../ui';

export function PasswordModal({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [repeat, setRepeat] = useState('');
  const [busy, setBusy] = useState(false);
  const mismatch = repeat !== '' && next !== repeat;

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      await api('POST', '/api/password', { current, new: next });
      notifications.show({ color: 'teal', message: t('password.done') });
      onClose();
    } catch (err) {
      showError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal opened onClose={onClose} title={t('nav.password')}>
      <form onSubmit={submit}>
        <Stack>
          <PasswordInput
            label={t('password.current')}
            autoComplete="current-password"
            required
            value={current}
            onChange={(e) => setCurrent(e.currentTarget.value)}
          />
          <PasswordInput
            label={t('password.new')}
            autoComplete="new-password"
            required
            minLength={10}
            value={next}
            onChange={(e) => setNext(e.currentTarget.value)}
          />
          <PasswordInput
            label={t('password.repeat')}
            autoComplete="new-password"
            required
            error={mismatch && t('password.mismatch')}
            value={repeat}
            onChange={(e) => setRepeat(e.currentTarget.value)}
          />
          <ExpandableText size="xs" c="dimmed">
            {t('password.hint')}
          </ExpandableText>
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" loading={busy} disabled={next !== repeat}>
              {t('password.submit')}
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}
