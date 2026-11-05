import { Paper, Stack, Title } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { useResource, type AuditEntry } from '../api';
import { DataTable, formatTime, Loaded } from '../ui';

export function AuditView() {
  const { t } = useTranslation();
  const { data, error } = useResource<AuditEntry[]>('/api/audit', 10_000);

  return (
    <Stack>
      <Title order={2}>{t('nav.audit')}</Title>
      <Paper withBorder p="md">
        <Loaded data={data} error={error}>
          {(entries) => (
            <DataTable
              empty={t('audit.empty')}
              headers={[t('audit.time'), t('audit.actor'), t('audit.action'), t('audit.detail')]}
              rows={entries.map((e, i) => ({
                key: String(i),
                cells: [formatTime(e.ts), e.actor, e.action, e.detail],
              }))}
            />
          )}
        </Loaded>
      </Paper>
    </Stack>
  );
}
