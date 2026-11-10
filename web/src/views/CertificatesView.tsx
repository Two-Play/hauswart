import { Alert, Button, Code, CopyButton, Group, Modal, Stack, Table, Text, TextInput, Title } from '@mantine/core';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { api, useResource } from '../api';
import { ExpandableText, Loaded, showError } from '../ui';

const SOON_DAYS = 30;

interface ServiceCert {
  serial: string;
  names: string[];
  not_after: number;
  created_by: string;
  created_at: number;
}

interface Issued {
  names: string[];
  cert: string;
  key: string;
  ca: string;
}

function Secret({ label, value }: { label: string; value: string }) {
  const { t } = useTranslation();
  return (
    <Stack gap={4}>
      <Group justify="space-between">
        <Text size="sm" fw={600}>
          {label}
        </Text>
        <CopyButton value={value}>
          {({ copied, copy }) => (
            <Button size="compact-xs" variant="default" onClick={copy}>
              {t(copied ? 'common.copied' : 'common.copy')}
            </Button>
          )}
        </CopyButton>
      </Group>
      <Code block>{value}</Code>
    </Stack>
  );
}

function IssuedModal({ issued, onClose }: { issued: Issued; onClose: () => void }) {
  const { t } = useTranslation();
  return (
    <Modal opened onClose={onClose} title={issued.names.join(', ')} size="lg" closeOnClickOutside={false}>
      <Stack>
        <Alert color="orange">{t('certificates.keyOnce')}</Alert>
        <Secret label={t('certificates.key')} value={issued.key} />
        <Secret label={t('certificates.cert')} value={issued.cert} />
        <Secret label={t('certificates.ca')} value={issued.ca} />
        <Group justify="flex-end">
          <Button onClick={onClose}>{t('actions.close')}</Button>
        </Group>
      </Stack>
    </Modal>
  );
}

export function CertificatesView() {
  const { t, i18n } = useTranslation();
  const { data, error, reload } = useResource<ServiceCert[]>('/api/certificates', 60_000);
  const [names, setNames] = useState('');
  const [days, setDays] = useState('365');
  const [busy, setBusy] = useState(false);
  const [issued, setIssued] = useState<Issued>();

  async function issue(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const out = await api<Issued>('POST', '/api/certificates', {
        names: names.split(/[\s,]+/).filter(Boolean),
        days: Number(days),
      });
      setIssued(out);
      setNames('');
      reload();
    } catch (err) {
      showError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Stack>
      <Title order={2}>{t('nav.certificates')}</Title>
      <ExpandableText size="sm" c="dimmed">
        {t('certificates.hint')}
      </ExpandableText>
      <form onSubmit={issue}>
        <Group align="flex-end">
          <TextInput
            flex={1}
            miw={220}
            required
            label={t('certificates.names')}
            value={names}
            onChange={(e) => setNames(e.currentTarget.value)}
          />
          <TextInput
            w={120}
            type="number"
            required
            label={t('certificates.days')}
            value={days}
            onChange={(e) => setDays(e.currentTarget.value)}
          />
          <Button type="submit" loading={busy}>
            {t('certificates.issue')}
          </Button>
        </Group>
      </form>

      <Loaded data={data} error={error}>
        {(certs) =>
          certs.length === 0 ? (
            <Text c="dimmed">{t('certificates.empty')}</Text>
          ) : (
            <Table.ScrollContainer minWidth={520}>
              <Table>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>{t('certificates.names')}</Table.Th>
                    <Table.Th>{t('certificates.expires')}</Table.Th>
                    <Table.Th>{t('certificates.issuedBy')}</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {certs.map((c) => {
                    const daysLeft = (c.not_after * 1000 - Date.now()) / 86_400_000;
                    return (
                      <Table.Tr key={c.serial}>
                        <Table.Td>{c.names.join(', ')}</Table.Td>
                        <Table.Td c={daysLeft < SOON_DAYS ? 'red' : undefined}>
                          {new Date(c.not_after * 1000).toLocaleDateString(i18n.language)}
                        </Table.Td>
                        <Table.Td>{c.created_by}</Table.Td>
                      </Table.Tr>
                    );
                  })}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          )
        }
      </Loaded>

      {issued && <IssuedModal issued={issued} onClose={() => setIssued(undefined)} />}
    </Stack>
  );
}
