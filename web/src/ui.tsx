import { Alert, Badge, Center, Loader, Table, Text } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import i18n from './i18n';

export function formatBytes(value = 0): string {
  if (!value) return '–';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let n = value;
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(i > 1 ? 1 : 0)} ${units[i]}`;
}

export function formatTime(ts: number): string {
  return ts ? new Date(ts * 1000).toLocaleString(i18n.language) : '–';
}

export function showError(err: unknown) {
  notifications.show({
    color: 'red',
    title: i18n.t('common.failed'),
    message: (err as Error).message,
  });
}

const STATUS_COLOR: Record<string, string> = {
  open: 'yellow',
  pending: 'yellow',
  running: 'blue',
  approved: 'teal',
  done: 'teal',
  denied: 'red',
  failed: 'red',
};

export function StatusBadge({ status }: { status: string }) {
  const { t } = useTranslation();
  return (
    <Badge color={STATUS_COLOR[status]} variant="light">
      {t(`status.${status}`)}
    </Badge>
  );
}

/** Handles the shared loading and error states of a view. */
export function Loaded<T>({
  data,
  error,
  children,
}: {
  data: T | undefined;
  error?: string;
  children: (data: T) => ReactNode;
}) {
  const { t } = useTranslation();
  if (data !== undefined) {
    return (
      <>
        {error && (
          <Alert color="red" mb="md">
            {error}
          </Alert>
        )}
        {children(data)}
      </>
    );
  }
  if (error) return <Alert color="red">{error}</Alert>;
  return (
    <Center p="xl">
      <Loader aria-label={t('common.loading')} />
    </Center>
  );
}

export function DataTable({
  headers,
  rows,
  empty,
}: {
  headers: string[];
  rows: { key: string; cells: ReactNode[] }[];
  empty: string;
}) {
  if (!rows.length) return <Text c="dimmed">{empty}</Text>;
  return (
    <Table.ScrollContainer minWidth={640}>
      <Table verticalSpacing="xs" highlightOnHover>
        <Table.Thead>
          <Table.Tr>
            {headers.map((h, i) => (
              <Table.Th key={i}>{h}</Table.Th>
            ))}
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {rows.map((row) => (
            <Table.Tr key={row.key}>
              {row.cells.map((cell, i) => (
                <Table.Td key={i}>{cell}</Table.Td>
              ))}
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
    </Table.ScrollContainer>
  );
}
