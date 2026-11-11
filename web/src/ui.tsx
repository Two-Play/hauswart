import { Alert, Badge, Center, Loader, Spoiler, Table, Text, type TextProps } from '@mantine/core';
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
  signing: 'grape',
  pending: 'yellow',
  running: 'blue',
  approved: 'teal',
  done: 'teal',
  denied: 'red',
  failed: 'red',
  lapsed: 'gray',
};

/** LAPSED is what the server writes into a task nobody approved in time. */
export const LAPSED = 'lapsed: nobody approved it in time';

/** taskStatus tells a lapsed task from one that failed on the device. */
export function taskStatus(task: { status: string; output: string }): string {
  return task.status === 'failed' && task.output === LAPSED ? 'lapsed' : task.status;
}

/** lapsesIn says how soon a waiting task lapses, in words. */
export function lapsesIn(ts: number | undefined): string {
  if (!ts) return '–';
  const minutes = Math.max(0, Math.round((ts * 1000 - Date.now()) / 60_000));
  const format = new Intl.RelativeTimeFormat(i18n.language, { numeric: 'auto' });
  if (minutes < 90) return format.format(minutes, 'minute');
  if (minutes < 48 * 60) return format.format(Math.round(minutes / 60), 'hour');
  return format.format(Math.round(minutes / 1440), 'day');
}

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

/** ExpandableText shows the first lines of a long text and the rest on demand,
 * so that a long output or reason does not stretch a list. */
export function ExpandableText({
  children,
  lines = 3,
  ...props
}: { children: ReactNode; lines?: number } & TextProps) {
  const { t } = useTranslation();
  const size = props.size === 'xs' ? 18 : 22;
  return (
    <Spoiler maxHeight={lines * size} showLabel={t('common.more')} hideLabel={t('common.less')} fz="xs">
      <Text {...props} style={{ wordBreak: 'break-word', whiteSpace: 'pre-wrap', ...(props.style as object) }}>
        {children}
      </Text>
    </Spoiler>
  );
}
