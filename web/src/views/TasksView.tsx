import { Code, Paper, Spoiler, Stack, Text, Title } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { useResource, type Device, type Task } from '../api';
import { taskKey } from '../tasks';
import { DataTable, formatTime, Loaded, StatusBadge } from '../ui';

export function TasksView() {
  const { t } = useTranslation();
  const tasks = useResource<Task[]>('/api/tasks', 3_000);
  const devices = useResource<Device[]>('/api/devices');
  const names = new Map((devices.data ?? []).map((d) => [d.id, d.hostname]));

  return (
    <Stack>
      <div>
        <Title order={2}>{t('nav.tasks')}</Title>
        <Text c="dimmed">{t('tasks.subtitle')}</Text>
      </div>
      <Paper withBorder p="md">
        <Loaded data={tasks.data} error={tasks.error}>
          {(list) => (
            <DataTable
              empty={t('tasks.empty')}
              headers={[
                t('tasks.time'),
                t('tasks.device'),
                t('tasks.action'),
                t('tasks.by'),
                t('tasks.status'),
                t('tasks.output'),
              ]}
              rows={list.map((task) => ({
                key: task.id,
                cells: [
                  formatTime(task.created_at),
                  names.get(task.device_id) ?? task.device_id,
                  t(taskKey(task.type)),
                  task.created_by,
                  <StatusBadge status={task.status} />,
                  task.output && (
                    <Spoiler maxHeight={44} showLabel={t('common.more')} hideLabel={t('common.less')} fz="xs">
                      <Code block>{task.output}</Code>
                    </Spoiler>
                  ),
                ],
              }))}
            />
          )}
        </Loaded>
      </Paper>
    </Stack>
  );
}
