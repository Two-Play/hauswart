import { Badge, Button, Divider, Group, Modal, Select, SimpleGrid, Stack, TagsInput, Text, Title } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api, useResource, type ApprovalMode, type ApprovalRules, type RequestKind } from '../api';
import { Loaded, showError } from '../ui';

export const REQUEST_KINDS: RequestKind[] = ['software', 'flatpak', 'sudo', 'screen'];
const MODES: ApprovalMode[] = ['auto', 'approver', 'admin', 'blocked'];

const MODE_COLORS: Record<ApprovalMode, string> = {
  auto: 'teal',
  approver: 'blue',
  admin: 'orange',
  blocked: 'red',
};

// Root without anyone looking is refused by the server as well.
function modesFor(kind: RequestKind) {
  return kind === 'sudo' ? MODES.filter((m) => m !== 'auto') : MODES;
}

function RulesForm({
  initial,
  inherit,
  onSave,
  onClose,
}: {
  initial: ApprovalRules;
  inherit: boolean;
  onSave: (rules: ApprovalRules) => void;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const [kinds, setKinds] = useState<Partial<Record<RequestKind, ApprovalMode>>>(initial.kinds ?? {});
  const [packages, setPackages] = useState(initial.auto_packages ?? []);
  const [flatpaks, setFlatpaks] = useState(initial.auto_flatpaks ?? []);

  function setKind(kind: RequestKind, mode: string | null) {
    const next = { ...kinds };
    if (mode && mode !== 'inherit') next[kind] = mode as ApprovalMode;
    else delete next[kind];
    setKinds(next);
  }

  function submit() {
    onSave({ kinds, auto_packages: packages, auto_flatpaks: flatpaks });
  }

  return (
    <Stack>
      <Text size="sm" c="dimmed">
        {t(inherit ? 'approvalRules.groupHint' : 'approvalRules.defaultHint')}
      </Text>
      <SimpleGrid cols={{ base: 1, sm: 2 }}>
        {REQUEST_KINDS.map((kind) => (
          <Select
            key={kind}
            label={t(`requests.kinds.${kind}`)}
            allowDeselect={false}
            value={kinds[kind] ?? (inherit ? 'inherit' : 'approver')}
            onChange={(mode) => setKind(kind, mode)}
            data={[
              ...(inherit ? [{ value: 'inherit', label: t('approvalRules.inherit') }] : []),
              ...modesFor(kind).map((mode) => ({ value: mode, label: t(`approvalRules.modes.${mode}`) })),
            ]}
          />
        ))}
      </SimpleGrid>
      <TagsInput
        label={t('approvalRules.autoPackages')}
        description={t('approvalRules.autoHint')}
        value={packages}
        onChange={setPackages}
        clearable
      />
      <TagsInput
        label={t('approvalRules.autoFlatpaks')}
        description={t('approvalRules.autoHint')}
        value={flatpaks}
        onChange={setFlatpaks}
        clearable
      />
      <Group justify="flex-end">
        <Button variant="subtle" onClick={onClose}>
          {t('approvalRules.cancel')}
        </Button>
        <Button onClick={submit}>{t('approvalRules.save')}</Button>
      </Group>
    </Stack>
  );
}

function Summary({ rules, inherit }: { rules: ApprovalRules; inherit: boolean }) {
  const { t } = useTranslation();
  const set = REQUEST_KINDS.filter((kind) => rules.kinds?.[kind]);
  const apps = [...(rules.auto_packages ?? []), ...(rules.auto_flatpaks ?? [])];
  if (set.length === 0 && apps.length === 0) {
    return (
      <Text size="sm" c="dimmed">
        {t(inherit ? 'approvalRules.inheritsAll' : 'approvalRules.noneSet')}
      </Text>
    );
  }
  return (
    <Stack gap={4}>
      {set.length > 0 && (
        <Group gap="xs">
          {set.map((kind) => {
            const mode = rules.kinds![kind]!;
            return (
              <Badge key={kind} variant="light" color={MODE_COLORS[mode]}>
                {t(`requests.kinds.${kind}`)}: {t(`approvalRules.modes.${mode}`)}
              </Badge>
            );
          })}
        </Group>
      )}
      {apps.length > 0 && (
        <Text size="sm">
          {t('approvalRules.autoApps')}: {apps.join(', ')}
        </Text>
      )}
    </Stack>
  );
}

// ApprovalRulesPanel shows and edits who decides requests. A group inherits each
// kind it leaves open from the defaults; the defaults themselves fall back to
// an approver.
export function ApprovalRulesPanel({ path, inherit }: { path: string; inherit: boolean }) {
  const { t } = useTranslation();
  const rules = useResource<ApprovalRules>(path);
  const [editing, setEditing] = useState(false);

  async function save(next: ApprovalRules) {
    try {
      await api('PUT', path, next);
      notifications.show({ color: 'teal', message: t('approvalRules.saved') });
      setEditing(false);
      rules.reload();
    } catch (err) {
      showError(err);
    }
  }

  return (
    <>
      {inherit && <Divider />}
      <Loaded data={rules.data} error={rules.error}>
        {(data) => (
          <Stack gap="xs">
            <Group justify="space-between">
              <Title order={5}>{t(inherit ? 'approvalRules.title' : 'approvalRules.defaultTitle')}</Title>
              <Button size="xs" variant="light" onClick={() => setEditing(true)}>
                {t('approvalRules.edit')}
              </Button>
            </Group>
            <Summary rules={data} inherit={inherit} />
            <Modal
              opened={editing}
              onClose={() => setEditing(false)}
              title={t(inherit ? 'approvalRules.title' : 'approvalRules.defaultTitle')}
              size="lg"
            >
              <RulesForm initial={data} inherit={inherit} onSave={save} onClose={() => setEditing(false)} />
            </Modal>
          </Stack>
        )}
      </Loaded>
    </>
  );
}
