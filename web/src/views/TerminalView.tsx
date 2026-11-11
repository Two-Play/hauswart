import { Alert, Box, Button, Group, Modal, NumberInput, Select, Stack, Text } from '@mantine/core';
import { FitAddon } from '@xterm/addon-fit';
import { Terminal } from '@xterm/xterm';
import '@xterm/xterm/css/xterm.css';
import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api, type Device, type RunningTerminal } from '../api';
import { approveWithPasskey, decodeEnvelope, passkeysAvailable, type Challenge } from '../passkey';
import { allowScriptStyles } from '../terminalStyles';
import { ExpandableText, showError } from '../ui';

const MIN_USER_UID = 1000;
const DEFAULT_MINUTES = 60;
const MAX_MINUTES = 240;

interface Opened {
  id: string;
  session: string;
}

interface Approval {
  opened: Opened;
  challenge: Challenge;
  user: string;
  minutes: number;
}

/** A live shell on a device: choose the account, approve with a passkey, type.
 * With resume, it goes straight back to a session that still runs. */
export function TerminalView({
  device,
  resume,
  onClose,
}: {
  device: Device;
  resume?: RunningTerminal;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const [user, setUser] = useState('root');
  const [minutes, setMinutes] = useState(DEFAULT_MINUTES);
  const [approval, setApproval] = useState<Approval>();
  const [session, setSession] = useState<{ id: string; until: Date } | undefined>(
    resume && { id: resume.session, until: new Date(resume.until) },
  );
  const [busy, setBusy] = useState(false);

  const accounts = (device.report?.accounts ?? []).filter((a) => a.uid >= MIN_USER_UID).map((a) => a.name);
  const users = [{ value: 'root', label: t('terminal.root') }, ...accounts.map((name) => ({ value: name, label: name }))];

  async function start() {
    setBusy(true);
    try {
      const opened = await api<Opened>('POST', `/api/devices/${device.id}/terminal`, { user, minutes });
      const challenge = await api<Challenge>('POST', `/api/tasks/${opened.id}/passkey-challenge`);
      setApproval({ opened, challenge, user, minutes });
    } catch (err) {
      showError(err);
    } finally {
      setBusy(false);
    }
  }

  async function approve() {
    if (!approval) return;
    setBusy(true);
    try {
      await approveWithPasskey(approval.opened.id, approval.challenge);
      setSession({ id: approval.opened.session, until: new Date(Date.now() + approval.minutes * 60_000) });
    } catch (err) {
      showError(err);
    } finally {
      setBusy(false);
    }
  }

  let body;
  if (session) {
    body = <Console session={session.id} until={session.until} />;
  } else if (!device.report?.protected) {
    body = <Alert color="yellow">{t('terminal.unprotected')}</Alert>;
  } else if (!passkeysAvailable()) {
    body = <Alert color="yellow">{t('terminal.noPasskeys')}</Alert>;
  } else if (approval) {
    // What the passkey signs, read from the envelope and not from the form.
    const envelope = decodeEnvelope(approval.challenge);
    const payload = envelope.payload as unknown as { user: string; minutes: number };
    body = (
      <Stack>
        <Text>
          {t('terminal.confirm', { user: payload.user, device: approval.challenge.hostname, minutes: payload.minutes })}
        </Text>
        <Group>
          <Button loading={busy} onClick={approve}>
            {t('terminal.approve')}
          </Button>
        </Group>
      </Stack>
    );
  } else {
    body = (
      <Stack>
        <ExpandableText size="sm" c="dimmed">
          {t('terminal.hint')}
        </ExpandableText>
        <ExpandableText size="sm" c="dimmed" lines={2}>
          {t('terminal.resumeHint')}
        </ExpandableText>
        <Select label={t('terminal.user')} data={users} value={user} onChange={(v) => setUser(v ?? 'root')} allowDeselect={false} />
        <NumberInput
          label={t('terminal.minutes')}
          min={1}
          max={MAX_MINUTES}
          value={minutes}
          onChange={(v) => setMinutes(typeof v === 'number' ? v : DEFAULT_MINUTES)}
        />
        <Group>
          <Button loading={busy} onClick={start}>
            {t('terminal.start')}
          </Button>
        </Group>
      </Stack>
    );
  }

  return (
    <Modal opened onClose={onClose} fullScreen={!!session} size="lg" title={t('terminal.title', { name: device.hostname })}>
      {body}
    </Modal>
  );
}

function Console({ session, until }: { session: string; until: Date }) {
  const { t } = useTranslation();
  const box = useRef<HTMLDivElement>(null);
  const [state, setState] = useState<'waiting' | 'open' | 'ended'>('waiting');
  const [reason, setReason] = useState('');
  const [exit, setExit] = useState<number>();

  useEffect(() => {
    if (!box.current) return;
    allowScriptStyles();
    const term = new Terminal({ cursorBlink: true, fontFamily: 'monospace', fontSize: 14, scrollback: 5000 });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(box.current);
    fit.fit();
    const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
    const ws = new WebSocket(`${scheme}://${location.host}/api/terminal/${encodeURIComponent(session)}`);
    ws.binaryType = 'arraybuffer';
    const encoder = new TextEncoder();
    const sendSize = () => {
      if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ resize: { cols: term.cols, rows: term.rows } }));
    };
    ws.onmessage = (event) => {
      if (event.data instanceof ArrayBuffer) {
        term.write(new Uint8Array(event.data));
        return;
      }
      const message = JSON.parse(event.data as string) as { state?: 'waiting' | 'open'; exit?: number };
      if (message.state) setState(message.state);
      if (message.state === 'open') {
        sendSize();
        term.focus();
      }
      if (message.exit !== undefined) setExit(message.exit);
    };
    ws.onclose = (event) => {
      setState('ended');
      setReason(event.reason || String(event.code));
    };
    const typed = term.onData((data) => {
      if (ws.readyState === WebSocket.OPEN) ws.send(encoder.encode(data));
    });
    const resized = term.onResize(sendSize);
    const observer = new ResizeObserver(() => fit.fit());
    observer.observe(box.current);
    return () => {
      observer.disconnect();
      typed.dispose();
      resized.dispose();
      ws.close();
      term.dispose();
    };
  }, [session]);

  const time = until.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  return (
    <Stack h="calc(100vh - 100px)" gap="xs">
      <Text size="sm" c={state === 'ended' ? 'red' : 'dimmed'}>
        {state === 'waiting' && t('terminal.waiting')}
        {state === 'open' && t('terminal.running', { time })}
        {state === 'ended' && t('terminal.ended', { reason })}
        {exit !== undefined && ` ${t('terminal.exit', { code: exit })}`}
      </Text>
      <Box ref={box} style={{ flex: 1, minHeight: 0, background: '#000', padding: 4 }} />
    </Stack>
  );
}
