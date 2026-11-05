import { useCallback, useEffect, useState } from 'react';
import i18n from './i18n';

export interface User {
  id: number;
  username: string;
  linux_user: string;
  role: 'admin' | 'member';
}

export interface Report {
  distro?: string;
  kernel?: string;
  backends?: string[];
  load1?: number;
  cpus?: number;
  mem_total?: number;
  mem_used?: number;
  disk_total?: number;
  disk_used?: number;
}

export interface Device {
  id: string;
  hostname: string;
  revoked: boolean;
  last_seen: number;
  report: Report | null;
}

export interface Task {
  id: string;
  device_id: string;
  type: string;
  status: 'pending' | 'running' | 'done' | 'failed';
  output: string;
  created_by: string;
  created_at: number;
}

export interface AccessRequest {
  id: string;
  username: string;
  hostname: string;
  kind: 'software' | 'flatpak' | 'sudo';
  detail: string;
  reason: string;
  status: 'open' | 'approved' | 'denied';
  created_at: number;
}

export interface AuditEntry {
  ts: number;
  actor: string;
  action: string;
  detail: string;
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

let onUnauthorized = () => {};

/** Registers what happens when the session ends while the app is open. */
export function setUnauthorizedHandler(handler: () => void) {
  onUnauthorized = handler;
}

export async function api<T = void>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    headers: { 'Content-Type': 'application/json', 'X-Hauswart': '1' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 401 && path !== '/api/login' && path !== '/api/me') {
    onUnauthorized();
  }
  const text = await res.text();
  if (!res.ok) {
    throw new ApiError(res.status, errorMessage(res.status, text));
  }
  return (text ? JSON.parse(text) : undefined) as T;
}

/** Prefers the translation of the error code over the server's English text. */
function errorMessage(status: number, text: string): string {
  let data: { error?: string; code?: string; value?: string } = {};
  try {
    data = JSON.parse(text);
  } catch {
    // Not from our API, for example a proxy error page.
  }
  const key = `errors.${data.code}`;
  if (data.code && i18n.exists(key)) return i18n.t(key, { value: data.value });
  return data.error ?? `HTTP ${status}`;
}

/** Loads a resource, optionally refreshing it on an interval. */
export function useResource<T>(path: string, pollMs?: number) {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<string>();

  const reload = useCallback(async () => {
    try {
      setData(await api<T>('GET', path));
      setError(undefined);
    } catch (err) {
      setError((err as Error).message);
    }
  }, [path]);

  useEffect(() => {
    reload();
    if (!pollMs) return;
    const timer = setInterval(reload, pollMs);
    return () => clearInterval(timer);
  }, [reload, pollMs]);

  return { data, error, reload };
}
