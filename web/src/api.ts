import { useCallback, useEffect, useState } from 'react';
import i18n from './i18n';

export interface User {
  id: number;
  username: string;
  linux_user: string;
  role: 'admin' | 'approver' | 'member';
  source?: string;
  disabled?: boolean;
}

export interface Report {
  protected?: boolean;
  distro?: string;
  kernel?: string;
  backends?: string[];
  load1?: number;
  cpus?: number;
  mem_total?: number;
  mem_used?: number;
  disk_total?: number;
  disk_used?: number;
  cert_expires?: string;
  accounts?: Account[];
  updates?: UpdateStatus;
}

export interface Account {
  name: string;
  uid: number;
  groups: string[];
  privileged?: string[];
  sudo?: string[];
  sudo_unknown?: boolean;
  grant_expires?: string;
}

export interface UpdateStatus {
  checked_at?: string;
  pending: number;
  packages?: string[];
  reboot: 'required' | 'not_required' | 'unknown';
  error?: string;
}

export interface Warning {
  code: 'disk_full' | 'cert_expiring' | 'warranty_ending';
  value: number;
}

export interface Device {
  id: string;
  hostname: string;
  revoked: boolean;
  suspended: boolean;
  last_seen: number;
  report: Report | null;
  warnings?: Warning[];
}

export interface Task {
  id: string;
  device_id: string;
  type: string;
  status: 'signing' | 'pending' | 'running' | 'done' | 'failed';
  output: string;
  created_by: string;
  created_at: number;
}

export interface WaitingTask extends Task {
  hostname: string;
  payload: unknown;
}

export interface PasskeyEntry {
  id: number;
  username: string;
  name: string;
  created_at: number;
}

export type RequestKind = 'software' | 'flatpak' | 'sudo' | 'screen';
export type ApprovalMode = 'auto' | 'approver' | 'admin' | 'blocked';

export interface AccessRequest {
  id: string;
  username: string;
  hostname: string;
  kind: RequestKind;
  detail: string;
  reason: string;
  status: 'open' | 'approved' | 'denied';
  decided_by: string;
  created_at: number;
  // mode says who decides an open request, by the rules of now.
  mode?: ApprovalMode;
}

export interface ApprovalRules {
  kinds?: Partial<Record<RequestKind, ApprovalMode>>;
  auto_packages?: string[];
  auto_flatpaks?: string[];
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
    readonly code?: string,
  ) {
    super(message);
  }
}

/** Whether someone may approve requests and tasks. */
export function isApprover(user: User): boolean {
  return user.role === 'admin' || user.role === 'approver';
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
    throw new ApiError(res.status, errorMessage(res.status, text), errorCode(text));
  }
  return (text ? JSON.parse(text) : undefined) as T;
}

function errorCode(text: string): string | undefined {
  try {
    return (JSON.parse(text) as { code?: string }).code;
  } catch {
    return undefined;
  }
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

export interface Asset {
  tag?: string;
  person?: string;
  location?: string;
  purchased?: string;
  warranty_until?: string;
  note?: string;
}

export interface InstalledPackage {
  kind: 'package' | 'flatpak';
  name: string;
  version?: string;
}

export interface StoredInventory {
  hardware: { vendor?: string; model?: string; serial?: string; bios?: string; cpu?: string };
  disks?: { name: string; model?: string; size: number; rotational?: boolean }[];
  network?: { name: string; mac?: string; addresses?: string[] }[];
  security: { disk_encryption?: string; screen_lock?: string; firewall?: string };
  truncated?: boolean;
  package_count: number;
  updated_at: number;
}

export interface InventoryDevice {
  id: string;
  hostname: string;
  revoked: boolean;
  last_seen: number;
  distro?: string;
  kernel?: string;
  cpus?: number;
  mem_total?: number;
  disk_total?: number;
  agent_version?: string;
  updates?: UpdateStatus;
  inventory?: StoredInventory;
  asset: Asset;
  warnings?: Warning[];
  packages?: InstalledPackage[];
}

export interface SoftwareEntry {
  kind: string;
  name: string;
  version: string;
  devices: { id: string; hostname: string }[];
}
