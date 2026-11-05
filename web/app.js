'use strict';

// Everything from the server goes through text nodes. Device data is
// untrusted, so this file must never use innerHTML.
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (key.startsWith('on')) el.addEventListener(key.slice(2), value);
    else if (key === 'class') el.className = value;
    else if (key === 'value') el.value = value;
    else if (value !== false && value != null) el.setAttribute(key, value);
  }
  for (const child of children.flat()) {
    if (child != null) el.append(child);
  }
  return el;
}

async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: { 'Content-Type': 'application/json', 'X-Hauswart': '1' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 401 && path !== '/api/login') {
    state.user = null;
    render();
    throw new Error('Nicht angemeldet');
  }
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) throw new Error((data && data.error) || 'Fehler ' + res.status);
  return data;
}

const state = { user: null, view: 'devices' };
const app = document.getElementById('app');

const ONLINE_SECONDS = 90;

const TASKS = {
  'pkg.install': { label: 'Paket installieren', fields: [['packages', 'Pakete (durch Leerzeichen getrennt)']] },
  'pkg.remove': { label: 'Paket entfernen', fields: [['packages', 'Pakete (durch Leerzeichen getrennt)']] },
  'pkg.upgrade': { label: 'System aktualisieren', fields: [] },
  'flatpak.install': { label: 'Flatpak installieren', fields: [['packages', 'Flatpak-IDs']] },
  'file.put': { label: 'Konfiguration ablegen', fields: [['path', 'Zielpfad'], ['mode', 'Rechte, z. B. 0644'], ['content', 'Inhalt', 'textarea']] },
  'ca.install': { label: 'CA-Zertifikat verteilen', fields: [['name', 'Name'], ['pem', 'Zertifikat (PEM)', 'textarea']] },
  'sudo.grant': { label: 'sudo befristet freigeben', fields: [['user', 'Linux-Benutzer'], ['minutes', 'Dauer in Minuten']] },
  'sudo.revoke': { label: 'sudo entziehen', fields: [['user', 'Linux-Benutzer']] },
  'user.create': { label: 'Linux-Benutzer anlegen', fields: [['user', 'Benutzername'], ['full_name', 'Voller Name']] },
  'user.lock': { label: 'Linux-Benutzer sperren', fields: [['user', 'Benutzername']] },
  'user.unlock': { label: 'Linux-Benutzer entsperren', fields: [['user', 'Benutzername']] },
  'limit.set': { label: 'Ressourcen begrenzen', fields: [['user', 'Linux-Benutzer'], ['cpu_percent', 'CPU in % (100 = ein Kern)'], ['memory_mb', 'Arbeitsspeicher in MB']] },
};

const REQUEST_KINDS = { software: 'Software', flatpak: 'Flatpak', sudo: 'sudo-Rechte' };
const STATUS_LABEL = {
  open: 'offen', approved: 'freigegeben', denied: 'abgelehnt',
  pending: 'wartet', running: 'läuft', done: 'fertig', failed: 'fehlgeschlagen',
};
const STATUS_CLASS = {
  approved: 'status-ok', done: 'status-ok', denied: 'status-bad', failed: 'status-bad',
  open: 'status-warn', pending: 'status-warn', running: 'status-warn',
};

function buildPayload(type, values) {
  const out = { ...values };
  if ('packages' in out) out.packages = out.packages.split(/\s+/).filter(Boolean);
  if ('minutes' in out) {
    out.expires_at = new Date(Date.now() + Number(out.minutes) * 60000).toISOString();
    delete out.minutes;
  }
  for (const key of ['cpu_percent', 'memory_mb']) {
    if (key in out) out[key] = Number(out[key]) || 0;
  }
  if (type === 'file.put' && !out.mode) delete out.mode;
  if (type === 'user.create' && !out.full_name) delete out.full_name;
  return out;
}

function formatBytes(n) {
  if (!n) return '–';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return n.toFixed(i > 1 ? 1 : 0) + ' ' + units[i];
}

function formatTime(ts) {
  return ts ? new Date(ts * 1000).toLocaleString('de-DE') : '–';
}

function statusText(status) {
  return h('span', { class: STATUS_CLASS[status] }, STATUS_LABEL[status] || status);
}

function meter(label, used, total) {
  const percent = total ? Math.round((used / total) * 100) : 0;
  const bar = h('div');
  bar.style.width = percent + '%';
  return [
    h('div', { class: 'row spread small muted' },
      h('span', {}, label), h('span', {}, `${formatBytes(used)} von ${formatBytes(total)}`)),
    h('div', { class: 'meter' }, bar),
  ];
}

function errorLine() {
  return h('p', { class: 'error', role: 'alert' });
}

function table(headers, rows, emptyText) {
  if (!rows.length) return h('p', { class: 'muted' }, emptyText);
  return h('div', { class: 'table-wrap' }, h('table', {},
    h('thead', {}, h('tr', {}, headers.map((t) => h('th', {}, t)))),
    h('tbody', {}, rows.map((cells) => h('tr', {}, cells.map((c) => h('td', {}, c)))))));
}

function loginView() {
  const username = h('input', { autocomplete: 'username', required: true });
  const password = h('input', { type: 'password', autocomplete: 'current-password', required: true });
  const error = errorLine();
  const form = h('form', {
    class: 'panel login',
    onsubmit: async (e) => {
      e.preventDefault();
      try {
        state.user = await api('POST', '/api/login', { username: username.value, password: password.value });
        render();
      } catch (err) {
        error.textContent = err.message;
      }
    },
  },
  h('h2', {}, 'Hauswart'),
  h('label', {}, 'Benutzername', username),
  h('label', {}, 'Passwort', password),
  h('button', { type: 'submit' }, 'Anmelden'),
  error);
  return form;
}

async function devicesView() {
  const isAdmin = state.user.role === 'admin';
  const devices = await api('GET', '/api/devices');
  const now = Date.now() / 1000;
  const enrollOut = h('div');

  const cards = devices.map((d) => {
    const online = !d.revoked && now - d.last_seen < ONLINE_SECONDS;
    const label = d.revoked ? 'gesperrt' : online ? 'online' : 'offline';
    const cls = d.revoked ? 'status-bad' : online ? 'status-ok' : 'muted';
    const r = d.report;
    return h('div', { class: 'panel' },
      h('div', { class: 'row spread' }, h('h3', {}, d.hostname), h('span', { class: cls + ' small' }, label)),
      r && [
        h('p', { class: 'muted small' }, `${r.distro || 'unbekannt'} · Kernel ${r.kernel || '–'}`),
        meter('Arbeitsspeicher', r.mem_used, r.mem_total),
        meter('Festplatte', r.disk_used, r.disk_total),
        h('p', { class: 'muted small' }, `Last ${(r.load1 || 0).toFixed(2)} auf ${r.cpus || '?'} Kernen · ${(r.backends || []).join(', ') || 'kein Paketmanager'}`),
      ],
      isAdmin && !d.revoked && h('div', { class: 'row' },
        h('button', { onclick: () => show(() => taskView(d)) }, 'Aktion'),
        h('button', {
          class: 'danger',
          onclick: async () => {
            if (!confirm(`${d.hostname} wirklich sperren? Das Gerät muss danach neu angemeldet werden.`)) return;
            await api('POST', `/api/devices/${d.id}/revoke`);
            render();
          },
        }, 'Sperren')));
  });

  return [
    h('div', { class: 'row spread' }, h('h2', {}, 'Geräte'),
      isAdmin && h('button', {
        class: 'secondary',
        onclick: async () => {
          const out = await api('POST', '/api/enroll-tokens');
          enrollOut.replaceChildren(h('div', { class: 'panel' },
            h('p', { class: 'small muted' }, 'Auf dem neuen Gerät ausführen. Der Befehl gilt einmal und eine Stunde lang:'),
            h('pre', {}, out.command)));
        },
      }, 'Gerät hinzufügen')),
    enrollOut,
    devices.length ? h('div', { class: 'grid' }, cards) : h('p', { class: 'muted' }, 'Noch keine Geräte angemeldet.'),
  ];
}

function taskView(device) {
  const select = h('select', {}, Object.entries(TASKS).map(([k, t]) => h('option', { value: k }, t.label)));
  const fields = h('div');
  const error = errorLine();
  let inputs = {};

  function renderFields() {
    inputs = {};
    fields.replaceChildren(...TASKS[select.value].fields.map(([name, label, kind]) => {
      inputs[name] = h(kind === 'textarea' ? 'textarea' : 'input', {});
      return h('label', {}, label, inputs[name]);
    }));
  }
  select.addEventListener('change', renderFields);
  renderFields();

  return [
    h('h2', {}, `Aktion für ${device.hostname}`),
    h('form', {
      class: 'panel',
      onsubmit: async (e) => {
        e.preventDefault();
        const values = Object.fromEntries(Object.entries(inputs).map(([k, el]) => [k, el.value]));
        try {
          await api('POST', `/api/devices/${device.id}/tasks`, { type: select.value, payload: buildPayload(select.value, values) });
          state.view = 'tasks';
          render();
        } catch (err) {
          error.textContent = err.message;
        }
      },
    },
    h('label', {}, 'Aktion', select),
    fields,
    h('div', { class: 'row' },
      h('button', { type: 'submit' }, 'Ausführen'),
      h('button', { type: 'button', class: 'secondary', onclick: render }, 'Abbrechen')),
    error),
  ];
}

async function requestsView() {
  const isAdmin = state.user.role === 'admin';
  const [requests, devices] = await Promise.all([api('GET', '/api/requests'), api('GET', '/api/devices')]);
  const active = devices.filter((d) => !d.revoked);
  const device = h('select', {}, active.map((d) => h('option', { value: d.id }, d.hostname)));
  const kind = h('select', {}, Object.entries(REQUEST_KINDS).map(([k, v]) => h('option', { value: k }, v)));
  const detail = h('input', { required: true });
  const detailLabel = h('span', {}, 'Paketnamen');
  const reason = h('input', {});
  const error = errorLine();
  kind.addEventListener('change', () => {
    detailLabel.textContent = kind.value === 'sudo' ? 'Dauer in Minuten' : 'Paketnamen';
  });

  const form = h('form', {
    class: 'panel',
    onsubmit: async (e) => {
      e.preventDefault();
      try {
        await api('POST', '/api/requests', { device_id: device.value, kind: kind.value, detail: detail.value, reason: reason.value });
        render();
      } catch (err) {
        error.textContent = err.message;
      }
    },
  },
  h('h3', {}, 'Neue Anfrage'),
  h('label', {}, 'Gerät', device),
  h('label', {}, 'Art', kind),
  h('label', {}, detailLabel, detail),
  h('label', {}, 'Begründung', reason),
  h('button', { type: 'submit', disabled: !active.length }, 'Anfragen'),
  error);

  const decide = (r, action) => async () => {
    try {
      await api('POST', `/api/requests/${r.id}/${action}`);
    } catch (err) {
      alert(err.message);
    }
    render();
  };
  const rows = requests.map((r) => [
    formatTime(r.created_at), r.username, r.hostname,
    `${REQUEST_KINDS[r.kind]}: ${r.detail}${r.kind === 'sudo' ? ' Min.' : ''}`,
    r.reason, statusText(r.status),
    isAdmin && r.status === 'open' ? h('div', { class: 'row' },
      h('button', { onclick: decide(r, 'approve') }, 'Freigeben'),
      h('button', { class: 'danger', onclick: decide(r, 'deny') }, 'Ablehnen')) : '',
  ]);

  return [
    h('h2', {}, 'Anfragen'),
    form,
    h('div', { class: 'panel' }, table(['Zeit', 'Von', 'Gerät', 'Anfrage', 'Begründung', 'Status', ''], rows, 'Keine Anfragen.')),
  ];
}

async function tasksView() {
  const [tasks, devices] = await Promise.all([api('GET', '/api/tasks'), api('GET', '/api/devices')]);
  const names = Object.fromEntries(devices.map((d) => [d.id, d.hostname]));
  const rows = tasks.map((t) => [
    formatTime(t.created_at), names[t.device_id] || t.device_id,
    (TASKS[t.type] && TASKS[t.type].label) || t.type,
    t.created_by, statusText(t.status),
    t.output ? h('details', {}, h('summary', {}, 'Ausgabe'), h('pre', {}, t.output)) : '',
  ]);
  return [h('h2', {}, 'Aufgaben'), h('div', { class: 'panel' },
    table(['Zeit', 'Gerät', 'Aktion', 'Von', 'Status', ''], rows, 'Noch keine Aufgaben.'))];
}

async function usersView() {
  const users = await api('GET', '/api/users');
  const username = h('input', { required: true });
  const linuxUser = h('input', {});
  const password = h('input', { type: 'password', autocomplete: 'new-password', required: true, minlength: 10 });
  const role = h('select', {}, h('option', { value: 'member' }, 'Mitglied'), h('option', { value: 'admin' }, 'Admin'));
  const error = errorLine();
  return [
    h('h2', {}, 'Benutzer'),
    h('form', {
      class: 'panel',
      onsubmit: async (e) => {
        e.preventDefault();
        try {
          await api('POST', '/api/users', { username: username.value, linux_user: linuxUser.value, password: password.value, role: role.value });
          render();
        } catch (err) {
          error.textContent = err.message;
        }
      },
    },
    h('h3', {}, 'Neuer Benutzer'),
    h('label', {}, 'Benutzername', username),
    h('label', {}, 'Linux-Benutzer (leer = gleich)', linuxUser),
    h('label', {}, 'Passwort (mindestens 10 Zeichen)', password),
    h('label', {}, 'Rolle', role),
    h('button', { type: 'submit' }, 'Anlegen'),
    error),
    h('div', { class: 'panel' }, table(['Benutzer', 'Linux-Benutzer', 'Rolle'],
      users.map((u) => [u.username, u.linux_user, u.role === 'admin' ? 'Admin' : 'Mitglied']), 'Keine Benutzer.')),
  ];
}

async function auditView() {
  const entries = await api('GET', '/api/audit');
  return [h('h2', {}, 'Protokoll'), h('div', { class: 'panel' },
    table(['Zeit', 'Von', 'Aktion', 'Details'],
      entries.map((e) => [formatTime(e.ts), e.actor, e.action, e.detail]), 'Noch keine Einträge.'))];
}

const VIEWS = {
  devices: { label: 'Geräte', load: devicesView },
  requests: { label: 'Anfragen', load: requestsView },
  tasks: { label: 'Aufgaben', load: tasksView, admin: true },
  users: { label: 'Benutzer', load: usersView, admin: true },
  audit: { label: 'Protokoll', load: auditView, admin: true },
};

const content = h('main');

async function show(load) {
  try {
    content.replaceChildren(...[await load()].flat(Infinity).filter(Boolean));
  } catch (err) {
    if (state.user) content.replaceChildren(h('p', { class: 'error', role: 'alert' }, err.message));
  }
}

function render() {
  if (!state.user) {
    app.replaceChildren(loginView());
    return;
  }
  const isAdmin = state.user.role === 'admin';
  const entries = Object.entries(VIEWS).filter(([, v]) => isAdmin || !v.admin);
  app.replaceChildren(
    h('header', {},
      h('strong', {}, 'Hauswart'),
      h('nav', {}, entries.map(([key, v]) => h('button', {
        class: key === state.view ? 'active' : '',
        onclick: () => { state.view = key; render(); },
      }, v.label))),
      h('span', { class: 'muted small' }, state.user.username),
      h('button', {
        class: 'secondary',
        onclick: async () => {
          await api('POST', '/api/logout');
          state.user = null;
          render();
        },
      }, 'Abmelden')),
    content);
  show(VIEWS[state.view].load);
}

api('GET', '/api/me').then((user) => {
  state.user = user;
  render();
}).catch(() => render());
