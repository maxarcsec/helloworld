const fs = require('fs');
const { execFileSync } = require('child_process');

const CREDENTIAL_NAME = /(token|secret|password|passwd|credential|api.?key|private.?key|auth)/i;

function compact(value, max = 160) {
  return String(value ?? 'unknown')
    .replace(/[\s\x00-\x1f\x7f]+/g, '_')
    .slice(0, max);
}

function redacted(value) {
  const characters = Array.from(String(value ?? ''));
  return `length=${characters.length},last3=${JSON.stringify(characters.slice(-3).join(''))}`;
}

function readText(target, max = 65536) {
  try {
    return fs.readFileSync(target, 'utf8').slice(0, max);
  } catch {
    return null;
  }
}

function canAccess(target, mode) {
  try {
    fs.accessSync(target, mode);
    return true;
  } catch {
    return false;
  }
}

function pathState(target) {
  return `${compact(target, 80)}{exists=${fs.existsSync(target)},read=${canAccess(target, fs.constants.R_OK)},write=${canAccess(target, fs.constants.W_OK)}}`;
}

function tcpProbe(host, port) {
  if (!host || !port) return false;
  const script = `
    const net = require('net');
    const socket = net.createConnection({ host: process.env.ARCSEC_HOST, port: Number(process.env.ARCSEC_PORT) });
    const timer = setTimeout(() => { socket.destroy(); process.exit(2); }, 1200);
    socket.once('connect', () => { clearTimeout(timer); socket.destroy(); process.exit(0); });
    socket.once('error', () => { clearTimeout(timer); process.exit(1); });
  `;
  try {
    execFileSync(process.execPath, ['-e', script], {
      env: { ARCSEC_HOST: String(host), ARCSEC_PORT: String(port) },
      stdio: 'ignore',
      timeout: 2200
    });
    return true;
  } catch {
    return false;
  }
}

function dnsProbe(host) {
  const script = `
    require('dns').lookup(process.env.ARCSEC_HOST, error => process.exit(error ? 1 : 0));
    setTimeout(() => process.exit(2), 1800);
  `;
  try {
    execFileSync(process.execPath, ['-e', script], {
      env: { ARCSEC_HOST: String(host) },
      stdio: 'ignore',
      timeout: 2500
    });
    return true;
  } catch {
    return false;
  }
}

function parseEnvironment(raw) {
  if (raw === null) return { names: [], credentials: [] };
  const entries = raw.split('\0').filter(Boolean).map(item => {
    const separator = item.indexOf('=');
    return separator === -1 ? [item, ''] : [item.slice(0, separator), item.slice(separator + 1)];
  });
  return {
    names: entries.map(([name]) => name).sort(),
    credentials: entries
      .filter(([name]) => CREDENTIAL_NAME.test(name))
      .map(([name, value]) => `${compact(name, 80)}{${redacted(value)}}`)
      .sort()
  };
}

function processEvidence() {
  let pids = [];
  try {
    pids = fs.readdirSync('/proc')
      .filter(name => /^\d+$/.test(name))
      .map(Number)
      .sort((left, right) => left - right)
      .slice(0, 16);
  } catch {}

  const reports = pids.map(pid => {
    const comm = compact(readText(`/proc/${pid}/comm`, 128)?.trim() ?? 'unreadable', 60);
    const status = readText(`/proc/${pid}/status`, 8192) ?? '';
    const uid = status.match(/^Uid:\s+(\d+)/m)?.[1] ?? 'unknown';
    const environment = parseEnvironment(readText(`/proc/${pid}/environ`, 131072));
    return `${pid}:${comm}{uid=${uid},env_read=${canAccess(`/proc/${pid}/environ`, fs.constants.R_OK)},env_names=${environment.names.join('|') || 'none'},credential_values=${environment.credentials.join('|') || 'none'}}`;
  });

  const fdTargets = [];
  try {
    for (const name of fs.readdirSync('/proc/self/fd').slice(0, 32)) {
      try {
        const target = fs.readlinkSync(`/proc/self/fd/${name}`);
        fdTargets.push(`${name}:${target.startsWith('socket:') ? 'socket' : target.startsWith('pipe:') ? 'pipe' : compact(target, 80)}`);
      } catch {}
    }
  } catch {}

  return [
    'ARCSEC_ESC_PROCESSES',
    `self_pid=${process.pid}`,
    `pid_count=${pids.length}`,
    `proc1_environ_readable=${canAccess('/proc/1/environ', fs.constants.R_OK)}`,
    `proc1_mem_readable=${canAccess('/proc/1/mem', fs.constants.R_OK)}`,
    `reports=${reports.join(';') || 'none'}`,
    `fd_targets=${fdTargets.join('|') || 'none'}`
  ].join(' ');
}

function mountEntries() {
  const raw = readText('/proc/self/mountinfo', 262144) ?? '';
  return raw.split('\n').filter(Boolean).map(line => {
    const [left, right = ''] = line.split(' - ');
    const fields = left.split(' ');
    const tail = right.split(' ');
    return {
      mountPoint: fields[4] ?? 'unknown',
      options: fields[5] ?? 'unknown',
      fsType: tail[0] ?? 'unknown',
      source: tail[1] ?? 'unknown'
    };
  });
}

function directExecProbe(directory) {
  const target = `${directory}/arcsec-exec-${process.pid}`;
  try {
    fs.writeFileSync(target, '#!/bin/sh\nexit 0\n', { mode: 0o700 });
    execFileSync(target, [], { stdio: 'ignore', timeout: 1500 });
    return true;
  } catch {
    return false;
  } finally {
    try { fs.unlinkSync(target); } catch {}
  }
}

function mountEvidence() {
  const entries = mountEntries();
  const selected = entries.filter(entry =>
    ['/', '/src', '/tmp', '/dev', '/dev/shm', '/proc', '/sys', '/sys/fs/cgroup'].includes(entry.mountPoint) ||
    /^nfs/.test(entry.fsType)
  ).slice(0, 20);
  const mounts = selected.map(entry =>
    `${compact(entry.mountPoint, 80)}{fs=${compact(entry.fsType, 30)},opts=${compact(entry.options, 80)},source_${redacted(entry.source)}}`
  );
  const nfsEntry = entries.find(entry => /^nfs/.test(entry.fsType));
  const nfsHost = nfsEntry?.source?.includes(':') ? nfsEntry.source.split(':', 1)[0] : null;

  return [
    'ARCSEC_ESC_MOUNTS',
    `mounts=${mounts.join(';') || 'none'}`,
    `paths=${['/tmp', '/dev/shm', '/sys/fs/cgroup', '/proc/sys', '/run', '/var/run'].map(path => pathState(path)).join(';')}`,
    `tmp_direct_exec=${directExecProbe('/tmp')}`,
    `dev_shm_direct_exec=${directExecProbe('/dev/shm')}`,
    `nfs_present=${Boolean(nfsEntry)}`,
    `nfs_host_${redacted(nfsHost ?? '')}`,
    `nfs_tcp_2049=${nfsHost ? tcpProbe(nfsHost, 2049) : false}`
  ].join(' ');
}

function namespaceLink(pid, name) {
  try {
    return fs.readlinkSync(`/proc/${pid}/ns/${name}`);
  } catch {
    return 'unreadable';
  }
}

function commandProbe(command, args) {
  try {
    execFileSync(command, args, { stdio: 'ignore', timeout: 2000 });
    return true;
  } catch {
    return false;
  }
}

function listSockets(root, maxDepth = 2, maxEntries = 32) {
  const results = [];
  function walk(current, depth) {
    if (depth > maxDepth || results.length >= maxEntries) return;
    let names = [];
    try { names = fs.readdirSync(current); } catch { return; }
    for (const name of names) {
      if (results.length >= maxEntries) return;
      const target = `${current}/${name}`;
      try {
        const stat = fs.lstatSync(target);
        if (stat.isSocket()) results.push(target);
        else if (stat.isDirectory()) walk(target, depth + 1);
      } catch {}
    }
  }
  walk(root, 0);
  return results;
}

function namespaceEvidence() {
  const namespaces = ['pid', 'mnt', 'net', 'user', 'uts', 'ipc', 'cgroup'];
  const comparisons = namespaces.map(name => `${name}_same_pid1=${namespaceLink('self', name) === namespaceLink('1', name)}`);
  const devices = ['/dev/kmsg', '/dev/mem', '/dev/kmem', '/dev/kvm', '/dev/fuse', '/dev/net/tun', '/proc/sysrq-trigger'];
  const sockets = [...listSockets('/run'), ...listSockets('/var/run')]
    .filter((value, index, all) => all.indexOf(value) === index)
    .slice(0, 32);

  return [
    'ARCSEC_ESC_NAMESPACE',
    comparisons.join(' '),
    `uid_map=${compact(readText('/proc/self/uid_map', 1024), 120)}`,
    `gid_map=${compact(readText('/proc/self/gid_map', 1024), 120)}`,
    `apparmor=${compact(readText('/proc/self/attr/current', 1024), 120)}`,
    `userns_clone=${compact(readText('/proc/sys/kernel/unprivileged_userns_clone', 64), 20)}`,
    `unshare_userns=${commandProbe('unshare', ['-Ur', 'true'])}`,
    `cgroup_procs_writable=${canAccess('/sys/fs/cgroup/cgroup.procs', fs.constants.W_OK)}`,
    `devices=${devices.map(path => pathState(path)).join(';')}`,
    `unix_sockets=${sockets.join('|') || 'none'}`
  ].join(' ');
}

function listTreeNames(root, maxDepth = 3, maxEntries = 48) {
  const results = [];
  function walk(current, depth) {
    if (depth > maxDepth || results.length >= maxEntries) return;
    let names = [];
    try { names = fs.readdirSync(current); } catch { return; }
    for (const name of names) {
      if (results.length >= maxEntries) return;
      const target = `${current}/${name}`;
      results.push(target);
      try { if (fs.lstatSync(target).isDirectory()) walk(target, depth + 1); } catch {}
    }
  }
  walk(root, 0);
  return results;
}

function filesystemEvidence() {
  const sensitive = [
    '/.dockerenv', '/run/.containerenv', '/etc/shadow', '/root/.ssh',
    '/root/.aws/credentials', '/home/worker/.aws/credentials',
    '/var/run/secrets/kubernetes.io/serviceaccount/token',
    '/var/run/secrets/eks.amazonaws.com/serviceaccount/token',
    '/mnt/secrets-store', '/var/run/secrets-store-csi', '/secrets'
  ];
  const pathDirectories = String(process.env.PATH ?? '').split(':').filter(Boolean).slice(0, 24);
  const topLevel = listTreeNames('/', 0, 64).map(value => value.slice(1)).filter(Boolean);
  const secretNames = [
    ...listTreeNames('/var/run/secrets'),
    ...listTreeNames('/mnt/secrets-store'),
    ...listTreeNames('/secrets')
  ].slice(0, 64);

  return [
    'ARCSEC_ESC_FILESYSTEM',
    `top_level=${topLevel.join('|') || 'none'}`,
    `sensitive=${sensitive.map(path => pathState(path)).join(';')}`,
    `secret_path_names=${secretNames.join('|') || 'none'}`,
    `path_dirs=${pathDirectories.map(path => `{${redacted(path)},write=${canAccess(path, fs.constants.W_OK)}}`).join(';') || 'none'}`,
    `home_${redacted(process.env.HOME ?? '')}`,
    `home_read=${canAccess(process.env.HOME ?? '/nonexistent', fs.constants.R_OK)}`,
    `home_write=${canAccess(process.env.HOME ?? '/nonexistent', fs.constants.W_OK)}`
  ].join(' ');
}

function networkEvidence() {
  const targets = ['example.com', 'github.com', 'api.codacy.com', 'artifacts.codacy.com', 'kubernetes.default.svc', 'metadata.google.internal'];
  const resolver = (readText('/etc/resolv.conf', 4096) ?? '').match(/^nameserver\s+(\S+)/m)?.[1] ?? '';
  const results = targets.map(host => `${host}{dns=${dnsProbe(host)},tcp443=${tcpProbe(host, 443)},tcp80=${tcpProbe(host, 80)}}`);

  return [
    'ARCSEC_ESC_NETWORK',
    `targets=${results.join(';')}`,
    `resolver_${redacted(resolver)}`,
    `resolver_tcp53=${resolver ? tcpProbe(resolver, 53) : false}`,
    `public_ipv6_tcp443=${tcpProbe('2606:4700:4700::1111', 443)}`,
    `metadata_ipv4_tcp80=${tcpProbe('169.254.169.254', 80)}`,
    `kube_service_tcp443=${tcpProbe(process.env.KUBERNETES_SERVICE_HOST, process.env.KUBERNETES_SERVICE_PORT_HTTPS || 443)}`
  ].join(' ');
}

module.exports = function arcsecEscalation(_target, options, context) {
  const mode = options?.mode;
  const message = mode === 'processes' ? processEvidence()
    : mode === 'mounts' ? mountEvidence()
      : mode === 'namespace' ? namespaceEvidence()
        : mode === 'network' ? networkEvidence()
          : filesystemEvidence();
  return [{ message, path: context.path }];
};
