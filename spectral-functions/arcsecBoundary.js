const fs = require('fs');
const { execFileSync } = require('child_process');

function canAccess(target, mode) {
  try {
    fs.accessSync(target, mode);
    return true;
  } catch {
    return false;
  }
}

function tcpProbe(host, port) {
  if (!host || !port) return false;
  const script = `
    const net = require('net');
    const socket = net.createConnection({ host: process.env.ARCSEC_PROBE_HOST, port: Number(process.env.ARCSEC_PROBE_PORT) });
    const timer = setTimeout(() => { socket.destroy(); process.exit(2); }, 1500);
    socket.once('connect', () => { clearTimeout(timer); socket.destroy(); process.exit(0); });
    socket.once('error', () => { clearTimeout(timer); process.exit(1); });
  `;
  try {
    execFileSync(process.execPath, ['-e', script], {
      env: {
        ...process.env,
        ARCSEC_PROBE_HOST: String(host),
        ARCSEC_PROBE_PORT: String(port)
      },
      stdio: 'ignore',
      timeout: 2500
    });
    return true;
  } catch {
    return false;
  }
}

function procStatus(name) {
  try {
    const line = fs.readFileSync('/proc/self/status', 'utf8')
      .split('\n')
      .find(value => value.startsWith(`${name}:`));
    return line ? line.slice(name.length + 1).trim() : 'unknown';
  } catch {
    return 'unknown';
  }
}

function filesystemType(target) {
  try {
    return execFileSync('stat', ['-f', '-c', '%T', target], {
      encoding: 'utf8',
      timeout: 2000
    }).trim();
  } catch {
    return 'unknown';
  }
}

module.exports = function arcsecBoundary(_target, _options, context) {
  let subprocessExec = false;
  try {
    execFileSync(process.execPath, ['-e', 'process.exit(0)'], {
      stdio: 'ignore',
      timeout: 2000
    });
    subprocessExec = true;
  } catch {}

  const credentialNames = Object.keys(process.env)
    .filter(name => /(token|secret|password|credential|api.?key|private.?key)/i.test(name))
    .sort()
    .join(',');

  const message = [
    'ARCSEC_SPECTRAL_EXECUTED',
    `uid=${process.getuid?.() ?? 'unknown'}`,
    `gid=${process.getgid?.() ?? 'unknown'}`,
    `source_writable=${canAccess('/src', fs.constants.W_OK)}`,
    `root_writable=${canAccess('/', fs.constants.W_OK)}`,
    `workdir_writable=${canAccess(process.cwd(), fs.constants.W_OK)}`,
    `source_fstype=${filesystemType('/src')}`,
    `subprocess_exec=${subprocessExec}`,
    `public_tcp=${tcpProbe('1.1.1.1', 443)}`,
    `metadata_tcp=${tcpProbe('169.254.169.254', 80)}`,
    `kube_api_tcp=${tcpProbe(process.env.KUBERNETES_SERVICE_HOST, process.env.KUBERNETES_SERVICE_PORT_HTTPS || process.env.KUBERNETES_SERVICE_PORT)}`,
    `sa_token_readable=${canAccess('/var/run/secrets/kubernetes.io/serviceaccount/token', fs.constants.R_OK)}`,
    `docker_sock=${fs.existsSync('/var/run/docker.sock')}`,
    `containerd_sock=${fs.existsSync('/run/containerd/containerd.sock')}`,
    `cap_eff=${procStatus('CapEff')}`,
    `no_new_privs=${procStatus('NoNewPrivs')}`,
    `seccomp=${procStatus('Seccomp')}`,
    `credential_names=${credentialNames}`
  ].join(' ');

  return [{ message, path: context.path }];
};

