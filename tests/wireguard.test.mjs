import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { chmod, mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import https from 'node:https';
import { deriveTestKeys, testSetupToken } from './auth-helper.mjs';
import { protectPackage } from './claim-helper.mjs';

const root = resolve(import.meta.dirname, '..');
const docker = (...args) => execFileSync('docker', args, {
  encoding: 'utf8', timeout: 120000, stdio: ['ignore', 'pipe', 'pipe'],
}).trim();

function publicRequest(port, ca, path, method = 'GET', headers = {}) {
  return new Promise((resolve, reject) => {
    const req = https.request({ hostname: '127.0.0.1', servername: 'vault.example', port,
      ca, path, method, headers: { Host: 'vault.example', ...headers }, timeout: 5000 }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
    });
    req.on('timeout', () => req.destroy(new Error('public TLS request timed out')));
    req.on('error', reject);
    req.end();
  });
}

test('real WireGuard tunnel reaches admin HTTPS but cannot forward to the backend or publish admin TCP', { timeout: 240000 }, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'vault-wireguard-'));
  // Permit hardened root to traverse runner-owned fixtures without listing the directory.
  await chmod(dir, 0o711);
  const project = `vault-wireguard-${process.pid}`;
  const peer = `${project}-peer`;
  const file = join(dir, 'compose.json');
  const compose = (...args) => docker('compose', '-p', project, '-f', file, ...args);
  let created = false;
  let peerCreated = false;
  try {
    const config = JSON.parse(execFileSync('docker', ['compose', '--env-file', '/dev/null',
      '-f', join(root, 'compose.yaml'), 'config', '--format', 'json'], {
      encoding: 'utf8', timeout: 60000,
      env: { ...process.env, ACME_EMAIL: 'test@example.com', PUBLIC_BIND_IP: '127.0.0.1',
        DOMAIN: 'vault.example', VPN_BIND_IP: '10.13.13.1', WIREGUARD_PORT: '51821',
        WIREGUARD_SUBNET: '10.13.13.0/24', WIREGUARD_PEERS: 'admin', WIREGUARD_ENDPOINT: 'vault.example' },
    }));
    delete config.name;
    const { services, networks, volumes } = config;
    for (const service of Object.values(services)) {
      service.restart = 'no';
      // Compose's JSON renderer omits both zero-valued fields for a core limit of zero.
      service.ulimits.core = 0;
    }
    for (const network of Object.values(networks)) delete network.name;
    // Disposable stand-in for the webserver repo's shared network; this test
    // reaches public Caddy through its own loopback ports instead.
    networks.webserver = {};
    for (const volume of Object.values(volumes)) delete volume.name;
    networks.backend.ipam.config[0].subnet = '172.28.0.0/25';
    networks.vpn_backend.ipam.config[0].subnet = '172.28.0.128/25';
    services.api.networks.backend.ipv4_address = '172.28.0.2';
    services.api.networks.vpn_backend.ipv4_address = '172.28.0.130';
    Object.assign(services.api.environment, {
      PUBLIC_LISTEN_ADDR: '172.28.0.2:8080', ADMIN_LISTEN_ADDR: '172.28.0.130:8081',
      ADMIN_PROXY_IP: '172.28.0.131', TRUSTED_PROXY_CIDR: '172.28.0.0/24',
      ADMIN_SETUP_TOKEN: testSetupToken, ADMIN_USER: 'admin', PUBLIC_ORIGIN: 'https://vault.example',
    });
    services.wireguard.networks.vpn_backend.ipv4_address = '172.28.0.131';
    services.wireguard.ports = [{ target: 51820, published: '0', host_ip: '127.0.0.1', protocol: 'udp' }];
    services['caddy-vpn'].environment.API_UPSTREAM = '172.28.0.130:8081';
    services.caddy.environment.API_UPSTREAM = '172.28.0.2:8080';
    services.caddy.ports = [80, 443].map(target => ({ target, published: '0', host_ip: '127.0.0.1', protocol: 'tcp' }));
    const image = services.caddy.image;
    const publicConfig = JSON.parse(docker('run', '--rm', '-e', 'DOMAIN=vault.example',
      '-e', 'ACME_EMAIL=test@example.com', '-e', 'PUBLIC_ORIGIN=https://vault.example',
      '-e', 'API_UPSTREAM=172.28.0.2:8080',
      '-v', `${join(root, 'Caddyfile')}:/etc/caddy/Caddyfile:ro`,
      '-v', `${join(root, 'Caddyfile.common')}:/etc/caddy/common.caddy:ro`,
      image, 'caddy', 'adapt', '--config', '/etc/caddy/Caddyfile', '--adapter', 'caddyfile'));
    for (const policy of publicConfig.apps.tls.automation.policies) policy.issuers = [{ module: 'internal' }];
    await writeFile(join(dir, 'public.json'), JSON.stringify(publicConfig), { mode: 0o644 });
    services.caddy.volumes = services.caddy.volumes.filter(volume => volume.target !== '/etc/caddy/Caddyfile');
    services.caddy.volumes.push({ type: 'bind', source: join(dir, 'public.json'), target: '/etc/caddy/test.json', read_only: true });
    services.caddy.command = ['caddy', 'run', '--config', '/etc/caddy/test.json'];
    await writeFile(file, JSON.stringify(config), { mode: 0o644 });
    compose('config', '--quiet');
    docker('run', '--rm', '-e', 'CGO_ENABLED=0', '-e', 'GOTELEMETRY=off',
      '-v', `${root}:/src:ro`, '-v', `${dir}:/out`, '-w', '/src', 'golang:1.26-alpine',
      'go', 'build', '-o', '/out/probe', './tests/vpn-probe.go');
    created = true;
    try {
      compose('up', '--build', '-d', '--wait', '--wait-timeout', '60');
    } catch (error) {
      throw new Error(`${error.message}\n${compose('logs', '--no-color', '--tail', '20')}`);
    }
    const vpn = compose('ps', '-q', 'caddy-vpn');
    const gateway = compose('ps', '-q', 'wireguard');
    const pub = compose('ps', '-q', 'caddy');
    const [gatewayState] = JSON.parse(docker('inspect', gateway));
    const [vpnState] = JSON.parse(docker('inspect', vpn));
    assert.equal(vpnState.HostConfig.NetworkMode, `container:${gateway}`);
    assert.ok(!vpnState.HostConfig.PortBindings || Object.keys(vpnState.HostConfig.PortBindings).length === 0);
    assert.equal(gatewayState.NetworkSettings.Ports['51820/udp'][0].HostIp, '127.0.0.1');
    assert.deepEqual(Object.keys(gatewayState.NetworkSettings.Ports), ['51820/udp']);
    const ingress = Object.entries(gatewayState.NetworkSettings.Networks).find(([name]) => name.endsWith('_vpn_ingress'));
    assert.ok(ingress);
    const gatewayIP = ingress[1].IPAddress;
    docker('cp', `${gateway}:/config/peers/admin/admin.conf`, join(dir, 'wg0.conf'));
    const originalProfile = await readFile(join(dir, 'wg0.conf'), 'utf8');
    assert.match(originalProfile, /Endpoint\s*=\s*vault\.example:51821/);
    assert.match(originalProfile, /AllowedIPs\s*=\s*10\.13\.13\.1\/32/);
    // Exercise the real encrypted tunnel on its Docker ingress; loopback-published UDP is inspected above.
    await writeFile(join(dir, 'wg0.conf'), originalProfile.replace(/^Endpoint\s*=.*$/m, `Endpoint = ${gatewayIP}:51820`), { mode: 0o600 });
    const [runtime] = JSON.parse(docker('inspect', gateway));
    // The peer runs as root with no DAC override; keep its private key root-only, not world-readable.
    docker('run', '--rm', '--cap-drop', 'ALL', '--cap-add', 'CHOWN',
      '-v', `${dir}:/test`, runtime.Config.Image, 'chown', '0:0', '/test/wg0.conf');
    docker('run', '-d', '--name', peer, '--network', ingress[0], '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN',
      '--security-opt', 'no-new-privileges:true', '--read-only', '--tmpfs', '/tmp',
      '-v', `${dir}:/test:ro`, '--entrypoint', '/bin/sh', runtime.Config.Image,
      '-c', 'wg-quick up /test/wg0.conf && exec sleep infinity');
    peerCreated = true;
    const probe = (url, method = 'GET', body = '', headers = {}, ca = '/test/vpn-root.crt') => JSON.parse(execFileSync('docker',
      ['exec', '-i', peer, '/test/probe', ca], {
        input: JSON.stringify({ url, method, body, headers }), encoding: 'utf8', timeout: 15000,
      }));
    docker('cp', `${vpn}:/data/caddy/pki/authorities/local/root.crt`, join(dir, 'vpn-root.crt'));
    docker('cp', `${pub}:/data/caddy/pki/authorities/local/root.crt`, join(dir, 'public-root.crt'));
    // These are public trust certificates, not CA private keys or peer credentials.
    await chmod(join(dir, 'vpn-root.crt'), 0o644);
    await chmod(join(dir, 'public-root.crt'), 0o644);
    let admin;
    for (let attempt = 0; attempt < 30; attempt++) {
      admin = probe('https://10.13.13.1/admin');
      if (admin.status === 200) break;
      await new Promise(resolve => setTimeout(resolve, 200));
    }
    assert.equal(admin.status, 200, admin.error);
    assert.match(admin.body, /id="login-form"/);
    assert.match(probe('https://10.13.13.1/admin', 'GET', '', {}, '/test/public-root.crt').error, /certificate|authority/);
    const redirect = probe('http://10.13.13.1/admin?test=1');
    assert.equal(redirect.status, 308);
    assert.deepEqual(redirect.headers.Location, ['https://10.13.13.1/admin?test=1']);
    const info = JSON.parse(probe('https://10.13.13.1/admin/api/auth').body);
    const keys = await deriveTestKeys('integration-admin-password-with-zero-server-knowledge', info.labelKey);
    assert.equal(probe('https://10.13.13.1/admin/api/setup', 'POST', JSON.stringify({
      setupToken: testSetupToken, authentication: keys.authentication,
    }), { 'Content-Type': 'application/json' }).status, 204);
    const auth = { Authorization: `Basic ${Buffer.from(`admin:${keys.authentication}`).toString('base64')}` };
    const createdPackage = probe('https://10.13.13.1/admin/api/packages', 'POST', '{"ttlSeconds":3600}', auth);
    assert.equal(createdPackage.status, 201, createdPackage.body);
    const p = await protectPackage(JSON.parse(createdPackage.body));
    assert.equal(probe(`https://10.13.13.1/admin/api/packages/${p.id}/chunks/0`, 'PUT', 'x'.repeat(32), {
      ...auth, 'X-Upload-Token': p.uploadToken,
    }).status, 204);
    assert.equal(probe(`https://10.13.13.1/admin/api/packages/${p.id}/finalize`, 'POST',
      JSON.stringify({ chunks: 1, claimHash: p.claimHash }), { ...auth, 'X-Upload-Token': p.uploadToken }).status, 204);
    const [publicState] = JSON.parse(docker('inspect', pub));
    const publicPort = Number(publicState.NetworkSettings.Ports['443/tcp'][0].HostPort);
    const ca = await readFile(join(dir, 'public-root.crt'));
    for (const path of ['/admin', '/admin/api/auth', '/api/admin/packages', '/admin.js']) {
      assert.equal((await publicRequest(publicPort, ca, path)).status, 404);
    }
    assert.equal((await publicRequest(publicPort, ca, `/api/packages/${p.id}`)).status, 200);
    const claimed = await publicRequest(publicPort, ca, `/api/packages/${p.id}/consume`, 'POST', p.claimHeaders);
    assert.equal(claimed.status, 200);
    assert.equal(claimed.body.length, 36);
    assert.ok(docker('exec', gateway, 'wg', 'show', 'wg0', 'latest-handshakes').split(/\s+/).some(value => /^\d+$/.test(value) && Number(value) > 0));
    for (const port of [80, 443]) {
      assert.ok(probe(`http://${gatewayIP}:${port}/admin`).error, 'admin must not listen on the ingress bridge');
    }
    const serverKey = docker('exec', peer, 'wg', 'show', 'wg0', 'peers');
    docker('exec', peer, 'wg', 'set', 'wg0', 'peer', serverKey, 'allowed-ips', '0.0.0.0/0');
    docker('exec', peer, 'ip', 'route', 'add', '172.28.0.130/32', 'dev', 'wg0');
    assert.ok(probe('http://172.28.0.130:8081/healthz').error, 'even a manually rerouted peer must not reach the backend');
    assert.equal(probe('https://10.13.13.1/admin').status, 200, 'blocked forwarding must not break local administration');
  } finally {
    try {
      if (peerCreated) docker('rm', '-f', '-v', peer);
      if (created) compose('down', '-v', '--remove-orphans');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
});
