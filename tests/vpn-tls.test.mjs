import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import https from 'node:https';
import http from 'node:http';
import { checkServerIdentity } from 'node:tls';

const root = resolve(import.meta.dirname, '..');
const docker = (...args) => execFileSync('docker', args, { encoding: 'utf8', timeout: 60000, stdio: ['ignore', 'pipe', 'pipe'] }).trim();

function request(port, path, hostname, ca, sendSNI = true, hostHeader = hostname) {
  return new Promise((resolve, reject) => {
    const req = https.get({
      hostname: '127.0.0.1', port, path, ca,
      servername: sendSNI ? hostname : '',
      checkServerIdentity: (_, cert) => checkServerIdentity(hostname, cert),
      headers: { Host: hostHeader }, timeout: 5000,
    }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    req.on('timeout', () => req.destroy(new Error('TLS request timed out')));
    req.on('error', reject);
  });
}

function plainRequest(port, path, host) {
  return new Promise((resolve, reject) => {
    const req = http.get({ hostname: '127.0.0.1', port, path, headers: { Host: host }, timeout: 5000 }, res => {
      res.resume();
      res.on('end', () => resolve(res));
    });
    req.on('timeout', () => req.destroy(new Error('HTTP request timed out')));
    req.on('error', reject);
  });
}

test('production VPN IP serves admin while public listeners abort IP and unknown-host requests', { timeout: 90000 }, async () => {
  const compose = await readFile(join(root, 'compose.yaml'), 'utf8');
  const image = /image: (caddy:[^\s]+)/.exec(compose)[1];
  const { services, networks } = JSON.parse(execFileSync('docker', [
    'compose', '--env-file', '/dev/null', '-f', join(root, 'compose.yaml'), 'config', '--format', 'json',
  ], {
    encoding: 'utf8', timeout: 60000,
    env: { ...process.env, ACME_EMAIL: 'test@example.com', PUBLIC_BIND_IP: '192.0.2.10' },
  }));
  const dir = await mkdtemp(join(tmpdir(), 'vault-vpn-tls-'));
  const name = `vault-vpn-tls-${process.pid}`;
  const vpnName = `${name}-private`;
  const started = [];
  const testNetworks = new Map();
  try {
    for (const [container, config, expectedPorts] of [
      [name, 'Caddyfile', [80, 443]],
      [vpnName, 'Caddyfile.vpn', [80, 443]],
    ]) {
      const adapted = JSON.parse(docker('run', '--rm',
        '-e', 'DOMAIN=vault.example', '-e', 'VPN_BIND_IP=10.0.0.1',
        '-e', 'ACME_EMAIL=test@example.com', '-e', 'PUBLIC_ORIGIN=https://vault.example',
        '-v', `${join(root, config)}:/etc/caddy/Caddyfile:ro`,
        '-v', `${join(root, 'Caddyfile.common')}:/etc/caddy/common.caddy:ro`,
        image, 'caddy', 'adapt', '--config', '/etc/caddy/Caddyfile', '--adapter', 'caddyfile'));
      const listeners = Object.values(adapted.apps.http.servers).flatMap(server => server.listen).sort();
      assert.deepEqual(listeners, expectedPorts.map(port => `${container === vpnName ? '10.0.0.1' : ''}:${port}`).sort());
      if (container === vpnName) {
        // TLS/routing fixture only; wireguard.test.mjs exercises the unmodified tunnel-IP bindings.
        for (const server of Object.values(adapted.apps.http.servers)) {
          server.listen = server.listen.map(address => `:${address.split(':').at(-1)}`);
        }
      }
      const policies = adapted.apps.tls.automation.policies;
      if (container === vpnName) {
        const vpnPolicy = policies.find(policy => policy.subjects?.includes('10.0.0.1'));
        assert.equal(vpnPolicy.issuers[0].module, 'internal');
        assert.ok(!policies.some(policy => policy.subjects?.includes('vault.example')));
      } else {
        assert.ok(!policies.some(policy => policy.subjects?.includes('10.0.0.1')));
        assert.ok(!policies.find(policy => policy.subjects?.includes('vault.example'))?.issuers?.some(issuer => issuer.module === 'internal'));
        // Substitute only public issuance; production VPN policy and all routes stay unchanged.
        for (const policy of policies) policy.issuers = [{ module: 'internal' }];
      }
      await writeFile(join(dir, `${container}.json`), JSON.stringify(adapted));
      docker('run', '--rm', '-v', `${dir}:/test:ro`, image, 'caddy', 'validate', '--config', `/test/${container}.json`);
      const service = services[container === vpnName ? 'caddy-vpn' : 'caddy'];
      assert.equal(service.read_only, true);
      assert.deepEqual(service.cap_drop, ['ALL']);
      assert.ok(service.security_opt.includes('no-new-privileges:true'));
      const networkOwner = container === vpnName ? services.wireguard : service;
      for (const network of Object.keys(networkOwner.networks)) {
        if (!testNetworks.has(network)) {
          const networkName = `${name}-${network}`;
          docker('network', 'create', ...(networks[network].internal ? ['--internal'] : []), networkName);
          testNetworks.set(network, networkName);
        }
      }
      docker('run', '-d', '--name', container,
        ...Object.keys(networkOwner.networks).flatMap(network => ['--network', testNetworks.get(network)]),
        '--read-only', '-v', '/data', '-v', '/config',
        ...service.tmpfs.flatMap(mount => ['--tmpfs', mount]),
        ...service.cap_drop.flatMap(capability => ['--cap-drop', capability]),
        ...(service.cap_add || []).flatMap(capability => ['--cap-add', capability]),
        ...service.security_opt.flatMap(option => ['--security-opt', option]),
        ...expectedPorts.flatMap(port => ['-p', `127.0.0.1::${port}`]),
        '-v', `${dir}:/test:ro`, '-v', `${join(root, 'web')}:/srv:ro`,
        image, 'caddy', 'run', '--config', `/test/${container}.json`);
      started.push(container);
    }
    for (const container of started) {
      assert.equal(docker('inspect', '--format', '{{.State.Running}}', container), 'true',
        `${container} failed to start: ${docker('logs', container)}`);
    }
    const ports = JSON.parse(docker('inspect', '--format', '{{json .NetworkSettings.Ports}}', name));
    const vpnPorts = JSON.parse(docker('inspect', '--format', '{{json .NetworkSettings.Ports}}', vpnName));
    for (const [bindings, expectedPorts] of [[ports, [80, 443]], [vpnPorts, [80, 443]]]) {
      for (const port of expectedPorts) {
        assert.ok(bindings[`${port}/tcp`]?.length, `host port binding for ${port}/tcp is missing`);
      }
    }
    const publicPlainPort = Number(ports['80/tcp'][0].HostPort);
    const publicPort = Number(ports['443/tcp'][0].HostPort);
    const vpnPort = Number(vpnPorts['443/tcp'][0].HostPort);
    const httpPort = Number(vpnPorts['80/tcp'][0].HostPort);
    let ca;
    let vpnCA;
    let admin;
    for (let attempt = 0; attempt < 60; attempt++) {
      try {
        docker('cp', `${name}:/data/caddy/pki/authorities/local/root.crt`, join(dir, 'root.crt'));
        ca = await readFile(join(dir, 'root.crt'));
        docker('cp', `${vpnName}:/data/caddy/pki/authorities/local/root.crt`, join(dir, 'vpn-root.crt'));
        vpnCA = await readFile(join(dir, 'vpn-root.crt'));
        admin = await request(vpnPort, '/admin', '10.0.0.1', vpnCA, false);
        await request(publicPort, '/public.js', 'vault.example', ca);
        break;
      } catch (error) {
        if (attempt === 59) throw error;
        await new Promise(resolve => setTimeout(resolve, 250));
      }
    }
    assert.equal(admin.status, 200);
    assert.match(admin.body, /id="login-form"/);
    assert.notDeepEqual(ca, vpnCA, 'public and private proxies must not share a certificate authority');
    await assert.rejects(request(vpnPort, '/admin', '10.0.0.1', ca, false));
    assert.equal((await request(vpnPort, '/admin.js', '10.0.0.1', vpnCA, false)).status, 200);
    for (const path of ['/admin', '/admin/api/packages', '/api/admin/packages', '/admin.js']) {
      assert.equal((await request(publicPort, path, 'vault.example', ca)).status, 404);
    }
    const redirect = await fetch(`http://127.0.0.1:${httpPort}/admin?test=1`, { redirect: 'manual' });
    assert.equal(redirect.status, 308);
    assert.equal(redirect.headers.get('location'), 'https://10.0.0.1/admin?test=1');
    const home = await request(publicPort, '/', 'vault.example', ca);
    assert.equal(home.headers.location, 'https://gergo.miszori.dev');
    const packagePage = await request(publicPort, '/package/example', 'vault.example', ca);
    assert.equal(packagePage.status, 200);
    assert.match(packagePage.body, /Checking package availability/);
    assert.equal((await request(publicPort, '/public.js', 'vault.example', ca)).status, 200);
    for (const [port, host, cert, sni] of [[publicPort, 'vault.example', ca, true], [vpnPort, '10.0.0.1', vpnCA, false]]) {
      const icon = await request(port, '/share-icon.png', host, cert, sni);
      assert.equal(icon.status, 404);
    }
    const publicRedirect = await plainRequest(publicPlainPort, '/package/example', 'vault.example');
    assert.equal(publicRedirect.statusCode, 308);
    assert.equal(publicRedirect.headers.location, 'https://vault.example/package/example');
    for (const host of ['192.0.2.10', '10.0.0.1', 'unknown.example']) {
      for (const path of ['/', '/admin', '/package/example']) {
        await assert.rejects(plainRequest(publicPlainPort, path, host), { code: 'ECONNRESET' });
        await assert.rejects(request(publicPort, path, 'vault.example', ca, true, host), { code: 'ECONNRESET' });
      }
    }
    await assert.rejects(request(publicPort, '/admin', '10.0.0.1', ca, false), error => ['ECONNRESET', 'EPROTO'].includes(error.code));
  } finally {
    for (const container of started.reverse()) docker('rm', '-f', '-v', container);
    for (const network of [...testNetworks.values()].reverse()) docker('network', 'rm', network);
    await rm(dir, { recursive: true, force: true });
  }
});
