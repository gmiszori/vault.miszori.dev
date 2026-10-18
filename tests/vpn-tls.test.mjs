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
  const dir = await mkdtemp(join(tmpdir(), 'vault-vpn-tls-'));
  const name = `vault-vpn-tls-${process.pid}`;
  let started = false;
  try {
    const adapted = JSON.parse(docker('run', '--rm',
      '-e', 'DOMAIN=vault.example', '-e', 'VPN_BIND_IP=10.0.0.1',
      '-e', 'ACME_EMAIL=test@example.com', '-e', 'PUBLIC_ORIGIN=https://vault.example',
      '-v', `${join(root, 'Caddyfile')}:/etc/caddy/Caddyfile:ro`,
      image, 'caddy', 'adapt', '--config', '/etc/caddy/Caddyfile', '--adapter', 'caddyfile'));
    const policies = adapted.apps.tls.automation.policies;
    const vpnPolicy = policies.find(policy => policy.subjects?.includes('10.0.0.1'));
    assert.equal(vpnPolicy.issuers[0].module, 'internal');
    assert.ok(!policies.find(policy => policy.subjects?.includes('vault.example'))?.issuers?.some(issuer => issuer.module === 'internal'));
    // Only the public certificate issuer is substituted for this isolated smoke test.
    // The private-IP policy and production routes remain unchanged; no real ACME requests run.
    for (const policy of policies) policy.issuers = [{ module: 'internal' }];
    await writeFile(join(dir, 'caddy.json'), JSON.stringify(adapted));
    docker('run', '--rm', '-v', `${dir}:/test:ro`, image, 'caddy', 'validate', '--config', '/test/caddy.json');
    docker('run', '-d', '--name', name,
      '-p', '127.0.0.1::80', '-p', '127.0.0.1::443', '-p', '127.0.0.1::8443', '-p', '127.0.0.1::8081',
      '-v', `${dir}:/test:ro`, '-v', `${join(root, 'web')}:/srv:ro`,
      image, 'caddy', 'run', '--config', '/test/caddy.json');
    started = true;
    const ports = JSON.parse(docker('inspect', '--format', '{{json .NetworkSettings.Ports}}', name));
    const publicPlainPort = Number(ports['80/tcp'][0].HostPort);
    const publicPort = Number(ports['443/tcp'][0].HostPort);
    const vpnPort = Number(ports['8443/tcp'][0].HostPort);
    const httpPort = Number(ports['8081/tcp'][0].HostPort);
    let ca;
    let admin;
    for (let attempt = 0; attempt < 60; attempt++) {
      try {
        docker('cp', `${name}:/data/caddy/pki/authorities/local/root.crt`, join(dir, 'root.crt'));
        ca = await readFile(join(dir, 'root.crt'));
        admin = await request(vpnPort, '/admin', '10.0.0.1', ca, false);
        break;
      } catch (error) {
        if (attempt === 59) throw error;
        await new Promise(resolve => setTimeout(resolve, 250));
      }
    }
    assert.equal(admin.status, 200);
    assert.match(admin.body, /id="login-form"/);
    assert.equal((await request(vpnPort, '/admin.js', '10.0.0.1', ca, false)).status, 200);
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
    for (const [port, host, sni] of [[publicPort, 'vault.example', true], [vpnPort, '10.0.0.1', false]]) {
      const icon = await request(port, '/share-icon.png', host, ca, sni);
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
    await assert.rejects(request(publicPort, '/admin', '10.0.0.1', ca, false), { code: 'ECONNRESET' });
  } finally {
    if (started) docker('rm', '-f', '-v', name);
    await rm(dir, { recursive: true, force: true });
  }
});
