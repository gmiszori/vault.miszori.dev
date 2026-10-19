import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';

const project = process.env.TEST_COMPOSE_PROJECT || 'vault-test';
const publicIP = process.env.TEST_PUBLIC_API_IP || '172.30.0.2';
const privateIP = process.env.TEST_PRIVATE_API_IP || '172.30.0.130';
const container = service => execFileSync('docker', ['ps', '-q',
  '--filter', `label=com.docker.compose.project=${project}`,
  '--filter', `label=com.docker.compose.service=${service}`,
], { encoding: 'utf8' }).trim();
const probe = (service, url) => {
  const id = container(service);
  assert.match(id, /^[a-f0-9]+$/, `one running ${service} container required`);
  return spawnSync('docker', ['exec', id, 'wget', '-T', '2', '-S', '-O', '-', url], { encoding: 'utf8', timeout: 10000 });
};

test('public proxy cannot discover admin API even when bypassing Caddy routing', () => {
  const result = probe('caddy', `http://${publicIP}:8080/api/admin/auth`);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /404 Not Found/);
  assert.doesNotMatch(result.stdout, /initialized|labelKey/);
});

test('another VPN-network container cannot act as the admin proxy', () => {
  const [proxy] = JSON.parse(execFileSync('docker', ['inspect', container('caddy-vpn')], { encoding: 'utf8' }));
  const networks = Object.keys(proxy.NetworkSettings.Networks);
  assert.equal(networks.length, 1);
  const result = spawnSync('docker', ['run', '--rm', '--network', networks[0],
    proxy.Config.Image, 'wget', '-T', '2', '-S', '-O', '-', `http://${privateIP}:8081/api/admin/auth`,
  ], { encoding: 'utf8', timeout: 15000 });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /404 Not Found/);
  assert.doesNotMatch(result.stdout, /initialized|labelKey/);
});

test('API listens only on the matching Docker interfaces', () => {
  for (const [service, url] of [
    ['caddy', `http://${publicIP}:8081/api/admin/auth`],
    ['caddy', `http://${privateIP}:8081/api/admin/auth`],
    ['caddy-vpn', `http://${privateIP}:8080/healthz`],
  ]) {
    const result = probe(service, url);
    assert.notEqual(result.status, 0, `${url} must not be accessible from ${service}`);
    assert.doesNotMatch(result.stdout, /initialized|labelKey/);
  }
  const allowed = probe('caddy-vpn', `http://${privateIP}:8081/api/admin/auth`);
  assert.equal(allowed.status, 0, allowed.stderr);
  assert.equal(typeof JSON.parse(allowed.stdout).initialized, 'boolean');
});
