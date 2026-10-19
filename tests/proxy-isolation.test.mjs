import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const config = JSON.parse(execFileSync('docker', ['compose', '-f', resolve(root, 'compose.yaml'), 'config', '--format', 'json'], {
  encoding: 'utf8',
  env: { ...process.env, PUBLIC_BIND_IP: '192.0.2.10', VPN_BIND_IP: '10.0.0.1', ACME_EMAIL: 'test@example.com' },
}));
const publicProxy = config.services.caddy;
const privateProxy = config.services['caddy-vpn'];

test('production proxies publish only their own interface and listeners', () => {
  assert.deepEqual(publicProxy.ports.map(({ host_ip, published, target }) => [host_ip, published, target]), [
    ['192.0.2.10', '80', 80], ['192.0.2.10', '443', 443],
  ]);
  assert.deepEqual(privateProxy.ports.map(({ host_ip, published, target }) => [host_ip, published, target]), [
    ['10.0.0.1', '80', 8081], ['10.0.0.1', '443', 8443],
  ]);
  assert.equal(config.services.api.ports, undefined);
});

test('VPN proxy has no public network or shared proxy state', () => {
  assert.deepEqual(Object.keys(publicProxy.networks).sort(), ['backend', 'edge']);
  assert.deepEqual(Object.keys(privateProxy.networks), ['vpn_backend']);
  assert.deepEqual(Object.keys(config.services.api.networks).sort(), ['backend', 'vpn_backend']);
  for (const network of ['backend', 'vpn_backend']) assert.equal(config.networks[network].internal, true);
  // Both disjoint networks remain within the API's existing trusted-proxy /24.
  assert.equal(config.networks.backend.ipam.config[0].subnet, '172.30.0.0/25');
  assert.equal(config.networks.vpn_backend.ipam.config[0].subnet, '172.30.0.128/25');
  assert.equal(config.services.api.environment.PUBLIC_LISTEN_ADDR, '172.30.0.2:8080');
  assert.equal(config.services.api.environment.ADMIN_LISTEN_ADDR, '172.30.0.130:8081');
  assert.equal(config.services.api.environment.ADMIN_PROXY_IP, '172.30.0.131');
  assert.equal(config.services.api.networks.backend.ipv4_address, '172.30.0.2');
  assert.equal(config.services.api.networks.vpn_backend.ipv4_address, '172.30.0.130');
  assert.equal(privateProxy.networks.vpn_backend.ipv4_address, '172.30.0.131');
  assert.equal(privateProxy.environment.API_UPSTREAM, '172.30.0.130:8081');
  assert.equal(publicProxy.environment.API_UPSTREAM, undefined);
  assert.equal(privateProxy.environment.ACME_EMAIL, undefined);
  assert.equal(publicProxy.environment.VPN_BIND_IP, undefined);
  assert.equal(privateProxy.image, publicProxy.image);
  for (const target of ['/data', '/config']) {
    const pub = publicProxy.volumes.find(volume => volume.target === target);
    const vpn = privateProxy.volumes.find(volume => volume.target === target);
    assert.equal(pub.type, 'volume');
    assert.equal(vpn.type, 'volume');
    assert.notEqual(pub.source, vpn.source);
  }
  for (const [proxy, filename] of [[publicProxy, 'Caddyfile'], [privateProxy, 'Caddyfile.vpn']]) {
    const mounted = proxy.volumes.find(volume => volume.target === '/etc/caddy/Caddyfile');
    assert.equal(mounted.source, resolve(root, filename));
    assert.equal(mounted.read_only, true);
    assert.equal(proxy.volumes.find(volume => volume.target === '/etc/caddy/common.caddy').read_only, true);
    assert.equal(proxy.read_only, true);
    assert.deepEqual(proxy.cap_drop, ['ALL']);
    assert.ok(proxy.security_opt.includes('no-new-privileges:true'));
  }
  assert.equal(privateProxy.cap_add, undefined, 'VPN listeners do not need privileged-port capabilities');
});
