import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const config = JSON.parse(execFileSync('docker', ['compose', '--env-file', '/dev/null', '-f', resolve(root, 'compose.yaml'), 'config', '--format', 'json'], {
  encoding: 'utf8',
  env: { ...process.env, PUBLIC_BIND_IP: '192.0.2.10', VPN_BIND_IP: '10.13.13.1', WIREGUARD_PORT: '51821',
    TRUSTED_PROXY_CIDR: '172.30.0.0/24', ACME_EMAIL: 'test@example.com' },
}));
const publicProxy = config.services.caddy;
const privateProxy = config.services['caddy-vpn'];
const wireguard = config.services.wireguard;

test('production proxies publish only their own interface and listeners', () => {
  // Public 80/443 belong to the webserver repo's proxy, which reaches Caddy by this alias.
  assert.equal(publicProxy.ports, undefined);
  assert.deepEqual(publicProxy.networks.webserver.aliases, ['vault']);
  assert.equal(config.networks.webserver.external, true);
  assert.deepEqual(wireguard.ports.map(({ host_ip, published, target, protocol }) => [host_ip, published, target, protocol]), [
    ['192.0.2.10', '51821', 51820, 'udp'],
  ]);
  assert.equal(privateProxy.ports, undefined);
  assert.equal(privateProxy.network_mode, 'service:wireguard');
  assert.equal(config.services.api.ports, undefined);
});

test('WireGuard UDP port and tunnel address are configurable without publishing admin TCP', () => {
  const custom = JSON.parse(execFileSync('docker', ['compose', '--env-file', '/dev/null',
    '-f', resolve(root, 'compose.yaml'), 'config', '--format', 'json'], {
    encoding: 'utf8', timeout: 60000,
    env: { ...process.env, PUBLIC_BIND_IP: '192.0.2.10', ACME_EMAIL: 'test@example.com',
      WIREGUARD_PORT: '53421', WIREGUARD_SUBNET: '10.42.42.0/24', VPN_BIND_IP: '10.42.42.1' },
  }));
  assert.deepEqual(custom.services.wireguard.ports.map(({ published, target, protocol }) => [published, target, protocol]), [
    ['53421', 51820, 'udp'],
  ]);
  assert.equal(custom.services.wireguard.environment.WIREGUARD_PORT, '53421');
  assert.equal(custom.services.wireguard.environment.WIREGUARD_SUBNET, '10.42.42.0/24');
  assert.equal(custom.services['caddy-vpn'].environment.VPN_BIND_IP, '10.42.42.1');
  assert.equal(custom.services['caddy-vpn'].ports, undefined);
});

test('VPN namespace has a dedicated ingress bridge and isolated backend and secrets', () => {
  assert.deepEqual(Object.keys(publicProxy.networks).sort(), ['backend', 'edge', 'webserver']);
  assert.equal(privateProxy.networks, undefined);
  assert.deepEqual(Object.keys(wireguard.networks).sort(), ['vpn_backend', 'vpn_ingress']);
  assert.notEqual(config.networks.vpn_ingress.internal, true);
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
  assert.equal(wireguard.networks.vpn_backend.ipv4_address, '172.30.0.131');
  assert.equal(config.services.api.environment.TRUSTED_PROXY_CIDR, '172.30.0.0/24');
  assert.equal(privateProxy.environment.VPN_BIND_IP, '10.13.13.1');
  assert.equal(privateProxy.depends_on.wireguard.condition, 'service_healthy');
  assert.equal(privateProxy.depends_on.wireguard.restart, true);
  assert.deepEqual(wireguard.cap_drop, ['ALL']);
  assert.deepEqual(wireguard.cap_add, ['NET_ADMIN']);
  assert.ok(wireguard.security_opt.includes('no-new-privileges:true'));
  assert.equal(wireguard.privileged, undefined);
  assert.equal(wireguard.read_only, true);
  assert.equal(wireguard.volumes.length, 1);
  assert.equal(wireguard.volumes[0].target, '/config');
  assert.equal(wireguard.volumes[0].source, 'wireguard_config');
  for (const proxy of [publicProxy, privateProxy]) {
    assert.ok(!proxy.volumes.some(volume => volume.source === 'wireguard_config'));
  }
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
  assert.deepEqual(privateProxy.cap_add, ['NET_BIND_SERVICE']);
  assert.deepEqual(publicProxy.cap_add, ['NET_BIND_SERVICE']);
});
