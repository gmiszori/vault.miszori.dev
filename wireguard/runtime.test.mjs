import test, { before } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const image = process.env.WIREGUARD_TEST_IMAGE || 'vault-wireguard-test:latest';
const runtime = '/usr/local/bin/vault-wireguard';
const directory = fileURLToPath(new URL('.', import.meta.url));
const prefix = `vault-wg-runtime-${process.pid}`;
let sequence = 0;
const hardening = [
  '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
  '--tmpfs', '/tmp:rw,noexec,nosuid,size=8m',
];

function docker(...args) {
  return execFileSync('docker', args, {
    encoding: 'utf8', timeout: 30000, stdio: ['ignore', 'pipe', 'pipe'],
  }).trim();
}

function logs(name) {
  const result = spawnSync('docker', ['logs', name], { encoding: 'utf8', timeout: 30000 });
  assert.equal(result.status, 0);
  return `${result.stdout}${result.stderr}`;
}

function environment(overrides = {}) {
  return Object.entries({ WIREGUARD_ENDPOINT: 'vault.miszori.dev', ...overrides })
    .flatMap(([key, value]) => ['-e', `${key}=${value}`]);
}

function invoke(volume, env = {}, command = ['render'], options = []) {
  return docker('run', '--rm', ...hardening, ...options,
    ...(volume ? ['-v', `${volume}:/config`] : []), ...environment(env), image, ...command);
}

function shell(volume, script) {
  return invoke(volume, {}, ['/bin/sh', '-eu', '-c', script]);
}

function read(volume, path) {
  return shell(volume, `cat /config/${path}`);
}

function digest(value) {
  return createHash('sha256').update(value).digest('hex');
}

function keyDigests(volume, peer) {
  const location = peer ? `peers/${peer}` : 'server';
  return ['privatekey', 'publickey'].map(key => digest(read(volume, `${location}/${key}`)));
}

async function withVolume(fn) {
  const volume = `${prefix}-${++sequence}`;
  docker('volume', 'create', volume);
  try {
    await fn(volume);
  } finally {
    docker('volume', 'rm', volume);
  }
}

function expectFailure(fn, message) {
  let failure;
  try { fn(); } catch (error) { failure = error; }
  assert.ok(failure, message);
  assert.equal(failure.status, 1);
  return `${failure.stdout || ''}${failure.stderr || ''}`;
}

function quote(value) {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function start(name, volume, env = {}, options = []) {
  docker('run', '-d', '--name', name, ...hardening, '--cap-add', 'NET_ADMIN',
    '-v', `${volume}:/config`, ...environment(env), ...options, image);
}

async function waitReady(name) {
  for (let attempt = 0; attempt < 40; attempt++) {
    assert.equal(docker('inspect', '-f', '{{.State.Running}}', name), 'true', logs(name));
    try {
      docker('exec', name, runtime, 'healthcheck');
      return;
    } catch {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  }
  assert.fail('WireGuard did not become healthy within the startup deadline');
}

before(() => {
  if (!process.env.WIREGUARD_TEST_IMAGE) {
    execFileSync('docker', ['build', '-q', '-t', image, directory], {
      encoding: 'utf8', timeout: 240000, stdio: ['ignore', 'pipe', 'pipe'],
    });
  }
}, { timeout: 300000 });

test('strict environment validation and arbitrary command passthrough', { timeout: 60000 }, () => {
  assert.equal(invoke(null, {}, ['/bin/sh', '-c', 'printf passthrough']), 'passthrough');
  const invalid = [
    { WIREGUARD_ENDPOINT: '' }, { WIREGUARD_PORT: '' }, { WIREGUARD_PORT: '0' },
    { WIREGUARD_PORT: '65536' }, { WIREGUARD_PORT: '051821' }, { WIREGUARD_PORT: '-1' },
    { WIREGUARD_PORT: '1\n2' }, { WIREGUARD_PORT: 'abc' },
    ...['https://vault.example', 'vault.example:51821', 'a/b', 'a b', '-bad.example',
      'bad-.example', 'a..example', 'a'.repeat(64), '256.1.1.1', '01.1.1.1',
      '1.2.3.4\n5.6.7.8', '[2001:db8:::1]', '2001:db8:1', '2001:db8::1%eth0',
      '[2001:db8::1]:123', '::ffff:999.1.1.1', '1.2.3.4::', 'example.com\n']
      .map(WIREGUARD_ENDPOINT => ({ WIREGUARD_ENDPOINT })),
    ...['', '10.13.13.0/16', '10.13.13.1/24', '10.13.13.0/024', '10.13.013.0/24',
      '127.0.0.0/24', '0.0.0.0/24', '224.0.0.0/24', '256.1.1.0/24']
      .map(WIREGUARD_SUBNET => ({ WIREGUARD_SUBNET })),
    ...['', '10.13.13.0', '10.13.13.255', '10.13.14.1', '10.13.13.01']
      .map(VPN_BIND_IP => ({ VPN_BIND_IP })),
    ...['', ',admin', 'admin,', 'admin,,bob', 'admin,admin', 'admin,b ob', 'admin\nbob',
      '../admin', 'admin;id', '*', 'a'.repeat(33)]
      .map(WIREGUARD_PEERS => ({ WIREGUARD_PEERS })),
  ];
  const valid = [
    {}, { WIREGUARD_PORT: '1' }, { WIREGUARD_PORT: '65535' },
    { WIREGUARD_ENDPOINT: '192.0.2.10' }, { WIREGUARD_ENDPOINT: 'vpn.example.' },
    { WIREGUARD_ENDPOINT: '[2001:db8::1]' }, { WIREGUARD_ENDPOINT: '2001:db8::1' },
    { WIREGUARD_ENDPOINT: '::ffff:192.0.2.10' },
    { WIREGUARD_SUBNET: '192.168.50.0/24', VPN_BIND_IP: '192.168.50.254', WIREGUARD_PEERS: 'Admin1,bob2' },
  ];
  const scripts = [...invalid.map((env, index) =>
    `if env ${Object.entries(env).map(([key, value]) => `${key}=${quote(value)}`).join(' ')} ${runtime} check >/dev/null 2>&1; then echo 'accepted invalid case ${index}'; exit 1; fi`),
  ...valid.map(env => `env ${Object.entries(env).map(([key, value]) => `${key}=${quote(value)}`).join(' ')} ${runtime} check >/dev/null`)];
  invoke(null, {}, ['/bin/sh', '-eu', '-c', scripts.join('\n')]);
  const missing = docker('run', '--rm', ...hardening, image, '/bin/sh', '-c',
    `if ${runtime} check >/dev/null 2>&1; then exit 1; fi`);
  assert.equal(missing, '');
});

test('render creates restricted configurations and owner-only persistent state without networking', { timeout: 30000 }, () => withVolume(volume => {
  const output = invoke(volume);
  assert.match(output, /configuration ready for 1 active peer/);
  assert.ok(!/[A-Za-z0-9+/]{43}=/.test(output), 'render logs must not contain keys');
  assert.equal(read(volume, 'network'), '10.13.13.0/24 10.13.13.1');
  assert.equal(read(volume, 'peers/admin/address'), '10.13.13.2');
  const client = read(volume, 'peers/admin/admin.conf');
  assert.ok(/^Address = 10\.13\.13\.2\/32$/m.test(client));
  assert.ok(/^AllowedIPs = 10\.13\.13\.1\/32$/m.test(client));
  assert.ok(/^Endpoint = vault\.miszori\.dev:51821$/m.test(client));
  assert.ok(!/^DNS\s*=|0\.0\.0\.0\/0|::\/0|PostUp|PreUp/m.test(client));
  const server = read(volume, 'server/wg0.conf');
  assert.ok(/^ListenPort = 51820$/m.test(server));
  assert.ok(/^AllowedIPs = 10\.13\.13\.2\/32$/m.test(server));
  assert.equal((server.match(/^\[Peer\]$/gm) || []).length, 1);
  assert.deepEqual(new Set(shell(volume, "find /config -type d -exec stat -c '%a' '{}' +").split('\n')), new Set(['700']));
  assert.deepEqual(new Set(shell(volume, "find /config -type f -exec stat -c '%a' '{}' +").split('\n')), new Set(['600']));
  expectFailure(() => invoke(volume, {}, ['healthcheck']), 'render must not bring up a network interface');
}));

test('endpoint changes, reordered peers, removal and re-addition preserve identities and reservations', { timeout: 60000 }, () => withVolume(volume => {
  invoke(volume, { WIREGUARD_PEERS: 'admin,bob' });
  const serverKeys = keyDigests(volume);
  const adminKeys = keyDigests(volume, 'admin');
  const bobKeys = keyDigests(volume, 'bob');
  const bobPublic = read(volume, 'peers/bob/publickey');
  assert.equal(read(volume, 'peers/bob/address'), '10.13.13.3');
  invoke(volume, { WIREGUARD_PEERS: 'bob,admin,charlie', WIREGUARD_ENDPOINT: '2001:db8::1', WIREGUARD_PORT: '60000' });
  assert.deepEqual(keyDigests(volume), serverKeys);
  assert.deepEqual(keyDigests(volume, 'admin'), adminKeys);
  assert.deepEqual(keyDigests(volume, 'bob'), bobKeys);
  assert.equal(read(volume, 'peers/admin/address'), '10.13.13.2');
  assert.equal(read(volume, 'peers/bob/address'), '10.13.13.3');
  assert.equal(read(volume, 'peers/charlie/address'), '10.13.13.4');
  assert.ok(/^Endpoint = \[2001:db8::1\]:60000$/m.test(read(volume, 'peers/admin/admin.conf')));
  invoke(volume, { WIREGUARD_PEERS: 'admin,charlie,dave' });
  assert.ok(!read(volume, 'server/wg0.conf').includes(bobPublic), 'removed peer must not be authorized');
  assert.equal(shell(volume, 'test ! -e /config/peers/bob/bob.conf && printf absent'), 'absent');
  assert.deepEqual(keyDigests(volume, 'bob'), bobKeys);
  assert.equal(read(volume, 'peers/dave/address'), '10.13.13.5');
  invoke(volume, { WIREGUARD_PEERS: 'admin,bob' });
  assert.deepEqual(keyDigests(volume, 'bob'), bobKeys);
  assert.equal(read(volume, 'peers/bob/address'), '10.13.13.3');
  assert.ok(/^Endpoint = vault\.miszori\.dev:51821$/m.test(read(volume, 'peers/bob/bob.conf')));
  const originalConfig = digest(read(volume, 'server/wg0.conf'));
  expectFailure(() => invoke(volume, { WIREGUARD_SUBNET: '10.99.0.0/24', VPN_BIND_IP: '10.99.0.1' }));
  expectFailure(() => invoke(volume, { VPN_BIND_IP: '10.13.13.254' }));
  assert.equal(digest(read(volume, 'server/wg0.conf')), originalConfig);
}));

test('allocator excludes a non-default server address and fails closed on corrupt or exhausted state', { timeout: 60000 }, () => withVolume(volume => {
  invoke(volume, { VPN_BIND_IP: '10.13.13.2', WIREGUARD_PEERS: 'admin,bob' });
  assert.equal(read(volume, 'peers/admin/address'), '10.13.13.1');
  assert.equal(read(volume, 'peers/bob/address'), '10.13.13.3');
  const render = () => invoke(volume, { VPN_BIND_IP: '10.13.13.2', WIREGUARD_PEERS: 'admin,bob' });
  for (const invalidAddress of ['10.13.13.1', '10.13.13.2', '10.13.13.0', '10.13.13.255', '10.14.0.3', '10.13.13.03']) {
    shell(volume, `printf '%s\\n' ${quote(invalidAddress)} > /config/peers/bob/address`);
    assert.match(expectFailure(render), /peer address|duplicate|server/);
  }
  shell(volume, "printf '10.13.13.3\\n' > /config/peers/bob/address; cp /config/peers/bob/privatekey /config/peers/bob/key.backup; cp /config/peers/bob/publickey /config/peers/bob/pub.backup; cp /config/peers/admin/privatekey /config/peers/bob/privatekey; cp /config/peers/admin/publickey /config/peers/bob/publickey");
  assert.match(expectFailure(render), /duplicate public keys/);
  shell(volume, 'mv /config/peers/bob/key.backup /config/peers/bob/privatekey; mv /config/peers/bob/pub.backup /config/peers/bob/publickey; rm /config/peers/bob/address');
  assert.match(expectFailure(render), /address is missing/);
  shell(volume, "printf '10.13.13.3\\n' > /config/peers/bob/address; ln -s /etc/passwd /config/not-allowed");
  assert.match(expectFailure(render), /symbolic links/);
  shell(volume, 'rm /config/not-allowed; mkfifo /config/not-allowed');
  assert.match(expectFailure(render), /regular files/);
  shell(volume, 'rm /config/not-allowed');
  render();
  shell(volume, 'cp /config/server/privatekey /config/server/key.backup; rm /config/server/privatekey');
  assert.match(expectFailure(render), /refusing to rotate established keys/);
  shell(volume, 'mv /config/server/key.backup /config/server/privatekey; cp /config/peers/admin/privatekey /config/peers/admin/key.backup; cp /config/peers/bob/privatekey /config/peers/admin/privatekey');
  assert.match(expectFailure(render), /public and private keys do not match/);
  shell(volume, 'mv /config/peers/admin/key.backup /config/peers/admin/privatekey');
  render();
}));

test('all /24 peer addresses are unique and removed reservations are never reused', { timeout: 90000 }, () => withVolume(volume => {
  const peers = Array.from({ length: 253 }, (_, index) => `p${index + 1}`);
  invoke(volume, { WIREGUARD_PEERS: peers.join(',') });
  const addresses = shell(volume, 'cat /config/peers/*/address').split('\n');
  assert.equal(new Set(addresses).size, 253);
  assert.ok(!addresses.includes('10.13.13.1'));
  assert.ok(!addresses.includes('10.13.13.0') && !addresses.includes('10.13.13.255'));
  assert.match(expectFailure(() => invoke(volume, { WIREGUARD_PEERS: 'newpeer' })), /no unreserved peer addresses/);
  expectFailure(() => invoke(volume, { WIREGUARD_PEERS: [...peers, 'extra'].join(',') }));
}));

test('kernel runtime uses only NET_ADMIN, restricts both IP families, checks health and shuts down cleanly', { timeout: 90000 }, () => withVolume(async volume => {
  const name = `${prefix}-live`;
  const holder = `${prefix}-holder`;
  let runtimeCreated = false;
  let holderCreated = false;
  try {
    start(name, volume, { WIREGUARD_PEERS: 'admin,bob' }, ['--sysctl', 'net.ipv4.ip_forward=1']);
    runtimeCreated = true;
    await waitReady(name);
    assert.equal(docker('exec', name, '/bin/sh', '-c', "awk '/^CapEff:/ { print $2 }' /proc/1/status"), '0000000000001000');
    assert.equal(docker('exec', name, 'wg', 'show', 'wg0', 'peers').split('\n').length, 2);
    for (const fw of ['iptables', 'ip6tables']) {
      assert.match(docker('exec', name, fw, '-S', 'INPUT'), /^-A INPUT -i wg0 -j VAULT_WG_IN$/m);
      const forwarding = docker('exec', name, fw, '-S', 'FORWARD');
      assert.match(forwarding, /^-A FORWARD -i wg0 -j VAULT_WG_FWD$/m);
      assert.match(forwarding, /^-A FORWARD -o wg0 -j VAULT_WG_FWD$/m);
      assert.equal(docker('exec', name, fw, '-S', 'VAULT_WG_FWD'), '-N VAULT_WG_FWD\n-A VAULT_WG_FWD -j DROP');
      const input = docker('exec', name, fw, '-S', 'VAULT_WG_IN');
      assert.match(input, /-A VAULT_WG_IN -j DROP$/);
      if (fw === 'iptables') assert.match(input, /-d 10\.13\.13\.1\/32 -p tcp -m multiport --dports 80,443 -j ACCEPT/);
      else assert.ok(!input.includes('ACCEPT'));
    }
    assert.ok(!docker('exec', name, 'iptables', '-t', 'nat', '-S').includes('-A '), 'runtime must not install NAT');
    expectFailure(() => docker('exec', name, runtime, 'render'));
    docker('exec', name, 'wg', 'set', 'wg0', 'listen-port', '51822');
    expectFailure(() => docker('exec', name, runtime, 'healthcheck'));
    docker('exec', name, 'wg', 'set', 'wg0', 'listen-port', '51820');
    docker('exec', name, 'ip', 'address', 'del', '10.13.13.1/24', 'dev', 'wg0');
    expectFailure(() => docker('exec', name, runtime, 'healthcheck'));
    docker('exec', name, 'ip', 'address', 'add', '10.13.13.1/24', 'dev', 'wg0');
    docker('exec', name, 'ip', 'link', 'set', 'wg0', 'down');
    expectFailure(() => docker('exec', name, runtime, 'healthcheck'));
    docker('exec', name, 'ip', 'link', 'set', 'wg0', 'up');
    docker('exec', name, runtime, 'healthcheck');
    docker('run', '-d', '--name', holder, ...hardening, '--cap-add', 'NET_ADMIN',
      '--network', `container:${name}`, '-v', `${volume}:/config:ro`, image, '/bin/sh', '-c', 'sleep 120');
    holderCreated = true;
    assert.equal(docker('inspect', '-f', '{{.State.Running}}', holder), 'true');
    docker('exec', holder, 'iptables', '-N', 'UNIT_SENTINEL');
    docker('exec', holder, 'iptables', '-A', 'OUTPUT', '-j', 'UNIT_SENTINEL');
    docker('stop', '-t', '8', name);
    assert.equal(docker('inspect', '-f', '{{.State.ExitCode}}', name), '0');
    expectFailure(() => docker('exec', holder, 'ip', 'link', 'show', 'dev', 'wg0'));
    for (const fw of ['iptables', 'ip6tables']) {
      assert.ok(!docker('exec', holder, fw, '-S').includes('VAULT_WG_'));
    }
    assert.match(docker('exec', holder, 'iptables', '-S'), /UNIT_SENTINEL/);
    docker('rm', name);
    runtimeCreated = false;
    start(name, volume, { WIREGUARD_PEERS: 'bob' });
    runtimeCreated = true;
    await waitReady(name);
    assert.equal(digest(docker('exec', name, 'wg', 'show', 'wg0', 'peers')), digest(read(volume, 'peers/bob/publickey')));
    const output = logs(name);
    assert.ok(!/[A-Za-z0-9+/]{43}=/.test(output), 'runtime logs must not contain keys');
  } finally {
    if (runtimeCreated) docker('rm', '-f', name);
    if (holderCreated) docker('rm', '-f', holder);
  }
}));

test('network setup failures never silently start a partially protected interface', { timeout: 60000 }, () => withVolume(volume => withVolume(toolVolume => {
  const holder = `${prefix}-failure-holder`;
  const name = `${prefix}-failure`;
  docker('run', '-d', '--name', holder, ...hardening, '--cap-add', 'NET_ADMIN',
    '-v', `${volume}:/config:ro`, image, '/bin/sh', '-c', 'sleep 120');
  try {
    for (const [tool, script, expected] of [
      ['iptables', '#!/bin/sh\ncase " $* " in *" --dports "*) exit 1;; esac\nexec /usr/sbin/iptables "$@"\n', /failed to install.*firewall/],
      ['ip6tables', '#!/bin/sh\ncase " $* " in *" -I FORWARD "*) exit 1;; esac\nexec /usr/sbin/ip6tables "$@"\n', /failed to install.*firewall/],
      ['ip', '#!/bin/sh\ncase " $* " in *" type wireguard "*) exit 1;; esac\nexec /sbin/ip "$@"\n', /Linux kernel WireGuard support.*no userspace fallback/],
    ]) {
      shell(toolVolume, `mkdir -p /config/bin; printf '%s' ${quote(script)} > /config/bin/${tool}; chmod 0700 /config/bin/${tool}`);
      docker('run', '-d', '--name', name, ...hardening, '--cap-add', 'NET_ADMIN',
        '--network', `container:${holder}`, '-v', `${volume}:/config`, '-v', `${toolVolume}:/test-tools:ro`,
        ...environment({ PATH: '/test-tools/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' }), image);
      try {
        assert.equal(docker('wait', name), '1');
        assert.match(logs(name), expected);
        expectFailure(() => docker('exec', holder, 'ip', 'link', 'show', 'dev', 'wg0'));
        for (const fw of ['iptables', 'ip6tables']) assert.ok(!docker('exec', holder, fw, '-S').includes('VAULT_WG_'));
      } finally {
        docker('rm', '-f', name);
        shell(toolVolume, `rm /config/bin/${tool}`);
      }
    }
  } finally {
    docker('rm', '-f', holder);
  }
})));
