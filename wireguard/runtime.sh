#!/bin/sh
set -eu
umask 077
export LC_ALL=C
export XTABLES_LOCKFILE=/tmp/xtables.lock

fail() {
    printf 'WireGuard: %s\n' "$*" >&2
    exit 1
}

valid_ipv4() {
    printf '%s\n' "$1" | awk -F. '
        NR != 1 || NF != 4 { exit 1 }
        { for (i = 1; i <= 4; i++)
            if ($i !~ /^[0-9]+$/ || length($i) > 3 || $i > 255 ||
                (length($i) > 1 && substr($i, 1, 1) == "0")) exit 1 }
    '
}

valid_name() {
    case "$1" in ''|*[!a-zA-Z0-9]*) return 1 ;; esac
    [ "${#1}" -le 32 ]
}

validate_endpoint() {
    [ "${#WIREGUARD_ENDPOINT}" -le 253 ] || fail 'WIREGUARD_ENDPOINT is too long'
    case "$WIREGUARD_ENDPOINT" in
        *:*)
            endpoint_ip=$WIREGUARD_ENDPOINT
            case "$endpoint_ip" in \[*\]) endpoint_ip=${endpoint_ip#\[}; endpoint_ip=${endpoint_ip%\]} ;; esac
            printf '%s\n' "$endpoint_ip" | awk '
                function groups(s,    a,n,i,count,v,m,j,b) {
                    if (s == "") return 0
                    n = split(s, a, ":"); count = 0
                    for (i = 1; i <= n; i++) {
                        if (index(a[i], ".")) {
                            if (i != n || split(a[i], b, ".") != 4) return -100
                            for (j = 1; j <= 4; j++)
                                if (b[j] !~ /^[0-9]+$/ || length(b[j]) > 3 || b[j] > 255 ||
                                    (length(b[j]) > 1 && substr(b[j], 1, 1) == "0")) return -100
                            count += 2
                        } else {
                            if (length(a[i]) < 1 || length(a[i]) > 4 || a[i] ~ /[^0-9a-fA-F]/) return -100
                            count++
                        }
                    }
                    return count
                }
                NR != 1 { exit 1 }
                {
                    p = index($0, "::")
                    if (!p) { if (groups($0) != 8) exit 1 }
                    else {
                        left = substr($0, 1, p - 1); right = substr($0, p + 2)
                        a = groups(left); b = groups(right)
                        if (index(right, "::") || index(left, ".") || a < 0 || b < 0 || a + b >= 8) exit 1
                    }
                }
            ' || fail 'WIREGUARD_ENDPOINT must be a DNS hostname or IP literal (no scheme, path, zone or port)'
            endpoint_host="[$endpoint_ip]"
            ;;
        *[!0-9.]* )
            printf '%s\n' "$WIREGUARD_ENDPOINT" | awk '
                NR != 1 { exit 1 }
                {
                    sub(/\.$/, ""); n = split($0, labels, ".")
                    for (i = 1; i <= n; i++)
                        if (length(labels[i]) < 1 || length(labels[i]) > 63 ||
                            labels[i] ~ /[^a-zA-Z0-9-]/ || labels[i] !~ /^[a-zA-Z0-9]/ ||
                            labels[i] !~ /[a-zA-Z0-9]$/) exit 1
                }
            ' || fail 'WIREGUARD_ENDPOINT must be a DNS hostname or IP literal (no scheme, path or port)'
            endpoint_host=$WIREGUARD_ENDPOINT
            ;;
        *)
            valid_ipv4 "$WIREGUARD_ENDPOINT" || fail 'WIREGUARD_ENDPOINT is not a valid IPv4 address'
            endpoint_host=$WIREGUARD_ENDPOINT
            ;;
    esac
}

validate_env() {
    WIREGUARD_PORT=${WIREGUARD_PORT-51821}
    WIREGUARD_ENDPOINT=${WIREGUARD_ENDPOINT-}
    WIREGUARD_PEERS=${WIREGUARD_PEERS-admin}
    WIREGUARD_SUBNET=${WIREGUARD_SUBNET-10.13.13.0/24}
    VPN_BIND_IP=${VPN_BIND_IP-10.13.13.1}
    case "$WIREGUARD_PORT" in ''|0*|*[!0-9]*) fail 'WIREGUARD_PORT must be an integer from 1 to 65535' ;; esac
    [ "${#WIREGUARD_PORT}" -le 5 ] && [ "$WIREGUARD_PORT" -le 65535 ] || fail 'WIREGUARD_PORT must be an integer from 1 to 65535'
    [ -n "$WIREGUARD_ENDPOINT" ] || fail 'WIREGUARD_ENDPOINT is required'
    validate_endpoint
    case "$WIREGUARD_SUBNET" in */24) network=${WIREGUARD_SUBNET%/24} ;; *) fail 'WIREGUARD_SUBNET must be an IPv4 /24 network' ;; esac
    valid_ipv4 "$network" || fail 'WIREGUARD_SUBNET must be an IPv4 /24 network'
    prefix=${network%.*}
    first=${network%%.*}
    [ "${network##*.}" = 0 ] && [ "$first" -ge 1 ] && [ "$first" -le 223 ] && [ "$first" -ne 127 ] || fail 'WIREGUARD_SUBNET must be a unicast network address ending in .0/24'
    valid_ipv4 "$VPN_BIND_IP" || fail 'VPN_BIND_IP must be an IPv4 host in WIREGUARD_SUBNET'
    server_host=${VPN_BIND_IP##*.}
    [ "${VPN_BIND_IP%.*}" = "$prefix" ] && [ "$server_host" -ge 1 ] && [ "$server_host" -le 254 ] || fail 'VPN_BIND_IP must be a usable host in WIREGUARD_SUBNET'
    case "$WIREGUARD_PEERS" in ''|,*|*,|*,,*) fail 'WIREGUARD_PEERS must contain comma-separated alphanumeric names' ;; esac
    [ "${#WIREGUARD_PEERS}" -le 8348 ] || fail 'WIREGUARD_PEERS is too long'
    case "$WIREGUARD_PEERS" in *[!a-zA-Z0-9,]*) fail 'WIREGUARD_PEERS contains invalid characters' ;; esac
    peers=$(printf '%s' "$WIREGUARD_PEERS" | tr ',' ' ')
    seen=' '
    count=0
    for peer in $peers; do
        valid_name "$peer" || fail 'peer names must be 1 to 32 ASCII alphanumeric characters'
        case "$seen" in *" $peer "*) fail 'WIREGUARD_PEERS contains a duplicate name' ;; esac
        seen="$seen$peer "
        count=$((count + 1))
    done
    [ "$count" -le 253 ] || fail 'at most 253 peers fit in the /24 subnet'
}

regular_file() {
    [ -f "$1" ] && [ ! -L "$1" ] || fail 'persistent state contains a missing or non-regular file'
    chmod 0600 "$1"
}

ensure_keypair() {
    key_dir=$1
    if [ -e "$key_dir/privatekey" ]; then
        regular_file "$key_dir/privatekey"
    else
        [ "${2-0}" = 1 ] && [ ! -e "$key_dir/publickey" ] || fail 'a persistent private key is missing; refusing to rotate established keys'
        wg genkey > "$key_dir/privatekey.next" || fail 'private key generation failed'
        mv "$key_dir/privatekey.next" "$key_dir/privatekey"
    fi
    private_key=$(cat "$key_dir/privatekey")
    [ "${#private_key}" -eq 44 ] || fail 'persistent private key has an invalid length'
    case "$private_key" in *[!a-zA-Z0-9+/=]*) fail 'persistent private key has invalid characters' ;; esac
    public_key=$(wg pubkey < "$key_dir/privatekey" 2>/dev/null) || fail 'persistent private key is invalid; refusing to rotate keys'
    if [ -e "$key_dir/publickey" ]; then
        regular_file "$key_dir/publickey"
        [ "$(cat "$key_dir/publickey")" = "$public_key" ] || fail 'persistent public and private keys do not match'
    else
        printf '%s\n' "$public_key" > "$key_dir/publickey.next"
        mv "$key_dir/publickey.next" "$key_dir/publickey"
    fi
    case "$used_keys" in *"|$public_key|"*) fail 'persistent state contains duplicate public keys' ;; esac
    used_keys="$used_keys$public_key|"
}

prepare_state() {
    [ -d /config ] && [ ! -L /config ] || fail '/config must be a writable directory volume'
    special_files=$(find /config ! -type d ! -type f -print) || fail '/config is not readable by the runtime user'
    [ -z "$special_files" ] || fail '/config must contain only regular files and directories (no symbolic links)'
    chmod 0700 /config
    exec 9>/config/.runtime.lock
    flock -n 9 || fail '/config is already in use; stop the running service before rendering or starting another instance'
    chmod 0600 /config/.runtime.lock
    find /config -type d -exec chmod 0700 '{}' +
    find /config -type f -exec chmod 0600 '{}' +
    new_server=0
    if [ -e /config/network ]; then
        regular_file /config/network
        [ "$(cat /config/network)" = "$WIREGUARD_SUBNET $VPN_BIND_IP" ] || fail 'subnet/server address differs from persisted state; use a new volume rather than reassigning established addresses'
    else
        # Missing metadata must not silently adopt previously allocated identities.
        [ ! -e /config/server ] && [ ! -e /config/peers ] || fail 'persistent network metadata is missing'
        printf '%s %s\n' "$WIREGUARD_SUBNET" "$VPN_BIND_IP" > /config/network.next
        mv /config/network.next /config/network
        new_server=1
    fi
    mkdir -p /config/server /config/peers
    used_keys='|'
    ensure_keypair /config/server "$new_server"
    used_addresses=" $server_host "
    for peer_dir in /config/peers/*; do
        [ -e "$peer_dir" ] || continue
        [ -d "$peer_dir" ] || fail 'persistent peer state must contain directories only'
        valid_name "${peer_dir##*/}" || fail 'persistent state contains an invalid peer name'
        if [ ! -e "$peer_dir/address" ]; then
            [ ! -e "$peer_dir/privatekey" ] && [ ! -e "$peer_dir/publickey" ] || fail 'an established peer address is missing; refusing to reassign it'
            continue
        fi
        ensure_keypair "$peer_dir"
        if [ -e "$peer_dir/address" ]; then
            regular_file "$peer_dir/address"
            address=$(cat "$peer_dir/address")
            valid_ipv4 "$address" || fail 'persistent peer address is invalid'
            host=${address##*.}
            [ "${address%.*}" = "$prefix" ] && [ "$host" -ge 1 ] && [ "$host" -le 254 ] || fail 'persistent peer address is outside the usable subnet'
            case "$used_addresses" in *" $host "*) fail 'persistent state contains a duplicate or server peer address' ;; esac
            used_addresses="$used_addresses$host "
        fi
    done
    for peer in $peers; do
        peer_dir=/config/peers/$peer
        if [ ! -d "$peer_dir" ]; then
            mkdir "$peer_dir"
        fi
        if [ ! -e "$peer_dir/address" ]; then
            host=1
            while [ "$host" -le 254 ]; do
                case "$used_addresses" in *" $host "*) host=$((host + 1)) ;; *) break ;; esac
            done
            [ "$host" -le 254 ] || fail 'no unreserved peer addresses remain; removed peers retain their reservations'
            printf '%s.%s\n' "$prefix" "$host" > "$peer_dir/address.next"
            mv "$peer_dir/address.next" "$peer_dir/address"
            used_addresses="$used_addresses$host "
            ensure_keypair "$peer_dir" 1
        fi
    done
}

render() {
    prepare_state
    server_public=$(cat /config/server/publickey)
    {
        printf '[Interface]\nPrivateKey = %s\nListenPort = 51820\n' "$(cat /config/server/privatekey)"
        for peer in $peers; do
            peer_dir=/config/peers/$peer
            printf '\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n' "$(cat "$peer_dir/publickey")" "$(cat "$peer_dir/address")"
        done
    } > /config/server/wg0.conf.next
    for peer in $peers; do
        peer_dir=/config/peers/$peer
        {
            printf '[Interface]\nPrivateKey = %s\nAddress = %s/32\n' "$(cat "$peer_dir/privatekey")" "$(cat "$peer_dir/address")"
            printf '\n[Peer]\nPublicKey = %s\nEndpoint = %s:%s\nAllowedIPs = %s/32\nPersistentKeepalive = 25\n' "$server_public" "$endpoint_host" "$WIREGUARD_PORT" "$VPN_BIND_IP"
        } > "$peer_dir/${peer_dir##*/}.conf.next"
        mv "$peer_dir/${peer_dir##*/}.conf.next" "$peer_dir/${peer_dir##*/}.conf"
    done
    mv /config/server/wg0.conf.next /config/server/wg0.conf
    for peer_dir in /config/peers/*; do
        [ -d "$peer_dir" ] || continue
        case " $peers " in *" ${peer_dir##*/} "*) ;; *) rm -f "$peer_dir/${peer_dir##*/}.conf" "$peer_dir/${peer_dir##*/}.conf.next" ;; esac
    done
    printf 'WireGuard: configuration ready for %s active peer(s); private exports are under /config/peers/<name>/<name>.conf\n' "$count"
}

install_firewall() {
    for fw in iptables ip6tables; do
        "$fw" -w 5 -N VAULT_WG_IN || return 1
        if [ "$fw" = iptables ]; then v4_input=1; else v6_input=1; fi
        "$fw" -w 5 -N VAULT_WG_FWD || return 1
        if [ "$fw" = iptables ]; then v4_forward=1; else v6_forward=1; fi
        if [ "$fw" = iptables ]; then
            "$fw" -w 5 -A VAULT_WG_IN -d "$VPN_BIND_IP/32" -p tcp -m multiport --dports 80,443 -j ACCEPT || return 1
        fi
        "$fw" -w 5 -A VAULT_WG_IN -j DROP || return 1
        "$fw" -w 5 -A VAULT_WG_FWD -j DROP || return 1
        "$fw" -w 5 -I INPUT 1 -i wg0 -j VAULT_WG_IN || return 1
        "$fw" -w 5 -I FORWARD 1 -i wg0 -j VAULT_WG_FWD || return 1
        "$fw" -w 5 -I FORWARD 1 -o wg0 -j VAULT_WG_FWD || return 1
    done
}

cleanup() {
    status=$?
    trap - EXIT TERM INT
    if [ -n "$sleep_pid" ]; then kill "$sleep_pid" 2>/dev/null || :; wait "$sleep_pid" 2>/dev/null || :; fi
    # Keep isolation rules until the tunnel has been removed. If removal fails,
    # leave the rules in place instead of exposing a surviving interface.
    if [ "$interface_created" = 1 ] && ! ip link del dev wg0; then
        printf 'WireGuard: failed to remove wg0; retaining isolation firewall rules\n' >&2
        exit 1
    fi
    for fw in iptables ip6tables; do
        if [ "$fw" = iptables ]; then own_input=$v4_input; own_forward=$v4_forward; else own_input=$v6_input; own_forward=$v6_forward; fi
        if [ "$own_input" = 1 ]; then
            "$fw" -w 5 -D INPUT -i wg0 -j VAULT_WG_IN 2>/dev/null || :
            "$fw" -w 5 -F VAULT_WG_IN 2>/dev/null || :
            "$fw" -w 5 -X VAULT_WG_IN 2>/dev/null || :
        fi
        if [ "$own_forward" = 1 ]; then
            "$fw" -w 5 -D FORWARD -i wg0 -j VAULT_WG_FWD 2>/dev/null || :
            "$fw" -w 5 -D FORWARD -o wg0 -j VAULT_WG_FWD 2>/dev/null || :
            "$fw" -w 5 -F VAULT_WG_FWD 2>/dev/null || :
            "$fw" -w 5 -X VAULT_WG_FWD 2>/dev/null || :
        fi
    done
    exit "$status"
}

run() {
    render
    interface_created=0
    v4_input=0; v4_forward=0; v6_input=0; v6_forward=0; sleep_pid=''
    trap cleanup EXIT
    trap 'exit 0' TERM INT
    if ip link show dev wg0 >/dev/null 2>&1; then fail 'wg0 already exists; refusing to alter another interface'; fi
    install_firewall || fail 'failed to install IPv4/IPv6 isolation firewall; NET_ADMIN and kernel netfilter support are required'
    ip link add dev wg0 type wireguard || fail 'cannot create wg0; Linux kernel WireGuard support and NET_ADMIN are required (no userspace fallback)'
    interface_created=1
    wg setconf wg0 /config/server/wg0.conf || fail 'failed to configure kernel WireGuard interface'
    ip address add "$VPN_BIND_IP/24" dev wg0
    ip link set dev wg0 mtu 1420 up
    printf 'WireGuard: wg0 ready; internal UDP 51820; tunnel INPUT restricted to TCP 80/443; forwarding blocked\n'
    while :; do sleep 3600 & sleep_pid=$!; wait "$sleep_pid"; done
}

healthcheck() {
    ip -o link show dev wg0 | grep -Eq '<([^>]*,)?UP(,|>)' || return 1
    ip -o -4 address show dev wg0 | awk -v address="$VPN_BIND_IP/24" '$4 == address { found = 1 } END { exit !found }' || return 1
    [ "$(wg show wg0 listen-port)" = 51820 ]
}

case "${1-run}" in
    run|render|check|healthcheck) [ "$#" -le 1 ] || fail 'usage: vault-wireguard [run|render|check|healthcheck]' ;;
    *) exec "$@" ;;
esac
validate_env
case "${1-run}" in
    run) run ;;
    render) render ;;
    check) printf 'WireGuard: environment is valid\n' ;;
    healthcheck) healthcheck ;;
    *) fail 'usage: vault-wireguard [run|render|check|healthcheck]' ;;
esac
