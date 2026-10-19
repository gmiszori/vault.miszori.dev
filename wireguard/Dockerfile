FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

RUN apk add --no-cache wireguard-tools iproute2 iptables \
    && mkdir -p /config \
    && chmod 0700 /config

COPY --chmod=0755 runtime.sh /usr/local/bin/vault-wireguard

VOLUME ["/config"]
EXPOSE 51820/udp
HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/vault-wireguard", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/vault-wireguard"]
CMD ["run"]
