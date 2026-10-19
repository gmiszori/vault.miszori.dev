FROM alpine:3.23@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0

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
