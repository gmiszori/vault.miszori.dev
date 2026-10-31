FROM golang:1.27-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /vault ./cmd/vault \
    && mkdir -m 0700 /data && chown 10001:10001 /data

FROM scratch
COPY --from=build /vault /vault
COPY --from=build --chown=10001:10001 /data /data
USER 10001:10001
ENV DATA_DIR=/data
EXPOSE 8080 8081
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s CMD ["/vault", "healthcheck"]
ENTRYPOINT ["/vault"]
