FROM golang:1.27-alpine@sha256:eb61c3873c97416fff0116553fff65d67a3549f72e11d9758849a689cdd8b523 AS build
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
