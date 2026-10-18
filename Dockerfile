FROM golang:1.27-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
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
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s CMD ["/vault", "healthcheck"]
ENTRYPOINT ["/vault"]
