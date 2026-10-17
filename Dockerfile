FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /drive ./cmd/drive

FROM alpine:3.23
RUN addgroup -g 10001 drive && adduser -D -H -u 10001 -G drive drive && mkdir /data && chown drive:drive /data
COPY --from=build /drive /usr/local/bin/drive
USER drive
ENV DATA_DIR=/data
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/drive"]
