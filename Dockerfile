FROM golang:1.26-alpine@sha256:3082400e369fa24d5fc60bca20edab3f6d604e0c5a690ec66b295eff4dd87ade AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /drive ./cmd/drive \
    && mkdir -m 0700 /data && chown 10001:10001 /data

FROM scratch
COPY --from=build /drive /drive
COPY --from=build --chown=10001:10001 /data /data
USER 10001:10001
ENV DATA_DIR=/data
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s CMD ["/drive", "healthcheck"]
ENTRYPOINT ["/drive"]
