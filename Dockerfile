FROM alpine:latest AS certs
RUN apk --no-cache add ca-certificates

FROM scratch
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY target/x86_64-unknown-linux-musl/release/chronos-agent /chronos-agent
COPY certN.bin /certN.bin
COPY config.toml /config.toml

ENTRYPOINT ["/chronos-agent", "--config", "/config.toml", "--cert", "/certN.bin"]
