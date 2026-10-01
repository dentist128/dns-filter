FROM debian:12 AS binary

RUN apt -y update && \
    apt -y install gcc make

WORKDIR /tmp/src
COPY Makefile dns_filter.conf dns_filter.c ./

RUN make build

FROM gcr.io/distroless/static-debian12:latest AS base
# Run as root: the RouterOS container runtime does not grant
# CAP_NET_BIND_SERVICE to non-root containers, so a UID 1000 process
# cannot bind UDP/53. Plain Docker users can still override with
# `docker run --user 1000` (default capability set allows the bind).
USER 0
# Layout mirrors the systemd installation: binary in /usr/local/bin,
# working directory /etc/dns-filter with dns_filter.conf next to it.
# The config dir is the bind-mount point for RouterOS (dst=/etc/dns-filter).
WORKDIR /etc/dns-filter
COPY --from=binary /tmp/src/dns_filter.conf ./
COPY --from=binary /tmp/src/bin/dns_filter /usr/local/bin/dns_filter
LABEL org.opencontainers.image.authors="MarkelovEduard@gmail.com"
EXPOSE 53/udp
ENTRYPOINT [ "/usr/local/bin/dns_filter" ]
