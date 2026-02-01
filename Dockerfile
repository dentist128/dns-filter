FROM debian:12 AS binary

RUN apt -y update && \
    apt -y install gcc make

WORKDIR /tmp/src
COPY Makefile dns_filter.conf dns_filter.c ./

RUN make build

FROM gcr.io/distroless/static-debian12:latest AS base
# FROM debian:12
STOPSIGNAL SIGKILL
USER 1000
WORKDIR /dns-filter
COPY --from=binary /tmp/src/dns_filter.conf /tmp/src/bin/dns_filter .
LABEL org.opencontainers.image.authors="MarkelovEduard@gmail.com"
EXPOSE 53/udp
ENTRYPOINT [ "/dns-filter/dns_filter" ]
# CMD [ "/dns-filter/dns_filter" ]
