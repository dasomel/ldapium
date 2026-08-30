# trivy:ignore:AVD-DS-0002 sssd -i must run as root: it owns /var/lib/sss
# sockets and PID files and rewrites system NSS resolution, none of which a
# non-root USER can do. This image is a disposable CI test fixture, never
# published, so the usual non-root-runtime rationale doesn't apply here.
# trivy:ignore:AVD-DS-0026 one-shot check-and-exit container, not a service —
# there is nothing running after entrypoint exits for a HEALTHCHECK to poll.
FROM debian:trixie-slim@sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258

ENV DEBIAN_FRONTEND=noninteractive

# Build the disposable client instead of bind-mounting sssd.conf. Apart from
# making the CI image self-contained, this avoids macOS/Colima UID mapping
# making a root-only SSSD configuration unexpectedly unreadable.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        sssd-ldap \
        libnss-sss \
    && rm -rf /var/lib/apt/lists/* \
    && sed -ri 's/^(passwd|group):.*/\1: sss files/' /etc/nsswitch.conf \
    && mkdir -p /etc/sssd

COPY sssd.conf /etc/sssd/sssd.conf
COPY run-nss-check.sh /usr/local/bin/run-nss-check
RUN chown root:root /etc/sssd/sssd.conf /usr/local/bin/run-nss-check \
    && chmod 600 /etc/sssd/sssd.conf \
    && chmod 755 /usr/local/bin/run-nss-check

ENTRYPOINT ["/usr/local/bin/run-nss-check"]
