#
# From-source OpenLDAP 2.6.14, built and owned by this project — no osixia,
# no vegardit. See image/README.md for the full env var contract and
# image/ldifs/*.ldif for the bootstrap templates.

ARG OPENLDAP_VERSION=2.6.14
ARG OPENLDAP_SHA256=806dcd21d366428187fba3278da773d5930f774852c9e92517f950d585f19107

FROM debian:trixie-slim AS builder
ARG OPENLDAP_VERSION
ARG OPENLDAP_SHA256
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libssl-dev \
        libsasl2-dev \
        libltdl-dev \
        libargon2-dev \
        groff-base \
        pkgconf \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src
RUN curl -fsSL -o openldap.tgz \
        "https://www.openldap.org/software/download/OpenLDAP/openldap-release/openldap-${OPENLDAP_VERSION}.tgz" \
    && printf '%s  openldap.tgz\n' "${OPENLDAP_SHA256}" | sha256sum -c - \
    && tar xzf openldap.tgz \
    && rm openldap.tgz

WORKDIR /usr/src/openldap-${OPENLDAP_VERSION}
RUN ./configure \
        --prefix=/usr \
        --sysconfdir=/etc \
        --localstatedir=/var \
        --libexecdir=/usr/lib \
        --enable-modules \
        --enable-mdb=mod \
        --enable-memberof=mod \
        --enable-refint=mod \
        --enable-ppolicy=mod \
        --enable-unique=mod \
        --enable-syncprov=mod \
        --enable-accesslog=mod \
        --enable-auditlog=mod \
        --enable-constraint=mod \
        --enable-deref=mod \
        --enable-dynlist=mod \
        --enable-sssvlv=mod \
        --enable-otp=mod \
        --enable-argon2 \
        --with-tls=openssl \
        --with-cyrus-sasl \
        --with-argon2=libargon2 \
    && make depend \
    && make -j"$(nproc)" \
    && make install

# Keep the exporter build isolated from the OpenLDAP source toolchain so the
# application build cache is not invalidated when exporter code changes.
FROM golang:1.26-bookworm AS exporter-builder
ARG OPENLDAP_EXPORTER_VERSION=v2.9.14
ARG TARGETARCH
ENV CGO_ENABLED=0 GOOS=linux
RUN go install github.com/hm-edu/openldap-exporter/v2@${OPENLDAP_EXPORTER_VERSION} \
    && case "${TARGETARCH}" in amd64) arch=amd64 ;; arm64) arch=arm64 ;; *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; esac \
    && test -x "$(go env GOPATH)/bin/openldap-exporter"

FROM debian:trixie-slim AS runtime
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libssl3t64 \
        libsasl2-2 \
        libltdl7 \
        libargon2-1 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system ldap \
    && useradd --system --no-create-home --home-dir /var/lib/openldap \
        --shell /usr/sbin/nologin --gid ldap ldap

COPY --from=builder /usr/lib/slapd /usr/lib/slapd
COPY --from=builder /usr/lib/openldap/ /usr/lib/openldap/
COPY --from=builder /usr/lib/libldap.so* /usr/lib/liblber.so* /usr/lib/
COPY --from=builder /usr/sbin/slap* /usr/sbin/
COPY --from=builder /usr/bin/ldap* /usr/bin/
COPY --from=builder /etc/openldap/schema/ /etc/openldap/schema/
COPY --from=builder /etc/openldap/ldap.conf /etc/openldap/ldap.conf
COPY --from=exporter-builder /go/bin/openldap-exporter /usr/local/bin/openldap_exporter

RUN ln -s /usr/lib/slapd /usr/local/sbin/slapd \
    && ldconfig

COPY ldifs/01-cn-config.ldif ldifs/02-cn-config-admin.ldif ldifs/03-base-structure.ldif \
    /usr/local/share/ldapium/bootstrap/
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 755 /usr/local/bin/entrypoint.sh

RUN mkdir -p /etc/openldap/slapd.d /var/lib/openldap/data /var/lib/openldap/run \
    && chown -R ldap:ldap /etc/openldap/slapd.d /var/lib/openldap \
    && chmod 700 /var/lib/openldap/data \
    && mkdir -p /opt/ldifs \
    && chown ldap:ldap /opt/ldifs

ENV PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ENV LDAP_SEED_DIR=/opt/ldifs
ENV LDAPTLS_REQCERT=demand
ENV LDAPTLS_CACERT=/etc/openldap/tls/ca.crt

USER 999:999
WORKDIR /var/lib/openldap

VOLUME ["/etc/openldap/slapd.d", "/var/lib/openldap/data"]
EXPOSE 389 636

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ldapwhoami -x -H "ldapi://%2Fvar%2Flib%2Fopenldap%2Frun%2Fldapi" || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
